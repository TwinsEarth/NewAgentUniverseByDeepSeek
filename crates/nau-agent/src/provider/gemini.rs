//! The Gemini `generateContent` shape.
//!
//! `POST {base}/models/{model}:generateContent?key=<key>` — the credential is a
//! **query parameter**, not a header; the system prompt is `systemInstruction`;
//! messages are `contents[]` of `parts[]`; the assistant role is called `model`;
//! and the generated text is `candidates[0].content.parts[0].text`.
//!
//! upstream v2.5.6 fix: the upstream Gemini adapter did
//! `resp.candidates[0].content.parts[0]` and `.unwrap()`ed the client result.
//! Every step of that chain is now checked: an empty `candidates` array is a
//! typed error, an empty `parts` array is a typed error, and a missing `text` is
//! a typed error.
//!
//! upstream v2.8.2 fix (finding 3): `GePart.text` is a **required** `String`
//! upstream, so a `functionCall`, `inlineData` or `thought` part fails the whole
//! envelope. This decoder scans `parts` for the first non-blank `text` and
//! reports a function-call-only reply as the typed
//! [`ProviderError::ToolCallOnly`], and reads `usageMetadata` (and `modelVersion`)
//! only if present.

use super::{
    body_of, clamp_tokens, endpoint, finish_note, first_text_in, function_call_names, gemini_role,
    has_content, parse_json, string_field, tool_call_only, unsigned_field, HttpProvider,
    ProviderError, ProviderResult,
};
use crate::llm::{ChatRequest, ChatResponse, ChatRole};

/// The JSON shape this provider family sends.
const KIND: &str = "gemini generateContent";

/// Build a `POST /models/{model}:generateContent` request.
pub(super) fn build_request<T: nau_http::Transport>(
    provider: &HttpProvider<T>,
    base: &str,
    req: &ChatRequest,
    api_key: &str,
) -> ProviderResult<nau_http::HttpRequest> {
    let path = format!("models/{}:generateContent", provider.model());
    // Gemini authenticates with `?key=`, so the URL is the credential carrier
    // and the key has to be percent-safe. It is validated rather than escaped,
    // because escaping would silently change the credential.
    if !is_url_component_safe(api_key) {
        return Err(anyhow::anyhow!(
            "the API key for provider `{}` contains characters that cannot appear in a URL \
             query component, so it cannot be sent as `?key=`",
            provider.profile().name
        ));
    }
    let url = format!("{}?key={api_key}", endpoint(base, Some("v1beta"), &path));

    let mut system_parts: Vec<&str> = Vec::new();
    let mut contents: Vec<serde_json::Value> = Vec::new();
    for message in &req.messages {
        if message.role == ChatRole::System {
            system_parts.push(message.content.as_str());
            continue;
        }
        contents.push(serde_json::json!({
            "role": gemini_role(message.role),
            "parts": [{ "text": message.content }],
        }));
    }

    let mut body = serde_json::json!({
        "contents": contents,
        "generationConfig": {
            "maxOutputTokens": req.max_tokens,
            "temperature": super::temperature(req),
        },
    });
    if !system_parts.is_empty() {
        body["systemInstruction"] = serde_json::json!({
            "parts": [{ "text": system_parts.join("\n\n") }],
        });
    }

    Ok(nau_http::HttpRequest {
        method: "POST".to_string(),
        url,
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: Some(body_of(&body)?),
    })
}

/// Parse a `generateContent` body.
pub(super) fn parse_response<T: nau_http::Transport>(
    provider: &HttpProvider<T>,
    resp: &nau_http::HttpResponse,
) -> ProviderResult<ChatResponse> {
    let value = parse_json(&provider.profile().name, KIND, resp)?;
    let name = &provider.profile().name;

    // upstream v2.5.6 fix: `candidates[0].content.parts[0]` panicked on an empty
    // `candidates` array, which is what a content filter or a blocked prompt
    // produces. Each step is now a checked `.first()` with its own message.
    let candidate = value
        .get("candidates")
        .and_then(|candidates| candidates.as_array())
        .and_then(|candidates| candidates.first())
        .ok_or_else(|| ProviderError::EmptyCompletion {
            provider: name.clone(),
            detail: "the `candidates` array is empty or absent".to_string(),
        })?;
    let parts = candidate
        .get("content")
        .and_then(|content| content.get("parts"))
        .and_then(|parts| parts.as_array())
        .ok_or_else(|| ProviderError::EmptyCompletion {
            provider: name.clone(),
            detail: "candidates[0].content.parts is absent or not an array".to_string(),
        })?;

    let finish_reason = candidate
        .get("finishReason")
        .and_then(|reason| reason.as_str())
        .map(str::to_string)
        // A blocked prompt reports no finish reason but does report a block
        // reason, and that is the more useful of the two to surface.
        .or_else(|| {
            value
                .get("promptFeedback")
                .and_then(|feedback| string_field(feedback, "blockReason"))
        })
        .unwrap_or_else(|| "unknown".to_string());

    // upstream v2.8.2 fix (finding 3): scan the parts for the first text-bearing
    // one. A `functionCall` part has no `text`, and a real reply may put one
    // before the text part.
    let Some(text) = first_text_in(parts) else {
        let calls = function_call_names(parts);
        if !calls.is_empty() {
            return Err(tool_call_only(name, "parts[].functionCall", calls).into());
        }
        let detail = if parts.is_empty() {
            format!(
                "candidates[0].content.parts is an empty array{}",
                finish_note(Some(&finish_reason))
            )
        } else {
            format!(
                "no part in candidates[0].content.parts carries a non-blank `text` field ({} \
                 part(s){})",
                parts.len(),
                finish_note(Some(&finish_reason))
            )
        };
        return Err(ProviderError::EmptyCompletion {
            provider: name.clone(),
            detail,
        }
        .into());
    };
    debug_assert!(has_content(text));

    let usage = value
        .get("usageMetadata")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(ChatResponse {
        model: string_field(&value, "modelVersion")
            .or_else(|| string_field(&value, "model"))
            .unwrap_or_else(|| provider.model().to_string()),
        content: text.to_string(),
        prompt_tokens: clamp_tokens(unsigned_field(&usage, "promptTokenCount").unwrap_or(0)),
        completion_tokens: clamp_tokens(
            unsigned_field(&usage, "candidatesTokenCount").unwrap_or(0),
        ),
        finish_reason,
    })
}

/// Whether every character of `value` is safe, unescaped, in a query component.
///
/// Deliberately strict: a key that needs escaping is refused rather than
/// rewritten, so the credential that travels is exactly the credential the
/// environment supplied.
fn is_url_component_safe(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b':')
        })
}
