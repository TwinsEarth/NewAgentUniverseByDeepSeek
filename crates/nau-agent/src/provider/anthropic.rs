//! The Anthropic Messages shape.
//!
//! `POST {base}/v1/messages` with **`x-api-key`** (not `Authorization`) plus the
//! mandatory `anthropic-version` header, the system prompt hoisted out of the
//! message list into a top-level `system` field, and the generated text at
//! `content[0].text` — a *content block array*, not a string, which is why the
//! shape cannot be folded into the OpenAI-compatible one.
//!
//! upstream v2.5.6 fix: the upstream Anthropic adapter did `resp.content[0]` and
//! `.unwrap()`ed the client result, and no code anywhere could set
//! `x-api-key` or `anthropic-version`. Here the array is read with `.first()`,
//! the headers are set by [`build_request`], and an empty content array is
//! [`ProviderError::EmptyCompletion`].

use super::{
    body_of, clamp_tokens, endpoint, has_content, parse_json, reported_model, unsigned_field,
    HttpProvider, ProviderError, ProviderResult,
};
use crate::llm::{ChatRequest, ChatResponse, ChatRole};

/// The JSON shape this provider family sends.
const KIND: &str = "anthropic messages";

/// The Anthropic API version this client is written against.
///
/// Pinned as a constant so a request cannot silently drift onto a different
/// revision of the protocol.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Build a `POST /v1/messages` request.
pub(super) fn build_request<T: nau_http::Transport>(
    provider: &HttpProvider<T>,
    base: &str,
    req: &ChatRequest,
    api_key: &str,
) -> ProviderResult<nau_http::HttpRequest> {
    let url = endpoint(base, Some("v1"), "messages");

    // Anthropic rejects `role: system` inside `messages`; the system prompt is a
    // top-level field. Flattening rather than dropping it keeps the instruction
    // in the request, which is the whole point of a system prompt.
    let mut system_parts: Vec<&str> = Vec::new();
    let mut messages: Vec<serde_json::Value> = Vec::new();
    for message in &req.messages {
        match message.role {
            ChatRole::System => system_parts.push(message.content.as_str()),
            ChatRole::User => messages.push(serde_json::json!({
                "role": "user",
                "content": message.content,
            })),
            ChatRole::Assistant => messages.push(serde_json::json!({
                "role": "assistant",
                "content": message.content,
            })),
        }
    }

    let mut body = serde_json::json!({
        "model": provider.model(),
        "messages": messages,
        "max_tokens": req.max_tokens,
        "temperature": super::temperature(req),
        "stream": false,
    });
    if !system_parts.is_empty() {
        body["system"] = serde_json::Value::from(system_parts.join("\n\n"));
    }

    Ok(nau_http::HttpRequest {
        method: "POST".to_string(),
        url,
        headers: vec![
            // The credential header is `x-api-key`, not `Authorization: Bearer`:
            // sending the wrong one is a 401, and inventing both is how a
            // credential leaks to an unexpected place.
            ("x-api-key".to_string(), api_key.to_string()),
            (
                "anthropic-version".to_string(),
                ANTHROPIC_VERSION.to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: Some(body_of(&body)?),
    })
}

/// Parse a Messages body.
pub(super) fn parse_response<T: nau_http::Transport>(
    provider: &HttpProvider<T>,
    resp: &nau_http::HttpResponse,
) -> ProviderResult<ChatResponse> {
    let value = parse_json(&provider.profile().name, KIND, resp)?;

    // upstream v2.5.6 fix: `.first()` on the content-block array instead of
    // `content[0]`, which panicked whenever the reply was empty.
    let blocks = value
        .get("content")
        .and_then(|content| content.as_array())
        .ok_or_else(|| ProviderError::EmptyCompletion {
            provider: provider.profile().name.clone(),
            detail: "the response has no `content` array",
        })?;
    let first = blocks
        .first()
        .ok_or_else(|| ProviderError::EmptyCompletion {
            provider: provider.profile().name.clone(),
            detail: "the `content` array is empty",
        })?;
    let text = first
        .get("text")
        .and_then(|text| text.as_str())
        .ok_or_else(|| ProviderError::EmptyCompletion {
            provider: provider.profile().name.clone(),
            detail: "content[0] has no `text` field (a tool-use-only reply has none)",
        })?;
    if !has_content(text) {
        return Err(ProviderError::EmptyCompletion {
            provider: provider.profile().name.clone(),
            detail: "content[0].text is empty",
        }
        .into());
    }

    let usage = value
        .get("usage")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    // Anthropic names them `input_tokens` / `output_tokens`, not
    // `prompt_tokens` / `completion_tokens`.
    let finish_reason = value
        .get("stop_reason")
        .and_then(|reason| reason.as_str())
        .unwrap_or("unknown")
        .to_string();

    Ok(ChatResponse {
        model: reported_model(&value, provider.model()),
        content: text.to_string(),
        prompt_tokens: clamp_tokens(unsigned_field(&usage, "input_tokens").unwrap_or(0)),
        completion_tokens: clamp_tokens(unsigned_field(&usage, "output_tokens").unwrap_or(0)),
        finish_reason,
    })
}
