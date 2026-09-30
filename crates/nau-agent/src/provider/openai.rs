//! The OpenAI-compatible request/response shape.
//!
//! `openai`, `deepseek`, `qwen`, `zhipu`, `kimi` and `doubao` all speak this:
//! `POST {base}/chat/completions` with `Authorization: Bearer <key>`, messages
//! carrying their own `role`, `max_tokens` for the output cap, and the generated
//! text at `choices[0].message.content`.
//!
//! upstream v2.5.6 fix: the upstream OpenAI/DeepSeek/Qwen/Zhipu/Kimi/Doubao
//! adapters all did `resp.choices[0]` and `.unwrap()`ed the client result. Both
//! are gone: the array is read with `.first()` and every failure is typed.
//!
//! upstream v2.8.2 fix (finding 3): `OaChatResponse` requires `id`, `usage` and
//! `choices`, and requires `message.content` to be a `String`, so three
//! legitimate replies failed the **whole envelope**: a tool-call-only reply
//! (`"content": null` + `tool_calls`), a gateway that omits `usage`, and the
//! part-array form of `content`. This decoder reads a
//! [`serde_json::Value`] field by field, so no absent optional field can reject
//! the envelope, and it reports a tool-call-only reply as
//! [`ProviderError::ToolCallOnly`] — a typed outcome the caller can act on —
//! instead of an empty completion.

use super::{
    body_of, clamp_tokens, finish_note, has_content, openai_content_text, parse_json,
    reported_model, role_label, string_field, temperature, tool_call_only, unsigned_field,
    HttpProvider, ProviderError, ProviderResult,
};
use crate::llm::{ChatRequest, ChatResponse};

/// The JSON shape this provider family sends.
const KIND: &str = "openai-compatible chat completion";

/// Build a `POST /chat/completions` request.
pub(super) fn build_request<T: nau_http::Transport>(
    provider: &HttpProvider<T>,
    base: &str,
    req: &ChatRequest,
    api_key: &str,
) -> ProviderResult<nau_http::HttpRequest> {
    let url = format!("{base}/chat/completions");
    let messages: Vec<serde_json::Value> = req
        .messages
        .iter()
        .map(|message| {
            serde_json::json!({
                "role": role_label(message.role),
                "content": message.content,
            })
        })
        .collect();
    let body = serde_json::json!({
        "model": provider.model(),
        "messages": messages,
        "max_tokens": req.max_tokens,
        "temperature": temperature(req),
        "stream": false,
    });

    Ok(nau_http::HttpRequest {
        method: "POST".to_string(),
        url,
        headers: vec![
            ("Authorization".to_string(), format!("Bearer {api_key}")),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: Some(body_of(&body)?),
    })
}

/// Parse a `chat.completion` body.
pub(super) fn parse_response<T: nau_http::Transport>(
    provider: &HttpProvider<T>,
    resp: &nau_http::HttpResponse,
) -> ProviderResult<ChatResponse> {
    let value = parse_json(&provider.profile().name, KIND, resp)?;
    let name = &provider.profile().name;

    // upstream v2.5.6 fix: `.first()` instead of `choices[0]`, and an empty or
    // absent array is a typed error rather than a panic.
    let choice = value
        .get("choices")
        .and_then(|choices| choices.as_array())
        .and_then(|choices| choices.first())
        .ok_or_else(|| ProviderError::EmptyChoices {
            provider: name.clone(),
        })?;

    let finish_reason = choice
        .get("finish_reason")
        .and_then(|reason| reason.as_str())
        .unwrap_or("unknown")
        .to_string();
    let message = choice.get("message");

    // `content` is a string in the chat-completions shape and a part array in
    // several gateways; both are legitimate.
    let content = message
        .and_then(|message| message.get("content"))
        .and_then(openai_content_text);

    let Some(content) = content else {
        // No text. Distinguish the two reasons, because they mean different
        // things to a caller: the model asked to call a tool, or the reply is
        // genuinely empty (a content filter, a zero-token completion, a
        // truncation at the cap).
        let tools = message.map(tool_call_names).unwrap_or_default();
        if !tools.is_empty() {
            return Err(tool_call_only(name, "tool_calls", tools).into());
        }
        let detail = if message.is_none() {
            "choices[0] has no `message` object".to_string()
        } else if message
            .and_then(|message| message.get("content"))
            .is_some_and(|content| content.is_array())
        {
            format!(
                "choices[0].message.content is a part array with no text part{}",
                finish_note(Some(&finish_reason))
            )
        } else {
            format!(
                "choices[0].message.content is absent, null or empty{}",
                finish_note(Some(&finish_reason))
            )
        };
        return Err(ProviderError::EmptyCompletion {
            provider: name.clone(),
            detail,
        }
        .into());
    };
    debug_assert!(has_content(content));

    let usage = value
        .get("usage")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(ChatResponse {
        model: reported_model(&value, provider.model()),
        content: content.to_string(),
        prompt_tokens: clamp_tokens(unsigned_field(&usage, "prompt_tokens").unwrap_or(0)),
        completion_tokens: clamp_tokens(unsigned_field(&usage, "completion_tokens").unwrap_or(0)),
        finish_reason,
    })
}

/// The tool names a `message.tool_calls` array asks for, in wire order.
///
/// A tool call with no `function.name` is reported as `"<unnamed>"`: the presence
/// of the call is what makes this a tool-call reply, not the name.
fn tool_call_names(message: &serde_json::Value) -> Vec<String> {
    message
        .get("tool_calls")
        .and_then(|calls| calls.as_array())
        .map(|calls| {
            calls
                .iter()
                .map(|call| {
                    call.get("function")
                        .and_then(|function| string_field(function, "name"))
                        .or_else(|| string_field(call, "name"))
                        .or_else(|| string_field(call, "id"))
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or_else(|| "<unnamed>".to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}
