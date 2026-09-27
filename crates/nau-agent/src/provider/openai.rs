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

use super::{
    body_of, clamp_tokens, has_content, parse_json, reported_model, role_label, temperature,
    unsigned_field, HttpProvider, ProviderError, ProviderResult,
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

    // upstream v2.5.6 fix: `.first()` instead of `choices[0]`, and an empty or
    // absent array is a typed error rather than a panic.
    let choice = value
        .get("choices")
        .and_then(|choices| choices.as_array())
        .and_then(|choices| choices.first())
        .ok_or_else(|| ProviderError::EmptyChoices {
            provider: provider.profile().name.clone(),
        })?;

    let content = choice
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(|content| content.as_str())
        .ok_or_else(|| ProviderError::EmptyCompletion {
            provider: provider.profile().name.clone(),
            detail: "choices[0].message.content is absent or not a string",
        })?;
    if !has_content(content) {
        return Err(ProviderError::EmptyCompletion {
            provider: provider.profile().name.clone(),
            detail: "choices[0].message.content is empty",
        }
        .into());
    }

    let usage = value
        .get("usage")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let finish_reason = choice
        .get("finish_reason")
        .and_then(|reason| reason.as_str())
        .unwrap_or("unknown")
        .to_string();

    Ok(ChatResponse {
        model: reported_model(&value, provider.model()),
        content: content.to_string(),
        prompt_tokens: clamp_tokens(unsigned_field(&usage, "prompt_tokens").unwrap_or(0)),
        completion_tokens: clamp_tokens(unsigned_field(&usage, "completion_tokens").unwrap_or(0)),
        finish_reason,
    })
}
