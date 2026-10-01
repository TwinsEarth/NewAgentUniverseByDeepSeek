//! Live-provider tests: real request shapes, real error paths, deterministic
//! transports, and one end-to-end run over a real loopback socket.
//!
//! upstream v2.5.6 fix set covered here:
//! * every provider was a `Mock*Client` returning a fixed string, and the crate
//!   had **no HTTP client at all**, so `LlmProvider` had no live path;
//! * every adapter `.unwrap()`ed the client result inside a function that could
//!   not report failure, so any provider error was an unconditional panic;
//! * `choices[0]`, `content[0]` and `candidates[0].content.parts[0]` were indexed
//!   unchecked, so an empty completion panicked;
//! * no `Authorization` / `x-api-key` / `anthropic-version` header mechanism
//!   existed anywhere;
//! * `api_key_env` was stored and never read.

use nau_agent::provider::{HttpProvider, ProviderKind};
use nau_agent::{ChatMessage, ChatRequest, LlmProvider, ProviderProfile};
use nau_http::{HttpResponse, RecordingTransport, Transport};
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The credential used by every test. Never read from the environment.
const TEST_KEY: &str = "sk-test-not-a-real-key";

/// The seven catalog providers, for the shape-classification assertions.
fn profiles() -> Vec<ProviderProfile> {
    nau_agent::known_profiles()
}

fn profile_for(name: &str) -> ProviderProfile {
    profiles()
        .into_iter()
        .find(|profile| profile.name == name)
        .unwrap_or_else(|| panic!("the catalog must contain `{name}`"))
}

/// A profile for a vendor the catalog does not list, speaking the
/// OpenAI-compatible shape.
///
/// `doubao` is exactly that case: the brief names it as a shape this layer must
/// support, and the catalog's seven entries do not include it. Building the
/// profile by hand is what a deployment would do.
fn openai_compatible_profile(name: &str, base_url: &str) -> ProviderProfile {
    ProviderProfile {
        name: name.to_string(),
        base_url: base_url.to_string(),
        models: vec![format!("{name}-model")],
        context_window: 32_768,
        api_key_env: Some(format!(
            "{}_API_KEY",
            name.to_ascii_uppercase().replace('-', "_")
        )),
    }
}

fn request(model: &str) -> ChatRequest {
    ChatRequest {
        model: model.to_string(),
        messages: vec![
            ChatMessage::system("You are a careful agent."),
            ChatMessage::user("Summarise the ledger."),
            ChatMessage::assistant("Which ledger?"),
            ChatMessage::user("The escrow one."),
        ],
        max_tokens: 512,
        temperature_milli: 700,
    }
}

fn provider(
    name: &str,
    model: &str,
    responses: Vec<HttpResponse>,
) -> HttpProvider<RecordingTransport> {
    HttpProvider::new(
        profile_for(name),
        model,
        RecordingTransport::with_responses(responses),
    )
    .expect("the catalog profiles carry an api_key_env")
}

/// A response with a JSON body and a status.
fn json_response(status: u16, body: Value) -> HttpResponse {
    let bytes = serde_json::to_vec(&body).expect("fixture serializes");
    let mut headers = nau_http::Headers::new();
    headers.push("Content-Type", "application/json");
    headers.push("Content-Length", bytes.len().to_string());
    HttpResponse {
        status,
        headers,
        body: bytes,
    }
}

fn raw_response(status: u16, body: &str) -> HttpResponse {
    let mut headers = nau_http::Headers::new();
    headers.push("Content-Length", body.len().to_string());
    HttpResponse {
        status,
        headers,
        body: body.as_bytes().to_vec(),
    }
}

/// Deserialize a request body for structural assertions.
fn body_of(request: &nau_http::HttpRequest) -> Value {
    serde_json::from_slice(request.body.as_deref().expect("a body")).expect("body is JSON")
}

fn header_of<'a>(request: &'a nau_http::HttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The error text of a failed `chat` call.
///
/// Generic over the transport, so the same helper covers the deterministic
/// double and the real socket.
async fn chat_error_text<T: Transport>(provider: &HttpProvider<T>, req: ChatRequest) -> String {
    match provider.chat(req).await {
        Ok(response) => panic!("expected a failure, got {response:?}"),
        Err(error) => error.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Shape classification
// ---------------------------------------------------------------------------

#[test]
fn every_catalog_provider_maps_onto_a_real_wire_shape() {
    assert_eq!(
        ProviderKind::from_name("openai"),
        ProviderKind::OpenAiCompatible
    );
    assert_eq!(
        ProviderKind::from_name("deepseek"),
        ProviderKind::OpenAiCompatible
    );
    assert_eq!(
        ProviderKind::from_name("doubao"),
        ProviderKind::OpenAiCompatible,
        "an unknown vendor name is OpenAI-compatible, which is what doubao speaks"
    );
    assert_eq!(
        ProviderKind::from_name("qwen"),
        ProviderKind::OpenAiCompatible
    );
    assert_eq!(
        ProviderKind::from_name("zhipu"),
        ProviderKind::OpenAiCompatible
    );
    assert_eq!(
        ProviderKind::from_name("kimi"),
        ProviderKind::OpenAiCompatible
    );
    assert_eq!(
        ProviderKind::from_name("Anthropic"),
        ProviderKind::Anthropic
    );
    assert_eq!(ProviderKind::from_name("gemini"), ProviderKind::Gemini);
    assert_eq!(ProviderKind::from_name("GOOGLE"), ProviderKind::Gemini);

    // Every catalog entry must classify to something, and the three shapes must
    // all be represented.
    let kinds: Vec<ProviderKind> = profiles()
        .iter()
        .map(|profile| ProviderKind::from_name(&profile.name))
        .collect();
    assert!(kinds.contains(&ProviderKind::Anthropic));
    assert!(kinds.contains(&ProviderKind::Gemini));
    assert!(kinds.contains(&ProviderKind::OpenAiCompatible));
}

#[test]
fn a_profile_without_an_api_key_env_cannot_become_a_provider() {
    let mut profile = profile_for("deepseek");
    profile.api_key_env = None;

    let error = HttpProvider::new(profile, "deepseek-flash", RecordingTransport::new())
        .expect_err("a provider that can never authenticate must not be constructed");

    let message = error.to_string();
    assert!(
        message.contains("api_key_env"),
        "the error must name the missing field: {message}"
    );
    assert!(message.contains("deepseek"), "and the provider: {message}");
}

#[test]
fn the_context_window_comes_from_the_requested_model_not_a_flat_constant() {
    let big = provider("gemini", "gemini-3-pro", Vec::new());
    let small = provider("gemini", "gemini-3-flash", Vec::new());
    assert_eq!(big.context_window(), 1_000_000);
    assert_eq!(small.context_window(), 200_000);

    // A model the catalog does not know falls back to the profile's declared
    // window instead of inventing one.
    let unknown = provider("gemini", "gemini-does-not-exist", Vec::new());
    assert_eq!(
        unknown.context_window(),
        profile_for("gemini").context_window
    );
}

#[test]
fn the_provider_reports_its_protocol_name() {
    assert_eq!(provider("openai", "gpt-4o", Vec::new()).name(), "openai");
    assert_eq!(
        provider("anthropic", "claude-sonnet-4-6", Vec::new()).name(),
        "anthropic"
    );
    assert_eq!(
        provider("gemini", "gemini-3-pro", Vec::new()).name(),
        "gemini"
    );
}

// ---------------------------------------------------------------------------
// OpenAI-compatible shape: openai, deepseek, doubao
// ---------------------------------------------------------------------------

#[test]
fn an_openai_compatible_request_carries_a_bearer_token_and_a_chat_body() {
    let sut = provider("deepseek", "deepseek-flash", Vec::new());
    let built = sut
        .build_request(&request("deepseek-flash"), TEST_KEY)
        .expect("builds");

    assert_eq!(built.method, "POST");
    assert_eq!(built.url, "https://api.deepseek.com/chat/completions");
    assert_eq!(
        header_of(&built, "authorization"),
        Some("Bearer sk-test-not-a-real-key"),
        "the deferred API key is the one that travels"
    );
    assert_eq!(header_of(&built, "content-type"), Some("application/json"));
    assert!(
        header_of(&built, "x-api-key").is_none(),
        "an OpenAI-compatible provider must not send the Anthropic header"
    );

    let body = body_of(&built);
    assert_eq!(body["model"], Value::from("deepseek-flash"));
    assert_eq!(body["stream"], Value::from(false));
    assert_eq!(body["max_tokens"], Value::from(512));
    assert_eq!(body["temperature"], Value::from(0.7));
    assert_eq!(body["messages"].as_array().map(Vec::len), Some(4));
    assert_eq!(body["messages"][0]["role"], Value::from("system"));
    assert_eq!(
        body["messages"][0]["content"],
        Value::from("You are a careful agent.")
    );
    assert_eq!(body["messages"][3]["role"], Value::from("user"));
}

#[test]
fn the_openai_headers_are_identical_for_every_compatible_vendor() {
    // `doubao` is not in the catalog, so its profile is built by hand exactly as
    // a deployment would: name, base URL, and the variable holding the key.
    let doubao = openai_compatible_profile("doubao", "https://ark.cn-beijing.volces.com/api/v3");
    assert_eq!(
        ProviderKind::from_name(&doubao.name),
        ProviderKind::OpenAiCompatible
    );

    let cases: Vec<(ProviderProfile, &str)> = vec![
        (profile_for("openai"), "gpt-4o"),
        (profile_for("deepseek"), "deepseek-flash"),
        (doubao, "doubao-pro-32k"),
    ];
    for (profile, model) in cases {
        let name = profile.name.clone();
        let sut = HttpProvider::new(profile, model, RecordingTransport::new())
            .expect("the profile names an api_key_env");
        let built = sut
            .build_request(&request(model), TEST_KEY)
            .expect("builds");
        assert_eq!(
            header_of(&built, "authorization"),
            Some("Bearer sk-test-not-a-real-key"),
            "{name} must use the Bearer convention"
        );
        assert_eq!(
            header_of(&built, "content-type"),
            Some("application/json"),
            "{name}"
        );
        assert!(
            built.url.ends_with("/chat/completions"),
            "{name} must post to the shared completion endpoint: {}",
            built.url
        );
        assert_eq!(body_of(&built)["model"], Value::from(model), "{name}");
    }
}

#[test]
fn an_openai_compatible_response_parses_with_token_counts() {
    let response = json_response(
        200,
        serde_json::json!({
            "id": "chatcmpl-1",
            "model": "deepseek-chat-0724",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "The escrow ledger."},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 42, "completion_tokens": 7, "total_tokens": 49}
        }),
    );

    let parsed = provider("deepseek", "deepseek-flash", Vec::new())
        .parse_response(&response)
        .expect("parses");

    assert_eq!(
        parsed.model, "deepseek-chat-0724",
        "the served model is reported"
    );
    assert_eq!(parsed.content, "The escrow ledger.");
    assert_eq!(parsed.prompt_tokens, 42);
    assert_eq!(parsed.completion_tokens, 7);
    assert_eq!(parsed.finish_reason, "stop");
}

#[test]
fn a_missing_usage_block_reports_zero_tokens_rather_than_failing() {
    let response = json_response(
        200,
        serde_json::json!({
            "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}]
        }),
    );
    let parsed = provider("openai", "gpt-4o", Vec::new())
        .parse_response(&response)
        .expect("parses");
    assert_eq!(parsed.prompt_tokens, 0);
    assert_eq!(parsed.completion_tokens, 0);
    assert_eq!(parsed.model, "gpt-4o", "falls back to the requested model");
}

#[test]
fn token_counts_sent_as_strings_are_accepted() {
    let response = json_response(
        200,
        serde_json::json!({
            "choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": "11", "completion_tokens": "3"}
        }),
    );
    let parsed = provider("openai", "gpt-4o", Vec::new())
        .parse_response(&response)
        .expect("parses");
    assert_eq!(parsed.prompt_tokens, 11);
    assert_eq!(parsed.completion_tokens, 3);
}

// ---------------------------------------------------------------------------
// Anthropic shape
// ---------------------------------------------------------------------------

#[test]
fn an_anthropic_request_uses_x_api_key_and_hoists_the_system_prompt() {
    let sut = provider("anthropic", "claude-sonnet-4-6", Vec::new());
    let built = sut
        .build_request(&request("claude-sonnet-4-6"), TEST_KEY)
        .expect("builds");

    assert_eq!(built.url, "https://api.anthropic.com/v1/messages");
    assert_eq!(header_of(&built, "x-api-key"), Some(TEST_KEY));
    assert_eq!(
        header_of(&built, "anthropic-version"),
        Some("2023-06-01"),
        "Anthropic rejects a request without a pinned version"
    );
    assert!(
        header_of(&built, "authorization").is_none(),
        "Anthropic does not read `Authorization: Bearer`"
    );

    let body = body_of(&built);
    assert_eq!(
        body["system"],
        Value::from("You are a careful agent."),
        "the system prompt is a top-level field, not a message"
    );
    let messages = body["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 3, "the system message is not in `messages`");
    assert!(
        messages.iter().all(|message| message["role"] != "system"),
        "Anthropic rejects `role: system` inside messages: {body}"
    );
    assert_eq!(messages[0]["role"], Value::from("user"));
    assert_eq!(messages[1]["role"], Value::from("assistant"));
    assert_eq!(body["max_tokens"], Value::from(512));
}

#[test]
fn an_anthropic_response_parses_content_blocks_and_its_own_token_names() {
    let response = json_response(
        200,
        serde_json::json!({
            "id": "msg_1",
            "model": "claude-sonnet-4-6-20260101",
            "content": [{"type": "text", "text": "The escrow ledger."}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 31, "output_tokens": 9}
        }),
    );

    let parsed = provider("anthropic", "claude-sonnet-4-6", Vec::new())
        .parse_response(&response)
        .expect("parses");

    assert_eq!(parsed.content, "The escrow ledger.");
    assert_eq!(parsed.prompt_tokens, 31, "input_tokens is the prompt count");
    assert_eq!(parsed.completion_tokens, 9);
    assert_eq!(parsed.finish_reason, "end_turn");
    assert_eq!(parsed.model, "claude-sonnet-4-6-20260101");
}

#[test]
fn an_anthropic_tool_only_reply_is_a_typed_error_and_not_a_panic() {
    // upstream v2.5.6 fix: `resp.content[0]` panicked on an empty array, and a
    // tool-use-only reply has no `text` field even when the array is non-empty.
    // upstream v2.8.2 fix (finding 3): the two cases are now *different typed
    // outcomes*. An empty array is `EmptyCompletion`; a reply that consists of a
    // tool call is `ToolCallOnly`, which names the tool the model asked for, so a
    // caller can act on it instead of guessing why there was no text.
    let empty = json_response(
        200,
        serde_json::json!({"content": [], "stop_reason": "tool_use"}),
    );
    let error = provider("anthropic", "claude-sonnet-4-6", Vec::new())
        .parse_response(&empty)
        .expect_err("an empty content array has no completion");
    match error.downcast_ref::<nau_agent::provider::ProviderError>() {
        Some(nau_agent::provider::ProviderError::EmptyCompletion { detail, .. }) => {
            assert!(detail.contains("empty"), "{detail}");
            assert!(
                detail.contains("tool_use"),
                "the stop reason is reported: {detail}"
            );
        }
        other => panic!("expected EmptyCompletion, got {other:?}"),
    }

    let tool_only = json_response(
        200,
        serde_json::json!({
            "content": [{"type": "tool_use", "id": "toolu_1", "name": "search", "input": {}}],
            "stop_reason": "tool_use"
        }),
    );
    let error = provider("anthropic", "claude-sonnet-4-6", Vec::new())
        .parse_response(&tool_only)
        .expect_err("a tool-use block carries no text");
    match error.downcast_ref::<nau_agent::provider::ProviderError>() {
        Some(nau_agent::provider::ProviderError::ToolCallOnly { tools, shape, .. }) => {
            assert_eq!(shape, &"content[].tool_use");
            assert_eq!(tools, &vec!["search".to_string()]);
        }
        other => panic!("expected ToolCallOnly, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Gemini shape
// ---------------------------------------------------------------------------

#[test]
fn a_gemini_request_puts_the_key_in_the_query_and_uses_parts() {
    let sut = provider("gemini", "gemini-3-pro", Vec::new());
    let built = sut
        .build_request(&request("gemini-3-pro"), TEST_KEY)
        .expect("builds");

    assert_eq!(
        built.url,
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-pro:generateContent?key=sk-test-not-a-real-key"
    );
    assert!(
        header_of(&built, "authorization").is_none(),
        "Gemini authenticates with `?key=`, not a header"
    );
    assert!(header_of(&built, "x-api-key").is_none());

    let body = body_of(&built);
    assert_eq!(
        body["systemInstruction"]["parts"][0]["text"],
        Value::from("You are a careful agent.")
    );
    let contents = body["contents"].as_array().expect("contents array");
    assert_eq!(
        contents.len(),
        3,
        "the system message is not a content entry"
    );
    assert_eq!(contents[0]["role"], Value::from("user"));
    assert_eq!(
        contents[1]["role"],
        Value::from("model"),
        "Gemini calls the assistant role `model`"
    );
    assert_eq!(
        contents[1]["parts"][0]["text"],
        Value::from("Which ledger?")
    );
    assert_eq!(
        body["generationConfig"]["maxOutputTokens"],
        Value::from(512)
    );
    assert_eq!(body["generationConfig"]["temperature"], Value::from(0.7));
}

#[test]
fn a_gemini_key_that_would_need_escaping_is_refused_rather_than_rewritten() {
    let sut = provider("gemini", "gemini-3-pro", Vec::new());
    let error = sut
        .build_request(&request("gemini-3-pro"), "key with spaces&more")
        .expect_err("the credential must travel unchanged or not at all");
    assert!(error.to_string().contains("query component"), "{error}");
}

#[test]
fn a_gemini_response_parses_candidates_and_usage_metadata() {
    let response = json_response(
        200,
        serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "The escrow ledger."}]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {"promptTokenCount": 21, "candidatesTokenCount": 6},
            "modelVersion": "gemini-3-pro-001"
        }),
    );

    let parsed = provider("gemini", "gemini-3-pro", Vec::new())
        .parse_response(&response)
        .expect("parses");

    assert_eq!(parsed.content, "The escrow ledger.");
    assert_eq!(parsed.prompt_tokens, 21);
    assert_eq!(parsed.completion_tokens, 6);
    assert_eq!(parsed.finish_reason, "STOP");
    assert_eq!(parsed.model, "gemini-3-pro-001");
}

#[test]
fn a_gemini_blocked_prompt_is_a_typed_error_that_names_the_block_reason() {
    // upstream v2.5.6 fix: `candidates[0]` panicked here, and a blocked prompt
    // has no candidates at all.
    let response = json_response(
        200,
        serde_json::json!({
            "promptFeedback": {"blockReason": "SAFETY"},
            "usageMetadata": {"promptTokenCount": 12}
        }),
    );

    let error = provider("gemini", "gemini-3-pro", Vec::new())
        .parse_response(&response)
        .expect_err("a blocked prompt produced no completion");
    assert!(error.to_string().contains("candidates"), "{error}");
}

// ---------------------------------------------------------------------------
// Empty completions: the upstream panic, now a typed error
// ---------------------------------------------------------------------------

#[test]
fn an_empty_choices_array_is_a_typed_error_and_never_a_panic() {
    // upstream v2.5.6 fix (`resp.choices[0]`, `llm/adapter.rs:72,203,245`).
    let response = json_response(200, serde_json::json!({"choices": []}));
    let error = provider("deepseek", "deepseek-flash", Vec::new())
        .parse_response(&response)
        .expect_err("an empty choices array has no completion");
    assert!(
        error.to_string().contains("empty choices array"),
        "the cause must be named: {error}"
    );
}

#[test]
fn a_missing_choices_key_is_a_typed_error() {
    let response = json_response(200, serde_json::json!({"id": "x"}));
    let error = provider("openai", "gpt-4o", Vec::new())
        .parse_response(&response)
        .expect_err("no choices at all");
    assert!(error.to_string().contains("empty choices array"), "{error}");
}

#[test]
fn an_empty_message_content_is_a_typed_error_not_an_empty_completion() {
    for content in [Value::from(""), Value::from("   "), Value::Null] {
        let response = json_response(
            200,
            serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "content_filter"}]
            }),
        );
        let error = provider("deepseek", "deepseek-flash", Vec::new())
            .parse_response(&response)
            .expect_err("a content-filtered reply must not pass as success");
        assert!(
            error.to_string().contains("no text content"),
            "for {content:?} the cause must be named: {error}"
        );
    }
}

#[test]
fn an_empty_candidates_array_is_a_typed_error() {
    // upstream v2.5.6 fix (`resp.candidates[0].content.parts[0]`, `:111`).
    for body in [
        serde_json::json!({"candidates": []}),
        serde_json::json!({"candidates": [{"content": {"parts": []}}]}),
        serde_json::json!({"candidates": [{"content": {}}]}),
    ] {
        let response = json_response(200, body.clone());
        let error = provider("gemini", "gemini-3-pro", Vec::new())
            .parse_response(&response)
            .expect_err("no text in the candidate");
        assert!(
            error.to_string().contains("no text content"),
            "for {body} the cause must be named: {error}"
        );
    }
}

// ---------------------------------------------------------------------------
// Status and JSON failures
// ---------------------------------------------------------------------------

#[test]
fn a_non_2xx_response_is_a_typed_error_carrying_the_status() {
    let response = raw_response(404, "{\"error\":{\"message\":\"model not found\"}}");
    let error = provider("deepseek", "deepseek-flash", Vec::new())
        .parse_response(&response)
        .expect_err("a 404 is a provider error");

    let message = error.to_string();
    assert!(message.contains("404"), "{message}");
    assert!(message.contains("Not Found"), "{message}");
    assert!(
        message.contains("model not found"),
        "the body explains the failure and must be quoted: {message}"
    );
}

#[test]
fn an_error_body_snippet_is_bounded() {
    let huge = "e".repeat(64 * 1024);
    let response = raw_response(500, &huge);
    let error = provider("openai", "gpt-4o", Vec::new())
        .parse_response(&response)
        .expect_err("a 500 is a provider error");

    let message = error.to_string();
    assert!(
        message.len() < 2048,
        "a provider error must not paste a whole error page into a log line: {} bytes",
        message.len()
    );
    assert!(message.contains("500"), "{message}");
}

#[test]
fn malformed_json_is_a_typed_error() {
    let response = raw_response(200, "{\"choices\": [ this is not json");
    let error = provider("openai", "gpt-4o", Vec::new())
        .parse_response(&response)
        .expect_err("the body is not JSON");
    assert!(
        error.to_string().contains("not the expected"),
        "the cause must be named: {error}"
    );
}

#[test]
fn a_json_document_of_the_wrong_shape_is_a_typed_error() {
    // `200 OK` with an error document is a real provider behaviour.
    let response = json_response(200, serde_json::json!({"error": "rate limited"}));
    let error = provider("openai", "gpt-4o", Vec::new())
        .parse_response(&response)
        .expect_err("a success status is not a guarantee of a completion");
    assert!(error.to_string().contains("empty choices array"), "{error}");
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

#[test]
fn a_missing_api_key_environment_variable_is_a_typed_error_naming_it() {
    // A single test touches the process environment, so it is serialized by
    // construction: nothing else in this file sets or removes a variable.
    let variable = "NAU_TEST_PROVIDER_API_KEY_THAT_IS_DEFINITELY_UNSET";
    assert!(
        std::env::var(variable).is_err(),
        "this test requires `{variable}` to be unset"
    );

    let mut profile = profile_for("deepseek");
    profile.api_key_env = Some(variable.to_string());
    let sut = HttpProvider::new(
        profile,
        "deepseek-flash",
        RecordingTransport::with_responses(vec![json_response(
            200,
            serde_json::json!({"choices": [{"message": {"content": "unreachable"}}]}),
        )]),
    )
    .expect("constructs");

    let error = sut.api_key().expect_err("the variable is unset");
    let message = error.to_string();
    assert!(
        message.contains(variable),
        "the error must name the variable: {message}"
    );
    assert!(message.contains("deepseek"), "and the provider: {message}");

    // The transport must not have been touched: no unauthenticated request may
    // ever leave.
    assert_eq!(sut.transport().call_count(), 0);
}

#[test]
fn an_empty_api_key_environment_variable_is_refused() {
    let variable = "NAU_TEST_PROVIDER_API_KEY_THAT_IS_EMPTY";
    // This is the only place in the crate that writes the environment, and it is
    // confined to a test binary whose other env-touching test uses a *different*
    // variable name, so the two cannot interfere.
    std::env::set_var(variable, "   ");

    let mut profile = profile_for("openai");
    profile.api_key_env = Some(variable.to_string());
    let sut = HttpProvider::new(profile, "gpt-4o", RecordingTransport::new()).expect("constructs");

    let error = sut.api_key().expect_err("whitespace is not a credential");
    assert!(error.to_string().contains(variable), "{error}");
    std::env::remove_var(variable);
}

#[test]
fn the_provider_never_holds_the_key_it_sends() {
    // The key is passed straight through to `build_request`, so a `Debug` print
    // of the provider cannot leak it.
    let mut profile = profile_for("deepseek");
    profile.api_key_env = Some("NAU_TEST_PROVIDER_API_KEY_FOR_DEBUGGING".to_string());
    std::env::set_var("NAU_TEST_PROVIDER_API_KEY_FOR_DEBUGGING", TEST_KEY);

    let sut = HttpProvider::new(profile, "deepseek-flash", RecordingTransport::new()).expect("ok");
    let printed = format!("{sut:?}");
    assert!(
        !printed.contains(TEST_KEY),
        "the provider must not print its credential: {printed}"
    );
    assert!(printed.contains("deepseek"), "{printed}");

    // A built request, however, *does* carry the credential in a header — and its
    // own `Debug` must redact it.
    let built = sut
        .build_request(&request("deepseek-flash"), TEST_KEY)
        .expect("builds");
    let request_debug = format!("{built:?}");
    assert!(
        !request_debug.contains(TEST_KEY),
        "a request print must redact the credential: {request_debug}"
    );
    assert!(request_debug.contains("<redacted>"), "{request_debug}");

    std::env::remove_var("NAU_TEST_PROVIDER_API_KEY_FOR_DEBUGGING");
}

#[test]
fn an_empty_base_url_is_refused_before_any_transport_call() {
    let mut profile = profile_for("openai");
    profile.base_url = "   ".to_string();
    let sut = HttpProvider::new(profile, "gpt-4o", RecordingTransport::new()).expect("constructs");

    let error = sut
        .build_request(&request("gpt-4o"), TEST_KEY)
        .expect_err("there is no endpoint to call");
    assert!(error.to_string().contains("base_url"), "{error}");
}

#[test]
fn the_base_url_version_segment_is_never_duplicated() {
    // The `base_url` version segment is never duplicated: anthropic's catalog
    // base already ends in `/v1`.
    let built = provider("anthropic", "claude-sonnet-4-6", Vec::new())
        .build_request(&request("claude-sonnet-4-6"), TEST_KEY)
        .expect("builds");
    assert_eq!(built.url, "https://api.anthropic.com/v1/messages");
    assert!(!built.url.contains("/v1/v1/"), "{}", built.url);

    // Gemini's already ends in `/v1beta`.
    let built = provider("gemini", "gemini-3-pro", Vec::new())
        .build_request(&request("gemini-3-pro"), TEST_KEY)
        .expect("builds");
    assert!(!built.url.contains("/v1beta/v1beta/"), "{}", built.url);

    // A base with no version segment gets one.
    let mut profile = profile_for("anthropic");
    profile.base_url = "https://gateway.internal/anthropic".to_string();
    let sut = HttpProvider::new(profile, "claude-sonnet-4-6", RecordingTransport::new())
        .expect("constructs");
    let built = sut
        .build_request(&request("claude-sonnet-4-6"), TEST_KEY)
        .expect("builds");
    assert_eq!(built.url, "https://gateway.internal/anthropic/v1/messages");
}

// ---------------------------------------------------------------------------
// The full port path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn chat_through_the_port_returns_a_parsed_completion() {
    let response = json_response(
        200,
        serde_json::json!({
            "model": "deepseek-flash",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "The escrow ledger."},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 42, "completion_tokens": 7}
        }),
    );
    let mut profile = profile_for("deepseek");
    profile.api_key_env = Some("NAU_TEST_PROVIDER_API_KEY_FOR_CHAT".to_string());
    std::env::set_var("NAU_TEST_PROVIDER_API_KEY_FOR_CHAT", TEST_KEY);

    let sut = HttpProvider::new(
        profile,
        "deepseek-flash",
        RecordingTransport::with_responses(vec![response]),
    )
    .expect("constructs");

    let parsed = sut
        .chat(request("deepseek-flash"))
        .await
        .expect("the port produces a completion");

    assert_eq!(parsed.content, "The escrow ledger.");
    assert_eq!(parsed.prompt_tokens, 42);
    assert_eq!(parsed.completion_tokens, 7);
    assert_eq!(parsed.finish_reason, "stop");

    // The recorded request proves the credential header really was set and that
    // the body was the provider's own shape.
    let recorded = sut.transport().request(0).expect("one request was sent");
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.url, "https://api.deepseek.com/chat/completions");
    assert_eq!(
        header_of(&recorded, "authorization"),
        Some("Bearer sk-test-not-a-real-key")
    );
    assert_eq!(body_of(&recorded)["model"], Value::from("deepseek-flash"));

    std::env::remove_var("NAU_TEST_PROVIDER_API_KEY_FOR_CHAT");
}

#[tokio::test]
async fn every_failure_mode_of_chat_is_an_error_and_none_is_a_panic() {
    let cases: Vec<(&str, &str, HttpResponse, &str)> = vec![
        (
            "openai",
            "gpt-4o",
            raw_response(401, "{\"error\":{\"message\":\"invalid api key\"}}"),
            "401",
        ),
        (
            "deepseek",
            "deepseek-flash",
            json_response(200, serde_json::json!({"choices": []})),
            "empty choices array",
        ),
        (
            "openai",
            "gpt-4o",
            json_response(
                200,
                serde_json::json!({"choices": [{"message": {"content": ""}}]}),
            ),
            "no text content",
        ),
        (
            "openai",
            "gpt-4o",
            raw_response(200, "not json at all"),
            "not the expected",
        ),
        (
            "gemini",
            "gemini-3-pro",
            json_response(200, serde_json::json!({"candidates": []})),
            "no text content",
        ),
    ];

    for (name, model, response, expected) in cases {
        let mut profile = profile_for(name);
        profile.api_key_env = Some("NAU_TEST_PROVIDER_API_KEY_FOR_FAILURES".to_string());
        std::env::set_var("NAU_TEST_PROVIDER_API_KEY_FOR_FAILURES", TEST_KEY);
        let sut = HttpProvider::new(
            profile,
            model,
            RecordingTransport::with_responses(vec![response]),
        )
        .expect("constructs");

        let text = chat_error_text(&sut, request(model)).await;
        assert!(
            text.contains(expected),
            "for `{name}` the error should mention `{expected}`, saw: {text}"
        );
    }
    std::env::remove_var("NAU_TEST_PROVIDER_API_KEY_FOR_FAILURES");
}

#[tokio::test]
async fn a_transport_fault_reaches_the_caller_as_a_typed_port_error() {
    // No queued response: the recording transport reports a typed error, and the
    // port must surface it rather than panicking.
    let mut profile = profile_for("deepseek");
    profile.api_key_env = Some("NAU_TEST_PROVIDER_API_KEY_FOR_TRANSPORT".to_string());
    std::env::set_var("NAU_TEST_PROVIDER_API_KEY_FOR_TRANSPORT", TEST_KEY);
    let sut = HttpProvider::new(profile, "deepseek-flash", RecordingTransport::new())
        .expect("constructs");

    let text = chat_error_text(&sut, request("deepseek-flash")).await;
    assert!(
        text.contains("the request to"),
        "the transport failure must be reported: {text}"
    );
    std::env::remove_var("NAU_TEST_PROVIDER_API_KEY_FOR_TRANSPORT");
}

// ---------------------------------------------------------------------------
// End to end over a real socket
// ---------------------------------------------------------------------------

/// Read one HTTP/1.1 request: head, plus `Content-Length` bytes of body.
async fn read_request(socket: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = socket.read(&mut byte).await.expect("read head");
        if read == 0 {
            break;
        }
        head.push(byte[0]);
        assert!(head.len() < 64 * 1024, "the request head is unbounded");
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let length = text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if length > 0 {
        socket.read_exact(&mut body).await.expect("read body");
    }
    format!("{text}{}", String::from_utf8_lossy(&body))
}

/// Start a loopback stub that answers one request with `response` and returns
/// what it received.
async fn spawn_stub(
    response: impl Into<Vec<u8>> + Send + 'static,
) -> (u16, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();
    let response = response.into();
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let seen = read_request(&mut socket).await;
        socket.write_all(&response).await.expect("write");
        socket.flush().await.expect("flush");
        let _ = socket.shutdown().await;
        seen
    });
    (port, handle)
}

#[tokio::test]
async fn the_whole_path_works_over_a_real_loopback_socket() {
    let body = "{\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\
                \"message\":{\"role\":\"assistant\",\"content\":\"live over TCP\"},\
                \"finish_reason\":\"stop\"}],\
                \"usage\":{\"prompt_tokens\":5,\"completion_tokens\":3}}";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (port, stub) = spawn_stub(response).await;

    // Point a real provider at the loopback stub instead of a vendor.
    let mut profile = profile_for("openai");
    profile.base_url = format!("http://127.0.0.1:{port}");
    profile.api_key_env = Some("NAU_TEST_PROVIDER_API_KEY_FOR_E2E".to_string());
    std::env::set_var("NAU_TEST_PROVIDER_API_KEY_FOR_E2E", TEST_KEY);

    let sut = HttpProvider::new(
        profile,
        "gpt-4o-mini",
        nau_http::TcpTransport::builder()
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(5))
            .build()
            .expect("limits are valid"),
    )
    .expect("constructs");

    let parsed = sut
        .chat(request("gpt-4o-mini"))
        .await
        .expect("the whole path works without a vendor");

    assert_eq!(parsed.content, "live over TCP");
    assert_eq!(parsed.prompt_tokens, 5);
    assert_eq!(parsed.completion_tokens, 3);
    assert_eq!(parsed.model, "gpt-4o-mini");

    // The stub saw the real wire form: method, path, credential header and body.
    let seen = stub.await.expect("stub task");
    assert!(
        seen.starts_with("POST /chat/completions HTTP/1.1"),
        "unexpected request line: {seen}"
    );
    assert!(
        seen.contains("authorization: Bearer sk-test-not-a-real-key")
            || seen.contains("Authorization: Bearer sk-test-not-a-real-key"),
        "the credential must travel as a Bearer header: {seen}"
    );
    assert!(
        seen.contains("content-type: application/json")
            || seen.contains("Content-Type: application/json"),
        "{seen}"
    );
    assert!(
        seen.contains("\"model\":\"gpt-4o-mini\""),
        "the provider's own body shape must be on the wire: {seen}"
    );
    assert!(
        seen.contains("You are a careful agent."),
        "the system prompt must be on the wire: {seen}"
    );

    std::env::remove_var("NAU_TEST_PROVIDER_API_KEY_FOR_E2E");
}

#[tokio::test]
async fn a_real_socket_returning_an_error_status_is_a_typed_port_error() {
    // `{"error":"slow down"}` is exactly 21 bytes.
    let (port, _stub) = spawn_stub(
        "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 21\r\n\r\n{\"error\":\"slow down\"}",
    )
    .await;

    let mut profile = profile_for("deepseek");
    profile.base_url = format!("http://127.0.0.1:{port}");
    profile.api_key_env = Some("NAU_TEST_PROVIDER_API_KEY_FOR_E2E_429".to_string());
    std::env::set_var("NAU_TEST_PROVIDER_API_KEY_FOR_E2E_429", TEST_KEY);

    let sut = HttpProvider::new(profile, "deepseek-flash", nau_http::TcpTransport::new())
        .expect("constructs");

    let text = chat_error_text(&sut, request("deepseek-flash")).await;
    assert!(text.contains("429"), "{text}");
    assert!(text.contains("Too Many Requests"), "{text}");

    std::env::remove_var("NAU_TEST_PROVIDER_API_KEY_FOR_E2E_429");
}
