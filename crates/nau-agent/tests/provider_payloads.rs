//! Payload-shape tests for the live provider layer.
//!
//! These exist because upstream v2.8.2 *believed* it had fixed the LLM defects
//! (`grep 'GAP §'` hits 52 sites in its source) while the risk had only moved:
//!
//! 1. **An error became an answer.** Upstream's `chat()` still returns a
//!    non-`Result`, turning a failure into the string
//!    `format!("ERROR: llm request: {e}")` (`llm/adapter.rs:70-76`), which
//!    deliberation reads as a proposal it may vote for (`hetero_llm.rs:61-69`).
//!    [`an_error_is_never_returned_as_content`] asserts structurally that no
//!    failure of ours can be mistaken for an answer.
//! 2. **A real response could not be parsed.** Upstream's response structs
//!    require fields real providers omit (`AnContentBlock.text`, `GePart.text`,
//!    `OaChatResponse.id`/`usage`/`choices`), so the *whole envelope* failed —
//!    and the mocks always emitted the friendly shape, so its tests certified a
//!    decoder no real provider satisfies. Every test below feeds the shape a real
//!    vendor sends.
//! 3. **The adapter field was the concrete mock type**, so a real client could
//!    not be injected. [`a_real_transport_is_injectable`] defines its own
//!    transport in this test crate — something impossible if the field were
//!    `MockOpenAiClient`.
//! 4. **Non-finite floats.** This crate orders no float at all; the domain test
//!    proves that the JSON this layer accepts cannot carry a non-finite one.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use nau_agent::provider::{HttpProvider, ProviderError};
use nau_agent::{ChatMessage, ChatRequest, LlmProvider, ProviderProfile};
use nau_http::{Headers, HttpError, HttpRequest, HttpResponse, Result as HttpResult, Transport};
use serde_json::{json, Value};

/// The credential every test here uses. Never read from the environment.
const TEST_KEY: &str = "sk-payload-test";

/// The environment variable the fixtures read the key from.
const KEY_ENV: &str = "NAU_TEST_PROVIDER_PAYLOAD_KEY";

fn profile(name: &str, base_url: &str) -> ProviderProfile {
    ProviderProfile {
        name: name.to_string(),
        base_url: base_url.to_string(),
        models: vec![format!("{name}-model")],
        context_window: 128_000,
        api_key_env: Some(KEY_ENV.to_string()),
    }
}

fn set_key() {
    std::env::set_var(KEY_ENV, TEST_KEY);
}

fn request() -> ChatRequest {
    ChatRequest {
        model: "test-model".to_string(),
        messages: vec![ChatMessage::user("hello")],
        max_tokens: 64,
        temperature_milli: 0,
    }
}

fn json_response(status: u16, body: Value) -> HttpResponse {
    let bytes = serde_json::to_vec(&body).expect("fixture serialises");
    let mut headers = Headers::new();
    headers.push("Content-Type", "application/json");
    headers.push("Content-Length", bytes.len().to_string());
    HttpResponse {
        status,
        headers,
        body: bytes,
    }
}

fn raw_response(status: u16, body: &str) -> HttpResponse {
    let mut headers = Headers::new();
    headers.push("Content-Length", body.len().to_string());
    HttpResponse {
        status,
        headers,
        body: body.as_bytes().to_vec(),
    }
}

fn provider(name: &str, base: &str, responses: Vec<HttpResponse>) -> HttpProvider<TestTransport> {
    HttpProvider::new(
        profile(name, base),
        format!("{name}-model"),
        TestTransport::answering(responses),
    )
    .expect("the fixture profile names an api key variable")
}

// ---------------------------------------------------------------------------
// A transport defined *in the test crate*: proof that a real implementation can
// be injected.
// ---------------------------------------------------------------------------

/// A hand-written [`Transport`] that lives outside the library.
///
/// upstream v2.8.2 fix (finding 1): upstream's adapter field is
/// `client: MockOpenAiClient` (`llm/adapter.rs:44-47`), a concrete private type,
/// so no production client — and no test double of the caller's own — can be
/// substituted. This type compiles only because `HttpProvider<T>` is generic over
/// the port.
struct TestTransport {
    responses: Mutex<Vec<HttpResponse>>,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    /// When set, every call fails with this transport error instead of answering.
    failure: Option<&'static str>,
}

impl TestTransport {
    fn answering(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: Mutex::new(responses),
            requests: Arc::new(Mutex::new(Vec::new())),
            failure: None,
        }
    }

    fn failing(message: &'static str) -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
            requests: Arc::new(Mutex::new(Vec::new())),
            failure: Some(message),
        }
    }

    fn requests(&self) -> Vec<HttpRequest> {
        match self.requests.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

#[async_trait]
impl Transport for TestTransport {
    async fn execute(&self, request: HttpRequest) -> HttpResult<HttpResponse> {
        match self.requests.lock() {
            Ok(mut guard) => guard.push(request),
            Err(poisoned) => poisoned.into_inner().push(request),
        }
        if let Some(message) = self.failure {
            return Err(HttpError::MalformedHead(message.to_string()));
        }
        let mut guard = match self.responses.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_empty() {
            return Err(HttpError::MalformedHead("no response queued".to_string()));
        }
        Ok(guard.remove(0))
    }
}

#[tokio::test]
async fn a_real_transport_is_injectable() {
    set_key();
    let sut = provider(
        "deepseek",
        "https://api.deepseek.com",
        vec![json_response(
            200,
            json!({"choices": [{"message": {"content": "injected"}, "finish_reason": "stop"}]}),
        )],
    );

    let parsed = sut
        .chat(request())
        .await
        .expect("the injected transport answers");
    assert_eq!(parsed.content, "injected");
    assert_eq!(sut.transport().requests().len(), 1);

    // And a transport that reports a transport fault is surfaced, not swallowed.
    let broken = HttpProvider::new(
        profile("deepseek", "https://api.deepseek.com"),
        "deepseek-model",
        TestTransport::failing("the injected socket died"),
    )
    .expect("constructs");
    let error = broken
        .chat(request())
        .await
        .expect_err("a transport fault must reach the caller");
    assert!(error.to_string().contains("socket died"), "{error}");
}

// ---------------------------------------------------------------------------
// Finding 3: real payload shapes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_openai_tool_call_only_reply_is_typed_and_never_a_whole_envelope_failure() {
    set_key();
    // The exact shape `gpt-4o` sends when it decides to call a tool: `content`
    // is JSON `null` and the payload is in `tool_calls`. Upstream's
    // `OaChatResponse` requires `content: String`, so this failed the whole
    // envelope.
    let sut = provider(
        "openai",
        "https://api.openai.com/v1",
        vec![json_response(
            200,
            json!({
                "id": "chatcmpl-tool",
                "object": "chat.completion",
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "market_deposit", "arguments": "{}"}
                        }]
                    },
                    "finish_reason": "tool_calls"
                }]
                // no `usage`: some gateways omit it
            }),
        )],
    );

    let error = sut
        .chat(request())
        .await
        .expect_err("a tool-call-only reply is not a text answer");
    let text = error.to_string();
    assert!(
        text.contains("tool calls") && text.contains("market_deposit"),
        "the failure must name the tool the model asked for: {text}"
    );
    assert!(
        !text.contains("expected openai-compatible chat completion JSON"),
        "this is not a malformed envelope: {text}"
    );
}

#[tokio::test]
async fn an_anthropic_tool_use_block_with_no_text_is_typed() {
    set_key();
    let sut = provider(
        "anthropic",
        "https://api.anthropic.com",
        vec![json_response(
            200,
            json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-4-6",
                // `AnContentBlock.text` is a required `String` upstream, so this
                // whole document failed to deserialise.
                "content": [{
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "market_get_task",
                    "input": {"task_id": "t-1"}
                }],
                "stop_reason": "tool_use"
                // no `usage`
            }),
        )],
    );

    let error = sut
        .chat(request())
        .await
        .expect_err("a tool_use block carries no text");
    let text = error.to_string();
    assert!(
        text.contains("market_get_task"),
        "the tool name must be reported: {text}"
    );
    assert!(
        !text.contains("expected anthropic messages JSON"),
        "not an envelope failure: {text}"
    );
}

#[tokio::test]
async fn a_gemini_function_call_part_with_no_text_is_typed() {
    set_key();
    let sut = provider(
        "gemini",
        "https://generativelanguage.googleapis.com/v1beta",
        vec![json_response(
            200,
            json!({
                "candidates": [{
                    "content": {
                        "role": "model",
                        // `GePart.text` is a required `String` upstream.
                        "parts": [{"functionCall": {"name": "market_balance", "args": {}}}]
                    },
                    "finishReason": "STOP"
                }]
                // no `usageMetadata`, no `modelVersion`
            }),
        )],
    );

    let error = sut
        .chat(request())
        .await
        .expect_err("a functionCall part carries no text");
    let text = error.to_string();
    assert!(text.contains("market_balance"), "{text}");
    assert!(
        !text.contains("expected gemini generateContent JSON"),
        "not an envelope failure: {text}"
    );
}

#[tokio::test]
async fn a_reply_with_no_usage_and_no_id_still_parses() {
    set_key();
    // Some gateways answer without `id` and without `usage`. Upstream required
    // both, so a perfectly good completion failed the envelope.
    for (name, base, body, expected) in [
        (
            "openai",
            "https://api.openai.com/v1",
            json!({"choices": [{"message": {"role": "assistant", "content": "no usage here"}}]}),
            "no usage here",
        ),
        (
            "anthropic",
            "https://api.anthropic.com",
            json!({"content": [{"type": "text", "text": "no usage here"}], "role": "assistant"}),
            "no usage here",
        ),
        (
            "gemini",
            "https://generativelanguage.googleapis.com/v1beta",
            json!({"candidates": [{"content": {"parts": [{"text": "no usage here"}]}}]}),
            "no usage here",
        ),
    ] {
        let sut = provider(name, base, vec![json_response(200, body.clone())]);
        let parsed = sut
            .chat(request())
            .await
            .unwrap_or_else(|e| panic!("`{name}` must parse {body}: {e}"));
        assert_eq!(parsed.content, expected, "{name}");
        assert_eq!(
            parsed.prompt_tokens, 0,
            "`{name}`: an absent usage block is reported as zero, which is the only \
             value the port's `u32` token fields can carry"
        );
        assert_eq!(parsed.completion_tokens, 0, "{name}");
    }
}

#[tokio::test]
async fn a_reply_with_both_a_text_and_a_tool_use_block_returns_the_text() {
    set_key();
    // The order matters: upstream reads `content[0]` and requires `text`, so the
    // tool-first ordering is the one that breaks a reply which *does* contain an
    // answer. Both orders must yield the text.
    for blocks in [
        json!([
            {"type": "tool_use", "id": "toolu_1", "name": "search", "input": {}},
            {"type": "text", "text": "The escrow ledger."}
        ]),
        json!([
            {"type": "text", "text": "The escrow ledger."},
            {"type": "tool_use", "id": "toolu_1", "name": "search", "input": {}}
        ]),
    ] {
        let sut = provider(
            "anthropic",
            "https://api.anthropic.com",
            vec![json_response(
                200,
                json!({
                    "content": blocks,
                    "stop_reason": "tool_use",
                    "usage": {"input_tokens": 5, "output_tokens": 6}
                }),
            )],
        );
        let parsed = sut
            .chat(request())
            .await
            .expect("the text block is an answer");
        assert_eq!(parsed.content, "The escrow ledger.");
        assert_eq!(parsed.prompt_tokens, 5);
        assert_eq!(parsed.completion_tokens, 6);
    }

    // The same ordering hazard for Gemini parts.
    for parts in [
        json!([{"functionCall": {"name": "search", "args": {}}}, {"text": "The escrow ledger."}]),
        json!([{"text": "The escrow ledger."}, {"functionCall": {"name": "search", "args": {}}}]),
    ] {
        let sut = provider(
            "gemini",
            "https://generativelanguage.googleapis.com/v1beta",
            vec![json_response(
                200,
                json!({"candidates": [{"content": {"parts": parts}}]}),
            )],
        );
        let parsed = sut
            .chat(request())
            .await
            .expect("the text part is an answer");
        assert_eq!(parsed.content, "The escrow ledger.");
    }
}

#[tokio::test]
async fn blocks_without_text_are_skipped_rather_than_treated_as_the_answer() {
    set_key();
    // `thinking` and `inlineData` are real blocks that carry no `text`; they must
    // neither reject the reply nor be mistaken for content.
    let anthropic = provider(
        "anthropic",
        "https://api.anthropic.com",
        vec![json_response(
            200,
            json!({
                "content": [
                    {"type": "thinking", "thinking": "let me think"},
                    {"type": "text", "text": "   "},
                    {"type": "text", "text": "the real answer"}
                ]
            }),
        )],
    );
    assert_eq!(
        anthropic.chat(request()).await.expect("parses").content,
        "the real answer"
    );

    let gemini = provider(
        "gemini",
        "https://generativelanguage.googleapis.com/v1beta",
        vec![json_response(
            200,
            json!({
                "candidates": [{"content": {"parts": [
                    {"inlineData": {"mimeType": "image/png", "data": "AAAA"}},
                    {"text": "the real answer"}
                ]}}]
            }),
        )],
    );
    assert_eq!(
        gemini.chat(request()).await.expect("parses").content,
        "the real answer"
    );
}

#[tokio::test]
async fn an_openai_part_array_content_form_is_read() {
    set_key();
    // Several OpenAI-compatible gateways return the part-array form of
    // `content`. Upstream's `String` field rejected it.
    let sut = provider(
        "deepseek",
        "https://api.deepseek.com",
        vec![json_response(
            200,
            json!({"choices": [{"message": {"content": [
                {"type": "text", "text": "part one"},
                {"type": "text", "text": "part two"}
            ]}}]}),
        )],
    );
    assert_eq!(
        sut.chat(request()).await.expect("parses").content,
        "part one"
    );
}

#[tokio::test]
async fn an_empty_reply_names_the_finish_reason() {
    set_key();
    // The finish reason is the only thing that distinguishes "the model had
    // nothing to say" from "the output cap truncated it".
    let sut = provider(
        "openai",
        "https://api.openai.com/v1",
        vec![json_response(
            200,
            json!({"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}),
        )],
    );
    let error = sut
        .chat(request())
        .await
        .expect_err("empty is not an answer");
    assert!(error.to_string().contains("length"), "{error}");
}

// ---------------------------------------------------------------------------
// Finding 2: an error can never become an answer
// ---------------------------------------------------------------------------

/// Assert every number in `value` is finite.
///
/// upstream v2.8.2 fix (finding 4): upstream orders caller-supplied `f64`
/// weights with `partial_cmp(..).unwrap()` (`hetero_llm.rs:68,100`), which panics
/// on `NaN`. Nothing in this layer computes with a float, and this walk proves
/// the values it hands to a caller cannot be non-finite either.
fn assert_all_numbers_finite(value: &Value, context: &str) {
    match value {
        Value::Number(number) => {
            let as_f64 = number.as_f64().unwrap_or(0.0);
            assert!(
                as_f64.is_finite(),
                "{context}: a non-finite number reached the caller: {number}"
            );
        }
        Value::Array(items) => {
            for item in items {
                assert_all_numbers_finite(item, context);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                assert_all_numbers_finite(item, context);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn the_json_this_layer_accepts_cannot_carry_a_non_finite_number() {
    set_key();
    // Neither the parser nor the number type can represent `NaN`/`Infinity`:
    // `serde_json` refuses the JSON literals, and `Number::from_f64` refuses the
    // values. That is *why* there is no ordering of a non-finite float anywhere in
    // this layer, and the assertion pins the property rather than the assumption.
    for hostile in ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"] {
        assert!(
            serde_json::from_str::<Value>(hostile).is_err(),
            "`{hostile}` must not be a JSON value"
        );
    }
    assert!(serde_json::Number::from_f64(f64::NAN).is_none());
    assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());

    // And a hostile body is a typed error, never a panic and never a partial
    // answer: the whole document is rejected.
    for hostile in ["NaN", "Infinity", "1e999"] {
        let body = format!(
            "{{\"choices\":[{{\"message\":{{\"content\":\"ok\"}}}}],\"usage\":{{\"prompt_tokens\":{hostile}}}}}"
        );
        let sut = provider(
            "openai",
            "https://api.openai.com/v1",
            vec![raw_response(200, &body)],
        );
        match sut.chat(request()).await {
            Err(error) => assert!(
                error.to_string().contains("not the expected"),
                "`{hostile}` must be a typed JSON failure: {error}"
            ),
            // A provider that *did* parse the document must not have produced a
            // non-finite number anywhere.
            Ok(response) => assert!(
                (response.prompt_tokens as f64).is_finite(),
                "`{hostile}` produced a non-finite count"
            ),
        }
    }
}

#[tokio::test]
async fn a_built_request_contains_no_non_finite_number_and_no_float_weight() {
    set_key();
    for (name, base) in [
        ("openai", "https://api.openai.com/v1"),
        ("anthropic", "https://api.anthropic.com"),
        ("gemini", "https://generativelanguage.googleapis.com/v1beta"),
    ] {
        let sut = provider(name, base, Vec::new());
        let built = sut
            .build_request(&request(), TEST_KEY)
            .expect("the request builds");
        let body: Value = serde_json::from_slice(built.body.as_deref().expect("a body"))
            .expect("the body is JSON");
        assert_all_numbers_finite(&body, name);
        // The temperature is the only fractional value this layer ever sends, and
        // it is formatted from an integer in milli-units.
        let text = String::from_utf8(built.body.expect("a body")).expect("utf-8");
        assert!(
            !text.contains("NaN") && !text.contains("Infinity"),
            "{name} sent a non-finite literal: {text}"
        );
    }
}

/// Every failure mode, as the payloads that produce it.
fn failure_modes() -> Vec<(&'static str, &'static str, HttpResponse)> {
    vec![
        (
            "openai",
            "https://api.openai.com/v1",
            raw_response(401, "{\"error\":{\"message\":\"invalid api key\"}}"),
        ),
        (
            "openai",
            "https://api.openai.com/v1",
            json_response(200, json!({"choices": []})),
        ),
        (
            "openai",
            "https://api.openai.com/v1",
            json_response(200, json!({"choices": [{"message": {"content": ""}}]})),
        ),
        (
            // The tool-call-only reply: a failure that upstream's non-`Result`
            // `chat()` would have turned into a string the deliberator can vote for.
            "openai",
            "https://api.openai.com/v1",
            json_response(
                200,
                json!({"choices": [{"message": {"content": null, "tool_calls": [
                    {"id": "c1", "function": {"name": "deposit", "arguments": "{}"}}
                ]}}]}),
            ),
        ),
        (
            "openai",
            "https://api.openai.com/v1",
            raw_response(200, "this is not json"),
        ),
        (
            "anthropic",
            "https://api.anthropic.com",
            json_response(200, json!({"content": [], "stop_reason": "tool_use"})),
        ),
        (
            "anthropic",
            "https://api.anthropic.com",
            json_response(
                200,
                json!({"content": [{"type": "tool_use", "name": "search", "input": {}}]}),
            ),
        ),
        (
            "gemini",
            "https://generativelanguage.googleapis.com/v1beta",
            json_response(200, json!({"candidates": []})),
        ),
        (
            "gemini",
            "https://generativelanguage.googleapis.com/v1beta",
            json_response(
                200,
                json!({"candidates": [{"content": {"parts": [{"functionCall": {"name": "x"}}]}}]}),
            ),
        ),
        (
            "gemini",
            "https://generativelanguage.googleapis.com/v1beta",
            json_response(200, json!({"promptFeedback": {"blockReason": "SAFETY"}})),
        ),
    ]
}

#[tokio::test]
async fn an_error_is_never_returned_as_content() {
    set_key();
    // The structural claim of finding 2: **every** failure path returns `Err`, and
    // an `Err` can never be observed as a `ChatResponse`. Upstream instead built
    // `Ok(ChatResponse { content: format!("ERROR: llm request: {e}") })`-shaped
    // data and deliberation voted on it.
    for (name, base, response) in failure_modes() {
        let sut = provider(name, base, vec![response]);
        match sut.chat(request()).await {
            Ok(response) => panic!(
                "`{name}` turned a failure into an answer: {response:?} — this is the upstream \
                 defect, where an error string becomes a votable proposal"
            ),
            Err(error) => {
                let text = error.to_string();
                assert!(!text.is_empty(), "`{name}`: an error must explain itself");
                assert!(
                    !text.starts_with("ERROR: llm request"),
                    "`{name}`: the upstream error-as-string shape must not exist: {text}"
                );
            }
        }
    }
}

#[tokio::test]
async fn an_ok_completion_always_carries_non_blank_content() {
    set_key();
    // The other half of the same claim: no success value can be an empty answer,
    // so a caller that only ever sees `Ok` never has to ask whether the model
    // actually said anything.
    for (name, base, body) in [
        (
            "openai",
            "https://api.openai.com/v1",
            json!({"choices": [{"message": {"content": "  padded  "}}]}),
        ),
        (
            "anthropic",
            "https://api.anthropic.com",
            json!({"content": [{"type": "text", "text": "  padded  "}]}),
        ),
        (
            "gemini",
            "https://generativelanguage.googleapis.com/v1beta",
            json!({"candidates": [{"content": {"parts": [{"text": "  padded  "}]}}]}),
        ),
    ] {
        let sut = provider(name, base, vec![json_response(200, body)]);
        let response = sut.chat(request()).await.expect("a real answer");
        assert!(
            !response.content.trim().is_empty(),
            "`{name}` returned Ok with blank content"
        );
        assert_eq!(response.content, "  padded  ");
    }
}

#[tokio::test]
async fn the_tool_call_only_error_is_a_distinct_typed_variant() {
    set_key();
    // A caller can branch on this: "the model wants to call a tool" is actionable,
    // "the completion was empty" is not. Structural, not string matching.
    let sut = provider(
        "openai",
        "https://api.openai.com/v1",
        vec![json_response(
            200,
            json!({"choices": [{"message": {"content": null, "tool_calls": [
                {"id": "c1", "function": {"name": "z_tool", "arguments": "{}"}},
                {"id": "c2", "function": {"name": "a_tool", "arguments": "{}"}}
            ]}}]}),
        )],
    );
    let error = sut
        .parse_response(&json_response(
            200,
            json!({"choices": [{"message": {"content": null, "tool_calls": [
                {"id": "c1", "function": {"name": "z_tool", "arguments": "{}"}},
                {"id": "c2", "function": {"name": "a_tool", "arguments": "{}"}}
            ]}}]}),
        ))
        .expect_err("tool calls only");
    match error.downcast_ref::<ProviderError>() {
        Some(ProviderError::ToolCallOnly { shape, tools, .. }) => {
            assert_eq!(*shape, "tool_calls");
            assert_eq!(
                tools,
                &vec!["a_tool".to_string(), "z_tool".to_string()],
                "the tool names are sorted, so the error is stable"
            );
        }
        other => panic!("expected ToolCallOnly, got {other:?}"),
    }
    // The same call through the port is an `Err`.
    assert!(sut.chat(request()).await.is_err());
}
