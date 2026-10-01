//! The live provider layer: a real `HttpProvider` behind the [`LlmProvider`]
//! port, one request/response shape per vendor family, and errors that name the
//! cause instead of panicking.
//!
//! [`LlmProvider`]: crate::llm::LlmProvider
//!
//! ## upstream v2.5.6 fix set covered here
//!
//! 1. **There was no HTTP client and no live path.** `gsn-core/Cargo.toml`
//!    declares no HTTP dependency at all, and all six providers were
//!    `Mock*Client`s returning a fixed string, so `LlmBackend` / `LlmResult`
//!    could never be produced by a real exchange. [`HttpProvider`] drives a real
//!    [`nau_http::Transport`].
//! 2. **Every provider error was an unconditional panic.** Each adapter called
//!    `.unwrap()` on the client result inside a function returning a non-`Result`
//!    type. Every method here is fallible and returns a typed error.
//! 3. **Responses were indexed unchecked**, `resp.choices[0]`,
//!    `resp.candidates[0].content.parts[0]` and `resp.content[0]`, so an empty
//!    completion — content filter, tool-only reply, empty array — panicked. This
//!    module uses `.first()` and reports
//!    [`ProviderError::EmptyCompletion`] /
//!    [`ProviderError::EmptyChoices`] instead.
//! 4. **No header mechanism existed for a key.** Nothing in the upstream tree
//!    could set `Authorization`, `x-api-key` or `anthropic-version`.
//!    [`HttpProvider::build_request`] sets the right one per provider shape, and
//!    the key is read from the environment variable
//!    [`ProviderProfile::api_key_env`] names.
//! 5. **`DeepSeekConfig.api_key_env` was stored and never read.** Here a profile
//!    without a usable `api_key_env` cannot even construct a provider, and a
//!    missing variable is [`ProviderError::MissingApiKey`], never a silent
//!    unauthenticated call.
//!
//! ## upstream v2.8.2 fix set covered here (the *remaining* upstream defects)
//!
//! upstream's v2.8.2 attempt at these defects is incomplete in ways that move the
//! risk rather than remove it. Three of them land in this module:
//!
//! 1. **An error could become a legitimate answer.** Upstream's `chat()` still
//!    returns a non-`Result` type and turns a failure into the string
//!    `format!("ERROR: llm request: {e}")` (`llm/adapter.rs:70-76`), which
//!    deliberation reads as a *proposal it can vote for*
//!    (`hetero_llm.rs:61-69`). Every method here is `Result`-returning and
//!    [`HttpProvider::chat`] has no path that produces an `Ok` without a
//!    non-empty completion — see `tests/provider_payloads.rs`, which asserts that
//!    structurally over every failure mode.
//! 2. **A real provider response could not be parsed.** Upstream's response
//!    structs require fields real providers omit (`AnContentBlock.text`,
//!    `GePart.text`, `OaChatResponse.id`/`usage`/`choices`), so a tool-call-only
//!    reply (`"content": null` + `tool_calls`), a `tool_use`/`functionCall` block
//!    or a response with no `usage` failed the *whole envelope*, and the mocks
//!    never produced one. Every decoder here reads a
//!    [`serde_json::Value`] field by field, scans a block array for the first
//!    text-bearing block instead of indexing `[0]`, and reports a tool-call-only
//!    reply as the typed [`ProviderError::ToolCallOnly`] rather than collapsing it
//!    into "empty".
//! 3. **Non-finite floats.** Upstream orders caller-supplied `f64` weights with
//!    `partial_cmp(..).unwrap()` (`hetero_llm.rs:68,100`), which panics on `NaN`.
//!    This module contains no float arithmetic at all:
//!    [`ChatRequest::temperature_milli`] is an integer, and the token counts are
//!    read with [`unsigned_field`], so no externally supplied float is ever
//!    ordered, compared or converted here.
//!
//! [`ChatRequest::temperature_milli`]: crate::llm::ChatRequest::temperature_milli
//!
//! ## What is verified here
//!
//! Everything except a real vendor: request construction and response parsing
//! for all three shapes are tested against [`nau_http::RecordingTransport`], and
//! the whole path is driven end to end once over a real loopback TCP socket.
//! No test in this crate contacts a vendor, and nothing here is a stub.

use std::env;

use async_trait::async_trait;
use nau_core::NauError;

use crate::llm::{ChatRequest, ChatResponse, ChatRole, LlmProvider, ProviderProfile};

pub mod anthropic;
pub mod gemini;
pub mod openai;

/// The request/response shape a provider speaks.
///
/// The three variants are genuinely different protocols, not configuration of
/// one: they disagree about the endpoint path, the credential header, where the
/// system prompt goes, how the output cap is named, and where the generated text
/// lives in the response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProviderKind {
    /// `POST {base}/chat/completions`, `Authorization: Bearer <key>`,
    /// `choices[0].message.content`, `usage.{prompt,completion}_tokens`.
    ///
    /// Covers openai, deepseek, doubao and every other OpenAI-compatible vendor.
    OpenAiCompatible,
    /// `POST {base}/v1/messages`, `x-api-key` + `anthropic-version`, the system
    /// prompt as a top-level field, `content[0].text`,
    /// `usage.{input,output}_tokens`.
    Anthropic,
    /// `POST {base}/models/{model}:generateContent?key=<key>`, the system prompt
    /// as `systemInstruction`, `candidates[0].content.parts[0].text`,
    /// `usageMetadata.{promptTokenCount,candidatesTokenCount}`.
    Gemini,
}

impl ProviderKind {
    /// Classify a provider by the name in its [`ProviderProfile`].
    ///
    /// Unknown names are OpenAI-compatible, because that is the shape the
    /// ecosystem has standardised on and the one a self-hosted gateway will
    /// speak. The classification is available as data, so a caller can assert
    /// which shape it got rather than discovering it from a failed request.
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => Self::Anthropic,
            "gemini" | "google" | "google-gemini" => Self::Gemini,
            _ => Self::OpenAiCompatible,
        }
    }

    /// A stable label, for logs and assertions.
    pub fn label(&self) -> &'static str {
        match self {
            Self::OpenAiCompatible => "openai-compatible",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
        }
    }

    /// The name [`LlmProvider::name`] reports for this shape.
    ///
    /// It names the **protocol**, not the vendor: the port's `name` is
    /// `'static`, and a provider configured for a self-hosted gateway must not
    /// claim to be a specific vendor.
    ///
    /// [`LlmProvider::name`]: crate::llm::LlmProvider::name
    pub fn provider_name(&self) -> &'static str {
        match self {
            Self::OpenAiCompatible => "openai",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
        }
    }
}

/// Everything this layer can fail at.
///
/// Every variant is reachable and every one names its cause. There is no
/// `unwrap()` anywhere in this module, which is the point: upstream's adapter
/// panics were the defect.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// [`ProviderProfile::api_key_env`] is `None`, so no variable can be read.
    #[error(
        "provider `{provider}` has no api_key_env, so no credential can be resolved; set one \
         rather than sending an unauthenticated request"
    )]
    MissingApiKeyEnv {
        /// The provider's name.
        provider: String,
    },

    /// The environment variable named by the profile is not set.
    #[error(
        "environment variable `{variable}` is not set, so provider `{provider}` has no API key"
    )]
    MissingApiKey {
        /// The provider's name.
        provider: String,
        /// The variable that was consulted.
        variable: String,
    },

    /// The environment variable is set but empty.
    #[error("environment variable `{variable}` is set but empty, so provider `{provider}` has no API key")]
    EmptyApiKey {
        /// The provider's name.
        provider: String,
        /// The variable that was consulted.
        variable: String,
    },

    /// The transport itself failed: no connection, a timeout, a truncated body.
    #[error("the request to `{url}` failed: {source}")]
    Http {
        /// The URL that was attempted.
        url: String,
        /// The transport's typed error.
        #[source]
        source: nau_http::HttpError,
    },

    /// The provider answered with a non-2xx status.
    ///
    /// The status, its reason phrase, and a **bounded** excerpt of the body are
    /// carried, because a provider's error document is the only explanation of
    /// what went wrong.
    #[error("provider `{provider}` returned HTTP {status} {reason}: {snippet}")]
    HttpStatus {
        /// The provider's name.
        provider: String,
        /// The status code.
        status: u16,
        /// The reason phrase sent with it, or a standard one.
        reason: &'static str,
        /// A bounded, single-line excerpt of the error body.
        snippet: String,
    },

    /// The body was not JSON, or not the JSON shape this provider family sends.
    #[error(
        "provider `{provider}` returned a body that is not the expected {kind} JSON: {source}"
    )]
    MalformedJson {
        /// The provider's name.
        provider: String,
        /// The shape that was expected.
        kind: &'static str,
        /// The deserialization failure.
        #[source]
        source: serde_json::Error,
    },

    /// The `choices` array was empty or absent. Upstream indexed `[0]` here.
    #[error(
        "provider `{provider}` returned an empty choices array, so there is no completion to read"
    )]
    EmptyChoices {
        /// The provider's name.
        provider: String,
    },

    /// The completion exists but carries no text at all. Upstream indexed
    /// `[0]` here too, and a content filter or an empty reply is exactly when it
    /// fired.
    #[error("provider `{provider}` returned a successful response with no text content: {detail}")]
    EmptyCompletion {
        /// The provider's name.
        provider: String,
        /// Which field was empty, and why it was empty.
        detail: String,
    },

    /// The reply consisted only of tool calls, with no text block anywhere.
    ///
    /// upstream v2.8.2 fix (finding 3): upstream's structs make this a whole
    /// envelope deserialization failure, because `content` is a required string
    /// for OpenAI and `text` is required on every Anthropic content block and
    /// every Gemini part. It is not a parse failure — the provider answered
    /// exactly as designed — and it is not an empty completion either:
    ///
    /// * it is **not** `Ok`, because [`ChatResponse`] has no field a tool call
    ///   could travel in, and returning `Ok` with empty content is how an error
    ///   becomes a legitimate answer that deliberation can vote for;
    /// * it is **not** `EmptyCompletion`, because the caller can act on this:
    ///   the tool names say what the model wanted to do.
    #[error(
        "provider `{provider}` answered with tool calls and no text ({shape}: {tools:?}); this port \
         cannot return a tool call, so the call is an error rather than an empty completion"
    )]
    ToolCallOnly {
        /// The provider's name.
        provider: String,
        /// The wire shape that carried the tool calls, e.g. `tool_calls`.
        shape: &'static str,
        /// The tool names the provider asked to call, in wire order.
        tools: Vec<String>,
    },
}

/// The result type used by [`HttpProvider`]'s explicit methods.
pub type ProviderResult<T> = std::result::Result<T, anyhow::Error>;

/// The standard reason phrase for a status code, for error messages.
pub(crate) fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

/// How many body bytes an error message may quote.
const ERROR_SNIPPET_BYTES: usize = 512;

/// A real provider behind the [`LlmProvider`] port, driven by an HTTP transport.
///
/// It **holds no secret**. The API key is read from the environment variable
/// named by [`ProviderProfile::api_key_env`] at call time, so a profile can be
/// logged, serialized and shipped without carrying a credential.
///
/// [`LlmProvider`]: crate::llm::LlmProvider
pub struct HttpProvider<T> {
    profile: ProviderProfile,
    kind: ProviderKind,
    name: &'static str,
    model: String,
    transport: T,
}

impl<T> std::fmt::Debug for HttpProvider<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The transport is deliberately not printed, and neither is any key:
        // this type never holds one. The profile is printed, which is why
        // `ProviderProfile` carries only a variable *name*.
        formatter
            .debug_struct("HttpProvider")
            .field("profile", &self.profile)
            .field("kind", &self.kind)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

impl<T: nau_http::Transport> HttpProvider<T> {
    /// Build a provider for `profile` and `model`.
    ///
    /// `transport` is the only way this type can reach the network; passing a
    /// [`nau_http::RecordingTransport`] makes every call deterministic and
    /// offline.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::MissingApiKeyEnv`] when the profile does not name
    /// an environment variable, because constructing a provider that can never
    /// authenticate only defers the failure to the first request.
    pub fn new(
        profile: ProviderProfile,
        model: impl Into<String>,
        transport: T,
    ) -> ProviderResult<Self> {
        if profile
            .api_key_env
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
        {
            return Err(ProviderError::MissingApiKeyEnv {
                provider: profile.name.clone(),
            }
            .into());
        }
        let kind = ProviderKind::from_name(&profile.name);
        Ok(Self {
            profile,
            kind,
            name: kind.provider_name(),
            model: model.into(),
            transport,
        })
    }

    /// The wire shape this provider speaks.
    pub fn kind(&self) -> ProviderKind {
        self.kind
    }

    /// The profile this provider was built from.
    pub fn profile(&self) -> &ProviderProfile {
        &self.profile
    }

    /// The model identifier sent in requests.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The environment variable the API key is read from.
    pub fn api_key_env(&self) -> Option<&str> {
        self.profile.api_key_env.as_deref()
    }

    /// The transport this provider sends through.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Read the API key from the environment.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::MissingApiKeyEnv`] when the profile names no
    /// variable, [`ProviderError::MissingApiKey`] when the variable is unset, and
    /// [`ProviderError::EmptyApiKey`] when it is set to nothing. Every case is a
    /// hard error: the alternative is an unauthenticated request that looks
    /// healthy and bills nobody.
    pub fn api_key(&self) -> ProviderResult<String> {
        let variable = self
            .profile
            .api_key_env
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| ProviderError::MissingApiKeyEnv {
                provider: self.profile.name.clone(),
            })?;
        match env::var(variable) {
            Ok(value) if !value.trim().is_empty() => Ok(value),
            Ok(_) => Err(ProviderError::EmptyApiKey {
                provider: self.profile.name.clone(),
                variable: variable.to_string(),
            }
            .into()),
            Err(_) => Err(ProviderError::MissingApiKey {
                provider: self.profile.name.clone(),
                variable: variable.to_string(),
            }
            .into()),
        }
    }

    /// Build the provider-specific request: endpoint, credential header and JSON
    /// body.
    ///
    /// `api_key` is passed in rather than read here so this method is pure and
    /// testable without touching the process environment.
    ///
    /// # Errors
    ///
    /// Returns an error when the base URL is empty, or when the request body
    /// cannot be serialized.
    pub fn build_request(
        &self,
        req: &ChatRequest,
        api_key: &str,
    ) -> ProviderResult<nau_http::HttpRequest> {
        let base = self.profile.base_url.trim().trim_end_matches('/');
        if base.is_empty() {
            return Err(anyhow::anyhow!(
                "provider `{}` has an empty base_url, so there is no endpoint to call",
                self.profile.name
            ));
        }
        match self.kind {
            ProviderKind::OpenAiCompatible => openai::build_request(self, base, req, api_key),
            ProviderKind::Anthropic => anthropic::build_request(self, base, req, api_key),
            ProviderKind::Gemini => gemini::build_request(self, base, req, api_key),
        }
    }

    /// Parse the provider-specific response.
    ///
    /// # Errors
    ///
    /// * [`ProviderError::HttpStatus`] for any non-2xx status, carrying the
    ///   status and a bounded body excerpt.
    /// * [`ProviderError::MalformedJson`] when the body is not the JSON shape of
    ///   this provider family.
    /// * [`ProviderError::EmptyChoices`] / [`ProviderError::EmptyCompletion`]
    ///   when the exchange succeeded but produced no text.
    pub fn parse_response(&self, resp: &nau_http::HttpResponse) -> ProviderResult<ChatResponse> {
        if !(200..300).contains(&resp.status) {
            return Err(ProviderError::HttpStatus {
                provider: self.profile.name.clone(),
                status: resp.status,
                reason: reason_phrase(resp.status),
                snippet: resp.body_snippet(ERROR_SNIPPET_BYTES),
            }
            .into());
        }
        match self.kind {
            ProviderKind::OpenAiCompatible => openai::parse_response(self, resp),
            ProviderKind::Anthropic => anthropic::parse_response(self, resp),
            ProviderKind::Gemini => gemini::parse_response(self, resp),
        }
    }
}

#[async_trait]
impl<T: nau_http::Transport + Send + Sync> LlmProvider for HttpProvider<T> {
    fn name(&self) -> &'static str {
        self.name
    }

    fn context_window(&self) -> u32 {
        // The window of the *requested* model when the catalog knows it, and the
        // profile's declared window otherwise: reporting another model's window
        // is how a request gets silently oversized.
        crate::llm::context_window_for(&self.model).unwrap_or(self.profile.context_window)
    }

    async fn chat(&self, req: ChatRequest) -> NauErrorResult<ChatResponse> {
        // upstream v2.5.6 fix: every failure below is returned, never
        // `unwrap`ped. The old adapters had no way to report any of this.
        let api_key = self.api_key().map_err(to_nau_error)?;
        let request = self.build_request(&req, &api_key).map_err(to_nau_error)?;
        let response = self.transport.execute(request).await.map_err(|source| {
            to_nau_error(
                ProviderError::Http {
                    url: self.profile.base_url.clone(),
                    source,
                }
                .into(),
            )
        })?;
        self.parse_response(&response).map_err(to_nau_error)
    }
}

/// The `nau_core` result type, aliased so the port's signature stays readable.
type NauErrorResult<T> = std::result::Result<T, NauError>;

/// Fold any error into the port's [`NauError`], preserving its message.
///
/// `NauError::Validation` carries the provider's own text, so the reason reaches
/// the caller instead of being flattened into a generic string. The whole
/// `anyhow` chain is rendered — provider error first, then the transport error
/// underneath it — so a caller sees both what failed and why.
fn to_nau_error(error: anyhow::Error) -> NauError {
    let mut rendered = error.to_string();
    for cause in error.chain().skip(1) {
        rendered.push_str(": ");
        rendered.push_str(&cause.to_string());
    }
    NauError::Validation(rendered)
}

// ---------------------------------------------------------------------------
// Shared helpers, used by every provider shape
// ---------------------------------------------------------------------------

/// A string field, or `None` when it is absent, `null`, or not a string.
pub(crate) fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_string)
}

/// The first non-blank `text` in an array of content blocks or parts.
///
/// upstream v2.8.2 fix (finding 3): a block array is **scanned**, never indexed
/// at `[0]`. A real reply may lead with a `tool_use`, `thinking`, `functionCall`
/// or `inlineData` block and carry the text in a later one, and indexing `[0]`
/// turned that perfectly good answer into a parse error. Upstream's `[0]`
/// indexing has the same defect one level up: it makes the *shape* of the reply
/// decide whether it can be read at all.
///
/// Blocks with no `text`, a `null` `text`, or a whitespace-only `text` are
/// skipped, so the returned slice is always [`has_content`].
pub(crate) fn first_text_in(blocks: &[serde_json::Value]) -> Option<&str> {
    blocks.iter().find_map(|block| {
        block
            .get("text")
            .and_then(|text| text.as_str())
            .filter(|text| has_content(text))
    })
}

/// The `name` of every block whose `type` is `type_value`, in wire order.
///
/// Used for the Anthropic `tool_use` block. A block with the right `type` but no
/// usable `name` still counts as a tool call, because the point of the list is to
/// prove that the reply was a tool call and not an empty completion; such a block
/// is reported as `"<unnamed>"` rather than being dropped.
pub(crate) fn blocks_of_type(blocks: &[serde_json::Value], type_value: &str) -> Vec<String> {
    blocks
        .iter()
        .filter(|block| block.get("type").and_then(|kind| kind.as_str()) == Some(type_value))
        .map(|block| {
            string_field(block, "name")
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| "<unnamed>".to_string())
        })
        .collect()
}

/// The `functionCall.name` of every Gemini part that carries one, in wire order.
///
/// A `functionCall` with no `name` is reported as `"<unnamed>"` for the same
/// reason as [`blocks_of_type`].
pub(crate) fn function_call_names(parts: &[serde_json::Value]) -> Vec<String> {
    parts
        .iter()
        .filter_map(|part| part.get("functionCall"))
        .map(|call| {
            string_field(call, "name")
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| "<unnamed>".to_string())
        })
        .collect()
}

/// The text of an OpenAI-compatible `content` field, which is *either* a string
/// or an array of `{"type":"text","text":...}` parts.
///
/// Both forms are in the wild: the chat-completions API sends a string, while
/// several gateways and the newer responses shape send the part array. Upstream's
/// `OaChatResponse` had one `String` field for it, so the array form failed the
/// whole envelope.
pub(crate) fn openai_content_text(content: &serde_json::Value) -> Option<&str> {
    if let Some(text) = content.as_str() {
        return has_content(text).then_some(text);
    }
    content.as_array().and_then(|parts| first_text_in(parts))
}

/// Render a `finish_reason`/`stop_reason` for an empty-completion message.
///
/// A provider that answers 200 with no text usually says *why* in this field —
/// `content_filter`, `length`, `SAFETY` — and that reason is the only thing that
/// distinguishes "the model had nothing to say" from "the request was truncated
/// at the output cap".
pub(crate) fn finish_note(finish_reason: Option<&str>) -> String {
    match finish_reason {
        Some(reason) if !reason.trim().is_empty() => format!(" (finish_reason: {reason})"),
        _ => String::new(),
    }
}

/// Turn a tool-call-only reply into the typed error that keeps it out of the
/// deliberation loop.
///
/// upstream v2.8.2 fix (finding 3): this is the single constructor of
/// [`ProviderError::ToolCallOnly`], so all three shapes report the same typed
/// outcome and none of them can degrade into an empty `Ok`.
pub(crate) fn tool_call_only(
    provider: &str,
    shape: &'static str,
    tools: Vec<String>,
) -> ProviderError {
    // A tool call with no name at all is still a tool call: the field that proves
    // the reply was not text is the presence of the call, not its name. Sorting
    // and deduplicating keeps the message stable for a caller that asserts on it.
    let mut tools = tools;
    tools.sort();
    tools.dedup();
    ProviderError::ToolCallOnly {
        provider: provider.to_string(),
        shape,
        tools,
    }
}

/// An unsigned field, accepting either a JSON integer or a numeric string.
///
/// Some gateways report token counts as strings; refusing those would turn a
/// perfectly good response into a parse error.
pub(crate) fn unsigned_field(value: &serde_json::Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    }
}

/// Clamp a token count into the `u32` the port uses.
pub(crate) fn clamp_tokens(value: u64) -> u32 {
    if value > u64::from(u32::MAX) {
        u32::MAX
    } else {
        value as u32
    }
}

/// Whether a completion carries any text at all.
///
/// Whitespace-only is treated as empty on purpose: a provider that answers with
/// `" "` has not answered, and passing that through as `ChatResponse.content`
/// would hand the caller an empty completion that looks successful.
pub(crate) fn has_content(text: &str) -> bool {
    !text.trim().is_empty()
}

/// The wire name of a role in the OpenAI-compatible shape.
pub(crate) fn role_label(role: ChatRole) -> &'static str {
    match role {
        ChatRole::System => "system",
        ChatRole::User => "user",
        ChatRole::Assistant => "assistant",
    }
}

/// The wire name of a role in the Gemini shape, which has no `system` role.
pub(crate) fn gemini_role(role: ChatRole) -> &'static str {
    match role {
        // A system message is never placed in `contents`; it becomes
        // `systemInstruction`. If one arrives here it is rendered as user text
        // rather than dropped.
        ChatRole::Assistant => "model",
        ChatRole::System | ChatRole::User => "user",
    }
}

/// The temperature as a JSON number in the `0.0..=1.0` range every vendor here
/// accepts.
///
/// [`ChatRequest::temperature_milli`] is an integer in milli-units
/// (`0..=1000`), so the fraction is formatted from integers — no `f64` is ever
/// computed, which keeps the request reproducible byte for byte.
///
/// [`ChatRequest::temperature_milli`]: crate::llm::ChatRequest::temperature_milli
pub(crate) fn temperature(req: &ChatRequest) -> serde_json::Value {
    let milli = req.temperature_milli.min(1000);
    if milli == 1000 {
        return serde_json::Value::from(1.0);
    }
    let text = format!("0.{milli:03}");
    // The formatted text is a valid JSON number by construction; the fallback is
    // unreachable but exists so this function cannot panic.
    serde_json::from_str(&text).unwrap_or_else(|_| serde_json::Value::from(0.0))
}

/// Join a base URL with the path a provider shape needs.
///
/// The seam exists because the seven profiles in [`crate::llm::known_profiles`]
/// are not consistent about where the version segment lives: anthropic ships
/// `https://api.anthropic.com/v1` while openai ships
/// `https://api.openai.com/v1` *and* gemini ships
/// `.../v1beta`. Appending blindly produces `/v1/v1/messages`, so a version
/// segment already present at the end of the base is not repeated.
///
/// [`crate::llm::known_profiles`]: crate::llm::known_profiles
pub(crate) fn endpoint(base: &str, version: Option<&str>, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let has_version = base
        .rsplit('/')
        .next()
        .is_some_and(looks_like_version_segment);
    match (has_version, version) {
        (true, _) => format!("{base}/{path}"),
        (false, Some(version)) => format!("{base}/{version}/{path}"),
        (false, None) => format!("{base}/{path}"),
    }
}

/// Whether a URL path segment looks like `v1`, `v2`, `v1beta`, `v1alpha`...
fn looks_like_version_segment(segment: &str) -> bool {
    let Some(rest) = segment.strip_prefix('v') else {
        return false;
    };
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    if digits == 0 {
        return false;
    }
    rest[digits..].chars().all(|c| c.is_ascii_alphabetic())
}

/// The response's own `model` field, or the requested one when it is absent.
pub(crate) fn reported_model(value: &serde_json::Value, requested: &str) -> String {
    string_field(value, "model").unwrap_or_else(|| requested.to_string())
}

/// Helper used by the per-shape parsers to turn a body into JSON.
pub(crate) fn parse_json(
    provider: &str,
    kind: &'static str,
    resp: &nau_http::HttpResponse,
) -> ProviderResult<serde_json::Value> {
    let value: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|source| ProviderError::MalformedJson {
            provider: provider.to_string(),
            kind,
            source,
        })?;
    Ok(value)
}

/// A private request-body builder, so every shape serializes the same way.
pub(crate) fn body_of(value: &serde_json::Value) -> ProviderResult<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}
