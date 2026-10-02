//! The LLM provider port: integer-only budgets, a fallible trait, and provider
//! metadata as *data*.
//!
//! ## What changed from upstream v2.5.6
//!
//! * **Adapters were infallible wrappers around fallible calls.** Upstream's
//!   `OpenAiClient::chat` and friends returned a plain `OaChatResponse` built
//!   with `.unwrap()` on the HTTP result and `choices[0]` indexing, so a single
//!   provider hiccup was an unconditional panic, and an empty `choices` array
//!   panicked too. [`LlmProvider::chat`] returns [`nau_core::Result`], and the
//!   reference implementation below never indexes unchecked.
//! * **Temperature was `f64`.** [`ChatRequest::temperature_milli`] is a `u16` in
//!   milli-units (`0..=1000` for `0.0..=1.0`), which round-trips through JSON
//!   without ever producing a float.
//! * **Truncation silently discarded the conversation.** Upstream's
//!   `ContextBudget::truncate_history` (`gsn-core/src/deepseek/tokenizer.rs`)
//!   broke out of its loop and returned whatever it had — which, when the newest
//!   message alone did not fit, was *only the system prompt*, sent as if it were
//!   the request. [`TokenBudget::truncate_history`] returns an error in that case
//!   instead of quietly changing the question.
//! * **Clients held secrets and side effects.** [`ProviderProfile`] is plain
//!   data: endpoint, model ids and context window, with the API key named only
//!   as an environment variable. Nothing in this crate opens a socket.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chain::{link_digest, GENESIS_DIGEST};

/// Fixed per-message framing overhead, matching the documented
/// `4 tokens per message` convention.
const MESSAGE_OVERHEAD_TOKENS: u64 = 4;
/// Fixed per-conversation framing overhead.
const CONVERSATION_OVERHEAD_TOKENS: u64 = 3;
/// Byte-domain divisor used by the heuristic for printable ASCII.
const ASCII_BYTES_PER_TOKEN: u64 = 4;
/// Divisor used by the heuristic for non-ASCII code points.
const NON_ASCII_CHARS_PER_TOKEN: u64 = 2;
/// Divisor used by the heuristic for control bytes.
const CONTROL_BYTES_PER_TOKEN: u64 = 2;

/// Who produced a message.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatRole {
    /// Instructions that frame the conversation.
    System,
    /// Input from the caller.
    User,
    /// A previous model turn.
    Assistant,
}

/// One message in a conversation.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Who produced it.
    pub role: ChatRole,
    /// The text.
    pub content: String,
}

impl ChatMessage {
    /// Build a message.
    pub fn new(role: ChatRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }

    /// A system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::new(ChatRole::System, content)
    }

    /// A user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::new(ChatRole::User, content)
    }

    /// An assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(ChatRole::Assistant, content)
    }
}

/// A completion request.
///
/// Note there is no `temperature: f64` field: milli-units keep the entire
/// request expressible as JSON integers, which is what the canonical-payload
/// rules require for anything that might be signed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Model identifier, as the provider names it.
    pub model: String,
    /// The conversation, oldest first.
    pub messages: Vec<ChatMessage>,
    /// Upper bound on generated tokens.
    pub max_tokens: u32,
    /// Sampling temperature in milli-units: `0..=1000` maps to `0.0..=1.0`.
    pub temperature_milli: u16,
}

/// A completion.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChatResponse {
    /// The model that actually served the request.
    pub model: String,
    /// The generated text.
    pub content: String,
    /// Prompt tokens billed.
    pub prompt_tokens: u32,
    /// Completion tokens billed.
    pub completion_tokens: u32,
    /// Why generation stopped.
    pub finish_reason: String,
}

/// A context-window budget.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TokenBudget {
    context_window: u32,
    reserve_output: u32,
}

impl TokenBudget {
    /// A budget that keeps `reserve_output` tokens free for the completion.
    ///
    /// Fails when `context_window` is zero or `reserve_output` meets or exceeds
    /// it — in both cases no input could ever be sent, and failing at
    /// construction is better than failing on every request.
    pub fn new(context_window: u32, reserve_output: u32) -> Result<Self> {
        if context_window == 0 {
            return Err(NauError::Validation(
                "context window must be greater than zero".into(),
            ));
        }
        if reserve_output >= context_window {
            return Err(NauError::Validation(format!(
                "reserving {reserve_output} output tokens leaves no room in a {context_window}-token \
                 context window"
            )));
        }
        Ok(Self {
            context_window,
            reserve_output,
        })
    }

    /// The configured context window.
    pub fn context_window(&self) -> u32 {
        self.context_window
    }

    /// The output tokens held back for the completion.
    pub fn reserve_output(&self) -> u32 {
        self.reserve_output
    }

    /// Input tokens available after the reservation.
    pub fn input_budget(&self) -> u32 {
        self.context_window.saturating_sub(self.reserve_output)
    }

    /// Estimated prompt tokens for `messages`.
    ///
    /// # This is a heuristic, not a tokenizer
    ///
    /// There is no real BPE tokenizer here and this function does not claim to
    /// be one. It counts printable ASCII at ~4 bytes per token, control bytes at
    /// ~2, and non-ASCII code points at ~1.5 (evaluated as 3 code points per 2
    /// tokens) — including CJK, which real tokenizers treat quite differently.
    /// It exists to decide *whether a request is obviously too large*, and its
    /// error is deliberately on the conservative side. Anything that needs exact
    /// accounting must ask a real tokenizer.
    ///
    /// The computation is entirely integer: upstream's version cast to `f64` to
    /// take `ceil`, which this avoids.
    pub fn estimate(&self, messages: &[ChatMessage]) -> u32 {
        if messages.is_empty() {
            return 0;
        }
        let mut total = CONVERSATION_OVERHEAD_TOKENS;
        for message in messages {
            total = total.saturating_add(message_tokens(message));
        }
        clamp_u64_to_u32(total)
    }

    /// Whether `messages` plus `max_tokens` of output fit the window.
    ///
    /// Fails closed: an empty message list never fits, because the heuristic
    /// cannot size the completion.
    pub fn fits(&self, messages: &[ChatMessage], max_tokens: u32) -> bool {
        if messages.is_empty() {
            return false;
        }
        u64::from(self.estimate(messages)) + u64::from(max_tokens) <= u64::from(self.context_window)
    }

    /// Drop the oldest non-system messages until the request fits.
    ///
    /// Returns how many messages were dropped. System messages are never
    /// dropped, order is preserved, and the **newest non-system message is
    /// protected**: it is the question actually being asked.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] when the request still does not fit
    /// after every droppable message has been removed. Upstream instead returned
    /// "system prompt only" and sent it, silently replacing the user's question
    /// with an empty conversation; silently changing the question is a worse
    /// failure than refusing to send it, and the same reasoning applies to
    /// dropping the newest message and keeping a stale one.
    ///
    /// On error the caller's vector is left untouched.
    pub fn truncate_history(
        &self,
        messages: &mut Vec<ChatMessage>,
        max_tokens: u32,
    ) -> Result<usize> {
        // Work on a copy and commit only on success, so a failed truncation does
        // not leave the conversation half-shortened.
        let mut working = messages.clone();
        let mut dropped = 0usize;
        while !self.fits(&working, max_tokens) {
            let protected = working.iter().rposition(|m| m.role != ChatRole::System);
            let victim = working.iter().enumerate().position(|(index, message)| {
                message.role != ChatRole::System && Some(index) != protected
            });
            match victim {
                Some(position) => {
                    working.remove(position);
                    dropped = dropped.saturating_add(1);
                }
                None => {
                    return Err(NauError::Validation(format!(
                        "no non-system message can be dropped, yet the request still exceeds the \
                         {}-token window (max_tokens={max_tokens}, reserve_output={})",
                        self.context_window, self.reserve_output
                    )));
                }
            }
        }
        *messages = working;
        Ok(dropped)
    }
}

/// Count the tokens of a single message, including framing overhead.
fn message_tokens(message: &ChatMessage) -> u64 {
    MESSAGE_OVERHEAD_TOKENS.saturating_add(estimate_text_tokens(&message.content))
}

/// Heuristic token estimate for one string. See [`TokenBudget::estimate`].
fn estimate_text_tokens(text: &str) -> u64 {
    let non_ascii_chars = text.chars().filter(|c| !c.is_ascii()).count() as u64;
    let mut ascii_bytes = 0u64;
    let mut control_bytes = 0u64;
    for byte in text.bytes() {
        if byte < 0x20 || byte == 0x7f {
            control_bytes = control_bytes.saturating_add(1);
        } else {
            ascii_bytes = ascii_bytes.saturating_add(1);
        }
    }
    let ascii_tokens = div_ceil_u64(ascii_bytes, ASCII_BYTES_PER_TOKEN);
    let control_tokens = div_ceil_u64(control_bytes, CONTROL_BYTES_PER_TOKEN);
    // 3 code points per 2 tokens: ceil(3n / 2).
    let non_ascii_tokens =
        div_ceil_u64(non_ascii_chars.saturating_mul(3), NON_ASCII_CHARS_PER_TOKEN);
    ascii_tokens
        .saturating_add(control_tokens)
        .saturating_add(non_ascii_tokens)
}

fn div_ceil_u64(value: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return value;
    }
    value / divisor + u64::from(value % divisor != 0)
}

fn clamp_u64_to_u32(value: u64) -> u32 {
    if value > u64::from(u32::MAX) {
        u32::MAX
    } else {
        value as u32
    }
}

/// The provider port.
///
/// Every implementation is fallible. Upstream's adapters returned a plain
/// response struct and called `.unwrap()` on the client result inside, so no
/// caller could observe a provider error — it was an unconditional panic
/// instead.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Stable provider name.
    fn name(&self) -> &'static str;

    /// The context window of the default model, in tokens.
    fn context_window(&self) -> u32;

    /// Produce a completion, or explain why it could not.
    async fn chat(&self, req: ChatRequest) -> Result<ChatResponse>;
}

/// A deterministic provider driven by a fixed script of replies.
///
/// **Not** a vendor adapter: this type performs no I/O, needs no credentials,
/// and exists so that agent behaviour can be tested without a network. It is
/// deliberately not named after any real vendor.
pub struct ScriptedProvider {
    name: &'static str,
    context_window: u32,
    replies: Mutex<VecDeque<String>>,
    calls: Mutex<usize>,
}

impl ScriptedProvider {
    /// A provider that answers successive `chat` calls with `replies`, in order.
    pub fn new(name: &'static str, context_window: u32, replies: Vec<String>) -> Self {
        Self {
            name,
            context_window,
            replies: Mutex::new(replies.into_iter().collect()),
            calls: Mutex::new(0),
        }
    }

    /// How many `chat` calls have been attempted.
    pub fn calls(&self) -> usize {
        self.calls.lock().map(|guard| *guard).unwrap_or(0)
    }

    /// How many scripted replies remain.
    pub fn remaining(&self) -> usize {
        self.replies.lock().map(|guard| guard.len()).unwrap_or(0)
    }
}

/// A stable digest of a request, so tests can prove byte-level determinism.
pub fn request_digest(req: &ChatRequest) -> Result<String> {
    let encoded = serde_json::to_string(req)?;
    let mut hasher = Sha256::new();
    hasher.update(b"nau-chat-request-v1\0");
    hasher.update(encoded.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Hash-chain a sequence of requests, so a conversation's request stream is
/// tamper-evident.
///
/// Reuses [`link_digest`] from the memory chain, so the audit format is
/// identical everywhere in the crate.
pub fn digest_request_sequence(requests: &[ChatRequest]) -> Result<Vec<String>> {
    let mut digests = Vec::with_capacity(requests.len());
    let mut previous = GENESIS_DIGEST.to_string();
    for (index, request) in requests.iter().enumerate() {
        let payload = serde_json::to_string(request)?;
        let seq = index as u64 + 1;
        let digest = link_digest(seq, seq, &payload, &previous);
        previous = digest.clone();
        digests.push(digest);
    }
    Ok(digests)
}

#[async_trait]
impl LlmProvider for ScriptedProvider {
    fn name(&self) -> &'static str {
        self.name
    }

    fn context_window(&self) -> u32 {
        self.context_window
    }

    async fn chat(&self, req: ChatRequest) -> Result<ChatResponse> {
        {
            // A poisoned mutex must not abort the request; the call counter is
            // still useful, so recover the guard instead of panicking.
            let mut calls = match self.calls.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *calls = calls.saturating_add(1);
        }
        // Bound the completion even for a scripted provider, so tests exercise
        // the same refusal path a real provider would take.
        if let Ok(budget) = TokenBudget::new(self.context_window, req.max_tokens) {
            if !budget.fits(&req.messages, req.max_tokens) {
                return Err(NauError::Validation(format!(
                    "scripted request for `{}` does not fit the {}-token window",
                    req.model, self.context_window
                )));
            }
        }
        let prompt_tokens = TokenBudget::new(self.context_window, 0)
            .map(|budget| budget.estimate(&req.messages))
            .unwrap_or(0);
        let mut replies = match self.replies.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match replies.pop_front() {
            Some(content) => {
                let completion_tokens = clamp_u64_to_u32(estimate_text_tokens(&content));
                Ok(ChatResponse {
                    model: req.model,
                    content,
                    prompt_tokens,
                    completion_tokens,
                    finish_reason: "stop".to_string(),
                })
            }
            None => Err(NauError::Validation(format!(
                "scripted provider `{}` has no reply left",
                self.name
            ))),
        }
    }
}

/// A provider described entirely by data.
///
/// `api_key_env` names an environment variable; the value is never held here,
/// never serialized, and never logged.
///
/// `context_window` is the window of the profile's **primary** model
/// (`models[0]`). Because the field cannot express a window per model, the
/// per-model truth lives in [`model_context_windows`], and
/// [`context_window_for`] is the accessor to use when the model is known — a
/// single flattened window for every model is one of the things this port exists
/// to avoid.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProviderProfile {
    /// Provider identifier, e.g. `deepseek`.
    pub name: String,
    /// Base URL of the OpenAI-compatible (or native) endpoint.
    pub base_url: String,
    /// Model ids, most capable first.
    pub models: Vec<String>,
    /// Context window of `models[0]`, in tokens.
    pub context_window: u32,
    /// Name of the environment variable holding the API key.
    pub api_key_env: Option<String>,
}

/// Outcome of a `chat` call, as observed through `dyn LlmProvider`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProviderOutcome {
    /// A completion was produced.
    Answered(ChatResponse),
    /// The provider refused or failed; the error is preserved, not swallowed.
    Failed(String),
}

/// The provider catalog, with a context window per model.
///
/// ## Provenance of the numbers
///
/// Context windows are taken from each vendor's published model catalog.
/// Vendors change them without notice, so treat the table as a *default* a
/// deployment may override, and re-check the cited page before relying on it:
///
/// * deepseek — <https://api-docs.deepseek.com/quick_start/pricing>
/// * qwen — <https://help.aliyun.com/zh/model-studio/models>
/// * zhipu — <https://docs.bigmodel.cn/cn/guide/models/text/glm-5>
/// * kimi/moonshot — <https://platform.moonshot.cn/docs/intro>
/// * openai — <https://platform.openai.com/docs/models>
/// * anthropic — <https://docs.anthropic.com/en/docs/about-claude/models>
/// * gemini — <https://ai.google.dev/gemini-api/docs/models>
///
/// A flat constant for every model would be wrong, and the differences are not
/// cosmetic: `gpt-4o` (128_000) vs `gpt-5.2` (400_000), `gemini-3-pro`
/// (1_000_000) vs `gemini-3-flash` (200_000), `kimi-k3` (256_000) vs
/// `moonshot-v1-8k` (8_000), `qwen3.8-max` (1_000_000) vs `qwen-max` (131_072).
/// A test asserts those differences rather than trusting this comment.
/// Every `(model id, context window)` pair in the catalog, in catalog order.
///
/// This is the flat view of the per-model truth that [`ProviderProfile`] cannot
/// express. Deterministic: catalog order, no set iteration.
pub fn model_context_windows() -> Vec<(String, u32)> {
    PROVIDERS
        .iter()
        .flat_map(|(_, _, _, models)| models.iter())
        .map(|(id, window)| ((*id).to_string(), *window))
        .collect()
}

/// Every provider name in the catalog, in catalog order.
pub fn provider_names() -> Vec<&'static str> {
    PROVIDERS.iter().map(|(name, _, _, _)| *name).collect()
}

/// `(name, base_url, api_key_env, [(model id, context window)])`.
type ProviderEntry = (
    &'static str,
    &'static str,
    &'static str,
    &'static [(&'static str, u32)],
);

/// The single source of truth for [`known_profiles`] and
/// [`context_window_for`], so the two cannot drift apart.
const PROVIDERS: &[ProviderEntry] = &[
    (
        "deepseek",
        "https://api.deepseek.com",
        "DEEPSEEK_API_KEY",
        &[
            ("deepseek-flash", 1_000_000),
            ("deepseek-v4-pro", 1_000_000),
            ("deepseek-chat", 128_000),
            ("deepseek-reasoner", 128_000),
        ],
    ),
    (
        "openai",
        "https://api.openai.com/v1",
        "OPENAI_API_KEY",
        &[
            ("gpt-5.2", 400_000),
            ("gpt-4o", 128_000),
            ("gpt-4o-mini", 128_000),
        ],
    ),
    (
        "anthropic",
        "https://api.anthropic.com/v1",
        "ANTHROPIC_API_KEY",
        &[
            ("claude-sonnet-4-6", 200_000),
            ("claude-opus-4-6", 200_000),
            ("claude-haiku-4-5", 200_000),
        ],
    ),
    (
        "gemini",
        "https://generativelanguage.googleapis.com/v1beta",
        "GEMINI_API_KEY",
        &[
            ("gemini-3-pro", 1_000_000),
            ("gemini-3-flash", 200_000),
            ("gemini-2.5-pro", 1_000_000),
        ],
    ),
    (
        "qwen",
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "DASHSCOPE_API_KEY",
        &[
            ("qwen3.8-max", 1_000_000),
            ("qwen3.8-plus", 1_000_000),
            ("qwen3.8-flash", 1_000_000),
            ("qwen-max", 131_072),
            ("qwen-turbo", 131_072),
        ],
    ),
    (
        "zhipu",
        "https://open.bigmodel.cn/api/paas/v4",
        "ZHIPU_API_KEY",
        &[
            ("glm-5.3", 200_000),
            ("glm-5", 200_000),
            ("glm-4", 128_000),
            ("glm-4-flash", 128_000),
        ],
    ),
    (
        "kimi",
        "https://api.moonshot.cn/v1",
        "MOONSHOT_API_KEY",
        &[
            ("kimi-k3", 256_000),
            ("kimi-k2", 256_000),
            ("moonshot-v1-128k", 128_000),
            ("moonshot-v1-8k", 8_000),
        ],
    ),
];

/// The provider catalog as [`ProviderProfile`]s, most capable model first.
///
/// The seven entries cover deepseek, openai, anthropic, gemini and three Chinese
/// vendors (qwen, zhipu, kimi).
pub fn known_profiles() -> Vec<ProviderProfile> {
    PROVIDERS
        .iter()
        .map(|(name, base_url, api_key_env, models)| ProviderProfile {
            name: (*name).to_string(),
            base_url: (*base_url).to_string(),
            models: models.iter().map(|(id, _)| (*id).to_string()).collect(),
            context_window: models.iter().map(|(_, window)| *window).max().unwrap_or(0),
            api_key_env: Some((*api_key_env).to_string()),
        })
        .collect()
}

/// Look up the context window for `model`.
///
/// Matching is exact first, then case-insensitive. An unknown model yields
/// `None`; guessing a window is how a request gets silently rejected or silently
/// oversized.
pub fn context_window_for(model: &str) -> Option<u32> {
    let needle = model.trim();
    for (_, _, _, models) in PROVIDERS {
        for (id, window) in models.iter() {
            if *id == needle {
                return Some(*window);
            }
        }
    }
    let lower = needle.to_lowercase();
    for (_, _, _, models) in PROVIDERS {
        for (id, window) in models.iter() {
            if id.to_lowercase() == lower {
                return Some(*window);
            }
        }
    }
    None
}
