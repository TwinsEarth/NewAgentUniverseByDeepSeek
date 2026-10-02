//! # nau-agent — agent-side memory and the LLM provider port
//!
//! Two things live here, both replacing upstream `agent-universe` v2.5.6
//! modules (`gsn-core/src/memory/*`, `src/deepseek/*`, `src/llm/*`):
//!
//! 1. **Layered memory with a real provenance chain.** [`HashChain`] is a
//!    SHA-256 chain that stores its payloads and can re-verify itself;
//!    [`AgentMemory`] is a bounded store with genuine LRU eviction;
//!    [`SharedMemory`] enforces anti-pollution by *deriving* an experience's
//!    quality from its recorded outcomes; [`LayeredMemory`] ties the tiers
//!    together and exposes a cross-generation pointer; [`TransferBundle`]
//!    validates the six-field handoff with real length caps.
//! 2. **The [`LlmProvider`] port.** Fallible, integer-only in its budgets and
//!    rankings, and provider metadata as plain data — no socket, no secret, no
//!    vendor SDK.
//!
//! ## Design rules
//!
//! 1. **No `unsafe`.** `#![forbid(unsafe_code)]` is enforced crate-wide.
//! 2. **No panics on untrusted input.** No `unwrap()`, `expect()` or `panic!()`
//!    outside `#[cfg(test)]`; every failure is a typed [`nau_core::NauError`].
//! 3. **No floating point for scores, thresholds or quality.** Quality is `u16`
//!    basis points and ordering is integer comparison, so a `NaN` cannot exist
//!    to be compared — upstream's `partial_cmp(..).unwrap()` panic is
//!    structurally impossible here.
//! 4. **Bounded by construction.** Every store takes a capacity and enforces it.
//! 5. **Deterministic order** for anything user-visible: results are sorted by
//!    integers and then by key, never by hash-map iteration order.
//!
//! Every upstream defect fixed in this crate is marked with a
//! `// upstream v2.5.6 fix:` comment at the site of the fix.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod chain;
pub mod experience;
pub mod layered;
pub mod llm;
pub mod memory;
pub mod provider;
pub mod transfer;

pub use chain::{link_digest, ChainLink, HashChain, GENESIS_DIGEST};
pub use experience::{Experience, SharedMemory, MAX_QUALITY_BPS, MIN_SHARED_OBSERVATIONS};
pub use layered::{LayeredMemory, MemoryTier, DEFAULT_TIER_CAPACITY};
pub use llm::{
    context_window_for, digest_request_sequence, known_profiles, model_context_windows,
    provider_names, request_digest, ChatMessage, ChatRequest, ChatResponse, ChatRole, LlmProvider,
    ProviderOutcome, ProviderProfile, ScriptedProvider, TokenBudget,
};
pub use memory::{AgentMemory, MemoryRecord};
pub use provider::{HttpProvider, ProviderError, ProviderKind};
pub use transfer::{TransferBundle, MAX_ENTRIES, MAX_FIELD_BYTES};
