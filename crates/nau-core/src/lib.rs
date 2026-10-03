//! # nau-core — NewAgentUniverseByDeepSeek core domain
//!
//! This crate is the **frozen contract** of the whole system. It contains only
//! pure, deterministic, I/O-free logic:
//!
//! * [`identity`] — Ed25519 key material, `did:nau:` derivation, and the
//!   canonical-payload signing scheme that Rust, Python and JavaScript all
//!   implement byte-for-byte identically.
//! * [`domain`] — the shared vocabulary: agents, skills, tasks, bids, results,
//!   disputes, evidence grades, and exact integer [`domain::Money`].
//! * [`image`] — image manifests and content-addressed chunks: what an AUSec sandbox is
//!   created from, and how a chunk of it is named.
//! * [`clock`] — the time port, so that expiry/replay rules are testable.
//! * [`error`] — one error taxonomy for the whole workspace.
//!
//! ## Design rules
//!
//! 1. **No `unsafe`.** `#![forbid(unsafe_code)]` is enforced crate-wide.
//! 2. **No panics on untrusted input.** Parsing/verification results are
//!    `Result`, never `bool` that a caller can ignore by accident.
//! 3. **No floating point money.** See [`domain::Money`].
//! 4. **One canonical byte format.** See [`identity::canonical`].
//!
//! Upstream `agent-universe` v2.5.6 is a single 15.7 kLOC crate whose
//! `canonical_payload()` returned `Value::Null` when serialization failed (so a
//! signature could be produced over the literal payload `null`), admitted
//! floats into signed payloads, and modelled money as `f64`. Those three
//! defects are fixed here; see `docs/GAP-ANALYSIS.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod clock;
pub mod domain;
pub mod error;
pub mod identity;
pub mod image;
pub mod version;

pub use clock::{Clock, ManualClock, SystemClock};
pub use domain::{
    AgentCard, AgentCategory, Bid, Dispute, DisputeOutcome, EvidenceGrade, Money, NonceGuard,
    Pricing, PricingModel, PricingUnit, ReputationScore, ResultEnvelope, Skill, Sla, Task, TaskId,
    TaskSpec, TaskState, Verifiable, VerificationPolicy, MAX_CLOCK_SKEW_SECS,
};
pub use error::{NauError, Result};
pub use identity::{
    canonical, Did, Identity, Keypair, PublicKey, Signature64, DID_PREFIX, DID_PREFIX_LEGACY,
};
pub use image::{ChunkDigest, ChunkRef, ImageManifest};
pub use version::{PROJECT, PROTOCOL_VERSION, UPSTREAM_PROJECT, UPSTREAM_VERSION, VERSION};
