//! # nau-plugin — the V2.2.2 plugin kernel
//!
//! Everything above the infrastructure is a plugin. The kernel does exactly four
//! things — **register, route, arbitrate, transition** — and every other behaviour
//! in the system is a plugin that goes through the same door.
//!
//! ## What this crate replaces
//!
//! V1.2.3 is a single binary that wires sixteen crates together at compile time.
//! Adding a feature means editing the host; disabling one means shipping a new
//! binary; a bug in any of them is a bug in all of them. This crate makes the
//! extension point explicit, and makes the *trust* question explicit with it:
//! every plugin has a tier, every tier has a permission ceiling, and every ceiling
//! is enforced at one place — the bus.
//!
//! ## The rules this crate implements
//!
//! | Rule | Where it is enforced |
//! |---|---|
//! | A plugin's tier comes from its signed name alone, never a separate field | [`tier::Tier::from_name`] |
//! | A third party cannot occupy the vendor namespace | [`tier::Tier::from_name`]′s reserved-prefix branch |
//! | An unheld capability is refused at the bus, not at the call site | [`capability::CapabilityToken::require`] |
//! | Kernel authority has no approval path | [`capability::Capability::decision`] |
//! | A manifest is verified against the module it names, not merely parsed | [`manifest::Manifest::verify`] |
//! | A blacklist hit is a verdict that overrides the tier | [`tier::Tier::Blacklisted`] |
//! | An isolation level this build cannot enforce is refused, never downgraded | [`runtime::PluginRuntime`] |
//!
//! ## The refusal is the feature
//!
//! This crate is full of paths that end in `Err`, and that is the design rather
//! than a limitation. V1.2.3's audit of upstream `agent-universe` found the same
//! defect repeatedly: a policy that was *documented* but never *consulted*
//! (`NetworkGuard::check_egress`, `PermissionChecker::check`, `AuditLog::append`
//! all had zero production callers). A permission system that fails open is worse
//! than none, because it launders trust. So here, a request that cannot be honoured
//! is a typed refusal that names what was refused and why — and the tests assert the
//! refusals, not just the happy path.
//!
//! ## Layout
//!
//! * [`tier`] — the five-level classification and the name rule that derives it.
//! * [`capability`] — capabilities, the `(capability, tier)` matrix, and tokens.
//! * [`manifest`] — the signed manifest: parse, validate, digest, verify.
//! * [`arbiter`] — the load pipeline: manifest in, running plugin or typed refusal out.
//! * [`registry`] — who is registered, at what version, depending on what.
//! * [`lifecycle`] — the state machine, with one assignment site.
//! * [`arbiter`] — the load pipeline that turns a manifest into a running plugin or a typed refusal.
//! * [`bus`] — the plugin message bus, the only channel between plugins.
//! * [`runtime`] — the isolation port and its backends.
//! * [`hot`] — hot update, hot plug, and adapters for older plugin ABIs.
//! * [`secure`] — the opt-in end-to-end channel for payloads the host must not read.
//! * [`certify`] — the review a publisher goes through, and the scope it grants.
//! * [`blacklist`] — quarantine: fingerprint, evidence, appeal, emergency broadcast.
//!
//! ## Versioning
//!
//! The kernel is `V2.2.2`; plugins version independently and declare the `abi` they
//! were built against. V3.0.0 adds hot swap, hot plug and the ABI adapters that let a
//! `2.x` plugin load into a `3.x` host; the seams for those are already here and
//! tested (see `docs/PLUGIN-ARCHITECTURE.md` §9.4).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// Deliberately NOT `#![warn(clippy::pedantic)]`: no other crate in this workspace
// enables it, and CI runs `clippy --all-targets -- -D warnings` on the workspace, so a
// pedantic level here would be a lint standard that applies to one crate out of sixteen.
// The pedantic pass did find two real things while it was on, and both are fixed rather
// than silenced: a `usize as u32` cast that could truncate, and a collapsible `if` in the
// lifecycle. Keeping the crate on the same lint level as its siblings is the honest way
// to make the CI gate mean the same thing everywhere.

pub mod arbiter;
pub mod blacklist;
pub mod bus;
pub mod capability;
pub mod certify;
pub mod error;
pub mod hot;
pub mod lifecycle;
pub mod manifest;
pub mod registry;
pub mod runtime;
pub mod secure;
pub mod tier;

pub use arbiter::{Arbiter, LoadFailure, LoadRequest, Loaded};
pub use capability::{Approval, Capability, CapabilityToken, Grant};
pub use certify::{Certification, Finding, Review, ReviewStage, ScanReport};
pub use error::{LoadRefusal, PluginError, Result};
pub use manifest::{Limits, Manifest, SignatureSection, TrustStore, VerifiedManifest};
pub use tier::{PluginId, Tier};

/// This crate's version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The ABI major version this kernel speaks.
///
/// A plugin declares the ABI it was built against; a different major version has no
/// adapter in this host and is refused rather than loaded optimistically. V3.0.0
/// adds the adapter registry that maps `2.x` onto the `3.x` bus.
pub const ABI_MAJOR: u32 = 3;

/// The ABI minor version this kernel speaks.
///
/// A plugin built against an older minor is accepted (the bus is additive within a
/// major); one built against a newer minor is refused, because this host cannot know
/// what the newer minor added.
pub const ABI_MINOR: u32 = 2;

/// The upstream release whose plugin ambitions this architecture answers.
///
/// * **v2.8.2** was the release this build's kernel first audited, and the findings from that
///   audit are still attributed to it by name in the modules that fixed them — that attribution
///   is a record of where a defect came from, not a claim about the current upstream.
/// * **v3.5.0** is the release this build now answers for the plugin architecture itself: its
///   `v3.2.1…v3.5.0` line added four business-enabled official plugins, a global review release,
///   the orchestrator's data-plane takeover, system-plugin wiring, and process-plugin outbox
///   communication. Which of those this build adopted, and where it deliberately differs, is
///   recorded per item in `docs/PLUGIN-MIGRATION.md` and `docs/VERIFICATION.md` rather than
///   summarised here.
pub const UPSTREAM_AUDITED: &str = "agent-universe v3.5.0";

/// Whether this build can hot-swap a running plugin.
///
/// `true` from V3.2.1. The mechanism is [`hot::HotSwapper`]: the replacement is prepared
/// and health-checked beside the running version, the routing table is switched by one
/// pointer replacement, and only then is the old instance drained. The REST surface and
/// the CLI read this constant rather than each stating their own version of the truth.
///
/// It is `true` for the **routing table and the lifecycle**, and it does not mean every
/// runtime can be swapped: a system plugin is compiled into the kernel and cannot be
/// replaced at all (it is hot-*configurable*), and the WASM runtime does not exist in
/// this build.
pub const HOT_SWAP_SUPPORTED: bool = true;
