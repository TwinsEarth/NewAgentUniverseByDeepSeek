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
pub mod lifecycle;
pub mod manifest;
pub mod registry;
pub mod runtime;
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
pub const ABI_MAJOR: u32 = 2;

/// The ABI minor version this kernel speaks.
///
/// A plugin built against an older minor is accepted (the bus is additive within a
/// major); one built against a newer minor is refused, because this host cannot know
/// what the newer minor added.
pub const ABI_MINOR: u32 = 2;

/// The upstream release whose plugin ambitions this architecture answers.
pub const UPSTREAM_AUDITED: &str = "agent-universe v2.8.2";

/// Whether this build can hot-swap a running plugin.
///
/// `false` in V2.2.2, and reported rather than promised: the REST surface, the CLI
/// and the plugin manifest all read this constant instead of each stating their own
/// version of the truth. See `docs/PLUGIN-ARCHITECTURE.md` §0.
pub const HOT_SWAP_SUPPORTED: bool = false;
