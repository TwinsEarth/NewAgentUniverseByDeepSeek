//! The T0 system plugins this build ships.
//!
//! Four plugins, each wrapping behaviour that already exists and is already tested
//! elsewhere in this workspace rather than reimplementing it:
//!
//! | Plugin | Wraps | Capabilities |
//! |---|---|---|
//! | [`identity`] | `nau_core::identity` (DID derivation, Ed25519 verification, DID↔key binding) | the basic set |
//! | [`storage`] | `nau_store::FileStore` (its own directory, append-only, poison-free) | the basic set |
//! | [`policy`] | `nau_plugin::Capability::decision` (the `(capability, tier)` matrix) | basic + `kernel:policy:write` |
//! | [`orchestrator`] | `nau_plugin::registry::Registry::load_order` (the dependency graph) | basic + `kernel:plugin:manage` |
//!
//! Every one of them refuses a message that declares a capability its token does not
//! hold, and the refusal names the capability — see
//! [`PluginGrant::require_declared`](crate::host::PluginGrant::require_declared),
//! which is where that check lives so that all four behave identically.
//!
//! [`crate::host::standard_plugins`] constructs every one of them, and
//! [`crate::host::standard_declarations`] lists what each declares, for building the system
//! manifests they are registered against.
//!
//! The count is deliberately not written down here. It was "four" while four existed, and a
//! number in a doc comment is a number that goes stale silently; the invariant that matters --
//! every implementation is constructed and declared -- is enforced by the `plugin-invariants`
//! gate instead, which fails when one is added and not wired.

pub mod arbiter;
pub mod attest;
pub mod ausec;
pub mod blacklist;
pub mod chain;
pub mod erasure;
pub mod http;
pub mod identity;
pub mod ledger;
pub mod lifecycle;
pub mod migrate;
pub mod net_dht;
pub mod net_gossip;
pub mod orchestrator;
pub mod policy;
pub mod sandbox;
pub mod storage;
pub mod transport;
