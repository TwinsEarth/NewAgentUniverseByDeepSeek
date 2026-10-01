//! # nau-plugins — the V2.2.2 plugin implementations
//!
//! The kernel ([`nau_plugin`]) decides *who may do what*: tiers, capability tokens,
//! signed manifests, the bus, the lifecycle, the isolation port. It deliberately
//! contains no plugin. This crate contains them, and it contains the framework that
//! runs the one tier which lives in the host's address space.
//!
//! ## What is in here
//!
//! | Module | What it is |
//! |---|---|
//! | [`host`] | The T0 system-plugin framework: [`SystemPlugin`](host::SystemPlugin), the single door ([`HostContext`](host::HostContext)), and [`SystemPluginHost`](host::SystemPluginHost) |
//! | [`plugins`] | Four real T0 plugins: identity, storage, policy, orchestrator |
//! | [`sign`] | The vendor-side manifest signing helper (fixtures, release tooling, isolation tests); not feature-gated, for the reason its module docs give |
//! | [`frame`] | The host ABI frame on stdin/stdout, and the request/response envelopes |
//! | [`payload`] | Reading an operation and its arguments out of a PMB payload |
//!
//! ## The one door
//!
//! A T0 plugin runs in-process and is part of the kernel, which makes it more
//! dangerous than a guest, not less: it shares the host's memory, so a "permission
//! check" that it can walk around is decoration. [`HostContext`](host::HostContext)
//! therefore hands a plugin **three things and nothing else**:
//!
//! 1. its own capability token, read-only — `require` is the refusal path;
//! 2. a way to *request* a bus send, which the host performs after the bus has
//!    checked it (the plugin never touches [`nau_plugin::bus::Bus`]);
//! 3. a bounded log sink.
//!
//! It does **not** expose the registry, the sandbox manager, the arbiter, the
//! blacklist or any other plugin's state. In particular a T0 plugin cannot ask
//! "which plugins are loaded?" — the orchestrator, which legitimately needs the
//! dependency order, is given a port that answers exactly one question
//! ([`LoadOrderSource`](plugins::orchestrator::LoadOrderSource)), and that port is
//! host wiring rather than a method on the context. The distinction is the point:
//! the context is the door a plugin reaches at *runtime*, and the ports are what the
//! host chose to compile into it.
//!
//! Two further rules are enforced by the framework rather than documented:
//!
//! * a T0 plugin is registered **only** against a [`VerifiedManifest`] that
//!   classifies as [`Tier::System`](nau_plugin::Tier::System), names the same plugin
//!   and grants every capability the plugin declares — an under-granted plugin is
//!   refused at registration, naming the capability, so it can never run in a state
//!   where it would fail later and less legibly;
//! * a message is handled only while the plugin is `Running`, through the kernel's
//!   own [`Lifecycle`](nau_plugin::lifecycle::Lifecycle) state machine, so a
//!   stopped plugin does not keep answering.
//!
//! ## The host ABI frame
//!
//! A process plugin (T1/T2/T3) is an ordinary executable. It is driven by frames on
//! stdin and stdout; stderr is the plugin's own log and is not part of the protocol.
//!
//! ```text
//! frame   := length-prefix || payload
//! length-prefix := 4 bytes, big-endian unsigned, the payload length
//! payload := UTF-8 JSON, one of the envelopes below, at most 1048576 bytes
//! ```
//!
//! One request, one response, then exit — that is the whole protocol in V2.2.2
//! (`docs/PLUGIN-ARCHITECTURE.md` §9.3 puts the cost plainly: a process plugin talks
//! this ABI or it does not talk at all).
//!
//! Request:
//!
//! ```json
//! { "abi": "2.2", "id": "req-1", "op": "echo", "payload": { "any": "json" } }
//! ```
//!
//! Response:
//!
//! ```json
//! { "abi": "2.2", "id": "req-1", "plugin": "io.example.echo", "version": "1.2.3",
//!   "ok": true, "payload": { "any": "json" } }
//! ```
//!
//! A refusal is a response with `ok: false` and a machine-readable `code`, never an
//! empty success:
//!
//! ```json
//! { "abi": "2.2", "id": "req-1", "plugin": "io.example.echo", "version": "1.2.3",
//!   "ok": false, "code": "abi_unknown_operation", "message": "…" }
//! ```
//!
//! The frame codes are `abi_frame_too_large`, `abi_frame_truncated`,
//! `abi_payload_empty`, `abi_payload_not_json`, `abi_version_mismatch`,
//! `abi_unknown_operation`, `abi_payload_not_object`, `abi_missing_field` and
//! `abi_field_type`. A frame larger than [`frame::MAX_FRAME_BYTES`] is refused from
//! its length prefix, before anything is allocated for it.
//!
//! The process exit codes are: `0` answered, `1` answered with `ok: false`, `2` the
//! frame itself could not be read or written. A host that sees `2` knows the plugin
//! is not speaking this ABI at all, which is a different repair from "the plugin
//! refused the call".
//!
//! ### Example
//!
//! ```
//! use nau_plugins::frame::{self, Request, Response};
//!
//! # fn main() -> Result<(), nau_plugin::PluginError> {
//! let request = Request {
//!     abi: frame::abi_version(),
//!     id: "req-1".into(),
//!     op: "echo".into(),
//!     payload: serde_json::json!({ "hello": "world" }),
//! };
//! let mut wire = Vec::new();
//! frame::write_frame(&mut wire, &serde_json::to_vec(&request)?)?;
//!
//! let payload = frame::read_frame(&mut wire.as_slice())?.unwrap_or_default();
//! let decoded: Request = serde_json::from_slice(&payload)?;
//! assert_eq!(decoded.payload["hello"], "world");
//! # Ok(())
//! # }
//! ```
//!
//! ## What this crate is not
//!
//! * It is not the load pipeline. Turning a manifest into a running T1/T2/T3 plugin
//!   is the arbiter's job in `nau-plugin`; this crate produces the *artefacts* that
//!   pipeline consumes (fixtures, signed manifests) and the T0 side of the picture.
//! * It is not the host. Nothing here constructs a `nau-node` node, opens a socket or
//!   loads a T1 plugin; [`SystemPluginHost`](host::SystemPluginHost) is a registry of
//!   in-process plugins and a dispatcher, and it says so.
//! * It does not claim isolation for T0 plugins. There is none: a system plugin runs
//!   in the host's address space, which is exactly why it must be compiled in and
//!   cannot be hot-plugged ([`nau_plugin::HOT_SWAP_SUPPORTED`] is `false`).
//!
//! ## Layout of the test fixtures
//!
//! `tests/fixtures/` holds eleven signed manifests — three that load and eight that
//! are refused — with a `README.md` that states, for each, the keys involved, the
//! module bytes it covers, and the refusal code it must produce. They are generated
//! deterministically from one-byte seeds by [`sign`], and
//! `tests/manifest_fixtures.rs` asserts both the refusal codes and that the files on
//! disk are still exactly what this build produces.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// Deliberately NOT `#![warn(clippy::pedantic)]`: no other crate in this workspace
// enables it, and CI runs `clippy --all-targets -- -D warnings` over the workspace,
// so a pedantic level here would be a lint standard that applies to one crate out of
// seventeen.

pub mod frame;
pub mod host;
pub mod official;
pub mod payload;
pub mod plugins;
pub mod sign;

pub use host::{
    standard_declarations, standard_plugins, BusHandle, HostContext, HostLimits, LogLevel,
    LogRecord, OutboxOutcome, PluginGrant, SystemPlugin, SystemPluginHost,
};
pub use plugins::identity::IdentityPlugin;
pub use plugins::orchestrator::{LoadOrderSource, OrchestratorPlugin};
pub use plugins::policy::PolicyPlugin;
pub use plugins::storage::StoragePlugin;
