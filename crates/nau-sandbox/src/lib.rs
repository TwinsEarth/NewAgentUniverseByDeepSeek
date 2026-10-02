//! # nau-sandbox — the V1.2.3 Agent Sandbox
//!
//! ## What this replaces
//!
//! Upstream `agent-universe` v2.8.2 shipped an Agent Sandbox
//! (`gsn-core/src/sandbox/`, 1,847 lines) whose security boundaries existed **only
//! in documentation and unit tests**. The audit found, among others:
//!
//! * the whole isolation primitive was `Command::new("bash")`, and a repo-wide grep
//!   for `unshare|setrlimit|seccomp|chroot|landlock|setuid|cgroup` returned zero;
//! * `safe_join` guarded two Rust-side helpers and never the execution path, so
//!   sandboxed code read and wrote the entire host filesystem;
//! * `POST /api/v1/sandboxes/{id}/exec` was unauthenticated remote code execution
//!   with no ownership model and guessable `sb-N` ids that a restart reissued
//!   *on top of the previous sandbox's files*;
//! * `NetworkGuard::check_egress`, `PermissionChecker::check`, `AuditLog::append`
//!   and `ExecutionToken::authorize` had zero production callers, so "default deny
//!   egress" was false;
//! * two of six resource limits were real, the Windows branch applied none, and
//!   output was read with an unbounded `read_to_end`;
//! * `shutdown` and `evict_idle` had no callers, so a restart orphaned every
//!   sandbox.
//!
//! ## The rule this crate implements
//!
//! > A boundary that is documented but not enforced is worse than no boundary,
//! > because it launders trust. Every policy field must either be enforced in
//! > code, or make the request FAIL.
//!
//! ## How that rule is structurally enforced here
//!
//! | Concern | Mechanism |
//! |---|---|
//! | One path-component validator | [`SafeComponent`] is the only way to obtain a path component, and [`SafeComponent::join_under`] re-checks the canonical result |
//! | No optional limits | [`SandboxSpec`] has no `Option` and no `Default`; a missing limit is a compile error |
//! | Nothing runs by default | [`NullExecutor`] is the default backend and refuses with [`SandboxError::ExecutionDisabled`] |
//! | No unenforceable policy | Every backend publishes [`Capabilities`]; a request for a boundary it does not enforce fails with [`SandboxError::PolicyNotEnforceable`], **naming the boundary** |
//! | Unrestricted runs are visible | [`NetworkPolicy::Unrestricted`] and every waiver need a justification, and the manager writes it to the [`AuditEntry`] log before the sandbox exists |
//! | No id reuse, no orphans | v4-UUID ids through [`SafeComponent`], a per-run marker file, a startup sweep in [`SandboxManager::open`], and `Drop`/`shutdown` that remove everything |
//! | No global lock across execution | The table lock is held only for lookup; execution happens under a per-sandbox lock, and poisoning is a typed error rather than a panic |
//!
//! ## Layout
//!
//! * [`component`] — the one validation function, with the refusal table.
//! * [`spec`] — the complete, non-optional description of a sandbox.
//! * [`capability`] — what a backend enforces, and the refusal for the rest.
//! * [`executor`] — the port, [`NullExecutor`], and the real process backend.
//! * [`manager`] — identity, ownership, lifecycle, the startup sweep, the audit log.
//! * [`platform`] — the platform edge. Windows uses a Win32 Job Object; Unix uses
//!   `setsid` plus `setrlimit` and is **not verified on this machine**.
//!
//! ## Safety
//!
//! `#![deny(unsafe_code)]` is crate-wide, with exactly one exception: the private
//! module [`platform`] carries `#[allow(unsafe_code)]` because a Win32 Job Object
//! and `setrlimit` are reachable only through the C ABI. The exception, its
//! justification and its limits are documented in that module, and every `unsafe`
//! block has a `// SAFETY:` comment.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod capability;
pub mod component;
pub mod error;
pub mod executor;
pub mod manager;
pub mod process;
pub mod spec;

mod platform;

pub use capability::{
    check_boundary, BoundaryRequest, Capabilities, Capability, UnenforcedCapability,
};
pub use component::{SafeComponent, MAX_COMPONENT_BYTES};
pub use error::{ComponentError, Result, SandboxError};
pub use executor::{
    shared, DefaultExecutor, NullExecutor, RealProcessExecutor, SandboxExecutor, SandboxHandle,
};
pub use manager::{
    AuditAction, AuditEntry, SandboxDescription, SandboxManager, SandboxState, SweepReport,
    DEFAULT_MAX_SANDBOXES, MAX_ORPHANS_PER_SWEEP, ORPHAN_AGE_SECS,
};
pub use process::{ExecOutcome, ExecRequest, SAFE_PATH};
pub use spec::{
    AbsoluteProgramPath, Confinement, EnvPolicy, FilesystemPolicy, InheritPolicy, Interpreter,
    Limits, NetworkPolicy, SandboxSpec, Waivers,
};

/// This crate's version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The upstream release whose Agent Sandbox defects this crate corrects.
pub const UPSTREAM_AUDITED: &str = "agent-universe v2.8.2";

/// Which platform backend this build uses.
///
/// `windows-jobobject` on Windows, `unix-setrlimit` elsewhere. Reported so that
/// "which limits does this deployment actually have?" is answerable from the
/// binary rather than from a document.
pub const PLATFORM_BACKEND: &str = platform::PLATFORM_BACKEND;
