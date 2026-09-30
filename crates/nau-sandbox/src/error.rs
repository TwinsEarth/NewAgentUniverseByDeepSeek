//! One typed error taxonomy for the sandbox, plus the crate `Result` alias.
//!
//! Every variant here is a **closed** outcome: there is deliberately no variant
//! that means "the policy could not be applied, so we proceeded anyway". A
//! boundary that is requested and cannot be delivered is
//! [`SandboxError::PolicyNotEnforceable`], which names the boundary.

use serde::{Deserialize, Serialize};

use crate::capability::Capability;

/// Sandbox result.
pub type Result<T> = std::result::Result<T, SandboxError>;

/// Why a string was refused as a single path component.
///
/// The variants are exhaustive on purpose: a new reason to refuse a component is
/// a compile error at every `match`, so no call site can silently start
/// accepting it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ComponentError {
    /// The candidate was empty.
    Empty,
    /// The candidate was not valid UTF-8.
    NotUtf8,
    /// The candidate was longer than [`crate::component::MAX_COMPONENT_BYTES`].
    TooLong {
        /// Length in bytes.
        len: usize,
    },
    /// The candidate contained a NUL byte.
    Nul,
    /// The candidate contained `/` or `\`.
    Separator {
        /// The offending byte.
        byte: u8,
    },
    /// The candidate began with a Windows path prefix (`C:`, `\\?\`, `\\.\`).
    WindowsPrefix,
    /// The candidate was `.`, which resolves to the directory itself.
    CurDir,
    /// The candidate was `..`, which resolves to the parent directory.
    ParentDir,
    /// The candidate was root-relative (`/x`, `\x`).
    RootDir,
    /// The candidate was a Windows reserved device name (`CON`, `NUL`, `LPT1`).
    ReservedName,
    /// The candidate trailed with `.` or a space, or began with a space.
    ///
    /// Win32 strips a trailing dot or space from a path component, so a directory
    /// named `x.` is created as `x`: two different strings would name one directory,
    /// and a check on the string would not describe what is on disk.
    TrailingDotOrSpace,
    /// The candidate contained an ASCII control byte or `:`.
    ForbiddenByte {
        /// The offending byte.
        byte: u8,
    },
}

impl std::fmt::Display for ComponentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "component is empty"),
            Self::NotUtf8 => write!(f, "component is not valid UTF-8"),
            Self::TooLong { len } => write!(
                f,
                "component is {len} bytes, over the {}-byte cap",
                crate::component::MAX_COMPONENT_BYTES
            ),
            Self::Nul => write!(f, "component contains a NUL byte"),
            Self::Separator { byte } => {
                write!(
                    f,
                    "component contains the path separator `{}`",
                    *byte as char
                )
            }
            Self::WindowsPrefix => {
                write!(f, "component begins with a Windows path prefix")
            }
            Self::CurDir => write!(f, "component is `.`"),
            Self::ParentDir => write!(f, "component is `..`"),
            Self::RootDir => write!(f, "component is root-relative"),
            Self::ReservedName => write!(f, "component is a Windows reserved device name"),
            Self::TrailingDotOrSpace => write!(
                f,
                "component trails with `.` or a space, or begins with a space, which Win32 \
                 silently normalises"
            ),
            Self::ForbiddenByte { byte } => {
                write!(f, "component contains the forbidden byte 0x{byte:02x}")
            }
        }
    }
}

impl std::error::Error for ComponentError {}

impl ComponentError {
    /// True when the rejection is a path-traversal or path-escape attempt.
    ///
    /// The distinction exists so that callers (and tests) can reason about
    /// "hostile input" versus "misconfigured input" without string matching.
    pub fn is_traversal_attempt(&self) -> bool {
        matches!(
            self,
            Self::Separator { .. }
                | Self::WindowsPrefix
                | Self::CurDir
                | Self::ParentDir
                | Self::RootDir
                | Self::TrailingDotOrSpace
        )
    }
}

/// Everything that can go wrong in the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SandboxError {
    /// An identifier destined to become one path component was unsafe.
    ///
    /// Upstream v2.8.2 fix: the finding that `safe_join` guarded only the two
    /// Rust-side helpers and never the execution path. Here *every* id that
    /// reaches a filesystem path is a [`crate::SafeComponent`], so there is no
    /// second, unguarded way to build a path.
    #[error("unsafe path component: {0}")]
    Component(#[from] ComponentError),

    /// Execution is disabled: the configured backend is
    /// [`crate::NullExecutor`].
    ///
    /// Upstream v2.8.2 fix: the finding that the documented default-denied
    /// boundaries had no enforcing code. The default here runs nothing and says
    /// so, rather than running code with the boundaries merely written down.
    #[error("sandbox execution is disabled: {0}")]
    ExecutionDisabled(String),

    /// The backend cannot enforce a boundary the caller asked for.
    ///
    /// Upstream v2.8.2 fix: the finding that `NetworkGuard`, `PermissionChecker`,
    /// `AuditLog` and `ExecutionToken` had zero production callers, so policy
    /// fields were validated and then ignored. This variant is how a field is
    /// never ignored: it either has an enforcement site or the request fails.
    #[error("backend `{backend}` cannot enforce `{boundary}`: {detail}")]
    PolicyNotEnforceable {
        /// The capability that was requested and cannot be delivered.
        boundary: Capability,
        /// The backend that refused.
        backend: String,
        /// Why it cannot be delivered.
        detail: String,
    },

    /// The sandbox was permanently destroyed and cannot be reused.
    ///
    /// Upstream v2.8.2 fix: a paused sandbox could be resumed at any later point
    /// and the id was a counter, so a destroyed id came back with a new sandbox's
    /// contents. Here a destroyed id is terminal.
    #[error("sandbox `{0}` was destroyed")]
    Destroyed(String),

    /// A sandbox process is already running for this id.
    ///
    /// Upstream v2.8.2 fix: `manager.rs` had one lock for all sandboxes and no
    /// per-sandbox busy state, so the notion of "busy" did not exist and two
    /// execs interleaved in one working directory.
    #[error("sandbox `{0}` is busy: {1}")]
    Busy(String, String),

    /// A limit declared in [`crate::SandboxSpec`] was hit, and the boundary that
    /// was hit is named.
    #[error("sandbox limit hit: {limit}")]
    Limit {
        /// The limit that was hit.
        limit: String,
    },

    /// The sandbox did not finish inside `timeout_ms`; the job was killed.
    ///
    /// Upstream v2.8.2 fix: the timeout only polled `try_wait` and killed one
    /// pid, so a backgrounded grandchild outlived the sandbox.
    #[error("sandbox timed out after {timeout_ms} ms; the job was killed")]
    Timeout {
        /// The configured timeout.
        timeout_ms: u64,
    },

    /// The declared program could not be started.
    #[error("cannot start the declared program: {0}")]
    Start(String),

    /// The sandbox working directory (or the sandbox root) could not be
    /// created, locked or removed.
    #[error("sandbox directory error: {0}")]
    WorkDir(String),

    /// The audit log could not be read or written.
    ///
    /// Upstream v2.8.2 fix: `AuditLog::append` had zero production callers, so
    /// an unrestricted run left no trace at all.
    #[error("audit log error: {0}")]
    Audit(String),

    /// The manager is shutting down, or has already shut down.
    #[error("sandbox manager is shut down")]
    ManagerGone,

    /// A table or lock was found in a state that cannot be repaired.
    ///
    /// Upstream v2.8.2 fix: `mgr.lock().unwrap()` panicked on poisoning, so any
    /// earlier panic turned every later sandbox call into a panic. Here poison is
    /// detected, reported as this variant, and never silently reused.
    #[error("sandbox internal state is unusable: {0}")]
    Internal(String),

    /// Orphaned sandbox directories from a previous run could not be reclaimed,
    /// so the manager refuses to create new sandboxes.
    ///
    /// Upstream v2.8.2 fix: `acquire` never checked whether the directory
    /// already existed, so a restarted daemon reissued `sb-1` on top of the
    /// previous `sb-1`'s files. Failing closed is the whole point.
    #[error("cannot reclaim {count} orphaned sandbox director(ies): {detail}")]
    OrphanReclaim {
        /// How many directories could not be reclaimed.
        count: usize,
        /// The first failure, verbatim.
        detail: String,
    },

    /// No sandbox exists with this id, **or** the caller is not its owner.
    ///
    /// The two cases share one variant so that a caller cannot learn which one
    /// it was: the daemon answers 404 for both.
    #[error("no sandbox `{0}` for this principal")]
    NotFound(String),
}

impl From<std::io::Error> for SandboxError {
    fn from(e: std::io::Error) -> Self {
        Self::WorkDir(e.to_string())
    }
}
