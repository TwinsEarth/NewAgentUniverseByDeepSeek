//! Error taxonomy shared by every crate in the workspace.
//!
//! Upstream v2.5.6 reports most failures as `String` (e.g.
//! `settle(...) -> Result<f64, String>`) and several as bare `bool`, which makes
//! it impossible for a caller to distinguish "insufficient balance" from
//! "unknown account" without string matching. Here every failure mode is a
//! typed variant.

use thiserror::Error;

use crate::identity::canonical::CanonicalError;

/// Convenience alias used throughout the workspace.
pub type Result<T, E = NauError> = std::result::Result<T, E>;

/// Every way an operation in NewAgentUniverse can fail.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NauError {
    /// The canonical-JSON layer rejected the value.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),

    /// A signature did not verify against the claimed public key.
    #[error("signature verification failed")]
    InvalidSignature,

    /// A public key was malformed (wrong length or not a valid curve point).
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// A signature was malformed (wrong length or bad hex).
    #[error("invalid signature encoding: {0}")]
    InvalidSignatureEncoding(String),

    /// A DID string was malformed.
    #[error("invalid DID `{0}`")]
    InvalidDid(String),

    /// A DID does not actually fingerprint the supplied public key.
    #[error("DID `{did}` does not match the supplied public key")]
    DidKeyMismatch {
        /// The DID that failed to match.
        did: String,
    },

    /// Checked integer arithmetic overflowed or underflowed.
    #[error("arithmetic overflow while computing {0}")]
    Overflow(&'static str),

    /// An amount was zero, negative, or unparseable where a positive amount was required.
    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    /// A balance would have gone negative.
    #[error("insufficient balance for `{account}`: available {available}, required {required}")]
    InsufficientBalance {
        /// Account whose balance was too low.
        account: String,
        /// Balance available, in minor units.
        available: i64,
        /// Amount required, in minor units.
        required: i64,
    },

    /// JSON (de)serialization failed.
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A structure failed its own invariant checks.
    #[error("validation failed: {0}")]
    Validation(String),

    /// The referenced entity does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// The operation conflicts with existing state (duplicate id, double settle, ...).
    #[error("conflict: {0}")]
    Conflict(String),

    /// The caller proved no right to perform the operation.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// The caller's proof was valid but stale (expired, nonce reused, ...).
    #[error("stale request: {0}")]
    Stale(String),

    /// A state machine rejected a transition.
    #[error("invalid state transition for task `{task}`: {from} -> {to}")]
    InvalidTransition {
        /// Task whose state machine rejected the transition.
        task: String,
        /// Current state.
        from: String,
        /// Requested state.
        to: String,
    },

    /// A consensus round could not reach a decision.
    #[error("consensus failed: {0}")]
    Consensus(String),

    /// An I/O operation failed (persistence, transport, ...).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
