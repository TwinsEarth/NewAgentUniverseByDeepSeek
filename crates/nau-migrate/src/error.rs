//! Typed failures.
//!
//! Two levels of failure exist here, and keeping them apart is deliberate:
//!
//! * [`MigrateError`] — the migration **as a whole** cannot proceed (the source
//!   path is not a tree, a file cannot be read, the store refuses the write, the
//!   plan was already applied), *or* the whole point of the operation is the
//!   error itself (an amount that cannot be represented exactly — see
//!   [`crate::amount`]).
//! * [`Warning`](crate::Warning) with `Severity::Rejection` — **one record** was
//!   refused because it cannot be migrated honestly, while the rest of the tree
//!   is still migrated. A migration tool that aborts on the first unrepresentable
//!   float is useless; a migration tool that rounds it is worse.
//!
//! Every error names the file (and, where there is one, the field) it came from.

use thiserror::Error;

/// Convenience alias for this crate's fallible operations.
pub type Result<T, E = MigrateError> = std::result::Result<T, E>;

/// A failure that stops the migration as a whole.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MigrateError {
    /// A source path could not be read.
    #[error("cannot read `{path}`: {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying operating-system error.
        #[source]
        source: std::io::Error,
    },

    /// `--from` did not name a directory.
    #[error(
        "`{path}` is not a directory; nau-migrate reads a *tree* of upstream JSON \
         artifacts (see the crate documentation for the layout it expects)"
    )]
    NotADirectory {
        /// The path that was offered.
        path: String,
    },

    /// A value was not a decimal number at all.
    #[error("`{path}`: field `{field}` = `{value}` is not a decimal number")]
    AmountNotANumber {
        /// Source file.
        path: String,
        /// Field name.
        field: String,
        /// The literal, verbatim.
        value: String,
    },

    /// A decimal value cannot be represented exactly in the destination scale.
    #[error(
        "`{path}`: field `{field}` = `{value}` needs more than {decimals} decimal places \
         and cannot be represented exactly in integer minor units (1e-{decimals}); \
         refusing to round it"
    )]
    AmountNotExact {
        /// Source file.
        path: String,
        /// Field name.
        field: String,
        /// The literal, verbatim.
        value: String,
        /// Number of decimal places the destination can represent.
        decimals: u32,
    },

    /// A decimal value is outside the range of `i64` minor units.
    #[error("`{path}`: field `{field}` = `{value}` is outside the range of i64 minor units")]
    AmountOutOfRange {
        /// Source file.
        path: String,
        /// Field name.
        field: String,
        /// The literal, verbatim.
        value: String,
    },

    /// The store refused an operation.
    #[error("store error: {source}")]
    Store {
        /// The underlying `nau-core` error.
        #[from]
        source: nau_core::NauError,
    },

    /// A core operation outside any single record failed.
    #[error("core error: {0}")]
    Core(String),

    /// This plan has already been applied to this store.
    #[error(
        "this store already records migration digest `{digest}` ({meta_key}); applying the \
         same plan again would append a second copy of every ledger entry to an append-only \
         journal. Use a fresh store, or clear that metadata key deliberately."
    )]
    AlreadyApplied {
        /// Digest of the plan that was already applied.
        digest: String,
        /// Metadata key that records it.
        meta_key: String,
    },

    /// The plan could not be canonicalized to compute its provenance digest.
    #[error("the plan could not be canonicalized for its provenance digest: {0}")]
    PlanDigest(String),

    /// Adding up migrated amounts overflowed `i64` minor units.
    #[error("the migrated total overflowed i64 minor units")]
    TotalOverflow,
}

impl MigrateError {
    /// Wrap an I/O error with the path it happened on.
    pub fn io(path: &std::path::Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.display().to_string(),
            source,
        }
    }
}
