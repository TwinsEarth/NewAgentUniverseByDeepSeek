//! Validated ledger account identifiers and the reserved internal namespaces.
//!
//! Upstream v2.5.6 keeps balances in a `HashMap<String, f64>` and never checks
//! what a key may contain, so `""`, a 4 KB string, or a string containing a
//! newline are all legal "accounts" and a serialized log can be forged by
//! choosing a colliding label. [`AccountId::parse`] is the validating entry
//! point for any identifier that arrives from outside the process.
//!
//! The reserved namespaces come from upstream's one genuinely good idea: keeping
//! locked task funds in a *dedicated internal account* rather than in a side
//! variable. That makes escrow conservable by the same O(1) identity as every
//! other balance, and it makes the O(N) audit able to see a stolen escrow.

use std::fmt;
use std::str::FromStr;

use nau_core::{Did, NauError, Result, TaskId};
use serde::{Deserialize, Serialize};

/// Maximum length accepted by [`AccountId::parse`].
///
/// Internal namespace accounts ([`escrow_account`], [`stake_account`]) embed a
/// full [`TaskId`] or [`Did`] and may legitimately be longer than this; they are
/// constructed by this crate rather than parsed, and the bound here is the one
/// that applies to *externally supplied* identifiers.
pub const MAX_ACCOUNT_ID_LEN: usize = 64;

/// Namespace prefix of the per-task escrow account.
pub const ESCROW_PREFIX: &str = "__escrow__:";

/// Namespace prefix of the per-agent stake account.
pub const STAKE_PREFIX: &str = "__stake__:";

/// True when `b` may appear in a user-supplied account identifier.
const fn is_allowed_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':' || b == b'.'
}

/// A validated ledger account identifier.
///
/// Serializes transparently as a JSON string, exactly like [`TaskId`] and
/// [`Did`] in `nau-core`, so it can sit inside a signed canonical payload.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    /// Validate and wrap an externally supplied identifier.
    ///
    /// Rejected: the empty string, anything longer than [`MAX_ACCOUNT_ID_LEN`],
    /// and anything outside `[A-Za-z0-9_-:.]`.
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(NauError::Validation("account id must not be empty".into()));
        }
        if s.len() > MAX_ACCOUNT_ID_LEN {
            return Err(NauError::Validation(format!(
                "account id is {} bytes, the maximum is {MAX_ACCOUNT_ID_LEN}",
                s.len()
            )));
        }
        if !s.bytes().all(is_allowed_byte) {
            return Err(NauError::Validation(format!(
                "account id `{s}` may only contain ASCII letters, digits, `-`, `_`, `:` and `.`"
            )));
        }
        Ok(Self(s.to_string()))
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when this is a reserved internal (escrow or stake) account.
    pub fn is_system(&self) -> bool {
        self.0.starts_with(ESCROW_PREFIX) || self.0.starts_with(STAKE_PREFIX)
    }

    /// Build a reserved internal account. Not part of the public surface.
    ///
    /// The inputs are a compile-time prefix plus a [`TaskId`] or [`Did`], both of
    /// which are already restricted to characters this crate's alphabet accepts,
    /// so no character validation is needed — only the length bound is relaxed.
    fn system(prefix: &str, suffix: &str) -> Self {
        Self(format!("{prefix}{suffix}"))
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({})", self.0)
    }
}

impl FromStr for AccountId {
    type Err = NauError;
    fn from_str(s: &str) -> Result<Self> {
        AccountId::parse(s)
    }
}

/// The escrow account that holds `task`'s locked funds.
///
/// Upstream's trick of a dedicated internal account — rather than a
/// `HashMap<TaskId, f64>` of "locked" amounts — is kept deliberately: it makes
/// the locked funds part of the same balance sum as everything else, so a
/// conservation check covers them for free.
pub fn escrow_account(task: &TaskId) -> AccountId {
    AccountId::system(ESCROW_PREFIX, task.as_str())
}

/// The stake account that holds `agent`'s bonded funds.
pub fn stake_account(agent: &Did) -> AccountId {
    AccountId::system(STAKE_PREFIX, agent.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_identifiers_are_validated() {
        assert!(AccountId::parse("alice").is_ok());
        assert!(AccountId::parse("alice-01").is_ok());
        assert!(AccountId::parse("bank.eu:1_x").is_ok());
        assert_eq!(AccountId::parse("alice").unwrap().as_str(), "alice");
        assert_eq!(AccountId::parse("alice").unwrap().to_string(), "alice");

        assert!(AccountId::parse("").is_err());
        assert!(AccountId::parse("has space").is_err());
        assert!(AccountId::parse("has/slash").is_err());
        assert!(AccountId::parse("has\nnewline").is_err());
        assert!(AccountId::parse("ünicode").is_err());
        assert!(AccountId::parse(&"x".repeat(MAX_ACCOUNT_ID_LEN + 1)).is_err());
        assert!(AccountId::parse(&"x".repeat(MAX_ACCOUNT_ID_LEN)).is_ok());
    }

    #[test]
    fn from_str_matches_parse() {
        let by_str: AccountId = "alice".parse().unwrap();
        assert_eq!(by_str, AccountId::parse("alice").unwrap());
        assert!("".parse::<AccountId>().is_err());
    }

    #[test]
    fn internal_accounts_are_namespaced_and_marked_system() {
        let task = TaskId::parse("task-abc").unwrap();
        let escrow = escrow_account(&task);
        assert_eq!(escrow.as_str(), "__escrow__:task-abc");
        assert!(escrow.is_system());
        assert!(!AccountId::parse("alice").unwrap().is_system());

        let did = Did::parse("did:nau:34750f98bd59fcfc").unwrap();
        let stake = stake_account(&did);
        assert_eq!(stake.as_str(), "__stake__:did:nau:34750f98bd59fcfc");
        assert!(stake.is_system());

        // There is no way to confuse the two namespaces.
        assert_ne!(escrow, stake);
    }

    #[test]
    fn a_maximal_task_id_still_produces_a_usable_system_account() {
        // `TaskId` allows 64 characters, so the escrow account is longer than the
        // user-facing bound. That is intentional and documented: the bound applies
        // to `parse`, not to internal construction.
        let task = TaskId::parse(&"t".repeat(64)).unwrap();
        let escrow = escrow_account(&task);
        assert!(escrow.as_str().starts_with(ESCROW_PREFIX));
        assert!(escrow.as_str().len() > MAX_ACCOUNT_ID_LEN);
        assert!(escrow.as_str().bytes().all(is_allowed_byte));
    }
}
