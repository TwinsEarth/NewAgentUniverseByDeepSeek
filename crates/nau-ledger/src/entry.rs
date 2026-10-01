//! Individual ledger movements.
//!
//! Every mutation of the ledger appends exactly one [`LedgerEntry`]. The entry
//! list is the *journal*: [`crate::Ledger::audit`] re-derives every balance from
//! it, so the journal is not decoration — it is the second, independent source
//! of truth that makes corruption detectable.

use nau_core::{Money, TaskId};
use serde::{Deserialize, Serialize};

use crate::account::AccountId;

/// What kind of movement a [`LedgerEntry`] records.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EntryKind {
    /// External funds entering the ledger.
    Deposit,
    /// Funds leaving the ledger to the outside world.
    Withdraw,
    /// Funds locked out of a payer's account into a task's escrow account.
    Escrow,
    /// Escrowed funds paid out to a payee.
    Release,
    /// Escrowed funds returned to the original payer.
    Refund,
    /// Funds destroyed permanently.
    Slash,
    /// Funds bonded into an agent's stake account.
    Stake,
    /// Funds released from an agent's stake account.
    Unstake,
}

impl EntryKind {
    /// A stable, machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            EntryKind::Deposit => "deposit",
            EntryKind::Withdraw => "withdraw",
            EntryKind::Escrow => "escrow",
            EntryKind::Release => "release",
            EntryKind::Refund => "refund",
            EntryKind::Slash => "slash",
            EntryKind::Stake => "stake",
            EntryKind::Unstake => "unstake",
        }
    }

    /// True for a movement that only moves value between ledger accounts.
    ///
    /// Internal movements leave both the total supply and the sum of balances
    /// unchanged, which is exactly why an escrow cannot hide missing money from
    /// the conservation identity.
    pub fn is_internal(self) -> bool {
        matches!(
            self,
            EntryKind::Escrow
                | EntryKind::Release
                | EntryKind::Refund
                | EntryKind::Stake
                | EntryKind::Unstake
        )
    }

    /// True when the entry increases the total supply.
    pub fn creates_supply(self) -> bool {
        matches!(self, EntryKind::Deposit)
    }

    /// True when the entry decreases the total supply.
    pub fn destroys_supply(self) -> bool {
        matches!(self, EntryKind::Withdraw | EntryKind::Slash)
    }
}

/// One immutable journal record.
///
/// The last two fields are the record's position in the **hash chain** described
/// in [`crate::journal`]. They are part of the encoded record, so a stored entry
/// carries its own proof of position and any edit to the fields above changes
/// [`LedgerEntry::hash`].
///
/// upstream v2.8.2 fix (journal-integrity finding): upstream's persisted journal
/// was `(seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)` — no hash
/// chain, no signature, no checksum, no trigger, no constraint — while
/// `independent_audit` documented itself as trusting *only* that journal. The two
/// chain fields below are that missing integrity: they make an INSERTed
/// `Deposited` row detectable instead of silently conserved.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Zero-based position in the journal: record `i` carries `seq == i`, so the
    /// sequence numbers are dense and `0` is a real record.
    ///
    /// A break that concerns the whole file rather than one record uses
    /// [`crate::JournalBreak::FILE_LEVEL`] (`u64::MAX`) instead of a position,
    /// precisely because *every* small number including `0` is a real record.
    pub seq: u64,
    /// What kind of movement this is.
    pub kind: EntryKind,
    /// Account debited, if any.
    pub from: Option<AccountId>,
    /// Account credited, if any.
    pub to: Option<AccountId>,
    /// Amount moved. Always strictly positive.
    pub amount: Money,
    /// Free-text annotation. Never interpreted by the ledger.
    pub memo: String,
    /// Task this movement belongs to, when it is task-scoped.
    pub task: Option<TaskId>,
    /// Unix seconds at which the movement was applied.
    pub at: u64,
    /// Digest of the preceding record ([`crate::GENESIS_DIGEST`] for the first).
    ///
    /// `#[serde(default)]` so that a journal written before V1.2.3 still
    /// *deserialises*; it does not verify, and verification refuses it rather
    /// than treating an absent hash as acceptable. See
    /// [`crate::journal`] for why there is no "unhashed means fine" branch.
    #[serde(default)]
    pub prev_hash: String,
    /// Digest of this record, over `(prev_hash, canonical bytes of this entry)`.
    #[serde(default)]
    pub hash: String,
}

impl LedgerEntry {
    /// A copy of this record with both chain fields blanked: the exact byte
    /// string the digest covers.
    ///
    /// Exposed so a verifier can recompute a single record's digest without
    /// owning a whole [`crate::JournalChain`] — for example when auditing a
    /// record that was streamed off the wire.
    pub fn for_hashing(&self) -> Self {
        let mut copy = self.clone();
        copy.prev_hash = String::new();
        copy.hash = String::new();
        copy
    }

    /// Recompute this record's digest from its own bytes and `prev_hash`.
    pub fn computed_hash(&self) -> nau_core::Result<String> {
        crate::journal::entry_digest(&self.prev_hash, self)
    }

    /// True when the record carries a digest that covers its own bytes.
    ///
    /// This does **not** prove the record belongs where it is; only
    /// [`crate::JournalChain::verify`] can decide that, because belonging is a
    /// property of the whole chain.
    ///
    /// A record with no digest at all (`hash` empty — what a journal written
    /// before V1.2.3, or one an attacker stripped the chain fields from, decodes
    /// to) is **not** consistent. Reporting `true` there would be the
    /// "unhashed means fine" bypass this whole module exists to close.
    pub fn is_self_consistent(&self) -> bool {
        if self.hash.len() != 64 || !self.hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        match self.computed_hash() {
            Ok(recomputed) => recomputed == self.hash,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_and_supply_changing_kinds_are_classified_exactly_once() {
        for kind in [
            EntryKind::Deposit,
            EntryKind::Withdraw,
            EntryKind::Escrow,
            EntryKind::Release,
            EntryKind::Refund,
            EntryKind::Slash,
            EntryKind::Stake,
            EntryKind::Unstake,
        ] {
            let classifications = [
                kind.is_internal(),
                kind.creates_supply(),
                kind.destroys_supply(),
            ]
            .iter()
            .filter(|c| **c)
            .count();
            assert_eq!(
                classifications, 1,
                "{kind:?} must be internal, supply-creating or supply-destroying"
            );
            assert!(!kind.label().is_empty());
        }
    }

    #[test]
    fn entries_round_trip_through_serde_without_losing_exactness() {
        let task = TaskId::parse("task-abc").unwrap();
        let entry = LedgerEntry {
            seq: 7,
            kind: EntryKind::Escrow,
            from: Some(AccountId::parse("alice").unwrap()),
            to: Some(crate::account::escrow_account(&task)),
            amount: Money::parse("0.1").unwrap(),
            memo: "lock it".into(),
            task: Some(task.clone()),
            at: 1_700_000_000,
            prev_hash: "genesis".into(),
            hash: "0".repeat(64),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: LedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
        assert_eq!(back.amount.minor(), 100_000, "money stays an integer");
        assert!(json.contains("100000"), "no float representation: {json}");
    }

    #[test]
    fn chain_fields_are_dropped_from_the_hashed_bytes_and_defaulted_on_load() {
        let mut entry = LedgerEntry {
            seq: 1,
            kind: EntryKind::Deposit,
            from: None,
            to: Some(AccountId::parse("alice").unwrap()),
            amount: Money::from_minor(1_000),
            memo: String::new(),
            task: None,
            at: 5,
            prev_hash: "genesis".into(),
            hash: String::new(),
        };
        // An unstamped record is not self-consistent, because the empty digest is
        // not a digest. That is the fail-closed direction.
        assert!(!entry.is_self_consistent());
        // Stamp it with the digest its own bytes imply.
        entry.hash = entry.computed_hash().expect("hashable");
        let hashed = entry.for_hashing();
        assert!(hashed.prev_hash.is_empty() && hashed.hash.is_empty());
        // The digest cannot depend on the chain fields it stores: `computed_hash`
        // reads `self.prev_hash`, so compare against the blanked copy.
        assert_eq!(
            hashed.computed_hash().unwrap(),
            crate::journal::entry_digest("", &hashed).unwrap()
        );
        assert!(
            entry.is_self_consistent(),
            "a stamped record self-checks regardless of position"
        );

        // A pre-chain record (no `prev_hash`/`hash` keys at all) still decodes...
        let legacy = r#"{"seq":1,"kind":"Deposit","from":null,"to":"alice","amount":1000,"memo":"","task":null,"at":5}"#;
        let decoded: LedgerEntry = serde_json::from_str(legacy).unwrap();
        assert!(decoded.prev_hash.is_empty() && decoded.hash.is_empty());
        // ...but it does not verify, which is the fail-closed direction.
        assert!(!decoded.is_self_consistent());
    }
}
