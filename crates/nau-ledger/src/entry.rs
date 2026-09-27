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
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Zero-based position in the journal.
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
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: LedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
        assert_eq!(back.amount.minor(), 100_000, "money stays an integer");
        assert!(json.contains("100000"), "no float representation: {json}");
    }
}
