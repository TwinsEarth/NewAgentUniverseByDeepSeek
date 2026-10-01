//! The migrated journal: entries, re-derived balances and exact totals.
//!
//! # The defect being corrected
//!
//! Upstream kept balances in a `HashMap<String, f64>` inside
//! `SettlementEngine` (`gsn-core/src/marketplace/settlement.rs:47`) and checked
//! conservation with a tolerance, against two other `f64` counters that the *same*
//! functions updated (`:171-183`). The audit's finding (`docs/GAP-ANALYSIS.md`
//! §2.1/§2.4) is that this cannot detect corruption, that the tolerance is six
//! orders of magnitude looser than the JavaScript SDK's, and that the independent
//! re-derivation from the journal (`audit_full_scan`, `:186-204`) had **no call
//! site at all**.
//!
//! Here every entry amount is [`Money`], every balance is re-derived from the
//! entries by checked integer addition, and the totals are compared for **exact**
//! equality. An entry that cannot be represented exactly is rejected rather than
//! rounded, so the re-derived ledger is either right or visibly incomplete — never
//! quietly wrong.

use std::collections::BTreeMap;

use nau_core::Money;
use serde::Serialize;
use serde_json::Value;

use crate::error::{MigrateError, Result};

/// The reserved escrow namespace, mirrored from `nau-ledger`.
pub const ESCROW_PREFIX: &str = "__escrow__:";
/// The reserved stake namespace, mirrored from `nau-ledger`.
pub const STAKE_PREFIX: &str = "__stake__:";
/// Longest externally supplied account label accepted, mirrored from `nau-ledger`.
pub const MAX_ACCOUNT_LABEL_LEN: usize = 64;

/// The kind of movement an entry records.
///
/// The variant names are deliberately spelled exactly like
/// `nau_ledger::EntryKind`'s serde names, so a reader using that enum can
/// deserialize the migrated journal. `nau-migrate` does not depend on `nau-ledger`
/// (the dependency set is fixed), so this is a *spelling* contract pinned by a
/// test, not something the compiler checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LedgerKind {
    /// External funds entering the ledger.
    Deposit,
    /// Funds leaving the ledger.
    Withdraw,
    /// Funds locked out of a payer's account into escrow.
    Escrow,
    /// Escrowed funds paid out to a payee.
    Release,
    /// Escrowed funds returned to the payer.
    Refund,
    /// Funds destroyed permanently.
    Slash,
    /// Funds bonded into a stake account.
    Stake,
    /// Funds released from a stake account.
    Unstake,
}

impl LedgerKind {
    /// Every variant, so tests can pin all of the spellings.
    pub const ALL: &'static [LedgerKind] = &[
        LedgerKind::Deposit,
        LedgerKind::Withdraw,
        LedgerKind::Escrow,
        LedgerKind::Release,
        LedgerKind::Refund,
        LedgerKind::Slash,
        LedgerKind::Stake,
        LedgerKind::Unstake,
    ];

    /// The `nau-ledger` spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            LedgerKind::Deposit => "Deposit",
            LedgerKind::Withdraw => "Withdraw",
            LedgerKind::Escrow => "Escrow",
            LedgerKind::Release => "Release",
            LedgerKind::Refund => "Refund",
            LedgerKind::Slash => "Slash",
            LedgerKind::Stake => "Stake",
            LedgerKind::Unstake => "Unstake",
        }
    }

    /// Map an upstream settlement reason onto a movement, if it names one.
    pub fn from_upstream_reason(reason: &str) -> Option<Self> {
        let normalised = reason.trim().to_ascii_lowercase().replace([' ', '-'], "_");
        Some(match normalised.as_str() {
            "deposit" | "deposited" | "funding" | "top_up" => LedgerKind::Deposit,
            "withdraw" | "withdrawal" | "cash_out" => LedgerKind::Withdraw,
            "escrow" | "locked" | "lock" | "hold" | "held" => LedgerKind::Escrow,
            "release" | "released" | "settle" | "settled" | "settlement" | "completed"
            | "complete" | "payment" | "paid" | "transfer" => LedgerKind::Release,
            "refund" | "refunded" | "revert" | "reverted" => LedgerKind::Refund,
            "slash" | "slashed" | "penalty" | "slashing" => LedgerKind::Slash,
            "stake" | "staked" | "bond" | "bonded" => LedgerKind::Stake,
            "unstake" | "unstaked" | "unbond" => LedgerKind::Unstake,
            _ => return None,
        })
    }

    /// What the parties imply, when the reason does not name a movement.
    pub const fn from_parties(has_from: bool, has_to: bool) -> Self {
        match (has_from, has_to) {
            (true, true) => LedgerKind::Release,
            (false, true) => LedgerKind::Deposit,
            (true, false) => LedgerKind::Withdraw,
            // A record with neither party is rejected before it gets here.
            (false, false) => LedgerKind::Release,
        }
    }
}

/// One ledger movement, read from upstream and converted exactly.
#[derive(Debug, Clone, Serialize)]
pub struct PlannedEntry {
    /// Source file.
    pub source_file: String,
    /// 1-based line number inside `ledger.jsonl`.
    pub line: usize,
    /// The task this movement belongs to, when it names one.
    pub task_id: Option<String>,
    /// Account debited, if any.
    pub from: Option<String>,
    /// Account credited, if any.
    pub to: Option<String>,
    /// The exact amount, in integer minor units.
    pub amount: Money,
    /// The movement kind recorded for the journal.
    pub kind: LedgerKind,
    /// The upstream reason, verbatim.
    pub reason: String,
    /// The upstream timestamp, when it had one.
    pub at: Option<u64>,
    /// The exact decimal text as it appeared upstream — kept so that an operator
    /// can compare the source against the migrated value without re-reading the
    /// file, and so that "we did not round" is auditable.
    pub raw_amount: String,
}

impl PlannedEntry {
    /// The JSON object to append to [`nau_store::Store::append_ledger`].
    ///
    /// Field names follow `nau_ledger::LedgerEntry` (`seq`, `kind`, `from`, `to`,
    /// `amount`, `memo`, `task`, `at`); `amount` is an **integer** count of minor
    /// units, never a float. The three extra fields (`upstream_reason`,
    /// `raw_amount`, `source`) are provenance and are ignored by a reader that does
    /// not know them.
    pub fn to_ledger_value(&self, seq: u64) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("seq".to_string(), Value::from(seq));
        object.insert(
            "kind".to_string(),
            Value::String(self.kind.as_str().to_string()),
        );
        object.insert(
            "from".to_string(),
            self.from.clone().map_or(Value::Null, Value::String),
        );
        object.insert(
            "to".to_string(),
            self.to.clone().map_or(Value::Null, Value::String),
        );
        object.insert("amount".to_string(), Value::from(self.amount.minor()));
        object.insert(
            "memo".to_string(),
            Value::String(format!(
                "migrated from agent-universe v2.5.6 (modelled) ledger; upstream reason `{}`",
                self.reason
            )),
        );
        object.insert(
            "task".to_string(),
            self.task_id.clone().map_or(Value::Null, Value::String),
        );
        object.insert("at".to_string(), Value::from(self.at.unwrap_or(0)));
        object.insert(
            "upstream_at_known".to_string(),
            Value::Bool(self.at.is_some()),
        );
        object.insert(
            "upstream_reason".to_string(),
            Value::String(self.reason.clone()),
        );
        object.insert(
            "raw_amount".to_string(),
            Value::String(self.raw_amount.clone()),
        );
        object.insert(
            "source".to_string(),
            Value::String(self.source_file.clone()),
        );
        Value::Object(object)
    }
}

/// One account and the balance re-derived from the imported journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountBalance {
    /// Account label, exactly as upstream spelled it.
    pub account: String,
    /// Balance re-derived by checked integer addition over the entries.
    pub derived: Money,
}

/// Validate an upstream account label against this project's rules.
///
/// Mirrors `nau_ledger::AccountId::parse`: `[A-Za-z0-9_-:.]`, at most
/// [`MAX_ACCOUNT_LABEL_LEN`] bytes — except in the reserved internal namespaces,
/// which embed a whole DID or task id and are therefore longer by construction.
pub fn is_valid_account_label(label: &str) -> bool {
    let system = label.starts_with(ESCROW_PREFIX) || label.starts_with(STAKE_PREFIX);
    if !system && label.len() > MAX_ACCOUNT_LABEL_LEN {
        return false;
    }
    !label.is_empty()
        && label.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b':'
                || byte == b'.'
        })
}

/// True when the label is a reserved internal (escrow or stake) account.
pub fn is_system_account(label: &str) -> bool {
    label.starts_with(ESCROW_PREFIX) || label.starts_with(STAKE_PREFIX)
}

/// Apply `delta` to `account`, checked.
fn apply(balances: &mut BTreeMap<String, Money>, account: &str, delta: Money) -> Result<()> {
    let entry = balances.entry(account.to_string()).or_insert(Money::ZERO);
    let updated = entry
        .checked_add(delta)
        .map_err(|_| MigrateError::TotalOverflow)?;
    *entry = updated;
    Ok(())
}

/// Re-derive every account's balance from the journal, in minor units.
///
/// # Errors
///
/// [`MigrateError::TotalOverflow`] if the running balance leaves the `i64` range,
/// which cannot happen for data this crate accepted but is reported rather than
/// wrapped.
pub fn derive_balances(entries: &[PlannedEntry]) -> Result<Vec<AccountBalance>> {
    // upstream v2.5.6 fix: upstream never re-derived a balance from its journal in
    // production — `audit_full_scan` had zero call sites (`settlement.rs:186-204`)
    // — so its O(1) check only compared three counters that the same functions
    // updated. Re-deriving is the point here.
    let mut balances: BTreeMap<String, Money> = BTreeMap::new();
    for entry in entries {
        if let Some(from) = &entry.from {
            let debit = entry
                .amount
                .checked_neg()
                .map_err(|_| MigrateError::TotalOverflow)?;
            apply(&mut balances, from, debit)?;
        }
        if let Some(to) = &entry.to {
            apply(&mut balances, to, entry.amount)?;
        }
    }
    Ok(balances
        .into_iter()
        .map(|(account, derived)| AccountBalance { account, derived })
        .collect())
}

/// `(total moved, net change)` across the journal.
///
/// `total` is the sum of the amounts regardless of direction — the number an
/// operator compares against the source to prove nothing was dropped or rounded.
/// `net` is the sum of the signed movements, which is exactly zero for a closed
/// transfer journal and non-zero when an entry has only one party.
///
/// # Errors
///
/// [`MigrateError::TotalOverflow`].
// upstream v2.5.6 fix: conservation here is exact integer equality, never
// `abs() < 0.001`, and the total is reported rather than assumed to agree.
pub fn totals(entries: &[PlannedEntry]) -> Result<(Money, Money)> {
    let mut total = Money::ZERO;
    let mut net = Money::ZERO;
    for entry in entries {
        total = total
            .checked_add(Money::from_minor(entry.amount.abs_minor()))
            .map_err(|_| MigrateError::TotalOverflow)?;
        if entry.from.is_some() {
            net = net
                .checked_sub(entry.amount)
                .map_err(|_| MigrateError::TotalOverflow)?;
        }
        if entry.to.is_some() {
            net = net
                .checked_add(entry.amount)
                .map_err(|_| MigrateError::TotalOverflow)?;
        }
    }
    Ok((total, net))
}

/// Sum the re-derived balances; zero exactly when the journal is closed.
///
/// # Errors
///
/// [`MigrateError::TotalOverflow`].
pub fn sum_balances(balances: &[AccountBalance]) -> Result<Money> {
    let mut sum = Money::ZERO;
    for balance in balances {
        sum = sum
            .checked_add(balance.derived)
            .map_err(|_| MigrateError::TotalOverflow)?;
    }
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_decimal_exact;

    fn entry(from: &str, to: &str, amount: &str, reason: &str) -> PlannedEntry {
        PlannedEntry {
            source_file: "ledger.jsonl".to_string(),
            line: 1,
            task_id: None,
            from: Some(from.to_string()),
            to: Some(to.to_string()),
            amount: parse_decimal_exact(amount).expect("fixture amount is exact"),
            kind: LedgerKind::Release,
            reason: reason.to_string(),
            at: None,
            raw_amount: amount.to_string(),
        }
    }

    #[test]
    fn kinds_are_spelled_the_way_nau_ledger_spells_them() {
        // `nau_ledger::EntryKind` derives `Serialize` with no rename attribute, so
        // its serde names are the variant names. Pinned here because nau-migrate
        // does not depend on nau-ledger.
        let expected = [
            "Deposit", "Withdraw", "Escrow", "Release", "Refund", "Slash", "Stake", "Unstake",
        ];
        assert_eq!(LedgerKind::ALL.len(), expected.len());
        for (kind, name) in LedgerKind::ALL.iter().zip(expected) {
            assert_eq!(kind.as_str(), name);
            assert_eq!(
                serde_json::to_value(kind).expect("serializes"),
                Value::String(name.to_string())
            );
        }
    }

    #[test]
    fn upstream_reasons_map_to_movements_and_unknown_ones_do_not() {
        assert_eq!(
            LedgerKind::from_upstream_reason("Completed"),
            Some(LedgerKind::Release)
        );
        assert_eq!(
            LedgerKind::from_upstream_reason("  deposit "),
            Some(LedgerKind::Deposit)
        );
        assert_eq!(
            LedgerKind::from_upstream_reason("SLASHED"),
            Some(LedgerKind::Slash)
        );
        assert_eq!(
            LedgerKind::from_upstream_reason("stake"),
            Some(LedgerKind::Stake)
        );
        // A hyphenated upstream compound that does not name a movement is left
        // unmapped rather than guessed at.
        assert_eq!(LedgerKind::from_upstream_reason("stake-locked"), None);
        // The two variants the audit records as unreachable in upstream's own
        // production path are deliberately unmapped rather than guessed at.
        assert_eq!(LedgerKind::from_upstream_reason("DuplicateWork"), None);
        assert_eq!(LedgerKind::from_upstream_reason("Rejected"), None);
        assert_eq!(LedgerKind::from_upstream_reason("nonsense"), None);
        assert_eq!(LedgerKind::from_parties(true, true), LedgerKind::Release);
        assert_eq!(LedgerKind::from_parties(false, true), LedgerKind::Deposit);
        assert_eq!(LedgerKind::from_parties(true, false), LedgerKind::Withdraw);
    }

    #[test]
    fn balances_are_re_derived_exactly_from_the_journal() {
        let entries = vec![
            entry("alice", "bob", "0.1", "Completed"),
            entry("alice", "bob", "0.2", "Completed"),
            entry("bob", "carol", "0.05", "Completed"),
        ];
        let balances = derive_balances(&entries).expect("derives");
        let by_name: BTreeMap<&str, i64> = balances
            .iter()
            .map(|b| (b.account.as_str(), b.derived.minor()))
            .collect();
        assert_eq!(by_name["alice"], -300_000, "0.1 + 0.2 = 0.3 exactly");
        assert_eq!(by_name["bob"], 250_000);
        assert_eq!(by_name["carol"], 50_000);
        assert_eq!(
            sum_balances(&balances).expect("sums").minor(),
            0,
            "a closed journal sums to exactly zero"
        );
        let (total, net) = totals(&entries).expect("totals");
        assert_eq!(total.minor(), 350_000);
        assert_eq!(net.minor(), 0);
    }

    #[test]
    fn a_one_sided_entry_is_totalled_honestly_instead_of_being_smoothed_over() {
        let entries = vec![
            entry("alice", "bob", "1", "Completed"),
            PlannedEntry {
                from: None,
                ..entry("ignored", "bob", "0.5", "Deposit")
            },
        ];
        let (_total, net) = totals(&entries).expect("totals");
        assert_eq!(
            net.minor(),
            500_000,
            "an external inflow changes the supply"
        );
        let balances = derive_balances(&entries).expect("derives");
        assert_eq!(sum_balances(&balances).expect("sums").minor(), 500_000);
    }

    #[test]
    fn account_labels_follow_this_projects_rules() {
        assert!(is_valid_account_label("did:aip:34750f98bd59fcfc"));
        assert!(is_valid_account_label("bank.eu:1_x"));
        assert!(is_valid_account_label(&format!(
            "{STAKE_PREFIX}did:nau:34750f98bd59fcfc"
        )));
        assert!(is_system_account(&format!("{ESCROW_PREFIX}task-abc")));
        assert!(!is_system_account("did:nau:34750f98bd59fcfc"));
        assert!(!is_valid_account_label(""));
        assert!(!is_valid_account_label("has space"));
        assert!(!is_valid_account_label("has/slash"));
        assert!(!is_valid_account_label("ünicode"));
        assert!(!is_valid_account_label(
            &"x".repeat(MAX_ACCOUNT_LABEL_LEN + 1)
        ));
        assert!(is_valid_account_label(&"x".repeat(MAX_ACCOUNT_LABEL_LEN)));
    }

    #[test]
    fn the_journal_object_carries_an_integer_amount_and_full_provenance() {
        let value = entry("alice", "bob", "12.5", "Completed").to_ledger_value(7);
        assert_eq!(value["seq"], Value::from(7_u64));
        assert_eq!(value["amount"], Value::from(12_500_000_i64));
        assert!(
            value["amount"].is_i64(),
            "money must never reach the journal as a float"
        );
        assert_eq!(value["kind"], Value::String("Release".to_string()));
        assert_eq!(value["at"], Value::from(0_u64));
        assert_eq!(value["upstream_at_known"], Value::Bool(false));
        assert_eq!(value["raw_amount"], Value::String("12.5".to_string()));
        assert_eq!(
            value["upstream_reason"],
            Value::String("Completed".to_string())
        );
        assert!(value["memo"].as_str().expect("memo").contains("v2.5.6"));
        // A missing party is `null`, matching the optional field in the ledger type.
        let outgoing = PlannedEntry {
            to: None,
            ..entry("alice", "bob", "1", "Withdraw")
        }
        .to_ledger_value(0);
        assert_eq!(outgoing["to"], Value::Null);
        assert_eq!(outgoing["from"], Value::String("alice".to_string()));
    }
}
