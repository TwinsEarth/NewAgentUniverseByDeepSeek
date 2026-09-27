//! The ledger itself: accounts, balances, escrow, stakes and slashing.
//!
//! # The two conservation paths
//!
//! [`Ledger::conservation`] is **O(1)**. It compares incrementally maintained
//! counters:
//!
//! ```text
//! sum_of_balances == total_deposited - total_withdrawn - total_slashed
//! ```
//!
//! Every method that writes a balance writes the matching counter in the same
//! call, so this identity can only break if a counter is corrupted. What it
//! *cannot* see is an individual account balance that was changed behind the
//! ledger's back: the counter `balance_sum` is unchanged, so the identity still
//! holds and the ledger still reports `conserved: true`.
//!
//! [`Ledger::audit`] is **O(N)** and exists precisely for that case. It
//!
//! * sums the live balance map (rather than reading the counter),
//! * re-derives every balance by replaying the journal,
//! * re-derives `total_deposited`/`withdrawn`/`slashed` from the journal,
//! * re-derives the escrowed amount from the live escrow accounts, and
//! * reconciles the live escrow records against those accounts,
//!
//! and reports `conserved: false` if any of those disagree. Upstream v2.5.6 had
//! an equivalent full rescan (`audit_full_scan`) but called it from nowhere, so
//! the useless check was the only one that ever ran.
//!
//! # Escrow accounts are ordinary accounts
//!
//! Because locked funds live in a real account, [`Ledger::slash`] and
//! [`Ledger::withdraw`] *can* be pointed at an escrow account — a dispute ruling
//! seizing a locked budget is a real operation. When that happens the escrow
//! record no longer matches the funds behind it:
//!
//! * [`Ledger::release`] and [`Ledger::refund`] then refuse with
//!   [`NauError::InsufficientBalance`] rather than paying out, so the shortfall
//!   can never be covered by creating money;
//! * [`Ledger::escrow_shortfall`] reports it; and
//! * [`Ledger::audit`] reports `conserved: false`, because the books no longer
//!   reconcile — even though the *money* is still conserved (the `discrepancy`
//!   stays zero). [`Ledger::conservation`] sees none of this, which is exactly
//!   the difference between the two paths.

use std::collections::{BTreeMap, HashMap};

use nau_core::{Did, Money, NauError, Result, TaskId};

use crate::account::{escrow_account, stake_account, AccountId, ESCROW_PREFIX};
use crate::entry::{EntryKind, LedgerEntry};
use crate::report::{clamp_i64, ConservationReport};

/// A live escrow: funds locked for one task and awaiting release or refund.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EscrowRecord {
    /// The task the funds are held for.
    pub task: TaskId,
    /// The account the funds were taken from. Only this account may be refunded.
    pub payer: AccountId,
    /// The amount currently held. Always strictly positive.
    pub amount: Money,
    /// Unix seconds at which the escrow was opened.
    pub opened_at: u64,
}

/// An exact, integer-only double-entry ledger.
///
/// See the [module documentation](self) for the conservation model.
#[derive(Default)]
pub struct Ledger {
    /// Accounts in insertion order, so that the O(N) audit can iterate them
    /// deterministically.
    accounts: Vec<AccountId>,
    /// Live balances. Only [`Ledger::credit`] ever creates a key.
    balances: HashMap<AccountId, Money>,
    /// The journal. Every successful mutation appends exactly one entry.
    entries: Vec<LedgerEntry>,
    /// Next journal sequence number.
    seq: u64,

    /// O(1) counter: the sum of every balance.
    balance_sum: Money,
    /// O(1) counter: everything ever deposited.
    total_deposited: Money,
    /// O(1) counter: everything ever withdrawn.
    total_withdrawn: Money,
    /// O(1) counter: everything ever slashed.
    total_slashed: Money,
    /// O(1) counter: funds currently locked in escrow accounts.
    total_escrowed: Money,
    /// O(1) counter: funds released from escrow to payees.
    total_paid: Money,
    /// O(1) counter: funds returned from escrow to payers.
    total_refunded: Money,

    /// Live escrows, keyed by task.
    escrows: BTreeMap<TaskId, EscrowRecord>,
}

/// Reject a non-positive amount before it can invert the direction of a movement.
///
/// Upstream v2.5.6 fix: `deposit(&account, -100.0)` *credited* the account and
/// *incremented* `total_budget`, so the conservation identity stayed satisfied
/// while money appeared from nowhere. Refusing zero is equally important: a
/// zero-amount entry is a no-op that still advances the journal.
fn require_positive(amount: Money, what: &str) -> Result<()> {
    if amount.is_positive() {
        Ok(())
    } else {
        Err(NauError::InvalidAmount(format!(
            "{what} must be greater than zero, got {}",
            amount.to_decimal_string()
        )))
    }
}

/// A full replay of the journal, in `i128` so that accumulation cannot overflow
/// and so that a corrupted `i64` balance cannot masquerade as a valid one.
struct Replay {
    /// Balances re-derived from the journal.
    balances: HashMap<AccountId, i128>,
    /// Deposits re-derived from the journal.
    deposited: i128,
    /// Withdrawals re-derived from the journal.
    withdrawn: i128,
    /// Slashes re-derived from the journal.
    slashed: i128,
}

impl Replay {
    /// Replay `entries` from an empty ledger.
    fn of(entries: &[LedgerEntry]) -> Self {
        let mut replay = Replay {
            balances: HashMap::new(),
            deposited: 0,
            withdrawn: 0,
            slashed: 0,
        };
        for entry in entries {
            let amount = i128::from(entry.amount.minor());
            if let Some(from) = &entry.from {
                let slot = replay.balances.entry(from.clone()).or_insert(0);
                *slot = slot.saturating_sub(amount);
            }
            if let Some(to) = &entry.to {
                let slot = replay.balances.entry(to.clone()).or_insert(0);
                *slot = slot.saturating_add(amount);
            }
            match entry.kind {
                EntryKind::Deposit => replay.deposited = replay.deposited.saturating_add(amount),
                EntryKind::Withdraw => replay.withdrawn = replay.withdrawn.saturating_add(amount),
                EntryKind::Slash => replay.slashed = replay.slashed.saturating_add(amount),
                // Internal transfers change neither the supply nor the sum.
                EntryKind::Escrow
                | EntryKind::Release
                | EntryKind::Refund
                | EntryKind::Stake
                | EntryKind::Unstake => {}
            }
        }
        replay
    }
}

impl Ledger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    // ---------------------------------------------------------------- reads

    /// The balance of `account`. Unknown accounts have balance zero.
    pub fn balance(&self, account: &AccountId) -> Money {
        self.balances.get(account).copied().unwrap_or(Money::ZERO)
    }

    /// Every recognised account, in insertion order.
    ///
    /// This is the list the O(N) audit iterates. Accounts are never removed, so
    /// an account that has been drained to zero is still visible here — which is
    /// what lets the audit notice that it was drained *twice*.
    pub fn accounts(&self) -> &[AccountId] {
        &self.accounts
    }

    /// The number of recognised accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// The whole journal, in application order.
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    /// The amount currently escrowed for `task`, or zero.
    pub fn escrowed_for(&self, task: &TaskId) -> Money {
        self.escrows
            .get(task)
            .map(|record| record.amount)
            .unwrap_or(Money::ZERO)
    }

    /// The live escrow record for `task`, if there is one.
    pub fn escrow_record(&self, task: &TaskId) -> Option<&EscrowRecord> {
        self.escrows.get(task)
    }

    /// The number of live escrows.
    pub fn live_escrows(&self) -> usize {
        self.escrows.len()
    }

    /// How much of the currently recorded escrow is **not** backed by funds in
    /// its escrow account.
    ///
    /// This is normally zero. It becomes non-zero only if locked funds were
    /// seized by [`Ledger::slash`] or [`Ledger::withdraw`], which is a bookkeeping
    /// inconsistency and is reported by [`Ledger::audit`] as `conserved: false`.
    /// [`Ledger::release`] and [`Ledger::refund`] refuse to pay out more than the
    /// escrow account actually holds, so the shortfall can never be covered by
    /// minting.
    pub fn escrow_shortfall(&self) -> Money {
        let mut shortfall: i128 = 0;
        for record in self.escrows.values() {
            let held = i128::from(self.balance(&escrow_account(&record.task)).minor());
            let recorded = i128::from(record.amount.minor());
            if held < recorded {
                shortfall = shortfall.saturating_add(recorded - held);
            }
        }
        Money::from_minor(clamp_i64(shortfall))
    }

    /// Funds released from escrow to payees over the ledger's lifetime.
    pub fn total_paid(&self) -> Money {
        self.total_paid
    }

    /// Funds returned from escrow to payers over the ledger's lifetime.
    pub fn total_refunded(&self) -> Money {
        self.total_refunded
    }

    /// The O(1) conservation check: compare the maintained counters.
    ///
    /// This is cheap enough to run after every mutation, and it catches any
    /// counter drift. It is **not** a substitute for [`Ledger::audit`]: a single
    /// corrupted account balance that leaves `balance_sum` untouched is invisible
    /// here by construction.
    pub fn conservation(&self) -> ConservationReport {
        Self::assemble(
            self.balance_sum,
            self.total_deposited,
            self.total_withdrawn,
            self.total_slashed,
            self.total_escrowed,
            self.entries.len(),
            true,
        )
    }

    /// The O(N) audit: re-derive everything and compare.
    ///
    /// Upstream v2.5.6 fix: the upstream equivalent (`audit_full_scan`) was
    /// written and then never called, so the only conservation check in the
    /// system was the O(1) one that cannot fail. This path *can* fail, and a
    /// regression test corrupts a balance to prove that it does.
    pub fn audit(&self) -> ConservationReport {
        // (1) Sum the live balances rather than reading the O(1) counter.
        let live: HashMap<AccountId, i128> = self
            .balances
            .iter()
            .map(|(account, balance)| (account.clone(), i128::from(balance.minor())))
            .collect();
        let live_sum = live.values().copied().fold(0i128, i128::saturating_add);

        // (2) + (3) Re-derive balances and supply counters from the journal.
        let replayed = Replay::of(&self.entries);
        let replayed_sum = replayed
            .balances
            .values()
            .copied()
            .fold(0i128, i128::saturating_add);

        // (4) Re-derive the escrowed amount from the live escrow accounts, not
        //     from the counter.
        let escrowed_live = live
            .iter()
            .filter(|(account, _)| account.as_str().starts_with(ESCROW_PREFIX))
            .map(|(_, balance)| *balance)
            .fold(0i128, i128::saturating_add);

        // (5) Reconcile the escrow bookkeeping against those accounts.
        let escrowed_recorded = self
            .escrows
            .values()
            .map(|record| i128::from(record.amount.minor()))
            .fold(0i128, i128::saturating_add);

        let counters_agree = i128::from(self.total_deposited.minor()) == replayed.deposited
            && i128::from(self.total_withdrawn.minor()) == replayed.withdrawn
            && i128::from(self.total_slashed.minor()) == replayed.slashed;
        let escrow_agrees = i128::from(self.total_escrowed.minor()) == escrowed_live
            && escrowed_recorded == escrowed_live;
        let journal_agrees = live == replayed.balances && live_sum == replayed_sum;

        Self::assemble(
            Money::from_minor(clamp_i64(live_sum)),
            Money::from_minor(clamp_i64(replayed.deposited)),
            Money::from_minor(clamp_i64(replayed.withdrawn)),
            Money::from_minor(clamp_i64(replayed.slashed)),
            Money::from_minor(clamp_i64(escrowed_live)),
            self.entries.len(),
            journal_agrees && counters_agree && escrow_agrees,
        )
    }

    /// Build a report from explicit parts. `extra_consistent` carries whatever
    /// additional reconciliations the caller performed.
    fn assemble(
        sum_of_balances: Money,
        total_deposited: Money,
        total_withdrawn: Money,
        total_slashed: Money,
        total_escrowed: Money,
        entries: usize,
        extra_consistent: bool,
    ) -> ConservationReport {
        let accounted_minor = clamp_i64(
            i128::from(total_deposited.minor())
                - i128::from(total_withdrawn.minor())
                - i128::from(total_slashed.minor()),
        );
        let accounted_total = Money::from_minor(accounted_minor);
        let discrepancy =
            clamp_i64(i128::from(sum_of_balances.minor()) - i128::from(accounted_total.minor()));
        ConservationReport {
            total_deposited,
            total_withdrawn,
            total_slashed,
            total_escrowed,
            sum_of_balances,
            accounted_total,
            discrepancy,
            // Exact integer equality. Upstream compared with
            // `(balance_sum - expected_sum).abs() < 0.001`; there is no epsilon
            // in this crate.
            conserved: discrepancy == 0 && extra_consistent,
            entries,
        }
    }

    // ----------------------------------------------------------- mutations

    /// Credit external funds into `account`.
    ///
    /// # Errors
    ///
    /// [`NauError::InvalidAmount`] when `amount` is not strictly positive (this
    /// is the upstream negative-deposit fix), and [`NauError::Overflow`] when the
    /// balance or the running total would exceed [`Money::MAX`].
    pub fn deposit(
        &mut self,
        account: &AccountId,
        amount: Money,
        memo: &str,
        at: u64,
    ) -> Result<()> {
        // upstream v2.5.6 fix: a "negative deposit" credited the account *and*
        // incremented the deposit counter, so conservation still reported true.
        require_positive(amount, "deposit amount")?;
        let next_total = self.total_deposited.checked_add(amount)?;
        self.credit(account, amount)?;
        self.total_deposited = next_total;
        self.push_entry(
            EntryKind::Deposit,
            None,
            Some(account.clone()),
            amount,
            memo,
            None,
            at,
        );
        Ok(())
    }

    /// Debit `account` back out of the ledger.
    ///
    /// # Errors
    ///
    /// [`NauError::InvalidAmount`] for a non-positive amount, and
    /// [`NauError::InsufficientBalance`] when the account cannot cover it. A user
    /// balance can never go negative.
    pub fn withdraw(
        &mut self,
        account: &AccountId,
        amount: Money,
        memo: &str,
        at: u64,
    ) -> Result<()> {
        require_positive(amount, "withdraw amount")?;
        let next_total = self.total_withdrawn.checked_add(amount)?;
        self.debit(account, amount)?;
        self.total_withdrawn = next_total;
        self.push_entry(
            EntryKind::Withdraw,
            Some(account.clone()),
            None,
            amount,
            memo,
            None,
            at,
        );
        Ok(())
    }

    /// Lock `amount` of `payer`'s funds for `task`.
    ///
    /// The funds move into the task's dedicated escrow account, so they stay
    /// inside the balance sum and can never be double-spent.
    ///
    /// # Errors
    ///
    /// [`NauError::InvalidAmount`] for a non-positive amount,
    /// [`NauError::Conflict`] when the task already has an open escrow, and
    /// [`NauError::InsufficientBalance`] when the payer cannot cover it.
    pub fn escrow(
        &mut self,
        task: &TaskId,
        payer: &AccountId,
        amount: Money,
        at: u64,
    ) -> Result<()> {
        require_positive(amount, "escrow amount")?;
        if let Some(existing) = self.escrows.get(task) {
            return Err(NauError::Conflict(format!(
                "task `{task}` already has an open escrow of {} (opened at {})",
                existing.amount.to_decimal_string(),
                existing.opened_at
            )));
        }
        let account = escrow_account(task);
        let next_escrowed = self.total_escrowed.checked_add(amount)?;
        // upstream v2.5.6 fix: the payer must actually hold the funds. The old
        // code deposited them out of thin air when it did not.
        self.debit(payer, amount)?;
        self.credit(&account, amount)?;
        self.total_escrowed = next_escrowed;
        self.escrows.insert(
            task.clone(),
            EscrowRecord {
                task: task.clone(),
                payer: payer.clone(),
                amount,
                opened_at: at,
            },
        );
        self.push_entry(
            EntryKind::Escrow,
            Some(payer.clone()),
            Some(account),
            amount,
            "",
            Some(task.clone()),
            at,
        );
        Ok(())
    }

    /// Pay the escrowed amount for `task` to `payee`.
    ///
    /// # Errors
    ///
    /// [`NauError::NotFound`] when the task has no open escrow, and
    /// [`NauError::InsufficientBalance`] when the escrow account no longer holds
    /// the recorded amount (for example because it was slashed).
    pub fn release(&mut self, task: &TaskId, payee: &AccountId, at: u64) -> Result<Money> {
        let record = self.escrows.get(task).cloned().ok_or_else(|| {
            NauError::NotFound(format!("no open escrow for task `{task}` to release"))
        })?;
        let account = escrow_account(task);
        // upstream v2.5.6 fix: the old settle() path ran
        //   if self.settlement.balance(&payer) < amount { self.settlement.deposit(&payer, amount); }
        // which MINTS the shortfall. Here a shortfall is an error, never a loan.
        let held = self.balance(&account);
        if held < record.amount {
            return Err(NauError::InsufficientBalance {
                account: account.to_string(),
                available: held.minor(),
                required: record.amount.minor(),
            });
        }
        let next_escrowed = self.total_escrowed.checked_sub(record.amount)?;
        let next_paid = self.total_paid.checked_add(record.amount)?;
        self.debit(&account, record.amount)?;
        self.credit(payee, record.amount)?;
        self.total_escrowed = next_escrowed;
        self.total_paid = next_paid;
        self.escrows.remove(task);
        self.push_entry(
            EntryKind::Release,
            Some(account),
            Some(payee.clone()),
            record.amount,
            "",
            Some(task.clone()),
            at,
        );
        Ok(record.amount)
    }

    /// Return the escrowed funds for `task` to the account that funded them.
    ///
    /// # Errors
    ///
    /// [`NauError::NotFound`] when there is no open escrow,
    /// [`NauError::Unauthorized`] when `payer` is not the account that funded the
    /// escrow, and [`NauError::InsufficientBalance`] when the escrow account has
    /// been drained.
    pub fn refund(&mut self, task: &TaskId, payer: &AccountId, at: u64) -> Result<Money> {
        let record = self.escrows.get(task).cloned().ok_or_else(|| {
            NauError::NotFound(format!("no open escrow for task `{task}` to refund"))
        })?;
        if &record.payer != payer {
            // A refund is the one operation that could redirect locked funds, so
            // the destination is pinned to the original funder rather than taken
            // from the caller.
            return Err(NauError::Unauthorized(format!(
                "escrow for task `{task}` was funded by `{}`, not `{payer}`",
                record.payer
            )));
        }
        let account = escrow_account(task);
        let held = self.balance(&account);
        if held < record.amount {
            return Err(NauError::InsufficientBalance {
                account: account.to_string(),
                available: held.minor(),
                required: record.amount.minor(),
            });
        }
        let next_escrowed = self.total_escrowed.checked_sub(record.amount)?;
        let next_refunded = self.total_refunded.checked_add(record.amount)?;
        self.debit(&account, record.amount)?;
        self.credit(payer, record.amount)?;
        self.total_escrowed = next_escrowed;
        self.total_refunded = next_refunded;
        self.escrows.remove(task);
        self.push_entry(
            EntryKind::Refund,
            Some(account),
            Some(payer.clone()),
            record.amount,
            "",
            Some(task.clone()),
            at,
        );
        Ok(record.amount)
    }

    /// Destroy `amount` of `account`'s funds (stake slashing).
    ///
    /// # Errors
    ///
    /// [`NauError::InvalidAmount`] for a non-positive amount (upstream accepted
    /// negative slashes, which *credited* the offender) and
    /// [`NauError::InsufficientBalance`] when the account cannot cover it.
    pub fn slash(
        &mut self,
        account: &AccountId,
        amount: Money,
        memo: &str,
        at: u64,
    ) -> Result<Money> {
        // upstream v2.5.6 fix: `slash(&acc, -100.0)` credited `acc` while
        // incrementing the slashed total, i.e. a punishment that paid the guilty.
        require_positive(amount, "slash amount")?;
        let next_total = self.total_slashed.checked_add(amount)?;
        self.debit(account, amount)?;
        self.total_slashed = next_total;
        self.push_entry(
            EntryKind::Slash,
            Some(account.clone()),
            None,
            amount,
            memo,
            None,
            at,
        );
        Ok(amount)
    }

    /// Move `amount` from `payer` into `agent`'s stake account.
    ///
    /// # Errors
    ///
    /// [`NauError::InvalidAmount`] for a non-positive amount and
    /// [`NauError::InsufficientBalance`] when `payer` cannot cover it.
    pub fn stake(&mut self, agent: &Did, payer: &AccountId, amount: Money, at: u64) -> Result<()> {
        require_positive(amount, "stake amount")?;
        let account = stake_account(agent);
        self.debit(payer, amount)?;
        self.credit(&account, amount)?;
        self.push_entry(
            EntryKind::Stake,
            Some(payer.clone()),
            Some(account),
            amount,
            "",
            None,
            at,
        );
        Ok(())
    }

    /// Move `agent`'s entire stake back out to `payee`.
    ///
    /// Because the amount is read from the stake account rather than supplied by
    /// the caller, an unstake can never move more than is actually bonded.
    ///
    /// # Errors
    ///
    /// [`NauError::NotFound`] when the agent has nothing staked.
    pub fn unstake(&mut self, agent: &Did, payee: &AccountId, at: u64) -> Result<Money> {
        let account = stake_account(agent);
        let held = self.balance(&account);
        if !held.is_positive() {
            return Err(NauError::NotFound(format!(
                "`{agent}` has no stake to unstake"
            )));
        }
        self.debit(&account, held)?;
        self.credit(payee, held)?;
        self.push_entry(
            EntryKind::Unstake,
            Some(account),
            Some(payee.clone()),
            held,
            "",
            None,
            at,
        );
        Ok(held)
    }

    // ------------------------------------------------------------ internals

    /// Add `amount` to `account` and to the running balance sum.
    ///
    /// The counter is written by the same function as the balance, so the O(1)
    /// identity can never be left stale by a successful credit.
    fn credit(&mut self, account: &AccountId, amount: Money) -> Result<()> {
        require_positive(amount, "credit amount")?;
        let current = self.balance(account);
        let next = current.checked_add(amount)?;
        let next_sum = self.balance_sum.checked_add(amount)?;
        if !self.balances.contains_key(account) {
            self.accounts.push(account.clone());
        }
        self.balances.insert(account.clone(), next);
        self.balance_sum = next_sum;
        Ok(())
    }

    /// Remove `amount` from `account` and from the running balance sum.
    ///
    /// Refuses to overdraw, so no user balance can go negative, and refuses a
    /// non-positive amount, so no caller can turn a debit into a credit.
    fn debit(&mut self, account: &AccountId, amount: Money) -> Result<()> {
        require_positive(amount, "debit amount")?;
        let current = self.balance(account);
        if current < amount {
            return Err(NauError::InsufficientBalance {
                account: account.to_string(),
                available: current.minor(),
                required: amount.minor(),
            });
        }
        let next = current.checked_sub(amount)?;
        let next_sum = self.balance_sum.checked_sub(amount)?;
        self.balances.insert(account.clone(), next);
        self.balance_sum = next_sum;
        Ok(())
    }

    /// Append a journal entry and return its sequence number.
    #[allow(clippy::too_many_arguments)]
    fn push_entry(
        &mut self,
        kind: EntryKind,
        from: Option<AccountId>,
        to: Option<AccountId>,
        amount: Money,
        memo: &str,
        task: Option<TaskId>,
        at: u64,
    ) -> u64 {
        let seq = self.seq;
        // wrapping_add: reaching 2^64 entries is physically impossible, and a
        // debug-build panic on it would be strictly worse than wrapping.
        self.seq = self.seq.wrapping_add(1);
        self.entries.push(LedgerEntry {
            seq,
            kind,
            from,
            to,
            amount,
            memo: memo.to_string(),
            task,
            at,
        });
        seq
    }

    // -------------------------------------------------------- test-only hooks

    /// Overwrite one account balance **without** touching any counter, journal
    /// entry or escrow record.
    ///
    /// This is the backdoor the regression test for upstream defect #4 needs: it
    /// simulates "somebody edited one account behind the ledger's back". After it
    /// runs, [`Ledger::conservation`] still reports `conserved: true` (the
    /// counters were not touched) while [`Ledger::audit`] must report `false`.
    /// Compiled only for tests, so it cannot be reached from production code.
    #[cfg(test)]
    pub(crate) fn force_balance_for_test(&mut self, account: &AccountId, balance: Money) {
        if !self.balances.contains_key(account) {
            self.accounts.push(account.clone());
        }
        self.balances.insert(account.clone(), balance);
    }

    /// The number of live balance entries. Used to assert that `accounts()` and
    /// the balance map never drift apart.
    #[cfg(test)]
    pub(crate) fn balance_entry_count_for_test(&self) -> usize {
        self.balances.len()
    }

    /// Access the maintained O(1) balance sum directly, for invariant tests.
    #[cfg(test)]
    pub(crate) fn balance_sum_counter_for_test(&self) -> Money {
        self.balance_sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountId;

    fn account(name: &str) -> AccountId {
        AccountId::parse(name).unwrap()
    }

    #[test]
    fn a_default_ledger_is_empty_and_conserved() {
        let ledger = Ledger::new();
        let report = ledger.conservation();
        assert!(report.conserved);
        assert_eq!(report.discrepancy, 0);
        assert_eq!(report.sum_of_balances, Money::ZERO);
        assert_eq!(ledger.account_count(), 0);
        assert!(ledger.entries().is_empty());
        assert!(ledger.audit().conserved);
    }

    #[test]
    fn credit_and_debit_are_the_only_balance_writes_and_they_keep_the_counter_in_step() {
        let mut ledger = Ledger::new();
        let alice = account("alice");
        ledger
            .deposit(&alice, Money::parse("5").unwrap(), "grant", 1)
            .unwrap();
        assert_eq!(
            ledger.balance_sum_counter_for_test(),
            Money::parse("5").unwrap()
        );
        ledger
            .withdraw(&alice, Money::parse("2").unwrap(), "spend", 2)
            .unwrap();
        assert_eq!(
            ledger.balance_sum_counter_for_test(),
            Money::parse("3").unwrap()
        );
        assert_eq!(ledger.balance(&alice), Money::parse("3").unwrap());
    }

    #[test]
    fn accounts_and_balances_never_drift_apart() {
        let mut ledger = Ledger::new();
        let alice = account("alice");
        let bob = account("bob");
        ledger
            .deposit(&alice, Money::parse("1").unwrap(), "", 1)
            .unwrap();
        ledger
            .deposit(&alice, Money::parse("1").unwrap(), "", 2)
            .unwrap();
        ledger
            .deposit(&bob, Money::parse("1").unwrap(), "", 3)
            .unwrap();
        ledger
            .withdraw(&alice, Money::parse("2").unwrap(), "", 4)
            .unwrap();
        assert_eq!(
            ledger.account_count(),
            ledger.balance_entry_count_for_test()
        );
        assert_eq!(ledger.accounts().len(), 2);
        assert_eq!(
            ledger.balance(&alice),
            Money::ZERO,
            "drained, still visible"
        );
    }
}
