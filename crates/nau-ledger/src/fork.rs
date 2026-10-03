//! What forking a trajectory means for money.
//!
//! # The rule, and why it needs no new ledger mechanism
//!
//! A trajectory fork shares the sandbox state of the prefix and lets branches diverge after it.
//! Money is **not** sandbox state: an escrow opened before the fork point is held **once**, by the
//! ledger, and three branches settling it would pay it out three times. That is money creation,
//! and it would break the one invariant this crate exists to hold.
//!
//! So a fork does not copy financial state. An escrow that existed at the fork point is
//! **contested**: exactly one branch may settle it, and the others are refused. Nothing in
//! [`Ledger`] has to change for this — [`Ledger::release`] already refuses when the funds are not
//! there rather than covering a shortfall by creating money, which is the property the module
//! documentation of that crate calls out. What this module adds is the **bookkeeping that says
//! which branch got there first**, so the refusal can name it instead of looking like a lost
//! race.
//!
//! # What is contested and what is not
//!
//! The distinction is *when the escrow was opened*, not which branch asks:
//!
//! * opened **at or before** the fork point — contested; one settlement, for all branches;
//! * opened **after** the fork point — the branch's own; it settles it and no other branch can
//!   even name it, because the branch that opened it is the only one that knows the task id.
//!
//! The caller supplies the contested set, because the ledger cannot see a trajectory. A caller
//! that supplies an empty set gets the behaviour of `Ledger` alone — which is correct for a
//! session that never forked, and is why the set is a parameter rather than a mode.

use std::collections::BTreeMap;

use nau_core::{Money, NauError, Result, TaskId};

use crate::account::AccountId;
use crate::ledger::Ledger;

/// Which branch consumed a contested escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contested {
    /// Nobody has settled it yet. Any branch may.
    Open,
    /// This branch settled it. The others are refused from here on.
    SettledBy(usize),
}

/// A ledger with a trajectory fork's financial semantics attached.
#[derive(Debug)]
pub struct ForkedLedger<'a> {
    ledger: &'a mut Ledger,
    fork_after: usize,
    branches: usize,
    contested: BTreeMap<String, Contested>,
}

impl<'a> ForkedLedger<'a> {
    /// Attach a fork to a ledger.
    ///
    /// `contested` are the tasks whose escrow existed **at or before** `fork_after`.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `branches` is less than two (a fork with one branch is a
    /// rename), or when a contested task has no escrow in the ledger — a contested set that names
    /// something the ledger does not hold cannot be checked, so accepting it would produce a
    /// guard that silently does nothing.
    pub fn new(
        ledger: &'a mut Ledger,
        fork_after: usize,
        branches: usize,
        contested: impl IntoIterator<Item = TaskId>,
    ) -> Result<Self> {
        if branches < 2 {
            return Err(NauError::Validation(format!(
                "a fork needs at least two branches; {branches} is a rename"
            )));
        }
        let mut map = BTreeMap::new();
        for task in contested {
            if ledger.escrow_record(&task).is_none() {
                return Err(NauError::Validation(format!(
                    "task {task} is named as contested but the ledger holds no escrow for it; a \
                     guard over an escrow that is not there would never refuse anything"
                )));
            }
            map.insert(task.to_string(), Contested::Open);
        }
        Ok(Self {
            ledger,
            fork_after,
            branches,
            contested: map,
        })
    }

    /// The step this fork was placed after.
    #[must_use]
    pub fn fork_after(&self) -> usize {
        self.fork_after
    }

    /// How many branches continue.
    #[must_use]
    pub fn branches(&self) -> usize {
        self.branches
    }

    /// Who consumed a contested escrow, if anyone.
    #[must_use]
    pub fn consumer(&self, task: &TaskId) -> Option<usize> {
        match self.contested.get(task.to_string().as_str()) {
            Some(Contested::SettledBy(branch)) => Some(*branch),
            _ => None,
        }
    }

    /// Whether any branch has settled this task.
    #[must_use]
    pub fn is_settled(&self, task: &TaskId) -> bool {
        self.consumer(task).is_some()
    }

    /// The ledger underneath.
    #[must_use]
    pub fn ledger(&self) -> &Ledger {
        self.ledger
    }

    /// Settle a task in `branch`, paying `payee`.
    ///
    /// # Errors
    ///
    /// [`NauError::Conflict`] when the task is contested and **another** branch already settled
    /// it, naming that branch. [`NauError::Validation`] when `branch` is out of range.
    ///
    /// Any error [`Ledger::release`] returns is passed through unchanged, and that is deliberate:
    /// a contested escrow that has been seized by a dispute ruling should be refused by the
    /// ledger's own insufficient-balance path, not by a second rule written here that would have
    /// to be kept in step with the first.
    pub fn settle(
        &mut self,
        branch: usize,
        task: &TaskId,
        payee: &AccountId,
        at: u64,
    ) -> Result<Money> {
        if branch >= self.branches {
            return Err(NauError::Validation(format!(
                "branch {branch} does not exist in a {}-branch fork",
                self.branches
            )));
        }

        // The guard. A contested escrow is held once, so the second branch to reach it is not
        // racing -- it is asking for money that is already spent, and it is told which branch
        // spent it rather than being left to guess.
        if let Some(Contested::SettledBy(winner)) = self.contested.get(task.to_string().as_str()) {
            return Err(NauError::Conflict(format!(
                "task {task} was escrowed before the fork at step {} and branch {winner} already \
                 settled it; the escrow is held once, and paying it in branch {branch} as well \
                 would create money",
                self.fork_after
            )));
        }

        let paid = self.ledger.release(task, payee, at)?;
        if self.contested.contains_key(task.to_string().as_str()) {
            self.contested
                .insert(task.to_string(), Contested::SettledBy(branch));
        }
        Ok(paid)
    }

    /// Refund a task in `branch`, returning the funds to `payer`.
    ///
    /// # Errors
    ///
    /// As [`ForkedLedger::settle`]: a refund is a settlement in the other direction, and two
    /// branches refunding one escrow would create money just as surely as two branches releasing
    /// it.
    pub fn refund(
        &mut self,
        branch: usize,
        task: &TaskId,
        payer: &AccountId,
        at: u64,
    ) -> Result<Money> {
        if branch >= self.branches {
            return Err(NauError::Validation(format!(
                "branch {branch} does not exist in a {}-branch fork",
                self.branches
            )));
        }
        if let Some(Contested::SettledBy(winner)) = self.contested.get(task.to_string().as_str()) {
            return Err(NauError::Conflict(format!(
                "task {task} was escrowed before the fork at step {} and branch {winner} already \
                 settled it; refunding it in branch {branch} as well would create money",
                self.fork_after
            )));
        }
        let repaid = self.ledger.refund(task, payer, at)?;
        if self.contested.contains_key(task.to_string().as_str()) {
            self.contested
                .insert(task.to_string(), Contested::SettledBy(branch));
        }
        Ok(repaid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::escrow_account;

    fn account(tag: &str) -> AccountId {
        AccountId::parse(tag).expect("account")
    }

    fn task(n: u64) -> TaskId {
        TaskId::parse(&format!("task-{n}")).expect("task id")
    }

    /// A ledger with one payer holding 1000 minor units and one worker.
    fn ledger_with_escrow(amount: i64, task_id: u64) -> (Ledger, AccountId, AccountId) {
        let mut l = Ledger::new();
        let payer = account("payer");
        let worker = account("worker");
        l.deposit(&payer, Money::from_minor(1000), "seed", 1)
            .expect("deposit");
        l.escrow(&task(task_id), &payer, Money::from_minor(amount), 2)
            .expect("escrow");
        (l, payer, worker)
    }

    #[test]
    fn a_contested_escrow_is_settled_by_exactly_one_branch() {
        // B-07's first acceptance criterion. Three branches, one escrow: one payout.
        let (mut ledger, _payer, worker) = ledger_with_escrow(100, 1);
        let mut forked = ForkedLedger::new(&mut ledger, 5, 3, [task(1)]).expect("fork");

        let first = forked
            .settle(0, &task(1), &worker, 10)
            .expect("branch 0 wins");
        assert_eq!(first, Money::from_minor(100));
        assert_eq!(forked.consumer(&task(1)), Some(0));

        for branch in [1, 2] {
            let err = forked
                .settle(branch, &task(1), &worker, 10)
                .expect_err("a second settlement must be refused");
            let text = format!("{err}");
            assert!(
                text.contains("branch 0 already settled it"),
                "the refusal must name the branch that got there first, got: {text}"
            );
            assert!(
                text.contains("would create money"),
                "the refusal must say what would go wrong, got: {text}"
            );
        }
    }

    #[test]
    fn forking_and_settling_in_every_branch_conserves_the_books() {
        // B-07's second acceptance criterion, asserted on the ledger's own audit rather than on
        // arithmetic done in the test: `discrepancy` is exactly zero and the worker holds exactly
        // what one escrow was worth.
        let (mut ledger, _payer, worker) = ledger_with_escrow(100, 1);
        let mut forked = ForkedLedger::new(&mut ledger, 5, 3, [task(1)]).expect("fork");

        let mut paid = Money::from_minor(0);
        for branch in 0..3 {
            match forked.settle(branch, &task(1), &worker, 10) {
                Ok(amount) => paid = paid.checked_add(amount).expect("no overflow"),
                Err(_) => continue,
            }
        }

        assert_eq!(
            paid,
            Money::from_minor(100),
            "three branches settling one escrow must pay it once"
        );

        let forked_ledger = forked.ledger();
        let report = forked_ledger.audit();
        assert_eq!(report.discrepancy, 0_i64, "the books must reconcile");
        assert!(report.conserved, "and the audit must say so: {report:?}");
        assert_eq!(
            forked_ledger.balance(&worker),
            Money::from_minor(100),
            "the worker holds one escrow's worth, not three"
        );
    }

    #[test]
    fn a_refund_is_a_settlement_in_the_other_direction() {
        // Two branches refunding one escrow would create money just as surely as two releasing it.
        let (mut ledger, payer, _worker) = ledger_with_escrow(100, 1);
        let mut forked = ForkedLedger::new(&mut ledger, 3, 2, [task(1)]).expect("fork");

        forked
            .refund(0, &task(1), &payer, 10)
            .expect("branch 0 refunds");
        let err = forked
            .refund(1, &task(1), &payer, 10)
            .expect_err("must refuse");
        assert!(
            format!("{err}").contains("already settled it"),
            "got: {err}"
        );
        assert_eq!(
            forked.ledger().audit().discrepancy,
            0_i64,
            "a refused refund must leave the books reconciled"
        );
    }

    #[test]
    fn a_settlement_and_a_refund_cannot_both_take_the_same_escrow() {
        // The mixed case, which a rule written separately for each method would miss.
        let (mut ledger, payer, worker) = ledger_with_escrow(100, 1);
        let mut forked = ForkedLedger::new(&mut ledger, 3, 2, [task(1)]).expect("fork");

        forked
            .settle(0, &task(1), &worker, 10)
            .expect("branch 0 releases");
        let err = forked
            .refund(1, &task(1), &payer, 10)
            .expect_err("must refuse");
        assert!(format!("{err}").contains("already settled"), "got: {err}");
        assert_eq!(forked.ledger().balance(&payer), Money::from_minor(900));
    }

    #[test]
    fn an_escrow_opened_after_the_fork_belongs_to_its_branch() {
        // Not contested, so no guard applies: the branch that opened it is the only one that
        // knows the task id, and the ledger's own escrow/release pair is enough.
        let (mut ledger, payer, worker) = ledger_with_escrow(100, 1);
        let mut forked = ForkedLedger::new(&mut ledger, 3, 2, [task(1)]).expect("fork");

        // Branch 0's own escrow, opened after the fork.
        forked
            .ledger
            .escrow(&task(99), &payer, Money::from_minor(50), 11)
            .expect("branch 0 escrows");
        let paid = forked.settle(0, &task(99), &worker, 12).expect("settles");
        assert_eq!(paid, Money::from_minor(50));
        assert!(
            !forked.is_settled(&task(99)),
            "an escrow opened after the fork is not contested, so the fork keeps no record of it"
        );
        assert_eq!(forked.ledger().audit().discrepancy, 0_i64);
    }

    #[test]
    fn a_contested_task_with_no_escrow_is_refused_at_construction() {
        // A guard over an escrow that is not there would never refuse anything, which is worse
        // than no guard because it looks like one.
        let (mut ledger, _payer, _worker) = ledger_with_escrow(100, 1);
        let err = ForkedLedger::new(&mut ledger, 3, 2, [task(777)]).expect_err("must refuse");
        assert!(format!("{err}").contains("no escrow for it"), "got: {err}");
    }

    #[test]
    fn a_one_branch_fork_is_refused() {
        let (mut ledger, _payer, _worker) = ledger_with_escrow(100, 1);
        let err = ForkedLedger::new(&mut ledger, 3, 1, []).expect_err("must refuse");
        assert!(format!("{err}").contains("a rename"), "got: {err}");
    }

    #[test]
    fn a_branch_that_does_not_exist_is_refused() {
        let (mut ledger, _payer, worker) = ledger_with_escrow(100, 1);
        let mut forked = ForkedLedger::new(&mut ledger, 3, 2, [task(1)]).expect("fork");
        let err = forked
            .settle(5, &task(1), &worker, 10)
            .expect_err("must refuse");
        assert!(format!("{err}").contains("does not exist"), "got: {err}");
    }

    #[test]
    fn a_fork_with_nothing_contested_behaves_like_the_ledger_alone() {
        // The set is a parameter rather than a mode, so a session that never forked gets the
        // ledger's own semantics and no extra guard.
        let (mut ledger, _payer, worker) = ledger_with_escrow(100, 1);
        let mut forked = ForkedLedger::new(&mut ledger, 0, 2, []).expect("fork");
        assert!(!forked.is_settled(&task(1)));
        forked.settle(0, &task(1), &worker, 10).expect("settles");
        assert!(
            !forked.is_settled(&task(1)),
            "not contested, so not tracked"
        );
        assert_eq!(forked.ledger().audit().discrepancy, 0_i64);
    }

    #[test]
    fn the_ledgers_own_refusal_is_passed_through_unchanged() {
        // A contested escrow seized by a dispute ruling should be refused by the ledger's
        // insufficient-balance path, not by a second rule written here that would have to be kept
        // in step with the first.
        let (mut ledger, payer, worker) = ledger_with_escrow(100, 1);
        // Seize the escrowed funds, exactly as the ledger's documentation describes.
        ledger
            .slash(
                &escrow_account(&task(1)),
                Money::from_minor(100),
                "seized",
                5,
            )
            .expect("slash the escrow");

        let mut forked = ForkedLedger::new(&mut ledger, 3, 2, [task(1)]).expect("fork");
        let err = forked
            .settle(0, &task(1), &worker, 10)
            .expect_err("the escrow is gone");
        assert!(
            matches!(err, NauError::InsufficientBalance { .. }),
            "the ledger's own refusal must come through, got: {err:?}"
        );
        assert!(
            !forked.is_settled(&task(1)),
            "a refused settlement must not mark the escrow consumed, or the branch that could \
             have paid it would be locked out"
        );
        let _ = payer;
    }
}
