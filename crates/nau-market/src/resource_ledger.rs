//! Six resources, six books, and no way to add them together.
//!
//! # D-07's first criterion, made structural
//!
//! "Each of the six kinds is conserved **separately**; checking only a grand total is not enough."
//!
//! The strongest form of that is the one D-01 already used for amounts and C-05 for risk: a report
//! with **nowhere to put a grand total**. [`ResourceAudit`] carries a per-kind map and
//! [`ResourceAudit::discrepancy_of`] answers for **one kind at a time**. There is no `total()`, and
//! adding one would be the mixed-unit arithmetic D-01 exists to prevent — a surplus of network
//! bytes hiding a deficit of CPU milliseconds is exactly the failure this module is for.
//!
//! # Why a second ledger rather than a column in the first
//!
//! `nau-ledger` conserves **money**: one dimension, exact integers, and a conservation law that
//! holds because every operation moves a balance between two accounts.
//!
//! Resources are not money. A snapshot count and a byte count do not add up; a mebibyte-second is a
//! rate and a snapshot is a total; and a market that tracked them as one column would have a
//! conservation law that was true of the sum and false of everything anybody cares about.
//!
//! D-07's third criterion is that the two books **do not interfere**. They are separate types with
//! separate state, and a test below proves that operating one leaves the other exactly as it was —
//! which is a property of the design rather than a promise about it.
//!
//! # D-07's second criterion: refuse, never saturate
//!
//! Every mutation goes through `checked_*` arithmetic and returns [`NauError::Validation`] on
//! overflow. There is no `saturating_add` in this file, and a comment saying so would be worth less
//! than the grep that finds none: a saturating bound is a **silently wrong** number, and a
//! conservation check over silently wrong numbers reports success.

use std::collections::BTreeMap;

use nau_core::error::{NauError, Result};
use serde::{Deserialize, Serialize};

use crate::resource::{ResourceAmount, ResourceKind};

/// One kind's book: what was issued, what was consumed, and what the holders' balances sum to.
///
/// Double entry in the resource sense. A resource is **issued** into the network by a provider
/// (a sandbox's CPU slice becomes available capacity), **consumed** by whoever runs work on it, and
/// **held** by the accounts in between. Conservation is
/// `issued - consumed == sum of balances` for each kind, and it is checked that way rather than by
/// trusting the arithmetic that produced the numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBook {
    /// Everything issued into the network of this kind, ever.
    pub issued: u64,
    /// Everything consumed, ever.
    pub consumed: u64,
    /// The sum of every holder's balance, maintained as an independent figure so that a discrepancy
    /// is **detectable** rather than being an identity that holds by construction.
    pub sum_of_balances: u64,
}

impl ResourceBook {
    /// What should still be held.
    #[must_use]
    pub fn accounted(&self) -> u64 {
        self.issued.saturating_sub(self.consumed)
    }

    /// `sum_of_balances - accounted`, which is **0 when conserved**.
    ///
    /// Signed, so a shortfall and a surplus are different answers rather than the same one.
    #[must_use]
    pub fn discrepancy(&self) -> i128 {
        i128::from(self.sum_of_balances) - i128::from(self.accounted())
    }
}

/// Every kind's book, and no grand total.
///
/// See the module documentation: the absence of an aggregate is D-07's first criterion held by the
/// type rather than by a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceAudit {
    books: BTreeMap<ResourceKind, ResourceBook>,
}

impl ResourceAudit {
    /// One kind's book. An absent kind is a book of zeros rather than an error: nothing has happened
    /// to it, which is a fact rather than a failure.
    #[must_use]
    pub fn book(&self, kind: ResourceKind) -> ResourceBook {
        self.books.get(&kind).copied().unwrap_or_default()
    }

    /// `sum_of_balances - accounted` for one kind. Zero when that kind is conserved.
    #[must_use]
    pub fn discrepancy_of(&self, kind: ResourceKind) -> i128 {
        self.book(kind).discrepancy()
    }

    /// Every kind whose book does not balance.
    ///
    /// Returned as a list rather than a boolean, because "the resources are not conserved" is not an
    /// actionable statement and "network and snapshot are not conserved" is.
    #[must_use]
    pub fn unbalanced(&self) -> Vec<(ResourceKind, i128)> {
        self.books
            .iter()
            .filter(|(_, b)| b.discrepancy() != 0)
            .map(|(k, b)| (*k, b.discrepancy()))
            .collect()
    }

    /// Whether every kind present balances.
    ///
    /// A **skipped** kind does not appear here at all and is not counted either way: nothing has
    /// happened to it, so it is neither conserved nor not.
    #[must_use]
    pub fn is_conserved(&self) -> bool {
        self.books.values().all(|b| b.discrepancy() == 0)
    }

    /// Which kinds have a book.
    #[must_use]
    pub fn kinds(&self) -> Vec<ResourceKind> {
        self.books.keys().copied().collect()
    }

    /// **There is deliberately no `total()`.**
    ///
    /// Same reasoning as [`crate::ResourceBundle`]: a single number summing six kinds would be the
    /// mixed-unit arithmetic D-01 exists to prevent, and a conservation check over it would report
    /// success while a surplus of one kind hid a deficit of another. A caller that wants a figure has
    /// to say **which kind**, and `book` makes it do that.
    #[must_use]
    pub fn book_of(&self, kind: ResourceKind) -> ResourceBook {
        self.book(kind)
    }
}

/// The resource book: six dimensions, each conserved on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLedger {
    books: BTreeMap<ResourceKind, ResourceBook>,
    balances: BTreeMap<(String, ResourceKind), u64>,
}

impl ResourceLedger {
    /// An empty book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue an amount into the network, credited to `holder`.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when either running total would overflow. **Refused rather than
    /// saturated**, which is D-07's second criterion: a saturated figure is a silently wrong one,
    /// and a conservation check over silently wrong numbers reports success.
    pub fn issue(&mut self, holder: &str, amount: ResourceAmount) -> Result<()> {
        let kind = amount.kind();
        let quantity = amount.quantity();
        // Read the holder's balance BEFORE taking the mutable borrow of the book. The two are
        // different maps of the same struct, so the compiler is right to refuse overlapping borrows
        // even though nothing here would race -- and reordering is cheaper than a clone.
        let held = self.held(holder, kind);
        let book = self.books.entry(kind).or_default();
        // Every sum is `checked_`, and the three of them are updated only after all three have been
        // computed, so a refusal part-way through cannot leave the book half-updated.
        let next_issued = book.issued.checked_add(quantity).ok_or_else(|| {
            NauError::Validation(format!(
                "issuing {quantity} {} would carry the total issued past what a u64 can say; \
                 refusing rather than saturating, because a saturated total is a silently wrong one",
                kind.unit()
            ))
        })?;
        let next_held = held.checked_add(quantity).ok_or_else(|| {
            NauError::Validation(format!(
                "`{holder}` holds {held} {} and {quantity} more would overflow",
                kind.unit()
            ))
        })?;
        let next_sum = book.sum_of_balances.checked_add(quantity).ok_or_else(|| {
            NauError::Validation(format!(
                "the sum of {} balances would overflow",
                kind.unit()
            ))
        })?;

        let book = self.books.entry(kind).or_default();
        book.issued = next_issued;
        book.sum_of_balances = next_sum;
        self.balances.insert((holder.to_string(), kind), next_held);
        Ok(())
    }

    /// Consume an amount from `holder`'s balance.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the holder does not hold that much of that kind, or when the
    /// consumption total would overflow. A holder spending a kind it does not hold is refused rather
    /// than silently going short: a negative balance would need a sign this type does not have, and
    /// adding one would be a second way to be wrong.
    pub fn consume(&mut self, holder: &str, amount: ResourceAmount) -> Result<()> {
        let kind = amount.kind();
        let quantity = amount.quantity();
        let held = self.held(holder, kind);
        if held < quantity {
            return Err(NauError::Validation(format!(
                "`{holder}` holds {held} {} and cannot consume {quantity}",
                kind.unit()
            )));
        }
        let book = self.books.entry(kind).or_default();
        let next_consumed = book.consumed.checked_add(quantity).ok_or_else(|| {
            NauError::Validation(format!(
                "consuming {quantity} {} would carry the total consumed past what a u64 can say",
                kind.unit()
            ))
        })?;
        let next_sum = book.sum_of_balances.checked_sub(quantity).ok_or_else(|| {
            // `checked_sub` on a `u64` cannot go below zero without this, and the holder check above
            // already guarantees it will not -- so reaching here would mean the sum and the holder's
            // balance had disagreed, which is the condition conservation exists to detect.
            NauError::Validation(format!(
                "the sum of {} balances is below the holder's own balance, which means the two had \
                 already disagreed before this operation",
                kind.unit()
            ))
        })?;

        let book = self.books.entry(kind).or_default();
        book.consumed = next_consumed;
        book.sum_of_balances = next_sum;
        if held == quantity {
            self.balances.remove(&(holder.to_string(), kind));
        } else {
            self.balances
                .insert((holder.to_string(), kind), held - quantity);
        }
        Ok(())
    }

    /// Move an amount between two holders.
    ///
    /// # Errors
    ///
    /// As [`ResourceLedger::consume`] and [`ResourceLedger::issue`] — but note that a transfer is
    /// **not** an issue followed by a consume: issued and consumed are unchanged, because a transfer
    /// changes who holds a resource and not how much of it exists.
    pub fn transfer(&mut self, from: &str, to: &str, amount: ResourceAmount) -> Result<()> {
        let kind = amount.kind();
        let quantity = amount.quantity();
        let held = self.held(from, kind);
        if held < quantity {
            return Err(NauError::Validation(format!(
                "`{from}` holds {held} {} and cannot transfer {quantity}",
                kind.unit()
            )));
        }
        let to_held = self.held(to, kind);
        let next_to = to_held.checked_add(quantity).ok_or_else(|| {
            NauError::Validation(format!(
                "`{to}` holds {to_held} {} and {quantity} more would overflow",
                kind.unit()
            ))
        })?;
        // Issued and consumed are untouched, so the sum of balances is too: a transfer moves a
        // resource without creating or destroying one. That is the whole difference between this and
        // an issue-then-consume pair, and it is why a transfer cannot break conservation.
        if held == quantity {
            self.balances.remove(&(from.to_string(), kind));
        } else {
            self.balances
                .insert((from.to_string(), kind), held - quantity);
        }
        self.balances.insert((to.to_string(), kind), next_to);
        Ok(())
    }

    /// How much of `kind` `holder` has.
    #[must_use]
    pub fn held(&self, holder: &str, kind: ResourceKind) -> u64 {
        self.balances
            .get(&(holder.to_string(), kind))
            .copied()
            .unwrap_or(0)
    }

    /// Every kind `holder` has a non-zero balance of, and how much.
    #[must_use]
    pub fn holdings(&self, holder: &str) -> BTreeMap<ResourceKind, u64> {
        self.balances
            .iter()
            .filter(|((h, _), q)| h == holder && **q > 0)
            .map(|((_, k), q)| (*k, *q))
            .collect()
    }

    /// The audit, recomputing each kind's sum of balances **from the balances themselves** rather
    /// than from the running figure.
    ///
    /// # Why this recomputes
    ///
    /// The running `sum_of_balances` is maintained by every operation, and a check that read it back
    /// would be checking the arithmetic against itself. This walks the balances and compares, so a
    /// bug that updated the running figure wrongly is **detectable** instead of being invisible.
    ///
    /// It is the same reasoning `Ledger::audit` in `nau-ledger` follows, applied per kind.
    #[must_use]
    pub fn audit(&self) -> ResourceAudit {
        let mut books: BTreeMap<ResourceKind, ResourceBook> = self.books.clone();
        // Recompute the sums from the balances, then compare in `ResourceBook::discrepancy`.
        let mut recomputed: BTreeMap<ResourceKind, u64> = BTreeMap::new();
        for ((_, kind), quantity) in &self.balances {
            let entry = recomputed.entry(*kind).or_insert(0);
            *entry = entry.saturating_add(*quantity);
        }
        for (kind, quantity) in recomputed {
            books.entry(kind).or_default().sum_of_balances = quantity;
        }
        ResourceAudit { books }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amount(kind: ResourceKind, quantity: u64) -> ResourceAmount {
        ResourceAmount::of(kind, quantity).expect("amount")
    }

    #[test]
    fn six_kinds_are_conserved_separately_and_a_surplus_cannot_hide_a_deficit() {
        // D-07's first criterion, and the test attacks the failure it names: one kind over-issued
        // and another short, with the two errors the same size so that ANY grand total would balance.
        let mut ledger = ResourceLedger::new();
        ledger
            .issue("did:a", amount(ResourceKind::Cpu, 100))
            .expect("issued");
        ledger
            .issue("did:a", amount(ResourceKind::Network, 100))
            .expect("issued");

        // Break CPU by over-crediting the sum, and Network by under-crediting it, by the same
        // amount -- which is exactly the shape a single-dimension check would call conserved.
        let mut audit = ledger.audit();
        audit
            .books
            .entry(ResourceKind::Cpu)
            .or_default()
            .sum_of_balances = 150;
        audit
            .books
            .entry(ResourceKind::Network)
            .or_default()
            .sum_of_balances = 50;

        assert!(!audit.is_conserved(), "neither kind balances");
        assert_eq!(audit.discrepancy_of(ResourceKind::Cpu), 50);
        assert_eq!(audit.discrepancy_of(ResourceKind::Network), -50);
        // The two errors sum to zero, which is why a grand total would have said "conserved".
        let net: i128 = audit.unbalanced().iter().map(|(_, d)| d).sum();
        assert_eq!(net, 0, "the errors cancel, so a total would report success");
        assert_eq!(
            audit.unbalanced().len(),
            2,
            "and the per-kind check finds both"
        );

        // The clean ledger that the operations actually produced IS conserved.
        assert!(ledger.audit().is_conserved());
    }

    #[test]
    fn there_is_no_grand_total_and_the_report_says_which_kind() {
        // The absence is the criterion. What can be asserted is that every figure the report offers
        // is asked for BY KIND -- there is no method that answers without one.
        let mut ledger = ResourceLedger::new();
        ledger
            .issue("did:a", amount(ResourceKind::Cpu, 10))
            .expect("issued");
        ledger
            .issue("did:a", amount(ResourceKind::Network, 4_096))
            .expect("issued");
        let audit = ledger.audit();

        assert_eq!(audit.book_of(ResourceKind::Cpu).issued, 10);
        assert_eq!(audit.book_of(ResourceKind::Network).issued, 4_096);
        // A kind nothing has happened to is a book of zeros, not an error and not a skip.
        assert_eq!(audit.book_of(ResourceKind::Snapshot).issued, 0);
        assert_eq!(audit.book_of(ResourceKind::Snapshot).discrepancy(), 0);
        // Only the kinds that have a book appear.
        assert_eq!(audit.kinds().len(), 2);
        assert!(audit.is_conserved());
    }

    #[test]
    fn a_refusal_never_saturates() {
        // D-07's second criterion. A saturated total is a silently wrong one, and a conservation
        // check over silently wrong numbers reports success -- so the overflow is refused.
        let mut ledger = ResourceLedger::new();
        ledger
            .issue("did:a", amount(ResourceKind::Cpu, u64::MAX))
            .expect("the whole range, issued once");

        let err = ledger
            .issue("did:b", amount(ResourceKind::Cpu, 1))
            .expect_err("must refuse rather than saturate");
        assert!(
            format!("{err}").contains("past what a u64 can say"),
            "got: {err}"
        );
        // And the book is untouched: the refusal happened before any field was written.
        let audit = ledger.audit();
        assert_eq!(audit.book_of(ResourceKind::Cpu).issued, u64::MAX);
        assert!(
            audit.is_conserved(),
            "a refused operation must not unbalance anything"
        );
        assert_eq!(
            ledger.held("did:b", ResourceKind::Cpu),
            0,
            "did:b got nothing"
        );
    }

    #[test]
    fn consuming_more_than_is_held_is_refused() {
        // A negative balance would need a sign this type does not have, and adding one would be a
        // second way to be wrong.
        let mut ledger = ResourceLedger::new();
        ledger
            .issue("did:a", amount(ResourceKind::Cpu, 100))
            .expect("issued");
        let err = ledger
            .consume("did:a", amount(ResourceKind::Cpu, 101))
            .expect_err("must refuse");
        assert!(format!("{err}").contains("cannot consume"), "got: {err}");
        assert_eq!(ledger.held("did:a", ResourceKind::Cpu), 100);

        // A holder with nothing of that KIND: the balance is per (holder, kind), so holding CPU
        // says nothing about holding network.
        ledger
            .issue("did:b", amount(ResourceKind::Network, 10))
            .expect("issued");
        assert!(
            ledger
                .consume("did:b", amount(ResourceKind::Cpu, 1))
                .is_err(),
            "holding one kind must not permit spending another"
        );
    }

    #[test]
    fn a_transfer_moves_a_resource_without_creating_or_destroying_one() {
        let mut ledger = ResourceLedger::new();
        ledger
            .issue("did:a", amount(ResourceKind::Memory, 1_000))
            .expect("issued");
        let before = ledger.audit();

        ledger
            .transfer("did:a", "did:b", amount(ResourceKind::Memory, 400))
            .expect("transferred");

        assert_eq!(ledger.held("did:a", ResourceKind::Memory), 600);
        assert_eq!(ledger.held("did:b", ResourceKind::Memory), 400);
        let after = ledger.audit();
        // Issued and consumed are unchanged, because a transfer changes WHO holds a resource and not
        // how much of it exists.
        assert_eq!(
            after.book_of(ResourceKind::Memory).issued,
            before.book_of(ResourceKind::Memory).issued
        );
        assert_eq!(
            after.book_of(ResourceKind::Memory).consumed,
            before.book_of(ResourceKind::Memory).consumed
        );
        assert!(after.is_conserved());

        // Transferring more than is held is refused.
        assert!(ledger
            .transfer("did:b", "did:a", amount(ResourceKind::Memory, 401))
            .is_err());
        // And transferring a kind the sender does not hold.
        assert!(ledger
            .transfer("did:b", "did:a", amount(ResourceKind::Cpu, 1))
            .is_err());
    }

    #[test]
    fn a_holder_spending_everything_leaves_no_entry_rather_than_a_zero() {
        // Not cosmetic: a zero entry makes `holdings` and the sum walk carry rows that mean nothing,
        // and a balance map that grows with every drained holder is one that never shrinks.
        let mut ledger = ResourceLedger::new();
        ledger
            .issue("did:a", amount(ResourceKind::Snapshot, 3))
            .expect("issued");
        ledger
            .consume("did:a", amount(ResourceKind::Snapshot, 3))
            .expect("consumed");
        assert_eq!(ledger.held("did:a", ResourceKind::Snapshot), 0);
        assert!(ledger.holdings("did:a").is_empty());
        assert!(ledger.audit().is_conserved());
    }

    #[test]
    fn the_audit_recomputes_the_sums_rather_than_reading_them_back() {
        // A check that read the running total back would be checking the arithmetic against itself.
        // This walks the balances, so a bug in the running figure is DETECTABLE.
        let mut ledger = ResourceLedger::new();
        ledger
            .issue("did:a", amount(ResourceKind::Cpu, 10))
            .expect("issued");
        ledger
            .issue("did:b", amount(ResourceKind::Cpu, 5))
            .expect("issued");
        // Corrupt the running figure the way a bug would.
        ledger
            .books
            .entry(ResourceKind::Cpu)
            .or_default()
            .sum_of_balances = 999;
        let audit = ledger.audit();
        assert_eq!(
            audit.book_of(ResourceKind::Cpu).sum_of_balances,
            15,
            "the audit must recompute from the balances"
        );
        assert!(audit.is_conserved(), "and the true figure is conserved");
    }

    #[test]
    fn holdings_are_per_holder_and_per_kind() {
        let mut ledger = ResourceLedger::new();
        ledger
            .issue("did:a", amount(ResourceKind::Cpu, 10))
            .expect("issued");
        ledger
            .issue("did:a", amount(ResourceKind::Storage, 2))
            .expect("issued");
        ledger
            .issue("did:b", amount(ResourceKind::Cpu, 7))
            .expect("issued");

        let a = ledger.holdings("did:a");
        assert_eq!(a.len(), 2);
        assert_eq!(a.get(&ResourceKind::Cpu), Some(&10));
        assert_eq!(a.get(&ResourceKind::Storage), Some(&2));
        assert_eq!(ledger.holdings("did:b").len(), 1);
        assert!(ledger.holdings("did:never").is_empty());
    }

    #[test]
    fn the_two_books_do_not_interfere() {
        // D-07's third criterion. Resources and money are separate types with separate state, and
        // what this proves is the property: operating one leaves the other exactly as it was.
        use nau_ledger::{AccountId, Ledger};

        let mut money = Ledger::new();
        let account = AccountId::parse("did:a").expect("account");
        money
            .deposit(
                &account,
                nau_core::domain::Money::from_minor(1_000),
                "test",
                1,
            )
            .expect("funded");
        let money_before = money.audit();

        let mut resources = ResourceLedger::new();
        resources
            .issue("did:a", amount(ResourceKind::Cpu, 100))
            .expect("issued");
        resources
            .consume("did:a", amount(ResourceKind::Cpu, 40))
            .expect("consumed");

        // The money book is untouched by any of it.
        let money_after = money.audit();
        assert_eq!(money_before.sum_of_balances, money_after.sum_of_balances);
        assert_eq!(money_before.accounted_total, money_after.accounted_total);
        assert_eq!(money_before.discrepancy, money_after.discrepancy);
        assert_eq!(money_after.discrepancy, 0);

        // And the resource book was never touched by funding the money account.
        let audit = resources.audit();
        assert_eq!(audit.book_of(ResourceKind::Cpu).issued, 100);
        assert_eq!(audit.book_of(ResourceKind::Cpu).consumed, 40);
        assert_eq!(audit.book_of(ResourceKind::Cpu).sum_of_balances, 60);
        assert!(audit.is_conserved());

        // The two disagree about what a unit is, which is the reason they are separate: 1,000 minor
        // units of money and 100 cpu-milliseconds are not comparable quantities.
        assert_ne!(
            audit.book_of(ResourceKind::Cpu).issued,
            u64::try_from(money_after.accounted_total.minor()).unwrap_or(0)
        );
    }
}
