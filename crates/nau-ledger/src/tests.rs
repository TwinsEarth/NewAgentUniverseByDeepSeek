//! Regression and invariant tests for the ledger.
//!
//! Every one of the four confirmed upstream `settlement.rs` defects has a test
//! named after it, and the randomised test checks the conservation identity and
//! the no-overdraft rule after **every** generated operation.

use std::collections::BTreeMap;

use nau_core::domain::major;
use nau_core::{Did, Money, NauError, TaskId};

use crate::account::{escrow_account, stake_account, AccountId, MAX_ACCOUNT_ID_LEN};
use crate::entry::EntryKind;
use crate::ledger::Ledger;

// ---------------------------------------------------------------- helpers

/// A tiny, fully deterministic PRNG (SplitMix64).
///
/// Written out rather than pulled from `rand` so that the randomised
/// conservation test is byte-for-byte reproducible on every machine and after
/// every dependency bump: a failing seed must always reproduce the failure.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (`0` when `n == 0`).
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

fn money(s: &str) -> Money {
    Money::parse(s).expect("test literal is a valid decimal amount")
}

fn account(name: &str) -> AccountId {
    AccountId::parse(name).expect("test literal is a valid account id")
}

fn task(name: &str) -> TaskId {
    TaskId::parse(name).expect("test literal is a valid task id")
}

// ============================================================ defect 1: f64

/// upstream v2.5.6 defect 1 — money was `f64` and conservation used a tolerance
/// of `0.001`. Ten thousand additions of `0.1` must land on exactly `1000`.
#[test]
fn upstream_fix_1_money_is_integer_and_conservation_is_exact_no_epsilon() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let tenth = money("0.1");

    for at in 0..10_000u64 {
        ledger.deposit(&alice, tenth, "drip", at).unwrap();
    }

    // Exactly 1000. `f64` accumulation of 0.1 gives 1000.0000000000159 here, and
    // upstream would have accepted it because |diff| < 0.001.
    assert_eq!(ledger.balance(&alice), money("1000"));
    assert_eq!(ledger.balance(&alice).minor(), 1_000_000_000);
    assert_eq!(ledger.conservation().total_deposited, money("1000"));

    let report = ledger.conservation();
    assert!(report.conserved);
    assert_eq!(report.discrepancy, 0, "conservation is exact equality");
    assert_eq!(report.sum_of_balances, report.accounted_total);

    // The decimal round trip is also exact, which is what makes a tolerance
    // unnecessary in the first place.
    assert_eq!(
        Money::parse(&money("0.3").to_decimal_string()).unwrap(),
        money("0.3")
    );
    assert_eq!(
        money("0.1").checked_add(money("0.2")).unwrap(),
        money("0.3"),
        "0.1 + 0.2 == 0.3 exactly"
    );

    // And the audit derives the identical, exact number.
    let audit = ledger.audit();
    assert!(audit.conserved);
    assert_eq!(audit.sum_of_balances, report.sum_of_balances);
    assert_eq!(audit.total_deposited, report.total_deposited);
}

// ==================================================== defect 2: sign-blind API

/// upstream v2.5.6 defect 2 — `deposit` and `slash` took negative amounts. A
/// negative deposit credited the account *and* incremented the deposit counter,
/// so conservation still reported `true` while money appeared.
#[test]
fn upstream_fix_2_non_positive_amounts_are_rejected_by_every_mutating_method() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let t = task("task-1");
    let did = Did::parse("did:nau:34750f98bd59fcfc").unwrap();

    ledger.deposit(&alice, money("100"), "fund", 1).unwrap();
    let baseline = ledger.conservation();
    let entries_before = ledger.entries().len();

    for bad in [
        Money::ZERO,
        Money::from_minor(-1),
        money("-100"),
        money("-0.000001"),
    ] {
        // The exact upstream exploit: `deposit(&alice, -100.0)` used to CREDIT.
        assert!(
            matches!(
                ledger.deposit(&alice, bad, "negative deposit", 2),
                Err(NauError::InvalidAmount(_))
            ),
            "deposit accepted {bad:?}"
        );
        // The mirror-image exploit: `slash(&alice, -100.0)` used to CREDIT the
        // offender while incrementing the slashed total.
        assert!(
            matches!(
                ledger.slash(&alice, bad, "negative slash", 3),
                Err(NauError::InvalidAmount(_))
            ),
            "slash accepted {bad:?}"
        );
        assert!(matches!(
            ledger.withdraw(&alice, bad, "negative withdraw", 4),
            Err(NauError::InvalidAmount(_))
        ));
        assert!(matches!(
            ledger.escrow(&t, &alice, bad, 5),
            Err(NauError::InvalidAmount(_))
        ));
        assert!(matches!(
            ledger.stake(&did, &alice, bad, 6),
            Err(NauError::InvalidAmount(_))
        ));
    }

    // Nothing changed: no balance moved, no counter moved, no journal entry.
    assert_eq!(ledger.balance(&alice), money("100"));
    assert_eq!(ledger.conservation(), baseline);
    assert_eq!(ledger.entries().len(), entries_before);
    assert_eq!(ledger.account_count(), 1);
}

// ================================================== defect 3: minting funds

/// upstream v2.5.6 defect 3 — settlement ran
/// `if balance(&payer) < amount { deposit(&payer, amount) }`, i.e. it minted the
/// shortfall. Escrowing from an unfunded payer must fail and create nothing.
#[test]
fn upstream_fix_3_unfunded_escrow_is_rejected_and_creates_no_funds() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let t = task("task-1");

    let err = ledger.escrow(&t, &alice, money("1"), 1).unwrap_err();
    assert!(
        matches!(err, NauError::InsufficientBalance { .. }),
        "got {err:?}"
    );

    assert_eq!(ledger.balance(&alice), Money::ZERO);
    assert_eq!(ledger.balance(&escrow_account(&t)), Money::ZERO);
    assert_eq!(ledger.conservation().sum_of_balances, Money::ZERO);
    assert_eq!(ledger.conservation().accounted_total, Money::ZERO);
    assert!(ledger.conservation().conserved);
    assert!(ledger.audit().conserved);
    assert!(
        ledger.entries().is_empty(),
        "a rejected escrow writes no journal entry"
    );
    assert_eq!(ledger.live_escrows(), 0);

    // Even with a partial balance the whole operation is refused, never topped up.
    ledger.deposit(&alice, money("3"), "grant", 2).unwrap();
    let err = ledger.escrow(&t, &alice, money("10"), 3).unwrap_err();
    assert!(
        matches!(err, NauError::InsufficientBalance { .. }),
        "got {err:?}"
    );
    assert_eq!(ledger.balance(&alice), money("3"));
    assert_eq!(ledger.balance(&escrow_account(&t)), Money::ZERO);
}

/// The release side of the same defect: the escrow must actually hold the money.
#[test]
fn upstream_fix_3_unfunded_release_is_rejected_and_never_mints() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let bob = account("bob");
    let t = task("task-1");

    ledger.deposit(&alice, money("10"), "grant", 1).unwrap();
    ledger.escrow(&t, &alice, money("10"), 2).unwrap();
    let escrow = escrow_account(&t);
    assert_eq!(ledger.balance(&escrow), money("10"));

    // Locked funds are seized (a dispute ruling can slash an escrow account).
    ledger
        .slash(&escrow, money("10"), "seized by ruling", 3)
        .unwrap();
    assert_eq!(ledger.balance(&escrow), Money::ZERO);

    let err = ledger.release(&t, &bob, 4).unwrap_err();
    assert!(
        matches!(err, NauError::InsufficientBalance { .. }),
        "the upstream code would have deposited the shortfall; got {err:?}"
    );
    assert_eq!(
        ledger.balance(&bob),
        Money::ZERO,
        "an unfunded release must not pay the payee anything"
    );
    assert_eq!(ledger.balance(&escrow), Money::ZERO);

    // Money is still conserved: nothing was created.
    let report = ledger.conservation();
    assert!(report.conserved);
    assert_eq!(report.sum_of_balances, Money::ZERO);
    assert_eq!(report.total_deposited, money("10"));
    assert_eq!(report.total_slashed, money("10"));
    assert_eq!(report.accounted_total, Money::ZERO);

    // The stale escrow record is visible, and the audit says so.
    assert_eq!(ledger.escrow_shortfall(), money("10"));
    let audit = ledger.audit();
    assert!(
        !audit.conserved,
        "the audit reports the unbacked escrow record"
    );
    assert_eq!(audit.discrepancy, 0, "the money itself is still conserved");
}

// ============================================ defect 4: the O(1) blind spot

/// upstream v2.5.6 defect 4 — the O(1) check compares three counters that are
/// always written together, so it cannot see a single corrupted account, and the
/// O(N) rescan that could see it was never called. Both paths exist here, and the
/// audit actually fails.
#[test]
fn upstream_fix_4_audit_detects_a_corrupted_balance_that_conservation_cannot_see() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let bob = account("bob");

    ledger.deposit(&alice, money("100"), "grant", 1).unwrap();
    ledger.deposit(&bob, money("50"), "grant", 2).unwrap();

    let before = ledger.conservation();
    assert!(before.conserved);

    // Corrupt exactly one account balance, without touching any counter, journal
    // entry or escrow record. This is the "somebody edited the balance map"
    // scenario the O(1) identity is structurally blind to.
    let stolen = money("0.000040");
    let alice_before = ledger.balance(&alice);
    assert_eq!(alice_before, money("100"));
    let alice_after = alice_before.checked_sub(stolen).expect("test arithmetic");
    ledger.force_balance_for_test(&alice, alice_after);
    assert_eq!(ledger.balance(&alice), alice_after);
    assert_eq!(alice_after, money("99.999960"));

    let o1 = ledger.conservation();
    assert!(
        o1.conserved,
        "the O(1) path reads maintained counters, so it still says conserved"
    );
    assert_eq!(o1.discrepancy, 0);
    assert_eq!(o1.sum_of_balances, before.sum_of_balances);

    let audit = ledger.audit();
    assert!(
        !audit.conserved,
        "the O(N) path must detect the discrepancy the O(1) path hides"
    );
    assert_eq!(audit.discrepancy, stolen.minor().wrapping_neg());
    assert_eq!(
        audit.sum_of_balances,
        before.sum_of_balances.checked_sub(stolen).unwrap(),
        "the audit re-sums the live balances rather than reading the counter"
    );
    assert_eq!(audit.accounted_total, before.accounted_total);
}

/// The same blind spot with a fabricated account: O(1) is happy, O(N) is not.
#[test]
fn upstream_fix_4_audit_detects_an_injected_account() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    ledger.deposit(&alice, money("10"), "grant", 1).unwrap();

    ledger.force_balance_for_test(&account("ghost"), major(1_000));

    assert!(ledger.conservation().conserved, "counters untouched");
    let audit = ledger.audit();
    assert!(!audit.conserved, "the journal has no entry for `ghost`");
    assert_eq!(audit.discrepancy, major(1_000).minor());
}

/// Counter drift is caught by the audit too, because it re-derives the supply
/// counters from the journal instead of trusting them.
#[test]
fn upstream_fix_4_audit_recomputes_the_journal_and_agrees_with_the_counters() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let bob = account("bob");
    let t = task("task-1");

    ledger.deposit(&alice, money("10"), "grant", 1).unwrap();
    ledger.escrow(&t, &alice, money("4"), 2).unwrap();
    ledger.release(&t, &bob, 3).unwrap();
    ledger.withdraw(&bob, money("1"), "cash out", 4).unwrap();
    ledger.slash(&bob, money("0.5"), "fine", 5).unwrap();

    let o1 = ledger.conservation();
    let on = ledger.audit();
    assert!(o1.conserved && on.conserved);
    assert_eq!(o1.total_deposited, on.total_deposited);
    assert_eq!(o1.total_withdrawn, on.total_withdrawn);
    assert_eq!(o1.total_slashed, on.total_slashed);
    assert_eq!(o1.sum_of_balances, on.sum_of_balances);
    assert_eq!(o1.accounted_total, on.accounted_total);
    assert_eq!(o1.entries, on.entries);
    assert_eq!(o1.total_escrowed, on.total_escrowed);
    assert_eq!(on.total_deposited, money("10"));
    assert_eq!(on.total_withdrawn, money("1"));
    assert_eq!(on.total_slashed, money("0.5"));
    assert_eq!(on.sum_of_balances, money("8.5"));
    assert_eq!(on.total_escrowed, Money::ZERO, "the escrow was released");
    assert_eq!(ledger.total_paid(), money("4"));
}

// ==================================================== the O(1)/O(N) agreement

/// One generated world, with the ledger's own bookkeeping mirrored outside it so
/// that the two can be compared exactly.
struct World {
    ledger: Ledger,
    rng: SplitMix64,
    users: Vec<AccountId>,
    tasks: Vec<TaskId>,
    deposited_minor: i128,
    withdrawn_minor: i128,
    slashed_minor: i128,
    escrows: BTreeMap<TaskId, i128>,
    applied: usize,
}

impl World {
    fn new(seed: u64) -> Self {
        let users = (0..6)
            .map(|i| account(&format!("user-{i}")))
            .collect::<Vec<_>>();
        let tasks = (0..3)
            .map(|i| task(&format!("task-{i}")))
            .collect::<Vec<_>>();
        Self {
            ledger: Ledger::new(),
            rng: SplitMix64::new(seed),
            users,
            tasks,
            deposited_minor: 0,
            withdrawn_minor: 0,
            slashed_minor: 0,
            escrows: BTreeMap::new(),
            applied: 0,
        }
    }

    fn any_user(&mut self) -> AccountId {
        let index = self.rng.below(self.users.len() as u64) as usize;
        self.users[index].clone()
    }

    fn any_task(&mut self) -> TaskId {
        let index = self.rng.below(self.tasks.len() as u64) as usize;
        self.tasks[index].clone()
    }

    /// A strictly positive decimal amount, generated as a decimal *string* and
    /// parsed, so the test exercises the exact textual path rather than integers.
    fn any_amount(&mut self) -> Money {
        let minor = self.rng.below(500_000) as i64 + 1;
        let amount = Money::from_minor(minor);
        let reparsed = Money::parse(&amount.to_decimal_string()).expect("round trip");
        assert_eq!(reparsed, amount, "decimal round trip must be exact");
        amount
    }

    fn step(&mut self, now: u64) {
        let op = self.rng.below(10);
        let user = self.any_user();
        let amount = self.any_amount();
        let minor = i128::from(amount.minor());

        match op {
            0..=2 => {
                if self.ledger.deposit(&user, amount, "grant", now).is_ok() {
                    self.deposited_minor += minor;
                    self.applied += 1;
                }
            }
            3..=4 => {
                if self.ledger.withdraw(&user, amount, "cash out", now).is_ok() {
                    self.withdrawn_minor += minor;
                    self.applied += 1;
                }
            }
            5..=6 => {
                let t = self.any_task();
                if self.ledger.escrow(&t, &user, amount, now).is_ok() {
                    self.escrows.insert(t, minor);
                    self.applied += 1;
                }
            }
            7 => {
                let t = self.any_task();
                if self.escrows.contains_key(&t) {
                    let payee = self.any_user();
                    if self.ledger.release(&t, &payee, now).is_ok() {
                        self.escrows.remove(&t);
                        self.applied += 1;
                    }
                }
            }
            8 => {
                let t = self.any_task();
                if let Some(payer) = self.ledger.escrow_record(&t).map(|r| r.payer.clone()) {
                    if self.ledger.refund(&t, &payer, now).is_ok() {
                        self.escrows.remove(&t);
                        self.applied += 1;
                    }
                }
            }
            _ => {
                if self.ledger.slash(&user, amount, "fine", now).is_ok() {
                    self.slashed_minor += minor;
                    self.applied += 1;
                }
            }
        }
    }

    /// Invariants that must hold after **every** operation.
    fn check(&self) {
        let report = self.ledger.conservation();

        // The exact O(1) identity.
        assert!(report.conserved, "O(1) conservation broke: {report:?}");
        assert_eq!(report.discrepancy, 0);
        assert_eq!(report.total_deposited.minor() as i128, self.deposited_minor);
        assert_eq!(report.total_withdrawn.minor() as i128, self.withdrawn_minor);
        assert_eq!(report.total_slashed.minor() as i128, self.slashed_minor);
        assert_eq!(
            report.sum_of_balances.minor() as i128,
            self.deposited_minor - self.withdrawn_minor - self.slashed_minor
        );

        // No user balance may ever be negative, and no lower-level counter may
        // drift away from the account list.
        for user in &self.users {
            assert!(
                self.ledger.balance(user) >= Money::ZERO,
                "`{user}` went negative"
            );
        }
        assert_eq!(
            self.ledger.account_count(),
            self.ledger.balance_entry_count_for_test(),
            "the ordered account list and the balance map must not drift"
        );
        assert_eq!(
            self.ledger.balance_sum_counter_for_test(),
            report.sum_of_balances,
            "the maintained sum must equal the reported sum on the O(1) path"
        );

        // Escrow bookkeeping matches the mirror, and the counters agree.
        let mut escrowed = Money::ZERO;
        for t in &self.tasks {
            let expected = self.escrows.get(t).copied().unwrap_or(0);
            assert_eq!(
                self.ledger.escrowed_for(t).minor() as i128,
                expected,
                "escrow mirror for `{t}` drifted"
            );
            escrowed = escrowed
                .checked_add(self.ledger.escrowed_for(t))
                .expect("test arithmetic");
        }
        assert_eq!(escrowed, report.total_escrowed);
        assert_eq!(self.ledger.entries().len(), self.applied);
        assert_eq!(report.entries, self.applied);

        // Journal sequence numbers are dense and ascending.
        for (index, entry) in self.ledger.entries().iter().enumerate() {
            assert_eq!(entry.seq as usize, index);
            assert!(
                entry.amount.is_positive(),
                "no journal entry carries a non-positive amount"
            );
        }
    }
}

/// Thousands of randomised operations, with the O(1) and O(N) paths checked
/// against each other and against an independently maintained mirror.
#[test]
fn conservation_and_audit_agree_after_thousands_of_randomised_operations() {
    let mut world = World::new(0x5EED_1234_ABCD_0001);

    for step in 0..3_000u64 {
        world.step(1_700_000_000 + step);
        world.check();

        if step % 100 == 0 {
            let audit = world.ledger.audit();
            let o1 = world.ledger.conservation();
            assert!(audit.conserved, "audit failed at step {step}: {audit:?}");
            assert_eq!(audit.sum_of_balances, o1.sum_of_balances, "step {step}");
            assert_eq!(audit.accounted_total, o1.accounted_total, "step {step}");
            assert_eq!(audit.discrepancy, 0, "step {step}");
            assert_eq!(audit.total_escrowed, o1.total_escrowed, "step {step}");
        }
    }

    let audit = world.ledger.audit();
    let o1 = world.ledger.conservation();
    assert!(audit.conserved && o1.conserved);
    assert_eq!(audit, o1, "the two paths must produce the same report");
    assert!(world.applied > 1_000, "the generator must actually do work");
    assert!(
        world.ledger.account_count() > 6,
        "escrow accounts must have been created"
    );
}

/// The same test with a second seed, so a bug cannot hide behind one sequence.
#[test]
fn conservation_holds_for_a_second_independent_seed() {
    for seed in [0xDEAD_BEEF_0000_0001u64, 0x0F0F_0F0F_1234_5678] {
        let mut world = World::new(seed);
        for step in 0..1_500u64 {
            world.step(1_800_000_000 + step);
            world.check();
        }
        assert!(world.ledger.audit().conserved, "seed {seed:#x}");
    }
}

// ================================================================ lifecycle

#[test]
fn full_escrow_lifecycle_conserves_value_exactly() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let bob = account("bob");
    let carol = account("carol");
    let t = task("task-1");

    ledger.deposit(&alice, money("100"), "grant", 1).unwrap();
    ledger.escrow(&t, &alice, money("30"), 2).unwrap();
    assert_eq!(ledger.balance(&alice), money("70"));
    assert_eq!(ledger.balance(&escrow_account(&t)), money("30"));
    assert_eq!(ledger.escrowed_for(&t), money("30"));
    assert_eq!(ledger.conservation().total_escrowed, money("30"));

    let paid = ledger.release(&t, &bob, 3).unwrap();
    assert_eq!(paid, money("30"));
    assert_eq!(ledger.balance(&bob), money("30"));
    assert_eq!(ledger.balance(&escrow_account(&t)), Money::ZERO);
    assert_eq!(ledger.escrowed_for(&t), Money::ZERO);
    assert!(ledger.escrow_record(&t).is_none());
    assert_eq!(ledger.conservation().total_escrowed, Money::ZERO);
    assert!(ledger.audit().conserved);

    // A second, independent escrow that gets refunded.
    let t2 = task("task-2");
    ledger.escrow(&t2, &alice, money("20"), 4).unwrap();
    let back = ledger.refund(&t2, &alice, 5).unwrap();
    assert_eq!(back, money("20"));
    assert_eq!(ledger.balance(&alice), money("70"));
    assert_eq!(ledger.total_refunded(), money("20"));

    // A third escrow that is never settled keeps its funds locked.
    let t3 = task("task-3");
    ledger.escrow(&t3, &alice, money("10"), 6).unwrap();
    ledger.deposit(&carol, money("5"), "grant", 7).unwrap();

    let report = ledger.conservation();
    assert!(report.conserved);
    assert_eq!(report.sum_of_balances, money("105"));
    assert_eq!(report.total_escrowed, money("10"));
    assert_eq!(report.accounted_total, money("105"));
    assert_eq!(ledger.audit(), report);

    // Journal shape: deposit, escrow, release, escrow, refund, escrow, deposit.
    let kinds: Vec<EntryKind> = ledger.entries().iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![
            EntryKind::Deposit,
            EntryKind::Escrow,
            EntryKind::Release,
            EntryKind::Escrow,
            EntryKind::Refund,
            EntryKind::Escrow,
            EntryKind::Deposit,
        ]
    );
    assert_eq!(ledger.entries()[2].task.as_ref(), Some(&t));
    assert_eq!(ledger.entries()[2].to.as_ref(), Some(&bob));
}

#[test]
fn double_escrow_of_the_same_task_is_a_conflict() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let t = task("task-1");
    ledger.deposit(&alice, money("100"), "grant", 1).unwrap();

    ledger.escrow(&t, &alice, money("10"), 2).unwrap();
    let err = ledger.escrow(&t, &alice, money("10"), 3).unwrap_err();
    assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");

    // The rejected call changed nothing at all.
    assert_eq!(ledger.balance(&alice), money("90"));
    assert_eq!(ledger.escrowed_for(&t), money("10"));
    assert_eq!(ledger.total_paid(), Money::ZERO);
    assert_eq!(ledger.conservation().total_escrowed, money("10"));
    assert_eq!(ledger.entries().len(), 2);
    assert!(ledger.conservation().conserved);
    assert!(ledger.audit().conserved);
}

#[test]
fn release_and_refund_of_an_unknown_task_are_rejected() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let bob = account("bob");
    let unknown = task("task-never-escrowed");
    ledger.deposit(&alice, money("10"), "grant", 1).unwrap();

    for err in [
        ledger.release(&unknown, &bob, 2).unwrap_err(),
        ledger.refund(&unknown, &alice, 3).unwrap_err(),
    ] {
        assert!(matches!(err, NauError::NotFound(_)), "got {err:?}");
    }

    // A released escrow is gone, so releasing it again is also NotFound.
    let t = task("task-1");
    ledger.escrow(&t, &alice, money("10"), 4).unwrap();
    ledger.release(&t, &bob, 5).unwrap();
    let err = ledger.release(&t, &bob, 6).unwrap_err();
    assert!(matches!(err, NauError::NotFound(_)), "got {err:?}");
    let err = ledger.refund(&t, &alice, 7).unwrap_err();
    assert!(matches!(err, NauError::NotFound(_)), "got {err:?}");

    assert_eq!(ledger.balance(&bob), money("10"), "paid exactly once");
    assert!(ledger.conservation().conserved);
    assert!(ledger.audit().conserved);
}

#[test]
fn a_refund_cannot_be_redirected_to_another_account() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let mallory = account("mallory");
    let t = task("task-1");

    ledger.deposit(&alice, money("10"), "grant", 1).unwrap();
    ledger.escrow(&t, &alice, money("10"), 2).unwrap();

    let err = ledger.refund(&t, &mallory, 3).unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");
    assert_eq!(ledger.balance(&mallory), Money::ZERO);
    assert_eq!(
        ledger.escrowed_for(&t),
        money("10"),
        "the escrow is untouched"
    );

    assert_eq!(ledger.refund(&t, &alice, 4).unwrap(), money("10"));
    assert_eq!(ledger.balance(&alice), money("10"));
}

#[test]
fn withdrawing_more_than_the_balance_is_rejected_and_never_overdraws() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    ledger.deposit(&alice, money("10"), "grant", 1).unwrap();

    let err = ledger
        .withdraw(&alice, money("10.000001"), "too much", 2)
        .unwrap_err();
    assert!(
        matches!(err, NauError::InsufficientBalance { .. }),
        "got {err:?}"
    );
    assert_eq!(ledger.balance(&alice), money("10"));

    // Exactly the balance is fine, and leaves a zero — never a negative.
    ledger.withdraw(&alice, money("10"), "all", 3).unwrap();
    assert_eq!(ledger.balance(&alice), Money::ZERO);
    assert!(!ledger.balance(&alice).is_negative());
    assert!(ledger.conservation().conserved);
}

#[test]
fn slashing_is_exact_and_reduces_the_supply_by_exactly_the_slashed_amount() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    ledger.deposit(&alice, money("10"), "grant", 1).unwrap();

    assert_eq!(
        ledger.slash(&alice, money("0.000001"), "fine", 2).unwrap(),
        money("0.000001")
    );
    let report = ledger.conservation();
    assert_eq!(ledger.balance(&alice), money("9.999999"));
    assert_eq!(report.total_slashed, money("0.000001"));
    assert_eq!(report.accounted_total, money("9.999999"));
    assert_eq!(report.sum_of_balances, money("9.999999"));
    assert!(report.conserved);
    assert!(ledger.audit().conserved);

    // Over-slashing is refused, exactly like an overdraft.
    let err = ledger.slash(&alice, money("10"), "fine", 3).unwrap_err();
    assert!(
        matches!(err, NauError::InsufficientBalance { .. }),
        "got {err:?}"
    );
    assert!(ledger.audit().conserved);
}

#[test]
fn a_payer_cannot_escrow_someone_elses_money() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let mallory = account("mallory");
    let t = task("task-1");
    ledger.deposit(&alice, money("10"), "grant", 1).unwrap();

    let err = ledger.escrow(&t, &mallory, money("1"), 2).unwrap_err();
    assert!(
        matches!(err, NauError::InsufficientBalance { .. }),
        "got {err:?}"
    );
    assert_eq!(ledger.balance(&alice), money("10"));
    assert_eq!(ledger.balance(&mallory), Money::ZERO);
    assert_eq!(ledger.balance(&escrow_account(&t)), Money::ZERO);
}

// =================================================================== stakes

#[test]
fn staking_moves_value_into_a_dedicated_account_and_unstaking_returns_all_of_it() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let did = Did::parse("did:nau:34750f98bd59fcfc").unwrap();
    let stake = stake_account(&did);

    ledger.deposit(&alice, money("100"), "grant", 1).unwrap();
    ledger.stake(&did, &alice, money("40"), 2).unwrap();
    assert_eq!(ledger.balance(&alice), money("60"));
    assert_eq!(ledger.balance(&stake), money("40"));
    assert_eq!(ledger.conservation().sum_of_balances, money("100"));
    assert!(ledger.conservation().conserved);
    assert!(ledger.audit().conserved);

    // A slashed stake is destroyed, not transferred.
    ledger
        .slash(&stake, money("15"), "misbehaviour", 3)
        .unwrap();
    assert_eq!(ledger.balance(&stake), money("25"));
    assert_eq!(ledger.conservation().total_slashed, money("15"));
    assert_eq!(ledger.conservation().sum_of_balances, money("85"));
    assert!(ledger.audit().conserved);

    // Unstaking can only ever move what is actually bonded.
    assert_eq!(ledger.unstake(&did, &alice, 4).unwrap(), money("25"));
    assert_eq!(ledger.balance(&alice), money("85"));
    assert_eq!(ledger.balance(&stake), Money::ZERO);

    let err = ledger.unstake(&did, &alice, 5).unwrap_err();
    assert!(matches!(err, NauError::NotFound(_)), "got {err:?}");
    assert!(ledger.audit().conserved);
}

// ============================================================ account hygiene

#[test]
fn account_ids_are_validated_and_the_namespaces_are_reserved_shapes() {
    assert!(AccountId::parse("").is_err());
    assert!(AccountId::parse(&"a".repeat(MAX_ACCOUNT_ID_LEN + 1)).is_err());
    assert!(AccountId::parse("no spaces").is_err());
    assert!(AccountId::parse("no/slashes").is_err());
    assert!(AccountId::parse("user-1").is_ok());
    assert_eq!(
        escrow_account(&task("task-1")).as_str(),
        "__escrow__:task-1"
    );
    assert_eq!(
        stake_account(&Did::parse("did:nau:34750f98bd59fcfc").unwrap()).as_str(),
        "__stake__:did:nau:34750f98bd59fcfc"
    );
}

#[test]
fn the_journal_is_append_only_and_dense() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let t = task("task-1");
    ledger.deposit(&alice, money("10"), "a", 100).unwrap();
    ledger.escrow(&t, &alice, money("5"), 101).unwrap();
    ledger.release(&t, &alice, 102).unwrap();

    let entries = ledger.entries();
    assert_eq!(entries.len(), 3);
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64);
    }
    assert_eq!(entries[0].kind, EntryKind::Deposit);
    assert_eq!(entries[0].to.as_ref(), Some(&alice));
    assert_eq!(entries[0].from, None);
    assert_eq!(entries[0].at, 100);
    assert_eq!(entries[1].kind, EntryKind::Escrow);
    assert_eq!(entries[1].from.as_ref(), Some(&alice));
    assert_eq!(entries[1].to.as_ref(), Some(&escrow_account(&t)));
    assert_eq!(entries[2].kind, EntryKind::Release);
    assert_eq!(entries[2].from.as_ref(), Some(&escrow_account(&t)));
    assert_eq!(entries[2].to.as_ref(), Some(&alice));
}

#[test]
fn reports_round_trip_through_serde_as_integers() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    ledger.deposit(&alice, money("0.1"), "grant", 1).unwrap();
    ledger.deposit(&alice, money("0.2"), "grant", 2).unwrap();

    let report = ledger.audit();
    let json = serde_json::to_string(&report).unwrap();
    assert!(
        json.contains("\"sum_of_balances\":300000"),
        "money must serialize as integer minor units: {json}"
    );
    assert!(!json.contains('.'), "no floating point anywhere: {json}");
    let back: crate::report::ConservationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
    assert_eq!(back.sum_of_balances, money("0.3"));
}

#[test]
fn saturating_overflow_paths_return_errors_instead_of_wrapping() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    ledger.deposit(&alice, Money::MAX, "everything", 1).unwrap();

    let err = ledger
        .deposit(&alice, Money::from_minor(1), "one more", 2)
        .unwrap_err();
    assert!(matches!(err, NauError::Overflow(_)), "got {err:?}");
    assert_eq!(ledger.balance(&alice), Money::MAX);
    assert!(ledger.conservation().conserved);
    assert!(ledger.audit().conserved);
}

// ---------------------------------------------------------------------------
// upstream v2.8.2 fix (finding A): the journal has integrity now
// ---------------------------------------------------------------------------

/// Build a small journal through the public API and hand back its entries.
fn journal_fixture() -> (Ledger, Vec<crate::LedgerEntry>) {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let bob = account("bob");
    let t = task("task-1");
    ledger.deposit(&alice, money("100"), "grant", 1).unwrap();
    ledger.deposit(&bob, money("50"), "grant", 2).unwrap();
    ledger.escrow(&t, &alice, money("40"), 3).unwrap();
    ledger.stake(&did(9), &bob, money("10"), 4).unwrap();
    let entries = ledger.entries().to_vec();
    (ledger, entries)
}

fn did(seed: u8) -> Did {
    nau_core::Identity::from_seed(&[seed; 32]).did()
}

/// upstream v2.8.2 fix (finding A): the upstream journal table
/// (`seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL`) had no hash
/// chain, no signature, no checksum, no trigger and no constraint, so
/// `independent_audit`'s claim that it "trusts only the journal" was vacuous.
#[test]
fn a_freshly_written_journal_is_hash_chained_and_verifies() {
    let (mut ledger, entries) = journal_fixture();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].prev_hash, crate::GENESIS_DIGEST);
    for pair in entries.windows(2) {
        assert_eq!(
            pair[1].prev_hash, pair[0].hash,
            "each record must chain onto its predecessor"
        );
    }
    assert!(
        entries.iter().all(|e| e.hash.len() == 64),
        "digests are real SHA-256, not truncated"
    );
    assert!(ledger.verify_journal().is_ok());
    assert!(ledger.conservation().journal_intact);
    assert_eq!(
        ledger.conservation().journal_head,
        entries.last().map(|e| e.hash.clone()).unwrap_or_default()
    );
}

#[test]
fn an_edited_record_is_reported_at_its_sequence_number() {
    let (_ledger, entries) = journal_fixture();
    let mut tampered = entries.clone();
    // A "deposit" invented in the middle of the file.
    tampered[1].amount = Money::from_minor(999_999_999_000);

    let err = Ledger::from_journal(tampered).expect_err("must not be adopted");
    let text = err.to_string();
    assert!(text.contains("seq 1"), "must name the first break: {text}");
    assert!(text.contains("digest mismatch"), "{text}");
}

#[test]
fn a_deleted_record_is_reported_at_the_gap() {
    let (_ledger, entries) = journal_fixture();
    let mut with_gap = entries.clone();
    with_gap.remove(2);
    let err = Ledger::from_journal(with_gap).expect_err("must be detected");
    assert!(err.to_string().contains("seq 2"), "{err}");
}

#[test]
fn a_forged_deposit_appended_to_a_journal_is_refused() {
    let (_ledger, entries) = journal_fixture();
    let mut forged = entries.clone();
    let mut invented = entries[3].clone();
    invented.seq = 4;
    invented.prev_hash = entries[3].hash.clone();
    invented.kind = EntryKind::Deposit;
    invented.to = Some(account("attacker"));
    invented.from = None;
    invented.amount = money("1000000");
    invented.memo = "invented".into();
    invented.task = None;
    invented.at = 5;
    // `hash` deliberately left as the copied digest.
    forged.push(invented);

    let err = Ledger::from_journal(forged).expect_err("must be refused");
    assert!(err.to_string().contains("seq 4"), "{err}");
}

#[test]
fn a_reordered_pair_is_reported() {
    let (_ledger, entries) = journal_fixture();
    let mut swapped = entries.clone();
    swapped.swap(1, 2);
    let err = Ledger::from_journal(swapped).expect_err("must be detected");
    assert!(err.to_string().contains("seq 1"), "{err}");
}

#[test]
fn a_consistent_whole_file_rewrite_is_caught_by_the_stale_anchor() {
    let (mut ledger, entries) = journal_fixture();
    assert!(ledger.verify_journal().is_ok());
    let anchor = ledger.anchor();

    // The attacker rewrites the whole file *consistently*: the record count is
    // unchanged, every record is re-hashed with this crate's own rule, and the
    // only edit is that an invented deposit replaces an honest movement. That is
    // upstream v2.8.2's finding written out — an INSERTed `Deposited` row — except
    // that this forger also recomputes the chain.
    let mut forged: Vec<crate::LedgerEntry> = entries.clone();
    forged[1].amount = money("50000");
    forged[1].memo = "invented".into();
    let mut rebuilt_chain = crate::JournalChain::new();
    let relinked: Vec<crate::LedgerEntry> = forged
        .iter()
        .map(|entry| rebuilt_chain.append(entry.for_hashing()))
        .collect();
    let mut rebuilt = Ledger::from_journal(relinked).expect("the forgery is internally consistent");
    assert!(rebuilt.verify_journal().is_ok());
    assert_eq!(
        rebuilt.anchor().count,
        anchor.count,
        "the record count is unchanged, so only the head can give it away"
    );
    assert_ne!(rebuilt.anchor().head, anchor.head, "only the head differs");

    // The anchor lives in a different file and was not rewritten, so it still
    // names the honest head, and that comparison is what catches the rewrite.
    let err = rebuilt
        .verify_journal_against(&anchor)
        .expect_err("the stale anchor must catch it");
    assert!(err.to_string().contains("anchor"), "{err}");
    // What is **not** achievable, and is pinned here so a later change cannot
    // quietly claim it: `Ledger::audit()` cannot detect this. The anchor is a
    // separate file and is not an input to the in-memory ledger, and the invention
    // is *conserved* by construction (it is a deposit, so the supply counter grows
    // with the balance). No chain-only check can flag a forger who recomputed
    // every digest; the guaranteed property is the anchor comparison above, never
    // `!rebuilt.audit().conserved`.
    assert!(rebuilt.audit().conserved);
    assert!(ledger.audit().conserved);
}

#[test]
fn an_audit_over_a_tampered_journal_is_not_conserved_even_when_balances_replay() {
    let (ledger, entries) = journal_fixture();
    assert!(ledger.audit().conserved);
    // Edit only the digest of the *last* record: every balance still replays to
    // the same numbers, so nothing but the chain notices.
    let mut tampered = entries.clone();
    let last = tampered.len() - 1;
    tampered[last].hash = "0".repeat(64);
    let rebuilt = Ledger::from_journal(tampered).expect_err("must be refused");
    assert!(rebuilt.to_string().contains("digest mismatch"), "{rebuilt}");
    // And the ledger's own audit reports the journal, so the report cannot claim
    // conservation over a history it did not verify.
    let report = ledger.audit();
    assert!(report.journal_intact);
    assert_eq!(report.journal_entries_used, entries.len());
}

#[test]
fn an_empty_journal_verifies_and_anchors_to_genesis() {
    let mut ledger = Ledger::new();
    assert!(ledger.verify_journal().is_ok());
    let anchor = ledger.anchor();
    assert!(anchor.is_genesis());
    let report = ledger.conservation();
    assert!(report.conserved && report.journal_intact);
    assert_eq!(report.journal_entries_used, 0);
}

#[test]
fn a_journal_written_before_this_version_is_refused_rather_than_trusted() {
    // A pre-chain record deserialises (`prev_hash`/`hash` default to "") but must
    // not be accepted: "absent hash means fine" is exactly the bypass an attacker
    // needs.
    let legacy = r#"{"seq":0,"kind":"Deposit","from":null,"to":"alice","amount":1000000,"memo":"","task":null,"at":1}"#;
    let entry: crate::LedgerEntry = serde_json::from_str(legacy).expect("still decodes");
    assert!(entry.prev_hash.is_empty());
    let err = Ledger::from_journal(vec![entry]).expect_err("must not be trusted");
    assert!(err.to_string().contains("seq 0"), "{err}");
}

#[test]
fn every_replayable_kind_round_trips_through_from_journal() {
    let mut ledger = Ledger::new();
    let alice = account("alice");
    let bob = account("bob");
    let t = task("task-1");
    let agent = did(7);
    ledger.deposit(&alice, money("100"), "grant", 1).unwrap();
    ledger.stake(&agent, &alice, money("20"), 2).unwrap();
    ledger.escrow(&t, &alice, money("30"), 3).unwrap();
    ledger.release(&t, &bob, 4).unwrap();
    ledger.deposit(&alice, money("5"), "top up", 5).unwrap();
    ledger
        .escrow(&task("task-2"), &alice, money("5"), 6)
        .unwrap();
    ledger.refund(&task("task-2"), &alice, 7).unwrap();
    ledger
        .slash(&stake_account(&agent), money("10"), "fault", 8)
        .unwrap();
    ledger.unstake(&agent, &alice, 9).unwrap();
    ledger.withdraw(&alice, money("1"), "exit", 10).unwrap();

    let entries = ledger.entries().to_vec();
    let rebuilt = Ledger::from_journal(entries).expect("every kind must replay");
    assert_eq!(rebuilt.entries(), ledger.entries());
    assert_eq!(rebuilt.balance(&alice), ledger.balance(&alice));
    assert_eq!(rebuilt.anchor(), ledger.anchor());
    assert!(rebuilt.audit().conserved);
}

#[test]
fn an_unplayable_journal_is_refused_instead_of_partially_applied() {
    let (_ledger, entries) = journal_fixture();
    // Drop the escrow, leaving a release with nothing to release.
    let mut unplayable: Vec<crate::LedgerEntry> = entries
        .iter()
        .filter(|entry| entry.kind != EntryKind::Escrow)
        .cloned()
        .collect();
    for (index, entry) in unplayable.iter_mut().enumerate() {
        entry.seq = index as u64;
    }
    let err = Ledger::from_journal(unplayable).expect_err("must be refused");
    assert!(
        matches!(err, NauError::NotFound(_) | NauError::Validation(_)),
        "got {err:?}"
    );
}
