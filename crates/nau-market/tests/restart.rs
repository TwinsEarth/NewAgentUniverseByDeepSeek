//! Restart integrity: findings B, C, D and E.
//!
//! The upstream v2.8.2 persistence layer made a restart *weaken* the system. Each
//! test here fails on upstream's behaviour and passes on this crate's.

mod support;

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use nau_core::domain::money::major;
use nau_core::domain::EvidenceGrade;
use nau_core::{AgentCard, Money, NauError, Result as NauResult, TaskState};
use nau_ledger::LedgerEntry;
use nau_market::{Actor, Market, MarketConfig, MARKET_STATE_KEY};
use nau_store::file::LEDGER_FILE;
use nau_store::{FileStore, MemoryStore, Store};
use serde_json::Value;
use support::*;

/// A scratch directory unique to this process and instant.
fn scratch(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "nau-market-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

/// THE restart test.
///
/// Upstream's own persistence test asserted that "the rows reappeared" and
/// therefore missed all three of the properties below. This one does not.
#[test]
fn a_restart_does_not_weaken_the_evidence_gate_the_stake_or_the_reputation() {
    let dir = scratch("restart-gate");
    let store = FileStore::open(&dir).expect("open store");
    // The market runs open, and is reopened behind a reputation floor. Only a
    // restored reputation record can clear it: the default is 5_000 bps.
    let run_config = MarketConfig::default();
    let restore_config = MarketConfig {
        min_reputation_bps: 6_000,
        ..MarketConfig::default()
    };
    assert!(
        !nau_market::Reputation::default().is_eligible(6_000),
        "the fixture is only meaningful while a default reputation is ineligible"
    );
    let mut fx = Fixture::with_config(run_config);

    // Three settlement-grade tasks lift the agent's composite reputation above the
    // configured floor. A *default* reputation is 5_000 bps, so a restart that
    // forgot the record would lock the agent out of bidding.
    for i in 0..3 {
        let task = fx.run_to_accepted(
            &format!("task-clean-{i}"),
            major(50),
            major(30),
            EvidenceGrade::CpuProto,
        );
        let at = fx.tick();
        fx.market.settle(&task.id, at).expect("settle");
    }
    let reputation_before = fx
        .market
        .reputation(&fx.agent.did())
        .expect("reputation")
        .clone();
    assert!(
        reputation_before.overall_bps() > 6_000,
        "the fixture must clear the configured floor, got {}",
        reputation_before.overall_bps()
    );

    // An accepted task whose result is NOT settlement grade: the gate must hold
    // before and after the restart.
    let gated = fx.run_to_accepted(
        "task-gated",
        major(50),
        major(25),
        EvidenceGrade::Unverified,
    );
    let policy_before = fx.market.get_task(&gated.id).expect("task").verification;
    let at = fx.tick();
    assert!(
        fx.market.settle(&gated.id, at).is_err(),
        "the evidence gate must hold before the restart"
    );

    // A disputed task and an open task: the arbitration and bidding paths.
    let disputed = fx.publish("task-disputed", major(50));
    fx.bid(&disputed, major(20));
    fx.match_and_start(&disputed);
    let dispute_nonce = fx.nonces.take(&fx.requester);
    let signed_at = fx.tick();
    let dispute = dispute_of(
        &fx.requester,
        &disputed,
        &fx.agent,
        "d1",
        dispute_nonce,
        signed_at,
    );
    let at = fx.tick();
    fx.market
        .open_dispute(Actor::party(fx.requester.did()), dispute, at)
        .expect("dispute");
    let open = fx.publish("task-open", major(50));

    fx.market.persist(&store).expect("persist");
    let balance_before = fx.market.balance(&did_account(&fx.agent));
    let escrow_before = fx.market.escrowed_for(&gated.id);
    let stake_before = fx
        .market
        .balance(&Market::stake_account_for(&fx.agent.did()));
    let faults_before = reputation_before.faults;
    assert_eq!(stake_before, major(100), "the bond is on the books");
    // Drop the process's whole in-memory market: nothing below may rely on it.
    drop(fx.market);

    let (mut restored, report) =
        Market::restore_reporting(restore_config, &store, T0 + 100_000).expect("restore");
    assert!(report.is_clean(), "{}", report.summary());
    assert!(!restored.is_degraded());
    assert!(!restored.stats().degraded);

    // (B) the verification policy, the result envelope's grade and the winner price
    // all survived ...
    assert_eq!(
        restored.get_task(&gated.id).expect("task").verification,
        policy_before
    );
    assert_eq!(restored.winner_price(&gated.id), Some(major(25)));
    assert_eq!(
        restored.result_for(&gated.id).map(|e| e.evidence),
        Some(EvidenceGrade::Unverified)
    );
    // ... so the evidence gate still refuses the very same settlement, and the
    // funds stay escrowed.
    let err = restored.settle(&gated.id, T0 + 100_100).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert_eq!(restored.escrowed_for(&gated.id), escrow_before);
    assert_eq!(restored.balance(&did_account(&fx.agent)), balance_before);

    // (C) the reputation record survived, so an agent above a floor that the
    // default (5_000 bps) would fail can still bid.
    assert_eq!(
        restored.reputation(&fx.agent.did()),
        Some(&reputation_before)
    );
    let bid_nonce = fx.nonces.take(&fx.agent);
    let bid = bid_of(&fx.agent, &open, major(20), bid_nonce, T0 + 100_200);
    restored
        .submit_bid(bid, T0 + 100_200)
        .expect("a restored, staked agent must still be able to bid");

    // (C) the dispute and the stake record are both there, so a guilty verdict is
    // still applicable while the funds are on the books.
    assert_eq!(
        restored.balance(&Market::stake_account_for(&fx.agent.did())),
        stake_before
    );
    let ruling = ruling_of(
        &fx.arbiter,
        "d1",
        &disputed,
        true,
        major(10),
        1,
        T0 + 100_300,
    );
    let slashed = restored
        .arbitrate(Actor::arbitrator(fx.arbiter.did()), ruling, T0 + 100_300)
        .expect("arbitrate after a restart");
    assert_eq!(slashed, major(10), "10% of the restored bond");
    assert_eq!(
        restored.balance(&Market::stake_account_for(&fx.agent.did())),
        stake_before.checked_sub(major(10)).unwrap()
    );
    assert_eq!(
        restored.get_task(&disputed.id).expect("task").state,
        TaskState::Slashed
    );
    assert_eq!(
        restored.reputation(&fx.agent.did()).expect("rep").faults,
        faults_before + 1,
        "the fault count continues from the restored record"
    );
    assert!(restored.conservation().conserved);
    assert!(restored.audit().conserved);

    drop(restored);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Upstream restored `winner_price: None` and then paid
/// `winner_price.unwrap_or(budget)`. Settlement must refuse instead.
#[test]
fn settlement_refuses_to_substitute_the_budget_for_a_missing_price() {
    let store = MemoryStore::new();
    let config = MarketConfig::default();
    let mut fx = Fixture::with_config(config.clone());
    let task = fx.run_to_accepted("task-1", major(50), major(30), EvidenceGrade::CpuProto);
    fx.market.persist(&store).expect("persist");
    drop(fx.market);

    // Strip the recorded price exactly as upstream's restore did.
    let state = store
        .get_meta(MARKET_STATE_KEY)
        .expect("meta")
        .expect("the market state is written");
    let mut state: Value = serde_json::from_str(&state).expect("json");
    state["winner_price"] = serde_json::json!({});
    store
        .set_meta(MARKET_STATE_KEY, &state.to_string())
        .expect("set meta");

    let mut restored = Market::restore(config, &store, T0 + 100_000).expect("restore");
    assert_eq!(
        restored.get_task(&task.id).expect("task").state,
        TaskState::Accepted
    );
    assert_eq!(restored.winner_price(&task.id), None);
    let err = restored.settle(&task.id, T0 + 100_100).unwrap_err();
    assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
    assert!(err.to_string().contains("winner price"), "{err}");
    assert_eq!(
        restored.escrowed_for(&task.id),
        major(50),
        "the budget must stay locked, not be paid as a substitute"
    );
}

/// Finding D: a record that cannot be parsed is **reported**, the movements before
/// it are still restored, and nothing is written twice.
#[test]
fn a_record_that_cannot_be_decoded_is_reported_and_nothing_is_written_twice() {
    let dir = scratch("journal-gap");
    let store = FileStore::open(&dir).expect("open store");
    let mut market = Market::new(MarketConfig::default());
    let accounts: Vec<_> = (1..=4).map(|i| account(&format!("acct-{i}"))).collect();
    for (index, acct) in accounts.iter().enumerate() {
        market
            .deposit(acct, major(index as i64 + 1), T0 + index as u64)
            .expect("deposit");
    }
    market.persist(&store).expect("persist");
    assert_eq!(store.load_ledger().expect("ledger").len(), 4);

    // Corrupt the SECOND record. The store's line loader skips a line it cannot
    // decode, which is exactly the situation that used to move the watermark
    // permanently ahead and stop the journal recording.
    let path = store.path_of(LEDGER_FILE);
    let text = std::fs::read_to_string(&path).expect("read journal");
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    assert_eq!(lines.len(), 4);
    lines[1] = "{\"v\":1,\"payload\":".to_string();
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write journal");
    let corrupted = std::fs::read(&path).expect("read bytes");
    let store_view = store.load_ledger().expect("ledger").len();
    assert_eq!(store_view, 3, "the store's own view dropped the bad line");

    let (mut restored, report) =
        Market::restore_reporting(MarketConfig::default(), &store, T0 + 10_000).expect("restore");

    // The corruption is reported, with the sequence it concerns.
    assert!(report.is_degraded(), "{report:?}");
    assert_eq!(report.ledger_records_expected, 4);
    assert_eq!(report.ledger_records_restored, 1);
    assert!(
        report
            .defects
            .iter()
            .any(|d| d.kind == "sequence_gap" && d.seq == Some(1)),
        "{:?}",
        report.defects
    );
    assert!(report.missing_records.contains(&1));
    assert!(report.missing_records.contains(&3));
    assert!(restored.is_degraded());
    let stats = serde_json::to_value(restored.stats()).expect("stats json");
    assert_eq!(stats["degraded"], serde_json::json!(true));
    assert_eq!(stats["journal_records_expected"], serde_json::json!(4));
    assert_eq!(stats["journal_records_restored"], serde_json::json!(1));

    // No earlier movement is lost: the record before the gap is still applied...
    assert_eq!(restored.balance(&accounts[0]), major(1));
    // ... and the unreadable record is NOT invented.
    assert_eq!(restored.balance(&accounts[1]), Money::ZERO);
    assert_eq!(restored.balance(&accounts[2]), Money::ZERO);

    // Nothing is written twice, and a degraded market refuses to write at all.
    assert!(restored
        .deposit(&accounts[1], major(9), T0 + 10_100)
        .is_err());
    assert!(restored.persist(&store).is_err());
    assert_eq!(
        std::fs::read(&path).expect("read bytes"),
        corrupted,
        "the journal must be byte-identical after a refused persist"
    );
    assert_eq!(store.load_ledger().expect("ledger").len(), store_view);

    // A caller that would rather refuse to serve than serve degraded can say so.
    let refused = Market::restore_checked(MarketConfig::default(), &store, T0 + 10_000);
    assert!(
        refused.is_err(),
        "restore_checked must refuse a lossy store"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A torn tail is reported too — never silently skipped (finding D/E).
#[test]
fn a_torn_tail_is_reported_rather_than_silently_skipped() {
    let dir = scratch("journal-tail");
    let store = FileStore::open(&dir).expect("open store");
    let mut market = Market::new(MarketConfig::default());
    let accounts: Vec<_> = (1..=3).map(|i| account(&format!("tail-{i}"))).collect();
    for (index, acct) in accounts.iter().enumerate() {
        market
            .deposit(acct, major(index as i64 + 1), T0 + index as u64)
            .expect("deposit");
    }
    market.persist(&store).expect("persist");

    let path = store.path_of(LEDGER_FILE);
    let text = std::fs::read_to_string(&path).expect("read journal");
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    lines.pop();
    lines.push("{\"v\":1,\"payl".to_string());
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write journal");

    let (restored, report) =
        Market::restore_reporting(MarketConfig::default(), &store, T0 + 10_000).expect("restore");
    assert!(report.is_degraded(), "{report:?}");
    assert_eq!(report.ledger_records_expected, 3);
    assert_eq!(restored.stats().journal_records_restored, 2);
    assert!(
        report
            .defects
            .iter()
            .any(|d| d.kind == "truncated_tail" && d.seq == Some(2)),
        "{:?}",
        report.defects
    );
    assert_eq!(report.missing_records, vec![2]);
    // The movements before the torn record are intact.
    assert_eq!(restored.balance(&accounts[0]), major(1));
    assert_eq!(restored.balance(&accounts[1]), major(2));
    assert_eq!(restored.balance(&accounts[2]), Money::ZERO);
    assert!(restored.is_degraded());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A record whose payload was *edited* still decodes, so a loader that only
/// checks "does it parse" would replay it. The record's own digest does not cover
/// its bytes any more, and that is reported instead of applied.
#[test]
fn an_edited_record_is_detected_and_never_applied() {
    let dir = scratch("journal-edited");
    let store = FileStore::open(&dir).expect("open store");
    let mut market = Market::new(MarketConfig::default());
    let accounts: Vec<_> = (1..=3).map(|i| account(&format!("edit-{i}"))).collect();
    for (index, acct) in accounts.iter().enumerate() {
        market
            .deposit(acct, major(index as i64 + 1), T0 + index as u64)
            .expect("deposit");
    }
    market.persist(&store).expect("persist");

    // Edit the SECOND record's amount in place; every line stays valid JSON.
    let path = store.path_of(LEDGER_FILE);
    let text = std::fs::read_to_string(&path).expect("read journal");
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut edited: Value = serde_json::from_str(&lines[1]).expect("envelope");
    edited["payload"]["amount"] = serde_json::json!(999_000_000);
    lines[1] = edited.to_string();
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write journal");

    let (mut restored, report) =
        Market::restore_reporting(MarketConfig::default(), &store, T0 + 10_000).expect("restore");
    assert!(report.is_degraded(), "{report:?}");
    assert!(
        report
            .defects
            .iter()
            .any(|d| d.kind == "digest_mismatch" && d.seq == Some(1)),
        "{:?}",
        report.defects
    );
    assert_eq!(
        report.ledger_records_restored, 1,
        "only the record before the edit can be trusted"
    );
    // The edited movement is neither lost nor applied: the record before it is
    // there, the edited one is not, and the edited amount is nowhere.
    assert_eq!(restored.balance(&accounts[0]), major(1));
    assert_eq!(restored.balance(&accounts[1]), Money::ZERO);
    assert!(restored.is_degraded());
    assert!(restored.persist(&store).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A store that fails one append, so finding E can be tested without a real disk
/// error: the failure must be typed, must not advance the watermark past what is
/// durable, and a retry must not write anything twice.
#[derive(Debug, Default)]
struct FlakyStore {
    inner: MemoryStore,
    appends: AtomicUsize,
    fail_at: AtomicI64,
    meta_writes: AtomicUsize,
    fail_meta_at: AtomicI64,
}

impl FlakyStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            appends: AtomicUsize::new(0),
            fail_at: AtomicI64::new(-1),
            meta_writes: AtomicUsize::new(0),
            fail_meta_at: AtomicI64::new(-1),
        }
    }

    /// Fail the append whose zero-based index is `index`.
    fn fail_at(&self, index: i64) {
        self.fail_at.store(index, Ordering::SeqCst);
    }

    /// Fail the next metadata write, whenever it happens.
    fn fail_next_meta(&self) {
        let next = self.meta_writes.load(Ordering::SeqCst) as i64;
        self.fail_meta_at.store(next, Ordering::SeqCst);
    }

    /// Stop failing.
    fn heal(&self) {
        self.fail_at.store(-1, Ordering::SeqCst);
        self.fail_meta_at.store(-1, Ordering::SeqCst);
    }
}

impl Store for FlakyStore {
    fn save_agent(&self, card: &AgentCard) -> NauResult<()> {
        self.inner.save_agent(card)
    }
    fn load_agents(&self) -> NauResult<Vec<AgentCard>> {
        self.inner.load_agents()
    }
    fn save_task(&self, task: &nau_core::Task) -> NauResult<()> {
        self.inner.save_task(task)
    }
    fn load_tasks(&self) -> NauResult<Vec<nau_core::Task>> {
        self.inner.load_tasks()
    }
    fn save_reputation(&self, did: &str, reputation: &Value) -> NauResult<()> {
        self.inner.save_reputation(did, reputation)
    }
    fn load_reputations(&self) -> NauResult<Vec<(String, Value)>> {
        self.inner.load_reputations()
    }
    fn save_task_outcome(&self, task_id: &str, outcome: &Value) -> NauResult<()> {
        self.inner.save_task_outcome(task_id, outcome)
    }
    fn load_task_outcomes(&self) -> NauResult<Vec<(String, Value)>> {
        self.inner.load_task_outcomes()
    }
    fn append_ledger(&self, entry: &Value) -> NauResult<()> {
        let index = self.appends.fetch_add(1, Ordering::SeqCst) as i64;
        if index == self.fail_at.load(Ordering::SeqCst) {
            return Err(NauError::Io(std::io::Error::other(
                "simulated disk failure on append",
            )));
        }
        self.inner.append_ledger(entry)
    }
    fn append_journal(&self, prev: &str, payload: &Value) -> NauResult<nau_store::JournalAnchor> {
        let index = self.appends.fetch_add(1, Ordering::SeqCst) as i64;
        if index == self.fail_at.load(Ordering::SeqCst) {
            return Err(NauError::Io(std::io::Error::other(
                "simulated disk failure on append",
            )));
        }
        self.inner.append_journal(prev, payload)
    }
    fn journal_anchor(&self) -> NauResult<Option<nau_store::JournalAnchor>> {
        self.inner.journal_anchor()
    }
    fn load_journal(&self) -> NauResult<nau_store::LoadedJournal> {
        self.inner.load_journal()
    }
    fn load_ledger(&self) -> NauResult<Vec<Value>> {
        self.inner.load_ledger()
    }
    fn get_meta(&self, key: &str) -> NauResult<Option<String>> {
        self.inner.get_meta(key)
    }
    fn set_meta(&self, key: &str, value: &str) -> NauResult<()> {
        let index = self.meta_writes.fetch_add(1, Ordering::SeqCst) as i64;
        if index == self.fail_meta_at.load(Ordering::SeqCst) {
            return Err(NauError::Io(std::io::Error::other(
                "simulated disk failure on metadata write",
            )));
        }
        self.inner.set_meta(key, value)
    }
    fn flush(&self) -> NauResult<()> {
        self.inner.flush()
    }
}

#[test]
fn an_append_failure_is_typed_and_does_not_advance_the_watermark() {
    let store = FlakyStore::new();
    let mut market = Market::new(MarketConfig::default());
    let first = account("acct-first");
    let second = account("acct-second");
    market.deposit(&first, major(1), T0).expect("deposit");
    market.deposit(&second, major(2), T0 + 1).expect("deposit");

    // The SECOND append fails. Upstream did `let _ = store.append_ledger(r);` and
    // then advanced the watermark, losing that movement forever.
    store.fail_at(1);
    let err = market
        .persist(&store)
        .expect_err("the failure must surface");
    assert!(matches!(err, NauError::Io(_)), "got {err:?}");
    assert_eq!(
        store.load_ledger().expect("ledger").len(),
        1,
        "only the first record is durable"
    );
    assert_eq!(
        market.persisted_ledger_records(),
        1,
        "the watermark must stop at what is actually durable"
    );

    // A retry resumes at the failed record instead of duplicating the first one.
    store.heal();
    market.persist(&store).expect("the retry must succeed");
    let ledger = store.load_ledger().expect("ledger");
    assert_eq!(ledger.len(), 2, "the retry must not duplicate the journal");
    let seqs: Vec<u64> = ledger
        .iter()
        .map(|value| {
            serde_json::from_value::<LedgerEntry>(value.clone())
                .expect("a ledger entry")
                .seq
        })
        .collect();
    assert_eq!(seqs, vec![0, 1], "the journal stays dense and ordered");

    // The metadata write is an upsert as well. Failing it must be typed, must not
    // re-append the journal, and the next persist must be able to finish the job.
    market.deposit(&first, major(3), T0 + 2).expect("deposit");
    store.heal();
    store.fail_next_meta();
    let err = market
        .persist(&store)
        .expect_err("a metadata failure must surface");
    assert!(matches!(err, NauError::Io(_)), "got {err:?}");
    assert_eq!(
        market.persisted_ledger_records(),
        3,
        "the appended record is durable even though the snapshot write failed"
    );
    store.heal();
    market.persist(&store).expect("the metadata retry");
    assert_eq!(
        store.load_ledger().expect("ledger").len(),
        3,
        "the metadata retry must not duplicate the journal"
    );

    let restored = Market::restore(MarketConfig::default(), &store, T0 + 100).expect("restore");
    assert!(!restored.is_degraded());
    assert_eq!(restored.balance(&first), major(4));
    assert_eq!(restored.balance(&second), major(2));
    assert!(restored.conservation().conserved);
    assert!(restored.audit().conserved);
}
