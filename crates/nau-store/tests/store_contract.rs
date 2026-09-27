//! End-to-end contract tests for the persistence port.
//!
//! Each test asserts behaviour that upstream `agent-universe` v2.5.6 could not
//! pass, and each is marked with the defect it pins down. Where a constant is
//! needed (a record count, a line count) it is derived from the operations that
//! were just performed, never from a value the implementation also hardcodes.

use std::io::Write;
use std::path::{Path, PathBuf};

use nau_core::domain::task::VerificationPolicy;
use nau_core::domain::{major, Pricing, PricingModel, PricingUnit, Verifiable};
use nau_core::{
    AgentCard, AgentCategory, Identity, Money, Skill, Sla, Task, TaskId, TaskSpec, TaskState,
};
use nau_store::{FileStore, MemoryStore, Store};
use serde_json::{json, Value};

// ---------------------------------------------------------------- fixtures

/// A scratch directory that removes itself when the test ends.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "nau-store-{tag}-{}-{unique}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn identity(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

/// A fully-populated, signed card: every field carries a distinctive value so
/// that a lossy round trip cannot go unnoticed.
fn card(seed: u8, name: &str, nonce: u64, skills: Vec<Skill>) -> AgentCard {
    let owner = identity(seed);
    let mut card = AgentCard::draft(&owner, name, skills, major(100), 1_700_000_000, nonce);
    card.description = Some(format!("{name} performs {} duties", name.to_lowercase()));
    card.category = AgentCategory::Code;
    card.pricing = Pricing {
        model: PricingModel::PerUnit,
        unit_price: Money::from_minor(1_234_567),
        unit: PricingUnit::KiloToken,
    };
    card.sla = Sla {
        latency_p95_ms: 137,
        availability_bps: 9_999,
        max_concurrency: 3,
    };
    card.endpoints = vec![
        "tcp://127.0.0.1:7000".to_string(),
        "tcp://127.0.0.1:7001".to_string(),
    ];
    card.sign(&owner).expect("sign card");
    card
}

fn alpha_one() -> AgentCard {
    card(
        1,
        "Alpha",
        1,
        vec![Skill::new("translation", 1).with_description("en->zh")],
    )
}

/// The same DID as [`alpha_one`] but newer content: this is the record that must
/// win last-write-wins.
fn alpha_two() -> AgentCard {
    card(
        1,
        "Alpha II",
        2,
        vec![
            Skill::new("translation", 2).with_description("en->zh, ja->zh"),
            Skill::new("summarisation", 1),
        ],
    )
}

fn beta() -> AgentCard {
    card(2, "Beta", 1, vec![Skill::new("code-review", 2)])
}

fn task(seed: u8, id: &str, state: TaskState) -> Task {
    let requester = identity(seed);
    let spec = TaskSpec {
        goal: format!("deliver {id}"),
        context: "the acceptance criteria are in `done`".to_string(),
        done: vec!["all criteria met".to_string()],
        todo: vec!["plan".to_string(), "execute".to_string()],
        trace: Some(format!("trace-{id}")),
        owner: requester.did(),
    };
    let mut task = Task::draft(
        TaskId::parse(id).expect("valid task id"),
        spec,
        vec!["code-review".to_string()],
        major(50),
        Some(1_700_009_000),
        VerificationPolicy::Committee { n: 4, f: 1 },
        requester.public_key(),
        1_700_000_000,
        1,
    );
    task.state = state;
    task.sign(&requester).expect("sign task");
    task
}

/// Everything a caller can observe through the [`Store`] port.
#[derive(Debug, PartialEq)]
struct Snapshot {
    agents: Vec<AgentCard>,
    tasks: Vec<Task>,
    ledger: Vec<Value>,
    meta: Option<String>,
    unknown_meta_is_none: bool,
}

/// A fixed operation sequence (including overwrites) run against any [`Store`].
///
/// It asserts the invariants that must hold for *every* implementation and
/// returns the observable state so two implementations can be compared.
fn exercise<S: Store + ?Sized>(store: &S) -> Snapshot {
    let one = alpha_one();
    let two = alpha_two();
    let other = beta();
    let first_task = task(1, "task-1", TaskState::Open);
    let second_task = task(2, "task-2", TaskState::Open);
    let updated_task = task(2, "task-2", TaskState::Matched);

    store.save_agent(&one).expect("save agent");
    store.save_agent(&other).expect("save agent");
    store.save_agent(&two).expect("overwrite agent");
    store.save_task(&first_task).expect("save task");
    store.save_task(&second_task).expect("save task");
    store.save_task(&updated_task).expect("overwrite task");

    let entry_one = json!({ "kind": "transfer", "amount": 1_250_000_i64, "note": null });
    let entry_two = json!({
        "kind": "settle",
        "nested": { "z": [1, 2, { "b": true, "a": [] }], "a": "text" },
        "amount": -1_250_000_i64
    });
    store.append_ledger(&entry_one).expect("append ledger");
    store.append_ledger(&entry_two).expect("append ledger");
    store.set_meta("chain", "nau-local").expect("set meta");
    store.flush().expect("flush");

    let agents = store.load_agents().expect("load agents");
    let tasks = store.load_tasks().expect("load tasks");
    let ledger = store.load_ledger().expect("load ledger");

    // Invariants every implementation must satisfy.
    assert_eq!(
        agents.len(),
        2,
        "one record per DID after an overwrite, got {agents:#?}"
    );
    let winner = agents
        .iter()
        .find(|card| card.owner == identity(1).did())
        .expect("the alpha DID must be present");
    assert_eq!(
        winner, &two,
        "the newest content for a DID must win, not the first or a merge"
    );
    assert_eq!(
        serde_json::to_value(winner).expect("serialize"),
        serde_json::to_value(&two).expect("serialize"),
        "what is loaded must equal byte-for-byte what was saved"
    );
    assert!(agents[0].owner.as_str() < agents[1].owner.as_str());

    assert_eq!(tasks.len(), 2, "one record per task id after an overwrite");
    let matched = tasks
        .iter()
        .find(|task| task.id.as_str() == "task-2")
        .expect("task-2 must be present");
    assert_eq!(
        matched, &updated_task,
        "the newest task state must win and survive byte-for-byte"
    );

    assert_eq!(ledger, vec![entry_one.clone(), entry_two.clone()]);

    Snapshot {
        agents,
        tasks,
        ledger,
        meta: store.get_meta("chain").expect("get meta"),
        unknown_meta_is_none: store.get_meta("never-set").expect("get meta").is_none(),
    }
}

// ---------------------------------------------------------------- tests

/// upstream v2.5.6 fix (defect #1): `load_agents`/`load_tasks` had zero call
/// sites, so "real persistence with restore after restart" was never true.
#[test]
fn agents_tasks_and_ledger_survive_a_real_reopen() {
    let dir = TempDir::new("reopen");
    let saved_agents;
    let saved_tasks;
    let saved_ledger;
    {
        let store = FileStore::open(dir.path()).expect("open");
        saved_agents = {
            store.save_agent(&alpha_two()).expect("save");
            store.save_agent(&beta()).expect("save");
            store.load_agents().expect("load")
        };
        saved_tasks = {
            store
                .save_task(&task(3, "task-77", TaskState::Running))
                .expect("save");
            store.load_tasks().expect("load")
        };
        saved_ledger = {
            store
                .append_ledger(&json!({ "seq": 1, "amount": 42_i64 }))
                .expect("append");
            store
                .append_ledger(&json!({ "seq": 2, "amount": -42_i64 }))
                .expect("append");
            store.flush().expect("flush");
            store.load_ledger().expect("load")
        };
        store.set_meta("epoch", "7").expect("set meta");
    } // store dropped: this is a restart

    assert!(dir.path().join("agents.jsonl").is_file());
    assert!(dir.path().join("tasks.jsonl").is_file());
    assert!(dir.path().join("ledger.jsonl").is_file());

    let reopened = FileStore::open(dir.path()).expect("reopen");
    assert_eq!(reopened.load_agents().expect("load"), saved_agents);
    assert_eq!(reopened.load_tasks().expect("load"), saved_tasks);
    assert_eq!(reopened.load_ledger().expect("load"), saved_ledger);
    assert_eq!(
        reopened.get_meta("epoch").expect("meta").as_deref(),
        Some("7")
    );
}

/// upstream v2.5.6 fix (defect #3): the stored row was rebuilt from the raw
/// request body — `skills.join(",")`, hardcoded `reputation: 0.0`, regenerated
/// `created_at` — so what came back was not what was validated.
#[test]
fn stored_bytes_are_the_canonical_json_of_the_validated_card() {
    let dir = TempDir::new("canonical");
    let store = FileStore::open(dir.path()).expect("open");
    let saved = card(
        4,
        "Delta",
        9,
        vec![Skill::new("vision", 3).with_description("ocr + layout")],
    );
    store.save_agent(&saved).expect("save");

    let raw = std::fs::read_to_string(dir.path().join("agents.jsonl")).expect("read log");
    let line = raw.lines().next().expect("one record line");
    let envelope: Value = serde_json::from_str(line).expect("record is JSON");

    assert_eq!(envelope["v"], json!(1), "schema marker is mandatory");
    assert_eq!(envelope["id"], json!(saved.owner.as_str()));

    let expected_payload =
        nau_store::jsonl::canonical_json_bytes(&serde_json::to_value(&saved).expect("to value"))
            .expect("canonical bytes");
    let actual_payload =
        nau_store::jsonl::canonical_json_bytes(&envelope["payload"]).expect("canonical bytes");
    assert_eq!(
        actual_payload, expected_payload,
        "the bytes on disk must be the canonical JSON of the validated card"
    );

    let reloaded: AgentCard =
        serde_json::from_value(envelope["payload"].clone()).expect("payload is a card");
    assert_eq!(reloaded, saved, "field-for-field equality");
    // The specific fields upstream dropped or invented are all intact.
    assert_eq!(
        reloaded.skills[0].description.as_deref(),
        Some("ocr + layout")
    );
    assert_eq!(reloaded.skills[0].version, 3);
    assert_eq!(reloaded.endpoints.len(), 2);
    assert_eq!(reloaded.pricing.unit_price, Money::from_minor(1_234_567));
    assert_eq!(reloaded.pricing.model, PricingModel::PerUnit);
    assert_eq!(reloaded.sla.availability_bps, 9_999);
    assert_eq!(reloaded.nonce, 9);
    assert_eq!(reloaded.signed_at, 1_700_000_000);
    assert!(!reloaded.signature.is_empty());
    assert!(reloaded.verify().is_ok(), "the signature must still verify");
}

/// A crash in the middle of an append must not take the whole log with it.
#[test]
fn a_torn_tail_is_skipped_and_later_records_still_load() {
    let dir = TempDir::new("torn");
    let store = FileStore::open(dir.path()).expect("open");
    let first = alpha_two();
    let second = beta();
    store.save_agent(&first).expect("save");

    // Simulate the crash: half a record line, no trailing newline.
    let torn = br#"{"id":"did:nau:0011223344556677","payload":{"owner":"did:nau:00"#;
    let log = dir.path().join("agents.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("open log for the simulated crash");
    file.write_all(torn).expect("write the torn fragment");
    file.sync_all().expect("fsync");
    drop(file);

    // Appending after a torn tail must not concatenate onto it.
    store.save_agent(&second).expect("save after the crash");

    let reopened = FileStore::open(dir.path()).expect("reopen");
    let agents = reopened.load_agents().expect("the load must not fail");
    let mut expected = vec![first.clone(), second.clone()];
    expected.sort_by(|a, b| a.owner.as_str().cmp(b.owner.as_str()));
    assert_eq!(
        agents, expected,
        "both complete records must be readable, the torn one skipped"
    );

    // The torn bytes are still on disk as their own unreadable line...
    let raw = std::fs::read_to_string(&log).expect("read log");
    assert!(
        raw.contains("did:nau:0011223344556677"),
        "the fragment is preserved verbatim, not silently rewritten"
    );
    // ...and a compaction is what reclaims it.
    reopened.compact().expect("compact");
    let after = std::fs::read_to_string(&log).expect("read log");
    assert!(
        !after.contains("0011223344556677"),
        "compact drops torn tails"
    );
    assert_eq!(
        reopened.load_agents().expect("load"),
        expected,
        "compaction must not change the visible state"
    );
}

#[test]
fn later_records_for_the_same_id_supersede_earlier_ones() {
    let dir = TempDir::new("lww");
    let store = FileStore::open(dir.path()).expect("open");
    for nonce in 1..=5u64 {
        store
            .save_agent(&card(
                7,
                &format!("Version {nonce}"),
                nonce,
                vec![Skill::new("data", nonce as u32)],
            ))
            .expect("save");
    }
    store
        .save_task(&task(7, "task-lww", TaskState::Open))
        .expect("save");
    store
        .save_task(&task(7, "task-lww", TaskState::Settled))
        .expect("save");

    // Five appends, one visible record.
    let log = std::fs::read_to_string(dir.path().join("agents.jsonl")).expect("read log");
    assert_eq!(log.lines().count(), 5);

    let reopened = FileStore::open(dir.path()).expect("reopen");
    let agents = reopened.load_agents().expect("load");
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].nonce, 5, "newest nonce wins");
    assert_eq!(agents[0].name, "Version 5");
    assert_eq!(agents[0].skills[0].version, 5);

    let tasks = reopened.load_tasks().expect("load");
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].state, TaskState::Settled);
}

#[test]
fn compact_preserves_the_visible_state_exactly() {
    let dir = TempDir::new("compact");
    let store = FileStore::open(dir.path()).expect("open");

    store.save_agent(&alpha_one()).expect("save");
    store.save_agent(&beta()).expect("save");
    store.save_agent(&alpha_two()).expect("overwrite");
    store
        .save_task(&task(1, "task-1", TaskState::Open))
        .expect("save");
    store
        .save_task(&task(1, "task-1", TaskState::Verifying))
        .expect("overwrite");
    store.append_ledger(&json!({"seq": 1})).expect("append");
    store.append_ledger(&json!({"seq": 2})).expect("append");

    let before = (
        store.load_agents().expect("load"),
        store.load_tasks().expect("load"),
        store.load_ledger().expect("load"),
    );
    let agent_lines_before = std::fs::read_to_string(dir.path().join("agents.jsonl"))
        .expect("read")
        .lines()
        .count();
    assert_eq!(agent_lines_before, 3, "three appends, two distinct agents");

    store.compact().expect("compact");

    let after = (
        store.load_agents().expect("load"),
        store.load_tasks().expect("load"),
        store.load_ledger().expect("load"),
    );
    assert_eq!(before, after, "compaction must not change visible state");

    let agent_lines_after = std::fs::read_to_string(dir.path().join("agents.jsonl"))
        .expect("read")
        .lines()
        .count();
    assert_eq!(
        agent_lines_after,
        after.0.len(),
        "one line per current record after compaction"
    );
    assert!(agent_lines_after < agent_lines_before);
    let ledger_lines = std::fs::read_to_string(dir.path().join("ledger.jsonl"))
        .expect("read")
        .lines()
        .count();
    assert_eq!(ledger_lines, 2, "ledger order and length are preserved");
    // The temp files used for the atomic swap must be gone.
    assert!(!dir.path().join("agents.jsonl.tmp").exists());
    assert!(!dir.path().join("meta.json.tmp").exists());
}

#[test]
fn the_two_stores_are_observably_identical() {
    let memory = MemoryStore::new();
    let memory_snapshot = exercise(&memory);

    let dir = TempDir::new("identical");
    let file_snapshot = {
        let store = FileStore::open(dir.path()).expect("open");
        exercise(&store)
    };
    assert_eq!(
        memory_snapshot, file_snapshot,
        "MemoryStore and FileStore must agree for the same operation sequence"
    );

    // And the file store must agree with itself after a reopen, including the
    // append-only ledger, whose order must be preserved verbatim.
    let reopened = FileStore::open(dir.path()).expect("reopen");
    assert_eq!(
        reopened.load_agents().expect("load"),
        memory_snapshot.agents
    );
    assert_eq!(reopened.load_tasks().expect("load"), memory_snapshot.tasks);
    assert_eq!(
        reopened.get_meta("chain").expect("meta"),
        memory_snapshot.meta
    );
    assert_eq!(
        reopened.load_ledger().expect("load"),
        memory_snapshot.ledger
    );
}

#[test]
fn unknown_metadata_keys_are_none_not_an_error() {
    let memory = MemoryStore::new();
    let dir = TempDir::new("meta-none");
    let file = FileStore::open(dir.path()).expect("open");
    for store in [&memory as &dyn Store, &file as &dyn Store] {
        assert_eq!(store.get_meta("absent").expect("get"), None);
        store.set_meta("present", "").expect("set");
        assert_eq!(store.get_meta("present").expect("get").as_deref(), Some(""));
        assert_eq!(store.get_meta("absent").expect("get"), None);
        assert!(store.set_meta("", "x").is_err(), "empty keys are refused");
    }
}

/// An explicit cap, enforced rather than documented: a log that exceeds it is an
/// error, so a runaway append loop cannot exhaust memory on the next restart.
#[test]
fn the_load_cap_is_enforced() {
    let dir = TempDir::new("cap");
    let store = FileStore::open_capped(dir.path(), 2).expect("open");
    for seed in 1..=3u8 {
        store
            .save_agent(&card(seed, "Capped", 1, vec![Skill::new("data", 1)]))
            .expect("save");
    }
    let err = store.load_agents().expect_err("the cap must be enforced");
    assert!(
        matches!(err, nau_core::NauError::Conflict(_)),
        "got {err:?}"
    );
    assert!(FileStore::open_capped(dir.path(), 0).is_err());

    // Compaction cannot rescue data that exceeds the cap, but a larger cap can.
    let generous = FileStore::open_capped(dir.path(), 16).expect("open");
    assert_eq!(generous.load_agents().expect("load").len(), 3);
}

/// A well-formed record with a payload that is not the expected type is
/// corruption of a *complete* record; dropping it silently would look exactly
/// like "that agent never registered".
#[test]
fn a_payload_of_the_wrong_shape_is_reported() {
    let dir = TempDir::new("wrong-shape");
    let store = FileStore::open(dir.path()).expect("open");
    store.save_agent(&beta()).expect("save a real card");
    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.path().join("agents.jsonl"))
        .expect("open log");
    log.write_all(b"{\"id\":\"x\",\"payload\":{\"not\":\"a card\"},\"v\":1}\n")
        .expect("write");
    log.sync_all().expect("fsync");
    drop(log);

    assert!(store.load_agents().is_err(), "must not silently drop it");
    // Tasks are unaffected: each log is independent.
    assert!(store.load_tasks().expect("load").is_empty());
}

#[test]
fn ledger_entries_round_trip_without_reordering_or_reformatting() {
    let dir = TempDir::new("ledger");
    let store = FileStore::open(dir.path()).expect("open");
    let entries = vec![
        json!({"seq": 1, "from": "did:nau:aaaaaaaaaaaaaaaa", "amount": 1_i64}),
        json!({"seq": 2, "nested": {"deep": {"deeper": [null, true, "leaf"]}}}),
        json!({"seq": 3, "big": i64::MAX}),
        json!({"seq": 4, "negative": i64::MIN}),
    ];
    for entry in &entries {
        store.append_ledger(entry).expect("append");
    }
    assert_eq!(store.load_ledger().expect("load"), entries);

    let reopened = FileStore::open(dir.path()).expect("reopen");
    assert_eq!(reopened.load_ledger().expect("load"), entries);
}
