#![allow(dead_code)]
//! Shared fixtures for nau-migrate's integration tests.
//!
//! # Honesty
//!
//! Every file this builder writes is **authored to model the audited upstream
//! v2.5.6 format** (AgentCard JSON, TaskRecord JSON, ledger JSONL; see the crate
//! documentation and `docs/GAP-ANALYSIS.md` §2, §4 and §6). **None of it was
//! captured from a live upstream instance, and no real upstream user data is
//! involved.** The single exception is stated where it appears:
//! `agents/card-upstream-vector.json` is built from the `upstream-v2.5.6-compat`
//! payload in `conformance/vectors.json`, which is upstream's own pinned
//! cross-language test vector (public key, DID, canonical payload and signature
//! verbatim from `gsn-core/tests/cross_lang_signature.rs:11-14`).
//!
//! # The tree
//!
//! ```text
//! agents/card-alice.json          legacy did:aip:, mixed-case capability, float price
//! agents/card-bob.json            did:nau:, no inline key, key from keys.json
//! agents/card-tampered.json       one byte of the payload changed after signing
//! agents/card-wrongkey.json       a DID paired with someone else's key
//! agents/card-float-stake.json    stake 100.0 inside the signed payload
//! agents/card-missing-stake.json  no stake at all
//! agents/card-upstream-vector.json upstream's own pinned, signed vector
//! tasks/task-translate-1.json     imports; status "completed" -> Accepted
//! tasks/task-badstatus.json       status "view_change" -> refused
//! tasks/task-tampered.json        one byte of the payload changed after signing
//! tasks/task-nospec.json          none of the six documented TaskSpec fields
//! ledger.jsonl                    9 lines: 7 exact, 1 inexact, 1 negative
//! keys.json                       bob and the upstream vector key
//! balances.json                   5 correct claims and 2 that do not reconcile
//! ```

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use nau_core::{Identity, PublicKey};
use serde_json::{json, Value};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A scratch directory that deletes itself when the test ends.
pub struct Scratch {
    root: PathBuf,
}

impl Scratch {
    /// Create an empty scratch directory with a unique name.
    pub fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "nau-migrate-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the scratch directory");
        Self { root }
    }

    /// The directory itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A path inside the scratch directory.
    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Write a file, creating its parent directory.
pub fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create the parent directory");
    }
    std::fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// A JSON string value.
pub fn s(text: impl Into<String>) -> Value {
    Value::String(text.into())
}

/// A JSON array of strings.
pub fn arr(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|item| s(*item)).collect())
}

/// A JSON integer value.
pub fn n(value: i64) -> Value {
    Value::from(value)
}

/// A JSON object with the given key order.
pub fn object(entries: Vec<(&str, Value)>) -> Value {
    let mut map = serde_json::Map::new();
    for (key, value) in entries {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

/// Sign an object with this project's canonical rules, as upstream's shapes allow.
pub fn sign(target: &mut Value, identity: &Identity) {
    target["signature"] = s("");
    let signature = identity
        .sign_payload(target)
        .expect("the fixture payload is signable");
    target["signature"] = s(signature);
}

/// `conformance/vectors.json`.
pub fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("vectors.json")
}

/// The parsed cross-language fixture file.
pub fn read_vectors() -> Value {
    let path = vectors_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("vectors.json is valid JSON")
}

/// The `upstream-v2.5.6-compat` card: upstream's own signed vector, verbatim.
pub fn upstream_vector_card() -> (Value, PublicKey) {
    let vectors = read_vectors();
    let payload = vectors["payloads"]
        .as_array()
        .expect("payloads is an array")
        .iter()
        .find(|payload| payload["id"] == json!("upstream-v2.5.6-compat"))
        .expect("the upstream vector is present")
        .clone();
    let mut card: Value = serde_json::from_str(
        payload["input_json"]
            .as_str()
            .expect("input_json is a string"),
    )
    .expect("the vector payload is valid JSON");
    card["signature"] = payload["signature_hex"].clone();
    let key = PublicKey::from_hex(
        vectors["identity"]["public_key_hex"]
            .as_str()
            .expect("public_key_hex is a string"),
    )
    .expect("the vector public key is valid");
    (card, key)
}

/// One ledger line, with the amount written as raw JSON text so that exponent
/// notation and long fractions survive verbatim.
fn ledger_line(task: &str, from: &str, to: &str, amount: &str, reason: &str, at: u64) -> String {
    format!(
        "{{\"task_id\":\"{task}\",\"from\":\"{from}\",\"to\":\"{to}\",\"amount\":{amount},\
         \"reason\":\"{reason}\",\"at\":{at}}}"
    )
}

/// The identities and expectations of the authored fixture tree.
pub struct Tree {
    /// The scratch directory holding the tree.
    pub scratch: Scratch,
    /// The agent that pays, with a legacy `did:aip:` DID.
    pub alice: Identity,
    /// The executor, with this project's `did:nau:` DID.
    pub bob: Identity,
    /// A payee whose claimed balance is deliberately wrong.
    pub carol: Identity,
    /// The payee of the exactly-migrated `0.1 + 0.2` pair.
    pub dave: Identity,
    /// The key of upstream's pinned vector.
    pub vector_key: PublicKey,
    /// The DID of upstream's pinned vector (`did:aip:34750f98bd59fcfc`).
    pub vector_did: String,
    /// Alice's legacy DID as text.
    pub alice_did: String,
    /// Bob's `did:nau:` DID as text.
    pub bob_did: String,
    /// Carol's legacy DID as text.
    pub carol_did: String,
    /// Dave's legacy DID as text.
    pub dave_did: String,
    /// The reserved escrow account of `task-translate-1`.
    pub escrow: String,
}

impl Tree {
    /// The root of the tree.
    pub fn root(&self) -> &Path {
        self.scratch.root()
    }
}

/// Build the authored tree under a fresh scratch directory.
pub fn build_upstream_tree(tag: &str) -> Tree {
    let scratch = Scratch::new(tag);
    let root = scratch.root().to_path_buf();

    let alice = Identity::from_seed(&[11u8; 32]);
    let bob = Identity::from_seed(&[22u8; 32]);
    let carol = Identity::from_seed(&[33u8; 32]);
    let dave = Identity::from_seed(&[44u8; 32]);
    let impostor = Identity::from_seed(&[55u8; 32]);
    let (vector_card, vector_key) = upstream_vector_card();

    let alice_did = alice.public_key().legacy_did().to_string();
    let bob_did = bob.did().to_string();
    let carol_did = carol.public_key().legacy_did().to_string();
    let dave_did = dave.public_key().legacy_did().to_string();
    let vector_did = vector_card["did"]
        .as_str()
        .expect("the vector names a DID")
        .to_string();
    let escrow = "__escrow__:task-translate-1".to_string();

    // ---- keys.json: the keys upstream transported out of band --------------
    let keys = object(vec![
        (bob_did.as_str(), s(bob.public_key().to_hex())),
        (vector_did.as_str(), s(vector_key.to_hex())),
    ]);
    write(
        &root.join("keys.json"),
        &serde_json::to_string_pretty(&keys).expect("keys serialize"),
    );

    // ---- agent cards -------------------------------------------------------
    // 1. Legacy prefix, a mixed-case capability, and a fractional price. The price
    //    is a decimal *string* on purpose: a non-integer JSON number inside a
    //    signed payload cannot be canonicalized by this project at all, so a card
    //    carrying one is refused (see `card-float-stake.json`). A float in an
    //    unsigned money field — a ledger amount — migrates exactly.
    let mut alice_card = object(vec![
        ("did", s(alice_did.clone())),
        ("name", s("Alice Agent")),
        ("capabilities", arr(&["Text-Generation", "mcp"])),
        ("endpoint", s("tcp://127.0.0.1:4101")),
        ("price_per_task", s("0.001")),
        ("stake", n(100)),
        ("public_key", s(alice.public_key().to_hex())),
        ("signature", s("")),
    ]);
    sign(&mut alice_card, &alice);
    write(
        &root.join("agents/card-alice.json"),
        &alice_card.to_string(),
    );

    // 2. This project's own prefix, the key only in keys.json, and a stake and
    //    price written as decimal strings.
    let mut bob_card = object(vec![
        ("did", s(bob_did.clone())),
        ("name", s("Bob Agent")),
        ("capabilities", arr(&["translation"])),
        ("price_per_task", s("12.5")),
        ("stake", s("250.5")),
        ("signature", s("")),
    ]);
    sign(&mut bob_card, &bob);
    write(&root.join("agents/card-bob.json"), &bob_card.to_string());

    // 3. One byte of the payload changed after signing: "Alice Agent" ->
    //    "Alice Agend".
    let mut tampered = alice_card.clone();
    tampered["name"] = s("Alice Agend");
    write(
        &root.join("agents/card-tampered.json"),
        &tampered.to_string(),
    );

    // 4. Alice's DID stamped on somebody else's key.
    let mut wrong_key = object(vec![
        ("did", s(alice_did.clone())),
        ("name", s("Impostor Agent")),
        ("capabilities", arr(&["translation"])),
        ("stake", n(10)),
        ("public_key", s(impostor.public_key().to_hex())),
        ("signature", s("")),
    ]);
    sign(&mut wrong_key, &impostor);
    write(
        &root.join("agents/card-wrongkey.json"),
        &wrong_key.to_string(),
    );

    // 5. A float inside the signed payload. Upstream signed this happily; this
    //    project's canonical form refuses floats, so the record cannot be
    //    verified at all. The signature here is a placeholder of the right shape:
    //    no signature could make this record acceptable, and the point of the
    //    fixture is that the reason is named.
    let float_card = object(vec![
        ("did", s(carol_did.clone())),
        ("name", s("Float Stake")),
        ("capabilities", arr(&["translation"])),
        ("stake", Value::from(100.0)),
        ("public_key", s(carol.public_key().to_hex())),
        ("signature", s("ab".repeat(64))),
    ]);
    write(
        &root.join("agents/card-float-stake.json"),
        &float_card.to_string(),
    );

    // 6. A card with no stake: upstream tolerated it (and even NaN); this
    //    project's AgentCard requires a positive stake.
    let mut no_stake = object(vec![
        ("did", s(dave_did.clone())),
        ("name", s("No Stake")),
        ("capabilities", arr(&["translation"])),
        ("public_key", s(dave.public_key().to_hex())),
        ("signature", s("")),
    ]);
    sign(&mut no_stake, &dave);
    write(
        &root.join("agents/card-missing-stake.json"),
        &no_stake.to_string(),
    );

    // 7. Upstream's own pinned vector, signature and all.
    write(
        &root.join("agents/card-upstream-vector.json"),
        &vector_card.to_string(),
    );

    // ---- tasks -------------------------------------------------------------
    let mut task = object(vec![
        ("task_id", s("task-translate-1")),
        ("requester", s(alice_did.clone())),
        ("executor", s(bob_did.clone())),
        ("reward", s("12.5")),
        ("status", s("completed")),
        ("goal", s("translate the document")),
        ("context", s("English to Chinese, 12 pages")),
        ("done", arr(&["every section translated"])),
        ("todo", arr(&["read", "translate"])),
        ("required_skills", arr(&["translation"])),
        ("public_key", s(alice.public_key().to_hex())),
        ("signature", s("")),
    ]);
    sign(&mut task, &alice);
    write(&root.join("tasks/task-translate-1.json"), &task.to_string());

    let mut bad_status = task.clone();
    bad_status["task_id"] = s("task-badstatus");
    bad_status["status"] = s("view_change");
    sign(&mut bad_status, &alice);
    write(
        &root.join("tasks/task-badstatus.json"),
        &bad_status.to_string(),
    );

    let mut tampered_task = task.clone();
    tampered_task["task_id"] = s("task-tampered");
    tampered_task["reward"] = s("13.5");
    write(
        &root.join("tasks/task-tampered.json"),
        &tampered_task.to_string(),
    );

    let mut no_spec = object(vec![
        ("task_id", s("task-nospec")),
        ("requester", s(alice_did.clone())),
        ("reward", s("5")),
        ("status", s("open")),
        ("public_key", s(alice.public_key().to_hex())),
        ("signature", s("")),
    ]);
    sign(&mut no_spec, &alice);
    write(&root.join("tasks/task-nospec.json"), &no_spec.to_string());

    // ---- ledger ------------------------------------------------------------
    // 7 lines that convert exactly, plus one inexact and one negative line.
    let lines = [
        ledger_line(
            "task-translate-1",
            &alice_did,
            &escrow,
            "\"12.5\"",
            "Escrow",
            1_700_000_000,
        ),
        ledger_line(
            "task-translate-1",
            &escrow,
            &bob_did,
            "12.5",
            "Completed",
            1_700_000_100,
        ),
        ledger_line(
            "task-other",
            &alice_did,
            &carol_did,
            "\"0.1\"",
            "Completed",
            1_700_000_200,
        ),
        ledger_line(
            "task-other",
            &alice_did,
            &carol_did,
            "0.2",
            "Completed",
            1_700_000_300,
        ),
        ledger_line(
            "task-other",
            &alice_did,
            &carol_did,
            "1e-3",
            "Completed",
            1_700_000_400,
        ),
        ledger_line(
            "task-other",
            &alice_did,
            &carol_did,
            "0.0000001",
            "Completed",
            1_700_000_500,
        ),
        ledger_line(
            "task-other",
            &alice_did,
            &carol_did,
            "-1000",
            "DuplicateWork",
            1_700_000_600,
        ),
        ledger_line(
            "task-pair",
            &alice_did,
            &dave_did,
            "0.1",
            "Completed",
            1_700_000_700,
        ),
        ledger_line(
            "task-pair",
            &alice_did,
            &dave_did,
            "\"0.2\"",
            "Completed",
            1_700_000_800,
        ),
    ];
    write(&root.join("ledger.jsonl"), &lines.join("\n"));

    // ---- claimed balances --------------------------------------------------
    // Alice, bob, dave and the escrow account reconcile exactly. Carol's claim is
    // wrong by 0.001 on purpose, and one account is claimed that the journal never
    // mentions.
    let balances = object(vec![
        (alice_did.as_str(), s("-13.101")),
        (bob_did.as_str(), s("12.5")),
        (carol_did.as_str(), s("0.302")),
        (dave_did.as_str(), s("0.3")),
        (escrow.as_str(), n(0)),
        ("did:aip:ffffffffffffffff", s("1")),
    ]);
    write(
        &root.join("balances.json"),
        &serde_json::to_string_pretty(&balances).expect("balances serialize"),
    );

    Tree {
        scratch,
        alice,
        bob,
        carol,
        dave,
        vector_key,
        vector_did,
        alice_did,
        bob_did,
        carol_did,
        dave_did,
        escrow,
    }
}
