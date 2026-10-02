//! End to end: an authored upstream-shaped tree, planned, applied, and checked.
//!
//! # Honesty
//!
//! The fixture tree is **authored to model the audited upstream v2.5.6 format**
//! (see `tests/common/mod.rs` for the layout and for what each file is for). It was
//! **not** captured from a live upstream instance, and no real upstream user data
//! is migrated here. The one genuine upstream artifact in the tree is
//! `agents/card-upstream-vector.json`: upstream's own pinned cross-language test
//! vector, taken verbatim from `conformance/vectors.json`
//! (`gsn-core/tests/cross_lang_signature.rs:11-14`).

mod common;

use common::{arr, build_upstream_tree, n, object, s, sign, write, Scratch, Tree};
use nau_core::{Identity, TaskState};
use nau_migrate::{
    apply, plan_from_dir, Finding, MigrationPlan, Severity, Warning, SCHEMA_KEY, SCHEMA_VALUE,
    SOURCE_DIGEST_KEY,
};
use nau_store::{MemoryStore, Store};
use serde_json::json;

fn plan_for(tree: &Tree) -> MigrationPlan {
    plan_from_dir(tree.root()).expect("the authored tree must plan")
}

fn findings(plan: &MigrationPlan, code: Finding) -> Vec<&Warning> {
    plan.warnings
        .iter()
        .filter(|warning| warning.code == code)
        .collect()
}

#[test]
fn the_authored_upstream_tree_migrates_and_conserves_exactly() {
    let tree = build_upstream_tree("e2e");
    let plan = plan_for(&tree);
    let summary = plan.summary().expect("the summary is computable");

    // ---- what the plan would import ----------------------------------------
    assert_eq!(summary.cards, 3, "alice, bob and upstream's own vector");
    assert_eq!(summary.tasks, 1);
    assert_eq!(summary.ledger_entries, 7);
    assert_eq!(
        summary.rejections, 9,
        "4 cards + 3 task records + 2 ledger lines are refused"
    );
    assert_eq!(summary.moved.minor(), 25_601_000, "the exact total moved");
    assert!(
        summary.net.is_zero(),
        "the authored journal is closed, so its net movement is exactly zero"
    );

    // ---- every refusal is typed and names its reason ------------------------
    let signatures = findings(&plan, Finding::SignatureInvalid);
    assert_eq!(
        signatures.len(),
        2,
        "the tampered card and the tampered task"
    );
    assert!(signatures
        .iter()
        .any(|warning| warning.detail.contains("Alice Agend")));
    assert!(signatures
        .iter()
        .any(|warning| warning.detail.contains("13.5")));

    let mismatches = findings(&plan, Finding::DidKeyMismatch);
    assert_eq!(mismatches.len(), 1);
    assert!(mismatches[0].detail.contains("refusing to verify"));

    let floats = findings(&plan, Finding::LegacyFloatInSignedPayload);
    assert_eq!(floats.len(), 1);
    assert!(floats[0].detail.contains("100.0"), "{}", floats[0].detail);

    let missing = findings(&plan, Finding::MissingField);
    assert_eq!(
        missing.len(),
        2,
        "the stake-less card and the spec-less task"
    );
    assert!(missing
        .iter()
        .any(|warning| warning.detail.contains("stake")));
    assert!(missing
        .iter()
        .any(|warning| warning.detail.contains("goal")));

    let statuses = findings(&plan, Finding::UnsupportedStatus);
    assert_eq!(statuses.len(), 1);
    assert!(
        statuses[0].detail.contains("view_change"),
        "the upstream status must be named: {}",
        statuses[0].detail
    );

    let inexact = findings(&plan, Finding::AmountNotExact);
    assert_eq!(inexact.len(), 1);
    assert!(
        inexact[0].detail.contains("0.0000001"),
        "{}",
        inexact[0].detail
    );
    assert!(
        inexact[0].detail.contains("ledger.jsonl#6"),
        "the rejection names the file and the line: {}",
        inexact[0].detail
    );
    assert!(
        inexact[0].detail.contains("refusing to round"),
        "{}",
        inexact[0].detail
    );

    let negative = findings(&plan, Finding::NonPositiveAmount);
    assert_eq!(negative.len(), 1);
    assert!(negative[0].detail.contains("not positive"));

    // ---- the balance claims that do not reconcile are reported, not smoothed --
    let discrepancies = findings(&plan, Finding::BalanceDiscrepancy);
    assert_eq!(
        discrepancies.len(),
        2,
        "carol's claim is off by 0.001 and one account is claimed that has no entries"
    );
    assert!(discrepancies
        .iter()
        .all(|warning| warning.severity == Severity::Warning));
    let carol = discrepancies
        .iter()
        .find(|warning| warning.detail.contains(&tree.carol_did))
        .expect("carol's claim is reported");
    assert!(carol.detail.contains("0.302"), "{}", carol.detail);
    assert!(carol.detail.contains("0.301"), "{}", carol.detail);
    assert!(discrepancies
        .iter()
        .any(|warning| warning.detail.contains("did:aip:ffffffffffffffff")));
    // Dave's claim reconciled exactly, so nothing was reported for him: this is
    // `0.1 + 0.2` migrating to exactly `0.3` through the whole pipeline.
    assert!(
        !discrepancies
            .iter()
            .any(|warning| warning.detail.contains(&tree.dave_did)),
        "0.1 + 0.2 is exactly 0.3, so dave's claim of 0.3 must reconcile"
    );

    // ---- the notes that record what had to be decided -----------------------
    assert!(!findings(&plan, Finding::LegacyDidPrefix).is_empty());
    assert_eq!(
        findings(&plan, Finding::KeyFromRegistry).len(),
        2,
        "bob's key and the vector's key both come from keys.json"
    );
    assert_eq!(findings(&plan, Finding::CapabilityNormalised).len(), 1);
    assert!(!findings(&plan, Finding::SystemAccountKept).is_empty());
    assert!(!findings(&plan, Finding::TargetNotWireValid).is_empty());
    assert!(plan
        .warnings
        .iter()
        .all(|warning| !warning.detail.is_empty() && !warning.code.as_str().is_empty()));

    // ---- applying it -------------------------------------------------------
    let rendered = serde_json::to_string_pretty(&plan).expect("the plan serializes");
    assert!(rendered.contains("\"cards\""));
    // The plan canonicalizes, and the canonical form refuses floats: a plan that
    // canonicalizes is a plan in which no amount ever touched a float.
    let canonical = plan.canonical_json().expect("the plan contains no float");
    assert!(canonical.contains("\"amount\":"));
    assert_eq!(plan.digest().expect("digest").len(), 64);

    let mut store = MemoryStore::new();
    let report = apply(&plan, &mut store).expect("the plan applies");
    assert_eq!(report.cards_imported, 3);
    assert_eq!(report.tasks_imported, 1);
    assert_eq!(report.ledger_entries_imported, 7);
    assert_eq!(report.cards_planned, 3);
    assert_eq!(report.tasks_planned, 1);
    assert_eq!(report.ledger_entries_planned, 7);
    assert_eq!(
        report.rejected_at_apply, 0,
        "nothing was edited between planning and applying"
    );
    assert_eq!(report.rejected, 9);
    assert_eq!(report.migrated_total.minor(), 25_601_000);
    assert!(report.migrated_net.is_zero());
    assert!(
        report.conserved,
        "conservation is exact: the net movement is zero and the re-derived balances sum to it"
    );

    // ---- the imported agent state ------------------------------------------
    let agents = store.load_agents().expect("agents load");
    assert_eq!(agents.len(), 3);
    let dids: Vec<String> = agents.iter().map(|card| card.owner.to_string()).collect();
    let mut sorted = dids.clone();
    sorted.sort();
    assert_eq!(dids, sorted, "the store returns agents ordered by DID");
    for card in &agents {
        assert!(card.owner.matches_public_key(&card.owner_key));
        assert!(card.stake.is_positive());
        assert!(!card.skills.is_empty());
        assert!(
            card.signature.is_empty(),
            "a migrated card is stored unsigned and says so in the plan"
        );
    }
    let upstream = agents
        .iter()
        .find(|card| card.owner.as_str() == tree.vector_did)
        .expect("upstream's own vector card was imported");
    assert_eq!(upstream.name, "CrossLang");
    assert_eq!(upstream.stake.minor(), 100_000_000);
    let bob = agents
        .iter()
        .find(|card| card.owner.as_str() == tree.bob_did)
        .expect("bob was imported");
    assert_eq!(bob.stake.minor(), 250_500_000);
    let alice = agents
        .iter()
        .find(|card| card.owner.as_str() == tree.alice_did)
        .expect("alice was imported");
    assert_eq!(alice.pricing.unit_price.minor(), 1_000, "0.001 is exact");
    assert_eq!(alice.skills[0].id, "text-generation");
    assert_eq!(alice.endpoints, vec!["tcp://127.0.0.1:4101"]);

    // ---- the imported task -------------------------------------------------
    let tasks = store.load_tasks().expect("tasks load");
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].id.as_str(), "task-translate-1");
    assert_eq!(tasks[0].state, TaskState::Accepted);
    assert_eq!(tasks[0].budget.minor(), 12_500_000);
    assert_eq!(tasks[0].spec.owner.as_str(), tree.alice_did);
    assert_eq!(
        tasks[0].assigned_to.as_ref().map(ToString::to_string),
        Some(tree.bob_did.clone())
    );
    assert!(tasks[0].signature.is_empty());

    // ---- the imported journal ---------------------------------------------
    let ledger = store.load_ledger().expect("ledger loads");
    assert_eq!(ledger.len(), 7);
    let mut moved = 0i64;
    for (index, entry) in ledger.iter().enumerate() {
        assert_eq!(entry["seq"], json!(u64::try_from(index).expect("fits")));
        let amount = entry["amount"]
            .as_i64()
            .expect("money reaches the journal as an integer, never a float");
        assert!(amount > 0);
        moved += amount;
        assert!(
            entry["raw_amount"].is_string(),
            "the verbatim upstream literal is kept beside the converted value"
        );
        assert!(entry["source"]
            .as_str()
            .expect("source")
            .starts_with("ledger.jsonl#"));
        assert!(entry["memo"].as_str().expect("memo").contains("v2.5.6"));
    }
    assert_eq!(moved, 25_601_000);
    let kinds: Vec<&str> = ledger
        .iter()
        .map(|entry| entry["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(
        kinds,
        vec!["Escrow", "Release", "Release", "Release", "Release", "Release", "Release"],
        "upstream's reasons are mapped onto this project's movement kinds"
    );

    // ---- conservation, exactly --------------------------------------------
    let balance_of = |account: &str| {
        report
            .accounts
            .iter()
            .find(|balance| balance.account == account)
            .map_or(0, |balance| balance.derived.minor())
    };
    assert_eq!(balance_of(&tree.alice_did), -13_101_000);
    assert_eq!(balance_of(&tree.bob_did), 12_500_000);
    assert_eq!(balance_of(&tree.carol_did), 301_000);
    assert_eq!(
        balance_of(&tree.dave_did),
        300_000,
        "0.1 + 0.2 migrates to exactly 0.3 (300000 minor units) through the whole pipeline"
    );
    assert_eq!(balance_of(&tree.escrow), 0, "escrow in and out, exactly");
    let sum: i64 = report
        .accounts
        .iter()
        .map(|balance| balance.derived.minor())
        .sum();
    assert_eq!(sum, 0, "the books balance exactly: there is no epsilon");

    // ---- provenance --------------------------------------------------------
    assert_eq!(
        store.get_meta(SOURCE_DIGEST_KEY).expect("meta").as_deref(),
        Some(report.source_digest.as_str())
    );
    assert_eq!(
        store.get_meta(SCHEMA_KEY).expect("meta").as_deref(),
        Some(SCHEMA_VALUE)
    );
    assert_eq!(report.source_digest.len(), 64);

    // ---- the journal is append-only, so a second apply is refused ----------
    let error = apply(&plan, &mut store).expect_err("a second apply must be refused");
    assert!(matches!(
        error,
        nau_migrate::MigrateError::AlreadyApplied { .. }
    ));
    assert_eq!(store.load_ledger().expect("ledger loads").len(), 7);
}

#[test]
fn aggregate_array_files_are_read_and_deduplicated_by_identity() {
    // Upstream's own defect was that a repeated registration silently overwrote the
    // map entry *and* deposited the stake a second time (GAP §2.6). Here the later
    // record wins and the earlier one is reported.
    let scratch = Scratch::new("aggregate");
    let identity = Identity::from_seed(&[66u8; 32]);
    let did = identity.public_key().legacy_did().to_string();

    let mut first = object(vec![
        ("did", s(did.clone())),
        ("name", s("First")),
        ("capabilities", arr(&["translation"])),
        ("stake", n(1)),
        ("public_key", s(identity.public_key().to_hex())),
        ("signature", s("")),
    ]);
    sign(&mut first, &identity);
    let mut second = first.clone();
    second["name"] = s("Second");
    sign(&mut second, &identity);

    write(
        &scratch.path("agents.json"),
        &json!([first, second]).to_string(),
    );

    let plan = plan_from_dir(scratch.root()).expect("plans");
    assert_eq!(plan.cards.len(), 1, "one card per DID");
    assert_eq!(plan.cards[0].card.name, "Second", "the later record wins");
    assert_eq!(plan.cards[0].source_file, "agents.json#1");
    let duplicates = findings(&plan, Finding::DuplicateSourceRecord);
    assert_eq!(duplicates.len(), 1);
    assert!(duplicates[0].detail.contains("agents.json#0"));
    assert!(duplicates[0].detail.contains("§2.6"));
    assert_eq!(plan.rejections().count(), 0);
}
