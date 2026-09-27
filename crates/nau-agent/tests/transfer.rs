//! Six-field handoff bundle tests.
//!
//! upstream v2.5.6 fix: upstream's `TransferBundle::validate` checked only
//! `is_empty()` on six bare `String` fields, so the bundle was an unbounded
//! payload, `owner` was not required to be a DID, and the evidence grade was
//! never checked against the trace it claimed.

use nau_agent::{TransferBundle, MAX_ENTRIES, MAX_FIELD_BYTES};
use nau_core::{Did, EvidenceGrade, NauError};

fn owner() -> Did {
    Did::parse("did:nau:34750f98bd59fcfc").expect("a valid DID")
}

fn valid() -> TransferBundle {
    TransferBundle {
        goal: "ship the parser".into(),
        context: "the grammar is in grammar.ebnf".into(),
        done: vec!["lexer written".into()],
        todo: vec!["parser".into(), "tests".into()],
        trace: vec!["sha256:deadbeef".into()],
        owner: owner(),
        evidence: EvidenceGrade::CpuProto,
    }
}

#[test]
fn a_well_formed_bundle_validates() {
    let bundle = valid();
    assert!(bundle.validate().is_ok());
    assert_eq!(bundle.evidence_label(), "cpu-proto");
}

#[test]
fn every_one_of_the_six_fields_is_required() {
    // Each of the six documented fields, emptied in turn, must be reported.
    let base = valid();

    let mut goal = base.clone();
    goal.goal = "   ".into();
    assert!(goal.validate().is_err(), "goal is required");

    let mut context = base.clone();
    context.context = String::new();
    assert!(context.validate().is_err(), "context is required");

    let mut done = base.clone();
    done.done.clear();
    assert!(done.validate().is_err(), "done is required");

    let mut todo = base.clone();
    todo.todo = vec![String::new()];
    assert!(todo.validate().is_err(), "todo is required");

    let mut trace = base.clone();
    trace.trace.clear();
    assert!(trace.validate().is_err(), "trace is required");

    // `owner` is a `Did`, so it cannot be empty — only malformed, which the
    // parser refuses. Prove the type does that job.
    assert!(Did::parse("").is_err());
    assert!(Did::parse("owner").is_err());

    // The error names the field, so a receiver knows what to fix.
    let err = goal.validate().unwrap_err();
    assert!(err.to_string().contains("goal"), "got {err}");
    let err = context.validate().unwrap_err();
    assert!(err.to_string().contains("context"), "got {err}");
}

#[test]
fn an_over_long_field_is_rejected_where_upstream_accepted_it() {
    let mut bundle = valid();
    bundle.goal = "x".repeat(MAX_FIELD_BYTES + 1);
    let err = bundle.validate().unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert!(
        err.to_string().contains("goal") && err.to_string().contains("cap"),
        "the message must name the field and the cap: {err}"
    );

    // Exactly at the cap is fine.
    let mut at_cap = valid();
    at_cap.goal = "x".repeat(MAX_FIELD_BYTES);
    assert!(at_cap.validate().is_ok());

    // A long context is likewise bounded.
    let mut context = valid();
    context.context = "y".repeat(MAX_FIELD_BYTES + 1);
    assert!(context.validate().is_err());
}

#[test]
fn an_over_long_list_is_rejected_where_upstream_accepted_it() {
    let mut bundle = valid();
    bundle.todo = (0..(MAX_ENTRIES + 1))
        .map(|i| format!("step {i}"))
        .collect();
    let err = bundle.validate().unwrap_err();
    assert!(err.to_string().contains("todo"), "got {err}");
    assert!(err.to_string().contains("cap"), "got {err}");

    // Exactly at the cap is fine.
    let mut at_cap = valid();
    at_cap.todo = (0..MAX_ENTRIES).map(|i| format!("step {i}")).collect();
    assert!(at_cap.validate().is_ok());

    // A list of individually short entries that totals over the byte cap is also
    // rejected: otherwise `MAX_ENTRIES` would be a loophole for an unbounded
    // payload.
    let mut cumulative = valid();
    let chunk = "z".repeat(MAX_FIELD_BYTES / 4);
    cumulative.done = vec![chunk; 8];
    assert!(cumulative.done.len() <= MAX_ENTRIES);
    assert!(
        cumulative.validate().is_err(),
        "the total byte cap must hold"
    );
}

#[test]
fn a_claimed_evidence_grade_without_a_trace_is_rejected() {
    // `Verified` and `CpuProto` are claims of evidence; a bundle that claims one
    // while pointing at nothing is not mechanically sound. `Unverified` is the
    // honest default and is allowed through.
    let mut claimed = valid();
    claimed.evidence = EvidenceGrade::Verified;
    claimed.trace = vec![String::new()];
    let err = claimed.validate().unwrap_err();
    assert!(err.to_string().contains("trace"), "got {err}");

    let mut honest = valid();
    honest.evidence = EvidenceGrade::Unverified;
    honest.trace = vec!["no evidence gathered".into()];
    assert!(honest.validate().is_ok());
}

#[test]
fn every_problem_is_reported_at_once() {
    // Upstream returned on the first gap; collecting them lets a caller fix the
    // whole bundle in one pass.
    let broken = TransferBundle {
        goal: String::new(),
        context: String::new(),
        done: Vec::new(),
        todo: Vec::new(),
        trace: Vec::new(),
        owner: owner(),
        evidence: EvidenceGrade::Unverified,
    };
    let message = broken.validate().unwrap_err().to_string();
    for field in ["goal", "context", "done", "todo", "trace"] {
        assert!(
            message.contains(field),
            "`{field}` should be reported in: {message}"
        );
    }
}

#[test]
fn a_bundle_round_trips_through_json_with_integers_only() {
    let bundle = valid();
    let value = serde_json::to_value(&bundle).expect("serializes");
    let decoded: TransferBundle = serde_json::from_value(value.clone()).expect("deserializes");
    assert_eq!(decoded, bundle);
    assert!(decoded.validate().is_ok());
    assert!(
        serde_json::to_string(&bundle)
            .expect("serializes")
            .contains("did:nau:"),
        "the owner must travel as a DID string"
    );
}
