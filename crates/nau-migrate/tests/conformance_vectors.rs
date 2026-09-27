//! The exact decimal strings in `conformance/vectors.json`.
//!
//! `conformance/vectors.json` is the cross-language fixture: its
//! `upstream-v2.5.6-compat` payload is upstream's own pinned vector (public key,
//! DID, canonical payload and signature verbatim from
//! `gsn-core/tests/cross_lang_signature.rs:11-14`), generated and re-checked by
//! `conformance/generate.mjs` with Node/OpenSSL. It is the only genuine upstream
//! data this crate's tests touch, and these tests are what tie the migration to it:
//!
//! * every money-shaped literal in the file converts exactly, or is refused as out
//!   of range, with the literal read from the file rather than hardcoded;
//! * upstream's own signed card migrates through the whole pipeline
//!   (`plan_from_dir` then `apply`), with its canonical payload reproduced
//!   byte-for-byte and its signature verified;
//! * a float that is a perfectly good *amount* is still refused inside a *signed
//!   payload*, which is exactly why upstream's float-bearing artifacts cannot all
//!   be carried over.

mod common;

use std::collections::BTreeMap;

use common::{object, read_vectors, s, upstream_vector_card, write, Scratch};
use nau_migrate::{amount_from_decimal, plan_from_dir, top_level_scalar, AmountDefect, RawScalar};
use nau_store::{MemoryStore, Store};
use serde_json::{json, Value};

/// Keys in the vectors that are shaped like money.
const MONEY_KEYS: &[&str] = &["stake", "amount", "n", "neg", "zero"];

/// `(vector id, key, literal, expected minor units)`.
///
/// `None` means the literal is a valid integer but not a representable *amount*:
/// `Money` is `i64` minor units, so anything at or above 10^13 major units
/// overflows when scaled. The test fails if the file contains a money-shaped
/// literal that is not listed here, so this table cannot silently go stale.
const EXPECTED: &[(&str, &str, &str, Option<i64>)] = &[
    ("upstream-v2.5.6-compat", "stake", "100", Some(100_000_000)),
    ("basic-card", "stake", "100", Some(100_000_000)),
    (
        "integers-typed-and-null-and-empty",
        "neg",
        "-42",
        Some(-42_000_000),
    ),
    ("integers-typed-and-null-and-empty", "zero", "0", Some(0)),
    ("js-safe-integer-boundary", "n", "9007199254740991", None),
    ("int64-max", "n", "9223372036854775807", None),
    ("uint64-max", "n", "18446744073709551615", None),
    // The three rejection vectors: as *amounts* they convert exactly.
    ("float-value", "amount", "100.0", Some(100_000_000)),
    ("fractional-value", "amount", "1.5", Some(1_500_000)),
    ("exponent-notation", "amount", "1e2", Some(100_000_000)),
];

/// Every money-shaped literal the file contains, with its vector id.
fn money_literals_in_vectors() -> Vec<(String, String, String)> {
    let vectors = read_vectors();
    let mut found = Vec::new();
    for section in ["payloads", "rejections"] {
        for vector in vectors[section]
            .as_array()
            .unwrap_or_else(|| panic!("`{section}` is an array"))
        {
            let id = vector["id"].as_str().expect("every vector has an id");
            let Some(input) = vector["input_json"].as_str() else {
                continue;
            };
            for key in MONEY_KEYS {
                match top_level_scalar(input, key) {
                    Ok(Some(RawScalar::Number(literal))) | Ok(Some(RawScalar::Str(literal))) => {
                        found.push((id.to_string(), (*key).to_string(), literal));
                    }
                    _ => {}
                }
            }
        }
    }
    found
}

#[test]
fn every_money_shaped_literal_in_the_vectors_converts_exactly_or_is_refused_by_name() {
    let found = money_literals_in_vectors();
    assert!(
        !found.is_empty(),
        "the vectors file must still contain money-shaped literals; if its shape \
         changed, this test needs updating rather than deleting"
    );

    let mut checked: BTreeMap<(String, String), String> = BTreeMap::new();
    for (id, key, literal) in &found {
        let expectation = EXPECTED
            .iter()
            .find(|(vector, field, text, _)| vector == id && field == key && text == literal)
            .unwrap_or_else(|| {
                panic!("`{id}` field `{key}` holds `{literal}`, which is not in the expected table")
            });
        let path = format!("conformance/vectors.json#{id}");
        match expectation.3 {
            Some(minor) => {
                let money = amount_from_decimal(&path, key, literal)
                    .unwrap_or_else(|e| panic!("`{literal}` should convert exactly: {e}"));
                assert_eq!(money.minor(), minor, "`{id}` field `{key}`");
            }
            None => {
                let error = amount_from_decimal(&path, key, literal)
                    .expect_err("this literal is not a representable amount");
                assert_eq!(
                    AmountDefect::of(&error),
                    Some(AmountDefect::OutOfRange),
                    "`{id}` field `{key}` gave {error}"
                );
                assert!(
                    error.to_string().contains(literal),
                    "the error names the literal: {error}"
                );
            }
        }
        checked.insert((id.clone(), key.clone()), literal.clone());
    }

    // Nothing in the table went stale, and the exponent/fraction vector really was
    // read verbatim rather than normalised by a float round-trip.
    for (id, key, literal, _) in EXPECTED {
        assert_eq!(
            checked.get(&((*id).to_string(), (*key).to_string())),
            Some(&(*literal).to_string()),
            "`{id}` field `{key}` was not found in the file"
        );
    }
}

#[test]
fn upstreams_own_signed_vector_migrates_through_the_whole_pipeline() {
    let scratch = Scratch::new("vectors");
    let (card, key) = upstream_vector_card();
    let did = card["did"]
        .as_str()
        .expect("the vector names a DID")
        .to_string();

    write(
        &scratch.path("agents/card-upstream-vector.json"),
        &card.to_string(),
    );
    write(
        &scratch.path("keys.json"),
        &object(vec![(did.as_str(), s(key.to_hex()))]).to_string(),
    );

    let plan = plan_from_dir(scratch.root()).expect("upstream's vector card must plan");
    assert_eq!(
        plan.rejections().count(),
        0,
        "a byte-for-byte upstream artifact must verify: {:?}",
        plan.warnings
    );
    assert_eq!(plan.cards.len(), 1);
    let planned = &plan.cards[0];
    assert_eq!(planned.legacy_did, "did:aip:34750f98bd59fcfc");
    assert!(planned.legacy_prefix);

    // The canonical payload this crate reproduced must equal the one the vectors
    // file records, byte for byte: that is what makes upstream's signature
    // verifiable here at all.
    let vectors = read_vectors();
    let vector = vectors["payloads"]
        .as_array()
        .expect("payloads")
        .iter()
        .find(|payload| payload["id"] == json!("upstream-v2.5.6-compat"))
        .expect("the upstream vector")
        .clone();
    assert_eq!(
        planned.legacy_canonical_payload,
        vector["canonical"].as_str().expect("canonical")
    );
    assert_eq!(
        planned.legacy_signature,
        vector["signature_hex"].as_str().expect("signature")
    );

    let mut store = MemoryStore::new();
    let report = nau_migrate::apply(&plan, &mut store).expect("applies");
    assert_eq!(report.cards_imported, 1);
    assert!(
        report.conserved,
        "no ledger entries, so the books trivially balance"
    );
    let agents = store.load_agents().expect("agents");
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].owner.as_str(), "did:aip:34750f98bd59fcfc");
    assert_eq!(agents[0].name, "CrossLang");
    assert_eq!(agents[0].stake.minor(), 100_000_000);
    assert!(agents[0].skills.iter().any(|skill| skill.id == "mcp"));
}

#[test]
fn a_float_that_is_a_perfectly_good_amount_is_still_refused_inside_a_signed_payload() {
    // `{"amount":100.0}` appears in the vectors as a *rejection*: floats cannot be
    // canonicalized because `100` and `100.0` format differently in Rust, Python
    // and JavaScript. As an amount, though, `100.0` is exactly 100 NAU. Both facts
    // matter to a migration: a money field can be read exactly, while a signed
    // payload that contains a float cannot be verified at all.
    let money = amount_from_decimal("conformance/vectors.json#float-value", "amount", "100.0")
        .expect("100.0 is an exactly representable amount");
    assert_eq!(money.minor(), 100_000_000);

    let value: Value = serde_json::from_str(r#"{"amount":100.0}"#).expect("valid JSON");
    let error = nau_core::canonical::canonical_object(&value)
        .expect_err("this project's canonical form refuses floats in signed payloads");
    assert!(
        matches!(
            error,
            nau_core::canonical::CanonicalError::NonIntegerNumber(_)
        ),
        "got {error:?}"
    );
}
