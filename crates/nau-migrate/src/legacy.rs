//! Reading upstream-shaped records, and verifying their legacy signatures.
//!
//! # Why the signature check uses *this* project's canonicalizer
//!
//! Upstream built its signing payload with `serde_json::to_vec` after removing the
//! top-level `signature` key (`gsn-core/src/aca/crypto.rs:19-25`). The audit's
//! conclusion — and this crate's test `legacy_signature_verification.rs` — is that
//! for the shapes upstream actually signed, this project's canonical form produces
//! **the same bytes**: key order is irrelevant because both sort, and the two
//! disagree only where upstream was already broken (a nested `signature`, a float,
//! a `\u`-escaped non-ASCII character, an astral-plane key ordering — `ATTRIBUTION.md`
//! §3 pins the byte-for-byte agreement on upstream's own vector).
//!
//! So the verification here is: `canonical_object(record)` under this project's
//! rules, then Ed25519 `verify` with the record's claimed key — plus the binding
//! check that the DID really is that key's fingerprint. Where upstream's payload
//! cannot be reproduced under our rules (a float in the payload is the common case)
//! the record is **rejected and reported**, never accepted on faith.
//!
//! # Why a public key must arrive from somewhere
//!
//! Upstream's DID is `sha256(raw public key)[..8]` — a *fingerprint*
//! (`identity/did.rs:9-15`). A DID therefore cannot verify a signature by itself,
//! and upstream transported the key out of band. This crate accepts the key either
//! inline in the record (`public_key` / `owner_key` / `pubkey`) or from a
//! `keys.json` registry beside the tree, and refuses the record if neither has it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nau_core::canonical::{canonical_object, CanonicalError};
use nau_core::{Did, PublicKey, Signature64};
use serde_json::Value;

use crate::error::{MigrateError, Result};
use crate::rawjson;
use crate::warning::{Defect, Finding, Warning};

/// How a path is named in findings: relative to the source root, with `/`
/// separators, so that reports are identical on Windows and Unix.
pub fn path_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

/// One JSON object read from the source tree, with the verbatim text it came from.
#[derive(Debug, Clone)]
pub struct RecordSource {
    /// `agents/card-alice.json`, or `agents.json#3` for the fourth element of a
    /// root array.
    pub label: String,
    /// The verbatim JSON text of this object (a slice of the file).
    pub text: String,
    /// The parsed object.
    pub value: Value,
}

/// Read every record from `root/<aggregate>` and `root/<subdir>/*.json`.
///
/// The layout is this tool's documented reading convention over upstream-shaped
/// objects; it is not a claim about upstream's own directory layout (see the crate
/// documentation).
///
/// Per-file problems — an unreadable file, malformed JSON, a record that is not an
/// object — become rejection findings and the remaining files are still read, so
/// one bad artifact cannot block a migration.
///
/// # Errors
///
/// [`MigrateError::Io`] when the directory itself cannot be listed.
pub fn read_record_sources(
    root: &Path,
    aggregate: &str,
    subdir: &str,
    findings: &mut Vec<Warning>,
) -> Result<Vec<RecordSource>> {
    let mut files: Vec<PathBuf> = Vec::new();

    let aggregate_path = root.join(aggregate);
    if aggregate_path.is_file() {
        files.push(aggregate_path);
    }

    let subdir_path = root.join(subdir);
    if subdir_path.is_dir() {
        let entries =
            std::fs::read_dir(&subdir_path).map_err(|e| MigrateError::io(&subdir_path, e))?;
        let mut found: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| MigrateError::io(&subdir_path, e))?;
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                found.push(path);
            }
        }
        // Deterministic order: file name, so a run is reproducible.
        found.sort();
        files.extend(found);
    }

    let mut sources = Vec::new();
    for path in files {
        let label = path_label(root, &path);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                findings.push(Warning::reject(
                    Finding::UnreadableFile,
                    Some(label),
                    format!("the file could not be read as UTF-8 text: {error}"),
                ));
                continue;
            }
        };
        let slices = match rawjson::root_slices(&text) {
            Ok(slices) => slices,
            Err(error) => {
                findings.push(Warning::reject(
                    Finding::MalformedJson,
                    Some(label),
                    format!("the file is not one JSON value: {error}"),
                ));
                continue;
            }
        };
        let multiple = slices.len() > 1;
        for (index, slice) in slices.iter().enumerate() {
            let label = if multiple {
                format!("{label}#{index}")
            } else {
                label.clone()
            };
            match serde_json::from_str::<Value>(slice) {
                Ok(value) if value.is_object() => sources.push(RecordSource {
                    label,
                    text: (*slice).to_string(),
                    value,
                }),
                Ok(value) => findings.push(Warning::reject(
                    Finding::RecordNotAnObject,
                    Some(label),
                    format!(
                        "each record must be a JSON object, found {}",
                        crate::field::kind_of(&value)
                    ),
                )),
                Err(error) => findings.push(Warning::reject(
                    Finding::MalformedJson,
                    Some(label),
                    format!("the record is not valid JSON: {error}"),
                )),
            }
        }
    }
    Ok(sources)
}

/// `DID → public key`, the key material upstream transported beside its records.
#[derive(Debug, Default, Clone)]
pub struct KeyRegistry {
    keys: BTreeMap<String, PublicKey>,
}

impl KeyRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key.
    ///
    /// The key is accepted even when it does not fingerprint `did`; the binding
    /// check happens per record, so a registry entry that does not match is
    /// reported against the record that tried to use it.
    pub fn insert(&mut self, did: impl Into<String>, key: PublicKey) {
        self.keys.insert(did.into(), key);
    }

    /// Look a key up by the DID exactly as the record spells it.
    pub fn get(&self, did: &str) -> Option<PublicKey> {
        self.keys.get(did).copied()
    }

    /// How many keys the registry holds.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when the registry holds no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Read a `keys.json` object of `{"<did>": "<64 hex characters>"}`.
///
/// Entries that are not a DID/key pair are reported and skipped: one bad entry
/// must not make the whole registry unusable.
pub fn keys_from_json(label: &str, value: &Value, findings: &mut Vec<Warning>) -> KeyRegistry {
    let mut registry = KeyRegistry::new();
    let Some(object) = value.as_object() else {
        findings.push(Warning::reject(
            Finding::RecordNotAnObject,
            Some(label.to_string()),
            format!(
                "`keys.json` must be an object of {{\"<did>\": \"<public key hex>\"}}, found {}",
                crate::field::kind_of(value)
            ),
        ));
        return registry;
    };
    for (did_text, key_value) in object {
        let Some(key_hex) = key_value.as_str() else {
            findings.push(Warning::reject(
                Finding::InvalidFieldType,
                Some(label.to_string()),
                format!(
                    "`keys.json` entry `{did_text}` must be a hex string, found {}",
                    crate::field::kind_of(key_value)
                ),
            ));
            continue;
        };
        let key = match PublicKey::from_hex(key_hex) {
            Ok(key) => key,
            Err(error) => {
                findings.push(Warning::reject(
                    Finding::InvalidFieldValue,
                    Some(label.to_string()),
                    format!("`keys.json` entry `{did_text}` is not a public key: {error}"),
                ));
                continue;
            }
        };
        if Did::parse(did_text).is_err() {
            findings.push(Warning::reject(
                Finding::InvalidDid,
                Some(label.to_string()),
                format!("`keys.json` key `{did_text}` is not a DID"),
            ));
            continue;
        }
        registry.insert(did_text.clone(), key);
    }
    registry
}

/// A record whose legacy signature verified under this project's canonical form.
#[derive(Debug, Clone)]
pub struct VerifiedLegacy {
    /// Source file (and `#<index>`), as it will be reported.
    pub source_file: String,
    /// The DID exactly as upstream wrote it.
    pub did: Did,
    /// The key that fingerprints `did`.
    pub public_key: PublicKey,
    /// The canonical payload that was verified — kept in the plan so that
    /// [`crate::apply()`] can re-check the plan was not altered.
    pub canonical_payload: String,
    /// The verified hex signature.
    pub signature: String,
}

/// Verify one legacy record's signature against its claimed DID and key.
///
/// # Errors
///
/// A [`Defect`] naming the reason, one of:
/// [`Finding::SignatureInvalid`], [`Finding::SignatureEncodingInvalid`],
/// [`Finding::DidKeyMismatch`], [`Finding::LegacyFloatInSignedPayload`],
/// [`Finding::CanonicalizationRefused`], [`Finding::MissingField`].
pub fn verify_legacy_record(
    source: &str,
    value: &Value,
    did: Did,
    public_key: PublicKey,
) -> std::result::Result<VerifiedLegacy, Defect> {
    // 1. The claim must be self-consistent before anything is verified with it.
    if !did.matches_public_key(&public_key) {
        return Err(Defect::new(
            Finding::DidKeyMismatch,
            source,
            format!(
                "the supplied public key `{}` is not the key `{did}` fingerprints; \
                 refusing to verify a signature against a key the DID does not name",
                public_key.to_hex()
            ),
        ));
    }

    // 2. The signature field must be there and must be a hex string.
    let signature_hex = match crate::field::find_present(value, &["signature"]) {
        Some((_, found)) => match found.as_str() {
            Some(text) if !text.trim().is_empty() => text.to_string(),
            Some(_) => {
                return Err(Defect::new(
                    Finding::SignatureInvalid,
                    source,
                    "field `signature` is empty; an unsigned record cannot be verified".to_string(),
                ))
            }
            None => {
                return Err(Defect::new(
                    Finding::InvalidFieldType,
                    source,
                    format!(
                        "field `signature` must be a hex string, found {}",
                        crate::field::kind_of(found)
                    ),
                ))
            }
        },
        None => {
            return Err(Defect::new(
                Finding::MissingField,
                source,
                "required field `signature` is missing".to_string(),
            ))
        }
    };
    // 3. The payload must be reproducible under this project's canonical rules.
    //    This is checked before decoding the signature on purpose: a payload this
    //    project cannot canonicalize is unverifiable no matter how well-formed the
    //    signature is, and that is the more useful thing to report.
    // upstream v2.5.6 fix: upstream removed only the *top-level* `signature` key
    // (`aca/crypto.rs:19-25`) and admitted floats into signed payloads, so
    // `100`/`100.0`/`1e2` could not be reproduced across languages. Here every
    // `signature` key is dropped at every depth and a float is a hard refusal
    // rather than a silent divergence (GAP §4.1/§4.3).
    let canonical_payload = canonical_object(value).map_err(|error| match &error {
        CanonicalError::NonIntegerNumber(text) => Defect::new(
            Finding::LegacyFloatInSignedPayload,
            source,
            format!(
                "the signed payload contains the non-integer number `{text}`; upstream admitted \
                 floats into signed payloads (`100` and `100.0` format differently in Rust, \
                 Python and JavaScript), so its signature is not reproducible under this \
                 project's canonical form and the record cannot be accepted"
            ),
        ),
        other => Defect::new(
            Finding::CanonicalizationRefused,
            source,
            format!("the signed payload could not be canonicalized: {other}"),
        ),
    })?;

    // 4. The signature must be decodable, and must actually verify.
    let signature = Signature64::from_hex(&signature_hex).map_err(|error| {
        Defect::new(
            Finding::SignatureEncodingInvalid,
            source,
            format!("field `signature` is not 64 bytes of hex: {error}"),
        )
    })?;

    public_key
        .verify(canonical_payload.as_bytes(), signature.as_bytes())
        .map_err(|error| {
            Defect::new(
                Finding::SignatureInvalid,
                source,
                format!(
                    "the legacy signature does not verify over the canonical payload \
                     `{canonical_payload}`: {error}"
                ),
            )
        })?;

    Ok(VerifiedLegacy {
        source_file: source.to_string(),
        did,
        public_key,
        canonical_payload,
        signature: signature_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::Identity;
    use serde_json::json;

    fn signed_card(seed: u8, name: &str) -> (Identity, Value) {
        let identity = Identity::from_seed(&[seed; 32]);
        let mut card = json!({
            "did": identity.public_key().legacy_did().as_str(),
            "name": name,
            "capabilities": ["text-generation", "mcp"],
            "stake": 100,
            "signature": ""
        });
        let signature = identity.sign_payload(&card).expect("signs");
        card["signature"] = json!(signature);
        (identity, card)
    }

    #[test]
    fn a_hand_built_card_signed_by_a_real_key_verifies() {
        let (identity, card) = signed_card(1, "CrossLang");
        let verified = verify_legacy_record(
            "agents/card.json",
            &card,
            identity.public_key().legacy_did(),
            identity.public_key(),
        )
        .expect("verifies");
        assert_eq!(verified.did.as_str(), "did:aip:34750f98bd59fcfc");
        assert_eq!(verified.source_file, "agents/card.json");
        assert_eq!(
            verified.canonical_payload,
            r#"{"capabilities":["text-generation","mcp"],"did":"did:aip:34750f98bd59fcfc","name":"CrossLang","stake":100}"#
        );
        assert_eq!(verified.signature.len(), 128);
    }

    #[test]
    fn one_changed_byte_in_the_payload_is_rejected() {
        let (identity, mut card) = signed_card(1, "CrossLang");
        card["name"] = json!("CrossLane"); // one byte changed
        let defect = verify_legacy_record(
            "agents/card.json",
            &card,
            identity.public_key().legacy_did(),
            identity.public_key(),
        )
        .expect_err("must be rejected");
        assert_eq!(defect.code, Finding::SignatureInvalid);
        assert_eq!(defect.source, "agents/card.json");
        assert!(
            defect.detail.contains("CrossLane"),
            "the rejection names the payload that did not verify: {}",
            defect.detail
        );
    }

    #[test]
    fn one_changed_byte_in_the_signature_is_rejected() {
        let (identity, mut card) = signed_card(2, "Bob");
        let mut signature = card["signature"].as_str().expect("hex").to_string();
        let last = signature.pop().expect("non-empty");
        signature.push(if last == '0' { '1' } else { '0' });
        card["signature"] = json!(signature);
        let defect = verify_legacy_record(
            "agents/card.json",
            &card,
            identity.public_key().legacy_did(),
            identity.public_key(),
        )
        .expect_err("must be rejected");
        assert_eq!(defect.code, Finding::SignatureInvalid);
    }

    #[test]
    fn a_key_that_does_not_fingerprint_the_did_is_refused_before_any_verification() {
        let (_identity, card) = signed_card(1, "CrossLang");
        let other = Identity::from_seed(&[9u8; 32]);
        let defect = verify_legacy_record(
            "agents/card.json",
            &card,
            Did::parse("did:aip:34750f98bd59fcfc").expect("parses"),
            other.public_key(),
        )
        .expect_err("must be rejected");
        assert_eq!(defect.code, Finding::DidKeyMismatch);
    }

    #[test]
    fn a_float_in_the_signed_payload_is_reported_as_the_reason_it_cannot_be_verified() {
        // Upstream signed `stake: 100.0` happily; this project's canonical form
        // refuses floats, so such a record cannot be verified nor accepted.
        let identity = Identity::from_seed(&[3u8; 32]);
        let card = json!({
            "did": identity.public_key().legacy_did().as_str(),
            "name": "FloatStake",
            "stake": 100.0,
            "signature": "00"
        });
        let defect = verify_legacy_record(
            "agents/card-float.json",
            &card,
            identity.public_key().legacy_did(),
            identity.public_key(),
        )
        .expect_err("must be rejected");
        assert_eq!(defect.code, Finding::LegacyFloatInSignedPayload);
        assert!(defect.detail.contains("100.0"), "{}", defect.detail);
    }

    #[test]
    fn missing_and_malformed_signatures_are_distinguished() {
        let identity = Identity::from_seed(&[4u8; 32]);
        let did = identity.public_key().legacy_did();
        let no_signature = json!({ "did": did.as_str(), "name": "x" });
        assert_eq!(
            verify_legacy_record("f", &no_signature, did.clone(), identity.public_key())
                .expect_err("missing")
                .code,
            Finding::MissingField
        );
        let empty = json!({ "did": did.as_str(), "name": "x", "signature": "" });
        assert_eq!(
            verify_legacy_record("f", &empty, did.clone(), identity.public_key())
                .expect_err("empty")
                .code,
            Finding::SignatureInvalid
        );
        let short = json!({ "did": did.as_str(), "name": "x", "signature": "00" });
        assert_eq!(
            verify_legacy_record("f", &short, did, identity.public_key())
                .expect_err("short")
                .code,
            Finding::SignatureEncodingInvalid
        );
    }

    #[test]
    fn key_registries_report_bad_entries_and_keep_the_good_ones() {
        let identity = Identity::from_seed(&[5u8; 32]);
        let good_did = identity.did().to_string();
        let mut entries = serde_json::Map::new();
        entries.insert(good_did.clone(), json!(identity.public_key().to_hex()));
        entries.insert("did:aip:0000000000000000".to_string(), json!("not-hex"));
        entries.insert("alice".to_string(), json!(identity.public_key().to_hex()));
        entries.insert("did:nau:1111111111111111".to_string(), json!(17));
        let value = Value::Object(entries);
        let mut findings = Vec::new();
        let registry = keys_from_json("keys.json", &value, &mut findings);
        assert_eq!(registry.len(), 1, "only the valid pair is kept");
        assert!(registry.get(&good_did).is_some());
        assert!(!registry.is_empty());
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|warning| warning.is_rejection()));

        let mut findings = Vec::new();
        let empty = keys_from_json("keys.json", &json!([]), &mut findings);
        assert!(empty.is_empty());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn path_labels_are_relative_and_use_forward_slashes() {
        let root = Path::new("data/upstream");
        let label = path_label(root, &root.join("agents").join("card.json"));
        assert_eq!(label, "agents/card.json");
        assert_eq!(
            path_label(root, Path::new("elsewhere/x.json")),
            "elsewhere/x.json"
        );
    }
}
