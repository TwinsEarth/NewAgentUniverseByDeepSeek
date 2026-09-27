//! Canonical JSON payloads — the byte-level contract between Rust, Python and
//! JavaScript.
//!
//! # Why a hand-written serializer
//!
//! Upstream v2.5.6 builds its signing payload with
//! `serde_json::to_vec(&value)` after `map.remove("signature")`
//! (`gsn-core/src/aca/crypto.rs:19-25`). That delegates byte-format decisions to
//! whatever the local JSON library happens to do, which is exactly the thing a
//! cross-language signature scheme must not do. It also:
//!
//! * used `unwrap_or(Value::Null)`, so a serialization failure silently produced
//!   a signature over the four bytes `null`;
//! * removed `signature` only at the **top level**, so a nested signed
//!   structure would have its inner signature covered by the outer signature;
//! * accepted floats, so `100` and `100.0` — and any value above 2^53 in
//!   JavaScript — are different payloads in one language and the same in
//!   another.
//!
//! This module writes the bytes itself and enforces the rules below.
//!
//! # The canonical form (v1, protocol `nau/1`)
//!
//! 1. The value must be a JSON **object** at the root.
//! 2. Every object key named `signature` is dropped, **at every depth**.
//! 3. Object keys are emitted in ascending **Unicode code point** order.
//!    (Rust/`&str` ordering and Python's `sort_keys=True` already do this;
//!    JavaScript's default `Array.prototype.sort()` compares **UTF-16 code
//!    units**, which disagrees for astral-plane characters — the JS SDK must
//!    therefore use an explicit code-point comparator. See `docs/CONFORMANCE.md`.)
//! 4. No whitespace. Separators are exactly `,` and `:`.
//! 5. Strings are emitted as raw UTF-8. Only `"`, `\` and the seven control
//!    characters with short escapes are escaped; other control characters use
//!    lowercase `\u00xx`. Nothing else is escaped.
//! 6. Numbers must be **integers** that fit in `i64` or `u64`. Floats, exponent
//!    notation and out-of-range values are rejected with an error rather than
//!    silently reformatted. Money is therefore carried as integer minor units or
//!    as a decimal string, never as `f64`.
//! 7. Nesting is bounded to [`MAX_DEPTH`] so that a hostile document cannot
//!    overflow the stack during signing.
//!
//! These rules are verified against shared fixtures in
//! `conformance/vectors.json`, consumed by the Rust, Python and JS test suites.

use std::fmt::Write as _;

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

/// The object key removed (at every depth) before signing/verifying.
pub const SIGNATURE_FIELD: &str = "signature";

/// Maximum object/array nesting accepted while canonicalizing.
pub const MAX_DEPTH: usize = 64;

/// Ways canonicalization can fail.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CanonicalError {
    /// The root of a signing payload was not a JSON object.
    #[error("canonical payload root must be a JSON object, found {0}")]
    RootNotObject(&'static str),

    /// A float (or exponent-form) number appeared in a signing payload.
    #[error(
        "non-integer number `{0}` in canonical payload: signing payloads admit integers only \
         (carry money as integer minor units, never as a float)"
    )]
    NonIntegerNumber(String),

    /// An integer did not fit in `i64`/`u64`.
    #[error("number `{0}` does not fit in i64 or u64, which canonical payloads require")]
    NumberOutOfRange(String),

    /// The value nested deeper than [`MAX_DEPTH`].
    #[error("canonical payload nests deeper than {MAX_DEPTH} levels")]
    TooDeep,

    /// The value could not be serialized to JSON at all.
    #[error("value could not be serialized to JSON for canonicalization: {0}")]
    Serialize(String),
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Append `s` to `out` as a canonical JSON string literal (rule 5).
fn escape_into(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                // `write!` to a String cannot fail.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_value(out: &mut String, value: &Value, depth: usize) -> Result<(), CanonicalError> {
    if depth > MAX_DEPTH {
        return Err(CanonicalError::TooDeep);
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                let _ = write!(out, "{i}");
            } else if let Some(u) = n.as_u64() {
                let _ = write!(out, "{u}");
            } else if n.is_f64() {
                return Err(CanonicalError::NonIntegerNumber(n.to_string()));
            } else {
                return Err(CanonicalError::NumberOutOfRange(n.to_string()));
            }
        }
        Value::String(s) => escape_into(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Collect and sort explicitly: this must not depend on whether
            // serde_json was built with the `preserve_order` feature.
            let mut keys: Vec<&str> = map
                .keys()
                .map(String::as_str)
                .filter(|k| *k != SIGNATURE_FIELD)
                .collect();
            // `&str` Ord is byte order, which for UTF-8 equals code point order.
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_into(out, key);
                out.push(':');
                // `get` cannot be None: `key` came from this map's own keys.
                let child = map
                    .get(*key)
                    .ok_or(CanonicalError::RootNotObject("object"))?;
                write_value(out, child, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Canonicalize any JSON value (no root-object requirement).
///
/// Useful for hashing sub-structures; signing should use
/// [`canonical_payload`] or [`canonical_object`], which enforce rule 1.
pub fn canonical_string(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(&mut out, value, 0)?;
    Ok(out)
}

/// Canonicalize a JSON object intended to be signed (rules 1–7).
pub fn canonical_object(value: &Value) -> Result<String, CanonicalError> {
    if !value.is_object() {
        return Err(CanonicalError::RootNotObject(kind_of(value)));
    }
    canonical_string(value)
}

/// Serialize `obj` to JSON and produce the exact bytes to be signed.
///
/// Serialization failure is reported, never papered over (upstream signed the
/// payload `null` in that case).
pub fn canonical_payload<T: Serialize>(obj: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = serde_json::to_value(obj).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    Ok(canonical_object(&value)?.into_bytes())
}

/// Like [`canonical_payload`] but returns the payload as a `String`.
pub fn canonical_payload_string<T: Serialize>(obj: &T) -> Result<String, CanonicalError> {
    let value = serde_json::to_value(obj).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    canonical_object(&value)
}

/// BLAKE-free convenience: SHA-256 over the canonical payload, hex encoded.
///
/// Used as a content hash for signed structures (e.g. results, receipts).
pub fn payload_digest_hex<T: Serialize>(obj: &T) -> Result<String, CanonicalError> {
    use sha2::{Digest, Sha256};
    let bytes = canonical_payload(obj)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: &Value) -> String {
        canonical_string(v).expect("canonicalization should succeed")
    }

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        assert_eq!(canon(&json!({"b": 1, "a": 2})), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn drops_signature_at_every_depth() {
        let v = json!({
            "outer": 1,
            "signature": "deadbeef",
            "nested": { "inner": true, "signature": "cafe" },
            "list": [ { "signature": "x", "kept": 1 } ]
        });
        assert_eq!(
            canon(&v),
            r#"{"list":[{"kept":1}],"nested":{"inner":true},"outer":1}"#
        );
    }

    #[test]
    fn keeps_non_ascii_raw_and_escapes_controls() {
        // Chinese text stays raw UTF-8 (matches Python ensure_ascii=False and JS).
        let v = json!({ "n": "智能体宇宙" });
        assert_eq!(canon(&v), "{\"n\":\"智能体宇宙\"}");

        let v = json!({ "s": "a\"b\\c\nd\te\u{1}f" });
        assert_eq!(canon(&v), r#"{"s":"a\"b\\c\nd\te\u0001f"}"#);
    }

    #[test]
    fn rejects_floats_so_100_and_100_0_cannot_diverge() {
        let err = canonical_string(&json!({ "amount": 100.0 })).unwrap_err();
        assert!(
            matches!(err, CanonicalError::NonIntegerNumber(_)),
            "got {err:?}"
        );
        let err = canonical_string(&json!({ "amount": 1.5 })).unwrap_err();
        assert!(
            matches!(err, CanonicalError::NonIntegerNumber(_)),
            "got {err:?}"
        );
        // Exponent form is a float in serde_json and must also be refused.
        let err = canonical_string(&json!({ "amount": 1e2 })).unwrap_err();
        assert!(
            matches!(err, CanonicalError::NonIntegerNumber(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn accepts_full_integer_range_including_beyond_js_safe_range() {
        // 2^53 + 1 is not representable exactly by a JS double, which is exactly
        // why the JS SDK must parse canonical numbers without going through
        // Number. Encoding it here proves the format itself carries it.
        let big: i64 = (1i64 << 53) + 1;
        assert_eq!(canon(&json!({ "n": big })), format!("{{\"n\":{big}}}"));
        assert_eq!(
            canon(&json!({ "n": u64::MAX })),
            format!("{{\"n\":{}}}", u64::MAX)
        );
    }

    #[test]
    fn rejects_non_object_root_for_signing_payloads() {
        let err = canonical_object(&json!([1, 2, 3])).unwrap_err();
        assert_eq!(err, CanonicalError::RootNotObject("array"));
        let err = canonical_object(&json!("hi")).unwrap_err();
        assert_eq!(err, CanonicalError::RootNotObject("string"));
    }

    #[test]
    fn rejects_hostile_nesting_instead_of_overflowing_the_stack() {
        let mut v = json!(1);
        for _ in 0..(MAX_DEPTH + 10) {
            v = json!({ "n": v });
        }
        let err = canonical_string(&v).unwrap_err();
        assert_eq!(err, CanonicalError::TooDeep);
    }

    #[test]
    fn empty_object_and_null_values_are_stable() {
        assert_eq!(canon(&json!({})), "{}");
        assert_eq!(canon(&json!({ "a": null })), r#"{"a":null}"#);
    }

    #[test]
    fn serialization_failure_is_an_error_not_a_null_signature() {
        // A type whose Serialize impl always fails must NOT yield `null`.
        struct Boom;
        impl Serialize for Boom {
            fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("boom"))
            }
        }
        let err = canonical_payload(&Boom).unwrap_err();
        assert!(matches!(err, CanonicalError::Serialize(_)), "got {err:?}");
    }
}
