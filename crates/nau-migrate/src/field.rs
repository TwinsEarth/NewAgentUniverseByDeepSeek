//! Reading fields out of an upstream record without ever guessing silently.
//!
//! Upstream's artifacts are loosely shaped: the audit records an `AgentCard` with
//! 21 public fields (`marketplace/agent_card.rs:60-100`), a `TaskSpec` whose
//! `validate()` checks fields other than the six it documents
//! (`marketplace/task.rs:78`), and a ledger written from an in-memory
//! `HashMap<String, f64>`. A migration therefore has to *find* fields by more than
//! one name. Each helper here takes the list of names to try, in priority order,
//! and every failure names the field and the JSON kind it actually found.

use nau_core::{Did, Money};
use serde_json::Value;

use crate::amount::{amount_from_decimal, AmountDefect};
use crate::error::MigrateError;
use crate::rawjson::{self, RawScalar};
use crate::warning::{Defect, Finding};

/// The JSON kind of a value, for error messages.
pub fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The name and value of the first field present from `names`.
///
/// An explicit JSON `null` counts as present, so that a *required* field holding
/// `null` is reported as the wrong type rather than as absent.
pub fn find<'v>(value: &'v Value, names: &[&str]) -> Option<(String, &'v Value)> {
    let object = value.as_object()?;
    names
        .iter()
        .find_map(|name| object.get(*name).map(|found| ((*name).to_string(), found)))
}

/// Like [`find`], but an explicit JSON `null` counts as absent.
///
/// `"description": null` is the normal way to say "no description", so optional
/// fields treat it that way instead of failing the record.
pub fn find_present<'v>(value: &'v Value, names: &[&str]) -> Option<(String, &'v Value)> {
    find(value, names).filter(|(_, found)| !found.is_null())
}

/// A required string field.
pub fn required_str(
    source: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<String, Defect> {
    match find(value, names) {
        Some((name, found)) => match found.as_str() {
            Some(text) if !text.trim().is_empty() => Ok(text.to_string()),
            Some(text) => Err(Defect::new(
                Finding::InvalidFieldValue,
                source,
                format!("field `{name}` is present but empty (`{text}`)"),
            )),
            None => Err(Defect::new(
                Finding::InvalidFieldType,
                source,
                format!(
                    "field `{name}` must be a string, found {} ({found})",
                    kind_of(found)
                ),
            )),
        },
        None => Err(Defect::new(
            Finding::MissingField,
            source,
            format!("required field `{}` is missing", names[0]),
        )),
    }
}

/// An optional string field.
pub fn optional_str(
    source: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<Option<String>, Defect> {
    match find_present(value, names) {
        None => Ok(None),
        Some((name, found)) => match found.as_str() {
            Some(text) => Ok(Some(text.to_string())),
            None => Err(Defect::new(
                Finding::InvalidFieldType,
                source,
                format!(
                    "field `{name}` must be a string, found {} ({found})",
                    kind_of(found)
                ),
            )),
        },
    }
}

/// A required DID field.
///
/// Both `did:aip:` (upstream) and `did:nau:` (this project) parse; the identifier
/// is kept exactly as it was written.
pub fn required_did(
    source: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<Did, Defect> {
    let text = required_str(source, value, names)?;
    parse_did(source, names[0], &text)
}

/// An optional DID field.
pub fn optional_did(
    source: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<Option<Did>, Defect> {
    match optional_str(source, value, names)? {
        Some(text) => Ok(Some(parse_did(source, names[0], &text)?)),
        None => Ok(None),
    }
}

/// Parse one DID, reporting which field it came from.
pub fn parse_did(source: &str, field: &str, text: &str) -> std::result::Result<Did, Defect> {
    Did::parse(text).map_err(|err| {
        Defect::new(
            Finding::InvalidDid,
            source,
            format!("field `{field}` = `{text}` is not a DID: {err}"),
        )
    })
}

/// An optional unsigned-integer field (a timestamp, an expiry, a nonce).
pub fn optional_u64(
    source: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<Option<u64>, Defect> {
    match find_present(value, names) {
        None => Ok(None),
        Some((name, found)) => found.as_u64().map(Some).ok_or_else(|| {
            Defect::new(
                Finding::InvalidFieldType,
                source,
                format!(
                    "field `{name}` must be a non-negative integer, found {} ({found})",
                    kind_of(found)
                ),
            )
        }),
    }
}

/// A field that must be an array of strings; `None` when it is absent.
pub fn string_list(
    source: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<Option<Vec<String>>, Defect> {
    match find_present(value, names) {
        None => Ok(None),
        Some((name, found)) => {
            let items = found.as_array().ok_or_else(|| {
                Defect::new(
                    Finding::InvalidFieldType,
                    source,
                    format!(
                        "field `{name}` must be an array, found {} ({found})",
                        kind_of(found)
                    ),
                )
            })?;
            let mut out = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                match item.as_str() {
                    Some(text) => out.push(text.to_string()),
                    None => {
                        return Err(Defect::new(
                            Finding::InvalidFieldType,
                            source,
                            format!(
                                "field `{name}[{index}]` must be a string, found {} ({item})",
                                kind_of(item)
                            ),
                        ))
                    }
                }
            }
            Ok(Some(out))
        }
    }
}

/// Read a money field **verbatim from the source text** and convert it exactly.
///
/// Returns `Ok(None)` when none of `names` is present. The first name is the one
/// reported in errors, so it must be the canonical spelling.
///
/// # Errors
///
/// A [`Defect`] naming the field when the value is not a decimal number, needs
/// more than six decimal places, or is out of range.
pub fn money_field(
    source: &str,
    text: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<Option<Money>, Defect> {
    Ok(money_field_with_literal(source, text, value, names)?.map(|(money, _)| money))
}

/// Like [`money_field`], but also returns the verbatim decimal literal it read.
///
/// The literal is what makes "we did not round" auditable after the fact: the plan
/// keeps both the exact text upstream wrote and the minor-unit value it became.
///
/// # Errors
///
/// As [`money_field`].
pub fn money_field_with_literal(
    source: &str,
    text: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<Option<(Money, String)>, Defect> {
    let Some((name, found)) = find_present(value, names) else {
        return Ok(None);
    };
    let literal = match rawjson::top_level_scalar(text, &name) {
        Ok(Some(RawScalar::Number(literal))) => {
            if !found.is_number() {
                return Err(Defect::new(
                    Finding::RawLiteralUnavailable,
                    source,
                    format!(
                        "field `{name}` reads as the number `{literal}` on disk but parsed as {} \
                         ({found}); refusing to guess",
                        kind_of(found)
                    ),
                ));
            }
            literal
        }
        Ok(Some(RawScalar::Str(literal))) => {
            if !found.is_string() {
                return Err(Defect::new(
                    Finding::RawLiteralUnavailable,
                    source,
                    format!(
                        "field `{name}` reads as the string `{literal}` on disk but parsed as {} \
                         ({found}); refusing to guess",
                        kind_of(found)
                    ),
                ));
            }
            literal
        }
        Ok(None) => {
            return Err(Defect::new(
                Finding::InvalidFieldType,
                source,
                format!(
                "field `{name}` must be a decimal number or a decimal string, found {} ({found})",
                kind_of(found)
            ),
            ))
        }
        Err(error) => {
            return Err(Defect::new(
                Finding::RawLiteralUnavailable,
                source,
                format!("field `{name}` could not be read verbatim: {error}"),
            ))
        }
    };
    let money = amount_from_decimal(source, &name, &literal)
        .map_err(|err| defect_from_amount(source, &err))?;
    Ok(Some((money, literal)))
}

/// Turn an amount error into a rejection that keeps its full explanation.
pub fn defect_from_amount(source: &str, err: &MigrateError) -> Defect {
    let code = match AmountDefect::of(err) {
        Some(AmountDefect::NotANumber) => Finding::AmountNotANumber,
        Some(AmountDefect::NotExact) => Finding::AmountNotExact,
        Some(AmountDefect::OutOfRange) => Finding::AmountOutOfRange,
        None => Finding::InvalidFieldValue,
    };
    Defect::new(code, source, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEXT: &str = r#"{"amount":1e-3,"stake":"100","name":"Alice","did":"did:aip:34750f98bd59fcfc","ts":1700000000,"capabilities":["a","b"],"note":null}"#;

    fn parsed() -> Value {
        serde_json::from_str(TEXT).expect("fixture is valid JSON")
    }

    #[test]
    fn money_is_read_from_the_verbatim_text_and_not_from_the_parsed_float() {
        let value = parsed();
        let amount = money_field("t.json", TEXT, &value, &["amount"])
            .expect("converts")
            .expect("present");
        assert_eq!(amount.minor(), 1_000, "1e-3 is exactly 1000 minor units");
        let stake = money_field("t.json", TEXT, &value, &["stake"])
            .expect("converts")
            .expect("present");
        assert_eq!(stake.minor(), 100_000_000);
        assert_eq!(
            money_field("t.json", TEXT, &value, &["missing"]).expect("ok"),
            None
        );
    }

    #[test]
    fn an_unrepresentable_amount_is_a_defect_naming_the_field() {
        let text = r#"{"amount":0.0000001}"#;
        let value: Value = serde_json::from_str(text).expect("valid JSON");
        let defect =
            money_field("ledger.jsonl", text, &value, &["amount"]).expect_err("must be refused");
        assert_eq!(defect.code, Finding::AmountNotExact);
        assert!(defect.detail.contains("ledger.jsonl"), "{}", defect.detail);
        assert!(defect.detail.contains("amount"), "{}", defect.detail);
        assert!(defect.detail.contains("0.0000001"), "{}", defect.detail);
    }

    #[test]
    fn a_wrongly_typed_money_field_says_what_it_found_instead() {
        let text = r#"{"amount":true}"#;
        let value: Value = serde_json::from_str(text).expect("valid JSON");
        let defect = money_field("t.json", text, &value, &["amount"]).expect_err("must be refused");
        assert_eq!(defect.code, Finding::InvalidFieldType);
        assert!(defect.detail.contains("boolean"), "{}", defect.detail);
    }

    #[test]
    fn strings_dids_integers_and_lists_are_read_with_aliases() {
        let value = parsed();
        assert_eq!(
            required_str("t", &value, &["name"]).expect("name"),
            "Alice".to_string()
        );
        assert_eq!(
            required_did("t", &value, &["did", "agent_id"])
                .expect("did")
                .as_str(),
            "did:aip:34750f98bd59fcfc"
        );
        assert_eq!(
            optional_u64("t", &value, &["ts"]).expect("ts"),
            Some(1_700_000_000)
        );
        assert_eq!(
            string_list("t", &value, &["capabilities", "skills"]).expect("caps"),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(optional_str("t", &value, &["note"]).expect("note"), None);
        // `names[0]` is the field named in a missing-field error.
        let defect = required_str("t", &value, &["goal", "objective"]).expect_err("missing");
        assert_eq!(defect.code, Finding::MissingField);
        assert!(defect.detail.contains("`goal`"), "{}", defect.detail);
    }

    #[test]
    fn malformed_values_are_reported_with_their_kind() {
        let value = json!({ "capabilities": "text-generation", "ts": "later", "did": "nope" });
        let defect = string_list("t", &value, &["capabilities"]).expect_err("must be an array");
        assert!(defect.detail.contains("string"), "{}", defect.detail);
        assert!(optional_u64("t", &value, &["ts"]).is_err());
        let defect = required_did("t", &value, &["did"]).expect_err("not a DID");
        assert_eq!(defect.code, Finding::InvalidDid);
        assert_eq!(kind_of(&json!([])), "array");
    }
}
