//! Reading an operation and its arguments out of a PMB payload.
//!
//! A system plugin is handed a [`serde_json::Value`] and must answer with one. Every
//! way that can go wrong is a typed refusal here rather than a panic or a silently
//! absent field: a T0 plugin runs in the host's address space, so "the payload was
//! not what I expected" must not be able to take the host down, and a missing field
//! must not read as an empty string.
//!
//! The answer envelope is uniform across the four plugins
//! (`{"plugin", "op", "ok": true, …}`) so that a caller can log what answered
//! without knowing which plugin it asked.

use std::fmt::Display;

use serde_json::{Map, Value};

use nau_plugin::{PluginError, Result};

/// The key a request uses to name its operation.
pub const OP_FIELD: &str = "op";

/// Error code: the payload was not a JSON object.
pub const CODE_NOT_OBJECT: &str = "abi_payload_not_object";
/// Error code: a required field is absent.
pub const CODE_MISSING_FIELD: &str = "abi_missing_field";
/// Error code: a field is present but has the wrong type.
pub const CODE_FIELD_TYPE: &str = "abi_field_type";
/// Error code: the operation is not one this plugin implements.
pub const CODE_UNKNOWN_OPERATION: &str = "abi_unknown_operation";

/// Build a protocol refusal: a [`PluginError::Runtime`] whose message begins with
/// `code`, so a caller can branch on the code without matching prose.
#[must_use]
pub fn protocol(code: &str, detail: impl Display) -> PluginError {
    PluginError::Runtime(format!("{code}: {detail}"))
}

/// The payload as an object.
///
/// # Errors
///
/// [`CODE_NOT_OBJECT`] when the payload is an array, a string, a number, a boolean
/// or null. The message names the kind it found rather than echoing the value: a
/// plugin's error string is logged, and an unbounded echo of caller-supplied JSON
/// into a log is how a log becomes an attack surface.
pub fn object(payload: &Value) -> Result<&Map<String, Value>> {
    payload.as_object().ok_or_else(|| {
        protocol(
            CODE_NOT_OBJECT,
            format!(
                "a request payload must be a JSON object, found {}",
                kind_of(payload)
            ),
        )
    })
}

/// A short name for a JSON value's kind, for messages that must stay small.
#[must_use]
pub fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// The operation name a request carries.
///
/// # Errors
///
/// [`CODE_MISSING_FIELD`] or [`CODE_FIELD_TYPE`].
pub fn operation(payload: &Value) -> Result<&str> {
    string_field(payload, OP_FIELD)
}

/// A required string field.
///
/// # Errors
///
/// [`CODE_MISSING_FIELD`] when the key is absent, [`CODE_FIELD_TYPE`] when it is not
/// a string.
pub fn string_field<'a>(payload: &'a Value, key: &str) -> Result<&'a str> {
    let value = field(payload, key)?;
    value.as_str().ok_or_else(|| {
        protocol(
            CODE_FIELD_TYPE,
            format!("`{key}` must be a string, found {}", kind_of(value)),
        )
    })
}

/// A required field of any type.
///
/// # Errors
///
/// [`CODE_MISSING_FIELD`] when the key is absent.
pub fn field<'a>(payload: &'a Value, key: &str) -> Result<&'a Value> {
    object(payload)?
        .get(key)
        .ok_or_else(|| protocol(CODE_MISSING_FIELD, format!("a request must carry `{key}`")))
}

/// An optional string field: absent and `null` both mean "not supplied".
///
/// # Errors
///
/// [`CODE_FIELD_TYPE`] when the key is present and is neither a string nor null.
pub fn optional_string(payload: &Value, key: &str) -> Result<Option<String>> {
    match object(payload)?.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(other) => Err(protocol(
            CODE_FIELD_TYPE,
            format!("`{key}` must be a string, found {}", kind_of(other)),
        )),
    }
}

/// A required array of strings.
///
/// # Errors
///
/// [`CODE_MISSING_FIELD`] when the key is absent, [`CODE_FIELD_TYPE`] when it is not
/// an array of strings.
pub fn string_array(payload: &Value, key: &str) -> Result<Vec<String>> {
    let value = field(payload, key)?;
    let items = value.as_array().ok_or_else(|| {
        protocol(
            CODE_FIELD_TYPE,
            format!("`{key}` must be an array, found {}", kind_of(value)),
        )
    })?;
    items
        .iter()
        .map(|item| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                protocol(
                    CODE_FIELD_TYPE,
                    format!(
                        "every entry of `{key}` must be a string, found {}",
                        kind_of(item)
                    ),
                )
            })
        })
        .collect()
}

/// The refusal for an operation this plugin does not implement.
///
/// The known set is listed, so a caller that mistyped learns the vocabulary instead
/// of guessing — the same rule the kernel applies to an unknown capability name.
#[must_use]
pub fn unknown_operation(plugin: &str, op: &str, known: &[&str]) -> PluginError {
    protocol(
        CODE_UNKNOWN_OPERATION,
        format!(
            "`{plugin}` does not implement `{op}`; it implements {}",
            known.join(", ")
        ),
    )
}

/// The common answer envelope: `{"plugin", "op", "ok": true, …fields}`.
///
/// An object `fields` is merged at the top level; anything else is placed under
/// `result`, so the envelope's own keys cannot be overwritten by an answer.
#[must_use]
pub fn answer(plugin: &str, op: &str, fields: Value) -> Value {
    // The answer's own fields go in first and the envelope's keys last, so an answer
    // cannot claim `ok: false` or a different plugin name: a refusal is an `Err`, and
    // a value that says `ok: true` must be one.
    let mut map = match fields {
        Value::Object(extra) => extra,
        other => {
            let mut wrapper = Map::new();
            wrapper.insert("result".to_string(), other);
            wrapper
        }
    };
    map.insert("plugin".to_string(), Value::String(plugin.to_string()));
    map.insert("op".to_string(), Value::String(op.to_string()));
    map.insert("ok".to_string(), Value::Bool(true));
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_non_object_payload_is_refused_and_names_the_kind() {
        let err = operation(&json!([1, 2, 3])).expect_err("must be refused");
        assert!(err.to_string().contains(CODE_NOT_OBJECT), "{err}");
        assert!(err.to_string().contains("an array"), "{err}");
    }

    #[test]
    fn a_missing_field_is_refused_rather_than_read_as_empty() {
        let err = operation(&json!({})).expect_err("must be refused");
        assert!(err.to_string().contains(CODE_MISSING_FIELD), "{err}");
        assert!(err.to_string().contains("`op`"), "{err}");
    }

    #[test]
    fn a_field_of_the_wrong_type_is_refused() {
        let err = operation(&json!({ "op": 7 })).expect_err("must be refused");
        assert!(err.to_string().contains(CODE_FIELD_TYPE), "{err}");
    }

    #[test]
    fn an_optional_field_treats_null_as_absent() {
        assert_eq!(
            optional_string(&json!({ "a": null }), "a").expect("null is absent"),
            None
        );
        assert_eq!(optional_string(&json!({}), "a").expect("absent"), None);
        assert_eq!(
            optional_string(&json!({ "a": "x" }), "a").expect("present"),
            Some("x".to_string())
        );
        assert!(optional_string(&json!({ "a": 1 }), "a").is_err());
    }

    #[test]
    fn a_string_array_refuses_a_non_string_entry() {
        assert_eq!(
            string_array(&json!({ "caps": ["a", "b"] }), "caps").expect("ok"),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(string_array(&json!({ "caps": ["a", 2] }), "caps").is_err());
        assert!(string_array(&json!({ "caps": "a" }), "caps").is_err());
    }

    #[test]
    fn the_answer_envelope_cannot_be_overwritten_by_its_fields() {
        let value = answer("io.example.a", "op", json!({ "ok": false, "x": 1 }));
        assert_eq!(value["ok"], json!(true), "the envelope wins");
        assert_eq!(value["x"], json!(1));
        assert_eq!(value["plugin"], json!("io.example.a"));

        let wrapped = answer("io.example.a", "op", json!([1]));
        assert_eq!(wrapped["result"], json!([1]));
    }

    #[test]
    fn every_protocol_code_is_prefixed_on_the_message() {
        let err = unknown_operation("io.example.a", "nope", &["one", "two"]);
        let text = err.to_string();
        assert!(text.contains(CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("one, two"), "{text}");
    }
}
