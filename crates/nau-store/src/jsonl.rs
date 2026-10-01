//! The on-disk record format: one canonical JSON object per line.
//!
//! Every line written by this crate is a JSON object of the shape
//!
//! ```json
//! {"id":"did:nau:34750f98bd59fcfc","payload":{ … },"v":1}
//! ```
//!
//! * `v` is the schema marker ([`SCHEMA_VERSION`]). A line carrying a different
//!   marker is skipped on load with a warning instead of being misread.
//! * `id` is the dedupe key for *indexed* logs (`agents.jsonl`,
//!   `tasks.jsonl`): later records for the same key supersede earlier ones
//!   (last-write-wins). Append-only logs (`ledger.jsonl`) omit it.
//! * `payload` is the stored domain object. It is emitted in a canonical form —
//!   object keys sorted, no insignificant whitespace — so that the bytes on disk
//!   are a pure function of the value. That is what makes "what you load equals
//!   what you saved" checkable byte-for-byte, and it is the fix for upstream
//!   v2.5.6 defect #3, where the stored row was rebuilt from a raw request body
//!   (`skills.join(",")`, hardcoded `reputation: 0.0`, regenerated `created_at`).
//!
//! Ordering is enforced by [`sort_value`] rather than by relying on the JSON
//! library's map type: `serde_json::Map` is a `BTreeMap` by default but becomes
//! an insertion-ordered `IndexMap` if any crate in the same build turns on the
//! `preserve_order` feature, which would silently make the on-disk bytes depend
//! on build configuration and on field order.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema marker written into the `v` field of every record line.
pub const SCHEMA_VERSION: u32 = 1;

/// Hard cap on one serialized record, in bytes (8 MiB).
///
/// The same bound as the transport frame cap, so a value that can travel over
/// the wire can also be stored, and nothing larger can be used to exhaust disk
/// or heap. A record line longer than this is rejected *before* it is written.
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;

/// One decoded record line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// Schema marker; always [`SCHEMA_VERSION`] after a successful decode.
    pub v: u32,
    /// Dedupe key for indexed logs (`None` for append-only logs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The stored value, exactly as it was written.
    pub payload: Value,
}

/// Recursively rebuild `value` with object keys in ascending order.
///
/// Arrays keep their order (order is meaningful); only object key order is
/// normalised.
pub fn sort_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                if let Some(inner) = map.get(key) {
                    sorted.insert(key.clone(), sort_value(inner));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

/// Serialize `value` to canonical (key-sorted, whitespace-free) JSON bytes.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&sort_value(value))?)
}

/// Encode one record line (without the trailing newline).
///
/// Returns an error if the encoded record would exceed [`MAX_RECORD_BYTES`].
pub fn encode_record(id: Option<&str>, payload: &Value) -> Result<Vec<u8>> {
    let mut envelope = Map::new();
    envelope.insert("v".to_string(), Value::from(SCHEMA_VERSION));
    if let Some(id) = id {
        envelope.insert("id".to_string(), Value::from(id));
    }
    envelope.insert("payload".to_string(), payload.clone());
    let bytes = canonical_json_bytes(&Value::Object(envelope))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(NauError::Validation(format!(
            "record of {} bytes exceeds the {MAX_RECORD_BYTES}-byte cap",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Append one already-encoded record line, durably.
///
/// The line and its newline are written with a single `write_all` on a handle
/// opened in append mode, then `sync_data` is called. Nothing already in the
/// file is touched, so an interrupted append can only damage the final line —
/// which [`read_records`] tolerates.
///
/// If the file does not currently end with a newline, a crash left a partial
/// line behind; one newline is written first so that the new record starts on a
/// fresh line. Without that, the next record would be concatenated onto the torn
/// fragment and *both* would be unreadable.
pub fn append_line(path: &Path, line: &[u8]) -> Result<()> {
    if line.len() > MAX_RECORD_BYTES {
        return Err(NauError::Validation(format!(
            "record of {} bytes exceeds the {MAX_RECORD_BYTES}-byte cap",
            line.len()
        )));
    }
    let mut buffer = Vec::with_capacity(line.len() + 1);
    buffer.extend_from_slice(line);
    buffer.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    if !ends_with_newline(&mut file)? {
        file.write_all(b"\n")?;
    }
    file.write_all(&buffer)?;
    file.sync_data()?;
    Ok(())
}

/// True when `file` is empty or its final byte is a line feed.
fn ends_with_newline(file: &mut File) -> Result<bool> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(true);
    }
    file.seek(SeekFrom::Start(len - 1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}

/// Read every decodable record from `path`, in file order.
///
/// * A missing file is an empty log, not an error.
/// * A line that is not valid JSON, is not an object, has no `v`/`payload`, or
///   carries an unknown schema marker is **skipped with a warning**; this is
///   what a crash in the middle of an append leaves behind.
/// * More than `max_records` decodable records is a hard error
///   ([`NauError::Conflict`]), so a runaway log cannot exhaust memory.
pub fn read_records(path: &Path, max_records: usize) -> Result<Vec<Record>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(NauError::Io(err)),
    };

    let mut reader = BufReader::new(file);
    let mut buffer: Vec<u8> = Vec::new();
    let mut records: Vec<Record> = Vec::new();
    let mut line_no: u64 = 0;

    loop {
        buffer.clear();
        let read = reader.read_until(b'\n', &mut buffer)?;
        if read == 0 {
            break;
        }
        line_no += 1;
        let line = match std::str::from_utf8(&buffer) {
            Ok(line) => line.trim_end_matches(['\n', '\r']),
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    line = line_no,
                    error = %err,
                    "skipping record line that is not valid UTF-8"
                );
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match decode_record(line) {
            Ok(record) => {
                if records.len() >= max_records {
                    return Err(NauError::Conflict(format!(
                        "`{}` holds more than {max_records} records; compact it before loading",
                        path.display()
                    )));
                }
                records.push(record);
            }
            Err(reason) => {
                tracing::warn!(
                    path = %path.display(),
                    line = line_no,
                    reason = %reason,
                    "skipping unreadable record; a torn append must not fail the whole load"
                );
            }
        }
    }
    Ok(records)
}

/// Decode exactly one line, rejecting anything [`read_records`] would skip.
///
/// Every other read path deliberately tolerates a torn tail; the ledger journal
/// must not, because a skipped movement is a silent hole in the money (upstream
/// v2.8.2's watermark counted physical rows while its loader silently skipped
/// unparsable ones, so one skipped row permanently desynchronised the two). This
/// is the strict entry point: a caller that uses it turns "skipped with a warning"
/// into a typed error naming the line.
pub fn read_records_from_line(line: &str) -> Result<Record> {
    let trimmed = line.trim_end_matches(['\n', '\r']);
    decode_record(trimmed).map_err(|reason| {
        NauError::Validation(format!("journal line is not a readable record: {reason}"))
    })
}

/// Decode one line, describing (rather than hiding) why it was refused.
fn decode_record(line: &str) -> std::result::Result<Record, String> {
    let value: Value =
        serde_json::from_str(line).map_err(|err| format!("not valid JSON: {err}"))?;
    let Value::Object(mut map) = value else {
        return Err("record line is not a JSON object".to_string());
    };
    let version = map
        .get("v")
        .and_then(Value::as_u64)
        .ok_or_else(|| "record has no integer `v` schema marker".to_string())?;
    if version != u64::from(SCHEMA_VERSION) {
        return Err(format!(
            "unsupported schema marker v={version}, expected v={SCHEMA_VERSION}"
        ));
    }
    let payload = map
        .remove("payload")
        .ok_or_else(|| "record has no `payload` field".to_string())?;
    let id = match map.remove("id") {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) => Some(id),
        Some(other) => return Err(format!("record `id` must be a string, found `{other}`")),
    };
    Ok(Record {
        v: SCHEMA_VERSION,
        id,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encoding_is_a_pure_function_of_the_value() {
        let a = json!({ "z": 1, "a": { "y": [1, 2, {"b": true, "a": null}], "b": "x" } });
        // Same content, different insertion order: byte-identical output.
        let b = json!({ "a": { "b": "x", "y": [1, 2, {"a": null, "b": true}] }, "z": 1 });
        assert_eq!(
            canonical_json_bytes(&a).expect("canonical"),
            canonical_json_bytes(&b).expect("canonical")
        );
        let line = encode_record(Some("id-1"), &a).expect("encode");
        let text = String::from_utf8(line).expect("utf8");
        assert_eq!(
            text,
            r#"{"id":"id-1","payload":{"a":{"b":"x","y":[1,2,{"a":null,"b":true}]},"z":1},"v":1}"#
        );
    }

    #[test]
    fn an_oversized_record_is_refused_before_it_is_written() {
        let huge = json!({ "blob": "x".repeat(MAX_RECORD_BYTES + 1) });
        let err = encode_record(None, &huge).expect_err("must be refused");
        assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn records_with_a_foreign_schema_marker_are_skipped_not_misread() {
        let err = decode_record(r#"{"payload":{"a":1},"v":999}"#).expect_err("unknown marker");
        assert!(err.contains("unsupported schema marker"), "{err}");
        let err = decode_record("{\"v\":1,\"payload\":").expect_err("torn tail");
        assert!(err.contains("not valid JSON"), "{err}");
        assert!(
            decode_record(r#"[1,2,3]"#).is_err(),
            "arrays are not records"
        );
        assert!(decode_record(r#"{"v":1}"#).is_err(), "payload is mandatory");
        let ok = decode_record(r#"{"id":"a","payload":{"k":1},"v":1}"#).expect("valid");
        assert_eq!(ok.id.as_deref(), Some("a"));
        assert_eq!(ok.payload, json!({ "k": 1 }));
    }
}
