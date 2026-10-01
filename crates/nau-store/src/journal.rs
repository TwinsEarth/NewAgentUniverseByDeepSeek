//! Hash-chained, anchored ledger journal.
//!
//! # Why this module exists
//!
//! Upstream `agent-universe` v2.8.2 has *no* integrity on its persisted journal:
//! `(seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)` — no hash
//! chain, no signature, no checksum, no trigger and no constraint — while
//! `independent_audit` documents itself as trusting only that journal. Anyone who
//! can write the file can INSERT a `Deposited` row and **both** the restart and
//! the "independent" audit report `passed: true, conserved: true` over money that
//! was invented.
//!
//! The journal written by this module is chained and anchored:
//!
//! ```text
//! line i  = {"v":2,"seq":i,"prev":"<digest of line i-1>","hash":"<digest>","payload":{…}}
//! digest  = SHA-256( "nau-ledger-journal-v1\0" ‖ len(prev) ‖ prev ‖ len(canonical payload) ‖ canonical payload )
//! ```
//!
//! and the head of that chain is *also* recorded in `meta.json` (key
//! [`LEDGER_ANCHOR_KEY`]), a different file written by a different operation.
//! That anchor is what turns the largest attack — rewrite the whole journal
//! consistently — from undetectable into a reported break.
//!
//! ## What is detected, and what is not
//!
//! Detected, each as a typed [`JournalBreak`] naming the first offending
//! position: a payload edited in place; a record deleted, duplicated or
//! reordered; a forged record appended without the hash rule; and a whole-file
//! rewrite that leaves the anchor stale.
//!
//! **Not** detected: an attacker who rewrites the journal file *and* the anchor
//! in `meta.json`, consistently. This is tamper-**evidence**, not
//! tamper-proofness: the store can prove a history was not edited after the fact,
//! not that it is the history honest nodes saw. Detecting a fully consistent
//! forgery needs a witness this process does not have — a signature by a key the
//! writer lacks, or a hash published elsewhere. That limitation is stated in the
//! crate documentation and in the release notes rather than papered over.
//!
//! ## `read_records` tolerance does not apply here
//!
//! [`crate::jsonl::read_records`] deliberately *skips* a line it cannot decode, so
//! that a crash mid-append does not kill the whole load. For the journal that
//! behaviour is a defect: a silently skipped movement is a silent hole in the
//! money. [`load_journal`] is therefore strict — an undecodable line is reported
//! with its 1-based line number, and the reported set of records is never "the
//! ones that happened to parse".

use std::collections::HashSet;
use std::path::Path;

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::jsonl::{self, canonical_json_bytes, MAX_RECORD_BYTES};

/// Domain-separation tag for the journal chain digest.
///
/// Versioned. Changing it changes every digest, so it must change only with the
/// on-disk format and the anchor's [`LEDGER_ANCHOR_KEY`] value.
pub const JOURNAL_DOMAIN: &[u8] = b"nau-ledger-journal-v1\0";

/// The digest the first recorded journal entry chains onto.
pub const GENESIS_DIGEST: &str = "genesis";

/// `meta.json` key holding the journal anchor.
pub const LEDGER_ANCHOR_KEY: &str = "ledger.anchor";

/// Schema marker of a **linked** journal line.
///
/// A plain (unlinked) record written by an older build carries
/// [`crate::jsonl::SCHEMA_VERSION`]; a linked one carries this. The loader accepts
/// both so that an upgrade does not brick an existing data directory, and reports
/// which it found.
pub const LINKED_SCHEMA_VERSION: u32 = 2;

/// The head of a journal, recorded beside it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct JournalAnchor {
    /// Digest of the last record, or [`GENESIS_DIGEST`] when the journal is empty.
    pub head: String,
    /// How many records the anchor covers.
    pub count: usize,
}

impl Default for JournalAnchor {
    fn default() -> Self {
        Self::genesis()
    }
}

impl JournalAnchor {
    /// The anchor of an empty journal.
    pub fn genesis() -> Self {
        Self {
            head: GENESIS_DIGEST.to_string(),
            count: 0,
        }
    }

    /// True when this anchor covers no records.
    pub fn is_genesis(&self) -> bool {
        self.count == 0 && self.head == GENESIS_DIGEST
    }

    /// Reject an anchor that this crate could not have written.
    pub fn validate(&self) -> Result<()> {
        if self.count == 0 {
            if self.head == GENESIS_DIGEST {
                return Ok(());
            }
            return Err(NauError::Validation(format!(
                "journal anchor claims 0 records but head `{}`; an empty journal's head is \
                 `{GENESIS_DIGEST}`",
                self.head
            )));
        }
        if self.head.len() != 64 || !self.head.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(NauError::Validation(format!(
                "journal anchor head `{}` is not a 64-character hex SHA-256 digest",
                self.head
            )));
        }
        Ok(())
    }

    /// The anchor for a journal of `count` records whose last digest is `head`.
    pub fn of(head: impl Into<String>, count: usize) -> Self {
        Self {
            head: head.into(),
            count,
        }
    }
}

/// One line of a linked journal, as it is stored.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LinkedRecord {
    /// Schema marker; always [`LINKED_SCHEMA_VERSION`].
    pub v: u32,
    /// Position in the journal. Zero-based and dense.
    pub seq: usize,
    /// Digest of the preceding record ([`GENESIS_DIGEST`] for the first).
    pub prev: String,
    /// Digest of `(prev, canonical payload)`.
    pub hash: String,
    /// The recorded movement.
    pub payload: Value,
}

/// One record as the loader found it.
#[derive(Clone, PartialEq, Debug)]
pub struct JournalRecord {
    /// Position, zero-based.
    pub seq: usize,
    /// Digest this record carries.
    pub hash: String,
    /// Digest of its predecessor.
    pub prev: String,
    /// The recorded movement, exactly as stored.
    pub payload: Value,
}

/// What kind of integrity failure the loader found.
///
/// Every variant carries the position it was found at: "the journal is broken"
/// without a position is not an audit finding.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum JournalBreakKind {
    /// A line could not be decoded at all. `seq` is the 1-based line number.
    UnreadableRecord,
    /// The record's `seq` is not the position it occupies: deleted, inserted or
    /// reordered.
    SequenceMismatch,
    /// Two records claim the same `seq`.
    DuplicateSequence,
    /// `prev` is not the digest of the preceding record.
    PreviousHashMismatch,
    /// The record's digest does not cover its payload.
    DigestMismatch,
    /// The anchor in `meta.json` disagrees with the journal's head.
    AnchorMismatch,
    /// The anchor's record count disagrees with the journal's length.
    AnchorCountMismatch,
    /// The journal holds records but no anchor was ever recorded, so nothing
    /// can corroborate them.
    MissingAnchor,
    /// The anchor describes a chain but the records carry no chain fields, i.e.
    /// the chain was stripped rather than absent.
    StrippedChain,
}

impl JournalBreakKind {
    /// A stable, machine-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            JournalBreakKind::UnreadableRecord => "unreadable_record",
            JournalBreakKind::SequenceMismatch => "sequence_mismatch",
            JournalBreakKind::DuplicateSequence => "duplicate_sequence",
            JournalBreakKind::PreviousHashMismatch => "previous_hash_mismatch",
            JournalBreakKind::DigestMismatch => "digest_mismatch",
            JournalBreakKind::AnchorMismatch => "anchor_mismatch",
            JournalBreakKind::AnchorCountMismatch => "anchor_count_mismatch",
            JournalBreakKind::MissingAnchor => "missing_anchor",
            JournalBreakKind::StrippedChain => "stripped_chain",
        }
    }
}

/// The first place the persisted journal stopped being trustworthy.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct JournalBreak {
    /// The **first** offending position. Zero-based for a record; for
    /// [`JournalBreakKind::UnreadableRecord`] it is the 1-based *line* number,
    /// because there is no record to name.
    pub seq: u64,
    /// What kind of break it is.
    pub kind: JournalBreakKind,
    /// A human-readable description that always contains the position.
    pub detail: String,
}

impl JournalBreak {
    /// The sentinel used by a break that concerns the file as a whole.
    pub const FILE_LEVEL: u64 = u64::MAX;

    /// True when this break is about the file as a whole.
    pub fn is_file_level(&self) -> bool {
        self.seq == Self::FILE_LEVEL
    }

    /// Build a break, formatting the detail from the value that will be reported
    /// so the prose and the field cannot drift.
    pub fn new(seq: u64, kind: JournalBreakKind) -> Self {
        let at = if seq == Self::FILE_LEVEL {
            "the file as a whole".to_string()
        } else {
            format!("seq {seq}")
        };
        let detail = match &kind {
            JournalBreakKind::UnreadableRecord => format!(
                "journal line {seq} cannot be decoded; refusing to skip it (a skipped movement \
                 is a silent hole in the money)"
            ),
            JournalBreakKind::SequenceMismatch => {
                format!("journal chain broken at {at}: the record does not carry its own position")
            }
            JournalBreakKind::DuplicateSequence => {
                format!("journal chain broken at {at}: this sequence number appears more than once")
            }
            JournalBreakKind::PreviousHashMismatch => format!(
                "journal chain broken at {at}: `prev` does not match the preceding record's \
                 digest"
            ),
            JournalBreakKind::DigestMismatch => format!(
                "journal chain broken at {at}: the stored digest does not cover the payload"
            ),
            JournalBreakKind::AnchorMismatch => format!(
                "journal anchor mismatch ({at}): the anchor records a different head from the \
                 journal's actual last digest; the file was rewritten after the anchor was written"
            ),
            JournalBreakKind::AnchorCountMismatch => format!(
                "journal anchor count mismatch ({at}): the anchor and the journal disagree on how \
                 many records exist"
            ),
            JournalBreakKind::MissingAnchor => format!(
                "journal has records but no anchor was recorded ({at}); nothing corroborates the \
                 chain, so a whole-file rewrite would be undetectable"
            ),
            JournalBreakKind::StrippedChain => format!(
                "journal chain stripped ({at}): an anchor exists but the records carry no chain \
                 fields"
            ),
        };
        // The anchor variants need the two digests to be useful, so they are
        // replaced below by `anchor_break`.
        Self { seq, kind, detail }
    }

    /// An anchor break that names both digests (and both counts).
    pub fn anchor_break(anchored: &JournalAnchor, actual_count: usize, actual_head: &str) -> Self {
        let kind = if anchored.count != actual_count {
            JournalBreakKind::AnchorCountMismatch
        } else {
            JournalBreakKind::AnchorMismatch
        };
        let detail = format!(
            "journal anchor mismatch: the anchor records {} records ending at `{}` but the \
             journal holds {actual_count} records ending at `{actual_head}`; the file was \
             rewritten or truncated after the anchor was written",
            anchored.count, anchored.head
        );
        Self {
            seq: Self::FILE_LEVEL,
            kind,
            detail,
        }
    }

    /// The typed error a `Result` boundary returns.
    pub fn to_error(&self) -> NauError {
        NauError::Validation(self.detail.clone())
    }
}

impl std::fmt::Display for JournalBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

/// What a successful load found: the records, the anchor, and whether the chain
/// was actually linked.
#[derive(Clone, PartialEq, Debug)]
pub struct LoadedJournal {
    /// Every record, in file order.
    pub records: Vec<JournalRecord>,
    /// The anchor the store recorded.
    pub anchor: JournalAnchor,
    /// True when the records carry chain fields and verified against the anchor.
    ///
    /// `false` means the file predates linkage (an upgrade from a V1.2.2 data
    /// directory), which is reported rather than silently accepted: an unlinked
    /// journal is not evidence.
    pub linked: bool,
}

impl LoadedJournal {
    /// The payloads, in order — the list a restore should replay.
    pub fn payloads(&self) -> Vec<Value> {
        self.records
            .iter()
            .map(|record| record.payload.clone())
            .collect()
    }

    /// The head digest after this load.
    pub fn head(&self) -> &str {
        self.records
            .last()
            .map(|record| record.hash.as_str())
            .unwrap_or(GENESIS_DIGEST)
    }
}

/// Recompute one record's digest from its payload and predecessor digest.
///
/// The payload side is its canonical JSON, so the digest cannot depend on the key
/// order a particular writer happened to emit.
pub fn record_digest(prev: &str, payload: &Value) -> Result<String> {
    let canonical = canonical_json_bytes(payload)?;
    Ok(digest_of(prev, &canonical))
}

/// The SHA-256 over the domain tag, the length-prefixed predecessor digest and the
/// length-prefixed canonical payload.
fn digest_of(prev: &str, canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(JOURNAL_DOMAIN);
    hasher.update(format!("len(prev):{}", prev.len()).as_bytes());
    hasher.update(b"\0");
    hasher.update(prev.as_bytes());
    hasher.update(b"\0");
    hasher.update(format!("len(payload):{}", canonical.len()).as_bytes());
    hasher.update(b"\0");
    hasher.update(canonical);
    hex::encode(hasher.finalize())
}

/// Encode one linked record line (without the trailing newline).
pub fn encode_linked(seq: usize, prev: &str, hash: &str, payload: &Value) -> Result<Vec<u8>> {
    let record = LinkedRecord {
        v: LINKED_SCHEMA_VERSION,
        seq,
        prev: prev.to_string(),
        hash: hash.to_string(),
        payload: payload.clone(),
    };
    let bytes = canonical_json_bytes(&serde_json::to_value(&record)?)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(NauError::Validation(format!(
            "record of {} bytes exceeds the {MAX_RECORD_BYTES}-byte cap",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Read one line, or explain why it is not a linked journal record.
///
/// Returns `Ok(None)` when the line is a *plain* (pre-linkage) record envelope, so
/// the caller can distinguish "this file predates linkage" from "this line is
/// broken".
pub fn decode_line(line: &str) -> std::result::Result<Option<LinkedRecord>, String> {
    let value: Value =
        serde_json::from_str(line).map_err(|err| format!("not valid JSON: {err}"))?;
    let Value::Object(mut map) = value else {
        return Err("record line is not a JSON object".to_string());
    };
    let version = map
        .get("v")
        .and_then(Value::as_u64)
        .ok_or_else(|| "record has no integer `v` schema marker".to_string())?;
    if version == u64::from(jsonl::SCHEMA_VERSION) {
        return Ok(None);
    }
    if version != u64::from(LINKED_SCHEMA_VERSION) {
        return Err(format!(
            "unsupported schema marker v={version}, expected v={} (linked) or v={} (plain)",
            LINKED_SCHEMA_VERSION,
            jsonl::SCHEMA_VERSION
        ));
    }
    let payload = map
        .remove("payload")
        .ok_or_else(|| "record has no `payload` field".to_string())?;
    let seq = map
        .remove("seq")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "linked record has no unsigned `seq`".to_string())?;
    let prev = match map.remove("prev") {
        Some(Value::String(s)) => s,
        _ => return Err("linked record has no string `prev`".to_string()),
    };
    let hash = match map.remove("hash") {
        Some(Value::String(s)) => s,
        _ => return Err("linked record has no string `hash`".to_string()),
    };
    let seq =
        usize::try_from(seq).map_err(|_| format!("`seq` {seq} does not fit this platform"))?;
    Ok(Some(LinkedRecord {
        v: LINKED_SCHEMA_VERSION,
        seq,
        prev,
        hash,
        payload,
    }))
}

/// Read a linked journal file strictly, verifying its chain and its anchor.
///
/// * A missing or empty file is an empty journal whose anchor must be
///   [`JournalAnchor::genesis`].
/// * An empty line is skipped (a crash can leave one); it carries no movement.
/// * **Any other undecodable line is a hard error naming the line number.** There
///   is deliberately no "skip and warn" path here: skipping is what made upstream's
///   watermark — a physical row count indexing a filtered list — desynchronise
///   permanently, so the journal silently stopped recording movements while the API
///   kept answering `200`.
/// * `line_cap` bounds the number of lines examined, so a runaway log cannot
///   exhaust memory before the anchor check even runs.
///
/// # Errors
///
/// A [`JournalBreak`] flattened through [`JournalBreak::to_error`], so the caller
/// gets the first offending position in the message.
pub fn load_journal(path: &Path, line_cap: usize) -> Result<LoadedJournal> {
    let lines = read_lines(path)?;
    if lines.len() > line_cap {
        return Err(NauError::Conflict(format!(
            "`{}` holds more than {line_cap} journal lines; compact it before loading",
            path.display()
        )));
    }
    let mut records: Vec<JournalRecord> = Vec::with_capacity(lines.len());
    let mut seen_seq: HashSet<usize> = HashSet::new();
    let mut linked_records = 0usize;
    let mut plain_records = 0usize;
    let mut expected_prev = GENESIS_DIGEST.to_string();

    for (index, raw) in lines.iter().enumerate() {
        let trimmed = raw.trim_end_matches(['\n', '\r']);
        if trimmed.trim().is_empty() {
            continue;
        }
        let line_no = (index + 1) as u64;
        let decoded = decode_line(trimmed).map_err(|reason| {
            JournalBreak::new(line_no, JournalBreakKind::UnreadableRecord).to_error_with(&reason)
        })?;
        let Some(linked) = decoded else {
            // A plain envelope: an upgraded data directory, decoded leniently the
            // same way the agent/task logs are.
            let plain = jsonl::read_records_from_line(trimmed).map_err(|err| {
                JournalBreak::new(line_no, JournalBreakKind::UnreadableRecord)
                    .to_error_with(&err.to_string())
            })?;
            plain_records += 1;
            records.push(JournalRecord {
                seq: records.len(),
                hash: String::new(),
                prev: String::new(),
                payload: plain.payload,
            });
            continue;
        };
        linked_records += 1;
        let position = records.len();
        if !seen_seq.insert(linked.seq) {
            return Err(
                JournalBreak::new(linked.seq as u64, JournalBreakKind::DuplicateSequence)
                    .to_error(),
            );
        }
        if linked.seq != position {
            return Err(
                JournalBreak::new(linked.seq as u64, JournalBreakKind::SequenceMismatch).to_error(),
            );
        }
        if linked.prev != expected_prev {
            return Err(JournalBreak::new(
                linked.seq as u64,
                JournalBreakKind::PreviousHashMismatch,
            )
            .to_error());
        }
        let recomputed = record_digest(&linked.prev, &linked.payload)?;
        if recomputed != linked.hash {
            return Err(
                JournalBreak::new(linked.seq as u64, JournalBreakKind::DigestMismatch).to_error(),
            );
        }
        expected_prev = linked.hash.clone();
        records.push(JournalRecord {
            seq: linked.seq,
            hash: linked.hash,
            prev: linked.prev,
            payload: linked.payload,
        });
    }

    let mut anchor = read_anchor(path)?;
    if records.is_empty() {
        if let Some(anchor) = &anchor {
            anchor.validate()?;
            if !anchor.is_genesis() {
                return Err(JournalBreak::anchor_break(anchor, 0, GENESIS_DIGEST).to_error());
            }
        }
        return Ok(LoadedJournal {
            records,
            anchor: JournalAnchor::genesis(),
            linked: true,
        });
    }

    if linked_records == 0 && plain_records > 0 {
        // An upgraded directory: records exist but carry no chain fields.
        return Ok(LoadedJournal {
            records,
            anchor: anchor.take().unwrap_or_else(JournalAnchor::genesis),
            linked: false,
        });
    }

    let actual_head = expected_prev.clone();
    let actual_count = records.len();
    match anchor.take() {
        None => {
            // Records exist and are linked, but nobody recorded the head. That is
            // exactly the state in which a whole-file rewrite is undetectable, so
            // it is a failure rather than a warning.
            Err(
                JournalBreak::new(JournalBreak::FILE_LEVEL, JournalBreakKind::MissingAnchor)
                    .to_error(),
            )
        }
        Some(anchor) => {
            anchor.validate()?;
            if anchor.is_genesis() {
                // An anchor that describes an empty journal cannot cover records:
                // either the records were added without updating the anchor, or the
                // chain fields were stripped from a file the anchor knows about.
                return Err(JournalBreak::new(
                    JournalBreak::FILE_LEVEL,
                    JournalBreakKind::StrippedChain,
                )
                .to_error());
            }
            if anchor.count != actual_count || anchor.head != actual_head {
                return Err(
                    JournalBreak::anchor_break(&anchor, actual_count, &actual_head).to_error(),
                );
            }
            Ok(LoadedJournal {
                records,
                anchor,
                linked: true,
            })
        }
    }
}

/// Read the anchor recorded beside the journal.
///
/// A missing key is `Ok(None)`; a malformed value is an error, because an
/// unreadable anchor must not be treated as "no anchor required".
pub fn read_anchor_from(meta: Option<String>) -> Result<Option<JournalAnchor>> {
    match meta {
        None => Ok(None),
        Some(text) => {
            let anchor: JournalAnchor = serde_json::from_str(&text)?;
            anchor.validate()?;
            Ok(Some(anchor))
        }
    }
}

/// Serialize an anchor for storage.
pub fn anchor_to_meta(anchor: &JournalAnchor) -> Result<String> {
    anchor.validate()?;
    Ok(serde_json::to_string(anchor)?)
}

// ------------------------------------------------------------------ internals

/// A `JournalBreak` with an extra reason appended, for a decode failure.
trait BreakExt {
    /// [`JournalBreak::to_error`] with `reason` appended.
    fn to_error_with(&self, reason: &str) -> NauError;
}

impl BreakExt for JournalBreak {
    fn to_error_with(&self, reason: &str) -> NauError {
        NauError::Validation(format!("{}: {reason}", self.detail))
    }
}

/// Read every line of `path` as bytes, tolerating a missing file.
fn read_lines(path: &Path) -> Result<Vec<String>> {
    use std::io::BufRead;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(NauError::Io(err)),
    };
    let reader = std::io::BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.split(b'\n') {
        let bytes = line?;
        if bytes.is_empty() {
            continue;
        }
        match std::str::from_utf8(&bytes) {
            Ok(text) => lines.push(text.to_string()),
            Err(err) => {
                return Err(JournalBreak::new(
                    lines.len() as u64 + 1,
                    JournalBreakKind::UnreadableRecord,
                )
                .to_error_with(&format!("line is not valid UTF-8: {err}")))
            }
        }
    }
    Ok(lines)
}

/// Read the anchor from the store directory that owns `path`.
fn read_anchor(path: &Path) -> Result<Option<JournalAnchor>> {
    let meta_path = path.with_file_name(crate::file::META_FILE);
    let bytes = match std::fs::read(&meta_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(NauError::Io(err)),
    };
    if bytes.is_empty() {
        return Ok(None);
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    match value.get(LEDGER_ANCHOR_KEY) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => read_anchor_from(Some(text.clone())),
        Some(other) => Err(NauError::Validation(format!(
            "`{}` must hold the anchor as a JSON string, found `{other}`",
            meta_path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chain_of(count: usize) -> (Vec<LinkedRecord>, String) {
        let mut records = Vec::new();
        let mut head = GENESIS_DIGEST.to_string();
        for seq in 0..count {
            let payload = json!({ "seq": seq, "amount": (seq as i64 + 1) * 1_000 });
            let hash = record_digest(&head, &payload).expect("digest");
            records.push(LinkedRecord {
                v: LINKED_SCHEMA_VERSION,
                seq,
                prev: head.clone(),
                hash: hash.clone(),
                payload,
            });
            head = hash;
        }
        (records, head)
    }

    #[test]
    fn the_digest_covers_the_payload_and_the_predecessor() {
        let payload = json!({ "a": 1 });
        let other = json!({ "a": 2 });
        let a = record_digest(GENESIS_DIGEST, &payload).expect("digest");
        let b = record_digest(GENESIS_DIGEST, &other).expect("digest");
        assert_ne!(a, b);
        assert_ne!(a, record_digest(&a, &payload).expect("digest"));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn encoding_is_a_pure_function_of_the_record() {
        let (records, _) = chain_of(1);
        let record = &records[0];
        let line =
            encode_linked(record.seq, &record.prev, &record.hash, &record.payload).expect("encode");
        let text = String::from_utf8(line.clone()).expect("utf8");
        let decoded = decode_line(&text)
            .expect("decodes")
            .expect("is a linked record");
        assert_eq!(&decoded, record);
        // Encoding twice gives identical bytes.
        assert_eq!(
            line,
            encode_linked(record.seq, &record.prev, &record.hash, &record.payload).expect("encode")
        );
    }

    #[test]
    fn a_plain_record_is_reported_as_plain_rather_than_broken() {
        let plain = r#"{"payload":{"a":1},"v":1}"#;
        assert!(decode_line(plain).expect("valid line").is_none());
        assert!(decode_line(r#"{"v":1,"payload":"#).is_err());
        assert!(decode_line(r#"{"v":9,"payload":{}}"#).is_err());
        assert!(
            decode_line(r#"{"v":2,"payload":{},"prev":"g"}"#).is_err(),
            "no hash"
        );
        assert!(
            decode_line(r#"{"v":2,"payload":{},"prev":"g","hash":"h","seq":"x"}"#).is_err(),
            "seq must be a number"
        );
    }

    #[test]
    fn an_anchor_that_this_crate_could_not_have_written_is_refused() {
        assert!(JournalAnchor::genesis().validate().is_ok());
        assert!(JournalAnchor::of("not-hex", 1).validate().is_err());
        assert!(JournalAnchor::of(GENESIS_DIGEST, 1).validate().is_err());
        assert!(JournalAnchor::of("deadbeef", 0).validate().is_err());
        assert!(JournalAnchor::of("a".repeat(64), 3).validate().is_ok());
        let text = anchor_to_meta(&JournalAnchor::of("b".repeat(64), 2)).expect("meta");
        let back = read_anchor_from(Some(text)).expect("reads").expect("some");
        assert_eq!(back, JournalAnchor::of("b".repeat(64), 2));
        assert!(read_anchor_from(None).expect("none").is_none());
        assert!(
            read_anchor_from(Some("{}".into())).is_err(),
            "incomplete anchor"
        );
    }

    #[test]
    fn every_break_kind_has_a_distinct_label() {
        let kinds = [
            JournalBreakKind::UnreadableRecord,
            JournalBreakKind::SequenceMismatch,
            JournalBreakKind::DuplicateSequence,
            JournalBreakKind::PreviousHashMismatch,
            JournalBreakKind::DigestMismatch,
            JournalBreakKind::AnchorMismatch,
            JournalBreakKind::AnchorCountMismatch,
            JournalBreakKind::MissingAnchor,
            JournalBreakKind::StrippedChain,
        ];
        let mut labels: Vec<&str> = kinds.iter().map(JournalBreakKind::label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), kinds.len());
        for (index, kind) in kinds.into_iter().enumerate() {
            let brk = JournalBreak::new(index as u64, kind);
            assert!(!brk.detail.is_empty());
        }
        let anchor_break =
            JournalBreak::anchor_break(&JournalAnchor::of("a".repeat(64), 1), 2, "b");
        assert!(anchor_break.is_file_level());
        assert_eq!(anchor_break.kind.label(), "anchor_count_mismatch");
    }
}
