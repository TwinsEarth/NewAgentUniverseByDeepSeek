//! Tamper-evident hash chain over the ledger journal.
//!
//! # What this is, and what it is not
//!
//! A journal with no integrity is not a journal: upstream's ledger table is
//! `(seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)` — no hash
//! chain, no signature, no checksum, no trigger, no constraint — while
//! `independent_audit` states that it trusts *only* the journal. Anyone who can
//! write that database file can INSERT a `Deposited` row and **both** the restart
//! and the "independent" audit report `passed: true, conserved: true` over money
//! that was invented.
//!
//! [`JournalChain`] fixes that by making every record commit to its predecessor:
//!
//! ```text
//! digest(i) = SHA-256( DOMAIN ‖ prev_digest(i) ‖ canonical_json(entry_i) )
//! prev_digest(0) = GENESIS_DIGEST
//! ```
//!
//! so any edit, deletion, insertion or reorder inside the chain changes the
//! digest of the record it touches and breaks every record after it. The first
//! offending position is reported by [`JournalBreak::seq`], which is what makes
//! the report actionable — the same "first break index" style the `nau-agent`
//! memory layer uses.
//!
//! ## The honest boundary (read this before claiming anything)
//!
//! This is **tamper-evidence, not tamper-proofness**, and the difference is not
//! cosmetic:
//!
//! * an attacker who can rewrite the **entire** journal file *and* the recorded
//!   [`JournalAnchor`] (a separate file, `meta.json`) consistently can produce a
//!   chain that verifies. Nothing in this module can detect that, because the
//!   attacker is the only witness;
//! * an attacker who rewrites the journal file and leaves the anchor **stale**
//!   *is* detected ([`JournalBreak::kind`] = [`BreakKind::AnchorMismatch`]);
//! * because the anchor is a **different file**, it is not an input to the
//!   in-memory [`Ledger::audit`](crate::Ledger::audit): a ledger rebuilt from a
//!   consistently rewritten record list audits as `conserved: true`. Seeing the
//!   rewrite at all requires handing the stored anchor to
//!   [`Ledger::verify_journal_against`](crate::Ledger::verify_journal_against).
//!   The property this module guarantees is *"the journal and the anchor agree"*,
//!   never *"the chain alone proves this history"*;
//! * an attacker who knows the algorithm can compute a valid chain for any
//!   journal — the chain proves *"this history was not edited after the fact"*,
//!   not *"this history is the one honest nodes saw"*.
//!
//! Detecting a fully consistent forgery requires a witness this process does not
//! have: a signature by a key the writer does not hold, a hash published
//! elsewhere, or an append-only medium. That is stated as a gap in the crate and
//! release documentation rather than papered over here.

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entry::LedgerEntry;

/// Domain-separation tag. Versioned, so a future format change cannot silently
/// validate against digests produced by this one.
pub const JOURNAL_DOMAIN: &[u8] = b"nau-ledger-journal-v1\0";

/// The digest the first journal record chains onto.
pub const GENESIS_DIGEST: &str = "genesis";

/// Where a chain stopped being trustworthy.
///
/// Every variant names the **first** offending journal sequence number, because
/// "the chain is broken" without a position is not an audit finding.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BreakKind {
    /// The stored sequence number is not the position it sits at: a record was
    /// deleted, inserted, or reordered.
    SequenceOutOfOrder {
        /// The sequence number the record claims.
        stored: u64,
    },
    /// The record's `prev_hash` is not the digest of its predecessor: a record
    /// was deleted, inserted, reordered, or its predecessor was rewritten.
    PreviousHashMismatch {
        /// The `prev_hash` the record carries.
        stored: String,
        /// The digest it should have carried.
        expected: String,
    },
    /// The record's own digest does not match its content: the payload, the
    /// memo, the amount or the sequence number was edited.
    DigestMismatch {
        /// The digest the record carries.
        stored: String,
        /// The digest recomputed from the record's own bytes.
        recomputed: String,
    },
    /// The digest that is supposed to anchor the whole file does not match it:
    /// the file was rewritten (consistently or not) after the anchor was
    /// recorded.
    AnchorMismatch {
        /// The digest the anchor records.
        anchored: String,
        /// The digest the file actually ends with.
        actual: String,
    },
    /// The anchor's record count disagrees with the file's record count.
    AnchorCountMismatch {
        /// Records the anchor claims.
        anchored: usize,
        /// Records the file actually holds.
        actual: usize,
    },
    /// A sequence number appears more than once, so a record was replayed in a
    /// slot vacated by another one.
    DuplicateSequence {
        /// The repeated sequence number.
        seq: u64,
    },
}

impl BreakKind {
    /// A stable, machine-readable label, so a report does not have to be parsed
    /// out of prose.
    pub fn label(&self) -> &'static str {
        match self {
            BreakKind::SequenceOutOfOrder { .. } => "sequence_out_of_order",
            BreakKind::PreviousHashMismatch { .. } => "previous_hash_mismatch",
            BreakKind::DigestMismatch { .. } => "digest_mismatch",
            BreakKind::AnchorMismatch { .. } => "anchor_mismatch",
            BreakKind::AnchorCountMismatch { .. } => "anchor_count_mismatch",
            BreakKind::DuplicateSequence { .. } => "duplicate_sequence",
        }
    }
}

/// The first place a journal stopped verifying.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct JournalBreak {
    /// The **first** offending journal sequence number.
    ///
    /// Journal sequence numbers are zero-based and dense (entry `i` carries
    /// `seq == i`), so `0` is a real record here — it is the first record. An
    /// [`AnchorMismatch`](BreakKind::AnchorMismatch) or
    /// [`AnchorCountMismatch`](BreakKind::AnchorCountMismatch) is a property of
    /// the file as a whole rather than of one record, so those two use the
    /// sentinel [`JournalBreak::FILE_LEVEL`] instead.
    pub seq: u64,
    /// What kind of break it is.
    pub kind: BreakKind,
    /// A human-readable description that always contains [`JournalBreak::seq`].
    pub detail: String,
}

impl JournalBreak {
    /// The `seq` used by a break that concerns the whole file (the anchor
    /// checks) rather than one record: `u64::MAX`, which no real journal
    /// position can be.
    pub const FILE_LEVEL: u64 = u64::MAX;

    /// True when this break is about the file as a whole rather than one record.
    pub fn is_file_level(&self) -> bool {
        self.seq == Self::FILE_LEVEL
    }

    /// Build a break and format its detail from the same values the variant
    /// carries, so the number in the prose can never drift from the number in
    /// the field. Public so that the ledger can construct a break from a stored
    /// record without re-encoding the message.
    pub fn new(seq: u64, kind: BreakKind) -> Self {
        let position = if seq == Self::FILE_LEVEL {
            "the whole file".to_string()
        } else {
            format!("seq {seq}")
        };
        let detail = match &kind {
            BreakKind::SequenceOutOfOrder { stored } => format!(
                "journal chain broken at {position}: the record stores seq {stored}, \
                 so a record was deleted, inserted or reordered"
            ),
            BreakKind::PreviousHashMismatch { stored, expected } => format!(
                "journal chain broken at {position}: prev_hash is `{stored}`, expected `{expected}`"
            ),
            BreakKind::DigestMismatch { stored, recomputed } => format!(
                "journal chain broken at {position}: digest mismatch \
                 (recomputed `{recomputed}`, stored `{stored}`)"
            ),
            BreakKind::AnchorMismatch { anchored, actual } => format!(
                "journal anchor mismatch ({position}): the anchor records head `{anchored}` but \
                 the journal ends at `{actual}`; the file was rewritten after the anchor was written"
            ),
            BreakKind::AnchorCountMismatch { anchored, actual } => format!(
                "journal anchor count mismatch ({position}): the anchor records {anchored} entries \
                 but the journal holds {actual}; the file was truncated or extended outside the store"
            ),
            BreakKind::DuplicateSequence { seq: repeated } => format!(
                "journal chain broken at {position}: sequence number {repeated} appears more than \
                 once, so a record was replayed into another record's slot"
            ),
        };
        Self { seq, kind, detail }
    }

    /// A typed error carrying the same information, for a `Result` boundary.
    ///
    /// The variant is [`NauError::Validation`] because that is what a
    /// `status_for` mapping turns into `422 Unprocessable Entity`: a journal that
    /// does not verify is not a transport failure and not a missing entity.
    pub fn to_error(&self) -> NauError {
        NauError::Validation(self.detail.clone())
    }
}

impl std::fmt::Display for JournalBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

/// The head of a journal, recorded next to it so a whole-file rewrite can be
/// detected.
///
/// `head` is the digest of the last record ([`GENESIS_DIGEST`] for an empty
/// journal) and `count` is how many records the writer believes it wrote.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct JournalAnchor {
    /// Digest of the last record, or [`GENESIS_DIGEST`] when empty.
    pub head: String,
    /// How many records the anchor covers.
    pub count: usize,
}

impl Default for JournalAnchor {
    fn default() -> Self {
        Self {
            head: GENESIS_DIGEST.to_string(),
            count: 0,
        }
    }
}

impl JournalAnchor {
    /// The anchor of an empty journal.
    pub fn genesis() -> Self {
        Self::default()
    }

    /// True when the anchor covers no records.
    pub fn is_genesis(&self) -> bool {
        self.count == 0 && self.head == GENESIS_DIGEST
    }

    /// Reject an anchor that could not have been produced by this crate, so a
    /// hand-written `meta.json` cannot smuggle in an unverifiable head.
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

    /// The anchor implied by a journal that is already trusted (the in-memory one).
    pub fn of(entries: &[LedgerEntry]) -> Self {
        match entries.last() {
            Some(last) => Self {
                head: last.hash.clone(),
                count: entries.len(),
            },
            None => Self::genesis(),
        }
    }
}

/// Recompute the digest of one journal record.
///
/// The input is length-prefixed and domain-separated:
///
/// ```text
/// "nau-ledger-journal-v1\0"
/// len(prev):<decimal>  "\0"  prev_digest bytes  "\0"
/// len(entry):<decimal> "\0"  canonical entry bytes
/// ```
///
/// Both variable-length fields carry their own byte length, so no two distinct
/// `(prev_digest, entry)` pairs can encode to the same byte string. The entry
/// side is `serde_json` of the entry *with its two chain fields blanked*, which
/// is a pure function of the value: `LedgerEntry` is a struct, so its fields are
/// emitted in **declaration order** with no insignificant whitespace.
///
/// That determinism is a property of this crate's `LedgerEntry` definition, not
/// of the workspace's cross-language canonicalizer ([`nau_core`] sorts object
/// keys; `serde_json` does not, and it is not used for this digest). Reordering
/// or renaming a field would therefore change every digest, and a verifier in
/// another language must reproduce `serde_json`'s struct encoding rather than the
/// canonical form `conformance/vectors.json` pins. That is a deliberate open gap,
/// recorded here rather than implied away.
///
/// ## Why this returns `Result` even though it cannot fail today
///
/// The mutating methods of [`Ledger`](crate::Ledger) append *after* they have
/// moved money, so an append that could fail would leave the balances changed and
/// the journal short. [`JournalChain::append`] therefore hashes through
/// [`entry_digest_lossless`], which falls back to an unambiguous textual encoding
/// if the JSON encoder ever refuses a value. This function is the strict form, for
/// a verifier that would rather report a problem than guess.
pub fn entry_digest(prev_digest: &str, entry: &LedgerEntry) -> Result<String> {
    let canonical = serde_json::to_vec(&entry.for_hashing())?;
    Ok(digest_of(prev_digest, &canonical))
}

/// [`entry_digest`] with a total fallback, used by the append path.
///
/// The fallback encoding is `len(field):<decimal>\0<bytes>` per field, which is
/// injective for the same reason the main encoding is: every field is
/// length-prefixed. It differs from the main encoding, so a value that took the
/// fallback path on one node and the JSON path on another would not agree — which
/// is why the fallback only engages for a value the JSON encoder has already
/// refused, and is reported by [`JournalChain`]'s callers as a validation error if
/// it ever happens.
fn entry_digest_lossless(prev_digest: &str, entry: &LedgerEntry) -> String {
    match serde_json::to_vec(&entry.for_hashing()) {
        Ok(canonical) => digest_of(prev_digest, &canonical),
        Err(_) => {
            let hashed = entry.for_hashing();
            let mut fallback = Vec::new();
            for field in [
                hashed.seq.to_string(),
                format!("{:?}", hashed.kind),
                hashed
                    .from
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                hashed
                    .to
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                hashed.amount.minor().to_string(),
                hashed.memo.clone(),
                hashed
                    .task
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                hashed.at.to_string(),
            ] {
                fallback.extend_from_slice(format!("len:{}", field.len()).as_bytes());
                fallback.push(0);
                fallback.extend_from_slice(field.as_bytes());
            }
            digest_of(prev_digest, &fallback)
        }
    }
}

/// The SHA-256 over the domain tag, the length-prefixed previous digest and the
/// length-prefixed record bytes.
fn digest_of(prev_digest: &str, record_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(JOURNAL_DOMAIN);
    hasher.update(format!("len(prev):{}", prev_digest.len()).as_bytes());
    hasher.update(b"\0");
    hasher.update(prev_digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(format!("len(entry):{}", record_bytes.len()).as_bytes());
    hasher.update(b"\0");
    hasher.update(record_bytes);
    hex::encode(hasher.finalize())
}

/// An append-only, hash-chained journal.
///
/// The chain is the *ledger's own* record of its journal: [`Ledger`](crate::Ledger)
/// keeps one and refuses to append to a chain that does not verify, so a
/// tampered prefix cannot be grown into a "valid" longer history.
///
/// ## The verified prefix, and why it exists
///
/// Re-deriving every digest on every read would make `Ledger::conservation` an
/// O(N) hash walk — and a caller that checks conservation after every operation
/// would then be O(N²), which is how a test suite goes from seconds to minutes.
/// The chain therefore remembers how many leading records it has already proven:
///
/// * [`JournalChain::from_entries`] starts at `0`, i.e. an adopted chain is
///   **unproven**;
/// * [`JournalChain::verify`] establishes the prefix;
/// * [`JournalChain::append`] extends the proven prefix by exactly one record
///   when the appended record links correctly, and freezes it otherwise.
///
/// [`JournalChain::first_break`] recomputes from the end of the proven prefix and
/// is therefore O(1) on a healthy chain and O(records) only when something is
/// actually wrong. A chain that has never been verified reports a break at the
/// first record — there is deliberately no "unhashed means fine" escape hatch,
/// because that would be exactly the bypass an attacker needs.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct JournalChain {
    entries: Vec<LedgerEntry>,
    /// Digest the next record chains onto.
    head: String,
    /// Number of leading records whose digests this chain has proven.
    verified: usize,
}

impl JournalChain {
    /// An empty chain whose first record chains onto [`GENESIS_DIGEST`].
    ///
    /// Deliberately *not* `Default`: a derived [`Default`] would leave `head`
    /// empty, so the first record would chain onto `""` instead of
    /// [`GENESIS_DIGEST`] and every ledger would fail its own integrity check.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            head: GENESIS_DIGEST.to_string(),
            verified: 0,
        }
    }

    /// Adopt already-stored records, which are **claims** until verified.
    pub fn from_entries(entries: Vec<LedgerEntry>) -> Self {
        let head = entries
            .last()
            .map(|entry| entry.hash.clone())
            .unwrap_or_else(|| GENESIS_DIGEST.to_string());
        Self {
            entries,
            head,
            verified: 0,
        }
    }

    /// Every record, in chain order.
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    /// The digest the next record will chain onto.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// How many records this chain holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the chain holds no records.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many leading records have been proven to link correctly.
    pub fn verified(&self) -> usize {
        self.verified
    }

    /// The anchor this chain implies.
    ///
    /// On a chain whose prefix is fully proven this is the anchor a store should
    /// persist. On a chain with a break it covers the *unproven* records too, so
    /// callers deciding what is safe should read [`JournalChain::verified_anchor`].
    pub fn anchor(&self) -> JournalAnchor {
        JournalAnchor {
            head: self.head.clone(),
            count: self.entries.len(),
        }
    }

    /// The anchor covering only the proven prefix.
    ///
    /// This is what a degraded restart persists: everything at or after
    /// [`JournalChain::verified`] is not evidence.
    pub fn verified_anchor(&self) -> JournalAnchor {
        match self.verified {
            0 => JournalAnchor::genesis(),
            count => JournalAnchor {
                head: self.entries[count - 1].hash.clone(),
                count,
            },
        }
    }

    /// Append `entry` and return the digest that was written into it.
    ///
    /// The chain stamps all three positional fields: `prev_hash`, `hash` and
    /// `seq`. Stamping `seq` is not cosmetic — a record that is appended without
    /// one is a record that claims to be somewhere else, and the chain would
    /// refuse it (or, worse, accept a replay).
    ///
    /// Appending does **not** re-verify the stored prefix; it checks that this one
    /// record continues it and extends the proven prefix by one when it does. A
    /// caller holding a chain that came from outside the process must call
    /// [`JournalChain::verify`] first.
    ///
    /// # Why this cannot fail
    ///
    /// [`Ledger`](crate::Ledger)'s mutating methods move money *before* they
    /// append, so an append that could fail would leave the balances changed and
    /// the journal short — a silent hole, which is precisely the defect this
    /// module exists to close. Hashing therefore goes through
    /// [`entry_digest_lossless`], whose fallback encoding is defined for every
    /// value. The only way to observe the difference is to verify the same entry
    /// with the strict [`entry_digest`].
    pub fn append(&mut self, mut entry: LedgerEntry) -> LedgerEntry {
        entry.seq = self.entries.len() as u64;
        entry.prev_hash = self.head.clone();
        entry.hash = entry_digest_lossless(&entry.prev_hash, &entry);
        self.head = entry.hash.clone();
        let continues_prefix = self.verified == self.entries.len();
        self.entries.push(entry.clone());
        if continues_prefix {
            self.verified += 1;
        }
        entry
    }

    /// Re-derive every digest and report the **first** position that fails.
    ///
    /// On success the whole chain is marked proven, so a subsequent
    /// [`JournalChain::first_break`] is O(1).
    pub fn verify(&mut self) -> std::result::Result<(), JournalBreak> {
        self.verified = 0;
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        while self.verified < self.entries.len() {
            match self.check_at(self.verified, &mut seen) {
                Ok(()) => self.verified += 1,
                Err(brk) => return Err(brk),
            }
        }
        Ok(())
    }

    /// [`JournalChain::verify`] on a copy, for a caller that only has `&self`.
    ///
    /// An audit must not have a side effect on the thing it is auditing, so the
    /// read-only report path uses this and leaves `self.verified` alone.
    pub fn verify_readonly(&self) -> std::result::Result<(), JournalBreak> {
        let mut copy = self.clone();
        copy.verify()
    }

    /// The first break, if any, advancing the proven prefix as far as it goes.
    ///
    /// O(1) on a chain whose prefix is already proven (the append path keeps it
    /// current), and O(remaining records) otherwise.
    pub fn first_break(&mut self) -> Option<JournalBreak> {
        let mut seen: std::collections::HashSet<u64> = (0..self.verified)
            .map(|index| self.entries[index].seq)
            .collect();
        while self.verified < self.entries.len() {
            match self.check_at(self.verified, &mut seen) {
                Ok(()) => self.verified += 1,
                Err(brk) => return Some(brk),
            }
        }
        None
    }

    /// Check the record at `position` against its predecessor, its own digest and
    /// the sequence numbers already seen.
    fn check_at(
        &self,
        position: usize,
        seen: &mut std::collections::HashSet<u64>,
    ) -> std::result::Result<(), JournalBreak> {
        let seq = position as u64;
        let entry = &self.entries[position];
        let expected_prev = if position == 0 {
            GENESIS_DIGEST.to_string()
        } else {
            self.entries[position - 1].hash.clone()
        };
        // A repeated sequence number means a record was replayed into another
        // record's slot. Checked first, because that is the more specific finding.
        if !seen.insert(entry.seq) {
            return Err(JournalBreak::new(
                seq,
                BreakKind::DuplicateSequence { seq: entry.seq },
            ));
        }
        if entry.seq != seq {
            return Err(JournalBreak::new(
                seq,
                BreakKind::SequenceOutOfOrder { stored: entry.seq },
            ));
        }
        if entry.prev_hash != expected_prev {
            return Err(JournalBreak::new(
                seq,
                BreakKind::PreviousHashMismatch {
                    stored: entry.prev_hash.clone(),
                    expected: expected_prev,
                },
            ));
        }
        let recomputed = entry_digest(&entry.prev_hash, entry).map_err(|err| {
            JournalBreak::new(
                seq,
                BreakKind::DigestMismatch {
                    stored: entry.hash.clone(),
                    recomputed: format!("unhashable: {err}"),
                },
            )
        })?;
        if recomputed != entry.hash {
            return Err(JournalBreak::new(
                seq,
                BreakKind::DigestMismatch {
                    stored: entry.hash.clone(),
                    recomputed,
                },
            ));
        }
        Ok(())
    }

    /// Re-link records whose **chain fields** were damaged, preserving every
    /// record's payload.
    ///
    /// Returns the sequence numbers of records that could not be preserved
    /// because their own digest no longer covers their bytes — those are the only
    /// ones a recovery may drop, because a record whose payload was edited is a
    /// claim nothing can corroborate.
    ///
    /// # What a caller must check afterwards
    ///
    /// Re-linking proves connectivity, not content. The caller must also require
    /// that the ledger **replays** every record's movement and that the audit's
    /// independent reconciliation passes before serving degraded: otherwise the
    /// recovery would be laundering an edited payload into a fresh, valid chain.
    /// [`crate::Ledger::recover_journal`] enforces that.
    pub fn relink_preserving_payloads(&mut self) -> Vec<u64> {
        let mut dropped = Vec::new();
        let mut kept: Vec<LedgerEntry> = Vec::with_capacity(self.entries.len());
        let mut head = GENESIS_DIGEST.to_string();
        for entry in self.entries.drain(..) {
            // Self-consistency is independent of position: it asks only whether
            // the digest covers the bytes. A record that fails it was edited.
            let Ok(recomputed) = entry_digest(&entry.prev_hash, &entry) else {
                dropped.push(entry.seq);
                continue;
            };
            if recomputed != entry.hash {
                dropped.push(entry.seq);
                continue;
            }
            let mut rehashed = entry.clone();
            rehashed.seq = kept.len() as u64;
            rehashed.prev_hash = head.clone();
            rehashed.hash = entry_digest_lossless(&rehashed.prev_hash, &rehashed);
            head = rehashed.hash.clone();
            kept.push(rehashed);
        }
        self.head = head;
        self.entries = kept;
        self.verified = self.entries.len();
        dropped
    }

    /// Verify the chain, then check the anchor that is stored beside it.
    ///
    /// The anchor is what turns "rewrite the whole file consistently" from an
    /// undetectable edit into a detected one — as long as the attacker does not
    /// also rewrite the anchor.
    pub fn verify_against(
        &mut self,
        anchor: &JournalAnchor,
    ) -> std::result::Result<(), JournalBreak> {
        anchor.validate().map_err(|err| {
            JournalBreak::new(
                JournalBreak::FILE_LEVEL,
                BreakKind::AnchorMismatch {
                    anchored: anchor.head.clone(),
                    actual: format!("anchor is not well formed: {err}"),
                },
            )
        })?;
        self.verify()?;
        if anchor.count != self.entries.len() {
            return Err(JournalBreak::new(
                JournalBreak::FILE_LEVEL,
                BreakKind::AnchorCountMismatch {
                    anchored: anchor.count,
                    actual: self.entries.len(),
                },
            ));
        }
        if anchor.head != self.head {
            return Err(JournalBreak::new(
                JournalBreak::FILE_LEVEL,
                BreakKind::AnchorMismatch {
                    anchored: anchor.head.clone(),
                    actual: self.head.clone(),
                },
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountId;
    use nau_core::{Money, TaskId};

    fn entry(seq: u64, amount: i64, memo: &str) -> LedgerEntry {
        LedgerEntry {
            seq,
            kind: crate::entry::EntryKind::Deposit,
            from: None,
            to: Some(AccountId::parse("alice").expect("account")),
            amount: Money::from_minor(amount),
            memo: memo.to_string(),
            task: None,
            at: 1_700_000_000,
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    fn chain_of(count: u64) -> JournalChain {
        let mut chain = JournalChain::new();
        for index in 0..count {
            chain.append(entry(index, index as i64 * 1_000, "move"));
        }
        chain
    }

    #[test]
    fn a_fresh_chain_is_empty_verifies_and_anchors_to_genesis() {
        let mut chain = JournalChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.head(), GENESIS_DIGEST);
        assert!(chain.verify().is_ok());
        assert_eq!(chain.anchor(), JournalAnchor::genesis());
        assert!(chain.anchor().is_genesis());
    }

    #[test]
    fn appending_links_each_record_to_its_predecessor() {
        let mut chain = chain_of(4);
        let entries = chain.entries();
        assert_eq!(entries[0].prev_hash, GENESIS_DIGEST);
        for index in 1..entries.len() {
            assert_eq!(entries[index].prev_hash, entries[index - 1].hash);
        }
        assert_eq!(chain.head(), entries[3].hash);
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn the_digest_is_a_function_of_the_previous_digest_and_the_entry() {
        let first = entry(0, 1_000, "a");
        let second = entry(0, 1_000, "b");
        let a = entry_digest(GENESIS_DIGEST, &first).expect("hash");
        let b = entry_digest(GENESIS_DIGEST, &second).expect("hash");
        assert_ne!(a, b, "the memo is covered by the digest");
        let chained = entry_digest(&a, &first).expect("hash");
        assert_ne!(a, chained, "the previous digest is covered by the digest");
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn an_edited_record_is_reported_at_its_own_index() {
        let chain = chain_of(5);
        let mut entries = chain.entries().to_vec();
        entries[2].amount = Money::from_minor(999_999_999);
        let mut tampered = JournalChain::from_entries(entries);
        let brk = tampered.verify().expect_err("must be detected");
        assert_eq!(brk.seq, 2);
        assert_eq!(brk.kind.label(), "digest_mismatch");
        assert!(brk.detail.contains("seq 2"), "{}", brk.detail);
    }

    #[test]
    fn a_deleted_record_is_reported_at_the_gap() {
        let chain = chain_of(5);
        let mut entries = chain.entries().to_vec();
        entries.remove(2);
        let brk = JournalChain::from_entries(entries)
            .verify()
            .expect_err("must be detected");
        assert_eq!(brk.seq, 2, "the first position that no longer lines up");
    }

    #[test]
    fn a_reordered_pair_is_reported_at_the_first_swapped_index() {
        let chain = chain_of(5);
        let mut entries = chain.entries().to_vec();
        entries.swap(1, 2);
        let brk = JournalChain::from_entries(entries)
            .verify()
            .expect_err("must be detected");
        assert_eq!(brk.seq, 1);
    }

    #[test]
    fn a_forged_record_appended_to_a_valid_prefix_is_refused_unless_rehashed() {
        // A forged `Deposit` that copies the previous digest but not the digest is
        // refused; the same record re-hashed through the chain is accepted, which
        // is the honest limitation stated in the module documentation.
        let chain = chain_of(3);
        let mut entries = chain.entries().to_vec();
        let mut forged = entry(3, 5_000_000, "invented money");
        forged.prev_hash = entries[2].hash.clone();
        entries.push(forged);
        let brk = JournalChain::from_entries(entries)
            .verify()
            .expect_err("an unhashed forgery must be refused");
        assert_eq!(brk.seq, 3);
        assert_eq!(brk.kind.label(), "digest_mismatch");

        // ...and the honest limitation: a forger who *does* run the hash rule can
        // extend the chain. Only the anchor (a different file) catches a rewrite.
        let mut recomputed = chain_of(3);
        recomputed.append(entry(3, 5_000_000, "invented money"));
        assert!(
            recomputed.verify().is_ok(),
            "a consistent forgery is undetectable from the chain alone"
        );
    }

    #[test]
    fn a_stale_anchor_detects_a_consistent_whole_file_rewrite() {
        let mut honest = chain_of(3);
        assert!(honest.verify().is_ok());
        let anchor = honest.anchor();

        // The attacker rewrites the whole file: keeps the same records, re-hashes
        // them consistently, and pads the count back to the honest length, so the
        // file is internally perfect *and* as long as the anchor says. The only
        // difference is that one movement was replaced with an invented one.
        // The sequence numbers matter: this test is about a forgery that is
        // internally PERFECT, so it must not trip a sequence check on its way in.
        // The first version of this test appended `entry(0, ...)` three times,
        // which made `verify()` fail on a non-increasing seq and turned the
        // assertion below into a tautology about the wrong property. Keep the
        // honest seq numbering (0, 1, 2) and change only one movement.
        let mut forged = JournalChain::new();
        for (seq, amount) in [0i64, 999_000, 2_000].into_iter().enumerate() {
            forged.append(entry(seq as u64, amount, "move"));
        }
        assert_eq!(forged.len(), anchor.count, "the count is unchanged");
        if let Err(brk) = forged.verify() {
            panic!("the forgery is internally consistent: {brk}");
        }
        assert_ne!(forged.head(), honest.head(), "only the head differs");
        // ...but the anchor is a different file, and it was not rewritten.
        let brk = forged
            .verify_against(&anchor)
            .expect_err("the stale anchor must catch it");
        assert!(brk.is_file_level(), "an anchor break is file-level");
        assert!(matches!(
            brk.kind,
            BreakKind::AnchorMismatch { .. } | BreakKind::AnchorCountMismatch { .. }
        ));
        assert!(brk.detail.contains("anchor"));
    }

    #[test]
    fn an_anchor_that_disagrees_on_count_is_reported() {
        let mut chain = chain_of(3);
        let mut anchor = chain.anchor();
        anchor.count = 2;
        let brk = chain.verify_against(&anchor).expect_err("count mismatch");
        assert_eq!(brk.kind.label(), "anchor_count_mismatch");
    }

    #[test]
    fn a_hand_written_anchor_is_refused_rather_than_trusted() {
        let mut chain = chain_of(1);
        let mut anchor = chain.anchor();
        anchor.head = "not-a-digest".to_string();
        assert!(chain.verify_against(&anchor).is_err());
        let mut empty = JournalChain::new();
        assert!(empty
            .verify_against(&JournalAnchor {
                head: "deadbeef".into(),
                count: 0
            })
            .is_err());
    }

    #[test]
    fn a_replayed_record_in_a_vacated_slot_is_reported() {
        let chain = chain_of(4);
        let mut entries = chain.entries().to_vec();
        // Replace record 3 with a copy of record 2: the file still has 4 records
        // and the count still matches, but a sequence number repeats.
        entries[2] = entries[1].clone();
        let brk = JournalChain::from_entries(entries)
            .verify()
            .expect_err("must be detected");
        assert_eq!(brk.kind.label(), "duplicate_sequence");
        assert_eq!(brk.seq, 2);
    }

    #[test]
    fn a_task_scoped_entry_hashes_the_task_field_too() {
        let task = TaskId::parse("task-1").expect("task id");
        let mut a = entry(0, 1_000, "x");
        let mut b = a.clone();
        a.task = Some(task.clone());
        b.task = Some(TaskId::parse("task-2").expect("task id"));
        assert_ne!(
            entry_digest(GENESIS_DIGEST, &a).expect("hash"),
            entry_digest(GENESIS_DIGEST, &b).expect("hash"),
            "the task id is part of the committed bytes"
        );
    }

    #[test]
    fn break_kinds_all_have_distinct_labels() {
        let kinds = [
            BreakKind::SequenceOutOfOrder { stored: 1 },
            BreakKind::PreviousHashMismatch {
                stored: "a".into(),
                expected: "b".into(),
            },
            BreakKind::DigestMismatch {
                stored: "a".into(),
                recomputed: "b".into(),
            },
            BreakKind::AnchorMismatch {
                anchored: "a".into(),
                actual: "b".into(),
            },
            BreakKind::AnchorCountMismatch {
                anchored: 1,
                actual: 2,
            },
            BreakKind::DuplicateSequence { seq: 1 },
        ];
        let mut labels: Vec<&str> = kinds.iter().map(BreakKind::label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), kinds.len());
    }
}
