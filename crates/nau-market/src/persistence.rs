//! Restart integrity: what the market persists beside the ledger, and what a
//! restore is allowed to trust.
//!
//! Upstream v2.8.2's persistence layer introduced *worse* defects than the ones
//! it replaced, and this module exists so that none of them can be reintroduced
//! silently:
//!
//! * **finding B** — upstream rebuilt every restored task with
//!   `verification_policy: VerificationPolicy::None` and `winner_price: None`,
//!   so `settle` (which gates on exactly those fields) paid
//!   `winner_price.unwrap_or(budget)`: a restart was a way to skip the evidence
//!   gate and to be paid the full budget. Here the snapshot persists the result
//!   envelope with its evidence grade, the winning price, the verified-evidence
//!   upgrade and the reputation records, and settlement refuses when the price is
//!   missing rather than substituting the budget.
//! * **finding C** — upstream never saved result envelopes, reputations or
//!   stakes, so after a restart `submit_bid` failed for every agent and
//!   `arbitrate(guilty = true)` could not find a stake record *while the staked
//!   funds were still on the books*. Here those records are part of the snapshot
//!   and the nonce high-water marks are persisted with them.
//! * **finding D** — upstream derived its watermark from a physical row count
//!   (`SELECT COUNT(*)`) while indexing a list from which unparseable rows had
//!   been silently dropped, so one corrupt record moved the watermark permanently
//!   ahead and the journal stopped recording. Here the logical record count is
//!   persisted (`journal_records`) *and* every restored record is checked for
//!   position, self-consistency and chain linkage; the first defect is reported in
//!   a [`RestoreReport`] instead of being skipped.
//! * **finding E** — upstream swallowed both write and restore failures. A restore
//!   that does not verify exactly now produces a report, the market refuses to
//!   serve mutations while degraded, and the report is exposed through
//!   [`crate::MarketStats::degraded`] and [`crate::Market::restore_report`].

use std::collections::BTreeMap;

use nau_core::{
    Bid, Did, Dispute, DisputeOutcome, EvidenceGrade, Money, NauError, Result, ResultEnvelope,
    TaskId,
};
use serde::{Deserialize, Serialize};

use crate::reputation::Reputation;

/// Metadata key under which the market snapshot is stored.
pub const MARKET_STATE_KEY: &str = "market.state";
/// Metadata key recording the crate version that wrote the state.
pub const MARKET_VERSION_KEY: &str = "market.version";
/// Metadata key recording the wire protocol revision.
pub const MARKET_PROTOCOL_KEY: &str = "market.protocol";

/// Schema marker of the snapshot format. A snapshot carrying a different marker
/// is refused rather than misread.
pub const MARKET_STATE_SCHEMA: u32 = 1;

/// Everything the market persists that is not an agent card, a task or a ledger
/// record.
///
/// `Store` (see `nau-store`) exposes agent, task, ledger and metadata records
/// only; the market therefore keeps its own state in one metadata value. Writing
/// it as a **single** value is deliberate: one `set_meta` call is one atomic
/// replace, so the logical ledger count can never disagree with the state that
/// was written beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketSnapshot {
    /// Schema marker; always [`MARKET_STATE_SCHEMA`] for a snapshot this crate
    /// wrote.
    #[serde(default)]
    pub schema: u32,
    /// How many ledger journal records were durable when this snapshot was
    /// written: the **logical** sequence number, not a physical row count.
    #[serde(default)]
    pub journal_records: usize,
    /// Result envelopes by task, with their evidence grades (finding B).
    #[serde(default)]
    pub results: BTreeMap<TaskId, ResultEnvelope>,
    /// Reputation records by DID (finding C).
    #[serde(default)]
    pub reputation: BTreeMap<Did, Reputation>,
    /// Bids by task, so a restart does not erase the audit trail or the winner's
    /// price (findings B, C).
    #[serde(default)]
    pub bids: BTreeMap<TaskId, Vec<Bid>>,
    /// Open disputes by id (finding C: a ruling needs the dispute it decides).
    #[serde(default)]
    pub disputes: BTreeMap<String, Dispute>,
    /// Recorded rulings by dispute id, so a decided dispute stays decided.
    #[serde(default)]
    pub rulings: BTreeMap<String, DisputeOutcome>,
    /// The price the winning bid offered, recorded when the task was matched
    /// (finding B).
    #[serde(default)]
    pub winner_price: BTreeMap<TaskId, Money>,
    /// Evidence grades upgraded by a successful committee verification
    /// (finding G).
    #[serde(default)]
    pub verified_evidence: BTreeMap<TaskId, EvidenceGrade>,
    /// Highest nonce accepted per signer, so a replayed object stays refused
    /// after a restart (finding C).
    #[serde(default)]
    pub nonces: BTreeMap<Did, u64>,
}

impl Default for MarketSnapshot {
    fn default() -> Self {
        Self::empty()
    }
}

impl MarketSnapshot {
    /// An empty snapshot for the current schema.
    pub fn empty() -> Self {
        Self {
            schema: MARKET_STATE_SCHEMA,
            journal_records: 0,
            results: BTreeMap::new(),
            reputation: BTreeMap::new(),
            bids: BTreeMap::new(),
            disputes: BTreeMap::new(),
            rulings: BTreeMap::new(),
            winner_price: BTreeMap::new(),
            verified_evidence: BTreeMap::new(),
            nonces: BTreeMap::new(),
        }
    }

    /// True when this snapshot carries no records at all.
    pub fn is_empty(&self) -> bool {
        self.journal_records == 0
            && self.results.is_empty()
            && self.reputation.is_empty()
            && self.bids.is_empty()
            && self.disputes.is_empty()
            && self.rulings.is_empty()
            && self.winner_price.is_empty()
            && self.verified_evidence.is_empty()
            && self.nonces.is_empty()
    }

    /// Serialize for [`MARKET_STATE_KEY`].
    ///
    /// # Errors
    ///
    /// [`NauError::Serde`] if the snapshot cannot be encoded.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(NauError::from)
    }

    /// Parse a stored snapshot, refusing any schema this build does not know.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the text is not a snapshot object or carries
    /// a schema marker other than [`MARKET_STATE_SCHEMA`].
    pub fn from_json(text: &str) -> Result<Self> {
        let snapshot: Self = serde_json::from_str(text).map_err(|err| {
            NauError::Validation(format!(
                "`{MARKET_STATE_KEY}` is not a valid market snapshot: {err}"
            ))
        })?;
        if snapshot.schema != MARKET_STATE_SCHEMA {
            return Err(NauError::Validation(format!(
                "`{MARKET_STATE_KEY}` carries schema {} but this build writes and reads schema \
                 {MARKET_STATE_SCHEMA}; refusing to misread it",
                snapshot.schema
            )));
        }
        Ok(snapshot)
    }
}

/// One thing that was wrong with a store while it was being restored.
///
/// A defect is *reported*, never skipped: that is the whole point of finding D.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreDefect {
    /// Stable, machine-readable label (see the `*_KIND` constants).
    pub kind: String,
    /// The logical ledger sequence the defect concerns, when it concerns one.
    pub seq: Option<u64>,
    /// Human-readable description, always naming the sequence it concerns.
    pub detail: String,
}

impl RestoreDefect {
    /// A record whose payload could not be decoded at all.
    pub const UNPARSEABLE_KIND: &'static str = "unparseable_record";
    /// A record whose stored sequence number is not the position it occupies,
    /// which means at least one record before it is missing.
    pub const SEQUENCE_GAP_KIND: &'static str = "sequence_gap";
    /// A record whose own digest does not cover its bytes.
    pub const DIGEST_MISMATCH_KIND: &'static str = "digest_mismatch";
    /// A record that does not chain onto its predecessor.
    pub const BROKEN_LINK_KIND: &'static str = "broken_link";
    /// A record the ledger refused to reproduce from the journal.
    pub const UNREPRODUCIBLE_KIND: &'static str = "unreproducible_record";
    /// The journal ends before the logical count the snapshot recorded, so the
    /// tail was truncated (a torn append, or a lost record).
    pub const TRUNCATED_TAIL_KIND: &'static str = "truncated_tail";
    /// The market snapshot itself could not be decoded.
    pub const SNAPSHOT_UNREADABLE_KIND: &'static str = "unreadable_snapshot";

    /// Build a defect.
    pub fn new(kind: &str, seq: Option<u64>, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            seq,
            detail: detail.into(),
        }
    }
}

/// What a restore could, and could not, rebuild.
///
/// `is_clean()` is the only thing a caller needs to decide whether the market is
/// serving trustworthy state; everything else is evidence for the operator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    /// The `at` the restore was opened with.
    pub restored_at: u64,
    /// Ledger journal records the snapshot says should have been durable.
    pub ledger_records_expected: usize,
    /// Ledger journal records actually applied.
    pub ledger_records_restored: usize,
    /// Logical sequence numbers that could not be restored, ascending.
    pub missing_records: Vec<u64>,
    /// Every defect found, in the order the replay stopped.
    pub defects: Vec<RestoreDefect>,
    /// Agent cards restored.
    pub agents: usize,
    /// Tasks restored.
    pub tasks: usize,
    /// Result envelopes restored.
    pub results: usize,
    /// Disputes restored.
    pub disputes: usize,
}

impl RestoreReport {
    /// True when every record the store held was applied and nothing was wrong.
    pub fn is_clean(&self) -> bool {
        self.defects.is_empty() && self.missing_records.is_empty()
    }

    /// True when the restore did not verify exactly.
    pub fn is_degraded(&self) -> bool {
        !self.is_clean()
    }

    /// A single line naming what was wrong, for an error message or a log.
    pub fn summary(&self) -> String {
        if self.is_clean() {
            return format!(
                "restored {} ledger record(s), {} agent(s), {} task(s)",
                self.ledger_records_restored, self.agents, self.tasks
            );
        }
        let defects = self
            .defects
            .iter()
            .map(|defect| {
                let position = match defect.seq {
                    Some(seq) => format!("seq {seq}"),
                    None => "the store as a whole".to_string(),
                };
                format!("{} at {position}: {}", defect.kind, defect.detail)
            })
            .collect::<Vec<_>>()
            .join("; ");
        format!(
            "restored {} of {} ledger record(s); missing {:?}; {}",
            self.ledger_records_restored,
            self.ledger_records_expected,
            self.missing_records,
            if defects.is_empty() {
                "no further detail".to_string()
            } else {
                defects
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_round_trips_and_refuses_a_foreign_schema() {
        let snapshot = MarketSnapshot::empty();
        let text = snapshot.to_json().expect("encode");
        let back = MarketSnapshot::from_json(&text).expect("decode");
        assert_eq!(back, snapshot);
        assert!(back.is_empty());

        let mut foreign = snapshot.clone();
        foreign.schema = MARKET_STATE_SCHEMA + 1;
        let text = foreign.to_json().expect("encode");
        assert!(MarketSnapshot::from_json(&text).is_err());
        assert!(MarketSnapshot::from_json("not json").is_err());
    }

    #[test]
    fn a_report_is_only_clean_when_nothing_was_lost() {
        let mut report = RestoreReport {
            ledger_records_expected: 3,
            ledger_records_restored: 3,
            ..RestoreReport::default()
        };
        assert!(report.is_clean());
        report.missing_records.push(2);
        assert!(report.is_degraded());
        assert!(report.summary().contains("seq 2") || report.summary().contains("missing [2]"));
    }
}
