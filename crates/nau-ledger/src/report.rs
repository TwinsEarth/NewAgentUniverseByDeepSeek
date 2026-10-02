//! The conservation report produced by both the O(1) and the O(N) code paths.

use nau_core::Money;
use serde::{Deserialize, Serialize};

use crate::journal::{JournalAnchor, JournalBreak};

/// The state of the conservation identity.
///
/// Produced by [`crate::Ledger::conservation`] (O(1), reads maintained counters)
/// and by [`crate::Ledger::audit`] (O(N), re-derives everything from the
/// journal). The two are deliberately the *same* type so that a caller can
/// compare them and so that a service can log either without a conversion.
///
/// The `journal_*` fields are what the V1.2.3 hardening added: a conservation
/// report that does not say whether the journal it was computed from is intact is
/// not an audit. `conserved: true` now requires an intact chain as well as a
/// zero discrepancy.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConservationReport {
    /// Everything ever deposited, in minor units.
    pub total_deposited: Money,
    /// Everything ever withdrawn to the outside world.
    pub total_withdrawn: Money,
    /// Everything ever destroyed by slashing.
    pub total_slashed: Money,
    /// Funds **currently** locked in escrow accounts.
    pub total_escrowed: Money,
    /// The sum of every account balance.
    pub sum_of_balances: Money,
    /// `total_deposited - total_withdrawn - total_slashed`: what the balances
    /// are supposed to add up to.
    pub accounted_total: Money,
    /// `sum_of_balances - accounted_total`, in minor units. Zero when
    /// conserved; `i64::MIN`/`i64::MAX` only if the difference itself is not
    /// representable, which cannot happen for a ledger built through the public
    /// API.
    pub discrepancy: i64,
    /// Whether this path considers the ledger conserved.
    pub conserved: bool,
    /// Number of journal entries considered.
    pub entries: usize,
    /// True when the journal's hash chain re-derives exactly.
    #[serde(default)]
    pub journal_intact: bool,
    /// Digest of the last journal record ([`crate::GENESIS_DIGEST`] when empty).
    ///
    /// Compare this against the anchor a store persisted; if they differ, the
    /// journal file was rewritten after the anchor was written.
    #[serde(default)]
    pub journal_head: String,
    /// How many journal entries the chain check actually consumed.
    ///
    /// This is the *logical* count. A store whose watermark is a physical row
    /// count can disagree with it, which is exactly upstream defect D — so the
    /// report carries both numbers instead of one.
    #[serde(default)]
    pub journal_entries_used: usize,
    /// The **first** offending sequence number, when the chain does not verify.
    ///
    /// `None` means "no break found". A file-level break (a stale anchor) reports
    /// [`crate::JournalBreak::FILE_LEVEL`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_break_seq: Option<u64>,
    /// A machine-readable label for the break kind, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_break_kind: Option<String>,
}

impl ConservationReport {
    /// True when the identity holds and the reported discrepancy is zero.
    pub fn is_conserved(&self) -> bool {
        self.conserved
    }

    /// The net supply issued into the ledger.
    pub fn net_issued(&self) -> Money {
        self.accounted_total
    }

    /// True when the journal's hash chain verified.
    pub fn is_journal_intact(&self) -> bool {
        self.journal_intact
    }

    /// Attach the outcome of a chain verification to this report, and make
    /// `conserved` require it.
    ///
    /// Kept on the report rather than in a wrapper so that every existing caller
    /// of `conservation()`/`audit()` sees the journal status without changing a
    /// call: "conserved" that does not mention the journal is the vacuous claim
    /// upstream made.
    pub(crate) fn with_journal_integrity(
        mut self,
        brk: &Option<JournalBreak>,
        anchor: &JournalAnchor,
    ) -> Self {
        self.journal_head = anchor.head.clone();
        self.journal_entries_used = anchor.count;
        match brk {
            None => {
                self.journal_intact = true;
                self.journal_break_seq = None;
                self.journal_break_kind = None;
            }
            Some(brk) => {
                self.journal_intact = false;
                self.conserved = false;
                self.journal_break_seq = Some(brk.seq);
                self.journal_break_kind = Some(brk.kind.label().to_string());
            }
        }
        self
    }
}

/// Narrow an `i128` accumulator into the `i64` minor-unit domain without ever
/// panicking or wrapping.
pub(crate) fn clamp_i64(value: i128) -> i64 {
    if value > i64::MAX as i128 {
        i64::MAX
    } else if value < i64::MIN as i128 {
        i64::MIN
    } else {
        // In range, so the cast is exact.
        value as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamping_never_wraps() {
        assert_eq!(clamp_i64(0), 0);
        assert_eq!(clamp_i64(-1), -1);
        assert_eq!(clamp_i64(i128::from(i64::MAX)), i64::MAX);
        assert_eq!(clamp_i64(i128::from(i64::MIN)), i64::MIN);
        assert_eq!(clamp_i64(i128::MAX), i64::MAX);
        assert_eq!(clamp_i64(i128::MIN), i64::MIN);
    }
}
