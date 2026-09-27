//! The conservation report produced by both the O(1) and the O(N) code paths.

use nau_core::Money;
use serde::{Deserialize, Serialize};

/// The state of the conservation identity.
///
/// Produced by [`crate::Ledger::conservation`] (O(1), reads maintained counters)
/// and by [`crate::Ledger::audit`] (O(N), re-derives everything from the
/// journal). The two are deliberately the *same* type so that a caller can
/// compare them and so that a service can log either without a conversion.
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
