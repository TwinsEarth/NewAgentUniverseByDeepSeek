//! BFT-lite committee parameters, with checked arithmetic.
//!
//! Upstream v2.5.6 computed the BFT relation on bare `u32`
//! (`marketplace/qa_committee.rs:53`):
//!
//! ```text
//! if n < 3 * f + 1 { return Err("..."); }
//! let quorum = 2 * f + 1;
//! ```
//!
//! With `f = 1_431_655_766`, `3 * f + 1` wraps to `1` in release, so the guard
//! evaluates `n < 1` and an absurd committee is accepted; in debug the same
//! expression panics on overflow. Both operations are checked here.

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};

/// The size and fault tolerance of a BFT-lite committee.
///
/// The fields are public so that a spec can be carried inside a larger
/// configuration struct, but every constructor and every consumer validates the
/// `n >= 3f + 1` relation with checked arithmetic, so a hand-built literal cannot
/// smuggle in a committee that violates it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CommitteeSpec {
    /// Number of assigned committee members.
    pub n: u32,
    /// Number of Byzantine members the committee tolerates.
    pub f: u32,
}

impl CommitteeSpec {
    /// Validate and build a committee specification.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `3f + 1` overflows `u32` (the upstream
    /// overflow) or when `n < 3f + 1`.
    pub fn new(n: u32, f: u32) -> Result<Self> {
        let spec = Self { n, f };
        spec.validate()?;
        Ok(spec)
    }

    /// Re-check the BFT relation, using checked arithmetic.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `3f + 1` overflows `u32` or when
    /// `n < 3f + 1`.
    pub fn validate(&self) -> Result<()> {
        let (n, f) = (self.n, self.f);
        // upstream v2.5.6 fix: `3 * f + 1` was computed on unchecked u32, which
        // panics in debug and wraps in release.
        let minimum = f
            .checked_mul(3)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                NauError::Validation(format!(
                    "committee f={f} overflows 3f+1; no committee of that size is expressible"
                ))
            })?;
        if n < minimum {
            return Err(NauError::Validation(format!(
                "BFT-lite requires n >= 3f+1, got n={n}, f={f} (need n >= {minimum})"
            )));
        }
        Ok(())
    }

    /// The number of assigned committee members.
    pub fn n(&self) -> u32 {
        self.n
    }

    /// The number of tolerated Byzantine members.
    pub fn f(&self) -> u32 {
        self.f
    }

    /// The quorum size, `2f + 1`.
    ///
    /// For any spec produced by [`CommitteeSpec::new`] (or accepted by
    /// [`CommitteeSpec::validate`]) this cannot overflow `u32`: `3f + 1 <= u32::MAX`
    /// already bounds `f` far below the point where `2f + 1` could wrap. A
    /// hand-built literal that skips validation saturates at `u32::MAX` rather
    /// than wrapping or panicking — use [`CommitteeSpec::quorum_checked`] when a
    /// hard error is preferred.
    pub fn quorum(&self) -> u32 {
        self.quorum_checked().unwrap_or(u32::MAX)
    }

    /// The quorum size, `2f + 1`, with overflow reported as an error.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `2f + 1` would overflow `u32`.
    pub fn quorum_checked(&self) -> Result<u32> {
        // upstream v2.5.6 fix: `2 * f + 1` was unchecked.
        self.f
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| NauError::Validation(format!("committee f={} overflows 2f+1", self.f)))
    }

    /// The number of simultaneous faults that leaves the quorum intersection
    /// property intact, i.e. `n - quorum`.
    pub fn fault_margin(&self) -> u32 {
        self.n.saturating_sub(self.quorum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bft_relation_is_enforced() {
        assert!(CommitteeSpec::new(4, 1).is_ok());
        assert!(CommitteeSpec::new(3, 1).is_err(), "3 < 3*1+1");
        assert!(CommitteeSpec::new(7, 2).is_ok());
        assert!(CommitteeSpec::new(6, 2).is_err(), "6 < 7");
        assert!(CommitteeSpec::new(0, 0).is_err(), "0 < 1");
        assert!(CommitteeSpec::new(1, 0).is_ok());
        assert!(CommitteeSpec::new(4, 0).is_ok());
    }

    #[test]
    fn quorum_is_two_f_plus_one() {
        assert_eq!(CommitteeSpec::new(1, 0).unwrap().quorum(), 1);
        assert_eq!(CommitteeSpec::new(4, 1).unwrap().quorum(), 3);
        assert_eq!(CommitteeSpec::new(7, 2).unwrap().quorum(), 5);
        assert_eq!(CommitteeSpec::new(10, 3).unwrap().quorum(), 7);
        assert_eq!(CommitteeSpec::new(4, 1).unwrap().n(), 4);
        assert_eq!(CommitteeSpec::new(4, 1).unwrap().f(), 1);
    }

    /// upstream v2.5.6 defect 3: `n < 3 * f + 1` wrapped in release and panicked
    /// in debug. Here it is a typed error, at both the `3f+1` and the `2f+1` step.
    #[test]
    fn upstream_fix_3_large_fault_bounds_error_instead_of_overflowing() {
        // `3 * 1_431_655_766 + 1` is exactly 2^32, i.e. 0 in u32.
        let err = CommitteeSpec::new(1, 1_431_655_766).unwrap_err();
        assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
        assert!(CommitteeSpec::new(u32::MAX, u32::MAX).is_err());
        // u32::MAX / 3 == 1_431_655_765, and 3 * that + 1 is 2^32.
        assert!(CommitteeSpec::new(1, u32::MAX / 3).is_err());
        assert!(CommitteeSpec::new(u32::MAX, 1_431_655_765).is_err());
        assert!(
            CommitteeSpec::new(u32::MAX, 1_431_655_764).is_ok(),
            "3f+1 == u32::MAX is the largest expressible relation"
        );

        // The largest spec that is expressible at all.
        let biggest = CommitteeSpec::new(u32::MAX, 1_431_655_764).unwrap();
        assert_eq!(biggest.quorum(), 2_863_311_529);
        assert!(biggest.quorum_checked().is_ok());

        // A hand-built literal that skips validation saturates rather than wrapping.
        let forged = CommitteeSpec {
            n: u32::MAX,
            f: u32::MAX,
        };
        assert!(forged.quorum_checked().is_err());
        assert_eq!(forged.quorum(), u32::MAX, "saturating, never wrapping");
        assert!(forged.validate().is_err());
    }

    #[test]
    fn fault_margin_never_underflows() {
        assert_eq!(CommitteeSpec::new(4, 1).unwrap().fault_margin(), 1);
        assert_eq!(CommitteeSpec::new(7, 2).unwrap().fault_margin(), 2);
        assert_eq!(CommitteeSpec { n: 0, f: 5 }.fault_margin(), 0);
    }

    #[test]
    fn specs_round_trip_through_serde() {
        let spec = CommitteeSpec::new(7, 2).unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        let back: CommitteeSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, spec);
    }
}
