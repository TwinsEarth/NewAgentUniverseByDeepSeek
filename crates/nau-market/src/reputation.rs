//! Integer-only, multi-dimensional agent reputation.
//!
//! Upstream v2.5.6 has **three** unreconciled reputation implementations:
//! `marketplace/reputation.rs` (weights 0.35/0.20/0.30/0.15, **no time input**, and
//! this is the one that feeds matching), `aca/reputation.rs` (weights
//! 0.25/0.15/0.40/0.20, 90-day decay, unused by the market) and
//! `economy/reputation.rs` (a `u16` score, never instantiated outside tests).
//! The market module's own doc comment advertises a 90-day half-life that its
//! struct cannot implement, and three places compute a "success rate" with three
//! different formulas — one of which
//! (`marketplace/mod.rs:380-386`) has no `else` branch, so **failed calls raise the
//! recorded rate**.
//!
//! This module has exactly one implementation, and it stores **integers only**:
//! every dimension is basis points. Updating uses integer exponential smoothing,
//! so there is no float, no `partial_cmp(..).unwrap()` (which upstream calls on
//! `f64` scores in two places and which panics on `NaN`), and no way to represent a
//! score outside `0..=10_000`.

use nau_core::domain::ReputationScore;
use serde::{Deserialize, Serialize};

/// Exponentially-smoothed reputation across four dimensions.
///
/// Weights sum to 10_000 basis points: quality 3500, speed 2000, honesty 3000,
/// availability 1500. These are upstream's market weights, preserved so that
/// matching behaviour is comparable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reputation {
    /// Correctness of delivered work, in basis points.
    pub quality: ReputationScore,
    /// Delivery speed against the agent's own advertised SLA.
    pub speed: ReputationScore,
    /// Absence of disputes found against the agent.
    pub honesty: ReputationScore,
    /// Fraction of accepted tasks the agent actually completed.
    pub availability: ReputationScore,
    /// Total tasks settled for this agent.
    pub settled: u64,
    /// Total tasks that ended in a dispute found against this agent.
    pub faults: u64,
}

/// Integer exponential-smoothing rate: one tenth.
const ALPHA_DENOM: i64 = 10;

impl Default for Reputation {
    fn default() -> Self {
        Self {
            quality: ReputationScore::NEUTRAL,
            speed: ReputationScore::NEUTRAL,
            honesty: ReputationScore::NEUTRAL,
            availability: ReputationScore::NEUTRAL,
            settled: 0,
            faults: 0,
        }
    }
}

/// Move `current` a tenth of the way toward `target`, in integer space.
///
/// Equivalent to upstream's `current += 0.1 * (target - current)` but exact and
/// monotone, and it cannot produce a value outside the `0..=10_000` range.
fn smooth(current: ReputationScore, target_bps: u16) -> ReputationScore {
    let cur = i64::from(current.bps());
    let target = i64::from(target_bps.min(ReputationScore::MAX_BPS));
    let delta = (target - cur) / ALPHA_DENOM;
    let next = (cur + delta).clamp(0, i64::from(ReputationScore::MAX_BPS));
    // `clamp` guarantees the cast is in range.
    ReputationScore::clamped(next as u16)
}

impl Reputation {
    /// The composite score used for matching, in basis points.
    ///
    /// Deliberately integer: upstream computes a weighted `f64` sum and then sorts
    /// on it, which makes tie-breaking non-deterministic and can panic on `NaN`.
    pub fn overall_bps(&self) -> u32 {
        let q = u32::from(self.quality.bps());
        let s = u32::from(self.speed.bps());
        let h = u32::from(self.honesty.bps());
        let a = u32::from(self.availability.bps());
        // Weights: 35% / 20% / 30% / 15%. Division by 10_000 is exact here because
        // the numerator is at most 10_000 * 10_000.
        (q * 3_500 + s * 2_000 + h * 3_000 + a * 1_500) / 10_000
    }

    /// The composite score as a [`ReputationScore`].
    pub fn overall(&self) -> ReputationScore {
        ReputationScore::clamped(self.overall_bps() as u16)
    }

    /// Record a settled task.
    ///
    /// `latency_ratio_bps` is the observed latency divided by the agent's **own
    /// advertised** p95, expressed in basis points (10_000 == exactly on target).
    /// Upstream hard-coded the divisor at 2000 ms
    /// (`marketplace/mod.rs:368-370`: `latency_ms as f64 / 2000.0`) and ignored the
    /// agent's `Sla.latency_p95_ms` entirely, so the same latency helped or hurt
    /// every agent identically regardless of what they promised.
    pub fn record_settled(&mut self, latency_ratio_bps: u32, evidence_trustworthy: bool) {
        self.settled = self.settled.saturating_add(1);
        // Quality: a settled, settlement-grade result is a success.
        let (quality_target, availability_target) = if evidence_trustworthy {
            (10_000u16, 10_000u16)
        } else {
            (0, 3_000)
        };
        self.quality = smooth(self.quality, quality_target);
        self.availability = smooth(self.availability, availability_target);

        // Speed: meeting or beating the promised latency scores full marks; each
        // additional 100% of the promised latency costs half the remaining score
        // (2x the promise -> 5000, 3x -> 0). Integer, bounded, and measured against
        // the agent's OWN p95 rather than a magic constant.
        let speed_target: u32 = if latency_ratio_bps <= 10_000 {
            10_000
        } else {
            let over = latency_ratio_bps - 10_000;
            10_000 - (over / 2).min(10_000)
        };
        self.speed = smooth(self.speed, speed_target.min(10_000) as u16);

        // Honesty only moves on a *penalty* here; it must not ratchet upward for
        // free the way upstream's `reward_honesty()` did on every settlement.
    }

    /// Record a dispute that was found against this agent.
    pub fn record_fault(&mut self, severity_bps: u16) {
        self.faults = self.faults.saturating_add(1);
        let penalty = i64::from(severity_bps.min(ReputationScore::MAX_BPS));
        let next =
            (i64::from(self.honesty.bps()) - penalty).clamp(0, i64::from(ReputationScore::MAX_BPS));
        self.honesty = ReputationScore::clamped(next as u16);
        self.quality = smooth(self.quality, 0);
    }

    /// Record an honest outcome without a fault.
    pub fn record_clean(&mut self) {
        self.honesty = smooth(self.honesty, 10_000);
    }

    /// True when the agent may bid, given a floor in basis points.
    pub fn is_eligible(&self, min_overall_bps: u32) -> bool {
        self.overall_bps() >= min_overall_bps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_agent_scores_exactly_neutral() {
        let r = Reputation::default();
        assert_eq!(r.overall_bps(), 5_000);
        assert_eq!(r.settled, 0);
    }

    #[test]
    fn smoothing_is_integer_monotone_and_stays_in_range() {
        let mut r = Reputation::default();
        for _ in 0..100 {
            r.record_settled(10_000, true);
        }
        // Approaches 10_000 without ever exceeding it.
        assert!(r.quality.bps() <= 10_000);
        assert!(
            r.quality.bps() > 9_900,
            "should converge, got {}",
            r.quality.bps()
        );
        assert_eq!(r.settled, 100);

        let mut bad = Reputation::default();
        for _ in 0..100 {
            bad.record_settled(80_000, false);
        }
        assert!(
            bad.quality.bps() < 100,
            "quality should decay, got {}",
            bad.quality.bps()
        );
        assert!(bad.speed.bps() < 5_000);
    }

    #[test]
    fn honesty_does_not_ratchet_upward_for_free() {
        // Upstream rewarded honesty on every settlement, so it saturated after
        // ~10 tasks and became a function of task count rather than of behaviour.
        let mut r = Reputation::default();
        for _ in 0..50 {
            r.record_settled(10_000, true);
        }
        assert_eq!(
            r.honesty.bps(),
            5_000,
            "settling must not inflate honesty; only faults and clean findings should move it"
        );
        r.record_clean();
        assert!(r.honesty.bps() > 5_000);
    }

    #[test]
    fn a_fault_reduces_honesty_and_quality() {
        let mut r = Reputation::default();
        r.record_fault(3_000);
        assert_eq!(r.honesty.bps(), 2_000);
        assert!(r.quality.bps() < 5_000);
        assert_eq!(r.faults, 1);
        // Cannot go below zero no matter how many faults.
        for _ in 0..50 {
            r.record_fault(10_000);
        }
        assert_eq!(r.honesty.bps(), 0);
    }

    #[test]
    fn latency_is_judged_against_the_agents_own_promise() {
        // Twice the promised latency must score far worse than on-target.
        let mut on_time = Reputation::default();
        let mut late = Reputation::default();
        for _ in 0..30 {
            on_time.record_settled(10_000, true);
            late.record_settled(20_000, true);
        }
        assert!(
            on_time.speed.bps() > late.speed.bps() + 2_000,
            "speed must separate on-time from late: {} vs {}",
            on_time.speed.bps(),
            late.speed.bps()
        );
        assert!(on_time.overall_bps() > late.overall_bps());
    }

    #[test]
    fn eligibility_is_an_integer_comparison() {
        let r = Reputation::default();
        assert!(r.is_eligible(5_000));
        assert!(!r.is_eligible(5_001));
        assert!(r.is_eligible(0));
    }

    #[test]
    fn composite_weights_sum_to_the_documented_distribution() {
        // Built with struct-update syntax rather than field-by-field reassignment.
        let quality_only = Reputation {
            quality: ReputationScore::clamped(10_000),
            speed: ReputationScore::clamped(0),
            honesty: ReputationScore::clamped(0),
            availability: ReputationScore::clamped(0),
            ..Reputation::default()
        };
        assert_eq!(quality_only.overall_bps(), 3_500, "quality weight is 35%");

        let honesty_only = Reputation {
            quality: ReputationScore::clamped(0),
            speed: ReputationScore::clamped(0),
            honesty: ReputationScore::clamped(10_000),
            availability: ReputationScore::clamped(0),
            ..Reputation::default()
        };
        assert_eq!(honesty_only.overall_bps(), 3_000, "honesty weight is 30%");
    }

    #[test]
    fn a_serialised_reputation_contains_no_floats() {
        let r = Reputation::default();
        let v = serde_json::to_value(&r).unwrap();
        fn assert_integral(v: &serde_json::Value, path: &str) {
            match v {
                serde_json::Value::Number(n) => {
                    assert!(n.is_i64() || n.is_u64(), "{path} is not an integer: {n}");
                }
                serde_json::Value::Object(map) => {
                    for (k, child) in map {
                        assert_integral(child, &format!("{path}.{k}"));
                    }
                }
                serde_json::Value::Array(items) => {
                    for (i, child) in items.iter().enumerate() {
                        assert_integral(child, &format!("{path}[{i}]"));
                    }
                }
                _ => {}
            }
        }
        assert_integral(&v, "reputation");
        // And it must therefore survive canonicalization, which rejects floats.
        nau_core::canonical::canonical_object(&v).expect("reputation must be canonicalizable");
    }
}
