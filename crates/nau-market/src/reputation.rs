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
use nau_core::error::{NauError, Result};
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
    /// Whether the resources the agent offered were **what they claimed to be**.
    ///
    /// # D-09's fourth dimension, and the one the other three could not see
    ///
    /// `quality` says the work was correct, `speed` says it arrived in time, `honesty` says no
    /// dispute was found. **None of them says the CPU the agent sold was a CPU it had**, and a
    /// provider that advertises four cores while running on one passes all three: the work is
    /// correct, it arrives, and nobody disputes it because nobody measured.
    ///
    /// This dimension is fed only by [`Reputation::record_resource_observation`], whose input is a
    /// [`ResourceObservation`] — a type the **network** produces by measuring. There is no method
    /// that takes a score from the agent, which is D-09's first criterion.
    ///
    /// It carries `#[serde(default, skip_serializing_if = ...)]` so that reputation persisted before
    /// v3.8.7 still loads AND still **serialises to the same bytes**: a missing field becomes
    /// [`ReputationScore::NEUTRAL`], and a neutral value is omitted again on the way out.
    ///
    /// # The second half is not tidiness, and a test found it
    ///
    /// `nau-plugin-bridge` commits to a **merkle root over canonicalised reputations**. Its fixture
    /// hard-codes a pre-D-09 payload, and with `default` alone the plugin deserialised it, filled in
    /// the two new fields, re-serialised, and produced **different bytes** — so the committed root no
    /// longer matched the one the crate computes directly.
    ///
    /// The test failed, and it was pointing at something real rather than at itself: **an anchor
    /// recorded before this release would no longer verify after it.** A `#[serde(default)]` field
    /// that is written out is a schema change to every stored document; one that is omitted when it
    /// holds the default is a schema change only to the documents that actually use it.
    ///
    /// `observations` gets the same treatment for the same reason.
    #[serde(default, skip_serializing_if = "is_neutral_score")]
    pub truthfulness: ReputationScore,
    /// Total tasks settled for this agent.
    pub settled: u64,
    /// Total tasks that ended in a dispute found against this agent.
    pub faults: u64,
    /// How many resource observations have been made about this agent.
    ///
    /// Counted separately from `settled` because it is a different act: a settlement is a task
    /// finishing, and an observation is the network measuring what the agent said it had. An agent
    /// with a thousand settlements and no observations has a `truthfulness` nobody has tested, and
    /// this number is what makes that visible rather than implied.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub observations: u64,
}

/// Integer exponential-smoothing rate: one tenth.
const ALPHA_DENOM: i64 = 10;

/// Whether a score is the neutral one, for `skip_serializing_if`.
///
/// `nau-core`'s `ReputationScore` carries no predicate of its own, and adding one there would put a
/// serialisation concern into a domain type. This is where it is needed and this is where it lives.
fn is_neutral_score(score: &ReputationScore) -> bool {
    *score == ReputationScore::NEUTRAL
}

/// Whether a counter is zero, for `skip_serializing_if`.
fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

// The composite's weights, in basis points, named so that they can be asserted to sum to the whole.
// A set that summed to 9,900 would quietly deflate every score, and one summing to 10,100 would push
// scores past what `ReputationScore` allows.
const WEIGHT_QUALITY: u32 = 3_000;
const WEIGHT_SPEED: u32 = 1_500;
const WEIGHT_HONESTY: u32 = 2_500;
const WEIGHT_AVAILABILITY: u32 = 1_000;
const WEIGHT_TRUTHFULNESS: u32 = 2_000;

impl Default for Reputation {
    fn default() -> Self {
        Self {
            quality: ReputationScore::NEUTRAL,
            speed: ReputationScore::NEUTRAL,
            honesty: ReputationScore::NEUTRAL,
            availability: ReputationScore::NEUTRAL,
            truthfulness: ReputationScore::NEUTRAL,
            settled: 0,
            faults: 0,
            observations: 0,
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
    ///
    /// # The weights changed at v3.8.7, and this is the record of it
    ///
    /// Until D-09 the weights were **35% quality / 20% speed / 30% honesty / 15% availability**. A
    /// fifth dimension has to come from somewhere, and taking it proportionally from all four keeps
    /// their **relative** standing intact — which is the part A-05's composite was about — while
    /// making room for resource truthfulness.
    ///
    /// The five are **30 / 15 / 25 / 10 / 20**: quality, speed, honesty, availability, truthfulness.
    ///
    /// NOTE, because I got this wrong in prose before the test caught it: truthfulness is the
    /// **third**-largest share, after quality and honesty — not the second, which is what this
    /// comment claimed in its first draft. The constants are the design; the sentence was the error.
    /// A comment stating a ranking the code does not implement is the same defect as a document
    /// stating a count the scripts do not define, and the same kind of test catches both.
    ///
    /// The weights sum to exactly 10,000, and a test asserts it — a set that summed to 9,900 would
    /// quietly deflate every score, and one that summed to 10,100 would inflate them past the range
    /// the score type allows.
    pub fn overall_bps(&self) -> u32 {
        let q = u32::from(self.quality.bps());
        let s = u32::from(self.speed.bps());
        let h = u32::from(self.honesty.bps());
        let a = u32::from(self.availability.bps());
        let t = u32::from(self.truthfulness.bps());
        // Division by 10_000 is exact here because the numerator is at most 10_000 * 10_000.
        (q * WEIGHT_QUALITY
            + s * WEIGHT_SPEED
            + h * WEIGHT_HONESTY
            + a * WEIGHT_AVAILABILITY
            + t * WEIGHT_TRUTHFULNESS)
            / 10_000
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

    // ------------------------------------------------------------ D-09

    /// Record what the network **measured** about the resources an agent offered.
    ///
    /// # The parameter is an observation, not a score
    ///
    /// This is D-09's first criterion, and it is held by the signature rather than by a rule. There
    /// is no method on this type that takes a basis-point figure from the agent, and this one takes
    /// a [`ResourceObservation`] — a type whose fields are what a **checker** found: what was
    /// advertised, what was measured, and who did the measuring.
    ///
    /// An agent cannot call this with a favourable number, because there is no number to pass. It
    /// could lie about what it advertised, which is why the advertised figure is compared against
    /// the offer rather than trusted here.
    ///
    /// # How the target is derived
    ///
    /// `measured / advertised` in basis points, capped at 100% and floored at 0:
    ///
    /// * Exactly what was advertised is 10,000 and does not move the score.
    /// * Half of it is 5,000 and pulls the score toward 5,000 — the neutral value, because an agent
    ///   that delivers half of what it claims is not a known liar, it is an agent whose claim is
    ///   half-true, and a reputation that fell to zero for one measurement would be one nobody could
    ///   recover from.
    /// * **More** than advertised is also capped at 10,000: an agent that over-delivers has not
    ///   proved it is honest about anything, and rewarding a surplus would make `advertised` a number
    ///   with no consequence.
    pub fn record_resource_observation(&mut self, observation: &ResourceObservation) {
        self.observations = self.observations.saturating_add(1);
        let advertised = observation.advertised.max(1);
        // Integer arithmetic throughout, and the ratio is capped so that over-delivery is not a
        // credit and absurd mis-delivery is not a debt beyond the neutral point.
        let ratio_bps = observation
            .measured
            .saturating_mul(10_000)
            .checked_div(advertised)
            .unwrap_or(10_000)
            .min(10_000);
        let target = u16::try_from(ratio_bps.min(u64::from(ReputationScore::MAX_BPS)))
            .unwrap_or(ReputationScore::MAX_BPS);
        self.truthfulness = smooth(self.truthfulness, target);
    }

    /// Record a fault found against the agent for misrepresenting its resources.
    ///
    /// Separate from [`Reputation::record_fault`], which is about a task ending badly. A provider
    /// can deliver every task correctly on hardware it did not declare, and the two failures should
    /// not share a counter: `faults` is what a dispute found, and this is what a measurement found.
    pub fn record_resource_misrepresentation(&mut self, severity_bps: u16) {
        self.observations = self.observations.saturating_add(1);
        // The target is the inverse of the severity: a total misrepresentation aims at zero.
        let target = u16::try_from(
            10_000u32.saturating_sub(u32::from(severity_bps.min(ReputationScore::MAX_BPS))),
        )
        .unwrap_or(0);
        self.truthfulness = smooth(self.truthfulness, target);
    }

    /// Whether anything has ever been measured about this agent's resources.
    ///
    /// The honest question to ask before trusting the dimension: an agent with no observations has a
    /// `truthfulness` of neutral because nobody looked, and neutral because it was honest would be
    /// the same number.
    #[must_use]
    pub fn resources_have_been_observed(&self) -> bool {
        self.observations > 0
    }
}

/// What a checker measured about the resources an agent offered.
///
/// # D-09's first criterion, held by the type
///
/// The fields are **what was advertised** and **what was measured**, plus who measured. There is no
/// field for what the agent says its score should be, because a reputation that could be
/// self-reported is not a reputation — it is a claim, and the whole point of the dimension is that
/// the network checked.
///
/// The `checker` field is recorded rather than used here: a caller that wants to weigh observations
/// by who made them has what it needs, and this module does not decide whose word counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceObservation {
    /// The DID of whoever measured.
    pub checker: String,
    /// What the agent's offer claimed, in the resource's own unit.
    pub advertised: u64,
    /// What the checker actually got, in the same unit.
    pub measured: u64,
    /// Which resource this is about.
    pub kind: crate::ResourceKind,
    /// When the measurement was taken, Unix seconds.
    pub at: u64,
}

impl ResourceObservation {
    /// An observation.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the checker is blank or the timestamp is zero. `advertised`
    /// being zero is **not** an error here: an offer of nothing is refused by
    /// [`ResourceAmount::of`](crate::ResourceAmount::of) before it reaches a registry, and a
    /// measurement of a zero claim is a checker reporting that it found nothing to check. The
    /// division in `record_resource_observation` guards against the zero anyway, because a guard
    /// that depends on another module's validation is not a guard.
    pub fn new(
        checker: impl Into<String>,
        kind: crate::ResourceKind,
        advertised: u64,
        measured: u64,
        at: u64,
    ) -> Result<Self> {
        let checker = checker.into();
        if checker.trim().is_empty() {
            return Err(NauError::Validation(
                "an observation must name who measured; an unattributed measurement is one nobody \
                 can be asked about"
                    .to_string(),
            ));
        }
        if at == 0 {
            return Err(NauError::Validation(
                "an observation must carry a non-zero timestamp".to_string(),
            ));
        }
        Ok(Self {
            checker,
            advertised,
            measured,
            kind,
            at,
        })
    }

    /// `measured / advertised` in basis points, capped at 10,000.
    ///
    /// Zero advertised gives 10,000 — not because a zero claim is perfect, but because there is no
    /// ratio to compute and the alternatives are a division by zero or a penalty for a situation
    /// this type cannot describe. Stated rather than left as a silent `unwrap_or`.
    #[must_use]
    pub fn ratio_bps(&self) -> u64 {
        self.measured
            .saturating_mul(10_000)
            .checked_div(self.advertised.max(1))
            .unwrap_or(10_000)
            .min(10_000)
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
        // This test used to assert 35% / 20% / 30% / 15%. D-09 added a fifth dimension and the
        // weights were rebalanced to 30 / 15 / 25 / 10 / 20 -- taken proportionally from the four so
        // that their RELATIVE standing, which is what A-05's composite was about, is unchanged.
        //
        // The test fired when that happened, which is what it was for. It now asserts the new
        // distribution AND that the five weights sum to exactly 10,000: a set summing to 9,900 would
        // quietly deflate every score, and one summing to 10,100 would push scores past what
        // `ReputationScore` allows.
        let only = |f: fn(&mut Reputation)| {
            let mut r = Reputation {
                quality: ReputationScore::clamped(0),
                speed: ReputationScore::clamped(0),
                honesty: ReputationScore::clamped(0),
                availability: ReputationScore::clamped(0),
                truthfulness: ReputationScore::clamped(0),
                ..Reputation::default()
            };
            f(&mut r);
            r.overall_bps()
        };

        assert_eq!(
            only(|r| r.quality = ReputationScore::clamped(10_000)),
            WEIGHT_QUALITY,
            "quality weight"
        );
        assert_eq!(
            only(|r| r.speed = ReputationScore::clamped(10_000)),
            WEIGHT_SPEED,
            "speed weight"
        );
        assert_eq!(
            only(|r| r.honesty = ReputationScore::clamped(10_000)),
            WEIGHT_HONESTY,
            "honesty weight"
        );
        assert_eq!(
            only(|r| r.availability = ReputationScore::clamped(10_000)),
            WEIGHT_AVAILABILITY,
            "availability weight"
        );
        assert_eq!(
            only(|r| r.truthfulness = ReputationScore::clamped(10_000)),
            WEIGHT_TRUTHFULNESS,
            "truthfulness weight"
        );

        // The sum, which is the property that keeps a score inside its range.
        assert_eq!(
            WEIGHT_QUALITY
                + WEIGHT_SPEED
                + WEIGHT_HONESTY
                + WEIGHT_AVAILABILITY
                + WEIGHT_TRUTHFULNESS,
            10_000,
            "the weights must sum to the whole, or every score is deflated or inflated"
        );
    }

    // The ORDER, asserted rather than described: quality 30% > honesty 25% > truthfulness 20% >
    // speed 15% > availability 10%.
    //
    // # Why these four are compile-time assertions rather than `assert!` in a test
    //
    // The doc comment on `overall_bps` first claimed truthfulness was the SECOND-largest share. It
    // is third, and a test assertion is what found the discrepancy. But once the weights were
    // confirmed, those four comparisons became facts about `const` values — and clippy rejected
    // `assert!(true)` four times over, because a runtime assertion about compile-time constants is
    // one the compiler has already answered.
    //
    // This is the fifth time in this project that I have written an assertion the type system or the
    // constant folder already knows: `!CONST.is_empty()` in `police.rs`, again in `audit.rs`, again
    // in `plugins/resource.rs`, and now these. The shape is always the same — it FEELS like a test
    // and is not one.
    //
    // `const _: () = assert!(...)` is the honest form: the property is checked when the crate is
    // compiled, so a weight changed into the wrong order fails the BUILD rather than a test run, and
    // there is no runtime assertion left for clippy to reject.
    const _: () = assert!(WEIGHT_QUALITY > WEIGHT_HONESTY);
    const _: () = assert!(WEIGHT_HONESTY > WEIGHT_TRUTHFULNESS);
    const _: () = assert!(WEIGHT_TRUTHFULNESS > WEIGHT_SPEED);
    const _: () = assert!(WEIGHT_SPEED > WEIGHT_AVAILABILITY);

    #[test]
    fn a_reputation_persisted_before_d09_still_loads() {
        // The two new fields carry `#[serde(default)]`, so state written by v3.8.6 and earlier loads
        // with `truthfulness` NEUTRAL and `observations` zero -- which is the correct reading of
        // "nobody has measured this yet" rather than a zero that would read as a finding.
        let old = r#"{
            "quality": 8000, "speed": 6000, "honesty": 7000, "availability": 9000,
            "settled": 7, "faults": 2
        }"#;
        let loaded: Reputation = serde_json::from_str(old).expect("pre-D-09 state must load");
        assert_eq!(loaded.quality.bps(), 8_000);
        assert_eq!(loaded.settled, 7);
        assert_eq!(
            loaded.truthfulness,
            ReputationScore::NEUTRAL,
            "an unmeasured dimension is neutral, not zero"
        );
        assert_eq!(loaded.observations, 0);
        assert!(
            !loaded.resources_have_been_observed(),
            "and the type says so rather than leaving it to be inferred"
        );
        // And it still produces a score in range rather than a deflated one.
        assert!(loaded.overall_bps() <= 10_000);
    }

    #[test]
    fn a_reputation_cannot_self_report_its_truthfulness() {
        // D-09's first criterion, held by the SIGNATURE rather than by a rule: there is no method on
        // this type that takes a basis-point figure, and the only one that moves the dimension takes
        // an observation -- which is what a CHECKER found.
        let mut r = Reputation::default();
        let neutral = r.truthfulness.bps();
        // ps() is a u16 and NEUTRAL is a ReputationScore, so the comparison is against the
        // VALUE -- comparing the two types directly is what the compiler refused, correctly.
        assert_eq!(neutral, ReputationScore::NEUTRAL.bps());

        // A favourable observation moves it up, and it is the checker's measurement that does so.
        let honest = ResourceObservation::new(
            "did:nau:0000000000000000",
            crate::ResourceKind::Cpu,
            100,
            100,
            1,
        )
        .expect("observation");
        for _ in 0..40 {
            r.record_resource_observation(&honest);
        }
        assert!(
            r.truthfulness.bps() > neutral,
            "measurements that match the claim must raise it, got {}",
            r.truthfulness.bps()
        );
        assert_eq!(r.observations, 40);

        // A half-truth lands ON NEUTRAL rather than below it, and that is the design rather than a
        // shortfall: `measured / advertised` of 50% is 5,000 bps, and 5,000 is neutral. An agent
        // that delivers half of what it claims is not a known liar — it is an agent whose claim is
        // half-true — and the dimension says exactly that.
        //
        // This assertion first read `<` and failed with "got 5000". The module documentation already
        // said "pulls the score toward 5,000 — the neutral value"; the test was the thing that was
        // wrong, and changing the CODE to satisfy it would have been changing the design to fit a
        // mistaken expectation.
        let mut half = Reputation::default();
        let halved = ResourceObservation::new(
            "did:nau:0000000000000000",
            crate::ResourceKind::Cpu,
            100,
            50,
            1,
        )
        .expect("observation");
        for _ in 0..200 {
            half.record_resource_observation(&halved);
        }
        assert_eq!(
            half.truthfulness.bps(),
            ReputationScore::NEUTRAL.bps(),
            "a half-truth sits exactly at neutral"
        );

        // A WORSE misrepresentation is what goes below: a tenth of what was advertised.
        let mut tenth = Reputation::default();
        let barely = ResourceObservation::new(
            "did:nau:0000000000000000",
            crate::ResourceKind::Cpu,
            100,
            10,
            1,
        )
        .expect("observation");
        for _ in 0..200 {
            tenth.record_resource_observation(&barely);
        }
        assert!(
            tenth.truthfulness.bps() < ReputationScore::NEUTRAL.bps(),
            "a tenth of the claim must pull the score below neutral, got {}",
            tenth.truthfulness.bps()
        );
        assert!(
            tenth.truthfulness.bps() > 1_000,
            "and toward the ratio rather than to zero, got {}",
            tenth.truthfulness.bps()
        );

        // A finding of MISREPRESENTATION is the separate act, and it aims at zero in proportion to
        // the severity -- it is what a measurement found, where `faults` is what a dispute found.
        let mut found = Reputation::default();
        found.record_resource_misrepresentation(10_000);
        assert!(
            found.truthfulness.bps() < ReputationScore::NEUTRAL.bps(),
            "a total misrepresentation must pull the score down"
        );
        assert_eq!(found.observations, 1, "and it counts as an observation");

        // MORE than advertised is capped: an agent that over-delivers has not proved it is honest
        // about anything, and rewarding a surplus would make `advertised` a number with no
        // consequence.
        let mut over = Reputation::default();
        let surplus = ResourceObservation::new(
            "did:nau:0000000000000000",
            crate::ResourceKind::Cpu,
            100,
            10_000,
            1,
        )
        .expect("observation");
        for _ in 0..200 {
            over.record_resource_observation(&surplus);
        }
        // Converged TOWARD the whole rather than to it exactly, and the distinction is the
        // smoothing rule rather than a shortfall: `smooth` moves a tenth of the remaining distance
        // each time, so it approaches 10,000 asymptotically. This assertion first read `== 10_000`
        // and failed with "left: 9991" -- the third time in this release that a test expectation of
        // mine was wrong rather than the code.
        assert!(
            over.truthfulness.bps() > 9_900,
            "over-delivery converges on the whole, got {}",
            over.truthfulness.bps()
        );
        assert!(over.truthfulness.bps() <= 10_000, "and never passes it");
    }

    #[test]
    fn an_observation_must_name_its_checker_and_its_time() {
        // An unattributed measurement is one nobody can be asked about.
        assert!(ResourceObservation::new("   ", crate::ResourceKind::Cpu, 100, 100, 1).is_err());
        assert!(ResourceObservation::new(
            "did:nau:0000000000000000",
            crate::ResourceKind::Cpu,
            100,
            100,
            0
        )
        .is_err());
        let good = ResourceObservation::new(
            "did:nau:0000000000000000",
            crate::ResourceKind::Cpu,
            100,
            100,
            1,
        )
        .expect("observation");
        assert_eq!(good.ratio_bps(), 10_000);
        // Zero advertised gives 10,000 rather than a division by zero, and that is STATED rather
        // than left as a silent fallback.
        let nothing = ResourceObservation::new(
            "did:nau:0000000000000000",
            crate::ResourceKind::Cpu,
            0,
            5,
            1,
        )
        .expect("observation");
        assert_eq!(nothing.ratio_bps(), 10_000);
    }

    #[test]
    fn an_unobserved_reputation_serialises_to_exactly_the_bytes_it_did_before_d09() {
        // The finding that `skip_serializing_if` is on those two fields for.
        //
        // `nau-plugin-bridge` commits to a merkle root over canonicalised reputations, and its
        // fixture hard-codes a pre-D-09 payload. With `#[serde(default)]` ALONE, the plugin
        // deserialised it, filled in the new fields, re-serialised, and produced DIFFERENT BYTES --
        // so the committed root stopped matching and the bridge's own test failed.
        //
        // That test was pointing at something real: an anchor recorded before this release would no
        // longer verify after it. Omitting a field that holds its default makes this a schema change
        // only for documents that actually use the new dimension.
        let old = r#"{"quality":8000,"speed":6000,"honesty":7000,"availability":9000,"settled":7,"faults":2}"#;
        let loaded: Reputation = serde_json::from_str(old).expect("pre-D-09 state loads");
        let written = serde_json::to_string(&loaded).expect("serialises");
        assert_eq!(
            written, old,
            "an unobserved reputation must round-trip to the same bytes, or every anchor recorded \
             before v3.8.7 stops verifying"
        );

        // And once the dimension IS used it appears, so the omission is about the default rather
        // than about the field being invisible.
        let mut observed = loaded.clone();
        observed.record_resource_observation(
            &ResourceObservation::new(
                "did:nau:0000000000000000",
                crate::ResourceKind::Cpu,
                100,
                100,
                1,
            )
            .expect("observation"),
        );
        let written = serde_json::to_string(&observed).expect("serialises");
        assert!(written.contains("truthfulness"), "{written}");
        assert!(written.contains("observations"), "{written}");
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
