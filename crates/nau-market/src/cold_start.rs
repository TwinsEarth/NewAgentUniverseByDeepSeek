//! Cold start: what a provider with no history may be trusted with, and how that widens.
//!
//! # The problem this exists for
//!
//! [`Reputation::default`] starts every dimension at [`ReputationScore::NEUTRAL`] — deliberately, so
//! that a newcomer is neither trusted nor condemned. But **neutral is not safe to match against**:
//! an established provider with a neutral score is one whose record has decayed, and a brand-new
//! provider with the same number is one nobody has ever observed. The same figure, two different
//! facts.
//!
//! A market that ignored the difference would hand its largest tasks to whoever registered most
//! recently and most cheaply, which is the shape of every cold-start attack there is.
//!
//! # D-10's first criterion: the initial reputation cannot be raised by self-report
//!
//! It cannot be raised **at all**, and that is not a policy here — it is what
//! [`Reputation::record_resource_observation`] being the only writer means. This module reads
//! [`Reputation::observations`] and **nothing the provider can set**, so a provider that arrives
//! claiming perfection is admitted on exactly the same terms as one that arrives claiming nothing.
//!
//! # D-10's third criterion: the same history gives the same conclusion
//!
//! [`ColdStartPolicy::assess`] is a pure function of the policy and the reputation. There is no
//! clock, no random draw, and no accumulated state — so two nodes holding the same observations
//! about the same provider admit it to the same value of work. That is what makes an admission
//! something a provider can check rather than something it has to take on faith.

use nau_core::domain::ReputationScore;
use serde::{Deserialize, Serialize};

use crate::reputation::Reputation;

/// How a provider with a short history is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartPolicy {
    /// How many observations a provider must accumulate before it is admitted on reputation alone.
    ///
    /// Observations rather than settlements, because a settlement is a task finishing and an
    /// observation is the network measuring what the provider said it had. A provider can settle a
    /// thousand tasks on hardware it misdescribed; it cannot be **observed** a thousand times
    /// without somebody having looked.
    pub probation_observations: u32,
    /// What a provider with **no** observations may be trusted with, in basis points of the full
    /// limit.
    ///
    /// Not zero, and that is a decision rather than an oversight: a market that admitted nobody
    /// without a history would have no way to acquire one, and the first provider could never
    /// arrive. It is small, it is stated, and it widens.
    pub starter_cap_bps: u16,
    /// The least truthfulness a provider must have **once past probation** to be admitted in full.
    ///
    /// Below this the probation cap still applies, whatever the observation count: a provider that
    /// has been measured and found wanting should not graduate by being measured often.
    pub full_admission_truthfulness_bps: u16,
}

impl Default for ColdStartPolicy {
    /// The policy this workspace ships with.
    ///
    /// **Stated as a starting point rather than as a measurement.** The numbers are a judgement about
    /// what is prudent, not the result of a study, and this doc comment says so because a figure
    /// presented without that distinction is the kind of claim the `metric-claims` gate exists to
    /// refuse.
    fn default() -> Self {
        Self {
            probation_observations: 10,
            starter_cap_bps: 500,
            full_admission_truthfulness_bps: 5_000,
        }
    }
}

/// What a provider may be trusted with, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartAssessment {
    /// Whether the provider is admitted to the full limit.
    pub full_admission: bool,
    /// The cap on a single task's value, in basis points of the market's full limit.
    ///
    /// A figure rather than a boolean, because "not admitted" is not an answer a matcher can use: a
    /// provider on probation is admitted to **something**, and this is how much.
    pub cap_bps: u16,
    /// Why, in words.
    ///
    /// Carried for the same reason every other refusal in this workspace carries one: a provider
    /// held to 5% of the limit for reasons it cannot read is one that cannot work out how to
    /// graduate.
    pub because: String,
}

impl ColdStartAssessment {
    /// Whether a task worth `requested_bps` of the full limit is within what this provider may take.
    #[must_use]
    pub fn admits(&self, requested_bps: u16) -> bool {
        requested_bps <= self.cap_bps
    }

    /// The cap as a [`ReputationScore`], for a caller that wants the type rather than the number.
    #[must_use]
    pub fn cap(&self) -> ReputationScore {
        ReputationScore::clamped(self.cap_bps)
    }
}

impl ColdStartPolicy {
    /// What `reputation` may be trusted with.
    ///
    /// # The three cases, and why the order matters
    ///
    /// 1. **Past probation with an acceptable measurement record** — full admission. The provider has
    ///    been observed enough times, and what was measured was not bad.
    /// 2. **Past probation but found wanting** — the starter cap, not the full limit. A provider that
    ///    has been measured and found dishonest does not graduate by being measured often; that
    ///    would make the observation count a way to launder a bad record.
    /// 3. **On probation** — the cap, widened linearly by how far through probation it is. Linear
    ///    rather than stepped so that there is no threshold a provider can sit just below, and
    ///    integer throughout so that two nodes compute the same widening.
    ///
    /// # D-10's third criterion
    ///
    /// Pure: no clock, no state, no randomness. The same policy and the same reputation give the
    /// same assessment on every node, which is what makes it something a provider can check.
    #[must_use]
    pub fn assess(&self, reputation: &Reputation) -> ColdStartAssessment {
        let observed = reputation.observations;
        if observed >= u64::from(self.probation_observations) {
            if reputation.truthfulness.bps() >= self.full_admission_truthfulness_bps {
                return ColdStartAssessment {
                    full_admission: true,
                    cap_bps: 10_000,
                    because: format!(
                        "observed {observed} time(s), at or past the probation of {}, and measured \
                         at {} bps against a floor of {}",
                        self.probation_observations,
                        reputation.truthfulness.bps(),
                        self.full_admission_truthfulness_bps
                    ),
                };
            }
            return ColdStartAssessment {
                full_admission: false,
                cap_bps: self.starter_cap_bps,
                because: format!(
                    "observed {observed} time(s), past the probation of {}, but measured at {} bps \
                     against a floor of {}: a provider that has been measured and found wanting \
                     does not graduate by being measured often",
                    self.probation_observations,
                    reputation.truthfulness.bps(),
                    self.full_admission_truthfulness_bps
                ),
            };
        }

        // On probation. The cap widens from `starter_cap_bps` to the full limit as observations
        // accumulate, in integers, so that the arithmetic is the same everywhere.
        let steps = u64::from(self.probation_observations).max(1);
        let progress = observed.min(steps);
        let span = 10_000u64.saturating_sub(u64::from(self.starter_cap_bps));
        // Truncating division: the cap reaches the full limit only when probation is complete, which
        // the branch above handles. Reaching it a step early would be a cap that is not one.
        let widened = u64::from(self.starter_cap_bps) + span * progress / steps;
        let cap_bps = u16::try_from(widened.min(10_000)).unwrap_or(10_000);
        ColdStartAssessment {
            full_admission: false,
            cap_bps,
            because: format!(
                "on probation: {observed} of {} observations, so the cap is {cap_bps} bps rather \
                 than the full limit",
                self.probation_observations
            ),
        }
    }

    /// Whether `reputation` is past probation.
    #[must_use]
    pub fn is_past_probation(&self, reputation: &Reputation) -> bool {
        reputation.observations >= u64::from(self.probation_observations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::ResourceObservation;
    use crate::ResourceKind;

    const CHECKER: &str = "did:nau:0000000000000000";

    fn observed(times: u64, advertised: u64, measured: u64) -> Reputation {
        let mut r = Reputation::default();
        let observation =
            ResourceObservation::new(CHECKER, ResourceKind::Cpu, advertised, measured, 1)
                .expect("observation");
        for _ in 0..times {
            r.record_resource_observation(&observation);
        }
        r
    }

    #[test]
    fn a_brand_new_provider_is_admitted_to_something_rather_than_to_nothing() {
        // A market that admitted nobody without a history would have no way to acquire one, and the
        // first provider could never arrive. The cap is small and it is stated.
        let policy = ColdStartPolicy::default();
        let fresh = Reputation::default();
        let assessment = policy.assess(&fresh);
        assert!(!assessment.full_admission);
        assert_eq!(assessment.cap_bps, policy.starter_cap_bps);
        assert!(
            assessment.cap_bps > 0,
            "a zero cap is a market that cannot start"
        );
        assert!(assessment.admits(policy.starter_cap_bps));
        assert!(!assessment.admits(policy.starter_cap_bps + 1));
        assert!(
            assessment.because.contains("on probation"),
            "{}",
            assessment.because
        );
    }

    #[test]
    fn a_perfect_self_image_earns_exactly_nothing() {
        // D-10's first criterion, attacked from the angle that matters. Every dimension a provider
        // might hope to arrive with set to the maximum, and ZERO observations: the assessment is the
        // starter cap, identical to a provider that arrived claiming nothing.
        let policy = ColdStartPolicy::default();
        let boastful = Reputation {
            quality: ReputationScore::clamped(10_000),
            speed: ReputationScore::clamped(10_000),
            honesty: ReputationScore::clamped(10_000),
            availability: ReputationScore::clamped(10_000),
            truthfulness: ReputationScore::clamped(10_000),
            ..Reputation::default()
        };
        let assessment = policy.assess(&boastful);
        assert_eq!(
            assessment.cap_bps, policy.starter_cap_bps,
            "four perfect dimensions and no measurements must earn the starter cap and no more"
        );
        assert_eq!(assessment, policy.assess(&Reputation::default()));

        // And the reason is that `observations` is the only field this reads that a provider cannot
        // set: there is no `record_*` on `Reputation` that takes a number from outside.
        assert_eq!(boastful.observations, 0);
        assert!(!boastful.resources_have_been_observed());
    }

    #[test]
    fn the_cap_widens_with_observations_and_never_early() {
        let policy = ColdStartPolicy::default();
        let mut previous = 0u16;
        for count in 0..=u64::from(policy.probation_observations) {
            let assessment = policy.assess(&observed(count, 100, 100));
            if count < u64::from(policy.probation_observations) {
                assert!(
                    !assessment.full_admission,
                    "{count} observations must still be probation"
                );
                assert!(
                    assessment.cap_bps <= 10_000,
                    "and the cap must stay within the limit: {}",
                    assessment.cap_bps
                );
                assert!(
                    assessment.cap_bps >= previous,
                    "the cap must never shrink: {previous} -> {} at {count}",
                    assessment.cap_bps
                );
                previous = assessment.cap_bps;
            } else {
                // Only when probation is COMPLETE does the cap reach the limit. Reaching it a step
                // early would be a cap that is not one.
                assert!(
                    assessment.full_admission,
                    "probation is complete at {count}"
                );
                assert_eq!(assessment.cap_bps, 10_000);
            }
        }
        // Strictly widening while on probation, so there is no plateau a provider can sit on.
        let a = policy.assess(&observed(1, 100, 100)).cap_bps;
        let b = policy.assess(&observed(5, 100, 100)).cap_bps;
        assert!(b > a, "{a} -> {b}");
    }

    #[test]
    fn a_found_wanting_provider_does_not_graduate_by_being_measured_often() {
        // The case the ordering exists for. A provider measured fifty times and found to deliver a
        // tenth of what it claims is PAST probation and must still be held to the starter cap --
        // otherwise the observation count becomes a way to launder a bad record.
        let policy = ColdStartPolicy::default();
        let dishonest = observed(50, 100, 10);
        assert!(policy.is_past_probation(&dishonest));
        assert_eq!(dishonest.observations, 50, "it is past probation by count");
        let assessment = policy.assess(&dishonest);
        assert!(
            !assessment.full_admission,
            "and must not be admitted in full: {}",
            assessment.because
        );
        assert_eq!(assessment.cap_bps, policy.starter_cap_bps);
        assert!(
            assessment.because.contains("found wanting"),
            "{}",
            assessment.because
        );
    }

    #[test]
    fn the_same_history_gives_the_same_conclusion() {
        // D-10's third criterion. Pure: no clock, no state, no randomness -- so two nodes holding the
        // same observations about the same provider admit it to the same value of work, which is what
        // makes an admission something the provider can check rather than take on faith.
        let policy = ColdStartPolicy::default();
        for (times, advertised, measured) in [
            (0u64, 100u64, 100u64),
            (3, 100, 100),
            (10, 100, 100),
            (40, 100, 10),
        ] {
            let reputation = observed(times, advertised, measured);
            let first = policy.assess(&reputation);
            for _ in 0..8 {
                assert_eq!(policy.assess(&reputation), first, "assessment must be pure");
            }
        }
        // And the policy itself is `Copy`, so an assessment cannot depend on which clone was used.
        let copy = policy;
        assert_eq!(
            policy.assess(&observed(4, 100, 100)),
            copy.assess(&observed(4, 100, 100))
        );
    }

    #[test]
    fn a_measured_honest_provider_graduates_exactly_at_the_boundary() {
        // The floor is inclusive and the probation count is inclusive, so the boundary is stated
        // rather than discovered.
        //
        // # The mistake this test made, and what it taught
        //
        // The first version used a floor of 8_000 with three observations and expected full
        // admission. It failed: `smooth` moves a tenth of the remaining distance toward the target
        // each time, so three perfect observations take truthfulness from 5_000 to 5_500, 5_950,
        // 6_355 -- asymptotically approaching 10_000 and never arriving.
        //
        // That is the SAME misunderstanding v3.8.7's `9991` test recorded, and I made it again one
        // release later. The fix is not to lower the floor until the test passes; it is to state what
        // the smoothing actually does -- a floor near the top needs many observations, not three --
        // and to assert both sides of that.
        let policy = ColdStartPolicy {
            probation_observations: 3,
            starter_cap_bps: 1_000,
            full_admission_truthfulness_bps: 8_000,
        };
        let before = policy.assess(&observed(2, 100, 100));
        assert!(!before.full_admission);

        // Past probation by COUNT, but three perfect measurements only reach 6_355 -- so the
        // truthfulness branch holds it to the starter cap. Both conditions are required, and this is
        // the case where one is met and the other is not.
        let too_few = policy.assess(&observed(3, 100, 100));
        assert!(!too_few.full_admission, "{}", too_few.because);
        assert!(
            too_few.because.contains("found wanting"),
            "and the reason must say which condition held it: {}",
            too_few.because
        );
        assert!(
            observed(3, 100, 100).truthfulness.bps() < 8_000,
            "three observations cannot reach a floor of 8_000; smoothing is asymptotic"
        );

        // Enough observations, and it graduates.
        let graduated = policy.assess(&observed(60, 100, 100));
        assert!(graduated.full_admission, "{}", graduated.because);
        assert_eq!(graduated.cap_bps, 10_000);
        assert!(
            observed(60, 100, 100).truthfulness.bps() >= 8_000,
            "and sixty do reach it, got {}",
            observed(60, 100, 100).truthfulness.bps()
        );

        // A floor of NEUTRAL, by contrast, is met immediately: the boundary is about the number, not
        // about the branch.
        let low_bar = ColdStartPolicy {
            full_admission_truthfulness_bps: ReputationScore::NEUTRAL.bps(),
            ..policy
        };
        assert!(low_bar.assess(&observed(3, 100, 100)).full_admission);

        // A policy with no probation at all admits on the first assessment, which is a legitimate
        // configuration and not a special case.
        let none = ColdStartPolicy {
            probation_observations: 0,
            ..low_bar
        };
        assert!(none.assess(&Reputation::default()).full_admission);
    }

    #[test]
    fn the_assessment_round_trips_and_carries_its_reason() {
        let policy = ColdStartPolicy::default();
        let assessment = policy.assess(&observed(2, 100, 100));
        let text = serde_json::to_string(&assessment).expect("serialises");
        let back: ColdStartAssessment = serde_json::from_str(&text).expect("deserialises");
        assert_eq!(back, assessment);
        assert!(
            back.because.len() > 20,
            "a reason too short to be one: {}",
            back.because
        );
        assert_eq!(back.cap(), ReputationScore::clamped(back.cap_bps));
    }
}
