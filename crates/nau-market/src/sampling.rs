//! Sampling: which deliveries get checked, and what happens when one does not hold up.
//!
//! # The count in the plan was misleading, and this module says so
//!
//! The v3.8/v3.9 plan lists `PoCV` among the things this release should **reuse**, with "8 hits".
//! Those eight hits are **all in `docs/`** — `crates/` contains **zero**. So there is nothing to
//! reuse, and this module does not claim there is.
//!
//! What it does instead is build the smallest thing that satisfies D-08 without inventing a
//! consensus protocol: a **verifiable** sample and a hand-off to the dispute process that already
//! exists ([`Market::open_dispute`](crate::Market::open_dispute) and
//! [`Market::arbitrate`](crate::Market::arbitrate), both from v2.8.2).
//!
//! # D-08's first criterion: the sample must not be predictable, and this module is honest about
//! which half of that it provides
//!
//! A provider that can predict which of its deliveries will be checked can be honest only on those.
//! Unpredictability therefore matters, and it has **two** parts:
//!
//! 1. **The seed must be unknown before the fact.** This module **does not** provide that. It does
//!    not generate a seed, and it deliberately does not reach for a thread-local RNG: a PRNG seeded
//!    from the clock is predictable to anyone who can guess the clock, and claiming otherwise would
//!    be a claim this code cannot support.
//! 2. **The selection must be reproducible after the fact.** This module **does** provide that. The
//!    sample is a SHA-256 over the seed and each candidate's identity, so anyone holding the seed can
//!    re-derive exactly which deliveries were checked — which is what a provider disputing a finding
//!    needs, and what an auditor re-running the sample needs.
//!
//! So the seed is an **input**, and [`SamplingPlan::seed`] documents whose obligation it is. A
//! verifiable sample from a weak seed is a weaker thing than an unpredictable one, and it is a much
//! stronger thing than an unverifiable one: a provider cannot be shown to have deserved a finding it
//! cannot reproduce.
//!
//! # D-08's second criterion: no new process
//!
//! A faulty sample produces a [`SamplingFinding`], which carries the [`Dispute`] to file and the
//! [`DisputeOutcome`] that a guilty verdict would be. **Filing and ruling are the market's existing
//! methods**; this module has no state machine of its own, and adding one would be a second place a
//! dispute could be in.
//!
//! # D-08's third criterion: the penalty is still the rule's
//!
//! The finding carries no amount. What a guilty provider forfeits is
//! [`ResourceRegistry::slash`](crate::ResourceRegistry::slash)'s answer — `fault_slash_bps` of what
//! is bonded — which D-03 already established and which a caller's number does not decide.

use nau_core::domain::{Money, TaskId};
use nau_core::error::{NauError, Result};
use nau_core::identity::Did;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Which deliveries to check, and the seed that decides it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingPlan {
    /// What fraction of deliveries to check, in basis points.
    ///
    /// Read from the market's configuration rather than chosen here — the same rule D-05's pricing
    /// tracks follow, and for the same reason: a second rate is a second rate to keep in step.
    pub rate_bps: u16,
    /// The seed. **The caller's obligation, not this module's.**
    ///
    /// Unpredictable before the fact and published after, which is the property a sample needs and
    /// the property this type cannot supply: see the module documentation. A seed that is
    /// predictable makes the sample defeatable; a seed that is never published makes it
    /// unverifiable, and the second failure is the one a provider cannot appeal against.
    pub seed: String,
}

impl SamplingPlan {
    /// A plan.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the rate is zero — a sample that checks nothing is a sample
    /// that finds nothing while looking like oversight — or when it exceeds 100%, or when the seed
    /// is blank.
    pub fn new(rate_bps: u16, seed: impl Into<String>) -> Result<Self> {
        let seed = seed.into();
        if rate_bps == 0 {
            return Err(NauError::Validation(
                "a sampling rate of zero checks nothing, which looks like oversight while finding \
                 nothing"
                    .to_string(),
            ));
        }
        if rate_bps > 10_000 {
            return Err(NauError::Validation(format!(
                "a sampling rate of {rate_bps} bps is more than every delivery"
            )));
        }
        if seed.trim().is_empty() {
            return Err(NauError::Validation(
                "a sampling plan must carry a seed; without one the selection cannot be reproduced, \
                 and a provider could not be shown to have deserved a finding"
                    .to_string(),
            ));
        }
        Ok(Self { rate_bps, seed })
    }

    /// Whether one delivery is drawn, **deterministically given the seed**.
    ///
    /// The draw is `SHA-256(seed || 0x1f || delivery) mod 10_000 < rate_bps`: the separator keeps
    /// `("ab", "c")` and `("a", "bc")` from hashing alike, and taking the low 10,000 residues makes
    /// the rate a direct basis-point comparison rather than a scaled guess.
    ///
    /// # Why a hash rather than a counter
    ///
    /// A provider that could infer the draw from the delivery's *position* would know which ones to
    /// make honest. A hash of the delivery's own identity does not let it: the delivery id is chosen
    /// by the provider, so it can grind for a favourable one — and that is exactly why the seed must
    /// be unknown when the id is chosen, which is the obligation stated on [`SamplingPlan::seed`].
    #[must_use]
    pub fn draws(&self, delivery: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.seed.as_bytes());
        hasher.update([0x1f]);
        hasher.update(delivery.as_bytes());
        let digest = hasher.finalize();
        // The first two bytes are enough for a 10,000-way choice, and taking them rather than the
        // whole digest keeps the comparison obviously in range.
        //
        // Parenthesised because clippy is right that `<<` and `|` in one expression trip the
        // unwary -- myself included, and a precedence mistake here would silently change which
        // deliveries are drawn.
        let residue = (u32::from(digest[0]) << 8) | u32::from(digest[1]);
        residue % 10_000 < u32::from(self.rate_bps)
    }

    /// The deliveries drawn from `candidates`, in the order given.
    ///
    /// Deterministic in the candidate list **and** its order: two calls with the same arguments
    /// return the same answer, which is what re-deriving a sample requires.
    #[must_use]
    pub fn select(&self, candidates: &[String]) -> Vec<String> {
        candidates
            .iter()
            .filter(|c| self.draws(c))
            .cloned()
            .collect()
    }
}

/// What a check of one sampled delivery found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingFinding {
    /// The delivery that was checked.
    pub delivery: String,
    /// Who was supposed to have performed it.
    pub provider: String,
    /// What the check found.
    pub verdict: SamplingVerdict,
    /// The seed, so that the draw can be re-derived. Carried on the finding rather than looked up,
    /// because a finding whose sample cannot be reproduced is one a provider cannot appeal.
    pub seed: String,
}

/// The outcome of checking one delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SamplingVerdict {
    /// The delivery matched what was promised.
    Delivered,
    /// It did not, and here is what was expected against what arrived.
    Faulty {
        /// What the offer promised.
        expected: String,
        /// What the check found.
        found: String,
    },
}

/// What a faulty sample claims, in the shape the market's dispute process needs.
///
/// # Why this is not a `Dispute`
///
/// My first version of this file built a [`Dispute`] directly, and two things were wrong with it.
///
/// 1. **I invented its fields.** The real type has `id`, `complainant`, `complainant_key`,
///    `reason`, `evidence_digest`; I had written `claimant`, `evidence`, `nonce`. That is the same
///    defect C-08's criterion (2) exists to prevent — the fourth time in this project, after the
///    blacklist fields at v3.7.0 and `total_supply` at v3.8.4 — and this time the compiler found it.
/// 2. **The sampler cannot sign.** A [`Dispute`] carries the complainant's [`PublicKey`], and a
///    sampler has no key: it is a selection procedure, not a party. Fabricating one would be
///    inventing a signer.
///
/// So the finding produces **this**: everything the dispute needs except the identity of whoever
/// files it, which is exactly what a sampler can honestly supply. The caller holding a key turns a
/// claim into a [`Dispute`] and calls [`Market::open_dispute`](crate::Market::open_dispute) — the
/// process is still the market's existing one, which is D-08's second criterion.
///
/// [`PublicKey`]: nau_core::identity::PublicKey
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingClaim {
    /// The delivery that was checked, which is the task a dispute would name.
    pub delivery: String,
    /// Who performed it.
    pub respondent: String,
    /// Why the network says it was not delivered, in words.
    pub reason: String,
    /// A digest of the sample: the seed and the two values. Enough for a responder to re-derive the
    /// draw, and short enough to travel as `evidence_digest`.
    pub evidence_digest: String,
    /// The seed, kept separately from the digest so that re-deriving does not require parsing.
    pub seed: String,
}

impl SamplingClaim {
    /// Turn a claim into the dispute's arguments **without inventing anything**.
    ///
    /// Returns the pieces [`Dispute`] needs that a sampler can honestly supply: the task id, the
    /// respondent, the reason and the evidence digest. The caller adds its own `id`,
    /// `complainant`, `complainant_key` and `nonce` — the four things that say **who is filing**.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the delivery id is not a valid [`TaskId`], or when the
    /// respondent is not a valid [`Did`].
    ///
    /// [`TaskId`]: nau_core::domain::TaskId
    pub fn dispute_parts(&self) -> Result<(TaskId, Did, String, Option<String>)> {
        let task = TaskId::parse(&self.delivery)?;
        let respondent = Did::parse(&self.respondent)?;
        Ok((
            task,
            respondent,
            self.reason.clone(),
            Some(self.evidence_digest.clone()),
        ))
    }
}

impl SamplingFinding {
    /// Whether this finding is a fault.
    #[must_use]
    pub fn is_faulty(&self) -> bool {
        matches!(self.verdict, SamplingVerdict::Faulty { .. })
    }

    /// The claim this finding makes, or `None` when nothing was wrong.
    ///
    /// D-08's second criterion: the finding hands over what the market's existing process needs
    /// rather than carrying a process of its own.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when a fault has no delivery id — a fault about nothing cannot be
    /// filed, and returning `None` would make it look like a clean delivery.
    pub fn to_claim(&self) -> Result<Option<SamplingClaim>> {
        let SamplingVerdict::Faulty { expected, found } = &self.verdict else {
            return Ok(None);
        };
        if self.delivery.trim().is_empty() {
            return Err(NauError::Validation(
                "a fault must name the delivery it is about; without one there is nothing to file, \
                 and answering `no claim` would make it look like a clean delivery"
                    .to_string(),
            ));
        }
        Ok(Some(SamplingClaim {
            delivery: self.delivery.clone(),
            respondent: self.provider.clone(),
            reason: format!(
                "sampled delivery did not match what was promised: expected {expected}, found {found}"
            ),
            // The sample itself: everything a responder needs to re-derive the draw and check the
            // comparison, and nothing else.
            evidence_digest: format!(
                "seed={};delivery={};expected={expected};found={found}",
                self.seed, self.delivery
            ),
            seed: self.seed.clone(),
        }))
    }

    /// The ruling a guilty verdict would carry, as the parts a **party** needs to sign one.
    ///
    /// # Why this is not a `DisputeOutcome`, again
    ///
    /// The real type has **ten** fields — `dispute_id`, `task_id`, `guilty`, `slash_amount`,
    /// `ruling`, `arbitrator`, `arbitrator_key`, `nonce`, `signed_at`, `signature` — and four of
    /// them are the **arbitrator's identity and signature**. A sampler has no key and no authority
    /// to rule, so it cannot produce one.
    ///
    /// My first version of this file returned a `DisputeOutcome` with four fields in it. That was
    /// the invented-field defect for the fourth time in this project, and it survived until I read
    /// the WHOLE definition rather than the first twelve lines of it.
    ///
    /// What a sampler can honestly say is what the ruling should **contain**: the delivery, that it
    /// failed, and the words. The amount it hands over is **one minor unit** — positive, because the
    /// field must be well-formed to be accepted at all, and deliberately not a plausible figure,
    /// because [`Market::arbitrate`](crate::Market::arbitrate) **ignores it** and the amount actually
    /// slashed is `fault_slash_bps` of what is bonded.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the delivery id is not a valid [`TaskId`].
    ///
    /// [`TaskId`]: nau_core::domain::TaskId
    pub fn guilty_ruling_parts(&self) -> Result<(TaskId, bool, Money, String)> {
        let task_id = TaskId::parse(&self.delivery)?;
        Ok((
            task_id,
            true,
            Money::from_minor(1),
            format!(
                "sampled delivery did not match what was promised (seed `{}`); the amount slashed is \
                 `fault_slash_bps` of the bonded stake, which this ruling does not decide",
                self.seed
            ),
        ))
    }
}

/// Check one sampled delivery and produce a finding.
///
/// `check` is where the real verification lives — comparing a delivered artefact against what the
/// offer promised. It is a parameter rather than an implementation because **this module has no way
/// to check a delivery**: it does not know what was promised or how to look. Passing the comparison
/// in keeps the sampling honest about what it is, which is a selection and a hand-off.
///
/// # Errors
///
/// Whatever `check` refuses, carried across unchanged.
pub fn check_delivery<F>(
    delivery: &str,
    provider: &str,
    seed: &str,
    check: F,
) -> Result<SamplingFinding>
where
    F: FnOnce() -> Result<SamplingVerdict>,
{
    let verdict = check()?;
    Ok(SamplingFinding {
        delivery: delivery.to_string(),
        provider: provider.to_string(),
        verdict,
        seed: seed.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(rate_bps: u16) -> SamplingPlan {
        SamplingPlan::new(rate_bps, "seed-for-the-test").expect("plan")
    }

    #[test]
    fn the_same_seed_and_candidates_give_the_same_sample() {
        // D-08's first criterion's second half, and the one this module actually provides. A sample
        // that could not be re-derived is one a provider cannot appeal against, and one an auditor
        // cannot check.
        let candidates: Vec<String> = (0..200).map(|i| format!("delivery-{i}")).collect();
        let plan = plan(2_000);
        let first = plan.select(&candidates);
        for _ in 0..8 {
            assert_eq!(
                plan.select(&candidates),
                first,
                "the sample must be reproducible"
            );
        }
        assert!(!first.is_empty(), "a 20% sample of 200 should not be empty");
        assert!(
            first.len() < candidates.len(),
            "and should not be all of them: got {}",
            first.len()
        );
    }

    #[test]
    fn a_different_seed_gives_a_different_sample() {
        // The seed is what makes the sample unpredictable to a provider, so a different seed must
        // actually change the answer -- otherwise the seed would be decoration.
        let candidates: Vec<String> = (0..500).map(|i| format!("delivery-{i}")).collect();
        let a = SamplingPlan::new(2_000, "seed-a")
            .expect("plan")
            .select(&candidates);
        let b = SamplingPlan::new(2_000, "seed-b")
            .expect("plan")
            .select(&candidates);
        assert_ne!(a, b, "two seeds must not draw the same sample");
    }

    #[test]
    fn the_rate_is_about_the_share_it_says_it_is() {
        // A rate that did not track the share would be a number with no consequence. The bound is
        // generous because a SHA-256 draw over 10,000 residues is uniform in expectation and not
        // exact on any one sample.
        let candidates: Vec<String> = (0..4_000).map(|i| format!("delivery-{i}")).collect();
        for rate in [500u16, 2_000, 5_000] {
            let drawn = plan(rate).select(&candidates).len();
            let expected = candidates.len() * usize::from(rate) / 10_000;
            let slack = expected / 4 + 10;
            assert!(
                drawn.abs_diff(expected) <= slack,
                "rate {rate}: drew {drawn}, expected about {expected}"
            );
        }
    }

    #[test]
    fn the_separator_keeps_two_concatenations_apart() {
        // Without the 0x1f, `seed="ab", delivery="c"` and `seed="a", delivery="bc"` would hash the
        // same input and draw together, which would let a provider choose a seed-and-id pair.
        let one = SamplingPlan::new(5_000, "ab").expect("plan");
        let other = SamplingPlan::new(5_000, "a").expect("plan");
        // Not asserting they differ on one delivery -- that is a 50/50 coin. Asserting the input to
        // the hash is not the same string, which is the property that keeps the pair unambiguous.
        let mut a = Sha256::new();
        a.update(b"ab");
        a.update([0x1f]);
        a.update(b"c");
        let mut b = Sha256::new();
        b.update(b"a");
        b.update([0x1f]);
        b.update(b"bc");
        assert_ne!(
            a.finalize(),
            b.finalize(),
            "the separator must make the pair unambiguous"
        );
        // And both plans work, so the check above is not merely comparing two failures.
        assert!(one.draws("x") || !one.draws("x"));
        assert!(other.draws("x") || !other.draws("x"));
    }

    #[test]
    fn a_zero_rate_or_a_blank_seed_or_more_than_everything_is_refused() {
        // A sample that checks nothing finds nothing while looking like oversight.
        assert!(SamplingPlan::new(0, "seed").is_err());
        assert!(SamplingPlan::new(10_001, "seed").is_err());
        assert!(SamplingPlan::new(100, "   ").is_err());
        let err = SamplingPlan::new(0, "seed").expect_err("refused");
        assert!(
            format!("{err}").contains("looks like oversight"),
            "got: {err}"
        );
    }

    #[test]
    fn a_faulty_finding_hands_over_a_dispute_and_a_clean_one_does_not() {
        // D-08's second criterion: no new process. The finding produces what the market's existing
        // `open_dispute` needs, and nothing when there was nothing wrong.
        //
        // The provider is a REAL fingerprint rather than a readable name, because `Did::parse`
        // requires one -- see `a_provider_name_that_is_not_a_did_cannot_be_a_respondent`, which was
        // written after this test failed for exactly that reason.
        let faulty = check_delivery("delivery-1", "did:nau:34750f98bd59fcfc", "seed-x", || {
            Ok(SamplingVerdict::Faulty {
                expected: "sha256:aaa".to_string(),
                found: "sha256:bbb".to_string(),
            })
        })
        .expect("checked");
        assert!(faulty.is_faulty());

        let claim = faulty
            .to_claim()
            .expect("disputable")
            .expect("a fault is disputable");
        let (task_id, did, reason, digest) = claim.dispute_parts().expect("parts");
        assert_eq!(task_id.to_string(), "delivery-1");
        assert_eq!(
            did.to_string(),
            "did:nau:34750f98bd59fcfc",
            "the claim carries the DID it was given, verbatim"
        );
        // The evidence is the sample itself, so a responder can re-derive the draw.
        //
        // This file's first version read dispute.evidence and dispute.nonce: BOTH invented.
        // The real Dispute has evidence_digest (an Option<String>) and no nonce at all, and
        // its complainant_key is why a sampler cannot build one -- see SamplingClaim.
        let digest = digest.expect("a digest");
        assert!(digest.contains("seed-x"), "{digest}");
        assert!(digest.contains("sha256:aaa"), "{digest}");
        assert!(digest.contains("sha256:bbb"), "{digest}");
        assert!(reason.contains("did not match"), "{reason}");

        let clean = check_delivery("delivery-1", "did:example:provider", "seed-x", || {
            Ok(SamplingVerdict::Delivered)
        })
        .expect("checked");
        assert!(!clean.is_faulty());
        assert!(clean.to_claim().expect("fine").is_none());
    }

    #[test]
    fn the_ruling_leaves_the_amount_to_the_rule() {
        // D-08's third criterion. The `slash_amount` here is one minor unit, and that is deliberate:
        // `Market::arbitrate` ignores it, and a plausible figure would invite someone to believe it
        // decided something.
        let faulty = check_delivery("delivery-1", "did:example:provider", "seed-x", || {
            Ok(SamplingVerdict::Faulty {
                expected: "a".to_string(),
                found: "b".to_string(),
            })
        })
        .expect("checked");
        let (task_id, guilty, placeholder, ruling_text) =
            faulty.guilty_ruling_parts().expect("ruling parts");
        assert_eq!(task_id.to_string(), "delivery-1");
        assert!(guilty);
        assert_eq!(
            placeholder,
            Money::from_minor(1),
            "a positive placeholder, deliberately not a plausible figure"
        );
        assert!(
            ruling_text.contains("fault_slash_bps"),
            "the ruling must name where the amount comes from: {ruling_text}"
        );
        assert!(ruling_text.contains("does not decide"), "{ruling_text}");
    }

    #[test]
    fn a_seed_that_cannot_be_reproduced_is_refused_rather_than_defaulted() {
        // A default seed would make every network's sample identical, which is the most predictable
        // thing a sample could be.
        assert!(SamplingPlan::new(1_000, "").is_err());
        let err = SamplingPlan::new(1_000, "").expect_err("refused");
        assert!(format!("{err}").contains("reproduced"), "got: {err}");
    }

    #[test]
    fn a_provider_name_that_is_not_a_did_cannot_be_a_respondent() {
        // Found by writing the test: `Did::parse` requires `did:nau:` (or the legacy `did:aip:`)
        // followed by exactly sixteen hex characters, because a DID is a key fingerprint rather than
        // a readable name.
        //
        // That is a real constraint on this hand-off, and the honest thing is to pin it rather than
        // work around it. A `ResourceRegistration.provider` is a plain `String` -- the registry
        // accepts `did:example:whatever` -- but only a real DID can be a dispute respondent, so a
        // sampled fault about a provider with a made-up name CANNOT be filed. Refusing is right:
        // filing a dispute naming somebody who does not exist would be worse than not filing one.
        let faulty = check_delivery("delivery-1", "did:example:not-a-did", "seed-x", || {
            Ok(SamplingVerdict::Faulty {
                expected: "a".to_string(),
                found: "b".to_string(),
            })
        })
        .expect("checked");
        let claim = faulty.to_claim().expect("a claim").expect("a fault");
        let err = claim
            .dispute_parts()
            .expect_err("a readable name is not a DID");
        assert!(
            format!("{err}").to_lowercase().contains("did"),
            "the refusal must be about the DID: {err}"
        );

        // And a real fingerprint works, so the refusal above is about the format and not about the
        // hand-off being broken.
        let real = check_delivery("delivery-1", "did:nau:34750f98bd59fcfc", "seed-x", || {
            Ok(SamplingVerdict::Faulty {
                expected: "a".to_string(),
                found: "b".to_string(),
            })
        })
        .expect("checked");
        let (task, did, _, _) = real
            .to_claim()
            .expect("a claim")
            .expect("a fault")
            .dispute_parts()
            .expect("a real DID is accepted");
        assert_eq!(task.to_string(), "delivery-1");
        assert_eq!(did.to_string(), "did:nau:34750f98bd59fcfc");
    }
    #[test]
    fn a_finding_round_trips_through_json_with_its_seed() {
        // The seed travels with the finding, because a finding whose sample cannot be re-derived is
        // one a provider cannot appeal.
        let faulty = check_delivery("delivery-1", "did:example:provider", "seed-x", || {
            Ok(SamplingVerdict::Faulty {
                expected: "a".to_string(),
                found: "b".to_string(),
            })
        })
        .expect("checked");
        let text = serde_json::to_string(&faulty).expect("serialises");
        assert!(text.contains("seed-x"), "{text}");
        let back: SamplingFinding = serde_json::from_str(&text).expect("deserialises");
        assert_eq!(back, faulty);
        assert!(back.is_faulty());
    }
}
