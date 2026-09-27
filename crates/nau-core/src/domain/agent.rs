//! Agent identity cards and reputation.
//!
//! Contrast with upstream v2.5.6 (`marketplace/agent_card.rs:60-100`), which has
//! 21 all-`pub` fields, `stake: f64`, `reputation_score: f64`, **no public key
//! and no signature**, and whose `register_agent` validation
//! (`marketplace/mod.rs:116-148`) checks exactly three things: `agent_id` is
//! non-empty, `name` is non-empty, and `stake >= min_stake`.
//!
//! Concretely, upstream therefore accepts: a card whose `agent_id` is not a DID
//! at all; two cards with the same id (the `HashMap::insert` silently
//! overwrites, while `stake` is *also* deposited again — an audit finding);
//! `stake = NaN` (because `NaN < 100.0` is `false`); a negative price; and a
//! card whose owner is the empty string. Here, [`AgentCard::validate`] checks
//! every invariant, and the card is self-verifying because it carries the key
//! that must fingerprint its DID.

use serde::{Deserialize, Serialize};

use crate::domain::money::Money;
use crate::domain::Verifiable;
use crate::error::{NauError, Result};
use crate::identity::{Did, Identity, PublicKey};

/// A capability the agent claims, with a version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skill {
    /// Stable machine identifier, e.g. `text-generation`. Lowercased on insert.
    pub id: String,
    /// Capability revision; a higher number supersedes a lower one.
    pub version: u32,
    /// Optional human description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Skill {
    /// Build a skill.
    pub fn new(id: impl Into<String>, version: u32) -> Self {
        Self {
            id: id.into().to_ascii_lowercase(),
            version,
            description: None,
        }
    }

    /// Attach a description.
    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    /// Validation: the id must be a non-empty lowercase token.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(NauError::Validation("skill id must not be empty".into()));
        }
        if self.id.len() > 64 {
            return Err(NauError::Validation(format!(
                "skill id `{}` is longer than 64 characters",
                self.id
            )));
        }
        if self.id != self.id.to_ascii_lowercase() {
            return Err(NauError::Validation(format!(
                "skill id `{}` must be lowercase (skill lookup lowercases queries)",
                self.id
            )));
        }
        Ok(())
    }
}

/// How an agent charges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingModel {
    /// One price per task, agreed at bid time.
    Fixed,
    /// Price per unit of [`PricingUnit`].
    PerUnit,
    /// Price discovered by auction; `unit_price` is the reserve.
    Auction,
}

/// What a per-unit price is counted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingUnit {
    /// Whole task.
    Task,
    /// Per 1000 language-model tokens.
    KiloToken,
    /// Per second of wall clock.
    Second,
    /// Per mebibyte of data.
    Mebibyte,
}

/// An advertised price.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pricing {
    /// Charging model.
    pub model: PricingModel,
    /// Exact price in minor units. Never negative.
    pub unit_price: Money,
    /// Unit the price is counted in.
    pub unit: PricingUnit,
}

impl Default for Pricing {
    fn default() -> Self {
        Self {
            model: PricingModel::Auction,
            unit_price: Money::ZERO,
            unit: PricingUnit::Task,
        }
    }
}

impl Pricing {
    /// Validation: prices are never negative.
    pub fn validate(&self) -> Result<()> {
        if self.unit_price.is_negative() {
            return Err(NauError::InvalidAmount(format!(
                "unit_price {} must not be negative",
                self.unit_price.to_decimal_string()
            )));
        }
        Ok(())
    }
}

/// Advertised service level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sla {
    /// 95th-percentile latency the agent claims, in milliseconds.
    pub latency_p95_ms: u64,
    /// Availability in basis points (10000 = 100%).
    pub availability_bps: u16,
    /// Maximum concurrent tasks the agent accepts.
    pub max_concurrency: u32,
}

impl Default for Sla {
    fn default() -> Self {
        Self {
            latency_p95_ms: 2_000,
            availability_bps: 9_500,
            max_concurrency: 10,
        }
    }
}

impl Sla {
    /// Validation: basis points are bounded and concurrency is non-zero.
    pub fn validate(&self) -> Result<()> {
        if self.availability_bps > 10_000 {
            return Err(NauError::Validation(format!(
                "availability_bps {} exceeds 10000",
                self.availability_bps
            )));
        }
        if self.max_concurrency == 0 {
            return Err(NauError::Validation(
                "max_concurrency must be at least 1 (a node that accepts nothing cannot be matched)"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Coarse category, used for discovery grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCategory {
    /// General purpose.
    General,
    /// Language and translation.
    Language,
    /// Vision and multimodal.
    Vision,
    /// Code generation and review.
    Code,
    /// Data processing and analysis.
    Data,
    /// Infrastructure and operations.
    Infrastructure,
    /// Research and retrieval.
    Research,
    /// Anything else.
    Other,
}

/// A reputation score in basis points, `0..=10000`.
///
/// A newtype rather than a bare `f64`/`u16` so that "is this in range?" is
/// answered once, at construction, instead of at every use site. Upstream stores
/// reputation as `f64` and compares it with `partial_cmp(..).unwrap()` in two
/// places, which panics if a `NaN` ever reaches the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReputationScore(u16);

impl ReputationScore {
    /// The maximum possible score (100.00%).
    pub const MAX_BPS: u16 = 10_000;
    /// The neutral starting score (50.00%).
    pub const NEUTRAL: ReputationScore = ReputationScore(5_000);

    /// Construct from basis points, rejecting anything above [`Self::MAX_BPS`].
    pub fn from_bps(bps: u16) -> Result<Self> {
        if bps > Self::MAX_BPS {
            return Err(NauError::Validation(format!(
                "reputation {bps} bps exceeds the maximum of {}",
                Self::MAX_BPS
            )));
        }
        Ok(Self(bps))
    }

    /// Construct from basis points, clamping into range instead of failing.
    pub const fn clamped(bps: u16) -> Self {
        Self(if bps > Self::MAX_BPS {
            Self::MAX_BPS
        } else {
            bps
        })
    }

    /// The score in basis points.
    pub const fn bps(self) -> u16 {
        self.0
    }

    /// The score as a ratio in `0.0..=1.0`, for scoring formulas.
    pub fn ratio(self) -> f64 {
        f64::from(self.0) / f64::from(Self::MAX_BPS)
    }
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self::NEUTRAL
    }
}

/// A published agent identity card.
///
/// The card carries `owner_key`, so [`Verifiable::verify`] can check the
/// signature *and* that the key fingerprints `owner` without any out-of-band
/// lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCard {
    /// The agent's DID; also the signing identity.
    pub owner: Did,
    /// The public key that must fingerprint `owner`.
    pub owner_key: PublicKey,
    /// Human-facing name.
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Coarse category.
    pub category: AgentCategory,
    /// Claimed capabilities. Must be non-empty.
    pub skills: Vec<Skill>,
    /// Advertised price.
    pub pricing: Pricing,
    /// Advertised service level.
    pub sla: Sla,
    /// Stake locked behind the card, in minor units. Must be positive.
    pub stake: Money,
    /// Reachable endpoints (informational; the DHT is authoritative).
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// When the card was signed (Unix seconds).
    pub signed_at: u64,
    /// Optional expiry. Cards may be perpetual.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Replay-protection nonce; must strictly increase per owner.
    pub nonce: u64,
    /// Hex Ed25519 signature over the canonical payload.
    #[serde(default)]
    pub signature: String,
}

impl AgentCard {
    /// A minimal card owned by `identity`, with the signature not yet applied.
    pub fn draft(
        identity: &Identity,
        name: impl Into<String>,
        skills: Vec<Skill>,
        stake: Money,
        signed_at: u64,
        nonce: u64,
    ) -> Self {
        Self {
            owner: identity.did(),
            owner_key: identity.public_key(),
            name: name.into(),
            description: None,
            category: AgentCategory::General,
            skills,
            pricing: Pricing::default(),
            sla: Sla::default(),
            stake,
            endpoints: Vec::new(),
            signed_at,
            expires_at: None,
            nonce,
            signature: String::new(),
        }
    }

    /// Check every structural invariant. Returns the first failure.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(NauError::Validation("agent name must not be empty".into()));
        }
        if self.name.len() > 128 {
            return Err(NauError::Validation(
                "agent name must be at most 128 characters".into(),
            ));
        }
        if self.skills.is_empty() {
            return Err(NauError::Validation(
                "an agent must declare at least one skill to be discoverable".into(),
            ));
        }
        for skill in &self.skills {
            skill.validate()?;
        }
        // Duplicate skills would double-count in the discovery index.
        let mut seen = std::collections::HashSet::new();
        for skill in &self.skills {
            if !seen.insert(skill.id.clone()) {
                return Err(NauError::Validation(format!(
                    "duplicate skill `{}` in one card",
                    skill.id
                )));
            }
        }
        self.pricing.validate()?;
        self.sla.validate()?;
        if !self.stake.is_positive() {
            return Err(NauError::InvalidAmount(
                "stake must be greater than zero for a card to be admissible".into(),
            ));
        }
        if !self.owner.matches_public_key(&self.owner_key) {
            return Err(NauError::DidKeyMismatch {
                did: self.owner.to_string(),
            });
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.signed_at {
                return Err(NauError::Validation(format!(
                    "expires_at {expires_at} must be after signed_at {}",
                    self.signed_at
                )));
            }
        }
        Ok(())
    }

    /// Validate, then verify the signature.
    pub fn validate_and_verify(&self) -> Result<()> {
        self.validate()?;
        self.verify()
    }

    /// Validate, verify, and check freshness against `now`.
    pub fn validate_verified_fresh(&self, now: u64) -> Result<()> {
        self.validate()?;
        self.verify_fresh(now)
    }
}

impl Verifiable for AgentCard {
    fn signer(&self) -> &Did {
        &self.owner
    }
    fn signer_key(&self) -> &PublicKey {
        &self.owner_key
    }
    fn signature(&self) -> &str {
        &self.signature
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn signed_at(&self) -> u64 {
        self.signed_at
    }
    fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::money::major;

    fn identity() -> Identity {
        Identity::from_seed(&[7u8; 32])
    }

    fn valid_card() -> AgentCard {
        AgentCard::draft(
            &identity(),
            "Translator",
            vec![Skill::new("translation", 1)],
            major(100),
            1_700_000_000,
            1,
        )
    }

    #[test]
    fn a_well_formed_card_signs_and_verifies() {
        let id = identity();
        let mut card = valid_card();
        card.sign(&id).unwrap();
        assert!(card.verify().is_ok());
        assert!(card.validate_verified_fresh(1_700_000_100).is_ok());
    }

    #[test]
    fn card_with_no_skills_is_rejected() {
        let mut card = valid_card();
        card.skills.clear();
        assert!(card.validate().is_err());
    }

    #[test]
    fn zero_or_negative_stake_is_rejected() {
        let mut card = valid_card();
        card.stake = Money::ZERO;
        assert!(card.validate().is_err());
        card.stake = Money::from_minor(-1);
        assert!(card.validate().is_err());
    }

    #[test]
    fn negative_price_is_rejected() {
        let mut card = valid_card();
        card.pricing.unit_price = Money::from_minor(-5);
        assert!(card.validate().is_err());
    }

    #[test]
    fn a_card_cannot_claim_someone_elses_did() {
        // Owner DID belongs to a different key -> binding check must fail.
        let mut card = valid_card();
        card.owner = Identity::from_seed(&[9u8; 32]).did();
        let err = card.validate().unwrap_err();
        assert!(
            matches!(err, NauError::DidKeyMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn signing_as_another_identity_is_refused() {
        let mut card = valid_card();
        let impostor = Identity::from_seed(&[3u8; 32]);
        let err = card.sign(&impostor).unwrap_err();
        assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");
    }

    #[test]
    fn duplicate_skills_are_rejected() {
        let mut card = valid_card();
        card.skills.push(Skill::new("translation", 2));
        assert!(card.validate().is_err());
    }

    #[test]
    fn uppercase_skill_ids_are_rejected_to_keep_the_index_sound() {
        let mut card = valid_card();
        card.skills = vec![Skill {
            id: "Translation".into(),
            version: 1,
            description: None,
        }];
        assert!(card.validate().is_err());
    }

    #[test]
    fn expiry_must_be_after_signing() {
        let mut card = valid_card();
        card.expires_at = Some(card.signed_at);
        assert!(card.validate().is_err());
        card.expires_at = Some(card.signed_at + 1);
        assert!(card.validate().is_ok());
    }

    #[test]
    fn expired_cards_fail_the_freshness_check_but_not_the_signature_check() {
        let id = identity();
        let mut card = valid_card();
        card.expires_at = Some(1_700_000_500);
        card.sign(&id).unwrap();
        assert!(card.verify().is_ok(), "signature itself is still valid");
        let err = card.verify_fresh(1_700_001_000).unwrap_err();
        assert!(matches!(err, NauError::Stale(_)), "got {err:?}");
    }

    #[test]
    fn reputation_is_range_checked_where_upstream_would_panic_later() {
        assert!(ReputationScore::from_bps(10_000).is_ok());
        assert!(ReputationScore::from_bps(10_001).is_err());
        assert_eq!(ReputationScore::clamped(60_000).bps(), 10_000);
        assert_eq!(ReputationScore::default().bps(), 5_000);
        assert!((ReputationScore::NEUTRAL.ratio() - 0.5).abs() < f64::EPSILON);
    }
}
