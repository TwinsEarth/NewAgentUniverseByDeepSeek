//! Domain model: agents, tasks, bids, results, disputes, evidence.
//!
//! Every structure that travels over the wire and carries a `signature` field
//! implements [`Verifiable`], which gives it:
//!
//! * `sign(&Identity)` — sign the canonical payload;
//! * `verify()` — check the signature **and** that the claimed DID fingerprints
//!   the supplied public key;
//! * `verify_fresh(now)` — additionally enforce expiry and clock-skew bounds.
//!
//! Two deliberate departures from upstream v2.5.6:
//!
//! 1. **Signed structures carry their own public key.** Upstream signs an
//!    `AgentCard` containing a `did` but no key, so verification requires the key
//!    to arrive out of band and nothing forces it to match the DID. Embedding
//!    `signer_key` makes every artifact self-verifying, and the binding check in
//!    `verify()` is what stops an attacker from re-labelling their own key with
//!    someone else's DID.
//! 2. **Every signed structure carries `nonce` + `signed_at` (+ optional
//!    `expires_at`).** Upstream's cards, bids and results have no nonce and no
//!    timestamp, so a captured message can be replayed forever. Freshness is
//!    enforced in [`Verifiable::verify_fresh`].

pub mod agent;
pub mod money;
pub mod org;
pub mod task;

use serde::Serialize;

use crate::error::{NauError, Result};
use crate::identity::{verify_payload_bound, Did, Identity, PublicKey};

pub use agent::{
    AgentCard, AgentCategory, Pricing, PricingModel, PricingUnit, ReputationScore, Skill, Sla,
};
pub use money::{major, Money, CURRENCY, DECIMALS, MINOR_UNITS_PER_MAJOR};
pub use org::{AgentOrg, OrgAction, OrgId, OrgMember, OrgRole, Quota};
pub use task::{
    Bid, Dispute, DisputeOutcome, EvidenceGrade, ResultEnvelope, Task, TaskId, TaskSpec, TaskState,
    VerificationPolicy, SIX_FIELDS,
};

/// Tolerated clock skew, in seconds, when validating freshness.
///
/// Two nodes never agree on the time exactly, so `signed_at` slightly in the
/// future is accepted; anything beyond this is treated as a forgery or a
/// badly-broken clock.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// A signed, self-describing domain object.
///
/// `Clone` is a supertrait because signing works by cloning the value, blanking
/// the signature, and hashing the canonical form of the result.
pub trait Verifiable: Serialize + Clone + Sized {
    /// The DID that claims authorship.
    fn signer(&self) -> &Did;

    /// The public key that must fingerprint [`Verifiable::signer`].
    fn signer_key(&self) -> &PublicKey;

    /// The detached hex signature over the canonical payload.
    fn signature(&self) -> &str;

    /// The nonce that makes this instance unique (replay protection).
    fn nonce(&self) -> u64;

    /// When the signature was produced (Unix seconds).
    fn signed_at(&self) -> u64;

    /// When the object stops being valid, if it ever does.
    fn expires_at(&self) -> Option<u64>;

    /// Replace the signature field. Implementors assign `self.signature = s`.
    fn set_signature(&mut self, signature: String);

    /// Sign the canonical payload of `self` with `identity` and store the
    /// signature.
    ///
    /// Fails if `identity`'s DID is not the `signer` this object claims — signing
    /// on behalf of someone else is never legitimate.
    fn sign(&mut self, identity: &Identity) -> Result<()> {
        if &identity.did() != self.signer() {
            return Err(NauError::Unauthorized(format!(
                "cannot sign as `{}` with the key for `{}`",
                self.signer(),
                identity.did()
            )));
        }
        if self.signer_key() != &identity.public_key() {
            return Err(NauError::Unauthorized(
                "signer_key does not match the signing identity's public key".into(),
            ));
        }
        // Sign with the signature field cleared so that the payload matches what
        // a verifier will reconstruct (canonicalization also drops the field, so
        // this is belt-and-braces).
        let mut unsigned = self.clone_for_signing();
        unsigned.set_signature(String::new());
        let signature = identity.sign_payload(&unsigned)?;
        self.set_signature(signature);
        Ok(())
    }

    /// Verify the signature and the DID↔key binding.
    fn verify(&self) -> Result<()> {
        if self.signature().is_empty() {
            return Err(NauError::InvalidSignature);
        }
        verify_payload_bound(self, self.signature(), self.signer_key(), self.signer())
    }

    /// [`Verifiable::verify`] plus freshness: not expired, not from the future.
    fn verify_fresh(&self, now: u64) -> Result<()> {
        self.verify()?;
        self.check_freshness(now)
    }

    /// Enforce the timestamp rules alone (no signature check).
    fn check_freshness(&self, now: u64) -> Result<()> {
        let signed_at = self.signed_at();
        if signed_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(NauError::Stale(format!(
                "signed_at {signed_at} is more than {MAX_CLOCK_SKEW_SECS}s in the future of {now}"
            )));
        }
        if let Some(expires_at) = self.expires_at() {
            if now > expires_at {
                return Err(NauError::Stale(format!(
                    "expired at {expires_at}, now {now}"
                )));
            }
        }
        Ok(())
    }

    /// A clone with the signature blanked, used as the signing payload.
    fn clone_for_signing(&self) -> Self {
        let mut c = self.clone();
        c.set_signature(String::new());
        c
    }
}

/// A monotonic-value-free replay guard.
///
/// Tracks the highest `nonce` seen per signer and rejects anything not strictly
/// greater. Combined with `signed_at` this makes replaying a captured bid or
/// result fail. Kept in `nau-core` because every service needs the same rule and
/// the same diagnostics.
#[derive(Debug, Default, Clone)]
pub struct NonceGuard {
    highest: std::collections::HashMap<String, u64>,
}

impl NonceGuard {
    /// An empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `nonce` for `did`, rejecting reuse or regression.
    pub fn accept(&mut self, did: &Did, nonce: u64) -> Result<()> {
        let entry = self.highest.entry(did.to_string()).or_insert(0);
        if nonce <= *entry {
            return Err(NauError::Stale(format!(
                "nonce {nonce} for `{did}` is not greater than the highest seen ({entry})"
            )));
        }
        *entry = nonce;
        Ok(())
    }

    /// The highest nonce observed for `did`.
    pub fn highest(&self, did: &Did) -> u64 {
        self.highest.get(did.as_str()).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_guard_rejects_replay_and_regression() {
        let mut g = NonceGuard::new();
        let did = Did::parse("did:nau:34750f98bd59fcfc").unwrap();
        assert!(g.accept(&did, 1).is_ok());
        assert!(g.accept(&did, 1).is_err(), "same nonce is a replay");
        assert!(g.accept(&did, 0).is_err(), "older nonce is a replay");
        assert!(g.accept(&did, 2).is_ok());
        assert_eq!(g.highest(&did), 2);

        // Independent per identity.
        let other = Did::parse("did:nau:0000000000000000").unwrap();
        assert!(g.accept(&other, 1).is_ok());
    }
}
