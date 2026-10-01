//! Signed committee votes.
//!
//! Upstream v2.5.6 has no vote type at all: the REST/MCP handler reads
//! `approvals` and `committee_size` out of the **request**, invents members
//! `qa-0..qa-{n-1}` and casts their ballots locally, so the caller both supplies
//! the tally and selects the committee. A [`Vote`] here is a self-describing,
//! signed artifact: it carries the voter's DID, the public key that must
//! fingerprint it, a nonce, a timestamp and a detached Ed25519 signature over the
//! canonical payload. Fabricating one requires the voter's private key.

use nau_core::domain::Verifiable;
use nau_core::{Did, Identity, NauError, PublicKey, Result};
use serde::{Deserialize, Serialize};

/// Maximum accepted length of a proposal identifier.
pub const MAX_PROPOSAL_LEN: usize = 128;

/// The decision a member casts.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Decision {
    /// The proposal is approved.
    Accept,
    /// The proposal is rejected.
    Reject,
}

impl Decision {
    /// A stable, machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Decision::Accept => "accept",
            Decision::Reject => "reject",
        }
    }

    /// The other decision. Used to describe an equivocation.
    pub fn opposite(self) -> Self {
        match self {
            Decision::Accept => Decision::Reject,
            Decision::Reject => Decision::Accept,
        }
    }
}

/// A signed ballot for one round of one proposal.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Vote {
    /// The round this ballot belongs to.
    pub round: u64,
    /// The proposal (task id) being decided.
    pub proposal: String,
    /// The voting member.
    pub voter: Did,
    /// The public key that must fingerprint [`Vote::voter`].
    pub voter_key: PublicKey,
    /// The decision.
    pub decision: Decision,
    /// Replay-protection nonce. Must strictly increase per voter.
    pub nonce: u64,
    /// When the ballot was signed (Unix seconds).
    pub signed_at: u64,
    /// Hex Ed25519 signature by the voter.
    #[serde(default)]
    pub signature: String,
}

impl Vote {
    /// Build an unsigned ballot for `identity`.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the proposal id is empty or longer than
    /// [`MAX_PROPOSAL_LEN`].
    pub fn draft(
        round: u64,
        proposal: &str,
        identity: &Identity,
        decision: Decision,
        nonce: u64,
        signed_at: u64,
    ) -> Result<Self> {
        validate_proposal(proposal)?;
        Ok(Self {
            round,
            proposal: proposal.to_string(),
            voter: identity.did(),
            voter_key: identity.public_key(),
            decision,
            nonce,
            signed_at,
            signature: String::new(),
        })
    }

    /// Build a ballot and sign it.
    ///
    /// # Errors
    ///
    /// Propagates [`Vote::draft`] and [`Verifiable::sign`] failures.
    pub fn signed(
        round: u64,
        proposal: &str,
        identity: &Identity,
        decision: Decision,
        nonce: u64,
        signed_at: u64,
    ) -> Result<Self> {
        let mut vote = Self::draft(round, proposal, identity, decision, nonce, signed_at)?;
        vote.sign(identity)?;
        Ok(vote)
    }

    /// Structural validation, independent of the signature.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the proposal id is empty or too long.
    pub fn validate(&self) -> Result<()> {
        validate_proposal(&self.proposal)
    }

    /// Sign this ballot in place with `identity`.
    ///
    /// # Errors
    ///
    /// [`NauError::Unauthorized`] when `identity` is not the claimed voter.
    pub fn sign_with(&mut self, identity: &Identity) -> Result<()> {
        self.sign(identity)
    }

    /// True when this ballot agrees with `other` on everything the signature
    /// covers.
    pub fn same_ballot_as(&self, other: &Vote) -> bool {
        self.round == other.round
            && self.proposal == other.proposal
            && self.voter == other.voter
            && self.decision == other.decision
    }
}

/// Reject a proposal identifier that could not have come from a task id.
///
/// # Errors
///
/// [`NauError::Validation`] when `proposal` is empty or longer than
/// [`MAX_PROPOSAL_LEN`].
pub fn validate_proposal(proposal: &str) -> Result<()> {
    if proposal.trim().is_empty() {
        return Err(NauError::Validation("proposal id must not be empty".into()));
    }
    if proposal.len() > MAX_PROPOSAL_LEN {
        return Err(NauError::Validation(format!(
            "proposal id is {} bytes, the maximum is {MAX_PROPOSAL_LEN}",
            proposal.len()
        )));
    }
    Ok(())
}

impl Verifiable for Vote {
    fn signer(&self) -> &Did {
        &self.voter
    }

    fn signer_key(&self) -> &PublicKey {
        &self.voter_key
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
        // A ballot is bound to a round, which the committee itself validates, so
        // it needs no wall-clock expiry of its own.
        None
    }

    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}
