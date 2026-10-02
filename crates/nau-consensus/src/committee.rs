//! The committee itself: assignment, authenticated voting, tallying, and the
//! view change that follows a void round.

use std::collections::{BTreeMap, BTreeSet};

use nau_core::domain::Verifiable;
use nau_core::{Did, NauError, Result};
use serde::{Deserialize, Serialize};

use crate::spec::CommitteeSpec;
use crate::vote::{validate_proposal, Decision, Vote};

/// The verdict a tally produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Outcome {
    /// A quorum accepted the proposal.
    Accepted,
    /// A quorum rejected the proposal.
    Rejected,
    /// No verdict: not enough participation, an equivocation, or too much silence.
    NoQuorum,
    /// Two conflicting quorums were reached simultaneously.
    SafetyViolation,
}

/// Why a tally produced the outcome it did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TallyReason {
    /// A quorum agreed.
    QuorumReached,
    /// More than `f` members were silent, so no verdict can be trusted.
    SilenceExceedsFaults,
    /// Neither side reached quorum and silence was within bounds.
    InsufficientVotes,
    /// Both sides reached quorum at once.
    ConflictingQuorums,
    /// At least one member equivocated, which voids the whole round.
    RoundVoidedByEquivocation,
}

/// A recorded double vote.
///
/// Upstream v2.5.6 reduced equivocation to a bare `bool`, so the system could say
/// "somebody cheated" but never *who*, and never what the two conflicting
/// statements were. Both are recorded here.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Equivocation {
    /// Round in which the double vote happened.
    pub round: u64,
    /// The member who voted twice.
    pub voter: Did,
    /// The decision the member cast first.
    pub first: Decision,
    /// The conflicting decision the member cast afterwards.
    pub second: Decision,
}

/// The result of tallying a round.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TallyResult {
    /// The verdict.
    pub outcome: Outcome,
    /// Why that verdict was produced.
    pub reason: TallyReason,
    /// The quorum threshold that applied, `2f + 1`.
    pub quorum: u32,
    /// Number of members whose recorded ballot accepts.
    pub accept: u32,
    /// Number of members whose recorded ballot rejects.
    pub reject: u32,
    /// Number of assigned members with no recorded ballot.
    pub silent: u32,
    /// Every member on record as having equivocated, in the order they were
    /// first caught. Survives [`Committee::reset_for_next_round`].
    pub equivocators: Vec<Did>,
    /// True whenever **both** sides reached quorum, even if an earlier rule (for
    /// example excessive silence) determined the reported outcome. A safety
    /// violation is never masked by this field.
    pub safety_violation: bool,
}

impl TallyResult {
    /// True when the round produced a usable verdict.
    pub fn is_decided(&self) -> bool {
        matches!(self.outcome, Outcome::Accepted | Outcome::Rejected)
    }
}

/// A BFT-lite committee assigned to decide exactly one proposal.
///
/// The member set is fixed at construction and `n` is enforced against it, so
/// there is nothing to "add later" and no way for a caller to choose how many
/// votes a verdict needs.
#[derive(Clone, Debug)]
pub struct Committee {
    /// The validated committee parameters.
    spec: CommitteeSpec,
    /// The proposal being decided.
    proposal: String,
    /// Assigned members, in the order they were supplied.
    members: Vec<Did>,
    /// The same members, for O(log n) membership tests.
    member_set: BTreeSet<Did>,
    /// The current round.
    round: u64,
    /// The first ballot recorded from each member this round.
    votes: BTreeMap<Did, Vote>,
    /// The highest nonce accepted from each member, across all rounds.
    highest_nonce: BTreeMap<Did, u64>,
    /// Members recorded as having equivocated, across all rounds.
    equivocators: Vec<Did>,
    /// The full equivocation record, across all rounds.
    equivocation_log: Vec<Equivocation>,
}

impl Committee {
    /// Assign a committee to a proposal.
    ///
    /// Upstream v2.5.6 fix: `n` used to be decorative — `add_member` silently
    /// dropped anybody past `n` and `tally()` counted over the members that had
    /// been added, so `new(3, 0)` plus one voter decided a round. Here the full
    /// member list is supplied up front and must match `spec.n()` exactly, with
    /// no duplicates.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the spec is invalid, the proposal id is
    /// empty or too long, `members.len() != spec.n()`, or a member appears twice.
    pub fn assign(spec: CommitteeSpec, proposal: &str, members: Vec<Did>) -> Result<Self> {
        spec.validate()?;
        validate_proposal(proposal)?;

        let expected = usize::try_from(spec.n()).map_err(|_| {
            NauError::Validation(format!(
                "committee size n={} does not fit this platform's address space",
                spec.n()
            ))
        })?;
        if members.len() != expected {
            return Err(NauError::Validation(format!(
                "committee of n={} requires exactly {expected} assigned members, got {}",
                spec.n(),
                members.len()
            )));
        }

        let mut member_set = BTreeSet::new();
        for member in &members {
            if !member_set.insert(member.clone()) {
                return Err(NauError::Validation(format!(
                    "duplicate committee member `{member}`"
                )));
            }
        }

        Ok(Self {
            spec,
            proposal: proposal.to_string(),
            members,
            member_set,
            round: 0,
            votes: BTreeMap::new(),
            highest_nonce: BTreeMap::new(),
            equivocators: Vec::new(),
            equivocation_log: Vec::new(),
        })
    }

    // ---------------------------------------------------------------- reads

    /// The committee parameters.
    pub fn spec(&self) -> CommitteeSpec {
        self.spec
    }

    /// The current round.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// The proposal being decided.
    pub fn proposal(&self) -> &str {
        &self.proposal
    }

    /// The assigned members, in assignment order.
    pub fn members(&self) -> &[Did] {
        &self.members
    }

    /// The quorum threshold `2f + 1`.
    pub fn quorum(&self) -> u32 {
        self.spec.quorum()
    }

    /// The ballot recorded for `member` this round, if any.
    pub fn ballot_of(&self, member: &Did) -> Option<&Vote> {
        self.votes.get(member)
    }

    /// Every ballot recorded this round, in member order.
    pub fn ballots(&self) -> impl Iterator<Item = &Vote> {
        self.votes.values()
    }

    /// The members recorded as having equivocated, across all rounds.
    pub fn equivocations(&self) -> &[Did] {
        &self.equivocators
    }

    /// The full equivocation record, across all rounds.
    pub fn equivocation_details(&self) -> &[Equivocation] {
        &self.equivocation_log
    }

    /// True when `member` is one of the assigned members.
    pub fn is_member(&self, member: &Did) -> bool {
        self.member_set.contains(member)
    }

    // --------------------------------------------------------------- voting

    /// Verify and accept a signed ballot.
    ///
    /// This is the only way a vote enters the committee. It
    ///
    /// * rejects a ballot for another round or another proposal,
    /// * rejects a voter who is not in the assigned member set,
    /// * verifies the Ed25519 signature and the DID↔key binding with
    ///   [`Verifiable::verify_fresh`], so the API's host cannot invent a ballot,
    /// * rejects a replayed or regressed nonce, and
    /// * records — rather than discards — a ballot that contradicts one the same
    ///   member already cast, voiding the round.
    ///
    /// The first ballot from a member is the one that counts; a later conflicting
    /// ballot is evidence of misbehaviour, not a second vote.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] for a structurally invalid ballot or the wrong
    /// proposal, [`NauError::Stale`] for the wrong round or a replayed nonce,
    /// [`NauError::Unauthorized`] for a non-member,
    /// [`NauError::InvalidSignature`]/[`NauError::DidKeyMismatch`] for a forged
    /// ballot, and [`NauError::Conflict`] for an equivocation.
    pub fn cast(&mut self, vote: &Vote, now: u64) -> Result<()> {
        vote.validate()?;

        if vote.round != self.round {
            return Err(NauError::Stale(format!(
                "ballot is for round {} but the committee is in round {}",
                vote.round, self.round
            )));
        }
        if vote.proposal != self.proposal {
            return Err(NauError::Validation(format!(
                "ballot targets `{}` but this committee decides `{}`",
                vote.proposal, self.proposal
            )));
        }
        // upstream v2.5.6 fix: the member set is fixed at construction, so a
        // caller cannot vote on behalf of anybody it likes.
        if !self.member_set.contains(&vote.voter) {
            return Err(NauError::Unauthorized(format!(
                "`{}` is not an assigned member of this committee",
                vote.voter
            )));
        }
        // upstream v2.5.6 fix: the ballot is authenticated. A caller-supplied
        // "approvals" count can no longer become a verdict.
        vote.verify_fresh(now)?;

        if let Some(highest) = self.highest_nonce.get(&vote.voter).copied() {
            if vote.nonce <= highest {
                return Err(NauError::Stale(format!(
                    "nonce {} from `{}` is not greater than the highest already accepted ({highest})",
                    vote.nonce, vote.voter
                )));
            }
        }
        self.highest_nonce.insert(vote.voter.clone(), vote.nonce);

        match self.votes.get(&vote.voter) {
            Some(previous) if previous.decision != vote.decision => {
                // upstream v2.5.6 fix: equivocation used to be a bare bool. Name
                // the offender and both conflicting decisions, and void the round.
                let first = previous.decision;
                let second = vote.decision;
                if !self.equivocators.contains(&vote.voter) {
                    self.equivocators.push(vote.voter.clone());
                }
                self.equivocation_log.push(Equivocation {
                    round: self.round,
                    voter: vote.voter.clone(),
                    first,
                    second,
                });
                Err(NauError::Conflict(format!(
                    "`{}` equivocated in round {}: it already voted {:?} and now votes {:?}; \
                     the round is void",
                    vote.voter, self.round, first, second
                )))
            }
            Some(_) => {
                // Repeating the same decision with a fresh nonce is a duplicate
                // announcement, not a new ballot: idempotent.
                Ok(())
            }
            None => {
                self.votes.insert(vote.voter.clone(), vote.clone());
                Ok(())
            }
        }
    }

    // -------------------------------------------------------------- tallying

    /// Tally the round.
    ///
    /// Takes no arguments on purpose: there is no API anywhere in this crate that
    /// tallies a caller-supplied approval count, which is exactly the upstream
    /// defect this replaces.
    pub fn tally(&self) -> TallyResult {
        let quorum = self.spec.quorum();
        let mut accept: u32 = 0;
        let mut reject: u32 = 0;
        for vote in self.votes.values() {
            match vote.decision {
                Decision::Accept => accept = accept.saturating_add(1),
                Decision::Reject => reject = reject.saturating_add(1),
            }
        }
        let cast = accept.saturating_add(reject);
        let silent = self.spec.n().saturating_sub(cast);

        let accept_quorum = accept >= quorum;
        let reject_quorum = reject >= quorum;
        // upstream v2.5.6 fix: conflicting quorums are detected and exposed
        // rather than silently resolved in favour of whoever tallied first.
        let safety_violation = accept_quorum && reject_quorum;

        let (outcome, reason) = if silent > self.spec.f() {
            (Outcome::NoQuorum, TallyReason::SilenceExceedsFaults)
        } else if self.round_is_void() {
            (Outcome::NoQuorum, TallyReason::RoundVoidedByEquivocation)
        } else if safety_violation {
            (Outcome::SafetyViolation, TallyReason::ConflictingQuorums)
        } else if accept_quorum {
            (Outcome::Accepted, TallyReason::QuorumReached)
        } else if reject_quorum {
            (Outcome::Rejected, TallyReason::QuorumReached)
        } else {
            (Outcome::NoQuorum, TallyReason::InsufficientVotes)
        };

        TallyResult {
            outcome,
            reason,
            quorum,
            accept,
            reject,
            silent,
            equivocators: self.equivocators.clone(),
            safety_violation,
        }
    }

    // ----------------------------------------------------------- view change

    /// Start the next round.
    ///
    /// Upstream v2.5.6 fix: `NoQuorum` was a dead end. This bumps the round and
    /// clears the ballots, which is the "view change" the project's own papers
    /// describe — **and it deliberately preserves the equivocation record**, so a
    /// round change cannot launder a double vote. The record is what an
    /// accountability layer slashes on; it is never erased. The nonce guard
    /// survives too, so a ballot from an earlier round cannot be replayed into
    /// this one.
    ///
    /// Note that the *new* round is tallied on its own merits: only an
    /// equivocation observed in the current round voids it. Otherwise a single
    /// double vote would freeze the committee for ever, which is precisely the
    /// dead end this method exists to remove.
    pub fn reset_for_next_round(&mut self) {
        self.round = self.round.saturating_add(1);
        self.votes.clear();
    }

    /// True when the **current** round carries a recorded equivocation.
    ///
    /// Equivocations from earlier rounds remain visible through
    /// [`Committee::equivocations`] and [`Committee::equivocation_details`] but do
    /// not void a later round.
    pub fn round_is_void(&self) -> bool {
        self.equivocation_log
            .iter()
            .any(|record| record.round == self.round)
    }
}
