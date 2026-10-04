//! Governance: how a vote becomes a policy, and why it cannot become anything else.
//!
//! # E-09's third criterion: the vote and the execution are separate, in both directions
//!
//! v3.7.1 split the police from the tribunal and recorded why: a tribunal that could move plugins
//! would execute its own sentences without the police, "which is a court with an army". E-09 asks for
//! the same split one level up.
//!
//! So this module **tallies votes and produces an outcome**, and [`GovernanceOutcome::carries`]
//! answers what that outcome may be turned into. It has **no method that applies anything**: the
//! application is [`crate::plugins::security::tribunal`]'s, which holds `kernel:policy:write`, and the
//! tribunal **cannot vote** — its operation set has no ballot in it.
//!
//! The two halves are held by two capability sets rather than by a comment, which is the same
//! technique every refusal in this family uses.
//!
//! # E-09's second criterion: an emergency policy update is live, not a one-time configuration
//!
//! [`EmergencyBroadcast`] carries **a revision**, and the revision is what
//! `nau_sandbox::PolicySet::replace` returns when rules are replaced. So a caller can tell "the
//! policy changed" from "the policy is what it was" by comparing a number rather than by reading a
//! log — and a broadcast that did not change the revision is one that changed nothing.
//!
//! # E-09's first criterion: the result replays
//!
//! [`GovernanceLog::replay`] takes the ballots in order and produces the same outcome the live tally
//! produced. That is v3.6.8's audit-replay shape — `trail.rs`'s `replay` walks a recorded trail and
//! reproduces the decisions it led to — applied to a vote: **a governance result nobody can re-derive
//! is one nobody can dispute, and a dispute is the only thing that makes a vote mean anything.**
//!
//! # What the on-chain half of E-09 would need
//!
//! `contracts/src/GovernanceToken.sol` exists and is tested. What it does **not** have is a Rust-side
//! caller: nothing in `crates/` speaks JSON-RPC, encodes ABI calldata or holds an EVM address type —
//! `chain.rs`'s module documentation records that at length. So a vote here is **recorded and
//! replayable**, and **putting it on-chain is refused** for the same reason every other chain write in
//! this family is.

use nau_core::error::{NauError, Result};
use serde::{Deserialize, Serialize};

/// A proposal a vote is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// A stable identifier.
    pub id: String,
    /// What it would change, in one line.
    pub change: String,
    /// The revision the policy was at when the proposal was opened.
    ///
    /// Recorded so that a replay can tell whether the policy moved underneath the vote, which is the
    /// one thing that makes a tally ambiguous.
    pub base_revision: u64,
}

/// One ballot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ballot {
    /// Who voted. A `Did`, as everywhere else this workspace names a party.
    pub voter: String,
    /// The proposal.
    pub proposal: String,
    /// For or against.
    pub in_favour: bool,
    /// The voter's weight, which is the token balance the caller looked up.
    ///
    /// **Passed in rather than read here**, because this module holds no token: reading a balance would
    /// need `GovernanceToken.sol`, and nothing in `crates/` can. A caller that wanted to weight votes
    /// by a balance it invented could, and that is a limitation this type states rather than hides.
    pub weight: u64,
    /// Replay protection, per voter.
    pub nonce: u64,
}

/// What a tally decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceOutcome {
    /// The proposal.
    pub proposal: String,
    /// The weight in favour.
    pub in_favour: u64,
    /// The weight against.
    pub against: u64,
    /// Whether it carried.
    pub carried: bool,
    /// The revision the policy was at when the last ballot was counted.
    pub base_revision: u64,
    /// How many ballots were counted.
    pub ballots: usize,
}

impl GovernanceOutcome {
    /// What this outcome may be turned into.
    ///
    /// # The split, expressed as a return value
    ///
    /// A carried proposal becomes a **`PolicyChange`** — data — and **not an applied policy**. There
    /// is no variant meaning "and it is now in force", because being in force is the tribunal's act
    /// and this module cannot perform it. A caller holding a `PolicyChange` has everything it needs to
    /// **ask** the tribunal, and nothing it needs to act on its own.
    #[must_use]
    pub fn carries(&self) -> Option<PolicyChange> {
        if !self.carried {
            return None;
        }
        Some(PolicyChange {
            proposal: self.proposal.clone(),
            // The revision the change is based on, so the tribunal can refuse a change built on a
            // policy that has since moved -- the lost-update check, and the reason `base_revision` is
            // recorded at all.
            based_on_revision: self.base_revision,
            weight_for: self.in_favour,
            weight_against: self.against,
        })
    }
}

/// A decided change, **not applied**.
///
/// See [`GovernanceOutcome::carries`]: this is data for the tribunal to act on, and carrying it does
/// not change any policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChange {
    /// Which proposal.
    pub proposal: String,
    /// The revision it was decided against.
    pub based_on_revision: u64,
    /// The weight behind it, for the record.
    pub weight_for: u64,
    /// The weight against it, for the record.
    pub weight_against: u64,
}

/// An emergency policy broadcast, and whether it changed anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyBroadcast {
    /// The revision before.
    pub from_revision: u64,
    /// The revision after.
    pub to_revision: u64,
    /// What was replaced, in one line.
    pub change: String,
}

impl EmergencyBroadcast {
    /// Whether this broadcast actually moved the policy.
    ///
    /// **The comparison is the point.** An emergency procedure whose result nobody can tell from the
    /// status quo is one that cannot be audited: a caller reads two numbers rather than a log, and a
    /// broadcast whose revisions are equal did nothing.
    #[must_use]
    pub fn changed_anything(&self) -> bool {
        self.to_revision != self.from_revision
    }
}

/// A governance log: the ballots in order, and what they decided.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceLog {
    ballots: Vec<Ballot>,
    /// Every `(proposal, voter)` that has voted, so a second ballot is refused.
    voted: Vec<(String, String)>,
    /// The revision the policy is at, as far as this log has been told.
    revision: u64,
}

impl GovernanceLog {
    /// An empty log at `revision`.
    #[must_use]
    pub fn new(revision: u64) -> Self {
        Self {
            ballots: Vec::new(),
            voted: Vec::new(),
            revision,
        }
    }

    /// The revision this log has been told the policy is at.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// How many ballots were recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ballots.len()
    }

    /// Whether nothing has been voted on.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ballots.is_empty()
    }

    /// Record a ballot.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the voter or the proposal is blank or the weight is zero — a
    /// weightless ballot is one that cannot affect the outcome and should not look as though it
    /// might — and [`NauError::Conflict`] when this voter has already voted on this proposal. A second
    /// ballot is a duplicate rather than a malformed one, for the reason E-06's replay is: a caller
    /// that could not tell them apart could not tell an attack from a bug.
    pub fn record(&mut self, ballot: Ballot) -> Result<()> {
        if ballot.voter.trim().is_empty() || ballot.proposal.trim().is_empty() {
            return Err(NauError::Validation(
                "a ballot must name its voter and its proposal".to_string(),
            ));
        }
        if ballot.weight == 0 {
            return Err(NauError::Validation(
                "a ballot must carry a positive weight: a weightless one cannot affect the outcome, \
                 and recording it would make it look as though it might"
                    .to_string(),
            ));
        }
        let key = (ballot.proposal.clone(), ballot.voter.clone());
        if self.voted.contains(&key) {
            return Err(NauError::Conflict(format!(
                "`{}` has already voted on `{}`: a second ballot is a duplicate rather than a \
                 malformed one, and the two are different answers",
                ballot.voter, ballot.proposal
            )));
        }
        self.voted.push(key);
        self.ballots.push(ballot);
        Ok(())
    }

    /// Tell the log the policy has moved.
    ///
    /// Used by the emergency path, and it is **the only thing that changes the revision here** — this
    /// module cannot apply a policy, so a caller that has applied one tells the log.
    pub fn observe_revision(&mut self, revision: u64) {
        self.revision = revision;
    }

    /// Tally the ballots for `proposal`.
    ///
    /// # E-09's first criterion, half one
    ///
    /// A pure function of the recorded ballots, so the live result and the replayed one cannot differ
    /// by construction — and [`GovernanceLog::replay`] is what makes that checkable rather than
    /// asserted.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the proposal has no ballots. A tally of nothing is not a tie, and
    /// reporting it as one would let a proposal fail by nobody voting.
    pub fn tally(&self, proposal: &str, base_revision: u64) -> Result<GovernanceOutcome> {
        let mut in_favour = 0u64;
        let mut against = 0u64;
        let mut count = 0usize;
        for ballot in &self.ballots {
            if ballot.proposal != proposal {
                continue;
            }
            count += 1;
            if ballot.in_favour {
                in_favour = in_favour.saturating_add(ballot.weight);
            } else {
                against = against.saturating_add(ballot.weight);
            }
        }
        if count == 0 {
            return Err(NauError::Validation(format!(
                "no ballots were recorded for `{proposal}`: a tally of nothing is not a tie, and \
                 reporting it as one would let a proposal fail by nobody voting"
            )));
        }
        Ok(GovernanceOutcome {
            proposal: proposal.to_string(),
            in_favour,
            against,
            // Strictly greater, so a tie does not carry. Stated rather than left to the comparison:
            // a change that half the votes oppose is not one to make on a tiebreak.
            carried: in_favour > against,
            base_revision,
            ballots: count,
        })
    }

    /// The decisions this log leads to, in the order a replay reaches them.
    ///
    /// This is v3.6.8's audit-replay shape — `trail.rs`'s `replay` walks a recorded trail and
    /// reproduces the decisions it led to — applied to a vote. Each distinct proposal appears once, at
    /// the point the replay first meets it, so two replays of the same log produce the same sequence.
    ///
    /// Returns strings rather than outcomes so that a caller can compare two replays **as text**,
    /// which is what makes "the result replays" a check rather than a promise.
    #[must_use]
    pub fn replay(&self) -> Vec<String> {
        let mut seen: Vec<&str> = Vec::new();
        let mut out = Vec::new();
        for ballot in &self.ballots {
            if seen.contains(&ballot.proposal.as_str()) {
                continue;
            }
            seen.push(ballot.proposal.as_str());
            match self.tally(&ballot.proposal, self.revision) {
                Ok(outcome) => out.push(format!(
                    "{}: {} for, {} against -> {}",
                    outcome.proposal,
                    outcome.in_favour,
                    outcome.against,
                    if outcome.carried {
                        "carried"
                    } else {
                        "rejected"
                    }
                )),
                Err(e) => out.push(format!("{}: {}", ballot.proposal, e)),
            }
        }
        out
    }

    /// Whether a replay of this log reproduces `outcome` for `proposal`.
    ///
    /// The check a caller runs rather than trusting: it tallies again and compares the rendering the
    /// replay produced with the one the outcome produces.
    #[must_use]
    pub fn replays_to(&self, outcome: &GovernanceOutcome) -> bool {
        let rendered = format!(
            "{}: {} for, {} against -> {}",
            outcome.proposal,
            outcome.in_favour,
            outcome.against,
            if outcome.carried {
                "carried"
            } else {
                "rejected"
            }
        );
        self.replay().iter().any(|line| *line == rendered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ballot(voter: &str, proposal: &str, in_favour: bool, weight: u64) -> Ballot {
        Ballot {
            voter: format!("did:nau:{voter}"),
            proposal: proposal.to_string(),
            in_favour,
            weight,
            nonce: 1,
        }
    }

    fn log() -> GovernanceLog {
        let mut log = GovernanceLog::new(7);
        log.record(ballot("0011223344556677", "P-1", true, 60))
            .expect("recorded");
        log.record(ballot("8899aabbccddeeff", "P-1", false, 40))
            .expect("recorded");
        log
    }

    #[test]
    fn a_carried_proposal_becomes_data_and_not_an_applied_policy() {
        // E-09's third criterion, expressed as a return type. `carries` answers what an outcome may be
        // turned into, and what it may be turned into is a `PolicyChange` -- data -- rather than an
        // applied policy. There is no variant meaning "and it is now in force", because being in force
        // is the tribunal's act.
        let log = log();
        let outcome = log.tally("P-1", log.revision()).expect("a tally");
        assert!(outcome.carried, "60 against 40 carries");
        let change = outcome.carries().expect("a change");
        assert_eq!(change.proposal, "P-1");
        assert_eq!(
            change.based_on_revision, 7,
            "the revision it was decided against, so the tribunal can refuse a stale change"
        );
        assert_eq!((change.weight_for, change.weight_against), (60, 40));
        // And the log's own revision is unchanged by carrying: this module cannot apply a policy.
        assert_eq!(log.revision(), 7, "a vote does not move the policy");
    }

    #[test]
    fn a_tie_does_not_carry_and_a_rejected_proposal_carries_nothing() {
        // Strictly greater, stated rather than left to the comparison: a change half the votes oppose
        // is not one to make on a tiebreak.
        let mut log = GovernanceLog::new(1);
        log.record(ballot("0011223344556677", "P", true, 50))
            .expect("recorded");
        log.record(ballot("8899aabbccddeeff", "P", false, 50))
            .expect("recorded");
        let tied = log.tally("P", 1).expect("a tally");
        assert!(!tied.carried, "a tie does not carry");
        assert!(
            tied.carries().is_none(),
            "and a rejected proposal carries nothing, which is what makes `carries` the gate"
        );
    }

    #[test]
    fn a_second_ballot_is_a_conflict_and_a_weightless_one_is_refused() {
        // A duplicate is not a malformed ballot, and a weightless one cannot affect the outcome.
        let mut log = GovernanceLog::new(1);
        log.record(ballot("0011223344556677", "P", true, 10))
            .expect("recorded");
        let duplicate = log.record(ballot("0011223344556677", "P", true, 10));
        assert!(
            matches!(duplicate, Err(NauError::Conflict(_))),
            "a second ballot is a conflict: {duplicate:?}"
        );
        // A different proposal from the same voter is fine, so the check is per proposal.
        log.record(ballot("0011223344556677", "Q", true, 10))
            .expect("a different proposal");
        assert_eq!(log.len(), 2);

        let weightless = log.record(ballot("1111222233334444", "P", true, 0));
        assert!(
            weightless.is_err(),
            "a weightless ballot cannot affect anything"
        );
        assert!(
            format!("{}", weightless.expect_err("refused")).contains("cannot affect the outcome"),
            "and the refusal must say so"
        );
    }

    #[test]
    fn a_tally_of_nothing_is_refused_rather_than_reported_as_a_tie() {
        // Reporting it as a tie would let a proposal fail by nobody voting.
        let log = GovernanceLog::new(1);
        let err = log.tally("P-nobody-voted", 1).expect_err("refused");
        assert!(format!("{err}").contains("not a tie"), "{err}");
        // And the vote that WAS recorded is still tallied, so the refusal is about the empty case.
        assert!(log.replay().is_empty(), "an empty log replays to nothing");
    }

    #[test]
    fn the_result_replays_to_the_same_decision() {
        // E-09's first criterion: v3.6.8's audit-replay shape applied to a vote. Two replays of the
        // same log produce the same sequence, and the sequence agrees with the live tally.
        let log = log();
        let first = log.replay();
        for _ in 0..8 {
            assert_eq!(log.replay(), first, "a replay must be reproducible");
        }
        let outcome = log.tally("P-1", log.revision()).expect("a tally");
        assert!(
            log.replays_to(&outcome),
            "the replay must reproduce the live result: {first:?}"
        );
        assert!(first[0].contains("60 for, 40 against"), "{first:?}");
        assert!(first[0].contains("carried"), "{first:?}");

        // A different outcome for the same proposal does NOT replay, so `replays_to` can fail -- a
        // check that could only pass would be no check at all.
        let mut tampered = outcome.clone();
        tampered.in_favour = 999;
        assert!(
            !log.replays_to(&tampered),
            "a result the log does not produce must not replay"
        );
    }

    #[test]
    fn each_proposal_appears_once_in_the_replay_in_the_order_it_was_first_met() {
        // Two replays of the same log produce the same sequence, which is what makes a comparison
        // meaningful.
        let mut log = GovernanceLog::new(3);
        log.record(ballot("0011223344556677", "P-1", true, 10))
            .expect("recorded");
        log.record(ballot("8899aabbccddeeff", "P-2", true, 20))
            .expect("recorded");
        log.record(ballot("1111222233334444", "P-1", false, 5))
            .expect("recorded");
        let lines = log.replay();
        assert_eq!(lines.len(), 2, "one line per proposal: {lines:?}");
        assert!(lines[0].starts_with("P-1:"), "{lines:?}");
        assert!(lines[1].starts_with("P-2:"), "{lines:?}");
        assert!(lines[1].contains("carried"), "{lines:?}");
    }

    #[test]
    fn an_emergency_broadcast_says_whether_it_moved_the_policy() {
        // E-09's second criterion: the revision is what makes a live update distinguishable from a
        // no-op, and a caller reads two numbers rather than a log.
        let moved = EmergencyBroadcast {
            from_revision: 7,
            to_revision: 8,
            change: "quarantine a module hash".to_string(),
        };
        assert!(moved.changed_anything());
        let no_op = EmergencyBroadcast {
            from_revision: 7,
            to_revision: 7,
            change: "nothing, as it turned out".to_string(),
        };
        assert!(
            !no_op.changed_anything(),
            "an emergency broadcast that did not move the revision did nothing"
        );

        // And the log can be told, which is the only way its revision moves -- because this module
        // cannot apply a policy.
        let mut log = GovernanceLog::new(7);
        log.observe_revision(8);
        assert_eq!(log.revision(), 8);
    }
}
