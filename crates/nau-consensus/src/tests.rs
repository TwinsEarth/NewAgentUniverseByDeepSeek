//! Regression and invariant tests for the BFT-lite committee.
//!
//! Every one of the six confirmed upstream defects has a test named after it, and
//! each test builds real Ed25519 identities and real signatures — nothing here
//! exercises a fabricated or unsigned ballot, because the point of the rewrite is
//! that there is no such thing.

use nau_core::domain::Verifiable;
use nau_core::{Did, Identity, NauError};

use crate::committee::{Committee, Outcome, TallyReason};
use crate::spec::CommitteeSpec;
use crate::vote::{Decision, Vote, MAX_PROPOSAL_LEN};

const PROPOSAL: &str = "task-1";
const NOW: u64 = 1_700_000_000;

fn identity(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

/// Build a committee of `n` distinct members and hand back their identities.
fn committee_of(n: u32, f: u32) -> (Committee, Vec<Identity>) {
    let spec = CommitteeSpec::new(n, f).expect("test spec is valid");
    let identities: Vec<Identity> = (0..n).map(|i| identity(i as u8 + 1)).collect();
    let members: Vec<Did> = identities.iter().map(|i| i.did()).collect();
    let committee =
        Committee::assign(spec, PROPOSAL, members).expect("distinct members fill the spec");
    (committee, identities)
}

fn vote(round: u64, who: &Identity, decision: Decision, nonce: u64) -> Vote {
    Vote::signed(round, PROPOSAL, who, decision, nonce, NOW).expect("test ballot signs")
}

/// Cast `count` accepting ballots starting at member `from`, taking the first
/// member index that still has a clean ballot.
fn accept_from(committee: &mut Committee, identities: &[Identity], from: usize, count: usize) {
    for identity in identities.iter().skip(from).take(count) {
        committee
            .cast(&vote(committee.round(), identity, Decision::Accept, 1), NOW)
            .expect("a fresh member's first ballot is accepted");
    }
}

// ============================================== defect 1: client-controlled

/// upstream v2.5.6 defect 1 — `verify?approvals=1&committee_size=1` self-approved
/// any task, because the handler read the counts from the request, synthesized
/// members and tallied locally. Here a verdict needs `2f+1` real signatures.
#[test]
fn upstream_fix_1_a_verdict_needs_real_signatures_not_a_caller_supplied_count() {
    let (committee, identities) = committee_of(4, 1);

    // Nothing has been cast, so nothing is decided — no matter what a caller
    // claims. `tally` takes no arguments; there is no approvals parameter.
    let empty = committee.tally();
    assert_eq!(empty.accept, 0);
    assert_eq!(empty.reject, 0);
    assert_eq!(empty.quorum, 3, "n=4, f=1 needs three real ballots");
    assert_eq!(empty.outcome, Outcome::NoQuorum);
    assert!(!empty.is_decided());

    // One genuine member's signature is one vote, and one vote is not a verdict.
    let mut committee = committee;
    committee
        .cast(&vote(0, &identities[0], Decision::Accept, 1), NOW)
        .unwrap();
    let one = committee.tally();
    assert_eq!(one.accept, 1);
    assert!(
        !one.is_decided(),
        "1 approval out of a claimed size of 1 is not enough"
    );

    accept_from(&mut committee, &identities, 1, 2);
    assert_eq!(committee.tally().outcome, Outcome::Accepted);
}

/// A ballot cannot be fabricated by whoever hosts the API: the signature is the
/// authority, and a non-member has none.
#[test]
fn upstream_fix_1_a_non_member_cannot_vote() {
    let (mut committee, _identities) = committee_of(4, 1);
    let outsider = identity(200);

    let err = committee
        .cast(&vote(0, &outsider, Decision::Accept, 1), NOW)
        .unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");
    assert_eq!(committee.tally().accept, 0);
    assert_eq!(committee.ballots().count(), 0);
}

/// Rewriting the decision of an otherwise genuine ballot invalidates it.
#[test]
fn upstream_fix_1_a_ballot_with_a_tampered_decision_is_rejected() {
    let (mut committee, identities) = committee_of(4, 1);

    let mut ballot = vote(0, &identities[0], Decision::Reject, 1);
    ballot.decision = Decision::Accept;

    let err = committee.cast(&ballot, NOW).unwrap_err();
    assert!(matches!(err, NauError::InvalidSignature), "got {err:?}");
    assert_eq!(committee.tally().accept, 0);
    assert_eq!(committee.tally().reject, 0);
}

/// A signature made by a different key never becomes a vote for a member.
#[test]
fn upstream_fix_1_a_ballot_signed_by_another_key_is_rejected() {
    let (mut committee, identities) = committee_of(4, 1);
    let other = identity(201);

    // (a) Member 0's DID with somebody else's public key: the DID↔key binding
    //     check fires before the signature is even considered.
    let mut mislabelled = vote(0, &identities[0], Decision::Accept, 1);
    mislabelled.voter_key = other.public_key();
    let err = committee.cast(&mislabelled, NOW).unwrap_err();
    assert!(
        matches!(err, NauError::DidKeyMismatch { .. }),
        "got {err:?}"
    );

    // (b) A ballot `other` really signed, re-labelled with member 0's identity:
    //     the binding passes, the signature does not.
    let mut relabelled = vote(0, &other, Decision::Accept, 2);
    relabelled.voter = identities[0].did();
    relabelled.voter_key = identities[0].public_key();
    let err = committee.cast(&relabelled, NOW).unwrap_err();
    assert!(matches!(err, NauError::InvalidSignature), "got {err:?}");

    // (c) An entirely unsigned ballot is refused too.
    let mut unsigned = vote(0, &identities[0], Decision::Accept, 3);
    unsigned.signature = String::new();
    let err = committee.cast(&unsigned, NOW).unwrap_err();
    assert!(matches!(err, NauError::InvalidSignature), "got {err:?}");

    assert_eq!(committee.tally().accept, 0);
}

// ================================================== defect 2: decorative `n`

/// upstream v2.5.6 defect 2 — `add_member` silently dropped members past `n`, and
/// `tally()` counted over the members that had been added rather than `n`, so
/// `new(3, 0)` plus one voter decided the round. The full list is required up
/// front and must equal `n`.
#[test]
fn upstream_fix_2_the_assigned_member_list_must_equal_n_exactly() {
    let spec = CommitteeSpec::new(4, 1).unwrap();
    let a = identity(1);
    let b = identity(2);
    let c = identity(3);
    let d = identity(4);
    let e = identity(5);

    // Too few members: this is `new(3,0)` + one voter generalised — refused.
    let err = Committee::assign(spec, PROPOSAL, vec![a.did(), b.did(), c.did()]).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    let err = Committee::assign(spec, PROPOSAL, vec![a.did()]).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    let err = Committee::assign(spec, PROPOSAL, Vec::new()).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");

    // Too many: the old code silently dropped the extras; now it is an error.
    let err = Committee::assign(
        spec,
        PROPOSAL,
        vec![a.did(), b.did(), c.did(), d.did(), e.did()],
    )
    .unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");

    // Duplicates would let one identity cast two "different" votes.
    let err =
        Committee::assign(spec, PROPOSAL, vec![a.did(), a.did(), c.did(), d.did()]).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");

    // Exactly `n` distinct members is the only accepted shape.
    let committee =
        Committee::assign(spec, PROPOSAL, vec![a.did(), b.did(), c.did(), d.did()]).unwrap();
    assert_eq!(committee.members().len(), 4);
    assert_eq!(committee.members().len(), committee.spec().n() as usize);
    assert_eq!(committee.round(), 0);
    assert_eq!(committee.proposal(), PROPOSAL);
    assert!(committee.is_member(&a.did()));
    assert!(!committee.is_member(&e.did()));
}

/// `n < 3f+1` is refused by both the spec and the assignment.
#[test]
fn upstream_fix_2_a_committee_below_three_f_plus_one_is_refused() {
    let a = identity(1);
    let b = identity(2);
    let c = identity(3);
    let forged = CommitteeSpec { n: 3, f: 1 };
    let err = Committee::assign(forged, PROPOSAL, vec![a.did(), b.did(), c.did()]).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert!(CommitteeSpec::new(3, 1).is_err());
    assert!(CommitteeSpec::new(2, 0).is_ok(), "n=2, f=0 is legal");
}

/// A proposal identifier must look like something a task could own.
#[test]
fn upstream_fix_2_the_proposal_identifier_is_validated() {
    let spec = CommitteeSpec::new(4, 1).unwrap();
    let members: Vec<Did> = (1..=4).map(|i| identity(i).did()).collect();

    assert!(Committee::assign(spec, "", members.clone()).is_err());
    assert!(Committee::assign(spec, "   ", members.clone()).is_err());
    assert!(Committee::assign(spec, &"p".repeat(MAX_PROPOSAL_LEN + 1), members.clone()).is_err());
    assert!(Committee::assign(spec, &"p".repeat(MAX_PROPOSAL_LEN), members).is_ok());
    assert!(Vote::draft(0, "", &identity(1), Decision::Accept, 1, NOW).is_err());
}

/// A ballot for another proposal, or another round, never enters the count.
#[test]
fn upstream_fix_2_a_ballot_for_the_wrong_round_or_proposal_is_rejected() {
    let (mut committee, identities) = committee_of(4, 1);

    let wrong_proposal =
        Vote::signed(0, "task-2", &identities[0], Decision::Accept, 1, NOW).expect("signs fine");
    let err = committee.cast(&wrong_proposal, NOW).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");

    let err = committee
        .cast(&vote(7, &identities[0], Decision::Accept, 1), NOW)
        .unwrap_err();
    assert!(matches!(err, NauError::Stale(_)), "got {err:?}");

    assert_eq!(committee.tally().accept, 0);
}

// =============================================== defect 3: u32 overflow

/// upstream v2.5.6 defect 3 — `3 * f + 1` and `2 * f + 1` were unchecked, so a
/// large `f` panicked in debug and wrapped in release.
#[test]
fn upstream_fix_3_a_fault_bound_near_u32_max_errors_instead_of_overflowing() {
    assert!(matches!(
        CommitteeSpec::new(1, 1_431_655_766),
        Err(NauError::Validation(_))
    ));
    assert!(CommitteeSpec::new(u32::MAX, u32::MAX).is_err());
    let forged = CommitteeSpec {
        n: u32::MAX,
        f: u32::MAX,
    };
    assert!(forged.quorum_checked().is_err());
    assert_eq!(
        forged.quorum(),
        u32::MAX,
        "saturates; never wraps, never panics"
    );

    // And an absurd spec cannot be assigned a committee either.
    let a = identity(1);
    assert!(Committee::assign(forged, PROPOSAL, vec![a.did()]).is_err());
}

// ========================================== defect 4: safety violations

/// upstream v2.5.6 defect 4 — the papers require "if both sides reach quorum
/// simultaneously return `None` + `safety_violation = true` / `conflicting_quorums`",
/// and nothing implemented it.
#[test]
fn upstream_fix_4_conflicting_quorums_are_detected_and_exposed() {
    // n = 6 >= 3f+1 = 4 and 6 >= 4f+2 = 6, so two disjoint quorums of 3 fit
    // without anybody equivocating: this is a genuine, honest split.
    let (mut committee, identities) = committee_of(6, 1);
    assert_eq!(committee.quorum(), 3);

    for identity in identities.iter().take(3) {
        committee
            .cast(&vote(0, identity, Decision::Accept, 1), NOW)
            .unwrap();
    }
    for identity in identities.iter().skip(3) {
        committee
            .cast(&vote(0, identity, Decision::Reject, 1), NOW)
            .unwrap();
    }

    let tally = committee.tally();
    assert_eq!((tally.accept, tally.reject, tally.silent), (3, 3, 0));
    assert!(tally.safety_violation, "both sides reached quorum");
    assert_eq!(tally.outcome, Outcome::SafetyViolation);
    assert_eq!(tally.reason, TallyReason::ConflictingQuorums);
    assert!(!tally.is_decided(), "a safety violation is not a verdict");
    assert!(
        tally.equivocators.is_empty(),
        "nobody cheated; the split is honest"
    );
}

/// A near-miss is *not* reported as a safety violation.
#[test]
fn upstream_fix_4_one_vote_short_of_a_conflicting_quorum_is_not_a_violation() {
    let (mut committee, identities) = committee_of(6, 1);
    for identity in identities.iter().take(3) {
        committee
            .cast(&vote(0, identity, Decision::Accept, 1), NOW)
            .unwrap();
    }
    for identity in identities.iter().skip(3).take(2) {
        committee
            .cast(&vote(0, identity, Decision::Reject, 1), NOW)
            .unwrap();
    }
    let tally = committee.tally();
    assert_eq!((tally.accept, tally.reject), (3, 2));
    assert!(!tally.safety_violation);
    assert_eq!(tally.outcome, Outcome::Accepted);
    assert_eq!(tally.reason, TallyReason::QuorumReached);
}

// ================================================ defect 5: attribution

/// upstream v2.5.6 defect 5 — equivocation was a bare `bool`, so the offender was
/// never attributed. It is named here, both conflicting decisions are recorded,
/// and the round is voided.
#[test]
fn upstream_fix_5_equivocation_names_the_offender_and_both_decisions() {
    let (mut committee, identities) = committee_of(4, 1);

    // Three honest accepts are already a quorum...
    for identity in identities.iter().take(3) {
        committee
            .cast(&vote(0, identity, Decision::Accept, 1), NOW)
            .unwrap();
    }
    assert_eq!(committee.tally().outcome, Outcome::Accepted);

    // ...and then member 3 votes both ways.
    committee
        .cast(&vote(0, &identities[3], Decision::Accept, 1), NOW)
        .unwrap();
    let err = committee
        .cast(&vote(0, &identities[3], Decision::Reject, 2), NOW)
        .unwrap_err();
    assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");

    let tally = committee.tally();
    assert_eq!(tally.outcome, Outcome::NoQuorum, "the whole round is void");
    assert_eq!(tally.reason, TallyReason::RoundVoidedByEquivocation);
    assert_eq!(tally.equivocators, vec![identities[3].did()]);
    assert_eq!(committee.equivocations(), &[identities[3].did()]);
    assert!(committee.round_is_void());

    let details = committee.equivocation_details();
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].voter, identities[3].did());
    assert_eq!(details[0].round, 0);
    assert_eq!(details[0].first, Decision::Accept);
    assert_eq!(details[0].second, Decision::Reject);

    // Only the first ballot counted: an equivocator does not get two votes.
    assert_eq!(tally.accept, 4);
    assert_eq!(tally.reject, 0);

    // Replaying the conflicting ballot is a nonce replay, so it cannot pad the
    // record with duplicates either.
    let replay = vote(0, &identities[3], Decision::Reject, 2);
    assert!(matches!(
        committee.cast(&replay, NOW).unwrap_err(),
        NauError::Stale(_)
    ));
    assert_eq!(committee.equivocation_details().len(), 1);
}

/// Repeating the *same* decision with a fresh nonce is a duplicate announcement,
/// not an equivocation, and it does not double count.
#[test]
fn upstream_fix_5_repeating_the_same_decision_is_not_an_equivocation() {
    let (mut committee, identities) = committee_of(4, 1);
    committee
        .cast(&vote(0, &identities[0], Decision::Accept, 1), NOW)
        .unwrap();
    committee
        .cast(&vote(0, &identities[0], Decision::Accept, 2), NOW)
        .unwrap();
    let tally = committee.tally();
    assert_eq!(tally.accept, 1, "one member is one vote");
    assert!(tally.equivocators.is_empty());
    assert!(!committee.round_is_void());
}

// ============================================ defect 6: no recovery path

/// upstream v2.5.6 defect 6 — `NoQuorum` was absorbing. The view change advances
/// the round, drops the ballots, and keeps the equivocation on record.
#[test]
fn upstream_fix_6_a_view_change_does_not_launder_a_double_vote() {
    let (mut committee, identities) = committee_of(4, 1);

    // Members 1..3 vote honestly, so the round is not dominated by silence.
    for identity in identities.iter().skip(1) {
        committee
            .cast(&vote(0, identity, Decision::Accept, 1), NOW)
            .unwrap();
    }

    committee
        .cast(&vote(0, &identities[0], Decision::Accept, 1), NOW)
        .unwrap();
    let err = committee
        .cast(&vote(0, &identities[0], Decision::Reject, 2), NOW)
        .unwrap_err();
    assert!(matches!(err, NauError::Conflict(_)));
    assert_eq!(committee.round(), 0);
    assert_eq!(
        committee.tally().reason,
        TallyReason::RoundVoidedByEquivocation
    );

    committee.reset_for_next_round();

    // The round advanced and the ballots are gone...
    assert_eq!(committee.round(), 1);
    assert_eq!(committee.ballots().count(), 0);
    assert!(committee.ballot_of(&identities[0].did()).is_none());
    let empty = committee.tally();
    assert_eq!((empty.accept, empty.reject, empty.silent), (0, 0, 4));
    assert_eq!(empty.outcome, Outcome::NoQuorum);

    // ...but the offender is still on record, attributed to the round it happened
    // in, so the view change does not launder the double vote.
    assert_eq!(committee.equivocations(), &[identities[0].did()]);
    assert_eq!(empty.equivocators, vec![identities[0].did()]);
    assert_eq!(committee.equivocation_details().len(), 1);
    assert_eq!(committee.equivocation_details()[0].round, 0);
    assert!(!committee.round_is_void(), "the *new* round is not void");

    // A ballot for the old round is stale.
    assert!(matches!(
        committee
            .cast(&vote(0, &identities[1], Decision::Accept, 1), NOW)
            .unwrap_err(),
        NauError::Stale(_)
    ));
    // The nonce guard survives the view change, so an old ballot cannot be
    // replayed into the new round either.
    assert!(matches!(
        committee
            .cast(&vote(1, &identities[0], Decision::Accept, 2), NOW)
            .unwrap_err(),
        NauError::Stale(_)
    ));

    // And the recovery path is real: the new round can reach a verdict.
    for identity in identities.iter().take(3) {
        committee
            .cast(&vote(1, identity, Decision::Accept, 100), NOW)
            .unwrap();
    }
    let tally = committee.tally();
    assert_eq!(tally.outcome, Outcome::Accepted);
    assert_eq!(tally.reason, TallyReason::QuorumReached);
    assert_eq!(committee.round(), 1);
    assert_eq!(
        committee.equivocations(),
        &[identities[0].did()],
        "still on record after a successful round"
    );
}

// ============================================================ quorum maths

/// The `2f+1` boundary is exact: quorum passes, quorum-1 does not, on both sides.
#[test]
fn the_two_f_plus_one_quorum_boundary_is_exact() {
    // n = 3f+1 = 4, f = 1, quorum = 3. Exactly `f` members may stay silent.
    let (mut committee, identities) = committee_of(4, 1);
    assert_eq!(committee.quorum(), 3);
    accept_from(&mut committee, &identities, 0, 3);
    let tally = committee.tally();
    assert_eq!(tally.accept, 3);
    assert_eq!(tally.silent, 1);
    assert_eq!(tally.outcome, Outcome::Accepted);
    assert_eq!(tally.reason, TallyReason::QuorumReached);
    assert!(!tally.safety_violation);

    // One vote short.
    let (mut committee, identities) = committee_of(4, 1);
    accept_from(&mut committee, &identities, 0, 2);
    let tally = committee.tally();
    assert_eq!(tally.accept, 2);
    assert_eq!(tally.silent, 2);
    assert_eq!(tally.outcome, Outcome::NoQuorum);
    assert!(!tally.is_decided());
    assert_ne!(tally.reason, TallyReason::QuorumReached);

    // The same boundary on the reject side.
    let (mut committee, identities) = committee_of(4, 1);
    for identity in identities.iter().take(3) {
        committee
            .cast(&vote(0, identity, Decision::Reject, 1), NOW)
            .unwrap();
    }
    let tally = committee.tally();
    assert_eq!(tally.reject, 3);
    assert_eq!(tally.outcome, Outcome::Rejected);
    assert_eq!(tally.reason, TallyReason::QuorumReached);

    // A larger committee: n = 7, f = 2, quorum = 5.
    let (mut committee, identities) = committee_of(7, 2);
    assert_eq!(committee.quorum(), 5);
    accept_from(&mut committee, &identities, 0, 5);
    let tally = committee.tally();
    assert_eq!(tally.accept, 5);
    assert_eq!(tally.silent, 2);
    assert_eq!(tally.outcome, Outcome::Accepted);

    let (mut committee, identities) = committee_of(7, 2);
    accept_from(&mut committee, &identities, 0, 4);
    assert_eq!(committee.tally().outcome, Outcome::NoQuorum);
}

/// Silence beyond `f` blocks the round even when a quorum has voted, because the
/// safety argument needs `n - f` participants.
#[test]
fn silence_beyond_f_tolerated_faults_blocks_the_round() {
    let (mut committee, identities) = committee_of(4, 1);
    committee
        .cast(&vote(0, &identities[0], Decision::Accept, 1), NOW)
        .unwrap();
    let tally = committee.tally();
    assert_eq!(tally.silent, 3);
    assert_eq!(tally.outcome, Outcome::NoQuorum);
    assert_eq!(tally.reason, TallyReason::SilenceExceedsFaults);

    // On an over-provisioned committee the silence rule is evaluated first, as
    // specified: a quorum of three out of eight still leaves five silent, which
    // is more than `f = 1`.
    let (mut committee, identities) = committee_of(8, 1);
    assert_eq!(committee.quorum(), 3);
    accept_from(&mut committee, &identities, 0, 3);
    let tally = committee.tally();
    assert_eq!(tally.accept, 3, "a quorum did vote");
    assert_eq!(tally.silent, 5);
    assert_eq!(tally.outcome, Outcome::NoQuorum);
    assert_eq!(tally.reason, TallyReason::SilenceExceedsFaults);

    // With enough participation the same committee decides normally.
    let (mut committee, identities) = committee_of(8, 1);
    accept_from(&mut committee, &identities, 0, 7);
    let tally = committee.tally();
    assert_eq!(tally.silent, 1);
    assert_eq!(tally.outcome, Outcome::Accepted);
}

/// A split vote where nobody is silent reaches neither quorum and is not a
/// safety violation.
#[test]
fn a_split_vote_within_the_silence_budget_reports_insufficient_votes() {
    let (mut committee, identities) = committee_of(4, 1);
    committee
        .cast(&vote(0, &identities[0], Decision::Accept, 1), NOW)
        .unwrap();
    committee
        .cast(&vote(0, &identities[1], Decision::Accept, 1), NOW)
        .unwrap();
    committee
        .cast(&vote(0, &identities[2], Decision::Reject, 1), NOW)
        .unwrap();
    committee
        .cast(&vote(0, &identities[3], Decision::Reject, 1), NOW)
        .unwrap();

    let tally = committee.tally();
    assert_eq!((tally.accept, tally.reject, tally.silent), (2, 2, 0));
    assert_eq!(tally.outcome, Outcome::NoQuorum);
    assert_eq!(tally.reason, TallyReason::InsufficientVotes);
    assert!(!tally.safety_violation);
}

// ============================================================ replay guards

#[test]
fn a_replayed_or_regressed_nonce_is_rejected() {
    let (mut committee, identities) = committee_of(4, 1);
    let ballot = vote(0, &identities[0], Decision::Accept, 7);
    committee.cast(&ballot, NOW).unwrap();

    let err = committee.cast(&ballot, NOW).unwrap_err();
    assert!(matches!(err, NauError::Stale(_)), "got {err:?}");

    let older = vote(0, &identities[0], Decision::Accept, 6);
    assert!(matches!(
        committee.cast(&older, NOW).unwrap_err(),
        NauError::Stale(_)
    ));

    // A higher nonce is fine and does not double count.
    let newer = vote(0, &identities[0], Decision::Accept, 8);
    committee.cast(&newer, NOW).unwrap();
    assert_eq!(committee.tally().accept, 1);
}

#[test]
fn nonce_zero_is_accepted_once_and_only_once() {
    let (mut committee, identities) = committee_of(4, 1);
    let ballot = vote(0, &identities[0], Decision::Accept, 0);
    committee.cast(&ballot, NOW).unwrap();
    assert_eq!(committee.tally().accept, 1);
    assert!(matches!(
        committee.cast(&ballot, NOW).unwrap_err(),
        NauError::Stale(_)
    ));
}

#[test]
fn a_ballot_from_the_future_is_rejected_as_stale() {
    let (mut committee, identities) = committee_of(4, 1);
    // Re-sign with a timestamp well beyond the tolerated clock skew.
    let mut ballot = vote(0, &identities[0], Decision::Accept, 1);
    ballot.signed_at = NOW + 100_000;
    ballot.signature = String::new();
    ballot.sign(&identities[0]).unwrap();

    let err = committee.cast(&ballot, NOW).unwrap_err();
    assert!(matches!(err, NauError::Stale(_)), "got {err:?}");
    assert_eq!(committee.tally().accept, 0);
}

// ================================================================== wiring

#[test]
fn a_ballot_survives_serde_and_still_verifies() {
    let (mut committee, identities) = committee_of(4, 1);
    let ballot = vote(0, &identities[0], Decision::Accept, 1);

    let json = serde_json::to_string(&ballot).unwrap();
    let round_tripped: Vote = serde_json::from_str(&json).unwrap();
    assert_eq!(round_tripped, ballot);
    assert!(round_tripped.verify().is_ok());

    // Tampering with the serialized form is detectable.
    let mut tampered = round_tripped.clone();
    tampered.decision = Decision::Reject;
    assert!(matches!(tampered.verify(), Err(NauError::InvalidSignature)));

    committee.cast(&round_tripped, NOW).unwrap();
    assert_eq!(committee.tally().accept, 1);
    assert!(!ballot.same_ballot_as(&tampered));
}

#[test]
fn outcomes_and_reasons_round_trip_through_serde() {
    for outcome in [
        Outcome::Accepted,
        Outcome::Rejected,
        Outcome::NoQuorum,
        Outcome::SafetyViolation,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: Outcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, outcome);
    }
    for reason in [
        TallyReason::QuorumReached,
        TallyReason::SilenceExceedsFaults,
        TallyReason::InsufficientVotes,
        TallyReason::ConflictingQuorums,
        TallyReason::RoundVoidedByEquivocation,
    ] {
        let json = serde_json::to_string(&reason).unwrap();
        let back: TallyReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, reason);
    }
    let ballot = vote(0, &identity(1), Decision::Reject, 1);
    let json = serde_json::to_string(&ballot).unwrap();
    assert!(json.contains("\"decision\":\"Reject\""), "{json}");
    assert!(json.contains("\"round\":0"), "{json}");
}

#[test]
fn decisions_label_themselves_and_invert() {
    assert_eq!(Decision::Accept.label(), "accept");
    assert_eq!(Decision::Reject.label(), "reject");
    assert_eq!(Decision::Accept.opposite(), Decision::Reject);
    assert_eq!(Decision::Reject.opposite(), Decision::Accept);
}

/// The committee is a value: assigning two committees with the same inputs gives
/// independent state, and the member order supplied is the order reported.
#[test]
fn assignment_preserves_member_order_and_isolates_state() {
    let spec = CommitteeSpec::new(4, 1).unwrap();
    let identities: Vec<Identity> = (1..=4).map(identity).collect();
    let members: Vec<Did> = identities.iter().map(|i| i.did()).collect();
    let mut reversed = members.clone();
    reversed.reverse();

    let mut first = Committee::assign(spec, PROPOSAL, members.clone()).unwrap();
    let second = Committee::assign(spec, PROPOSAL, reversed.clone()).unwrap();
    assert_eq!(first.members(), members.as_slice());
    assert_eq!(second.members(), reversed.as_slice());

    first
        .cast(&vote(0, &identities[0], Decision::Accept, 1), NOW)
        .unwrap();
    assert_eq!(first.tally().accept, 1);
    assert_eq!(
        second.tally().accept,
        0,
        "separate committees, separate state"
    );
}

/// A committee never tallies more ballots than it has members, and the three
/// counts always add up to `n`.
#[test]
fn the_tally_partition_is_total_over_the_member_set() {
    let (mut committee, identities) = committee_of(7, 2);
    for (index, identity) in identities.iter().enumerate() {
        let decision = if index % 2 == 0 {
            Decision::Accept
        } else {
            Decision::Reject
        };
        committee
            .cast(&vote(0, identity, decision, 1), NOW)
            .unwrap();
        let tally = committee.tally();
        assert_eq!(
            tally.accept + tally.reject + tally.silent,
            committee.spec().n(),
            "the tally must partition the assigned member set"
        );
        assert!(tally.accept + tally.reject <= committee.members().len() as u32);
    }
}
