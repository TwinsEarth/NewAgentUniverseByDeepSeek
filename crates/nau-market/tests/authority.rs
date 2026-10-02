//! Findings F and G: the state machine is the only way a state changes, the
//! privileged operations take an explicit actor, the penalty is a server-side rule,
//! and every one-way side effect happens only after the transition was validated.

mod support;

use nau_consensus::{Committee, CommitteeSpec, Decision};
use nau_core::domain::money::major;
use nau_core::domain::EvidenceGrade;
use nau_core::{NauError, TaskState};
use nau_market::{Actor, Market, MarketConfig};
use support::*;

/// The production source, read back so the structural claims can be checked
/// rather than asserted in prose.
const SERVICE: &str = include_str!("../src/service.rs");

/// The body of one top-level function or method, from its header to the next
/// top-level item. Doc comments are excluded (the header line is the `fn` line).
fn body_of(source: &str, name: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let method = format!("    pub fn {name}(");
    let free = format!("fn {name}(");
    let start = lines
        .iter()
        .position(|line| line.starts_with(&method) || line.starts_with(&free))
        .unwrap_or_else(|| panic!("no definition of `{name}` in service.rs"));
    let rest = &lines[start + 1..];
    let end = rest
        .iter()
        .position(|line| {
            line.starts_with("    pub fn ")
                || line.starts_with("    fn ")
                || line.starts_with("fn ")
                || line.starts_with("///")
                || line.starts_with("    ///")
                || line.starts_with('}')
        })
        .unwrap_or(rest.len());
    rest[..end].join("\n")
}

// ---------------------------------------------------------------------------
// F: no state change outside the transition function, explicit actor, server rule
// ---------------------------------------------------------------------------

/// The production half of the source: everything before the first test module.
fn production_source() -> &'static str {
    match SERVICE.find("#[cfg(test)]") {
        Some(index) => &SERVICE[..index],
        None => SERVICE,
    }
}

#[test]
fn the_only_state_assignment_in_the_crate_is_the_transition_helper() {
    let mut assignments = Vec::new();
    for (index, line) in production_source().lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if line.contains(".state = ") {
            assignments.push((index + 1, line.trim().to_string()));
        }
    }
    assert_eq!(
        assignments.len(),
        1,
        "expected exactly one assignment site (finding F), found {assignments:?}"
    );
    let helper = body_of(SERVICE, "apply_transition");
    assert!(
        helper.contains(".state = ") && helper.contains("next_state(task, next)"),
        "the single assignment must be the validated transition: {helper}"
    );
}

#[test]
fn one_way_side_effects_happen_after_the_transition_is_validated() {
    let settle = body_of(SERVICE, "settle");
    let checked = settle
        .find("next_state(task, TaskState::Settled)")
        .expect("settle validates the transition");
    // Matched on the call rather than on the path to it. These assertions broke when the
    // ledger moved behind a `Mutex` and the path became `books().release` -- and the fix is not
    // to write the new path down, which the next refactor breaks again, but to match the thing
    // the property is about: a release on the ledger happens in this function.
    let money = settle.find(".release(").expect("settle releases escrow");
    assert!(
        checked < money,
        "settle must validate the transition before it moves money"
    );

    let arbitrate = body_of(SERVICE, "arbitrate");
    let checked = arbitrate
        .find("next_state(task, next)")
        .expect("arbitrate validates the transition");
    let slash = arbitrate.find(".slash(").expect("arbitrate slashes");
    assert!(
        checked < slash,
        "arbitrate must validate the transition before it slashes"
    );

    let submit = body_of(SERVICE, "submit_result");
    let checked = submit
        .find("next_state(task, TaskState::Submitted)")
        .expect("submit_result validates the transition");
    let recorded = submit
        .find("results.insert")
        .expect("submit_result records the envelope");
    assert!(
        checked < recorded,
        "submit_result must validate the transition before it records the envelope"
    );

    // G: the evidence upgrade is after the transition, not before it.
    let verify = body_of(SERVICE, "verify_result");
    let transition = verify
        .find("apply_transition(task, next)")
        .expect("the transition is applied");
    let upgrade = verify
        .find("verified_evidence")
        .expect("the evidence upgrade is recorded");
    assert!(
        transition < upgrade,
        "the evidence upgrade must happen only after a successful transition"
    );
}

#[test]
fn the_privileged_operations_take_an_explicit_actor() {
    assert!(
        SERVICE.contains("open_dispute(&mut self, actor: Actor,"),
        "open_dispute must take an explicit actor"
    );
    assert!(
        SERVICE.contains("arbitrate(&mut self, actor: Actor,"),
        "arbitrate must take an explicit actor"
    );
    let open = body_of(SERVICE, "open_dispute");
    assert!(
        open.contains("actor.authority() != Authority::Party")
            && open.contains("actor.did() != &dispute.complainant"),
        "the actor's authority and identity must both be checked"
    );
    let arbitrate = body_of(SERVICE, "arbitrate");
    assert!(
        arbitrate.contains("actor.authority() != Authority::Arbitrator")
            && arbitrate.contains("actor.did() != &ruling.arbitrator"),
        "the arbitrator's authority and identity must both be checked"
    );
    assert!(
        arbitrate.contains("penalty_for("),
        "the penalty must come from the server-side rule"
    );
    assert!(
        !arbitrate.contains("slash_amount"),
        "the caller's slash_amount must not decide the penalty"
    );
}

#[test]
fn the_market_never_emits_an_internal_transfer_it_cannot_replay() {
    // The market locks stake with `withdraw` + `deposit`, so its journal contains
    // no `Stake`/`Unstake` entry. The replay rules and the write rules must agree.
    // These two read `ledger.stake(` while the field was a plain `Ledger`. Once the ledger
    // moved behind a `Mutex` they would have been **vacuously true** -- the string can no longer
    // appear -- so the test would have kept passing while testing nothing at all. A negative
    // assertion is the one kind that fails silently when its subject is renamed, which is why
    // these are matched on the call the market must not make rather than on the path to it.
    assert!(!SERVICE.contains(".stake("));
    assert!(!SERVICE.contains(".unstake("));
}

#[test]
fn a_terminal_state_has_no_inbound_edge() {
    let mut fx = Fixture::new();
    let task = fx.run_to_accepted("task-1", major(50), major(30), EvidenceGrade::CpuProto);
    let at = fx.tick();
    fx.market.settle(&task.id, at).expect("settle");
    assert_eq!(
        fx.market.get_task(&task.id).expect("task").state,
        TaskState::Settled
    );

    // Settled -> Disputed is not an edge in the transition table, and upstream's
    // direct assignment created it anyway.
    let nonce = fx.nonces.take(&fx.requester);
    let signed_at = fx.tick();
    let dispute = dispute_of(&fx.requester, &task, &fx.agent, "d-late", nonce, signed_at);
    let at = fx.tick();
    let err = fx
        .market
        .open_dispute(Actor::party(fx.requester.did()), dispute, at)
        .unwrap_err();
    assert!(
        matches!(err, NauError::InvalidTransition { .. }),
        "got {err:?}"
    );
    assert!(
        fx.market.get_dispute("d-late").is_none(),
        "nothing recorded"
    );
    assert_eq!(
        fx.market.get_task(&task.id).expect("task").state,
        TaskState::Settled,
        "the state must be untouched"
    );
}

#[test]
fn one_task_cannot_accumulate_disputes_and_be_punished_twice() {
    let mut fx = Fixture::new();
    let task = fx.publish("task-1", major(50));
    fx.bid(&task, major(30));
    let at = fx.tick();
    fx.market.match_task(&task.id, at).expect("match");

    let nonce = fx.nonces.take(&fx.requester);
    let signed_at = fx.tick();
    let first = dispute_of(&fx.requester, &task, &fx.agent, "d1", nonce, signed_at);
    let at = fx.tick();
    fx.market
        .open_dispute(Actor::party(fx.requester.did()), first, at)
        .expect("the first dispute is legal");
    let stake = Market::stake_account_for(&fx.agent.did());
    let before = fx.market.balance(&stake);

    // `Disputed -> Disputed` is a repeat, not an edge, so a second dispute has
    // nowhere to go — which is what stops a second ruling (and a second slash).
    let nonce = fx.nonces.take(&fx.requester);
    let signed_at = fx.tick();
    let second = dispute_of(&fx.requester, &task, &fx.agent, "d2", nonce, signed_at);
    let at = fx.tick();
    let err = fx
        .market
        .open_dispute(Actor::party(fx.requester.did()), second, at)
        .unwrap_err();
    assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
    assert!(fx.market.get_dispute("d2").is_none());
    assert_eq!(fx.market.balance(&stake), before);

    // Ruling the same dispute twice is refused as well.
    let signed_at = fx.tick();
    let first_ruling = ruling_of(&fx.arbiter, "d1", &task, true, major(10), 1, signed_at);
    let at = fx.tick();
    fx.market
        .arbitrate(Actor::arbitrator(fx.arbiter.did()), first_ruling, at)
        .expect("the first ruling");
    let after = fx.market.balance(&stake);
    let signed_at = fx.tick();
    let second_ruling = ruling_of(&fx.arbiter, "d1", &task, true, major(10), 2, signed_at);
    let at = fx.tick();
    assert!(fx
        .market
        .arbitrate(Actor::arbitrator(fx.arbiter.did()), second_ruling, at)
        .is_err());
    assert_eq!(
        fx.market.balance(&stake),
        after,
        "a second ruling must not slash again"
    );
    assert_eq!(
        fx.market.get_task(&task.id).expect("task").state,
        TaskState::Slashed
    );
}

#[test]
fn an_actor_must_present_the_authority_the_operation_requires() {
    let mut fx = Fixture::new();
    let task = fx.publish("task-1", major(50));
    fx.bid(&task, major(30));
    let at = fx.tick();
    fx.market.match_task(&task.id, at).expect("match");

    let nonce = fx.nonces.take(&fx.requester);
    let signed_at = fx.tick();
    let dispute = dispute_of(&fx.requester, &task, &fx.agent, "d1", nonce, signed_at);

    // The arbitrator authority cannot open a dispute ...
    let at = fx.tick();
    let err = fx
        .market
        .open_dispute(Actor::arbitrator(fx.requester.did()), dispute.clone(), at)
        .unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");
    // ... and neither can a party who is not the DID that signed it.
    let at = fx.tick();
    let err = fx
        .market
        .open_dispute(Actor::party(fx.agent.did()), dispute.clone(), at)
        .unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");
    // The right party can.
    let at = fx.tick();
    fx.market
        .open_dispute(Actor::party(fx.requester.did()), dispute, at)
        .expect("a party may dispute");

    // A party authority cannot rule ...
    let signed_at = fx.tick();
    let ruling = ruling_of(&fx.arbiter, "d1", &task, true, major(10), 1, signed_at);
    let at = fx.tick();
    let err = fx
        .market
        .arbitrate(Actor::party(fx.arbiter.did()), ruling.clone(), at)
        .unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");
    // ... an arbitrator who is not the signer cannot rule ...
    let at = fx.tick();
    let err = fx
        .market
        .arbitrate(Actor::arbitrator(fx.agent.did()), ruling.clone(), at)
        .unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");
    // ... and a party to *this* dispute cannot rule even as an arbitrator.
    let nonce = fx.nonces.take(&fx.requester);
    let signed_at = fx.tick();
    let biased = ruling_of(
        &fx.requester,
        "d1",
        &task,
        true,
        major(10),
        nonce,
        signed_at,
    );
    let at = fx.tick();
    let err = fx
        .market
        .arbitrate(Actor::arbitrator(fx.requester.did()), biased, at)
        .unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");

    // The neutral arbitrator with the right authority is accepted.
    let at = fx.tick();
    let slashed = fx
        .market
        .arbitrate(Actor::arbitrator(fx.arbiter.did()), ruling, at)
        .expect("a neutral arbitrator may rule");
    assert_eq!(slashed, major(10));
}

#[test]
fn the_penalty_comes_from_the_server_rule_not_from_the_caller() {
    // Two markets, the same bond, wildly different declared amounts: the amount
    // actually slashed is the same because it is computed from `fault_slash_bps`.
    for declared in [major(1), major(99)] {
        let mut fx = Fixture::new();
        let task = fx.publish("task-1", major(50));
        fx.bid(&task, major(30));
        let at = fx.tick();
        fx.market.match_task(&task.id, at).expect("match");
        let nonce = fx.nonces.take(&fx.requester);
        let signed_at = fx.tick();
        let dispute = dispute_of(&fx.requester, &task, &fx.agent, "d1", nonce, signed_at);
        let at = fx.tick();
        fx.market
            .open_dispute(Actor::party(fx.requester.did()), dispute, at)
            .expect("dispute");
        let signed_at = fx.tick();
        let ruling = ruling_of(&fx.arbiter, "d1", &task, true, declared, 1, signed_at);
        let at = fx.tick();
        let slashed = fx
            .market
            .arbitrate(Actor::arbitrator(fx.arbiter.did()), ruling, at)
            .expect("rule");
        assert_eq!(
            slashed,
            major(10),
            "the declared {declared:?} must not decide the penalty"
        );
    }

    // A different server rule produces a different penalty from the same bond.
    let config = MarketConfig {
        fault_slash_bps: 5_000,
        ..MarketConfig::default()
    };
    let mut fx = Fixture::with_config(config);
    let task = fx.publish("task-1", major(50));
    fx.bid(&task, major(30));
    let at = fx.tick();
    fx.market.match_task(&task.id, at).expect("match");
    let nonce = fx.nonces.take(&fx.requester);
    let signed_at = fx.tick();
    let dispute = dispute_of(&fx.requester, &task, &fx.agent, "d1", nonce, signed_at);
    let at = fx.tick();
    fx.market
        .open_dispute(Actor::party(fx.requester.did()), dispute, at)
        .expect("dispute");
    let signed_at = fx.tick();
    let ruling = ruling_of(&fx.arbiter, "d1", &task, true, major(1), 1, signed_at);
    let at = fx.tick();
    let slashed = fx
        .market
        .arbitrate(Actor::arbitrator(fx.arbiter.did()), ruling, at)
        .expect("rule");
    assert_eq!(slashed, major(50), "50% of a 100-major-unit bond");
}

// ---------------------------------------------------------------------------
// G: the evidence upgrade, and one-way side effects, after validation
// ---------------------------------------------------------------------------

#[test]
fn an_accepted_round_upgrades_evidence_only_after_the_transition() {
    let mut fx = Fixture::new();

    // Accepted with evidence: the round upgrades CpuProto to Verified.
    let accepted = fx.run_to_accepted(
        "task-accepted",
        major(50),
        major(30),
        EvidenceGrade::CpuProto,
    );
    assert_eq!(
        fx.market.get_task(&accepted.id).expect("task").state,
        TaskState::Accepted
    );
    assert_eq!(
        fx.market.effective_evidence(&accepted.id),
        Some(EvidenceGrade::Verified),
        "an accepted round upgrades evidence that exists"
    );

    // Rejected: the transition succeeded, but to a different state, so the grade
    // is untouched.
    let rework = fx.publish("task-rework", major(50));
    fx.bid(&rework, major(30));
    fx.match_and_start(&rework);
    fx.submit_result(&rework, EvidenceGrade::CpuProto);
    let outcome = fx.verify(&rework.id, Decision::Reject);
    assert!(matches!(outcome, nau_consensus::Outcome::Rejected));
    assert_eq!(
        fx.market.get_task(&rework.id).expect("task").state,
        TaskState::Rework
    );
    assert_eq!(
        fx.market.effective_evidence(&rework.id),
        Some(EvidenceGrade::CpuProto),
        "a rejected round must not upgrade anything"
    );

    // Unverified is never upgraded: a round cannot launder "no evidence" into
    // trust, and settlement still refuses it.
    let unverified = fx.run_to_accepted(
        "task-unverified",
        major(50),
        major(30),
        EvidenceGrade::Unverified,
    );
    assert_eq!(
        fx.market.effective_evidence(&unverified.id),
        Some(EvidenceGrade::Unverified)
    );
    let at = fx.tick();
    assert!(fx.market.settle(&unverified.id, at).is_err());
}

#[test]
fn a_failed_verification_leaves_the_grade_and_the_state_untouched() {
    let mut fx = Fixture::new();
    let task = fx.publish("task-1", major(50));
    fx.bid(&task, major(30));
    fx.match_and_start(&task);
    fx.submit_result(&task, EvidenceGrade::CpuProto);

    // A vote whose decision was changed after signing fails before any tally.
    let members: Vec<_> = [11u8, 12, 13].iter().map(|s| id(*s).did()).collect();
    let mut committee = Committee::assign(
        CommitteeSpec::new(3, 0).expect("spec"),
        task.id.as_str(),
        members,
    )
    .expect("committee");
    let mut tampered = vote_of(&id(11), task.id.as_str(), Decision::Accept, 1);
    tampered.decision = Decision::Reject;
    let at = fx.tick();
    let err = fx
        .market
        .verify_result(&task.id, &mut committee, &[tampered], at)
        .unwrap_err();
    assert!(matches!(err, NauError::InvalidSignature), "got {err:?}");
    assert_eq!(
        fx.market.effective_evidence(&task.id),
        Some(EvidenceGrade::CpuProto),
        "a failed round must leave the grade untouched"
    );
    assert_eq!(
        fx.market.get_task(&task.id).expect("task").state,
        TaskState::Submitted
    );

    // A committee assigned to another task is refused for the same reason.
    let other = fx.publish("task-2", major(50));
    let members: Vec<_> = [11u8, 12, 13].iter().map(|s| id(*s).did()).collect();
    let mut other_committee = Committee::assign(
        CommitteeSpec::new(3, 0).expect("spec"),
        other.id.as_str(),
        members,
    )
    .expect("committee");
    let at = fx.tick();
    let err = fx
        .market
        .verify_result(&task.id, &mut other_committee, &[], at)
        .unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert_eq!(
        fx.market.effective_evidence(&task.id),
        Some(EvidenceGrade::CpuProto)
    );
}

#[test]
fn a_refused_submission_records_no_result() {
    let mut fx = Fixture::new();
    let task = fx.publish("task-1", major(50));

    // Not Running yet: the envelope must not be recorded as a side effect of a
    // refused call (finding G).
    let nonce = fx.nonces.take(&fx.agent);
    let at = fx.tick();
    let envelope = result_of(&fx.agent, &task, EvidenceGrade::CpuProto, nonce, at);
    let err = fx.market.submit_result(envelope, at).unwrap_err();
    assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
    assert!(
        fx.market.result_for(&task.id).is_none(),
        "a refused submission must not record a result"
    );

    // A second submission for an already-Submitted task must not replace the
    // envelope that the state machine actually accepted.
    fx.bid(&task, major(30));
    fx.match_and_start(&task);
    let first = fx.submit_result(&task, EvidenceGrade::CpuProto);
    let nonce = fx.nonces.take(&fx.agent);
    let at = fx.tick();
    let second = result_of(&fx.agent, &task, EvidenceGrade::Verified, nonce, at);
    assert!(fx.market.submit_result(second, at).is_err());
    assert_eq!(
        fx.market.result_for(&task.id).map(|e| e.nonce),
        Some(first.nonce),
        "the recorded result must be the one the state machine accepted"
    );
}
