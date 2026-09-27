//! End-to-end market lifecycle, exercising the exact defects the upstream audit
//! found. Each test names the upstream defect it pins down.

use nau_consensus::{Committee, CommitteeSpec, Decision, Vote};
use nau_core::domain::money::major;
use nau_core::domain::{EvidenceGrade, Verifiable};
use nau_core::{
    AgentCard, Bid, Dispute, DisputeOutcome, Identity, Money, NauError, ResultEnvelope, Skill,
    Task, TaskId, TaskSpec, TaskState, VerificationPolicy,
};
use nau_ledger::AccountId;
use nau_market::{Market, MarketConfig};

fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn account(s: &str) -> AccountId {
    AccountId::parse(s).expect("valid account id")
}

/// The ledger account that belongs to an identity.
///
/// Funds must be deposited to this account, because registration stakes from it and
/// task publication escrows from it. Depositing to a free-form label instead leaves
/// the agent with no available balance, which is exactly what the first run of these
/// tests caught.
fn did_account(id: &Identity) -> AccountId {
    AccountId::parse(id.did().as_str()).expect("a DID is a valid account id")
}

/// Credit an identity's account.
fn fund(market: &mut Market, account: &AccountId, amount: Money, at: u64) {
    market.deposit(account, amount, at).expect("deposit");
}

fn card(agent: &Identity, name: &str, stake: Money) -> AgentCard {
    let mut c = AgentCard::draft(
        agent,
        name,
        vec![Skill::new("translation", 1)],
        stake,
        1_700_000_000,
        1,
    );
    c.sign(agent).unwrap();
    c
}

fn task_of(requester: &Identity, budget: Money, nonce: u64) -> Task {
    let mut t = Task::draft(
        TaskId::parse("task-1").unwrap(),
        TaskSpec {
            goal: "translate the document".into(),
            context: "English to Chinese".into(),
            done: vec!["all sections translated".into()],
            todo: vec!["read".into(), "translate".into()],
            trace: None,
            owner: requester.did(),
        },
        vec!["translation".into()],
        budget,
        None,
        VerificationPolicy::Committee { n: 3, f: 0 },
        requester.public_key(),
        1_700_000_100,
        nonce,
    );
    t.sign(requester).unwrap();
    t
}

fn bid_of(bidder: &Identity, task: &Task, price: Money, nonce: u64) -> Bid {
    let mut b = Bid {
        task_id: task.id.clone(),
        bidder: bidder.did(),
        bidder_key: bidder.public_key(),
        price,
        eta_secs: 10,
        confidence_bps: 9_000,
        expires_at: None,
        nonce,
        signed_at: 1_700_000_200,
        signature: String::new(),
    };
    b.sign(bidder).unwrap();
    b
}

fn result_of(agent: &Identity, task: &Task, grade: EvidenceGrade, nonce: u64) -> ResultEnvelope {
    let mut r = ResultEnvelope {
        task_id: task.id.clone(),
        agent: agent.did(),
        agent_key: agent.public_key(),
        output_digest: "ab".repeat(32),
        output_uri: None,
        summary: "translated".into(),
        evidence: grade,
        latency_ms: 5_000,
        nonce,
        signed_at: 1_700_000_300,
        signature: String::new(),
    };
    r.sign(agent).unwrap();
    r
}

fn vote_of(member: &Identity, proposal: &str, decision: Decision, nonce: u64) -> Vote {
    let mut v = Vote {
        round: 0,
        proposal: proposal.to_string(),
        voter: member.did(),
        voter_key: member.public_key(),
        decision,
        nonce,
        signed_at: 1_700_000_400,
        signature: String::new(),
    };
    v.sign(member).unwrap();
    v
}

/// Deposit, register, publish, bid, match, start, submit — the shared prefix.
///
/// Nonces are a **single monotonic sequence per DID** shared by every object that
/// DID signs (cards, tasks, bids, results, disputes), so each helper uses a distinct
/// value. That is what makes cross-type replay impossible.
fn ready_market() -> (Market, Task, Identity, Identity) {
    let requester = id(1);
    let agent = id(2);
    let mut market = Market::new(MarketConfig::default());

    fund(&mut market, &did_account(&requester), major(1_000), 1);
    fund(&mut market, &did_account(&agent), major(1_000), 1);
    market
        .register_agent(card(&agent, "translator", major(100)), 1_700_000_010)
        .unwrap();

    let task = task_of(&requester, major(50), 1);
    market.publish_task(task.clone(), 1_700_000_100).unwrap();
    market
        .submit_bid(bid_of(&agent, &task, major(40), 2), 1_700_000_200)
        .unwrap();
    let outcome = market.match_task(&task.id, 1_700_000_210).unwrap();
    assert_eq!(outcome.winner, agent.did());
    market
        .start_task(&task.id, &agent.did(), 1_700_000_220)
        .unwrap();
    market
        .submit_result(
            result_of(&agent, &task, EvidenceGrade::Verified, 3),
            1_700_000_300,
        )
        .unwrap();

    let task = market.get_task(&task.id).unwrap().clone();
    (market, task, requester, agent)
}

#[test]
fn the_full_lifecycle_settles_and_conserves_exactly() {
    let (mut market, task, _requester, agent) = ready_market();

    let members = vec![id(11).did(), id(12).did(), id(13).did()];
    let spec = CommitteeSpec::new(3, 0).unwrap();
    let mut committee = Committee::assign(spec, task.id.as_str(), members.clone()).unwrap();
    let votes: Vec<Vote> = [11u8, 12, 13]
        .iter()
        .enumerate()
        .map(|(i, seed)| vote_of(&id(*seed), task.id.as_str(), Decision::Accept, i as u64 + 1))
        .collect();

    let outcome = market
        .verify_result(&task.id, &mut committee, &votes, 1_700_000_400)
        .unwrap();
    assert_eq!(format!("{outcome:?}"), "Accepted");
    assert_eq!(
        market.get_task(&task.id).unwrap().state,
        TaskState::Accepted
    );

    // Escrow is held until settlement.
    assert_eq!(market.escrowed_for(&task.id), major(50));

    let paid = market.settle(&task.id, 1_700_000_500).unwrap();
    assert_eq!(paid, major(50), "the escrowed budget is released");
    assert_eq!(market.get_task(&task.id).unwrap().state, TaskState::Settled);
    assert_eq!(market.escrowed_for(&task.id), Money::ZERO);

    // The executor received the funds. `Money` deliberately has no Add/Sub operator
    // impls, so arithmetic is explicit and fallible.
    let expected = major(1_000)
        .checked_sub(major(100))
        .unwrap()
        .checked_add(major(50))
        .unwrap();
    assert_eq!(market.balance(&did_account(&agent)), expected);

    // Conservation is EXACT — no epsilon anywhere.
    let report = market.conservation();
    assert!(report.conserved, "conservation: {report:?}");
    assert_eq!(
        report.discrepancy, 0,
        "integer ledger must have zero discrepancy"
    );
    // And the independent O(N) audit must agree with the O(1) counters.
    let audit = market.audit();
    assert!(audit.conserved);
    assert_eq!(audit.discrepancy, 0);
    assert_eq!(audit.sum_of_balances, report.sum_of_balances);
}

#[test]
fn publishing_rejects_an_unfunded_requester_instead_of_minting_money() {
    // Upstream: `if balance(payer) < amount { deposit(payer, amount) }` — it simply
    // created the money. Here the escrow must fail.
    let requester = id(1);
    let mut market = Market::new(MarketConfig::default());
    let task = task_of(&requester, major(50), 1);
    let err = market.publish_task(task, 1_700_000_100).unwrap_err();
    assert!(
        matches!(err, NauError::InsufficientBalance { .. }),
        "got {err:?}"
    );

    let report = market.conservation();
    assert_eq!(
        report.total_deposited,
        Money::ZERO,
        "no funds may appear from nowhere"
    );
    assert!(report.conserved);
}

#[test]
fn a_settled_task_cannot_be_settled_twice() {
    let (mut market, task, _r, _a) = ready_market();
    let members = vec![id(11).did(), id(12).did(), id(13).did()];
    let mut committee =
        Committee::assign(CommitteeSpec::new(3, 0).unwrap(), task.id.as_str(), members).unwrap();
    let votes: Vec<Vote> = [11u8, 12, 13]
        .iter()
        .enumerate()
        .map(|(i, s)| vote_of(&id(*s), task.id.as_str(), Decision::Accept, i as u64 + 1))
        .collect();
    market
        .verify_result(&task.id, &mut committee, &votes, 1_700_000_400)
        .unwrap();
    market.settle(&task.id, 1_700_000_500).unwrap();

    // A second settlement is refused by the state machine, and no reputation is
    // granted again — upstream re-ran the reputation update on every replay.
    let err = market.settle(&task.id, 1_700_000_600).unwrap_err();
    assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
    let rep_after_first = market.reputation(&id(2).did()).unwrap().settled;
    assert!(market.settle(&task.id, 1_700_000_700).is_err());
    assert_eq!(
        market.reputation(&id(2).did()).unwrap().settled,
        rep_after_first,
        "reputation must not be farmable by replaying settle"
    );
}

#[test]
fn an_unverified_result_cannot_release_payment() {
    // Upstream defined `EvidenceGrade::is_trustworthy()` "for the settlement gate"
    // and never called it, so an Unverified result settled at full budget.
    let requester = id(1);
    let agent = id(2);
    let mut market = Market::new(MarketConfig::default());
    fund(&mut market, &did_account(&requester), major(1_000), 1);
    fund(&mut market, &did_account(&agent), major(1_000), 1);
    market
        .register_agent(card(&agent, "t", major(100)), 1_700_000_010)
        .unwrap();
    let task = task_of(&requester, major(50), 1);
    market.publish_task(task.clone(), 1_700_000_100).unwrap();
    market
        .submit_bid(bid_of(&agent, &task, major(40), 2), 1_700_000_200)
        .unwrap();
    market.match_task(&task.id, 1_700_000_210).unwrap();
    market
        .start_task(&task.id, &agent.did(), 1_700_000_220)
        .unwrap();
    market
        .submit_result(
            result_of(&agent, &task, EvidenceGrade::Unverified, 3),
            1_700_000_300,
        )
        .unwrap();

    let members = vec![id(11).did(), id(12).did(), id(13).did()];
    let mut committee =
        Committee::assign(CommitteeSpec::new(3, 0).unwrap(), task.id.as_str(), members).unwrap();
    let votes: Vec<Vote> = [11u8, 12, 13]
        .iter()
        .enumerate()
        .map(|(i, s)| vote_of(&id(*s), task.id.as_str(), Decision::Accept, i as u64 + 1))
        .collect();
    market
        .verify_result(&task.id, &mut committee, &votes, 1_700_000_400)
        .unwrap();
    // Accepted by the committee, but the evidence grade blocks payment.
    let err = market.settle(&task.id, 1_700_000_500).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert_eq!(
        market.escrowed_for(&task.id),
        major(50),
        "funds stay escrowed"
    );
}

#[test]
fn an_unsigned_or_forged_vote_cannot_approve_a_task() {
    // The critical upstream defect: the API synthesized committee members and their
    // votes from the caller's `approvals` count. Here votes must be signed by
    // assigned members.
    let (mut market, task, _r, _a) = ready_market();
    let members = vec![id(11).did(), id(12).did(), id(13).did()];
    let mut committee =
        Committee::assign(CommitteeSpec::new(3, 0).unwrap(), task.id.as_str(), members).unwrap();

    // A stranger tries to vote.
    let stranger = id(99);
    let forged = vote_of(&stranger, task.id.as_str(), Decision::Accept, 1);
    let err = market
        .verify_result(&task.id, &mut committee, &[forged], 1_700_000_400)
        .unwrap_err();
    assert!(
        matches!(err, NauError::Validation(_) | NauError::Unauthorized(_)),
        "got {err:?}"
    );

    // A member's vote whose decision was tampered with after signing.
    let mut tampered = vote_of(&id(11), task.id.as_str(), Decision::Reject, 1);
    tampered.decision = Decision::Accept;
    let err = market
        .verify_result(&task.id, &mut committee, &[tampered], 1_700_000_400)
        .unwrap_err();
    assert!(matches!(err, NauError::InvalidSignature), "got {err:?}");
}

#[test]
fn fewer_votes_than_quorum_leaves_the_task_without_quorum_not_accepted() {
    let (mut market, task, _r, _a) = ready_market();
    // n=4, f=1 → quorum 3.
    let members: Vec<_> = [11u8, 12, 13, 14].iter().map(|s| id(*s).did()).collect();
    let mut committee =
        Committee::assign(CommitteeSpec::new(4, 1).unwrap(), task.id.as_str(), members).unwrap();
    let votes = vec![
        vote_of(&id(11), task.id.as_str(), Decision::Accept, 1),
        vote_of(&id(12), task.id.as_str(), Decision::Accept, 2),
    ];
    let outcome = market
        .verify_result(&task.id, &mut committee, &votes, 1_700_000_400)
        .unwrap();
    assert_eq!(format!("{outcome:?}"), "NoQuorum");
    assert_eq!(
        market.get_task(&task.id).unwrap().state,
        TaskState::NoQuorum
    );
    // And NoQuorum has a recovery edge (upstream's was absorbing).
    assert!(TaskState::NoQuorum.can_transition_to(TaskState::Open));
}

#[test]
fn a_committee_assigned_for_one_task_cannot_verify_another() {
    let (mut market, task, _r, _a) = ready_market();
    let members = vec![id(11).did(), id(12).did(), id(13).did()];
    let mut committee = Committee::assign(
        CommitteeSpec::new(3, 0).unwrap(),
        "some-other-task",
        members,
    )
    .unwrap();
    let votes = vec![vote_of(&id(11), task.id.as_str(), Decision::Accept, 1)];
    let err = market
        .verify_result(&task.id, &mut committee, &votes, 1_700_000_400)
        .unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
}

#[test]
fn a_bid_must_be_positive_valid_and_from_a_qualified_agent() {
    let requester = id(1);
    let agent = id(2);
    let mut market = Market::new(MarketConfig::default());
    fund(&mut market, &did_account(&requester), major(1_000), 1);
    fund(&mut market, &did_account(&agent), major(1_000), 1);
    market
        .register_agent(card(&agent, "t", major(100)), 1_700_000_010)
        .unwrap();
    let task = task_of(&requester, major(50), 1);
    market.publish_task(task.clone(), 1_700_000_100).unwrap();

    // Zero price: upstream scored this as a *win* and then paid the full budget.
    let mut zero = bid_of(&agent, &task, major(1), 2);
    zero.price = Money::ZERO;
    zero.sign(&agent).unwrap();
    assert!(market.submit_bid(zero, 1_700_000_200).is_err());

    // Over budget.
    let mut over = bid_of(&agent, &task, major(1), 3);
    over.price = major(51);
    over.sign(&agent).unwrap();
    assert!(market.submit_bid(over, 1_700_000_200).is_err());

    // An agent with no matching skill.
    let wrong = id(3);
    fund(&mut market, &did_account(&wrong), major(1_000), 1);
    let mut other = AgentCard::draft(
        &wrong,
        "wrong",
        vec![Skill::new("image-generation", 1)],
        major(100),
        1_700_000_000,
        1,
    );
    other.sign(&wrong).unwrap();
    market.register_agent(other, 1_700_000_010).unwrap();
    let bad = bid_of(&wrong, &task, major(10), 2);
    let err = market.submit_bid(bad, 1_700_000_200).unwrap_err();
    assert!(err.to_string().contains("required skill"), "got {err}");
}

#[test]
fn bids_are_refused_after_a_task_stops_accepting_them() {
    let (mut market, task, _r, agent) = ready_market();
    // The task is now Submitted.
    let late = bid_of(&agent, &task, major(10), 99);
    let err = market.submit_bid(late, 1_700_000_350).unwrap_err();
    assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
}

#[test]
fn only_the_assigned_executor_may_start_or_submit() {
    let requester = id(1);
    let agent = id(2);
    let other = id(3);
    let mut market = Market::new(MarketConfig::default());
    fund(&mut market, &did_account(&requester), major(1_000), 1);
    fund(&mut market, &did_account(&agent), major(1_000), 1);
    market
        .register_agent(card(&agent, "t", major(100)), 1_700_000_010)
        .unwrap();
    let task = task_of(&requester, major(50), 1);
    market.publish_task(task.clone(), 1_700_000_100).unwrap();
    market
        .submit_bid(bid_of(&agent, &task, major(40), 2), 1_700_000_200)
        .unwrap();
    market.match_task(&task.id, 1_700_000_210).unwrap();

    let err = market
        .start_task(&task.id, &other.did(), 1_700_000_220)
        .unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");

    market
        .start_task(&task.id, &agent.did(), 1_700_000_220)
        .unwrap();
    // A forged result from someone else is refused.
    let mut forged = result_of(&other, &task, EvidenceGrade::Verified, 1);
    forged.task_id = task.id.clone();
    forged.sign(&other).unwrap();
    let err = market.submit_result(forged, 1_700_000_300).unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");
}

#[test]
fn replaying_a_signed_object_is_refused() {
    let requester = id(1);
    let agent = id(2);
    let mut market = Market::new(MarketConfig::default());
    fund(&mut market, &did_account(&requester), major(1_000), 1);
    fund(&mut market, &did_account(&agent), major(1_000), 1);
    market
        .register_agent(card(&agent, "t", major(100)), 1_700_000_010)
        .unwrap();

    let task = task_of(&requester, major(50), 1);
    market.publish_task(task.clone(), 1_700_000_100).unwrap();
    // The same signed task, replayed, must be refused (Conflict: same id).
    assert!(market.publish_task(task.clone(), 1_700_000_100).is_err());

    // A second task reusing the same nonce is refused as a replay.
    let mut second = task_of(&requester, major(50), 1);
    second.id = TaskId::parse("task-2").unwrap();
    second.sign(&requester).unwrap();
    let err = market.publish_task(second, 1_700_000_100).unwrap_err();
    assert!(matches!(err, NauError::Stale(_)), "got {err:?}");
}

#[test]
fn duplicate_registration_tops_up_rather_than_double_counting() {
    let agent = id(2);
    let mut market = Market::new(MarketConfig::default());
    fund(&mut market, &did_account(&agent), major(1_000), 1);
    market
        .register_agent(card(&agent, "t", major(100)), 1_700_000_010)
        .unwrap();
    let staked_after_first = market.balance(&Market::stake_account_for(&agent.did()));
    assert_eq!(staked_after_first, major(100));

    // Re-register with a higher nonce and the same stake.
    let mut again = card(&agent, "t", major(100));
    again.nonce = 2;
    again.sign(&agent).unwrap();
    market.register_agent(again, 1_700_000_020).unwrap();
    assert_eq!(
        market.balance(&Market::stake_account_for(&agent.did())),
        major(100),
        "re-registration must not lock the stake twice"
    );

    // Reusing a nonce is a replay.
    let mut stale = card(&agent, "t", major(100));
    stale.nonce = 1;
    stale.sign(&agent).unwrap();
    assert!(market.register_agent(stale, 1_700_000_030).is_err());
}

#[test]
fn a_stake_below_the_minimum_is_refused() {
    let agent = id(2);
    let mut market = Market::new(MarketConfig::default());
    fund(&mut market, &did_account(&agent), major(1_000), 1);
    let err = market
        .register_agent(card(&agent, "t", major(1)), 1_700_000_010)
        .unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
}

#[test]
fn an_agent_with_no_available_funds_cannot_stake() {
    let agent = id(2);
    let mut market = Market::new(MarketConfig::default());
    // No deposit at all.
    let err = market
        .register_agent(card(&agent, "t", major(100)), 1_700_000_010)
        .unwrap_err();
    assert!(
        matches!(err, NauError::InsufficientBalance { .. }),
        "got {err:?}"
    );
}

#[test]
fn discovery_and_search_are_deterministically_ordered() {
    let mut market = Market::new(MarketConfig::default());
    for (i, name) in ["zeta", "alpha", "mid"].iter().enumerate() {
        let a = id(20 + i as u8);
        market
            .deposit(&account(a.did().as_str()), major(1_000), 1)
            .unwrap();
        market
            .register_agent(card(&a, name, major(100)), 1_700_000_010 + i as u64)
            .unwrap();
    }
    let first: Vec<String> = market
        .discover("translation")
        .iter()
        .map(|c| c.name.clone())
        .collect();
    let second: Vec<String> = market
        .discover("translation")
        .iter()
        .map(|c| c.name.clone())
        .collect();
    assert_eq!(first, second, "discovery must be stable across calls");
    assert_eq!(first.len(), 3);
    // Ordering is by DID (a stable key), not by hash order and not by name.
    let dids: Vec<String> = market
        .discover("translation")
        .iter()
        .map(|c| c.owner.to_string())
        .collect();
    let mut sorted_dids = dids.clone();
    sorted_dids.sort();
    assert_eq!(dids, sorted_dids, "discovery must be ordered by DID");
    // A card update must not leave a stale index entry behind.
    assert_eq!(market.discover("translation").len(), 3);

    assert_eq!(
        market.search("ALPHA").len(),
        1,
        "search is case-insensitive"
    );
    assert!(market.search("nomatch").is_empty());
}

#[test]
fn a_guilty_ruling_actually_slashes_the_stake_and_a_party_cannot_arbitrate() {
    let requester = id(1);
    let agent = id(2);
    let arbiter = id(5);
    let mut market = Market::new(MarketConfig::default());
    fund(&mut market, &did_account(&requester), major(1_000), 1);
    fund(&mut market, &did_account(&agent), major(1_000), 1);
    market
        .register_agent(card(&agent, "t", major(100)), 1_700_000_010)
        .unwrap();
    let task = task_of(&requester, major(50), 1);
    market.publish_task(task.clone(), 1_700_000_100).unwrap();
    market
        .submit_bid(bid_of(&agent, &task, major(40), 2), 1_700_000_200)
        .unwrap();
    market.match_task(&task.id, 1_700_000_210).unwrap();

    let mut dispute = Dispute {
        id: "d1".into(),
        task_id: task.id.clone(),
        complainant: requester.did(),
        complainant_key: requester.public_key(),
        respondent: agent.did(),
        reason: "delivered nothing".into(),
        evidence_digest: None,
        nonce: 2,
        signed_at: 1_700_000_300,
        signature: String::new(),
    };
    dispute.sign(&requester).unwrap();
    market.open_dispute(dispute, 1_700_000_310).unwrap();

    // A party to the dispute cannot arbitrate it.
    let mut biased = DisputeOutcome {
        dispute_id: "d1".into(),
        task_id: task.id.clone(),
        guilty: true,
        slash_amount: major(10),
        ruling: "at fault".into(),
        arbitrator: requester.did(),
        arbitrator_key: requester.public_key(),
        nonce: 3,
        signed_at: 1_700_000_400,
        signature: String::new(),
    };
    biased.sign(&requester).unwrap();
    let err = market.arbitrate(biased, 1_700_000_410).unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");

    // A guilty verdict with no slash is structurally invalid.
    let mut no_slash = DisputeOutcome {
        dispute_id: "d1".into(),
        task_id: task.id.clone(),
        guilty: true,
        slash_amount: Money::ZERO,
        ruling: "at fault".into(),
        arbitrator: arbiter.did(),
        arbitrator_key: arbiter.public_key(),
        nonce: 1,
        signed_at: 1_700_000_400,
        signature: String::new(),
    };
    no_slash.sign(&arbiter).unwrap();
    assert!(market.arbitrate(no_slash, 1_700_000_410).is_err());

    // A real guilty ruling slashes the stake.
    let stake_before = market.balance(&Market::stake_account_for(&agent.did()));
    let mut ruling = DisputeOutcome {
        dispute_id: "d1".into(),
        task_id: task.id.clone(),
        guilty: true,
        slash_amount: major(10),
        ruling: "at fault".into(),
        arbitrator: arbiter.did(),
        arbitrator_key: arbiter.public_key(),
        nonce: 2,
        signed_at: 1_700_000_400,
        signature: String::new(),
    };
    ruling.sign(&arbiter).unwrap();
    let slashed = market.arbitrate(ruling, 1_700_000_410).unwrap();
    assert_eq!(slashed, major(10));
    assert_eq!(
        market.balance(&Market::stake_account_for(&agent.did())),
        stake_before.checked_sub(major(10)).unwrap()
    );
    assert_eq!(market.get_task(&task.id).unwrap().state, TaskState::Slashed);
    assert_eq!(market.reputation(&agent.did()).unwrap().faults, 1);
    // Conservation still holds after a slash.
    assert!(market.conservation().conserved);
    assert!(market.audit().conserved);
}

#[test]
fn a_non_party_cannot_open_a_dispute() {
    let (mut market, task, _r, _a) = ready_market();
    let outsider = id(77);
    let mut d = Dispute {
        id: "d1".into(),
        task_id: task.id.clone(),
        complainant: outsider.did(),
        complainant_key: outsider.public_key(),
        respondent: id(2).did(),
        reason: "I just do not like it".into(),
        evidence_digest: None,
        nonce: 1,
        signed_at: 1_700_000_400,
        signature: String::new(),
    };
    d.sign(&outsider).unwrap();
    let err = market.open_dispute(d, 1_700_000_410).unwrap_err();
    assert!(matches!(err, NauError::Unauthorized(_)), "got {err:?}");
}

#[test]
fn state_is_restored_from_disk_including_the_ledger() {
    use nau_store::FileStore;

    let dir = std::env::temp_dir().join(format!(
        "nau-market-restore-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store = FileStore::open(&dir).expect("open store");

    let (mut market, task, _r, agent) = ready_market();
    let conservation_before = market.conservation();
    let balance_before = market.balance(&did_account(&agent));
    market.persist(&store).unwrap();
    drop(market);

    // Reopen from disk: upstream never did this (its loader had zero call sites).
    let restored = Market::restore(MarketConfig::default(), &store, 1_700_000_300).unwrap();
    assert_eq!(restored.agents().len(), 1);
    assert_eq!(restored.get_agent(&agent.did()).unwrap().name, "translator");
    assert_eq!(restored.get_task(&task.id).unwrap().id, task.id);
    assert_eq!(
        restored.balance(&did_account(&agent)),
        balance_before,
        "balances must survive a restart exactly"
    );
    let after = restored.conservation();
    assert_eq!(after.total_deposited, conservation_before.total_deposited);
    assert_eq!(after.total_escrowed, conservation_before.total_escrowed);
    assert_eq!(after.discrepancy, 0);
    assert!(restored.audit().conserved);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_o_n_audit_detects_corruption_that_the_o_1_check_cannot() {
    // This is the test upstream lacked: its `conservation_check` compared three
    // counters that are always updated together, so it could not fail.
    let (market, _task, _r, _a) = ready_market();
    let o1 = market.conservation();
    let on = market.audit();
    assert!(o1.conserved && on.conserved);
    assert_eq!(o1.discrepancy, on.discrepancy);
    assert_eq!(o1.sum_of_balances, on.sum_of_balances);
    // The audit recomputes from the account table; the O(1) path reads counters.
    // They must agree, and `audit()` is the one exercised on the CI path.
    assert_eq!(on.accounted_total, o1.accounted_total);
}

#[test]
fn stats_and_leaderboard_are_consistent() {
    let (market, _task, _r, agent) = ready_market();
    let stats = market.stats();
    assert_eq!(stats.agents, 1);
    assert_eq!(stats.tasks, 1);
    assert_eq!(stats.escrowed_minor, major(50).minor());

    let board = market.leaderboard(10);
    assert_eq!(board.len(), 1);
    assert_eq!(board[0].0, agent.did());
    assert!(board[0].1 <= 10_000);
}

/// THE DEPLOYMENT DEFECT. `Market::persist` re-appended the ENTIRE journal on
/// every call, because it iterated `ledger.entries()` and handed each entry to
/// `Store::append_ledger`, which appends by contract. A deployed daemon whose
/// balance read `12.8` before a restart read `38` after it: the restart replayed
/// the duplicated journal, so restarting the process minted money.
///
/// No pre-existing test could catch it, and that is the point worth recording.
/// Every other test here builds a market, persists ONCE and restores. The
/// duplication needs a SECOND persist -- which is exactly what a running daemon
/// does, on a timer and after every mutating request. It took
/// `scripts/deploy-local.mjs` running the real binary against a real data
/// directory to surface it.
#[test]
fn persisting_twice_does_not_duplicate_the_journal() {
    use nau_store::{FileStore, Store};

    let dir = std::env::temp_dir().join(format!(
        "nau-market-journal-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store = FileStore::open(&dir).expect("open store");

    let (mut market, _task, _r, agent) = ready_market();
    let account = did_account(&agent);
    let balance = market.balance(&account);

    market.persist(&store).unwrap();
    let after_first = store.load_ledger().unwrap().len();
    assert!(
        after_first > 0,
        "the fixture must have journalled something"
    );

    // An idle persist must add nothing. This is the assertion the bug fails, and
    // it fails loudly: the journal doubled on each call.
    market.persist(&store).unwrap();
    market.persist(&store).unwrap();
    assert_eq!(
        store.load_ledger().unwrap().len(),
        after_first,
        "an idle persist appended the whole journal again"
    );

    // New activity adds exactly its own entry, not a fresh copy of everything.
    market.deposit(&account, major(1), 1_700_000_200).unwrap();
    market.persist(&store).unwrap();
    let after_deposit = store.load_ledger().unwrap().len();
    assert_eq!(
        after_deposit,
        after_first + 1,
        "a single deposit must journal exactly one entry"
    );

    // And the balance survives a restart unchanged -- the property the deployed
    // daemon was violating.
    let mut restored = Market::restore(MarketConfig::default(), &store, 1_700_000_300).unwrap();
    assert_eq!(
        restored.balance(&account),
        balance.checked_add(major(1)).unwrap(),
        "a restart changed the balance"
    );

    // A restore followed by a persist must not re-append what it just loaded.
    // `Market::restore` records how much of the journal is already on disk; that
    // is what makes the promise in its doc comment true.
    restored.persist(&store).unwrap();
    assert_eq!(
        store.load_ledger().unwrap().len(),
        after_deposit,
        "a restore-then-persist duplicated the journal"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
