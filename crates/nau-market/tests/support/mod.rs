//! Shared fixtures for the `nau-market` integration tests.
//!
//! Not a test target itself (it lives in a subdirectory), so the no-panics gate
//! does not apply to it — and neither does production discipline: these helpers
//! build signed objects and are allowed to `expect`. Each test binary compiles the
//! whole module and uses only part of it, hence the dead-code allowance.

#![allow(dead_code)]

use std::collections::BTreeMap;

use nau_consensus::{Committee, CommitteeSpec, Decision, Outcome, Vote};
use nau_core::domain::money::major;
use nau_core::domain::{EvidenceGrade, Verifiable};
use nau_core::{
    AgentCard, Bid, Dispute, DisputeOutcome, Identity, Money, Pricing, ResultEnvelope, Skill, Sla,
    Task, TaskId, TaskSpec, VerificationPolicy,
};
use nau_ledger::AccountId;
use nau_market::{Market, MarketConfig};

/// A fixed base timestamp for every fixture.
pub const T0: u64 = 1_700_000_000;

/// A deterministic identity from a one-byte seed.
pub fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

/// A free-form account id.
pub fn account(s: &str) -> AccountId {
    AccountId::parse(s).expect("valid account id")
}

/// The ledger account that belongs to an identity.
pub fn did_account(id: &Identity) -> AccountId {
    AccountId::parse(id.did().as_str()).expect("a DID is a valid account id")
}

/// Credit an identity's account.
pub fn fund(market: &mut Market, account: &AccountId, amount: Money, at: u64) {
    market.deposit(account, amount, at).expect("deposit");
}

/// An agent card with an explicit SLA, ready to register.
pub fn card(agent: &Identity, stake: Money, p95_ms: u64, nonce: u64, at: u64) -> AgentCard {
    let mut c = AgentCard::draft(
        agent,
        "translator",
        vec![Skill::new("translation", 1)],
        stake,
        T0,
        nonce,
    );
    c.pricing = Pricing::default();
    c.sla = Sla {
        latency_p95_ms: p95_ms,
        availability_bps: 9_900,
        max_concurrency: 4,
    };
    c.sign(agent).expect("sign card");
    let _ = at;
    c
}

/// A signed task, ready to publish.
pub fn task_of(
    requester: &Identity,
    task_id: &str,
    budget: Money,
    nonce: u64,
    signed_at: u64,
    policy: VerificationPolicy,
) -> Task {
    let mut t = Task::draft(
        TaskId::parse(task_id).expect("task id"),
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
        policy,
        requester.public_key(),
        signed_at,
        nonce,
    );
    t.sign(requester).expect("sign task");
    t
}

/// A signed bid.
pub fn bid_of(bidder: &Identity, task: &Task, price: Money, nonce: u64, signed_at: u64) -> Bid {
    let mut b = Bid {
        task_id: task.id.clone(),
        bidder: bidder.did(),
        bidder_key: bidder.public_key(),
        price,
        eta_secs: 10,
        confidence_bps: 9_000,
        expires_at: None,
        nonce,
        signed_at,
        signature: String::new(),
    };
    b.sign(bidder).expect("sign bid");
    b
}

/// A signed result envelope.
pub fn result_of(
    agent: &Identity,
    task: &Task,
    grade: EvidenceGrade,
    nonce: u64,
    signed_at: u64,
) -> ResultEnvelope {
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
        signed_at,
        signature: String::new(),
    };
    r.sign(agent).expect("sign result");
    r
}

/// A signed committee vote.
pub fn vote_of(member: &Identity, proposal: &str, decision: Decision, nonce: u64) -> Vote {
    let mut v = Vote {
        round: 0,
        proposal: proposal.to_string(),
        voter: member.did(),
        voter_key: member.public_key(),
        decision,
        nonce,
        signed_at: T0 + 100,
        signature: String::new(),
    };
    v.sign(member).expect("sign vote");
    v
}

/// A signed dispute.
pub fn dispute_of(
    complainant: &Identity,
    task: &Task,
    respondent: &Identity,
    dispute_id: &str,
    nonce: u64,
    signed_at: u64,
) -> Dispute {
    let mut d = Dispute {
        id: dispute_id.to_string(),
        task_id: task.id.clone(),
        complainant: complainant.did(),
        complainant_key: complainant.public_key(),
        respondent: respondent.did(),
        reason: "delivered nothing".into(),
        evidence_digest: None,
        nonce,
        signed_at,
        signature: String::new(),
    };
    d.sign(complainant).expect("sign dispute");
    d
}

/// A signed ruling.
#[allow(clippy::too_many_arguments)]
pub fn ruling_of(
    arbitrator: &Identity,
    dispute_id: &str,
    task: &Task,
    guilty: bool,
    slash_amount: Money,
    nonce: u64,
    signed_at: u64,
) -> DisputeOutcome {
    let mut r = DisputeOutcome {
        dispute_id: dispute_id.to_string(),
        task_id: task.id.clone(),
        guilty,
        slash_amount,
        ruling: "at fault".into(),
        arbitrator: arbitrator.did(),
        arbitrator_key: arbitrator.public_key(),
        nonce,
        signed_at,
        signature: String::new(),
    };
    r.sign(arbitrator).expect("sign ruling");
    r
}

/// A monotonic per-identity nonce allocator.
///
/// Nonces are a single increasing sequence per DID across every object that DID
/// signs, so tests must allocate them from one place or they fail as replays.
#[derive(Debug, Default)]
pub struct Nonces {
    next: BTreeMap<String, u64>,
}

impl Nonces {
    /// An allocator that will hand out `1` for every identity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve the nonce already used for `id`, so the next one is higher.
    pub fn starting_at(&mut self, id: &Identity, nonce: u64) {
        self.next.insert(id.did().to_string(), nonce);
    }

    /// The next nonce for `id`.
    pub fn take(&mut self, id: &Identity) -> u64 {
        let slot = self.next.entry(id.did().to_string()).or_insert(0);
        *slot += 1;
        *slot
    }
}

/// A market plus the identities and clock a lifecycle test needs.
pub struct Fixture {
    /// The market under test.
    pub market: Market,
    /// The task requester.
    pub requester: Identity,
    /// The registered executor.
    pub agent: Identity,
    /// A neutral arbitrator who is never a party.
    pub arbiter: Identity,
    /// The configuration the market was built with, for a later restore.
    pub config: MarketConfig,
    /// Per-identity nonce allocation.
    pub nonces: Nonces,
    /// A monotonically increasing clock. Every object is signed "now".
    pub clock: u64,
}

impl Fixture {
    /// Build a market with the default configuration: both identities funded and
    /// the agent registered with a 100-major-unit stake.
    pub fn new() -> Self {
        Self::with_config(MarketConfig::default())
    }

    /// Build a market with an explicit configuration.
    pub fn with_config(config: MarketConfig) -> Self {
        let requester = id(1);
        let agent = id(2);
        let arbiter = id(5);
        let mut market = Market::new(config.clone());
        fund(&mut market, &did_account(&requester), major(1_000), T0);
        fund(&mut market, &did_account(&agent), major(1_000), T0);
        let mut nonces = Nonces::new();
        let card_nonce = nonces.take(&agent);
        market
            .register_agent(card(&agent, major(100), 60_000, card_nonce, T0), T0 + 10)
            .expect("register agent");
        Self {
            market,
            requester,
            agent,
            arbiter,
            config,
            nonces,
            clock: T0 + 10,
        }
    }

    /// Advance the clock and return the new instant.
    pub fn tick(&mut self) -> u64 {
        self.clock += 10;
        self.clock
    }

    /// Publish a task and return it.
    pub fn publish(&mut self, task_id: &str, budget: Money) -> Task {
        let nonce = self.nonces.take(&self.requester);
        let at = self.tick();
        let task = task_of(
            &self.requester,
            task_id,
            budget,
            nonce,
            at,
            VerificationPolicy::Committee { n: 3, f: 0 },
        );
        self.market.publish_task(task.clone(), at).expect("publish");
        task
    }

    /// Submit a bid from the registered agent.
    pub fn bid(&mut self, task: &Task, price: Money) -> Bid {
        let nonce = self.nonces.take(&self.agent);
        let at = self.tick();
        let bid = bid_of(&self.agent, task, price, nonce, at);
        self.market.submit_bid(bid.clone(), at).expect("bid");
        bid
    }

    /// Match the task to the agent and start it.
    pub fn match_and_start(&mut self, task: &Task) {
        let at = self.tick();
        self.market.match_task(&task.id, at).expect("match");
        let at = self.tick();
        self.market
            .start_task(&task.id, &self.agent.did(), at)
            .expect("start");
    }

    /// Submit a result from the assigned agent.
    pub fn submit_result(&mut self, task: &Task, grade: EvidenceGrade) -> ResultEnvelope {
        let nonce = self.nonces.take(&self.agent);
        let at = self.tick();
        let envelope = result_of(&self.agent, task, grade, nonce, at);
        self.market
            .submit_result(envelope.clone(), at)
            .expect("submit result");
        envelope
    }

    /// Cast a fresh committee round with the given verdict.
    pub fn verify(&mut self, task_id: &TaskId, decision: Decision) -> Outcome {
        let at = self.tick();
        let members: Vec<_> = [11u8, 12, 13].iter().map(|s| id(*s).did()).collect();
        let mut committee = Committee::assign(
            CommitteeSpec::new(3, 0).expect("spec"),
            task_id.as_str(),
            members,
        )
        .expect("committee");
        let votes: Vec<Vote> = [11u8, 12, 13]
            .iter()
            .enumerate()
            .map(|(i, seed)| vote_of(&id(*seed), task_id.as_str(), decision, i as u64 + 1))
            .collect();
        self.market
            .verify_result(task_id, &mut committee, &votes, at)
            .expect("verify")
    }

    /// Publish, bid, match, start, submit and accept in one call.
    pub fn run_to_accepted(
        &mut self,
        task_id: &str,
        budget: Money,
        price: Money,
        grade: EvidenceGrade,
    ) -> Task {
        let task = self.publish(task_id, budget);
        self.bid(&task, price);
        self.match_and_start(&task);
        self.submit_result(&task, grade);
        self.verify(&task.id, Decision::Accept);
        self.market.get_task(&task.id).expect("task").clone()
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}
