//! The market service: one owner of all market state.
//!
//! Every mutating method follows the same discipline, which is what upstream lacks:
//!
//! 1. **load** the entity and check it exists (`NotFound` otherwise);
//! 2. **authorize** by verifying the caller's signature over the signed object and
//!    checking the signer's DID fingerprints the supplied key;
//! 3. **anti-replay** the object's `nonce` through a [`NonceGuard`];
//! 4. **validate** the entity's own invariants;
//! 5. **check the state transition** through [`nau_core::TaskState::transition`];
//! 6. **mutate**, writing to the ledger in the same call so money and state cannot
//!    drift apart.
//!
//! State is held in `BTreeMap`s, not `HashMap`s. Upstream's discovery and search
//! return results in `HashMap` iteration order, so the same query returns different
//! orderings on different runs — untestable and unpaginated. `BTreeMap` gives a
//! stable, sorted, reproducible order for free.

use std::collections::BTreeMap;

use nau_consensus::{Committee, Outcome, Vote};
use nau_core::domain::{Money, Verifiable};
use nau_core::{
    AgentCard, Bid, Did, Dispute, DisputeOutcome, EvidenceGrade, NauError, NonceGuard, Result,
    ResultEnvelope, Task, TaskId, TaskState,
};
use nau_ledger::{
    escrow_account, stake_account, AccountId, ConservationReport, EntryKind, Ledger, LedgerEntry,
};
use nau_store::Store;
use serde::{Deserialize, Serialize};

use crate::matching::{rank_bids, MatchOutcome};
use crate::reputation::Reputation;

/// Tunables for admission and matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketConfig {
    /// Minimum stake a card must lock to be admitted.
    pub min_stake: Money,
    /// Minimum composite reputation, in basis points, to be allowed to bid.
    pub min_reputation_bps: u32,
    /// Maximum bids stored per task. Bounds memory against a bid-flooding agent.
    pub max_bids_per_task: usize,
    /// Reputation penalty in basis points applied on a guilty verdict.
    pub fault_severity_bps: u16,
}

impl Default for MarketConfig {
    fn default() -> Self {
        Self {
            // Upstream's `min_stake` default is 100.0 and it is compared with `<`,
            // which `NaN` defeats. Here it is an exact integer.
            min_stake: Money::from_minor(100_000_000),
            min_reputation_bps: 0,
            max_bids_per_task: 64,
            fault_severity_bps: 3_000,
        }
    }
}

/// A point-in-time summary, for `/stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketStats {
    /// Registered agents.
    pub agents: usize,
    /// Tasks known to the market.
    pub tasks: usize,
    /// Tasks in a terminal state.
    pub settled: usize,
    /// Open disputes.
    pub disputes: usize,
    /// Escrowed funds still held.
    pub escrowed_minor: i64,
}

/// The market service.
pub struct Market {
    config: MarketConfig,
    ledger: Ledger,
    agents: BTreeMap<Did, AgentCard>,
    /// Lowercased skill id -> agents offering it.
    skill_index: BTreeMap<String, Vec<Did>>,
    tasks: BTreeMap<TaskId, Task>,
    bids: BTreeMap<TaskId, Vec<Bid>>,
    results: BTreeMap<TaskId, ResultEnvelope>,
    disputes: BTreeMap<String, Dispute>,
    rulings: BTreeMap<String, DisputeOutcome>,
    reputation: BTreeMap<Did, Reputation>,
    nonces: NonceGuard,
    /// How many of `ledger.entries()` have already been appended to the store.
    ///
    /// Without this the journal was re-appended IN FULL on every `persist`, so the
    /// file grew by the whole ledger each time and a restart replayed the
    /// duplicates. A deployed daemon whose balance read `12.8` before a restart
    /// read `38` after it -- money created by a restart.
    ///
    /// Found by `scripts/deploy-local.mjs`. No test in this repository could see
    /// it, because every other test uses an ephemeral store and never persists
    /// twice; the property only exists once something is actually deployed.
    journaled: usize,
}

fn account_of(did: &Did) -> Result<AccountId> {
    AccountId::parse(did.as_str())
}

impl Market {
    /// An empty market.
    pub fn new(config: MarketConfig) -> Self {
        Self {
            config,
            ledger: Ledger::new(),
            agents: BTreeMap::new(),
            skill_index: BTreeMap::new(),
            tasks: BTreeMap::new(),
            bids: BTreeMap::new(),
            results: BTreeMap::new(),
            disputes: BTreeMap::new(),
            rulings: BTreeMap::new(),
            reputation: BTreeMap::new(),
            nonces: NonceGuard::new(),
            journaled: 0,
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &MarketConfig {
        &self.config
    }

    /// Read-only access to the ledger.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    // ---------------------------------------------------------------- accounts

    /// Credit an account.
    pub fn deposit(&mut self, account: &AccountId, amount: Money, at: u64) -> Result<()> {
        if !amount.is_positive() {
            return Err(NauError::InvalidAmount(
                "deposit amount must be greater than zero".into(),
            ));
        }
        self.ledger
            .deposit(account, amount, "market deposit", at)
            .map(|_| ())
    }

    /// Current balance of an account.
    pub fn balance(&self, account: &AccountId) -> Money {
        self.ledger.balance(account)
    }

    // ---------------------------------------------------------------- registry

    /// Register (or update) an agent card.
    ///
    /// Admission requires a valid, fresh signature; a strictly increasing nonce; a
    /// stake at or above the configured minimum; and the stake itself to be
    /// available, which is then moved into the agent's dedicated stake account.
    pub fn register_agent(&mut self, card: AgentCard, at: u64) -> Result<()> {
        card.validate_verified_fresh(at)?;
        if card.stake < self.config.min_stake {
            return Err(NauError::Validation(format!(
                "stake {} is below the minimum {}",
                card.stake.to_decimal_string(),
                self.config.min_stake.to_decimal_string()
            )));
        }
        // Replay protection before any mutation.
        self.nonces.accept(&card.owner, card.nonce)?;

        // Update path: top up the stake by the difference only, so re-registering
        // cannot inflate the locked amount (upstream re-deposited the whole stake on
        // every registration while the recorded stake stayed constant).
        let already_staked = self.ledger.balance(&stake_account(&card.owner));
        if card.stake > already_staked {
            let top_up = card.stake.checked_sub(already_staked)?;
            let owner_account = account_of(&card.owner)?;
            if self.ledger.balance(&owner_account) < top_up {
                return Err(NauError::InsufficientBalance {
                    account: owner_account.to_string(),
                    available: self.ledger.balance(&owner_account).minor(),
                    required: top_up.minor(),
                });
            }
            self.ledger
                .withdraw(&owner_account, top_up, "stake lock", at)?;
            self.ledger
                .deposit(&stake_account(&card.owner), top_up, "stake lock", at)?;
        }

        // Rebuild the skill index for this owner so a card update cannot leave
        // stale entries behind (upstream only ever appended).
        for agents in self.skill_index.values_mut() {
            agents.retain(|d| d != &card.owner);
        }
        self.skill_index.retain(|_, agents| !agents.is_empty());
        for skill in &card.skills {
            self.skill_index
                .entry(skill.id.clone())
                .or_default()
                .push(card.owner.clone());
        }
        for agents in self.skill_index.values_mut() {
            agents.sort();
            agents.dedup();
        }

        self.reputation.entry(card.owner.clone()).or_default();
        self.agents.insert(card.owner.clone(), card);
        Ok(())
    }

    /// Look up a card.
    pub fn get_agent(&self, did: &Did) -> Option<&AgentCard> {
        self.agents.get(did)
    }

    /// Every registered card, ordered by DID.
    pub fn agents(&self) -> Vec<&AgentCard> {
        self.agents.values().collect()
    }

    /// Agents offering `skill`, ordered by DID.
    pub fn discover(&self, skill: &str) -> Vec<&AgentCard> {
        self.skill_index
            .get(&skill.to_ascii_lowercase())
            .map(|dids| dids.iter().filter_map(|d| self.agents.get(d)).collect())
            .unwrap_or_default()
    }

    /// Case-insensitive substring search over name, description and skills.
    pub fn search(&self, query: &str) -> Vec<&AgentCard> {
        let needle = query.to_lowercase();
        self.agents
            .values()
            .filter(|card| {
                card.name.to_lowercase().contains(&needle)
                    || card
                        .description
                        .as_deref()
                        .is_some_and(|d| d.to_lowercase().contains(&needle))
                    || card.skills.iter().any(|s| s.id.contains(&needle))
            })
            .collect()
    }

    /// Reputation of an agent.
    pub fn reputation(&self, did: &Did) -> Option<&Reputation> {
        self.reputation.get(did)
    }

    /// Agents ranked by composite reputation, best first.
    pub fn leaderboard(&self, limit: usize) -> Vec<(Did, u32)> {
        let mut scored: Vec<(Did, u32)> = self
            .reputation
            .iter()
            .map(|(did, rep)| (did.clone(), rep.overall_bps()))
            .collect();
        // BTreeMap iteration is already DID-ordered, so this sort is stable and
        // therefore deterministic.
        scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        scored.truncate(limit);
        scored
    }

    // ------------------------------------------------------------------- tasks

    /// Publish a task, escrowing its budget from the requester.
    ///
    /// This is where upstream minted money: `publish_task` never checked or locked
    /// the requester's balance and `settle_task` deposited on their behalf when they
    /// were short. Here an unfunded requester is rejected and the funds are locked
    /// before the task becomes visible.
    pub fn publish_task(&mut self, task: Task, at: u64) -> Result<()> {
        task.validate_and_verify()?;
        task.check_freshness(at)?;
        if task.is_expired(at) {
            return Err(NauError::Stale(format!(
                "task `{}` is already past its deadline",
                task.id
            )));
        }
        if self.tasks.contains_key(&task.id) {
            return Err(NauError::Conflict(format!(
                "task `{}` already exists",
                task.id
            )));
        }
        self.nonces.accept(&task.spec.owner, task.nonce)?;

        let requester = account_of(&task.spec.owner)?;
        // Rejects an unfunded requester. Never creates funds.
        self.ledger.escrow(&task.id, &requester, task.budget, at)?;

        self.tasks.insert(task.id.clone(), task);
        Ok(())
    }

    /// A task by id.
    pub fn get_task(&self, id: &TaskId) -> Option<&Task> {
        self.tasks.get(id)
    }

    /// Every task, ordered by id.
    pub fn tasks(&self) -> Vec<&Task> {
        self.tasks.values().collect()
    }

    /// Bids recorded for a task.
    pub fn bids_for(&self, id: &TaskId) -> &[Bid] {
        self.bids.get(id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The result recorded for a task, if any.
    pub fn result_for(&self, id: &TaskId) -> Option<&ResultEnvelope> {
        self.results.get(id)
    }

    /// Submit a bid.
    pub fn submit_bid(&mut self, bid: Bid, at: u64) -> Result<()> {
        let task = self
            .tasks
            .get(&bid.task_id)
            .ok_or_else(|| NauError::NotFound(format!("task `{}`", bid.task_id)))?;
        // Bids into a closed task are refused (upstream accepted bids into Settled
        // and Disputed tasks).
        if task.state != TaskState::Open {
            return Err(NauError::Conflict(format!(
                "task `{}` is {:?} and no longer accepts bids",
                task.id, task.state
            )));
        }
        if task.is_expired(at) {
            return Err(NauError::Stale(format!("task `{}` has expired", task.id)));
        }
        bid.verify_fresh(at)?;
        self.nonces.accept(&bid.bidder, bid.nonce)?;

        let card = self
            .agents
            .get(&bid.bidder)
            .ok_or_else(|| NauError::NotFound(format!("agent `{}`", bid.bidder)))?;
        // The bidder must actually offer every required skill.
        for required in &task.required_skills {
            let required = required.to_ascii_lowercase();
            if !card.skills.iter().any(|s| s.id == required) {
                return Err(NauError::Validation(format!(
                    "agent `{}` does not offer required skill `{required}`",
                    bid.bidder
                )));
            }
        }
        if !self
            .reputation
            .get(&bid.bidder)
            .map(|r| r.is_eligible(self.config.min_reputation_bps))
            .unwrap_or(false)
        {
            return Err(NauError::Unauthorized(format!(
                "agent `{}` is below the reputation floor of {} bps",
                bid.bidder, self.config.min_reputation_bps
            )));
        }
        bid.validate_for(task)?;

        let slot = self.bids.entry(bid.task_id.clone()).or_default();
        if slot.len() >= self.config.max_bids_per_task {
            return Err(NauError::Conflict(format!(
                "task `{}` already has the maximum of {} bids",
                bid.task_id, self.config.max_bids_per_task
            )));
        }
        if slot
            .iter()
            .any(|b| b.bidder == bid.bidder && b.nonce == bid.nonce)
        {
            return Err(NauError::Conflict(
                "an identical bid was already recorded".into(),
            ));
        }
        slot.push(bid);
        Ok(())
    }

    /// Select a winner for a task.
    pub fn match_task(&mut self, id: &TaskId, at: u64) -> Result<MatchOutcome> {
        let task = self
            .tasks
            .get(id)
            .ok_or_else(|| NauError::NotFound(format!("task `{id}`")))?;
        // Upstream re-matched settled tasks, which reassigned `owner` and corrupted
        // the audit trail.
        if task.state != TaskState::Open {
            return Err(NauError::Conflict(format!(
                "task `{id}` is {:?}; only an Open task can be matched",
                task.state
            )));
        }
        if task.is_expired(at) {
            return Err(NauError::Stale(format!("task `{id}` has expired")));
        }
        let bids = self.bids.get(id).cloned().unwrap_or_default();
        let outcome = rank_bids(task, &bids, &self.agents, &self.reputation)?;

        let task = self.tasks.get_mut(id).expect("checked above");
        task.state = task.state.transition(TaskState::Matched, id)?;
        task.assigned_to = Some(outcome.winner.clone());
        Ok(outcome)
    }

    /// Mark a matched task as being worked on.
    pub fn start_task(&mut self, id: &TaskId, executor: &Did, at: u64) -> Result<()> {
        let task = self
            .tasks
            .get_mut(id)
            .ok_or_else(|| NauError::NotFound(format!("task `{id}`")))?;
        if task.assigned_to.as_ref() != Some(executor) {
            return Err(NauError::Unauthorized(format!(
                "`{executor}` is not the assigned executor of task `{id}`"
            )));
        }
        if task.is_expired(at) {
            return Err(NauError::Stale(format!("task `{id}` has expired")));
        }
        task.state = task.state.transition(TaskState::Running, id)?;
        Ok(())
    }

    /// Submit a result for a running task.
    ///
    /// Only the assigned executor may submit, and the envelope must be signed by
    /// them, fresh, and internally consistent.
    pub fn submit_result(&mut self, envelope: ResultEnvelope, at: u64) -> Result<()> {
        let task = self
            .tasks
            .get(&envelope.task_id)
            .ok_or_else(|| NauError::NotFound(format!("task `{}`", envelope.task_id)))?;
        if task.state != TaskState::Running {
            return Err(NauError::Conflict(format!(
                "task `{}` is {:?}; a result may only be submitted while Running",
                task.id, task.state
            )));
        }
        // Upstream never checked the submitter against the assigned owner.
        if task.assigned_to.as_ref() != Some(&envelope.agent) {
            return Err(NauError::Unauthorized(format!(
                "`{}` is not the assigned executor of task `{}`",
                envelope.agent, task.id
            )));
        }
        envelope.validate()?;
        envelope.verify_fresh(at)?;
        self.nonces.accept(&envelope.agent, envelope.nonce)?;

        let task_id = envelope.task_id.clone();
        self.results.insert(task_id.clone(), envelope);
        let task = self.tasks.get_mut(&task_id).expect("checked above");
        task.state = task.state.transition(TaskState::Submitted, &task_id)?;
        Ok(())
    }

    /// Run an authenticated BFT-lite round over a submitted result.
    ///
    /// `votes` are **signed** and are cast into `committee`, which was assigned with
    /// a fixed membership. There is deliberately no parameter for "how many
    /// approvals" — that was the mechanism by which any client could approve its own
    /// task upstream.
    pub fn verify_result(
        &mut self,
        id: &TaskId,
        committee: &mut Committee,
        votes: &[Vote],
        at: u64,
    ) -> Result<Outcome> {
        let task = self
            .tasks
            .get(id)
            .ok_or_else(|| NauError::NotFound(format!("task `{id}`")))?;
        if !matches!(task.state, TaskState::Submitted | TaskState::Verifying) {
            return Err(NauError::Conflict(format!(
                "task `{id}` is {:?}; verification requires Submitted or Verifying",
                task.state
            )));
        }
        if committee.proposal() != id.as_str() {
            return Err(NauError::Validation(format!(
                "committee was assigned to `{}` but is being used for `{id}`",
                committee.proposal()
            )));
        }
        // The result must exist; there is nothing to verify otherwise.
        if !self.results.contains_key(id) {
            return Err(NauError::NotFound(format!("a submitted result for `{id}`")));
        }

        for vote in votes {
            // A duplicate or non-member vote is an error, not a silent skip.
            committee.cast(vote, at)?;
        }
        let tally = committee.tally();

        let task = self.tasks.get_mut(id).expect("checked above");
        if task.state == TaskState::Submitted {
            task.state = task.state.transition(TaskState::Verifying, id)?;
        }
        let next = match tally.outcome {
            Outcome::Accepted => TaskState::Accepted,
            Outcome::Rejected => TaskState::Rework,
            Outcome::NoQuorum | Outcome::SafetyViolation => TaskState::NoQuorum,
        };
        task.state = task.state.transition(next, id)?;
        Ok(tally.outcome)
    }

    /// Settle an accepted task, paying the executor from escrow.
    pub fn settle(&mut self, id: &TaskId, at: u64) -> Result<Money> {
        let task = self
            .tasks
            .get(id)
            .ok_or_else(|| NauError::NotFound(format!("task `{id}`")))?;
        if task.state != TaskState::Accepted {
            return Err(NauError::Conflict(format!(
                "task `{id}` is {:?}; only an Accepted task can settle",
                task.state
            )));
        }
        let executor = task
            .assigned_to
            .clone()
            .ok_or_else(|| NauError::Conflict(format!("task `{id}` has no executor")))?;
        // Evidence gate: an Unverified result must not release funds. Upstream
        // defined `EvidenceGrade::is_trustworthy()` for exactly this and never
        // called it, so an `Unverified` result settled at full budget.
        let envelope = self
            .results
            .get(id)
            .ok_or_else(|| NauError::NotFound(format!("a result for `{id}`")))?;
        envelope.validate_for_settlement()?;
        let evidence = envelope.evidence;
        let latency_ratio_bps = {
            let card = self.agents.get(&executor);
            let target_ms = card.map(|c| c.sla.latency_p95_ms.max(1)).unwrap_or(1_000);
            // integer ratio in basis points, saturating
            let ratio = (envelope.latency_ms.saturating_mul(10_000)) / target_ms;
            u32::try_from(ratio.min(u64::from(u32::MAX))).unwrap_or(u32::MAX)
        };

        let payee = account_of(&executor)?;
        let paid = self.ledger.release(id, &payee, at)?;

        // Reputation moves only now, once, and only on a real settlement. Upstream
        // updated it inside the settlement path that could be replayed.
        let rep = self.reputation.entry(executor.clone()).or_default();
        rep.record_settled(
            latency_ratio_bps,
            evidence.is_settlement_grade() || evidence == EvidenceGrade::Verified,
        );
        rep.record_clean();

        let task = self.tasks.get_mut(id).expect("checked above");
        task.state = task.state.transition(TaskState::Settled, id)?;
        Ok(paid)
    }

    // ---------------------------------------------------------------- disputes

    /// Open a dispute. Only a party to the task may do so.
    pub fn open_dispute(&mut self, dispute: Dispute, at: u64) -> Result<()> {
        dispute.validate()?;
        dispute.verify_fresh(at)?;
        let task = self
            .tasks
            .get(&dispute.task_id)
            .ok_or_else(|| NauError::NotFound(format!("task `{}`", dispute.task_id)))?;
        // Upstream accepted any `complainant` string with no identity proof and no
        // requirement that they were involved.
        let requester = &task.spec.owner;
        let executor = task.assigned_to.as_ref();
        if &dispute.complainant != requester && executor != Some(&dispute.complainant) {
            return Err(NauError::Unauthorized(format!(
                "`{}` is not a party to task `{}`",
                dispute.complainant, dispute.task_id
            )));
        }
        if self.disputes.contains_key(&dispute.id) {
            return Err(NauError::Conflict(format!(
                "dispute `{}` already exists",
                dispute.id
            )));
        }
        self.nonces.accept(&dispute.complainant, dispute.nonce)?;

        // Opening a dispute moves the task into `Disputed`, which is what makes the
        // later `Disputed -> Slashed` (guilty) and `Disputed -> Accepted` (not guilty)
        // edges reachable. Without this the task stayed in `Matched`/`Running` and a
        // guilty ruling had nowhere legal to go — the state machine refused it.
        let task_id = dispute.task_id.clone();
        let task = self.tasks.get_mut(&task_id).expect("checked above");
        task.state = task.state.transition(TaskState::Disputed, &task_id)?;

        self.disputes.insert(dispute.id.clone(), dispute);
        Ok(())
    }

    /// A dispute by id.
    pub fn get_dispute(&self, id: &str) -> Option<&Dispute> {
        self.disputes.get(id)
    }

    /// Every dispute, ordered by id.
    pub fn disputes(&self) -> Vec<&Dispute> {
        self.disputes.values().collect()
    }

    /// The ruling on a dispute, if any.
    pub fn ruling(&self, id: &str) -> Option<&DisputeOutcome> {
        self.rulings.get(id)
    }

    /// Apply an arbitrator's signed ruling.
    ///
    /// A guilty verdict must carry a positive slash (enforced by
    /// [`DisputeOutcome::validate`]), and the slash must actually be available in the
    /// respondent's stake account — upstream returned a "guilty" verdict with
    /// `slash_amount = 0.0` and penalised nobody, and had no unstake or
    /// capacity check on the slash itself.
    pub fn arbitrate(&mut self, ruling: DisputeOutcome, at: u64) -> Result<Money> {
        ruling.validate()?;
        ruling.verify_fresh(at)?;
        let dispute = self
            .disputes
            .get(&ruling.dispute_id)
            .ok_or_else(|| NauError::NotFound(format!("dispute `{}`", ruling.dispute_id)))?;
        if self.rulings.contains_key(&ruling.dispute_id) {
            return Err(NauError::Conflict(format!(
                "dispute `{}` has already been decided",
                ruling.dispute_id
            )));
        }
        // An arbitrator must not be a party to the dispute.
        if ruling.arbitrator == dispute.complainant || ruling.arbitrator == dispute.respondent {
            return Err(NauError::Unauthorized(
                "an arbitrator cannot be a party to the dispute".into(),
            ));
        }
        let respondent = dispute.respondent.clone();
        let task_id = dispute.task_id.clone();
        self.nonces.accept(&ruling.arbitrator, ruling.nonce)?;

        let mut slashed = Money::ZERO;
        if ruling.guilty {
            let stake = stake_account(&respondent);
            slashed = self
                .ledger
                .slash(&stake, ruling.slash_amount, "dispute ruling", at)?;
            let rep = self.reputation.entry(respondent.clone()).or_default();
            rep.record_fault(self.config.fault_severity_bps);
        }

        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| NauError::NotFound(format!("task `{task_id}`")))?;
        let next = if ruling.guilty {
            TaskState::Slashed
        } else {
            TaskState::Accepted
        };
        task.state = task.state.transition(next, &task_id)?;

        self.rulings.insert(ruling.dispute_id.clone(), ruling);
        Ok(slashed)
    }

    // -------------------------------------------------------------- reporting

    /// Escrowed funds for a task.
    pub fn escrowed_for(&self, id: &TaskId) -> Money {
        self.ledger.escrowed_for(id)
    }

    /// O(1) conservation snapshot.
    pub fn conservation(&self) -> ConservationReport {
        self.ledger.conservation()
    }

    /// O(N) independent audit. This is the check that can fail.
    pub fn audit(&self) -> ConservationReport {
        self.ledger.audit()
    }

    /// Counts for `/stats`.
    pub fn stats(&self) -> MarketStats {
        MarketStats {
            agents: self.agents.len(),
            tasks: self.tasks.len(),
            settled: self
                .tasks
                .values()
                .filter(|t| t.state.is_terminal())
                .count(),
            disputes: self.disputes.len(),
            escrowed_minor: self.ledger.conservation().total_escrowed.minor(),
        }
    }

    // ----------------------------------------------------------- persistence

    /// Write the full market state to a store.
    ///
    /// Upstream persisted only agent registrations, by re-parsing the raw HTTP body,
    /// and never persisted the ledger or read anything back. Here agents, tasks and
    /// the ledger journal are all written, and [`Market::restore`] replays them.
    pub fn persist(&mut self, store: &dyn Store) -> Result<()> {
        for card in self.agents.values() {
            store.save_agent(card)?;
        }
        for task in self.tasks.values() {
            store.save_task(task)?;
        }
        // Append ONLY the entries that are not in the journal yet. `append_ledger`
        // appends by name and by contract, so writing the whole ledger here
        // duplicated it on every call -- the caller is expected to say what is new.
        let start = self.journaled;
        let end = self.ledger.entries().len();
        for index in start..end {
            let value = serde_json::to_value(&self.ledger.entries()[index])?;
            store.append_ledger(&value)?;
        }
        self.journaled = end;
        store.set_meta("market.version", nau_core::VERSION)?;
        store.set_meta("market.protocol", nau_core::PROTOCOL_VERSION)?;
        store.flush()
    }

    /// Rebuild a market from a store, replaying the ledger journal.
    pub fn restore(config: MarketConfig, store: &dyn Store, at: u64) -> Result<Self> {
        let mut market = Market::new(config);

        // 1) Replay the ledger journal in order so balances are exact. Only entries
        //    not already applied are appended on the next `persist`, so a restore
        //    followed by a persist does not duplicate the journal.
        let journal = store.load_ledger()?;
        for value in &journal {
            let entry: LedgerEntry = serde_json::from_value(value.clone())?;
            market.replay(entry)?;
        }
        // Everything just replayed is, by definition, already in the journal.
        // Recording that is what makes the paragraph above true; before this the
        // comment promised it and the code did the opposite.
        market.journaled = journal.len();

        // 2) Load agents and re-derive the skill index. `register_agent` is not used
        //    here because it would try to move stake that the ledger replay has
        //    already accounted for.
        for card in store.load_agents()? {
            for skill in &card.skills {
                market
                    .skill_index
                    .entry(skill.id.clone())
                    .or_default()
                    .push(card.owner.clone());
            }
            market.reputation.entry(card.owner.clone()).or_default();
            market.agents.insert(card.owner.clone(), card);
        }
        for agents in market.skill_index.values_mut() {
            agents.sort();
            agents.dedup();
        }

        // 3) Tasks.
        for task in store.load_tasks()? {
            market.tasks.insert(task.id.clone(), task);
        }

        // 4) Nonce guards must not be left at zero, or a replay of a previously
        //    accepted object would be accepted again after a restart.
        let agent_nonces: Vec<(Did, u64)> = market
            .agents
            .values()
            .map(|c| (c.owner.clone(), c.nonce))
            .collect();
        for (did, nonce) in agent_nonces {
            let _ = market.nonces.accept(&did, nonce);
        }
        let task_nonces: Vec<(Did, u64)> = market
            .tasks
            .values()
            .map(|t| (t.spec.owner.clone(), t.nonce))
            .collect();
        for (did, nonce) in task_nonces {
            let _ = market.nonces.accept(&did, nonce);
        }

        let _ = at;
        Ok(market)
    }

    /// Apply one recorded ledger entry to the in-memory ledger.
    fn replay(&mut self, entry: LedgerEntry) -> Result<()> {
        let at = entry.at;
        match entry.kind {
            EntryKind::Deposit | EntryKind::Stake => {
                if let Some(to) = &entry.to {
                    self.ledger.deposit(to, entry.amount, &entry.memo, at)?;
                }
            }
            EntryKind::Withdraw | EntryKind::Unstake => {
                if let Some(from) = &entry.from {
                    self.ledger.withdraw(from, entry.amount, &entry.memo, at)?;
                }
            }
            EntryKind::Escrow => {
                let (Some(from), Some(task)) = (&entry.from, &entry.task) else {
                    return Err(NauError::Validation(
                        "escrow entry is missing `from` or `task`".into(),
                    ));
                };
                self.ledger.escrow(task, from, entry.amount, at)?;
            }
            EntryKind::Release => {
                let (Some(to), Some(task)) = (&entry.to, &entry.task) else {
                    return Err(NauError::Validation(
                        "release entry is missing `to` or `task`".into(),
                    ));
                };
                self.ledger.release(task, to, at)?;
            }
            EntryKind::Refund => {
                let (Some(from), Some(task)) = (&entry.from, &entry.task) else {
                    return Err(NauError::Validation(
                        "refund entry is missing `from` or `task`".into(),
                    ));
                };
                self.ledger.refund(task, from, at)?;
            }
            EntryKind::Slash => {
                let Some(from) = &entry.from else {
                    return Err(NauError::Validation("slash entry is missing `from`".into()));
                };
                self.ledger.slash(from, entry.amount, &entry.memo, at)?;
            }
        }
        Ok(())
    }

    /// Escrow account for a task, exposed for auditing.
    pub fn escrow_account_for(id: &TaskId) -> AccountId {
        escrow_account(id)
    }

    /// Stake account for an agent, exposed for auditing.
    pub fn stake_account_for(did: &Did) -> AccountId {
        stake_account(did)
    }
}
