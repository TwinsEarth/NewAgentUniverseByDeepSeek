//! The market service: one owner of all market state.
//!
//! Every mutating method follows the same discipline, which is what upstream lacks:
//!
//! 1. **load** the entity and check it exists (`NotFound` otherwise);
//! 2. **authorize** by verifying the caller's signature over the signed object and
//!    checking the signer's DID fingerprints the supplied key — and, for the
//!    privileged operations, by checking the explicit [`Actor`] the caller passed
//!    against the object (finding F);
//! 3. **anti-replay** the object's `nonce` through a [`NonceGuard`];
//! 4. **validate** the entity's own invariants;
//! 5. **check the state transition** through [`nau_core::TaskState::transition`],
//!    *before* any side effect that cannot be undone (finding G);
//! 6. **mutate**, writing to the ledger in the same call so money and state cannot
//!    drift apart.
//!
//! State is held in `BTreeMap`s, not `HashMap`s. Upstream's discovery and search
//! return results in `HashMap` iteration order, so the same query returns different
//! orderings on different runs — untestable and unpaginated. `BTreeMap` gives a
//! stable, sorted, reproducible order for free.
//!
//! ## Restart integrity (V1.2.3, findings B–G)
//!
//! Upstream v2.8.2's persistence layer made a restart *weaken the system*: tasks
//! were rebuilt with `verification_policy: None` and `winner_price: None`, result
//! envelopes / reputations / stakes were never saved, a physical row count was
//! used as a watermark over a silently filtered list, and both write and restore
//! failures were swallowed. This module fixes each of those, and the tests in
//! `tests/restart.rs` lock them:
//!
//! * every gate is persisted and restored, so a restart cannot skip the evidence
//!   gate, cannot erase a reputation, and cannot lose a stake record while its
//!   funds stay on the books;
//! * the journal watermark is a persisted **logical** record count, and every
//!   restored record is checked for position, self-consistency and chain linkage —
//!   a defect is reported in a [`RestoreReport`], never skipped;
//! * an append or a metadata write that fails returns a typed error and advances
//!   the watermark only over records that are actually durable, so a retry cannot
//!   write anything twice;
//! * a restore that does not verify exactly marks the market **degraded**: it
//!   reports the defect through [`MarketStats::degraded`] and refuses every
//!   mutation, so a partial state can never be written back over the good one.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use nau_consensus::{Committee, Outcome, Vote};
use nau_core::domain::{Money, Verifiable};
use nau_core::{
    AgentCard, Bid, Did, Dispute, DisputeOutcome, EvidenceGrade, NauError, NonceGuard, Result,
    ResultEnvelope, Task, TaskId, TaskState,
};
use nau_ledger::{
    escrow_account, stake_account, AccountId, ConservationReport, Ledger, LedgerEntry,
    GENESIS_DIGEST,
};
use nau_store::Store;
use serde::{Deserialize, Serialize};

use crate::actor::{Actor, Authority};
use crate::matching::{rank_bids, MatchOutcome};
use crate::persistence::{
    MarketSnapshot, RestoreDefect, RestoreReport, MARKET_PROTOCOL_KEY, MARKET_STATE_KEY,
    MARKET_STATE_SCHEMA, MARKET_VERSION_KEY,
};
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
    /// Fraction of a guilty respondent's **bonded** stake that
    /// [`Market::arbitrate`] slashes, in basis points.
    ///
    /// upstream v2.8.2 fix (finding F): the penalty is computed here, from this
    /// rule and the balance actually bonded, and never taken from the caller's
    /// `DisputeOutcome::slash_amount`. The caller's field is still checked for
    /// well-formedness (a guilty verdict must declare a positive slash) but it does
    /// not decide the amount.
    #[serde(default = "default_fault_slash_bps")]
    pub fault_slash_bps: u16,
}

/// The value of [`MarketConfig::fault_slash_bps`] used when a configuration is
/// decoded from JSON that predates the field.
fn default_fault_slash_bps() -> u16 {
    1_000
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
            // 10% of the bonded stake: enough that a guilty verdict always
            // punishes a real bond, and never more than the bond itself.
            fault_slash_bps: 1_000,
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
    /// True when the market was restored from a store that did not verify exactly
    /// and is therefore serving in degraded, **read-only** mode (finding E).
    ///
    /// This is the field `/health` and `/stats` report, so a degraded node is
    /// labelled rather than silently serving a lossy state.
    pub degraded: bool,
    /// Ledger journal records the store should have held.
    pub journal_records_expected: usize,
    /// Ledger journal records actually restored.
    pub journal_records_restored: usize,
}

/// The market service.
pub struct Market {
    config: MarketConfig,
    ledger: Arc<Mutex<Ledger>>,
    agents: BTreeMap<Did, AgentCard>,
    /// Lowercased skill id -> agents offering it.
    skill_index: BTreeMap<String, Vec<Did>>,
    tasks: BTreeMap<TaskId, Task>,
    bids: BTreeMap<TaskId, Vec<Bid>>,
    results: BTreeMap<TaskId, ResultEnvelope>,
    /// Evidence grades the market itself upgraded after a successful committee
    /// verification (finding G). Kept beside the signed envelope because the
    /// envelope's signature covers its own `evidence` field, and the market holds
    /// no agent key with which to re-sign it.
    verified_evidence: BTreeMap<TaskId, EvidenceGrade>,
    /// The price the winning bid offered, recorded at match time (finding B).
    ///
    /// `settle` refuses to pay a task whose price was never recorded rather than
    /// falling back to the escrowed budget, which is exactly upstream's
    /// `winner_price.unwrap_or(budget)`.
    winner_price: BTreeMap<TaskId, Money>,
    disputes: BTreeMap<String, Dispute>,
    rulings: BTreeMap<String, DisputeOutcome>,
    reputation: BTreeMap<Did, Reputation>,
    nonces: NonceGuard,
    /// Highest nonce accepted per signer, mirrored so that it survives a restart
    /// (finding C). A nonce accepted for an object that was later refused must
    /// still be remembered, which is why this is not re-derived from the stored
    /// objects alone.
    nonce_high: BTreeMap<Did, u64>,
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
    /// The outcome of the last restore, or `None` for a market built in memory.
    restore_state: Option<RestoreReport>,
}

fn account_of(did: &Did) -> Result<AccountId> {
    AccountId::parse(did.as_str())
}

/// The state `task` would move to, or the reason it may not.
///
/// Pure: it validates without touching the task, so a caller can validate a
/// transition **before** performing a side effect that cannot be undone, such as
/// moving money (finding G).
///
/// upstream v2.8.2 fix (finding F): a repeated state is not an edge. Without this
/// a terminal task could be re-entered through `Slashed -> Slashed` and punished
/// twice, because `TaskState::transition` treats "already there" as a legal no-op.
fn next_state(task: &Task, next: TaskState) -> Result<TaskState> {
    if task.state == next {
        return Err(NauError::Conflict(format!(
            "task `{}` is already {next:?}; a repeated state is not a legal edge",
            task.id
        )));
    }
    task.state.transition(next, &task.id)
}

/// The **only** place a task's state is assigned in this crate (finding F).
///
/// Every mutation goes through [`next_state`], so the transition table is the sole
/// authority on which states are reachable. `tests/authority.rs` proves the
/// uniqueness of this assignment by reading this file back.
fn apply_transition(task: &mut Task, next: TaskState) -> Result<TaskState> {
    let state = next_state(task, next)?;
    task.state = state;
    Ok(state)
}

/// Note a signer's nonce in a high-water map, keeping the maximum.
fn note_nonce(highest: &mut BTreeMap<Did, u64>, did: &Did, nonce: u64) {
    let entry = highest.entry(did.clone()).or_insert(0);
    if nonce > *entry {
        *entry = nonce;
    }
}

/// Record `nonce` in the replay guard **and** in the durable high-water mark.
///
/// Takes the two fields rather than `&mut Market` on purpose: several callers hold
/// an immutable borrow of `self.tasks` at the same moment, and field-level borrows
/// let the guard and the tasks map be borrowed at once.
fn note_accepted(
    nonces: &mut NonceGuard,
    high: &mut BTreeMap<Did, u64>,
    did: &Did,
    nonce: u64,
) -> Result<()> {
    nonces.accept(did, nonce)?;
    note_nonce(high, did, nonce);
    Ok(())
}

impl Market {
    /// An empty market.
    pub fn new(config: MarketConfig) -> Self {
        Self::sharing(config, Arc::new(Mutex::new(Ledger::new())))
    }

    /// Build a market over books the caller already owns.
    ///
    /// # Why this exists
    ///
    /// `sys.ledger` is a plugin that answers `balance` and `escrow`, and until it was given the
    /// node's own books it answered about an empty ledger it had been constructed with — every
    /// balance `0`, every escrow `open: false`, whatever the node actually held. A host that
    /// wants the plugin to tell the truth has to **hand over the same handle**, and a handle is
    /// what a `Mutex` can be shared through and a `&Ledger` cannot.
    #[must_use]
    pub fn sharing(config: MarketConfig, ledger: Arc<Mutex<Ledger>>) -> Self {
        Self {
            config,
            ledger,
            agents: BTreeMap::new(),
            skill_index: BTreeMap::new(),
            tasks: BTreeMap::new(),
            bids: BTreeMap::new(),
            results: BTreeMap::new(),
            verified_evidence: BTreeMap::new(),
            winner_price: BTreeMap::new(),
            disputes: BTreeMap::new(),
            rulings: BTreeMap::new(),
            reputation: BTreeMap::new(),
            nonces: NonceGuard::new(),
            nonce_high: BTreeMap::new(),
            journaled: 0,
            restore_state: None,
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &MarketConfig {
        &self.config
    }

    /// The ledger handle, for a host that must share these books with a plugin.
    ///
    /// # Why a handle and not a reference
    ///
    /// The reason this accessor exists is the opposite of lending: `sys.ledger` has to read the
    /// **same** books the market mutates, which means shipping the `Arc` to the wiring site
    /// rather than handing out a reference that dies at the end of the statement.
    #[must_use]
    pub fn ledger_handle(&self) -> Arc<Mutex<Ledger>> {
        Arc::clone(&self.ledger)
    }

    /// The ledger, locked.
    ///
    /// Poisoning is recovered rather than propagated: a panic that left a movement half-applied
    /// is not made better by refusing every later read, and this crate's whole point is that the
    /// journal is what says what happened.
    fn books(&self) -> MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// True when this market is serving in degraded, read-only mode because its
    /// restore did not verify exactly (findings D, E).
    pub fn is_degraded(&self) -> bool {
        self.restore_state
            .as_ref()
            .is_some_and(RestoreReport::is_degraded)
    }

    /// What the last restore could and could not rebuild, when the market came
    /// from a store at all.
    pub fn restore_report(&self) -> Option<&RestoreReport> {
        self.restore_state.as_ref()
    }

    /// Ledger journal records this market has made durable.
    ///
    /// This is the logical watermark a restart compares against, and it advances by
    /// one only after the matching append has succeeded (finding E).
    pub fn persisted_ledger_records(&self) -> usize {
        self.journaled
    }

    /// Refuse a mutation while the market is degraded.
    ///
    /// A degraded market has already lost part of its state; letting it write would
    /// overwrite the good records still on disk with a partial view of them. Reads
    /// stay available and `/stats` reports the degradation.
    fn require_live(&self) -> Result<()> {
        match &self.restore_state {
            Some(report) if report.is_degraded() => Err(NauError::Conflict(format!(
                "market is in degraded read-only mode after an incomplete restore: {}",
                report.summary()
            ))),
            _ => Ok(()),
        }
    }

    /// Record `nonce` in the replay guard and in the durable high-water mark.
    fn accept_nonce(&mut self, did: &Did, nonce: u64) -> Result<()> {
        note_accepted(&mut self.nonces, &mut self.nonce_high, did, nonce)
    }

    // ---------------------------------------------------------------- accounts

    /// Credit an account.
    pub fn deposit(&mut self, account: &AccountId, amount: Money, at: u64) -> Result<()> {
        self.require_live()?;
        if !amount.is_positive() {
            return Err(NauError::InvalidAmount(
                "deposit amount must be greater than zero".into(),
            ));
        }
        self.books()
            .deposit(account, amount, "market deposit", at)
            .map(|_| ())
    }

    /// Current balance of an account.
    pub fn balance(&self, account: &AccountId) -> Money {
        self.books().balance(account)
    }

    // ---------------------------------------------------------------- registry

    /// Register (or update) an agent card.
    ///
    /// Admission requires a valid, fresh signature; a strictly increasing nonce; a
    /// stake at or above the configured minimum; and the stake itself to be
    /// available, which is then moved into the agent's dedicated stake account.
    pub fn register_agent(&mut self, card: AgentCard, at: u64) -> Result<()> {
        self.require_live()?;
        card.validate_verified_fresh(at)?;
        if card.stake < self.config.min_stake {
            return Err(NauError::Validation(format!(
                "stake {} is below the minimum {}",
                card.stake.to_decimal_string(),
                self.config.min_stake.to_decimal_string()
            )));
        }
        // Replay protection before any mutation.
        self.accept_nonce(&card.owner, card.nonce)?;

        // Update path: top up the stake by the difference only, so re-registering
        // cannot inflate the locked amount (upstream re-deposited the whole stake on
        // every registration while the recorded stake stayed constant).
        let already_staked = self.books().balance(&stake_account(&card.owner));
        if card.stake > already_staked {
            let top_up = card.stake.checked_sub(already_staked)?;
            let owner_account = account_of(&card.owner)?;
            if self.books().balance(&owner_account) < top_up {
                return Err(NauError::InsufficientBalance {
                    account: owner_account.to_string(),
                    available: self.books().balance(&owner_account).minor(),
                    required: top_up.minor(),
                });
            }
            self.books()
                .withdraw(&owner_account, top_up, "stake lock", at)?;
            self.books()
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
        self.require_live()?;
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
        self.accept_nonce(&task.spec.owner, task.nonce)?;

        let requester = account_of(&task.spec.owner)?;
        // Rejects an unfunded requester. Never creates funds.
        self.books().escrow(&task.id, &requester, task.budget, at)?;

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

    /// The winning price recorded when `id` was matched, if it was (finding B).
    pub fn winner_price(&self, id: &TaskId) -> Option<Money> {
        self.winner_price.get(id).copied()
    }

    /// The evidence grade the market will use for `id`'s settlement gate.
    ///
    /// This is the envelope's own grade unless a committee verified the result, in
    /// which case the market's recorded upgrade wins (finding G). An `Unverified`
    /// envelope is never upgraded: a verification round is not evidence that was
    /// never submitted.
    pub fn effective_evidence(&self, id: &TaskId) -> Option<EvidenceGrade> {
        self.verified_evidence
            .get(id)
            .copied()
            .or_else(|| self.results.get(id).map(|envelope| envelope.evidence))
    }

    /// Mutable access to a task, or a typed `NotFound`.
    fn task_mut(&mut self, id: &TaskId) -> Result<&mut Task> {
        self.tasks
            .get_mut(id)
            .ok_or_else(|| NauError::NotFound(format!("task `{id}`")))
    }

    /// Submit a bid.
    pub fn submit_bid(&mut self, bid: Bid, at: u64) -> Result<()> {
        self.require_live()?;
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
        // Field-level borrows: `task` above is still borrowed from `self.tasks`.
        note_accepted(
            &mut self.nonces,
            &mut self.nonce_high,
            &bid.bidder,
            bid.nonce,
        )?;

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

    /// Select a winner for a task, recording the price it will be paid.
    pub fn match_task(&mut self, id: &TaskId, at: u64) -> Result<MatchOutcome> {
        self.require_live()?;
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

        let task = self.task_mut(id)?;
        apply_transition(task, TaskState::Matched)?;
        task.assigned_to = Some(outcome.winner.clone());
        // Finding B: the price the winner offered is recorded, persisted and
        // restored. Upstream restored `winner_price: None` and then paid
        // `winner_price.unwrap_or(budget)`.
        self.winner_price.insert(id.clone(), outcome.price);
        Ok(outcome)
    }

    /// Mark a matched task as being worked on.
    pub fn start_task(&mut self, id: &TaskId, executor: &Did, at: u64) -> Result<()> {
        self.require_live()?;
        let task = self
            .tasks
            .get(id)
            .ok_or_else(|| NauError::NotFound(format!("task `{id}`")))?;
        if task.assigned_to.as_ref() != Some(executor) {
            return Err(NauError::Unauthorized(format!(
                "`{executor}` is not the assigned executor of task `{id}`"
            )));
        }
        if task.is_expired(at) {
            return Err(NauError::Stale(format!("task `{id}` has expired")));
        }
        let task = self.task_mut(id)?;
        apply_transition(task, TaskState::Running)?;
        Ok(())
    }

    /// Submit a result for a running task.
    ///
    /// Only the assigned executor may submit, and the envelope must be signed by
    /// them, fresh, and internally consistent.
    pub fn submit_result(&mut self, envelope: ResultEnvelope, at: u64) -> Result<()> {
        self.require_live()?;
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
        // The envelope is a one-way record: once stored it stays stored. Validate
        // the state transition **before** recording it (finding G), so a refused
        // submission cannot leave an envelope attached to a task that never
        // accepted one.
        next_state(task, TaskState::Submitted)?;
        let task_id = envelope.task_id.clone();
        self.accept_nonce(&envelope.agent, envelope.nonce)?;
        self.results.insert(task_id.clone(), envelope);
        let task = self.task_mut(&task_id)?;
        apply_transition(task, TaskState::Submitted)?;
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
        self.require_live()?;
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
        let outcome = tally.outcome;
        let next = match outcome {
            Outcome::Accepted => TaskState::Accepted,
            Outcome::Rejected => TaskState::Rework,
            Outcome::NoQuorum | Outcome::SafetyViolation => TaskState::NoQuorum,
        };

        {
            let task = self.task_mut(id)?;
            if task.state == TaskState::Submitted {
                apply_transition(task, TaskState::Verifying)?;
            }
            apply_transition(task, next)?;
        }

        // upstream v2.8.2 fix (finding G): the evidence upgrade happens only
        // **after** the transition above has succeeded, so a verification call that
        // returns an error leaves the grade untouched. Only a result that already
        // carries evidence can be upgraded: a committee round over an `Unverified`
        // envelope must not launder "no evidence" into trust.
        if matches!(outcome, Outcome::Accepted)
            && self.results.get(id).map(|envelope| envelope.evidence)
                == Some(EvidenceGrade::CpuProto)
        {
            self.verified_evidence
                .insert(id.clone(), EvidenceGrade::Verified);
        }
        Ok(outcome)
    }

    /// Settle an accepted task, paying the executor from escrow.
    ///
    /// The gate is the recorded result: it must be signed and of settlement grade,
    /// and the winning price must have been recorded when the task was matched.
    /// Nothing here falls back to the escrowed budget when the price is missing
    /// (finding B).
    pub fn settle(&mut self, id: &TaskId, at: u64) -> Result<Money> {
        self.require_live()?;
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
        // Finding B: the price is what the winner offered, recorded at match time
        // and restored from the snapshot. Upstream rebuilt this as `None` and then
        // paid `winner_price.unwrap_or(budget)`.
        let price = self.winner_price.get(id).copied().ok_or_else(|| {
            NauError::Conflict(format!(
                "task `{id}` has no recorded winner price; refusing to pay the escrowed budget \
                 in its place"
            ))
        })?;
        // Evidence gate: an Unverified result must not release funds. Upstream
        // defined `EvidenceGrade::is_settlement_grade()` for exactly this and never
        // called it, so an `Unverified` result settled at full budget.
        let envelope = self
            .results
            .get(id)
            .ok_or_else(|| NauError::NotFound(format!("a result for `{id}`")))?;
        envelope.validate_for_settlement()?;
        let evidence = self
            .effective_evidence(id)
            .ok_or_else(|| NauError::NotFound(format!("a result for `{id}`")))?;
        if !evidence.is_settlement_grade() {
            return Err(NauError::Validation(format!(
                "evidence grade `{}` is not sufficient to release payment",
                evidence.label()
            )));
        }
        let latency_ratio_bps = {
            let card = self.agents.get(&executor);
            let target_ms = card.map(|c| c.sla.latency_p95_ms.max(1)).unwrap_or(1_000);
            // integer ratio in basis points, saturating
            let ratio = (envelope.latency_ms.saturating_mul(10_000)) / target_ms;
            u32::try_from(ratio.min(u64::from(u32::MAX))).unwrap_or(u32::MAX)
        };
        // The escrow must at least cover the price the winner offered; if it does
        // not (for example because the escrow account was seized), settlement
        // refuses rather than underpaying.
        let escrowed = self.books().escrowed_for(id);
        if escrowed < price {
            return Err(NauError::Conflict(format!(
                "escrow for task `{id}` holds {} but the recorded winner price is {}; refusing to \
                 underpay the executor",
                escrowed.to_decimal_string(),
                price.to_decimal_string()
            )));
        }
        // Finding G: validate the transition before the money moves, so a rejected
        // settlement cannot leave funds released against an unchanged state.
        {
            let task = self
                .tasks
                .get(id)
                .ok_or_else(|| NauError::NotFound(format!("task `{id}`")))?;
            next_state(task, TaskState::Settled)?;
        }

        let payee = account_of(&executor)?;
        let paid = self.books().release(id, &payee, at)?;

        // Reputation moves only now, once, and only on a real settlement. Upstream
        // updated it inside the settlement path that could be replayed.
        let rep = self.reputation.entry(executor.clone()).or_default();
        rep.record_settled(
            latency_ratio_bps,
            evidence.is_settlement_grade() || evidence == EvidenceGrade::Verified,
        );
        rep.record_clean();

        let task = self.task_mut(id)?;
        apply_transition(task, TaskState::Settled)?;
        Ok(paid)
    }

    // ---------------------------------------------------------------- disputes

    /// Open a dispute as an explicit party to the task.
    ///
    /// upstream v2.8.2 fix (finding F): the actor is a parameter, not an implicit
    /// caller. The signature on `dispute` proves who signed; `actor` must be that
    /// same DID *and* must claim [`Authority::Party`], and the market checks the
    /// party against the task.
    pub fn open_dispute(&mut self, actor: Actor, dispute: Dispute, at: u64) -> Result<()> {
        self.require_live()?;
        dispute.validate()?;
        if actor.authority() != Authority::Party {
            return Err(NauError::Unauthorized(format!(
                "{actor} may not open a dispute; that requires the `party` authority"
            )));
        }
        if actor.did() != &dispute.complainant {
            return Err(NauError::Unauthorized(format!(
                "actor `{}` is not the complainant `{}` that signed the dispute",
                actor.did(),
                dispute.complainant
            )));
        }
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
        // Opening a dispute moves the task into `Disputed`, which is what makes the
        // later `Disputed -> Slashed` (guilty) and `Disputed -> Accepted` (not guilty)
        // edges reachable. Without this the task stayed in `Matched`/`Running` and a
        // guilty ruling had nowhere legal to go — the state machine refused it.
        //
        // A task already in `Disputed` has no second edge into it, so one task
        // cannot accumulate disputes and then be punished twice (finding F).
        next_state(task, TaskState::Disputed)?;
        self.accept_nonce(&dispute.complainant, dispute.nonce)?;

        let task_id = dispute.task_id.clone();
        let task = self.task_mut(&task_id)?;
        apply_transition(task, TaskState::Disputed)?;
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
    /// upstream v2.8.2 fix (finding F): the actor is an explicit
    /// [`Authority::Arbitrator`] who must be the ruling's signer and must not be a
    /// party to the dispute; and the amount slashed comes from
    /// [`MarketConfig::fault_slash_bps`] applied to the balance actually bonded,
    /// **not** from the caller's `slash_amount`.
    ///
    /// upstream v2.8.2 fix (finding G): the transition is validated before the stake
    /// is touched, so a ruling that could not be applied cannot slash anything.
    pub fn arbitrate(&mut self, actor: Actor, ruling: DisputeOutcome, at: u64) -> Result<Money> {
        self.require_live()?;
        ruling.validate()?;
        if actor.authority() != Authority::Arbitrator {
            return Err(NauError::Unauthorized(format!(
                "{actor} may not rule on a dispute; that requires the `arbitrator` authority"
            )));
        }
        if actor.did() != &ruling.arbitrator {
            return Err(NauError::Unauthorized(format!(
                "actor `{}` is not the arbitrator `{}` that signed the ruling",
                actor.did(),
                ruling.arbitrator
            )));
        }
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
        if ruling.task_id != dispute.task_id {
            return Err(NauError::Validation(format!(
                "ruling targets task `{}` but dispute `{}` is about `{}`",
                ruling.task_id, dispute.id, dispute.task_id
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
        // The penalty is a server-side rule over what is actually bonded.
        let stake = stake_account(&respondent);
        let penalty = if ruling.guilty {
            self.penalty_for(&respondent, self.books().balance(&stake))?
        } else {
            Money::ZERO
        };
        let next = if ruling.guilty {
            TaskState::Slashed
        } else {
            TaskState::Accepted
        };
        // Validate the transition before any of the side effects below.
        {
            let task = self
                .tasks
                .get(&task_id)
                .ok_or_else(|| NauError::NotFound(format!("task `{task_id}`")))?;
            next_state(task, next)?;
        }
        self.accept_nonce(&ruling.arbitrator, ruling.nonce)?;

        let mut slashed = Money::ZERO;
        if ruling.guilty {
            slashed = self.books().slash(&stake, penalty, "dispute ruling", at)?;
            let rep = self.reputation.entry(respondent.clone()).or_default();
            rep.record_fault(self.config.fault_severity_bps);
        }

        let task = self.task_mut(&task_id)?;
        apply_transition(task, next)?;
        self.rulings.insert(ruling.dispute_id.clone(), ruling);
        Ok(slashed)
    }

    /// The penalty a guilty verdict actually imposes.
    ///
    /// A server-side rule (finding F): `fault_slash_bps` of the bonded balance,
    /// floored at one minor unit so a guilty verdict always punishes, and capped at
    /// the bond so it can never overdraw the stake account.
    fn penalty_for(&self, respondent: &Did, bonded: Money) -> Result<Money> {
        if !bonded.is_positive() {
            return Err(NauError::Conflict(format!(
                "`{respondent}` has no bonded stake to slash"
            )));
        }
        let bps = i128::from(self.config.fault_slash_bps.min(10_000));
        let scaled = i128::from(bonded.minor()).saturating_mul(bps) / 10_000;
        let scaled = i64::try_from(scaled).map_err(|_| NauError::Overflow("fault slash"))?;
        Ok(Money::from_minor(scaled.max(1)).min(bonded))
    }

    // -------------------------------------------------------------- reporting

    /// Escrowed funds for a task.
    pub fn escrowed_for(&self, id: &TaskId) -> Money {
        self.books().escrowed_for(id)
    }

    /// O(1) conservation snapshot.
    pub fn conservation(&self) -> ConservationReport {
        self.books().conservation()
    }

    /// O(N) independent audit. This is the check that can fail.
    pub fn audit(&self) -> ConservationReport {
        self.books().audit()
    }

    /// Counts for `/stats`.
    pub fn stats(&self) -> MarketStats {
        let (degraded, expected, restored) = match &self.restore_state {
            Some(report) => (
                report.is_degraded(),
                report.ledger_records_expected,
                report.ledger_records_restored,
            ),
            None => {
                let records = self.books().entries().len();
                (false, records, records)
            }
        };
        MarketStats {
            agents: self.agents.len(),
            tasks: self.tasks.len(),
            settled: self
                .tasks
                .values()
                .filter(|t| t.state.is_terminal())
                .count(),
            disputes: self.disputes.len(),
            escrowed_minor: self.books().conservation().total_escrowed.minor(),
            degraded,
            journal_records_expected: expected,
            journal_records_restored: restored,
        }
    }

    // ----------------------------------------------------------- persistence

    /// Write the full market state to a store.
    ///
    /// Upstream persisted only agent registrations, by re-parsing the raw HTTP body,
    /// and never persisted the ledger or read anything back. Here agents, tasks, the
    /// ledger journal and the market's own state (results, reputations, bids,
    /// disputes, rulings, winner prices and nonce watermarks) are all written, and
    /// [`Market::restore`] replays them.
    ///
    /// # Errors
    ///
    /// The first failing write, as a typed error. The journal watermark advances by
    /// one **only after** the matching append succeeded, so a retry after a failure
    /// resumes at the failed record instead of duplicating the ones before it
    /// (finding E).
    pub fn persist(&mut self, store: &dyn Store) -> Result<()> {
        self.require_live()?;
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
        let end = self.books().entries().len();
        for index in start..end {
            let value = serde_json::to_value(&self.books().entries()[index])?;
            store.append_ledger(&value)?;
            // Finding E: upstream did `let _ = store.append_ledger(r);` and then
            // advanced the watermark, so a failed append lost that movement
            // forever. Here the failure propagates and only durable records are
            // counted, so a retry resumes rather than duplicating.
            self.journaled = index + 1;
        }
        store.set_meta(MARKET_VERSION_KEY, nau_core::VERSION)?;
        store.set_meta(MARKET_PROTOCOL_KEY, nau_core::PROTOCOL_VERSION)?;
        // One atomic metadata replace carries the whole market snapshot *and* the
        // logical record count, so the two can never disagree (finding D).
        store.set_meta(MARKET_STATE_KEY, &self.snapshot().to_json()?)?;
        store.flush()
    }

    /// The market's own state, as it is written beside the ledger.
    fn snapshot(&self) -> MarketSnapshot {
        MarketSnapshot {
            schema: MARKET_STATE_SCHEMA,
            journal_records: self.books().entries().len(),
            results: self.results.clone(),
            reputation: self.reputation.clone(),
            bids: self.bids.clone(),
            disputes: self.disputes.clone(),
            rulings: self.rulings.clone(),
            winner_price: self.winner_price.clone(),
            verified_evidence: self.verified_evidence.clone(),
            nonces: self.nonce_high.clone(),
        }
    }

    /// Rebuild a market from a store, replaying the ledger journal.
    ///
    /// A store that does not restore exactly (a record that cannot be decoded, a
    /// gap, a broken chain link, or a journal shorter than the recorded logical
    /// count) yields a market in **degraded, read-only** mode whose
    /// [`Market::restore_report`] names the defect and whose
    /// [`MarketStats::degraded`] field is `true`. Nothing is ever skipped silently
    /// (findings D, E). Use [`Market::restore_checked`] to refuse to serve at all
    /// instead.
    pub fn restore(config: MarketConfig, store: &dyn Store, at: u64) -> Result<Self> {
        Self::restore_reporting(config, store, at).map(|(market, _report)| market)
    }

    /// Rebuild a market, refusing to serve unless it restored exactly.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] naming the first defect when the store did not
    /// restore exactly, or whatever the store itself returned.
    pub fn restore_checked(config: MarketConfig, store: &dyn Store, at: u64) -> Result<Self> {
        let (market, report) = Self::restore_reporting(config, store, at)?;
        if report.is_degraded() {
            return Err(NauError::Validation(format!(
                "refusing to serve: the stored market did not restore exactly ({})",
                report.summary()
            )));
        }
        Ok(market)
    }

    /// Rebuild a market and return the restore report beside it.
    ///
    /// # Errors
    ///
    /// Only failures of the store itself, or an internal invariant violation while
    /// seeding the replay guards. A *defective store* is reported, not returned as
    /// an error, because the caller may still want to read the verified prefix —
    /// and because the market must be able to say out loud what is wrong with its
    /// own state (finding E).
    pub fn restore_reporting(
        config: MarketConfig,
        store: &dyn Store,
        at: u64,
    ) -> Result<(Self, RestoreReport)> {
        Self::restore_reporting_sharing(config, Arc::new(Mutex::new(Ledger::new())), store, at)
    }

    /// Rebuild a market over books the caller already owns, refusing to serve unless it
    /// restored exactly.
    ///
    /// # Why the handle is a parameter
    ///
    /// `sys.ledger` reads the ledger this market mutates, and a plugin cannot read books nobody
    /// handed it: before this existed the plugin was built over an empty ledger of its own and
    /// answered `0` and `open:false` to everything. Restoring into a caller-owned handle is how
    /// the node ends up with **one** ledger rather than two that agree only by accident.
    ///
    /// # Errors
    ///
    /// As [`Market::restore`].
    pub fn restore_sharing(
        config: MarketConfig,
        ledger: Arc<Mutex<Ledger>>,
        store: &dyn Store,
        at: u64,
    ) -> Result<Self> {
        Self::restore_reporting_sharing(config, ledger, store, at).map(|(market, _report)| market)
    }

    /// Restore, with a report and over books the caller owns.
    ///
    /// # Errors
    ///
    /// As [`Market::restore_reporting`].
    pub fn restore_reporting_sharing(
        config: MarketConfig,
        ledger: Arc<Mutex<Ledger>>,
        store: &dyn Store,
        at: u64,
    ) -> Result<(Self, RestoreReport)> {
        let mut market = Market::sharing(config, ledger);
        let mut report = RestoreReport {
            restored_at: at,
            ..RestoreReport::default()
        };

        // 1) The market snapshot. It is read first because it carries the logical
        //    ledger count the journal is checked against.
        let snapshot = match store.get_meta(MARKET_STATE_KEY)? {
            Some(text) => match MarketSnapshot::from_json(&text) {
                Ok(snapshot) => snapshot,
                Err(err) => {
                    report.defects.push(RestoreDefect::new(
                        RestoreDefect::SNAPSHOT_UNREADABLE_KIND,
                        None,
                        err.to_string(),
                    ));
                    // Finding B/C: nothing from the snapshot can be trusted, so the
                    // market is degraded, and a degraded market refuses to write. It
                    // must never settle or bid on the strength of records it failed
                    // to read.
                    MarketSnapshot::empty()
                }
            },
            // A store written before this format existed simply has no snapshot.
            None => MarketSnapshot::empty(),
        };
        report.ledger_records_expected = snapshot.journal_records;

        // 2) The ledger journal, as a *verified prefix*. Balances are re-derived by
        //    the ledger from the records themselves, so a record whose payload was
        //    edited cannot be laundered into a fresh chain.
        let journal = store.load_ledger()?;
        let restored = market.replay_journal(&journal, &mut report)?;
        market.journaled = restored;
        report.ledger_records_restored = restored;

        // 3) Agents, and the skill index re-derived from them. `register_agent` is
        //    not used here because it would try to move stake that the ledger replay
        //    has already accounted for.
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
        report.agents = market.agents.len();

        // 4) Tasks, exactly as they were written: their state, their verification
        //    policy and their assignment all come back unchanged. Upstream rebuilt
        //    them with `verification_policy: None`, which disabled the gate.
        for task in store.load_tasks()? {
            market.tasks.insert(task.id.clone(), task);
        }
        report.tasks = market.tasks.len();

        // 5) Everything else the gates depend on (findings B, C, G).
        market.results = snapshot.results;
        market.reputation.extend(snapshot.reputation);
        market.bids = snapshot.bids;
        market.disputes = snapshot.disputes;
        market.rulings = snapshot.rulings;
        market.winner_price = snapshot.winner_price;
        market.verified_evidence = snapshot.verified_evidence;
        report.results = market.results.len();
        report.disputes = market.disputes.len();

        // 6) Nonce guards must not be left at zero, or a replay of a previously
        //    accepted object would be accepted again after a restart. The durable
        //    high-water map is authoritative; the stored objects are folded in as
        //    well, so an object written by an older build that had no map still
        //    cannot be replayed.
        let mut highest = snapshot.nonces;
        for card in market.agents.values() {
            note_nonce(&mut highest, &card.owner, card.nonce);
        }
        for task in market.tasks.values() {
            note_nonce(&mut highest, &task.spec.owner, task.nonce);
        }
        for bids in market.bids.values() {
            for bid in bids {
                note_nonce(&mut highest, &bid.bidder, bid.nonce);
            }
        }
        for envelope in market.results.values() {
            note_nonce(&mut highest, &envelope.agent, envelope.nonce);
        }
        for dispute in market.disputes.values() {
            note_nonce(&mut highest, &dispute.complainant, dispute.nonce);
        }
        for ruling in market.rulings.values() {
            note_nonce(&mut highest, &ruling.arbitrator, ruling.nonce);
        }
        for (did, nonce) in highest {
            if nonce == 0 {
                continue;
            }
            market.accept_nonce(&did, nonce)?;
        }

        market.restore_state = Some(report.clone());
        Ok((market, report))
    }

    /// Apply the journal to an empty ledger, returning how many records were
    /// applied.
    ///
    /// The journal is treated as a **claim**: each record must decode, sit at the
    /// position its own `seq` names, carry a digest that covers its bytes and link
    /// onto its predecessor. The first record that fails any of those checks ends
    /// the verified prefix — and every logical sequence after it is reported as
    /// missing rather than skipped (finding D).
    fn replay_journal(
        &mut self,
        journal: &[serde_json::Value],
        report: &mut RestoreReport,
    ) -> Result<usize> {
        let mut trusted: Vec<LedgerEntry> = Vec::with_capacity(journal.len());
        let mut previous_hash = GENESIS_DIGEST.to_string();
        for (index, value) in journal.iter().enumerate() {
            let logical = index as u64;
            let entry: LedgerEntry = match serde_json::from_value(value.clone()) {
                Ok(entry) => entry,
                Err(err) => {
                    report.defects.push(RestoreDefect::new(
                        RestoreDefect::UNPARSEABLE_KIND,
                        Some(logical),
                        format!("the stored record could not be decoded as a ledger entry: {err}"),
                    ));
                    break;
                }
            };
            if entry.seq != logical {
                report.defects.push(RestoreDefect::new(
                    RestoreDefect::SEQUENCE_GAP_KIND,
                    Some(logical),
                    format!(
                        "the record at position {logical} stores seq {}, so at least one earlier \
                         record is missing",
                        entry.seq
                    ),
                ));
                break;
            }
            if !entry.is_self_consistent() {
                report.defects.push(RestoreDefect::new(
                    RestoreDefect::DIGEST_MISMATCH_KIND,
                    Some(logical),
                    "the record's digest does not cover its own bytes; it was edited or its chain \
                     fields were stripped"
                        .to_string(),
                ));
                break;
            }
            if entry.prev_hash != previous_hash {
                report.defects.push(RestoreDefect::new(
                    RestoreDefect::BROKEN_LINK_KIND,
                    Some(logical),
                    format!(
                        "the record does not chain onto its predecessor (prev_hash `{}` vs `{}`)",
                        entry.prev_hash, previous_hash
                    ),
                ));
                break;
            }
            previous_hash = entry.hash.clone();
            trusted.push(entry);
        }

        // Adopt the longest prefix the ledger can reproduce. `Ledger::from_journal`
        // replays every movement through the same public method a live mutation
        // uses and compares the resulting digest with the stored claim, so a record
        // the ledger will not reproduce is a record that is not evidence.
        let adopted = match Ledger::from_journal(trusted.clone()) {
            Ok(ledger) => {
                *self.books() = ledger;
                trusted.len()
            }
            Err(whole) => {
                // Binary search for the longest reproducible prefix. The property
                // is monotone: if a prefix replays, so does every shorter one.
                let mut good = 0usize;
                let mut bad = trusted.len();
                while bad - good > 1 {
                    let mid = good + (bad - good) / 2;
                    if Ledger::from_journal(trusted[..mid].to_vec()).is_ok() {
                        good = mid;
                    } else {
                        bad = mid;
                    }
                }
                *self.books() = Ledger::from_journal(trusted[..good].to_vec())?;
                report.defects.push(RestoreDefect::new(
                    RestoreDefect::UNREPRODUCIBLE_KIND,
                    Some(good as u64),
                    format!(
                        "the ledger refused to reproduce the record at seq {good}, so it and \
                         everything after it was not adopted: {whole}"
                    ),
                ));
                good
            }
        };

        // Every logical sequence from the adopted prefix onwards is missing, and that
        // is reported rather than silently skipped (finding D). A journal that is
        // *longer* than the recorded count is not a loss: the snapshot was simply
        // written before those records.
        let known = report.ledger_records_expected.max(journal.len());
        for seq in adopted..known {
            report.missing_records.push(seq as u64);
        }
        if adopted == journal.len() && adopted < report.ledger_records_expected {
            report.defects.push(RestoreDefect::new(
                RestoreDefect::TRUNCATED_TAIL_KIND,
                Some(adopted as u64),
                format!(
                    "the journal holds {adopted} record(s) but the snapshot recorded {}; the tail \
                     was truncated",
                    report.ledger_records_expected
                ),
            ));
        }
        Ok(adopted)
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

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::{Identity, TaskSpec, VerificationPolicy};

    fn task(state: TaskState, id: &str) -> Task {
        let owner = Identity::from_seed(&[42u8; 32]);
        let mut task = Task::draft(
            TaskId::parse(id).expect("id"),
            TaskSpec {
                goal: "g".into(),
                context: "c".into(),
                done: vec!["d".into()],
                todo: vec!["t".into()],
                trace: None,
                owner: owner.did(),
            },
            vec!["translation".into()],
            Money::from_minor(1_000_000),
            None,
            VerificationPolicy::RequesterOnly,
            owner.public_key(),
            1,
            1,
        );
        task.state = state;
        task
    }

    #[test]
    fn terminal_states_have_no_inbound_edge_and_a_repeat_is_not_an_edge() {
        let settled = task(TaskState::Settled, "task-settled");
        for next in [
            TaskState::Open,
            TaskState::Matched,
            TaskState::Running,
            TaskState::Submitted,
            TaskState::Verifying,
            TaskState::Accepted,
            TaskState::Rework,
            TaskState::Disputed,
            TaskState::Slashed,
            TaskState::Cancelled,
            TaskState::NoQuorum,
            TaskState::Settled,
        ] {
            assert!(
                next_state(&settled, next).is_err(),
                "Settled -> {next:?} must be refused"
            );
        }
        // And a non-terminal repeat is refused too, so `Slashed -> Slashed` cannot
        // punish twice.
        let disputed = task(TaskState::Disputed, "task-disputed");
        assert!(next_state(&disputed, TaskState::Disputed).is_err());
        assert!(next_state(&disputed, TaskState::Slashed).is_ok());
    }

    #[test]
    fn a_failed_transition_leaves_the_task_untouched() {
        let mut settled = task(TaskState::Settled, "task-settled");
        let before = settled.state;
        assert!(apply_transition(&mut settled, TaskState::Disputed).is_err());
        assert_eq!(settled.state, before, "a refused transition must not write");
    }

    #[test]
    fn a_guilty_penalty_is_a_server_side_rule_over_the_bond() {
        let market = Market::new(MarketConfig::default());
        let did = Identity::from_seed(&[9u8; 32]).did();
        // 10% of 100 major units is 10 major units, whatever a caller declares.
        let bond = Money::from_minor(100_000_000);
        assert_eq!(
            market.penalty_for(&did, bond).expect("penalty"),
            Money::from_minor(10_000_000)
        );
        // A dust bond still costs one minor unit rather than nothing.
        assert_eq!(
            market
                .penalty_for(&did, Money::from_minor(1))
                .expect("penalty"),
            Money::from_minor(1)
        );
        // An empty bond has nothing to slash, and a guilty verdict must not pass
        // silently.
        assert!(market.penalty_for(&did, Money::ZERO).is_err());
    }
}
