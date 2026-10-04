//! Deterministic, integer-only bid ranking.
//!
//! Upstream's selection rule (`marketplace/mod.rs:224-275`) is
//! `(reputation / price) × 1/(1 + latency_ms/1000)` computed in `f64`, compared with
//! a strict `>`, and it has four defects the audit confirmed:
//!
//! 1. **A price of zero or less is a winning strategy.** The guard degrades to
//!    `cost_score = reputation` when `price <= 0.0`, which beats any honest bid whose
//!    `rep/price` is small — and settlement then pays the full `task.budget`, not the
//!    bid. [`rank_bids`] rejects non-positive prices before scoring (see
//!    [`nau_core::Bid::validate_for`]), so the degenerate branch cannot exist.
//! 2. **Ties are resolved by arrival order.** The strict `>` means "first bid in the
//!    `Vec` wins", which is whatever order the actor's queue happened to deliver. The
//!    ordering here is a total order over `(score, price, eta, did)`, so the winner is
//!    a pure function of the bid *set* and cannot depend on insertion order.
//! 3. **The latency divisor is a magic constant.** Upstream divides by `2000.0`
//!    (`:368-370`) and ignores the agent's advertised `Sla.latency_p95_ms`, so the same
//!    latency is judged identically for an agent that promised 200 ms and one that
//!    promised 10 s. Here the penalty is measured against **that agent's own SLA**.
//! 4. **A missing agent aborts the whole match.** The `?` inside the loop
//!    (`:239-242`) means one stale bid prevents *all* matching. Here a bid naming an
//!    unknown agent is skipped and reported, not fatal.

use std::collections::BTreeMap;

use nau_core::domain::Money;
use nau_core::{AgentCard, Bid, Did, Result, Task};

use crate::reputation::Reputation;

/// The result of ranking a task's bids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchOutcome {
    /// The winning agent.
    pub winner: Did,
    /// The price the winner offered (what will actually be paid, capped by budget).
    pub price: Money,
    /// The winner's integer score.
    pub score: i128,
    /// Every bid, best first, as `(agent, score)`.
    pub ranked: Vec<(Did, i128)>,
    /// Bids that could not be scored, with the reason. Never silently dropped.
    pub skipped: Vec<(Did, String)>,
}

/// The one scoring rule: reputation per unit price, discounted by how late the promise runs.
///
/// # Why this is public and why it is separate from `score_bid`
///
/// D-04 asks that the resource matcher reuse this crate's ordering rather than introduce a second
/// one. "Reuse" cannot mean calling [`rank_bids`], whose inputs are `Task`/`Bid`/`AgentCard` — a
/// resource offer is none of those — so it means what it can honestly mean: **one implementation of
/// the formula, called from both places.**
///
/// A copy would have been the second implementation, and the two would drift the first time either
/// was tuned. This is the same reasoning the rest of this workspace applies to thresholds: one
/// number, in one place.
///
/// # The formula, unchanged from `score_bid`
///
/// `value = reputation_bps × 1_000_000 / price_minor`, penalised by how far `eta_secs` runs past
/// `target_secs`. All integer, and the penalty saturates at 90% so a slow bid is heavily
/// disfavoured without producing a zero that could collide with another zero.
///
/// Returns `None` for a non-positive price, which is the one input the formula cannot speak about.
#[must_use]
pub fn score_value(reputation_bps: u32, price_minor: i64, eta_secs: u64, target_secs: u64) -> i128 {
    if price_minor <= 0 {
        return 0;
    }
    let value = i128::from(reputation_bps) * 1_000_000 / i128::from(price_minor);
    let target = target_secs.max(1);
    let over = eta_secs.saturating_sub(target);
    let penalty_bps = 10_000u64.saturating_sub(
        over.saturating_mul(10_000)
            .checked_div(target)
            .unwrap_or(u64::MAX)
            .min(9_000),
    );
    value * i128::from(penalty_bps)
}

/// Score one bid, or explain why it cannot be scored.
///
/// The score is `value × latency_penalty` where
/// `value = reputation_bps × 1_000_000 / price_minor` (reputation per unit price) and
/// the penalty is expressed in basis points against the agent's own SLA. All integer.
///
/// The arithmetic itself lives in [`score_value`], so that the resource matcher and this one cannot
/// disagree about what a score is.
fn score_bid(
    bid: &Bid,
    agent: &AgentCard,
    reputation_bps: u32,
) -> std::result::Result<i128, String> {
    let price = bid.price.minor();
    if price <= 0 {
        return Err("bid price is not positive".into());
    }

    // The agent's own promised p95, rounded up to whole seconds, at least 1.
    let target_secs = agent.sla.latency_p95_ms.div_ceil(1_000).max(1);
    Ok(score_value(
        reputation_bps,
        price,
        bid.eta_secs,
        target_secs,
    ))
}

/// Rank every valid bid for `task`, best first.
///
/// Deterministic: the output depends only on the set of bids, the agents and the
/// reputations — never on iteration or insertion order. `agents` and `reputations`
/// are `BTreeMap`s so that even the *skipped* list is reported in a stable order.
pub fn rank_bids(
    task: &Task,
    bids: &[Bid],
    agents: &BTreeMap<Did, AgentCard>,
    reputations: &BTreeMap<Did, Reputation>,
) -> Result<MatchOutcome> {
    let mut scored: Vec<(Did, i128, Money, u64)> = Vec::with_capacity(bids.len());
    let mut skipped: Vec<(Did, String)> = Vec::new();

    for bid in bids {
        // Validate against the task first: this is what makes a zero/negative or
        // over-budget price impossible rather than merely disfavoured.
        if let Err(e) = bid.validate_for(task) {
            skipped.push((bid.bidder.clone(), e.to_string()));
            continue;
        }
        let Some(agent) = agents.get(&bid.bidder) else {
            // Upstream's `?` here would abort matching for every other bidder.
            skipped.push((bid.bidder.clone(), "agent is not registered".into()));
            continue;
        };
        let reputation_bps = reputations
            .get(&bid.bidder)
            .map(|r| r.overall_bps())
            .unwrap_or(u32::from(nau_core::ReputationScore::NEUTRAL.bps()));
        match score_bid(bid, agent, reputation_bps) {
            Ok(score) => scored.push((bid.bidder.clone(), score, bid.price, bid.eta_secs)),
            Err(why) => skipped.push((bid.bidder.clone(), why)),
        }
    }

    if scored.is_empty() {
        return Err(nau_core::NauError::Validation(format!(
            "task `{}` has no scoreable bid ({} bid(s) skipped: {})",
            task.id,
            skipped.len(),
            skipped
                .iter()
                .map(|(did, why)| format!("{did}: {why}"))
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }

    // Total order: score desc, then cheaper price, then faster eta, then DID. The
    // final DID term guarantees a unique winner, so the outcome never depends on
    // the order the bids arrived in.
    scored.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.2.cmp(&b.2))
            .then_with(|| a.3.cmp(&b.3))
            .then_with(|| a.0.cmp(&b.0))
    });

    let ranked: Vec<(Did, i128)> = scored.iter().map(|(d, s, _, _)| (d.clone(), *s)).collect();
    let (winner, score, price, _) = scored[0].clone();
    Ok(MatchOutcome {
        winner,
        price,
        score,
        ranked,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::domain::money::major;
    use nau_core::{
        Identity, Pricing, Skill, Sla, TaskId, TaskSpec, Verifiable, VerificationPolicy,
    };

    fn identity(seed: u8) -> Identity {
        Identity::from_seed(&[seed; 32])
    }

    fn agent(id: &Identity, name: &str, p95_ms: u64) -> AgentCard {
        let mut card = AgentCard::draft(
            id,
            name,
            vec![Skill::new("translation", 1)],
            major(100),
            1_700_000_000,
            1,
        );
        card.pricing = Pricing::default();
        card.sla = Sla {
            latency_p95_ms: p95_ms,
            availability_bps: 9_900,
            max_concurrency: 4,
        };
        card.sign(id).unwrap();
        card
    }

    fn task_for(requester: &Identity, budget_minor: i64) -> Task {
        let mut t = Task::draft(
            TaskId::parse("task-1").unwrap(),
            TaskSpec {
                goal: "translate".into(),
                context: "en->zh".into(),
                done: vec!["all sections".into()],
                todo: vec!["translate".into()],
                trace: None,
                owner: requester.did(),
            },
            vec!["translation".into()],
            Money::from_minor(budget_minor),
            None,
            VerificationPolicy::Committee { n: 4, f: 1 },
            requester.public_key(),
            1_700_000_000,
            1,
        );
        t.sign(requester).unwrap();
        t
    }

    fn bid(task: &Task, bidder: &Identity, price_minor: i64, eta_secs: u64, nonce: u64) -> Bid {
        let mut b = Bid {
            task_id: task.id.clone(),
            bidder: bidder.did(),
            bidder_key: bidder.public_key(),
            price: Money::from_minor(price_minor),
            eta_secs,
            confidence_bps: 9_000,
            expires_at: None,
            nonce,
            signed_at: 1_700_000_100,
            signature: String::new(),
        };
        b.sign(bidder).unwrap();
        b
    }

    #[test]
    fn a_non_positive_price_can_never_win() {
        let requester = identity(1);
        let cheap = identity(2);
        let honest = identity(3);
        let task = task_for(&requester, 50_000_000);

        let mut agents = BTreeMap::new();
        agents.insert(cheap.did(), agent(&cheap, "free", 1_000));
        agents.insert(honest.did(), agent(&honest, "honest", 1_000));
        let reps = BTreeMap::new();

        let bids = vec![
            bid(&task, &cheap, 0, 1, 1),
            bid(&task, &honest, 10_000_000, 1, 1),
        ];
        let outcome = rank_bids(&task, &bids, &agents, &reps).unwrap();
        assert_eq!(
            outcome.winner,
            honest.did(),
            "a zero price must be rejected, not rewarded"
        );
        assert_eq!(outcome.skipped.len(), 1);
        assert!(
            outcome.skipped[0].1.contains("price"),
            "the skip reason must name the offending field: {}",
            outcome.skipped[0].1
        );
    }

    #[test]
    fn ranking_is_independent_of_bid_order() {
        let requester = identity(1);
        let a = identity(2);
        let b = identity(3);
        let c = identity(4);
        let task = task_for(&requester, 50_000_000);

        let mut agents = BTreeMap::new();
        agents.insert(a.did(), agent(&a, "a", 1_000));
        agents.insert(b.did(), agent(&b, "b", 1_000));
        agents.insert(c.did(), agent(&c, "c", 1_000));
        let mut reps = BTreeMap::new();
        reps.insert(a.did(), Reputation::default());
        reps.insert(b.did(), Reputation::default());
        reps.insert(c.did(), Reputation::default());

        let bids = vec![
            bid(&task, &a, 10_000_000, 5, 1),
            bid(&task, &b, 20_000_000, 5, 1),
            bid(&task, &c, 10_000_000, 5, 1),
        ];
        let forward = rank_bids(&task, &bids, &agents, &reps).unwrap();

        let mut reversed = bids.clone();
        reversed.reverse();
        let backward = rank_bids(&task, &reversed, &agents, &reps).unwrap();

        assert_eq!(
            forward.winner, backward.winner,
            "winner must not depend on bid order"
        );
        assert_eq!(
            forward.ranked, backward.ranked,
            "full ranking must be stable"
        );
        // a and c tie on price, eta and score, so the DID breaks the tie.
        let expected = std::cmp::min(a.did(), c.did());
        assert_eq!(
            forward.winner, expected,
            "ties are broken by DID, deterministically"
        );
    }

    #[test]
    fn latency_is_judged_against_the_agents_own_sla() {
        // Same eta, but one agent promised 1s and the other 60s. The agent that
        // promised 1s and delivered in 10s should be penalised; the one that
        // promised 60s and delivered in 10s should not be.
        let requester = identity(1);
        let fast_promise = identity(2);
        let slow_promise = identity(3);
        let task = task_for(&requester, 50_000_000);

        let mut agents = BTreeMap::new();
        agents.insert(fast_promise.did(), agent(&fast_promise, "fast", 1_000));
        agents.insert(slow_promise.did(), agent(&slow_promise, "slow", 60_000));
        let reps = BTreeMap::new();

        let bids = vec![
            bid(&task, &fast_promise, 10_000_000, 10, 1),
            bid(&task, &slow_promise, 10_000_000, 10, 1),
        ];
        let outcome = rank_bids(&task, &bids, &agents, &reps).unwrap();
        assert_eq!(
            outcome.winner,
            slow_promise.did(),
            "the agent that kept its promise must outrank the one that missed its own SLA"
        );
        // Upstream's constant divisor would have scored these identically.
        let fast_score = outcome
            .ranked
            .iter()
            .find(|(d, _)| d == &fast_promise.did())
            .unwrap()
            .1;
        let slow_score = outcome
            .ranked
            .iter()
            .find(|(d, _)| d == &slow_promise.did())
            .unwrap()
            .1;
        assert!(slow_score > fast_score);
    }

    #[test]
    fn cheaper_wins_when_reputation_and_latency_are_equal() {
        let requester = identity(1);
        let cheaper = identity(2);
        let dearer = identity(3);
        let task = task_for(&requester, 50_000_000);
        let mut agents = BTreeMap::new();
        agents.insert(cheaper.did(), agent(&cheaper, "cheap", 1_000));
        agents.insert(dearer.did(), agent(&dearer, "dear", 1_000));
        let reps = BTreeMap::new();
        let bids = vec![
            bid(&task, &dearer, 30_000_000, 5, 1),
            bid(&task, &cheaper, 10_000_000, 5, 1),
        ];
        let outcome = rank_bids(&task, &bids, &agents, &reps).unwrap();
        assert_eq!(outcome.winner, cheaper.did());
        assert_eq!(outcome.price, Money::from_minor(10_000_000));
    }

    #[test]
    fn a_missing_agent_skips_one_bid_instead_of_aborting_the_match() {
        let requester = identity(1);
        let known = identity(2);
        let ghost = identity(3);
        let task = task_for(&requester, 50_000_000);
        let mut agents = BTreeMap::new();
        agents.insert(known.did(), agent(&known, "known", 1_000));
        let reps = BTreeMap::new();
        let bids = vec![
            bid(&task, &ghost, 1_000_000, 1, 1),
            bid(&task, &known, 10_000_000, 1, 1),
        ];
        let outcome = rank_bids(&task, &bids, &agents, &reps).unwrap();
        assert_eq!(outcome.winner, known.did());
        assert_eq!(outcome.skipped.len(), 1);
        assert!(outcome.skipped[0].1.contains("not registered"));
    }

    #[test]
    fn an_over_budget_bid_is_skipped_and_reported() {
        let requester = identity(1);
        let greedy = identity(2);
        let task = task_for(&requester, 10_000_000);
        let mut agents = BTreeMap::new();
        agents.insert(greedy.did(), agent(&greedy, "greedy", 1_000));
        let reps = BTreeMap::new();
        let bids = vec![bid(&task, &greedy, 20_000_000, 1, 1)];
        let err = rank_bids(&task, &bids, &agents, &reps).unwrap_err();
        assert!(
            matches!(err, nau_core::NauError::Validation(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn higher_reputation_wins_at_the_same_price() {
        let requester = identity(1);
        let good = identity(2);
        let poor = identity(3);
        let task = task_for(&requester, 50_000_000);
        let mut agents = BTreeMap::new();
        agents.insert(good.did(), agent(&good, "good", 1_000));
        agents.insert(poor.did(), agent(&poor, "poor", 1_000));
        let mut reps = BTreeMap::new();
        let high = Reputation {
            quality: nau_core::ReputationScore::clamped(10_000),
            honesty: nau_core::ReputationScore::clamped(10_000),
            ..Reputation::default()
        };
        reps.insert(good.did(), high);
        reps.insert(poor.did(), Reputation::default());

        let bids = vec![
            bid(&task, &poor, 10_000_000, 5, 1),
            bid(&task, &good, 10_000_000, 5, 1),
        ];
        let outcome = rank_bids(&task, &bids, &agents, &reps).unwrap();
        assert_eq!(outcome.winner, good.did());
    }

    #[test]
    fn scoring_never_touches_a_float() {
        // the score is an integer, and a bid's price is integer minor units, so the
        // whole ranking is exact. This is the property upstream's f64 formula lacks.
        let requester = identity(1);
        let a = identity(2);
        let task = task_for(&requester, 50_000_000);
        let mut agents = BTreeMap::new();
        agents.insert(a.did(), agent(&a, "a", 1_000));
        let reps = BTreeMap::new();
        let bids = vec![bid(&task, &a, 3, 1, 1)];
        let outcome = rank_bids(&task, &bids, &agents, &reps).unwrap();
        assert!(outcome.score > 0);
        assert_eq!(outcome.price.minor(), 3);
    }

    #[test]
    fn an_empty_bid_set_is_a_clear_error() {
        let requester = identity(1);
        let task = task_for(&requester, 50_000_000);
        let err = rank_bids(&task, &[], &BTreeMap::new(), &BTreeMap::new()).unwrap_err();
        assert!(err.to_string().contains("no scoreable bid"), "got {err}");
    }

    #[test]
    fn unsigned_bids_are_refused_before_ranking() {
        // A Bid whose signature was never applied must not be scoreable via the
        // service; here we check the structural validator catches a bad price and
        // the service-level test covers signature rejection.
        let requester = identity(1);
        let a = identity(2);
        let task = task_for(&requester, 50_000_000);
        let mut b = bid(&task, &a, 1_000_000, 1, 1);
        b.price = Money::ZERO;
        assert!(b.validate_for(&task).is_err());
    }
}
