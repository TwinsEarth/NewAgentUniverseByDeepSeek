//! # nau-market — the agent marketplace service
//!
//! Upstream v2.5.6 puts the whole market in a single 432-line `AgentMarket` plus a
//! 430-line `market_actor.rs`, and the audit found three **critical** defects in
//! that combination:
//!
//! 1. **The verification gate was caller-controlled.** `api/market_actor.rs:360-386`
//!    read `approvals` and `committee_size` straight from the HTTP request and then
//!    *synthesized* a committee (`qa-0`, `qa-1`, …) and its votes locally, so any
//!    client could approve its own task. Here, verification consumes **signed
//!    votes** ([`nau_consensus::Vote`]) from a committee whose membership was fixed
//!    at assignment time; there is no API that counts caller-supplied numbers.
//! 2. **Settlement minted money.** `marketplace/mod.rs:352-355` deposited funds on
//!    the payer's behalf when the balance was short. Here, publishing escrows the
//!    budget and an unfunded requester is rejected outright.
//! 3. **Nothing checked who was asking.** `settle_task`, `arbitrate`,
//!    `open_dispute` and `verify_result` had no authorization and no state
//!    precondition, so `verify`→`settle` could be replayed to farm reputation.
//!    Here every mutating entry point takes an already-verified signed object and
//!    enforces a state transition from [`nau_core::TaskState`], and the privileged
//!    operations additionally take an explicit [`Actor`].
//!
//! ## upstream v2.8.2 fix: the restart path no longer weakens any gate
//!
//! The persistence and restart layer upstream added in v2.8.2 introduced defects
//! that were **worse** than the ones they replaced, and this crate closes each of
//! them. They are named by letter, and every one has a regression test:
//!
//! * **B** — `restore_tasks_from_store` rebuilt tasks with
//!   `verification_policy: None` and `winner_price: None`, and `settle` gates on
//!   exactly those fields, so restarting the daemon bypassed the evidence gate and
//!   paid the full budget. The verification policy travels with the task, the
//!   result envelope (with its evidence grade), the winner price, the verified
//!   grade and the reputation records are persisted in [`MarketSnapshot`], and
//!   settlement refuses when the price is missing instead of substituting the
//!   budget.
//! * **C** — result envelopes, reputations and stakes were never saved, so after a
//!   restart bidding failed for every agent and `arbitrate(guilty = true)` could
//!   not find a stake record while the funds were still on the books. All of them
//!   are persisted, and the nonce high-water marks with them, so a replay is still
//!   refused after a restart.
//! * **D** — the watermark was a physical row count over a list that the loader
//!   silently filtered. Here the logical record count is persisted and every
//!   restored record is checked for position, self-consistency and chain linkage;
//!   a defect appears in a [`RestoreReport`] and ends the verified prefix instead
//!   of being skipped.
//! * **E** — `let _ = store.append_ledger(r);` followed by advancing the watermark
//!   lost a money movement forever, and a failed restore only printed a warning
//!   and then never persisted again. Here a failed append returns a typed error and
//!   advances the watermark only over durable records, and a restore that does not
//!   verify exactly puts the market into an explicitly-labelled **degraded,
//!   read-only** mode that [`MarketStats::degraded`] reports.
//! * **F** — upstream assigned `task.state = TaskState::Disputed` directly (an edge
//!   its own transition table did not even contain, including out of terminal
//!   `Settled`), had no arbitrator identity, and took the penalty from the caller.
//!   Here the only assignment site is `Market`'s transition helper, every
//!   privileged operation takes an [`Actor`] with an explicit [`Authority`], the
//!   penalty is a server-side rule over the bonded stake, and a terminal state has
//!   no inbound edge at all.
//! * **G** — upstream upgraded `env.evidence_grade = EvidenceGrade::Verified`
//!   *before* a transition that could fail, so a verify call that returned an error
//!   had already marked the envelope trustworthy. Here the upgrade happens only
//!   after a successful transition (and never for an evidence-free envelope), and
//!   the other one-way side effects — recording a result, moving settlement money,
//!   slashing a stake — are all ordered after the transition check.
//!
//! ## Layering
//!
//! ```text
//! nau-core        domain types, Money, canonical signing    (no I/O)
//! nau-ledger      exact integer accounts, escrow, slashing
//! nau-consensus   authenticated BFT-lite committee
//! nau-store       persistence ports
//! nau-market      <- this crate: registry + matching + lifecycle orchestration
//! nau-node        transport, HTTP API, composition root
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod actor;
pub mod matching;
pub mod persistence;
pub mod reputation;
pub mod resource;
pub mod service;

pub use actor::{Actor, Authority};
pub use matching::{rank_bids, score_value, MatchOutcome};
pub use persistence::{
    MarketSnapshot, RestoreDefect, RestoreReport, MARKET_PROTOCOL_KEY, MARKET_STATE_KEY,
    MARKET_STATE_SCHEMA, MARKET_VERSION_KEY,
};
pub use reputation::Reputation;
pub use resource::{
    match_demand, LatencyClass, MeteredAmount, RankedOffer, ResourceAmount, ResourceBundle,
    ResourceDemand, ResourceKind, ResourceMatch, ResourceOffer, ResourceRegistration,
    ResourceRegistry,
};
pub use service::{Market, MarketConfig, MarketStats};

/// Re-exported so callers of this crate need not depend on the ledger directly.
pub use nau_ledger::{AccountId, ConservationReport, Ledger};
