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
//!    enforces a state transition from [`nau_core::TaskState`].
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

pub mod matching;
pub mod reputation;
pub mod service;

pub use matching::{rank_bids, MatchOutcome};
pub use reputation::Reputation;
pub use service::{Market, MarketConfig, MarketStats};

/// Re-exported so callers of this crate need not depend on the ledger directly.
pub use nau_ledger::{AccountId, ConservationReport, Ledger};
