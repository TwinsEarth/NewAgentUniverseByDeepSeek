//! # nau-consensus — BFT-lite committee with authenticated votes
//!
//! This crate replaces upstream `agent-universe` v2.5.6
//! `gsn-core/src/marketplace/qa_committee.rs` and the tallying code in
//! `api/market_actor.rs:360-386`. Six confirmed defects of that code are fixed
//! here, each with a regression test:
//!
//! 1. **The verdict was fully client-controlled.** The REST/MCP layer read
//!    `approvals` and `committee_size` straight out of the *request*, synthesized
//!    members called `qa-0..qa-{n-1}`, cast their votes locally and tallied them,
//!    so `verify?approvals=1&committee_size=1` self-approved any task. Here a
//!    [`Vote`] is a signed [`nau_core::domain::Verifiable`] object carrying the
//!    voter's DID, public key, nonce and timestamp; the committee is built from a
//!    **fixed assigned member set**; [`Committee::cast`] verifies the signature
//!    and rejects any voter outside that set. No API in this crate accepts, or
//!    tallies, a caller-supplied count.
//! 2. **`n` was decorative.** Upstream's `add_member` silently dropped members
//!    past `n` and `tally()` counted over `members` rather than `n`, so
//!    `new(3, 0)` plus a single voter decided the round.
//!    [`Committee::assign`] requires `members.len() == spec.n()` and rejects
//!    duplicates.
//! 3. **Unchecked `3 * f + 1` / `2 * f + 1`.** Upstream computed both on `u32`,
//!    which panics in debug and wraps in release. [`CommitteeSpec::new`] and
//!    [`CommitteeSpec::quorum_checked`] use checked arithmetic and return
//!    [`nau_core::NauError`].
//! 4. **No safety-violation detection.** The project's own papers require "if
//!    both sides reach quorum simultaneously return `None` +
//!    `safety_violation = true` / `conflicting_quorums`". That condition is
//!    detected and exposed as [`Outcome::SafetyViolation`] /
//!    [`TallyReason::ConflictingQuorums`], with the raw condition available as
//!    [`TallyResult::safety_violation`].
//! 5. **Equivocation was a bare `bool`,** so the offender was never attributed.
//!    [`Committee::equivocations`] names the member and
//!    [`Committee::equivocation_details`] records both conflicting decisions.
//! 6. **`NoQuorum` had no recovery path.** [`Committee::reset_for_next_round`]
//!    bumps the round and clears the votes while **preserving** the equivocation
//!    record, so a view change cannot launder a double vote. Only an equivocation
//!    observed in the *current* round voids that round, so the recovery path is
//!    real and does not freeze the committee for ever.
//!
//! ## Tally semantics
//!
//! `quorum = 2f + 1`, evaluated in this exact order:
//!
//! 1. `silent > f` → [`Outcome::NoQuorum`] / [`TallyReason::SilenceExceedsFaults`]
//! 2. an equivocation recorded in the current round → [`Outcome::NoQuorum`] /
//!    [`TallyReason::RoundVoidedByEquivocation`] (the whole round is void)
//! 3. `accept >= quorum && reject >= quorum` → [`Outcome::SafetyViolation`] /
//!    [`TallyReason::ConflictingQuorums`]
//! 4. `accept >= quorum` → [`Outcome::Accepted`] / [`TallyReason::QuorumReached`]
//! 5. `reject >= quorum` → [`Outcome::Rejected`] / [`TallyReason::QuorumReached`]
//! 6. otherwise → [`Outcome::NoQuorum`] / [`TallyReason::InsufficientVotes`]
//!
//! Because a member's *first* vote is the one that counts (a later, conflicting
//! vote is evidence of misbehaviour rather than a second ballot), `silent` is
//! `n - (accept + reject)`. For the tightest legal committee, `n = 3f + 1`, this
//! makes "too many silent members" and "below quorum" the same condition.
//!
//! ## Design rules
//!
//! 1. **No `unsafe`.** `#![forbid(unsafe_code)]` is enforced crate-wide.
//! 2. **No panics on untrusted input.** Every failure is a typed
//!    [`nau_core::NauError`]; there is not a single integer operation on wire
//!    data that can overflow.
//! 3. **No floating point.** Every threshold is an exact integer comparison.
//! 4. **A vote is a signature, not a number.** Nothing here can be driven to a
//!    verdict by the process that happens to host the API.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod committee;
pub mod spec;
pub mod vote;

#[cfg(test)]
mod tests;

pub use committee::{Committee, Equivocation, Outcome, TallyReason, TallyResult};
pub use spec::CommitteeSpec;
pub use vote::{Decision, Vote, MAX_PROPOSAL_LEN};
