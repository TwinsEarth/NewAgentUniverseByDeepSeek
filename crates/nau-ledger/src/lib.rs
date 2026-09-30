//! # nau-ledger — exact, integer-only double-entry ledger
//!
//! This crate replaces upstream `agent-universe` v2.5.6
//! `gsn-core/src/marketplace/settlement.rs`. Four confirmed defects of that
//! module are fixed here, each with a regression test:
//!
//! 1. **Money was `f64` and conservation was asserted with a tolerance**
//!    (`(balance_sum - expected_sum).abs() < 0.001`). Here every amount is
//!    [`nau_core::Money`], an integer count of minor units, every arithmetic
//!    operation is checked, and conservation is an **exact equality**. There is
//!    no epsilon anywhere in this crate.
//! 2. **`deposit(account, amount)` and `slash(account, amount)` accepted
//!    negative amounts.** A "negative deposit" credits the account *and*
//!    increments the deposit counter, so the upstream conservation identity still
//!    reported `true` while real money appeared. Every mutating method here
//!    rejects a non-positive amount with [`nau_core::NauError::InvalidAmount`].
//! 3. **Settlement minted money for an unfunded payer**: upstream ran
//!    `if self.settlement.balance(&payer) < amount { self.settlement.deposit(&payer, amount); }`
//!    before releasing. [`Ledger::release`] instead requires the escrow account
//!    to actually hold the funds and otherwise returns
//!    [`nau_core::NauError::InsufficientBalance`]. No code path in this crate can
//!    create funds.
//! 4. **The O(1) conservation check could not detect per-account corruption**
//!    because it compared three counters that are always written together, and
//!    the independent O(N) rescan existed but was never called. Both paths are
//!    provided: [`Ledger::conservation`] is the O(1) counter identity and
//!    [`Ledger::audit`] replays every entry and re-sums every account, so it can
//!    and does fail.
//!
//! ## The journal is hash-chained (V1.2.3)
//!
//! Upstream `agent-universe` v2.8.2 introduced a **new, worse** defect while
//! fixing the money types: its persisted journal had *no integrity at all* —
//! `(seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)`, no hash
//! chain, no signature, no checksum, no trigger, no constraint — and yet its
//! `independent_audit` documented itself as trusting only that journal. Anyone
//! able to write the database file could INSERT a `Deposited` row and both the
//! restart and the "independent" audit would report `passed: true,
//! conserved: true` over invented money.
//!
//! [`journal`] closes that: every [`LedgerEntry`] carries the digest of its
//! predecessor and its own digest over `(prev digest, canonical bytes)`, and
//! [`Ledger::verify_journal`] re-derives the whole chain and names the **first**
//! offending sequence number. [`Ledger::anchor`] is the head a store persists
//! beside the journal, which is what makes a consistent whole-file rewrite
//! detectable.
//!
//! This is **tamper-evidence, not tamper-proofness**. An attacker who can rewrite
//! the entire journal *and* its anchor, consistently, produces a chain that
//! verifies; the module documentation states that boundary explicitly rather
//! than implying a guarantee this design cannot make.
//!
//! ## Model
//!
//! The ledger keeps an insertion-ordered list of **accounts** and a map of
//! balances. Escrowed task funds live in a dedicated internal account
//! (`__escrow__:<task>`); agent stakes live in `__stake__:<did>`. Because the
//! internal accounts are ordinary accounts, the O(1) identity
//!
//! ```text
//! total_deposited - total_withdrawn - total_slashed == sum_of_balances
//! ```
//!
//! holds after every operation, and escrow/release/refund/stake/unstake — being
//! internal transfers — never change either side. That is what makes an O(1)
//! conservation check possible and auditable at all.
//!
//! ## Design rules
//!
//! 1. **No `unsafe`.** `#![forbid(unsafe_code)]` is enforced crate-wide.
//! 2. **No panics on untrusted input.** Every failure is a typed
//!    [`nau_core::NauError`].
//! 3. **No floating point.** Thresholds and magnitudes are integers.
//! 4. **Every derived counter is updated in the same method as the balance
//!    write**, so no successful mutation can leave the counters stale.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod account;
pub mod entry;
pub mod journal;
pub mod ledger;
pub mod report;

#[cfg(test)]
mod tests;

pub use account::{
    escrow_account, stake_account, AccountId, ESCROW_PREFIX, MAX_ACCOUNT_ID_LEN, STAKE_PREFIX,
};
pub use entry::{EntryKind, LedgerEntry};
pub use journal::{
    entry_digest, BreakKind, JournalAnchor, JournalBreak, JournalChain, GENESIS_DIGEST,
    JOURNAL_DOMAIN,
};
pub use ledger::{EscrowRecord, Ledger};
pub use report::ConservationReport;
