//! The persistence port.
//!
//! One trait so that production code can be written against durable storage
//! while tests can use [`MemoryStore`](crate::MemoryStore) — and, crucially, so
//! that a single generic test helper can be run against **both** and assert they
//! behave identically (see `tests/store_contract.rs`).
//!
//! Upstream v2.5.6 has no such port: storage is a concrete struct with private
//! methods, `load_agents`/`load_tasks` are never called, and the read path is
//! therefore never exercised by any test.

use nau_core::{AgentCard, Result, Task};
use serde_json::Value;

use crate::journal::{JournalAnchor, LoadedJournal};

/// Durable storage for market state.
///
/// Implementations must:
///
/// * never panic — a torn file, a poisoned lock or an unreadable record is
///   reported as a `Result`;
/// * return records from the read methods in a **deterministic** order (both
///   implementations here order agents/tasks by their id and ledger entries by
///   insertion order), so that replaying the same operations yields the same
///   observable state;
/// * apply **last-write-wins** per id for agents and tasks.
pub trait Store: Send + Sync {
    /// Persist (or replace) an agent card, keyed by its owner DID.
    fn save_agent(&self, card: &AgentCard) -> Result<()>;

    /// Every known agent card: exactly one per DID, ordered by DID ascending.
    fn load_agents(&self) -> Result<Vec<AgentCard>>;

    /// Persist (or replace) a task, keyed by its task id.
    fn save_task(&self, task: &Task) -> Result<()>;

    /// Every known task: exactly one per task id, ordered by id ascending.
    fn load_tasks(&self) -> Result<Vec<Task>>;

    /// Persist (or replace) an agent's reputation snapshot, keyed by DID.
    ///
    /// upstream v2.8.2 fix (finding C): reputation was never persisted at all, so
    /// after a restart `submit_bid` failed for every agent (the eligibility
    /// predicate found no record) and `arbitrate(guilty = true)` failed with "no
    /// stake record" — while the staked funds were still on the books.
    fn save_reputation(&self, did: &str, reputation: &Value) -> Result<()>;

    /// Every persisted reputation snapshot, ordered by DID ascending.
    fn load_reputations(&self) -> Result<Vec<(String, Value)>>;

    /// Record the terminal outcome of a task, keyed by task id.
    ///
    /// Persisted so that a restart cannot resurrect a nonce guard, a dispute or a
    /// slashed stake that the previous process had already consumed.
    fn save_task_outcome(&self, task_id: &str, outcome: &Value) -> Result<()>;

    /// Every recorded task outcome, ordered by task id ascending.
    fn load_task_outcomes(&self) -> Result<Vec<(String, Value)>>;

    /// Append one ledger entry **without** a chain link.
    ///
    /// Kept for callers that store opaque values (and for the store contract
    /// tests); the market uses [`Store::append_journal`], which is the only path
    /// that keeps the chain and the anchor in step.
    ///
    /// Append-only: earlier entries are never rewritten or reordered, and a
    /// crash during the append cannot corrupt them.
    fn append_ledger(&self, entry: &Value) -> Result<()>;

    /// Append one ledger entry to the hash-chained journal.
    ///
    /// `prev` is the digest of the entry currently at the head of the chain; the
    /// store refuses the append when it disagrees with the anchored head, which is
    /// what makes a replayed or reordered append impossible rather than merely
    /// unlikely. On success the anchor is updated **after** the record is durable,
    /// and the new anchor is returned.
    ///
    /// # Errors
    ///
    /// [`NauError::Conflict`] when `prev` is not the anchored head (the caller's
    /// view of the journal is stale), and [`NauError::Io`] when either the record
    /// or the anchor cannot be made durable. A failed append must not advance any
    /// caller-side watermark.
    fn append_journal(&self, prev: &str, payload: &Value) -> Result<JournalAnchor>;

    /// The anchor recorded beside the journal.
    ///
    /// `None` means no anchor was ever written. That is *not* the same as "no
    /// anchor needed": [`Store::load_journal`] refuses a journal that holds
    /// records but has no anchor.
    fn journal_anchor(&self) -> Result<Option<JournalAnchor>>;

    /// Load the journal, verifying its chain and its anchor.
    ///
    /// `linked` is `false` only for a journal written before linkage existed; an
    /// unverified or broken journal is an error, never a partial list.
    fn load_journal(&self) -> Result<LoadedJournal>;

    /// Every ledger entry, in the order it was appended (unverified).
    ///
    /// Prefer [`Store::load_journal`], which is the same list plus a proof.
    fn load_ledger(&self) -> Result<Vec<Value>>;

    /// Read a metadata value. Unknown keys are `Ok(None)`, never an error.
    fn get_meta(&self, key: &str) -> Result<Option<String>>;

    /// Write a metadata value, replacing any previous value for `key`.
    fn set_meta(&self, key: &str, value: &str) -> Result<()>;

    /// Durability barrier: make everything written so far survive a crash.
    fn flush(&self) -> Result<()>;
}
