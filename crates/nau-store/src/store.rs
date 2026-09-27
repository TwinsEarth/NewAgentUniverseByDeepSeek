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

    /// Append one ledger entry.
    ///
    /// Append-only: earlier entries are never rewritten or reordered, and a
    /// crash during the append cannot corrupt them.
    fn append_ledger(&self, entry: &Value) -> Result<()>;

    /// Every ledger entry, in the order it was appended.
    fn load_ledger(&self) -> Result<Vec<Value>>;

    /// Read a metadata value. Unknown keys are `Ok(None)`, never an error.
    fn get_meta(&self, key: &str) -> Result<Option<String>>;

    /// Write a metadata value, replacing any previous value for `key`.
    fn set_meta(&self, key: &str, value: &str) -> Result<()>;

    /// Durability barrier: make everything written so far survive a crash.
    fn flush(&self) -> Result<()>;
}
