//! In-memory [`Store`] for tests and for nodes that run without a disk.
//!
//! This is deliberately named `MemoryStore`, not `Store` or `Persist`: upstream
//! v2.5.6 shipped `net/dht.rs::KademliaClient`, `net/gossip.rs::GossipSub` and
//! `net/libp2p_node.rs::GsnNode` as in-memory `HashMap` stand-ins *with the same
//! names as the real services*, so integration tests "proved" networking against
//! a map. A substitute must be recognisable as one at the call site.
//!
//! Behaviourally it matches [`FileStore`](crate::FileStore): same ordering, same
//! last-write-wins dedupe, same `Ok(None)` for unknown metadata.

use std::collections::BTreeMap;
use std::sync::RwLock;

use nau_core::{AgentCard, NauError, Result, Task};
use serde_json::Value;

use crate::store::Store;
use crate::sync;

/// Largest number of distinct agent cards (or tasks) a `MemoryStore` holds.
///
/// An explicit cap: a store that can grow without bound is a denial-of-service
/// vector, and `Vec::push` on a hostile workload eventually aborts the process.
pub const MAX_RECORDS: usize = 1_000_000;

/// Largest number of ledger entries a `MemoryStore` holds.
pub const MAX_LEDGER_ENTRIES: usize = 1_000_000;

/// A [`Store`] that keeps everything in memory.
///
/// Used by tests and by nodes explicitly configured to be ephemeral. Every lock
/// is poison-recovering, so a panicking writer cannot make the store unusable.
#[derive(Debug, Default)]
pub struct MemoryStore {
    agents: RwLock<BTreeMap<String, AgentCard>>,
    tasks: RwLock<BTreeMap<String, Task>>,
    ledger: RwLock<Vec<Value>>,
    meta: RwLock<BTreeMap<String, String>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn save_agent(&self, card: &AgentCard) -> Result<()> {
        let mut agents = sync::write(&self.agents);
        let key = card.owner.to_string();
        if !agents.contains_key(&key) && agents.len() >= MAX_RECORDS {
            return Err(NauError::Conflict(format!(
                "memory store already holds the maximum of {MAX_RECORDS} agent cards"
            )));
        }
        // Last-write-wins, exactly like the append-only file log.
        agents.insert(key, card.clone());
        Ok(())
    }

    fn load_agents(&self) -> Result<Vec<AgentCard>> {
        Ok(sync::read(&self.agents).values().cloned().collect())
    }

    fn save_task(&self, task: &Task) -> Result<()> {
        let mut tasks = sync::write(&self.tasks);
        let key = task.id.to_string();
        if !tasks.contains_key(&key) && tasks.len() >= MAX_RECORDS {
            return Err(NauError::Conflict(format!(
                "memory store already holds the maximum of {MAX_RECORDS} tasks"
            )));
        }
        tasks.insert(key, task.clone());
        Ok(())
    }

    fn load_tasks(&self) -> Result<Vec<Task>> {
        Ok(sync::read(&self.tasks).values().cloned().collect())
    }

    fn append_ledger(&self, entry: &Value) -> Result<()> {
        let mut ledger = sync::write(&self.ledger);
        if ledger.len() >= MAX_LEDGER_ENTRIES {
            return Err(NauError::Conflict(format!(
                "memory store already holds the maximum of {MAX_LEDGER_ENTRIES} ledger entries"
            )));
        }
        ledger.push(entry.clone());
        Ok(())
    }

    fn load_ledger(&self) -> Result<Vec<Value>> {
        Ok(sync::read(&self.ledger).clone())
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(sync::read(&self.meta).get(key).cloned())
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        if key.trim().is_empty() {
            return Err(NauError::Validation("meta key must not be empty".into()));
        }
        sync::write(&self.meta).insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        // Nothing to do: memory is already "durable" for the process lifetime.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memory_store_starts_empty_and_reports_unknown_keys_as_none() {
        let store = MemoryStore::new();
        assert!(store.load_agents().expect("load").is_empty());
        assert!(store.load_tasks().expect("load").is_empty());
        assert!(store.load_ledger().expect("load").is_empty());
        assert_eq!(store.get_meta("missing").expect("meta"), None);
    }

    #[test]
    fn an_empty_meta_key_is_refused() {
        let store = MemoryStore::new();
        assert!(store.set_meta("  ", "x").is_err());
    }
}
