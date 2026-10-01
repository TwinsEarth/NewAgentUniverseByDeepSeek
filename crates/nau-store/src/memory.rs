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

use crate::journal::{self, JournalAnchor, JournalRecord, LoadedJournal, GENESIS_DIGEST};
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
///
/// The ledger journal is hash-chained here exactly as it is on disk, so a
/// `MemoryStore` cannot be the place where an integrity check silently passes
/// only because nothing was verified.
#[derive(Debug, Default)]
pub struct MemoryStore {
    agents: RwLock<BTreeMap<String, AgentCard>>,
    tasks: RwLock<BTreeMap<String, Task>>,
    ledger: RwLock<Vec<JournalRecord>>,
    /// The head the appended records chain onto, kept in step with `ledger`.
    anchor: RwLock<JournalAnchor>,
    /// True once anything has been appended through [`Store::append_journal`].
    linked: RwLock<bool>,
    /// `true` when [`Store::append_ledger`] (the unchained path) was used, which
    /// makes the journal unlinked and therefore not evidence.
    unlinked: RwLock<bool>,
    reputations: RwLock<BTreeMap<String, Value>>,
    outcomes: RwLock<BTreeMap<String, Value>>,
    meta: RwLock<BTreeMap<String, String>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a [`LoadedJournal`] from the in-memory records, verifying the chain
    /// and the anchor exactly as the file store does.
    fn verified_journal(&self, ledger: &[JournalRecord]) -> Result<LoadedJournal> {
        let anchor = sync::read(&self.anchor).clone();
        let unlinked = *sync::read(&self.unlinked);
        if unlinked || !*sync::read(&self.linked) {
            return Ok(LoadedJournal {
                records: ledger.to_vec(),
                anchor,
                linked: false,
            });
        }
        let mut expected_prev = GENESIS_DIGEST.to_string();
        for (position, record) in ledger.iter().enumerate() {
            if record.seq != position {
                return Err(journal::JournalBreak::new(
                    record.seq as u64,
                    journal::JournalBreakKind::SequenceMismatch,
                )
                .to_error());
            }
            if record.prev != expected_prev {
                return Err(journal::JournalBreak::new(
                    record.seq as u64,
                    journal::JournalBreakKind::PreviousHashMismatch,
                )
                .to_error());
            }
            let recomputed = journal::record_digest(&record.prev, &record.payload)?;
            if recomputed != record.hash {
                return Err(journal::JournalBreak::new(
                    record.seq as u64,
                    journal::JournalBreakKind::DigestMismatch,
                )
                .to_error());
            }
            expected_prev = record.hash.clone();
        }
        if ledger.is_empty() {
            if !anchor.is_genesis() {
                return Err(
                    journal::JournalBreak::anchor_break(&anchor, 0, GENESIS_DIGEST).to_error(),
                );
            }
        } else if anchor.count != ledger.len() || anchor.head != expected_prev {
            return Err(
                journal::JournalBreak::anchor_break(&anchor, ledger.len(), &expected_prev)
                    .to_error(),
            );
        }
        Ok(LoadedJournal {
            records: ledger.to_vec(),
            anchor,
            linked: true,
        })
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
        let mut anchor = sync::write(&self.anchor);
        let seq = ledger.len();
        let hash = journal::record_digest(&anchor.head, entry)?;
        ledger.push(JournalRecord {
            seq,
            prev: anchor.head.clone(),
            hash: hash.clone(),
            payload: entry.clone(),
        });
        *anchor = JournalAnchor::of(hash, seq + 1);
        // The unchained path makes the journal unlinked, which the loader reports:
        // a mixed chain is not evidence.
        *sync::write(&self.unlinked) = true;
        Ok(())
    }

    fn append_journal(&self, prev: &str, payload: &Value) -> Result<JournalAnchor> {
        let mut ledger = sync::write(&self.ledger);
        if ledger.len() >= MAX_LEDGER_ENTRIES {
            return Err(NauError::Conflict(format!(
                "memory store already holds the maximum of {MAX_LEDGER_ENTRIES} ledger entries"
            )));
        }
        let mut anchor = sync::write(&self.anchor);
        if anchor.head != prev {
            return Err(NauError::Conflict(format!(
                "journal append refused: the caller chains onto `{prev}` but the anchored head is \
                 `{}` ({} records)",
                anchor.head, anchor.count
            )));
        }
        let seq = ledger.len();
        if anchor.count != seq {
            return Err(NauError::Conflict(
                "the journal anchor and the record list disagree on the length".into(),
            ));
        }
        let hash = journal::record_digest(prev, payload)?;
        ledger.push(JournalRecord {
            seq,
            prev: prev.to_string(),
            hash: hash.clone(),
            payload: payload.clone(),
        });
        let next = JournalAnchor::of(hash, seq + 1);
        *anchor = next.clone();
        *sync::write(&self.linked) = true;
        Ok(next)
    }

    fn journal_anchor(&self) -> Result<Option<JournalAnchor>> {
        Ok(Some(sync::read(&self.anchor).clone()))
    }

    fn load_journal(&self) -> Result<LoadedJournal> {
        let ledger = sync::read(&self.ledger);
        self.verified_journal(&ledger)
    }

    fn load_ledger(&self) -> Result<Vec<Value>> {
        Ok(sync::read(&self.ledger)
            .iter()
            .map(|record| record.payload.clone())
            .collect())
    }

    fn save_reputation(&self, did: &str, reputation: &Value) -> Result<()> {
        if did.trim().is_empty() {
            return Err(NauError::Validation(
                "reputation key must not be empty".into(),
            ));
        }
        let mut reputations = sync::write(&self.reputations);
        if !reputations.contains_key(did) && reputations.len() >= MAX_RECORDS {
            return Err(NauError::Conflict(format!(
                "memory store already holds the maximum of {MAX_RECORDS} reputation records"
            )));
        }
        reputations.insert(did.to_string(), reputation.clone());
        Ok(())
    }

    fn load_reputations(&self) -> Result<Vec<(String, Value)>> {
        Ok(sync::read(&self.reputations)
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    fn save_task_outcome(&self, task_id: &str, outcome: &Value) -> Result<()> {
        if task_id.trim().is_empty() {
            return Err(NauError::Validation(
                "task outcome key must not be empty".into(),
            ));
        }
        let mut outcomes = sync::write(&self.outcomes);
        if !outcomes.contains_key(task_id) && outcomes.len() >= MAX_RECORDS {
            return Err(NauError::Conflict(format!(
                "memory store already holds the maximum of {MAX_RECORDS} task outcomes"
            )));
        }
        outcomes.insert(task_id.to_string(), outcome.clone());
        Ok(())
    }

    fn load_task_outcomes(&self) -> Result<Vec<(String, Value)>> {
        Ok(sync::read(&self.outcomes)
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
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
