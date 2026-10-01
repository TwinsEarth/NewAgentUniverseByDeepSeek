//! Bounded individual memory with a real LRU eviction policy.
//!
//! ## Quality is an integer, always
//!
//! Scores are `u16` basis points (`0..=10_000`). Upstream stored `score: f64`
//! and ordered with `partial_cmp(..).unwrap()`, which panics the moment a `NaN`
//! reaches the field; ordering by integers cannot panic and is byte-stable
//! across platforms.
//!
//! ## Eviction is recency, not frequency
//!
//! Each record carries both `uses` (a monotonic counter) and `last_used` (a
//! logical clock stamp). Eviction compares `last_used` first, then `uses`.
//! Comparing `uses` first — which is what upstream did — is LFU, and it evicts
//! the entry you just used once in favour of one you hammered an hour ago.

use std::collections::HashMap;

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};

/// The largest quality a record may claim (100.00%).
pub const MAX_QUALITY_BPS: u16 = 10_000;

/// One memory record.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// Lookup key. Unique within a store.
    pub key: String,
    /// The remembered text.
    pub payload: String,
    /// Free-form tags used by [`AgentMemory::search`].
    pub tags: Vec<String>,
    /// Quality in basis points, `0..=10000`.
    pub quality_bps: u16,
    /// How many times the record has been recalled.
    pub uses: u64,
    /// Logical clock reading of the most recent use.
    pub last_used: u64,
}

impl MemoryRecord {
    /// A fresh record with zero uses, stamped at `at`.
    pub fn new(
        key: impl Into<String>,
        payload: impl Into<String>,
        quality_bps: u16,
        at: u64,
    ) -> Self {
        Self {
            key: key.into(),
            payload: payload.into(),
            tags: Vec::new(),
            quality_bps,
            uses: 0,
            last_used: at,
        }
    }

    /// Attach tags (builder style).
    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// True when the record matches `query` by exact tag (case-insensitive) or
    /// by case-insensitive substring of its payload or key.
    pub fn matches(&self, query: &str) -> bool {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return true;
        }
        if self.tags.iter().any(|t| t.to_lowercase() == needle) {
            return true;
        }
        self.payload.to_lowercase().contains(&needle) || self.key.to_lowercase().contains(&needle)
    }

    /// Ordering key used for eviction: least-recently-used first.
    fn lru_key(&self) -> (u64, u64) {
        // `uses` is the tie-break only; `last_used` decides.
        (self.last_used, self.uses)
    }
}

/// A capacity-limited set of [`MemoryRecord`]s with LRU eviction.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AgentMemory {
    records: Vec<MemoryRecord>,
    index: HashMap<String, usize>,
    capacity: usize,
}

impl AgentMemory {
    /// A store holding at most `capacity` records.
    ///
    /// upstream v2.5.6 fix: upstream
    /// (`gsn-core/src/memory/agent_memory.rs`) kept two uncapped `Vec`s and a
    /// `HashMap` and never evicted anything, and
    /// (`gsn-core/src/memory/enhanced.rs::EnhancedMemory`) used `capacity.max(1)`
    /// but still grew without bound when the same key was rewritten. Capacity is
    /// now explicit, clamped to at least 1, and enforced on every write.
    pub fn new(capacity: usize) -> Self {
        Self {
            records: Vec::new(),
            index: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Store `record`, evicting the least-recently-used entry if needed.
    ///
    /// Re-remembering an existing key replaces its payload, tags and quality,
    /// keeps the accumulated `uses`, and takes the newer `last_used` stamp. A
    /// quality above [`MAX_QUALITY_BPS`] is rejected rather than clamped, so a
    /// caller cannot smuggle a meaningless score in.
    pub fn remember(&mut self, record: MemoryRecord) -> Result<()> {
        if record.key.trim().is_empty() {
            return Err(NauError::Validation("memory key must not be empty".into()));
        }
        if record.quality_bps > MAX_QUALITY_BPS {
            return Err(NauError::Validation(format!(
                "quality_bps {} exceeds the maximum of {MAX_QUALITY_BPS}",
                record.quality_bps
            )));
        }
        if let Some(&position) = self.index.get(&record.key) {
            let existing = &mut self.records[position];
            let uses = existing.uses.saturating_add(record.uses);
            let last_used = existing.last_used.max(record.last_used);
            *existing = MemoryRecord {
                uses,
                last_used,
                ..record
            };
            return Ok(());
        }
        if self.records.len() >= self.capacity {
            self.evict_lru()?;
        }
        self.index.insert(record.key.clone(), self.records.len());
        self.records.push(record);
        Ok(())
    }

    /// Remove the entry with the smallest `(last_used, uses)` pair.
    fn evict_lru(&mut self) -> Result<()> {
        let victim = self
            .records
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| {
                a.lru_key()
                    .cmp(&b.lru_key())
                    .then_with(|| a.key.cmp(&b.key))
            })
            .map(|(position, _)| position)
            .ok_or_else(|| NauError::Validation("cannot evict from an empty memory".into()))?;
        let key = self.records[victim].key.clone();
        self.records.remove(victim);
        self.reindex();
        self.index.remove(&key);
        Ok(())
    }

    /// Rebuild the key index after a positional shift.
    fn reindex(&mut self) {
        self.index.clear();
        for (position, record) in self.records.iter().enumerate() {
            self.index.insert(record.key.clone(), position);
        }
    }

    /// Exact-key lookup.
    pub fn recall_exact(&self, key: &str) -> Option<&MemoryRecord> {
        self.index
            .get(key)
            .and_then(|position| self.records.get(*position))
    }

    /// Tag match or case-insensitive substring match, best first.
    ///
    /// Ordering is by `quality_bps` descending, then `last_used` descending,
    /// then key ascending — all integer comparisons, all deterministic, so equal
    /// inputs always produce identical output order.
    pub fn search(&self, query: &str, limit: usize) -> Vec<&MemoryRecord> {
        let mut hits: Vec<&MemoryRecord> = self
            .records
            .iter()
            .filter(|record| record.matches(query))
            .collect();
        hits.sort_by(|a, b| {
            b.quality_bps
                .cmp(&a.quality_bps)
                .then_with(|| b.last_used.cmp(&a.last_used))
                .then_with(|| a.key.cmp(&b.key))
        });
        hits.truncate(limit);
        hits
    }

    /// Record a use of `key` at logical time `now`.
    ///
    /// Returns false when the key is unknown. `uses` saturates rather than
    /// wrapping, so a counter cannot silently reset to zero.
    pub fn touch(&mut self, key: &str, now: u64) -> bool {
        match self.index.get(key).copied() {
            Some(position) => {
                if let Some(record) = self.records.get_mut(position) {
                    record.uses = record.uses.saturating_add(1);
                    record.last_used = record.last_used.max(now);
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    /// Number of stored records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The configured bound, always at least 1.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// All records in insertion order (deterministic).
    pub fn records(&self) -> &[MemoryRecord] {
        &self.records
    }
}
