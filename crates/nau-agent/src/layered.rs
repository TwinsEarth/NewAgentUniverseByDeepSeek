//! Layered, cross-generation memory.
//!
//! Three tiers, each with its own [`HashChain`]: individual (what one agent
//! learned), group (what a swarm agreed on), and generational (what outlives
//! the agents that discovered it). The generational head digest is the
//! "cross-generation pointer": it names the exact collective state a later
//! generation inherits.
//!
//! upstream v2.5.6 fix: upstream `LayeredMemory`
//! (`gsn-core/src/memory/layered.rs`) only counted entries per topology level
//! (`record(level, entries: u64)`), so nothing about *what* was learned survived
//! the counter, and its `IntergenMemory` chain hashed with `DefaultHasher` and
//! discarded the payload. Here every tier is a real, verifiable
//! [`HashChain`].

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};

use crate::chain::HashChain;

/// Default per-tier capacity, in links.
pub const DEFAULT_TIER_CAPACITY: usize = 4_096;

/// Which layer of memory an entry belongs to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTier {
    /// One agent's private history.
    Individual,
    /// Experience shared within a group.
    Group,
    /// Experience kept across generations.
    Generational,
}

impl MemoryTier {
    /// Every tier, in ascending order.
    pub const ALL: [MemoryTier; 3] = [
        MemoryTier::Individual,
        MemoryTier::Group,
        MemoryTier::Generational,
    ];

    /// The stable index used to address the tier's chain.
    pub const fn index(self) -> usize {
        match self {
            MemoryTier::Individual => 0,
            MemoryTier::Group => 1,
            MemoryTier::Generational => 2,
        }
    }

    /// Machine-readable name.
    pub const fn label(self) -> &'static str {
        match self {
            MemoryTier::Individual => "individual",
            MemoryTier::Group => "group",
            MemoryTier::Generational => "generational",
        }
    }
}

/// Three bounded, independently verifiable memory tiers.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LayeredMemory {
    chains: [HashChain; 3],
    tier_capacity: usize,
}

impl Default for LayeredMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl LayeredMemory {
    /// Three empty tiers, each bounded to [`DEFAULT_TIER_CAPACITY`] links.
    pub fn new() -> Self {
        Self {
            chains: [HashChain::new(), HashChain::new(), HashChain::new()],
            tier_capacity: DEFAULT_TIER_CAPACITY,
        }
    }

    /// Set the per-tier link bound.
    ///
    /// upstream v2.5.6 fix: upstream's layered memory had no bound at all. The
    /// bound is enforced on [`LayeredMemory::record`], which refuses to append
    /// past it rather than silently dropping the oldest link — an audit trail
    /// that quietly forgets is worse than one that says it is full.
    pub fn with_tier_capacity(mut self, capacity: usize) -> Self {
        self.tier_capacity = capacity.max(1);
        self
    }

    /// The per-tier link bound.
    pub fn tier_capacity(&self) -> usize {
        self.tier_capacity
    }

    /// Append `payload` to `tier` at logical time `at`.
    pub fn record(&mut self, tier: MemoryTier, payload: &str, at: u64) -> Result<()> {
        if payload.trim().is_empty() {
            return Err(NauError::Validation(format!(
                "{} tier memory payload must not be empty",
                tier.label()
            )));
        }
        let capacity = self.tier_capacity;
        let chain = self.chain_mut(tier);
        if chain.len() >= capacity {
            return Err(NauError::Validation(format!(
                "{} tier memory is full at capacity {}",
                tier.label(),
                capacity
            )));
        }
        chain.append(payload, at)?;
        Ok(())
    }

    /// The chain backing `tier`.
    pub fn chain(&self, tier: MemoryTier) -> &HashChain {
        // `index()` is total over the three variants, so this cannot be out of
        // range; `first()` keeps the function panic-free without `unwrap`.
        self.chains
            .get(tier.index())
            .unwrap_or_else(|| &self.chains[0])
    }

    /// Mutable access to the chain backing `tier`.
    fn chain_mut(&mut self, tier: MemoryTier) -> &mut HashChain {
        let index = tier.index().min(self.chains.len().saturating_sub(1));
        &mut self.chains[index]
    }

    /// Digest of the newest generational link — the cross-generation pointer.
    pub fn generational_head(&self) -> Option<String> {
        self.chain(MemoryTier::Generational)
            .head()
            .map(|link| link.digest.clone())
    }

    /// Verify all three tiers, reporting the first broken link.
    pub fn verify_all(&self) -> Result<()> {
        for tier in MemoryTier::ALL {
            self.chain(tier)
                .verify_chain()
                .map_err(|e| NauError::Validation(format!("{} tier: {e}", tier.label())))?;
        }
        Ok(())
    }

    /// Number of links recorded in `tier`.
    pub fn len(&self, tier: MemoryTier) -> usize {
        self.chain(tier).len()
    }

    /// True when all three tiers are empty.
    pub fn is_empty(&self) -> bool {
        MemoryTier::ALL.iter().all(|tier| self.len(*tier) == 0)
    }
}
