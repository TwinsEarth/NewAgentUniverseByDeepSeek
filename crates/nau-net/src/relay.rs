//! Relay pool with enforced capacity, monotone health statistics and
//! deterministic selection.
//!
//! # What upstream v2.5.6 got wrong
//!
//! * **Capacity was advisory.** The check ("is the pool full?") and the insert
//!   were separate statements, so two concurrent inserts both saw a free slot;
//!   several other insert paths skipped the check entirely. Here the check lives
//!   *inside* [`RelayPool::add`], which takes `&mut self`, so the decision and
//!   the mutation cannot be interleaved.
//! * **Dead relays came back to life.** `upsert_relay` reset `healthy` and
//!   `fail_count` on every upsert, so re-announcing a relay that had been failing
//!   made the pool believe it was fine. Here re-adding a known relay updates only
//!   its address and class; `healthy`, `fail_count` and `last_check` change only
//!   through [`RelayPool::record_failure`] and [`RelayPool::record_success`].
//! * **A duplicate probe silently evicted the first.** The pending map was keyed
//!   by `PeerId` and simply overwritten, so the first probe's outcome was applied
//!   to the second probe's state and a healthy relay could be marked dead. Here
//!   [`RelayPool::begin_probe`] refuses a second probe of the same relay, and
//!   [`RelayPool::end_probe`] refuses a token that is not the pending one.
//! * **Selection was map-iteration order.** Here it is class priority
//!   (`Dedicated > SelfHosted > ThirdParty > General`), then `fail_count`, then
//!   relay id — total and therefore deterministic.

use std::collections::BTreeMap;

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};

use crate::peer::PeerId;

/// How much a relay is trusted, in selection-priority order.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RelayClass {
    /// Run by the requesting operator for this purpose alone.
    Dedicated,
    /// Self-hosted by a participating node.
    SelfHosted,
    /// Operated by an unrelated third party.
    ThirdParty,
    /// Catch-all class; least preferred.
    General,
}

impl RelayClass {
    /// Selection priority; lower is preferred.
    pub const fn priority(self) -> u8 {
        match self {
            RelayClass::Dedicated => 0,
            RelayClass::SelfHosted => 1,
            RelayClass::ThirdParty => 2,
            RelayClass::General => 3,
        }
    }

    /// Stable machine-readable label, for logs and wire messages.
    pub const fn label(self) -> &'static str {
        match self {
            RelayClass::Dedicated => "dedicated",
            RelayClass::SelfHosted => "self-hosted",
            RelayClass::ThirdParty => "third-party",
            RelayClass::General => "general",
        }
    }
}

/// One candidate relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayNode {
    /// The relay's peer id.
    pub id: PeerId,
    /// `host:port` (or any transport address) to dial.
    pub addr: String,
    /// Trust class, which decides selection priority.
    pub class: RelayClass,
    /// Whether the most recent probe succeeded. **Never** written by `add`.
    pub healthy: bool,
    /// Consecutive failed probes. Reset only by an explicit success.
    pub fail_count: u32,
    /// Unix seconds of the last probe outcome, if it was ever probed.
    pub last_check: Option<u64>,
}

impl RelayNode {
    /// A healthy, never-probed relay.
    pub fn new(id: PeerId, addr: impl Into<String>, class: RelayClass) -> Self {
        Self {
            id,
            addr: addr.into(),
            class,
            healthy: true,
            fail_count: 0,
            last_check: None,
        }
    }
}

/// A probe that has been started and not yet concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingProbe {
    /// Token that must be presented to [`RelayPool::end_probe`].
    pub token: u64,
    /// When the probe started (Unix seconds, as given by the caller).
    pub started_at: u64,
}

/// A pool of relay candidates with a hard capacity.
#[derive(Debug)]
pub struct RelayPool {
    base_capacity: u32,
    nodes: BTreeMap<PeerId, RelayNode>,
    pending: BTreeMap<PeerId, PendingProbe>,
    last_token: u64,
}

impl RelayPool {
    /// An empty pool that holds at most `base_capacity` relays.
    ///
    /// A capacity of `0` is legal and means "no relay may be added"; every `add`
    /// then fails with [`NauError::Conflict`].
    pub fn new(base_capacity: u32) -> Self {
        Self {
            base_capacity,
            nodes: BTreeMap::new(),
            pending: BTreeMap::new(),
            last_token: 0,
        }
    }

    /// The configured maximum number of relays.
    ///
    /// Counts every known relay, healthy or not: an unhealthy relay still occupies
    /// its slot until [`RelayPool::remove`] evicts it, so capacity cannot be
    /// silently exceeded by a relay that is merely failing.
    pub fn capacity(&self) -> u32 {
        self.base_capacity
    }

    /// Number of known relays.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// True when no relay is known.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Look up one relay.
    pub fn get(&self, id: &PeerId) -> Option<&RelayNode> {
        self.nodes.get(id)
    }

    /// Add a relay, enforcing capacity in the same step.
    ///
    /// * A new relay is inserted only if a slot is free, otherwise
    ///   [`NauError::Conflict`] — the capacity check is inside the mutating call,
    ///   so it cannot be interleaved with another insert.
    /// * A relay that is already known has only its `addr` and `class` updated.
    ///   Its `healthy`, `fail_count` and `last_check` are left alone: upstream's
    ///   `upsert_relay` resurrected dead relays by resetting exactly those fields.
    pub fn add(&mut self, node: RelayNode) -> Result<()> {
        if node.addr.trim().is_empty() {
            return Err(NauError::Validation(format!(
                "relay `{}` has an empty address",
                node.id
            )));
        }
        if let Some(existing) = self.nodes.get_mut(&node.id) {
            existing.addr = node.addr;
            existing.class = node.class;
            return Ok(());
        }
        if self.nodes.len() >= self.base_capacity as usize {
            return Err(NauError::Conflict(format!(
                "relay pool is full: capacity {} reached, refusing `{}`",
                self.base_capacity, node.id
            )));
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    /// Remove a relay and any pending probe for it.
    pub fn remove(&mut self, id: &PeerId) -> Result<()> {
        if self.nodes.remove(id).is_none() {
            return Err(NauError::NotFound(format!(
                "relay `{id}` is not in the pool"
            )));
        }
        self.pending.remove(id);
        Ok(())
    }

    /// Record a failed probe: the relay becomes unhealthy and its consecutive
    /// failure count grows.
    pub fn record_failure(&mut self, id: &PeerId, now: u64) -> Result<()> {
        let node = self
            .nodes
            .get_mut(id)
            .ok_or_else(|| NauError::NotFound(format!("relay `{id}` is not in the pool")))?;
        node.healthy = false;
        // Saturating: a relay that fails forever must not wrap back to "healthy".
        node.fail_count = node.fail_count.saturating_add(1);
        node.last_check = Some(now);
        Ok(())
    }

    /// Record a successful probe: the relay becomes healthy again and its
    /// consecutive failure count is cleared.
    pub fn record_success(&mut self, id: &PeerId, now: u64) -> Result<()> {
        let node = self
            .nodes
            .get_mut(id)
            .ok_or_else(|| NauError::NotFound(format!("relay `{id}` is not in the pool")))?;
        node.healthy = true;
        node.fail_count = 0;
        node.last_check = Some(now);
        Ok(())
    }

    /// The healthy relays, in [`RelayPool::select`] order.
    pub fn healthy(&self) -> Vec<&RelayNode> {
        let mut healthy: Vec<&RelayNode> =
            self.nodes.values().filter(|node| node.healthy).collect();
        healthy.sort_by(|a, b| selection_key(a).cmp(&selection_key(b)));
        healthy
    }

    /// The `count` best relays, deterministically ordered.
    ///
    /// Ordering is class priority first (`Dedicated` before `SelfHosted` before
    /// `ThirdParty` before `General`), then `fail_count` ascending, then relay id
    /// ascending. Two pools holding the same relays therefore always return the
    /// same answer, which is what makes a relay choice reproducible after a
    /// restart.
    pub fn select(&self, count: usize) -> Vec<&RelayNode> {
        let mut healthy = self.healthy();
        healthy.truncate(count);
        healthy
    }

    /// Start a probe of `id`, returning the token that concludes it.
    ///
    /// A second probe of the same relay while one is pending is refused with
    /// [`NauError::Conflict`]: upstream overwrote the pending entry, so the first
    /// probe's outcome was applied to the wrong state and a healthy relay could be
    /// marked dead.
    pub fn begin_probe(&mut self, id: &PeerId, now: u64) -> Result<u64> {
        if !self.nodes.contains_key(id) {
            return Err(NauError::NotFound(format!(
                "relay `{id}` is not in the pool"
            )));
        }
        if let Some(existing) = self.pending.get(id) {
            return Err(NauError::Conflict(format!(
                "a probe of relay `{id}` (token {}) started at {} is already pending",
                existing.token, existing.started_at
            )));
        }
        let token = self
            .last_token
            .checked_add(1)
            .ok_or(NauError::Overflow("relay probe token"))?;
        self.last_token = token;
        self.pending.insert(
            id.clone(),
            PendingProbe {
                token,
                started_at: now,
            },
        );
        Ok(token)
    }

    /// The probe currently pending for `id`, if any.
    pub fn pending_probe(&self, id: &PeerId) -> Option<&PendingProbe> {
        self.pending.get(id)
    }

    /// How many probes are in flight.
    pub fn pending_probe_count(&self) -> usize {
        self.pending.len()
    }

    /// Conclude the probe identified by `token`.
    ///
    /// A token that is not the pending one is refused, so a late result from an
    /// abandoned probe cannot change a relay's health.
    pub fn end_probe(&mut self, id: &PeerId, token: u64) -> Result<PendingProbe> {
        let pending = self
            .pending
            .get(id)
            .ok_or_else(|| NauError::NotFound(format!("relay `{id}` has no pending probe")))?;
        if pending.token != token {
            return Err(NauError::Conflict(format!(
                "probe token {token} does not match the pending token {} for relay `{id}`",
                pending.token
            )));
        }
        self.pending
            .remove(id)
            .ok_or_else(|| NauError::NotFound(format!("relay `{id}` has no pending probe")))
    }
}

/// Total order used by `healthy` and `select`.
fn selection_key(node: &RelayNode) -> (u8, u32, &PeerId) {
    (node.class.priority(), node.fail_count, &node.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(name: &str, class: RelayClass) -> RelayNode {
        RelayNode::new(
            PeerId::parse(name).expect("valid id"),
            format!("127.0.0.1:{}", name.len()),
            class,
        )
    }

    #[test]
    fn capacity_is_enforced_inside_add() {
        let mut pool = RelayPool::new(2);
        assert_eq!(pool.capacity(), 2);
        pool.add(relay("relay-a", RelayClass::General))
            .expect("add");
        pool.add(relay("relay-b", RelayClass::General))
            .expect("add");
        let err = pool
            .add(relay("relay-c", RelayClass::Dedicated))
            .expect_err("must refuse");
        assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
        assert_eq!(pool.len(), 2, "a refused insert must not change the pool");
        assert!(pool.get(&PeerId::parse("relay-c").expect("id")).is_none());

        let mut empty = RelayPool::new(0);
        assert!(empty.is_empty());
        assert!(empty.add(relay("relay-a", RelayClass::General)).is_err());
    }

    #[test]
    fn re_adding_a_relay_never_resets_its_health_or_statistics() {
        let mut pool = RelayPool::new(4);
        let id = PeerId::parse("relay-a").expect("id");
        pool.add(relay("relay-a", RelayClass::General))
            .expect("add");
        pool.record_failure(&id, 1_000).expect("fail");
        pool.record_failure(&id, 1_060).expect("fail again");
        assert_eq!(pool.get(&id).expect("present").fail_count, 2);
        assert!(!pool.get(&id).expect("present").healthy);

        // The upstream defect: an upsert carrying healthy=true, fail_count=0.
        let mut reborn = relay("relay-a", RelayClass::Dedicated);
        reborn.addr = "10.0.0.9:9000".to_string();
        reborn.healthy = true;
        reborn.fail_count = 0;
        pool.add(reborn).expect("re-add");

        let stored = pool.get(&id).expect("present");
        assert!(
            !stored.healthy,
            "a dead relay must stay dead until a probe succeeds"
        );
        assert_eq!(
            stored.fail_count, 2,
            "statistics must be monotone across re-adds"
        );
        assert_eq!(stored.addr, "10.0.0.9:9000", "the address may be updated");
        assert_eq!(
            stored.class,
            RelayClass::Dedicated,
            "the class may be updated"
        );
        assert_eq!(stored.last_check, Some(1_060));

        // Only an explicit success clears the failure count.
        pool.record_success(&id, 2_000).expect("success");
        let stored = pool.get(&id).expect("present");
        assert!(stored.healthy);
        assert_eq!(stored.fail_count, 0);
        assert_eq!(stored.last_check, Some(2_000));

        assert!(pool
            .record_failure(&PeerId::parse("ghost").expect("id"), 1)
            .is_err());
    }

    #[test]
    fn a_duplicate_probe_is_refused_and_the_first_is_preserved() {
        let mut pool = RelayPool::new(2);
        let id = PeerId::parse("relay-a").expect("id");
        pool.add(relay("relay-a", RelayClass::General))
            .expect("add");

        let first = pool.begin_probe(&id, 100).expect("first probe");
        assert_eq!(pool.pending_probe_count(), 1);
        let err = pool.begin_probe(&id, 200).expect_err("duplicate");
        assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
        let pending = pool.pending_probe(&id).expect("still pending");
        assert_eq!(pending.token, first, "the first probe must survive");
        assert_eq!(pending.started_at, 100);

        // A stale token must not conclude the live probe.
        assert!(pool.end_probe(&id, first + 1).is_err());
        assert!(pool.pending_probe(&id).is_some());

        let concluded = pool.end_probe(&id, first).expect("concluded");
        assert_eq!(concluded.token, first);
        assert!(pool.pending_probe(&id).is_none());

        // Once concluded, a new probe is allowed and gets a fresh token.
        let second = pool.begin_probe(&id, 300).expect("second probe");
        assert_ne!(second, first);
        assert!(pool
            .begin_probe(&PeerId::parse("ghost").expect("id"), 1)
            .is_err());
    }

    #[test]
    fn removal_reports_unknown_relays_and_clears_pending_probes() {
        let mut pool = RelayPool::new(2);
        let id = PeerId::parse("relay-a").expect("id");
        assert!(matches!(
            pool.remove(&id).expect_err("unknown"),
            NauError::NotFound(_)
        ));
        pool.add(relay("relay-a", RelayClass::General))
            .expect("add");
        let token = pool.begin_probe(&id, 1).expect("probe");
        pool.remove(&id).expect("remove");
        assert!(pool.pending_probe(&id).is_none());
        assert!(pool.end_probe(&id, token).is_err());
        assert!(pool.is_empty());
    }

    #[test]
    fn an_empty_address_is_refused() {
        let mut pool = RelayPool::new(2);
        let mut node = relay("relay-a", RelayClass::General);
        node.addr = "   ".to_string();
        assert!(pool.add(node).is_err());
    }
}
