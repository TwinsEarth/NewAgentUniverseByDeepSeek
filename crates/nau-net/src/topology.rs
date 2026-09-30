//! Deterministic Lv1–Lv7 layered overlay topology.
//!
//! # The model
//!
//! Every node gets two values that are **pure functions of its id** (never of
//! the insertion order, never of the current membership):
//!
//! * a **level** `L` in `1..=7` (Lv1 is the finest, most numerous layer; Lv7 is
//!   the single root room);
//! * a **room** at each level, obtained by shifting its level-1 room id right by
//!   [`ROOM_BITS`] bits per level. The room tree is therefore a fixed 8-ary tree
//!   over `2^18` leaf rooms whose root is room `0` at Lv7 — the same shape for
//!   every run, for every peer, on every machine.
//!
//! The edge set is a pure function of the member set:
//!
//! 1. **Same-room ring.** Inside one `(level, room)` group, members are ordered by
//!    [`ring_key`] then id, and each member links to its next
//!    [`fanout`](LayeredTopology::new) ring successors (cyclically). A node's
//!    same-room in-degree is therefore exactly `min(fanout, group_size - 1)`.
//! 2. **Uplink.** For a node `X` at level `L < 7`, consider the merged order of
//!    the parent room's members (level `L + 1`) and of every node at level `L`
//!    in a *child* room of that room. `X`'s uplink goes to its immediate
//!    successor in that merged order, if that successor is at level `L + 1`.
//!    Because it is an *immediate successor*, at most one node can point at any
//!    given node, so the uplink contributes at most `1` to a node's in-degree.
//!
//! Together these give a fan-in bound of `fanout + 1` for **every** node, which
//! is asserted in `tests/topology.rs` along with the measured sub-quadratic edge
//! growth.
//!
//! # What upstream v2.5.6 got wrong
//!
//! * **Nondeterministic rooms.** Room assignment iterated a `HashMap`, so the
//!   same node could land in a different room on the next run, and two nodes
//!   never agreed on the topology. Fixed: [`LayeredTopology::room_of`] and
//!   [`LayeredTopology::level_of`] are pure hash functions, and
//!   `tests/topology.rs` builds the same 500 ids in two different insertion
//!   orders and asserts identical rooms, identical edge count and identical hop
//!   counts.
//! * **`route_hops` returned the constant `Some(7)`** for every cross-room pair,
//!   so the documented "≤ 7 hops" claim was vacuous and the test asserted
//!   `== Some(7)`, enshrining the constant. Fixed:
//!   [`LayeredTopology::route_hops`] computes the real number of tree levels
//!   between the two rooms' lowest common ancestor and returns `None` for an
//!   unknown node.
//! * **`fanin_of` omitted the uplink edge**, under-reporting fan-in. Fixed: it
//!   counts same-room predecessors *and* the uplink.
//! * **The sub-quadratic claim could never fail** (`edges < n * n / 100` with no
//!   scaling comparison). Fixed: the test *measures* `edges(2N) / edges(N)`.
//! * **`join` rebuilt every level on each insert**, making construction O(N²).
//!   Fixed: [`LayeredTopology::join`] is an O(log n) incremental insert into a
//!   map plus one group set; every query is derived from those structures.

use std::collections::{BTreeMap, BTreeSet};

use nau_core::{NauError, Result};
use sha2::{Digest, Sha256};

use crate::peer::PeerId;

/// Number of overlay levels, Lv1 through Lv7.
pub const MAX_LEVEL: u8 = 7;

/// Bits of room id consumed per level of the room tree.
///
/// Eight rooms per parent room, so `2^(3 * 6) = 262_144` rooms exist at Lv1 and
/// exactly one (room `0`) at Lv7.
pub const ROOM_BITS: u32 = 3;

/// Number of distinct rooms at level 1.
pub const ROOMS_AT_LEVEL_1: u64 = 1 << (ROOM_BITS * (MAX_LEVEL as u32 - 1));

/// Largest accepted fanout. An explicit bound, so one node cannot be asked to
/// maintain an unbounded number of neighbours.
pub const MAX_FANOUT: u32 = 64;

/// Largest accepted number of nodes in one topology view.
pub const MAX_NODES: usize = 1_000_000;

/// The deterministic ring key of a peer id: the first eight bytes of
/// `SHA-256(id)`, big-endian.
///
/// This is the ordering key of every ring in the topology. It is public because
/// a node must be able to compute its own neighbours without holding the whole
/// membership set, and because a test that recomputed the topology independently
/// would otherwise need private state.
pub fn ring_key(id: &PeerId) -> u64 {
    let digest = Sha256::digest(id.as_str().as_bytes());
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(head)
}

/// Immutable per-node derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NodeEntry {
    key: u64,
    level: u8,
    /// Level-1 room id.
    room: u64,
}

impl NodeEntry {
    fn derive(id: &PeerId) -> Self {
        let key = ring_key(id);
        // Level and room come from disjoint bit ranges of the hash, so they are
        // statistically independent: the room is the low 18 bits, the level the
        // next byte.
        let level = ((key >> 56) % u64::from(MAX_LEVEL)) as u8 + 1;
        let room = key % ROOMS_AT_LEVEL_1;
        Self { key, level, room }
    }

    /// This node's room at `level`, which must be `>= self.level`.
    fn room_at(&self, level: u8) -> u64 {
        // `saturating_sub` keeps the shift well-defined for any input; every call
        // site passes a level at or above this node's own level.
        self.room >> (ROOM_BITS * u32::from(level.saturating_sub(1)))
    }

    /// The group this node belongs to.
    fn group(&self) -> (u8, u64) {
        (self.level, self.room_at(self.level))
    }

    /// The parent room this node uplinks towards, if it has one.
    fn parent_group(&self) -> Option<(u8, u64)> {
        if self.level >= MAX_LEVEL {
            return None;
        }
        Some((self.level + 1, self.room_at(self.level + 1)))
    }
}

/// The deterministic Lv1–Lv7 layered topology.
///
/// See the module documentation for the model. Queries are pure functions of the
/// current membership; no query mutates anything, and `join`/`leave` are the only
/// mutators.
#[derive(Debug)]
pub struct LayeredTopology {
    fanout: u32,
    max_nodes: usize,
    nodes: BTreeMap<PeerId, NodeEntry>,
    /// Members of each `(level, room)` group, ordered by ring key then id.
    groups: BTreeMap<(u8, u64), BTreeSet<(u64, PeerId)>>,
}

impl LayeredTopology {
    /// A topology whose same-room rings hold at most `fanout` successors per
    /// node, and which accepts at most [`MAX_NODES`] nodes.
    ///
    /// `fanout` must be at least 1 and at most [`MAX_FANOUT`].
    pub fn new(fanout: u32) -> Result<Self> {
        Self::with_limits(fanout, MAX_NODES)
    }

    /// [`LayeredTopology::new`] with an explicit node cap.
    ///
    /// Mostly useful in tests and on memory-constrained nodes; the cap exists so
    /// that an unbounded membership feed cannot grow the maps without limit.
    pub fn with_limits(fanout: u32, max_nodes: usize) -> Result<Self> {
        if fanout == 0 {
            return Err(NauError::Validation(
                "fanout must be at least 1: a node with no neighbours is not in a topology".into(),
            ));
        }
        if fanout > MAX_FANOUT {
            return Err(NauError::Validation(format!(
                "fanout {fanout} exceeds the maximum of {MAX_FANOUT}"
            )));
        }
        if max_nodes == 0 {
            return Err(NauError::Validation("max_nodes must be at least 1".into()));
        }
        Ok(Self {
            fanout,
            max_nodes,
            nodes: BTreeMap::new(),
            groups: BTreeMap::new(),
        })
    }

    /// The configured fanout.
    pub fn fanout(&self) -> u32 {
        self.fanout
    }

    /// The configured node cap.
    pub fn max_nodes(&self) -> usize {
        self.max_nodes
    }

    /// Add a node.
    ///
    /// Deterministic and incremental: the level, the room and the resulting
    /// edges depend only on the id and on the set of ids, never on the order in
    /// which nodes joined. Joining an id that is already present is a no-op, so
    /// replaying a membership log is safe.
    pub fn join(&mut self, id: &PeerId) -> Result<()> {
        if self.nodes.contains_key(id) {
            return Ok(());
        }
        if self.nodes.len() >= self.max_nodes {
            return Err(NauError::Conflict(format!(
                "topology already holds the maximum of {} nodes",
                self.max_nodes
            )));
        }
        let entry = NodeEntry::derive(id);
        self.nodes.insert(id.clone(), entry);
        self.groups
            .entry(entry.group())
            .or_default()
            .insert((entry.key, id.clone()));
        Ok(())
    }

    /// Remove a node, or report that it was never present.
    pub fn leave(&mut self, id: &PeerId) -> Result<()> {
        let Some(entry) = self.nodes.remove(id) else {
            return Err(NauError::NotFound(format!(
                "node `{id}` is not in the topology"
            )));
        };
        let group = entry.group();
        if let Some(members) = self.groups.get_mut(&group) {
            members.remove(&(entry.key, id.clone()));
            if members.is_empty() {
                self.groups.remove(&group);
            }
        }
        Ok(())
    }

    /// Whether `id` has joined.
    pub fn contains(&self, id: &PeerId) -> bool {
        self.nodes.contains_key(id)
    }

    /// How many nodes have joined.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The level `1..=7` of a node.
    ///
    /// This is a pure function of the id: it is defined for any id, present or
    /// not. Use [`LayeredTopology::contains`] for membership.
    pub fn level_of(&self, id: &PeerId) -> u8 {
        NodeEntry::derive(id).level
    }

    /// The deterministic level-1 room bucket of a node (`0 .. ROOMS_AT_LEVEL_1`).
    ///
    /// Pure function of the id, independent of insertion order and of the current
    /// membership — the property upstream's `HashMap` iteration destroyed.
    pub fn room_of(&self, id: &PeerId) -> u64 {
        NodeEntry::derive(id).room
    }

    /// In-degree of a node: same-room predecessors **plus** the uplink.
    ///
    /// Returns `0` for an unknown node. upstream v2.5.6 fix: the uplink edge was
    /// omitted, so fan-in was under-reported and a node that is the sole relay for
    /// a whole child room looked idle.
    pub fn fanin_of(&self, id: &PeerId) -> u32 {
        let Some(entry) = self.nodes.get(id) else {
            return 0;
        };
        let mut fan_in = self.same_room_indegree(entry);
        // An uplink edge into this node can only come from its immediate
        // predecessor in the union below, and only if that node sits one level
        // lower — hence at most one such edge.
        if let Some(predecessor) = self.incoming_uplink_predecessor(entry) {
            if predecessor.level + 1 == entry.level {
                fan_in += 1;
            }
        }
        fan_in
    }

    /// The number of distinct undirected links in the topology.
    ///
    /// Counts each `{a, b}` pair once, whether it is a same-room ring edge or an
    /// uplink. `tests/topology.rs` measures the growth of this number rather than
    /// asserting a fixed threshold.
    pub fn logical_edges(&self) -> u64 {
        let mut edges: BTreeSet<(PeerId, PeerId)> = BTreeSet::new();
        for (id, entry) in &self.nodes {
            for successor in self.same_room_successors(entry) {
                edges.insert(ordered_pair(id, &successor));
            }
            if let Some(uplink) = self.uplink_of(entry) {
                edges.insert(ordered_pair(id, &uplink));
            }
        }
        edges.len() as u64
    }

    /// Real hop count between two nodes, derived from the room tree.
    ///
    /// The count is the number of tree levels from `from`'s room up to the rooms'
    /// lowest common ancestor plus the number from `to`'s room up to that same
    /// ancestor, plus the final hop into `to`. Nodes sharing a room are one hop
    /// apart; a node to itself is zero hops.
    ///
    /// Returns `None` when either node is unknown — upstream v2.5.6 fix: it
    /// returned `Some(7)` for every cross-room pair, a constant that made the
    /// "≤ 7 hops" documentation unfalsifiable.
    pub fn route_hops(&self, from: &PeerId, to: &PeerId) -> Option<u32> {
        let a = self.nodes.get(from)?;
        let b = self.nodes.get(to)?;
        if from == to {
            return Some(0);
        }
        let first_shared = a.level.max(b.level);
        // Lv7 holds exactly one room (`0`), so a common ancestor always exists and
        // the loop always terminates with a match.
        let mut lca = MAX_LEVEL;
        for level in first_shared..=MAX_LEVEL {
            if a.room_at(level) == b.room_at(level) {
                lca = level;
                break;
            }
        }
        Some(u32::from(lca - a.level) + u32::from(lca - b.level) + 1)
    }

    /// The same-room ring successors of a node, in ring order.
    fn same_room_successors(&self, entry: &NodeEntry) -> Vec<PeerId> {
        let Some(members) = self.groups.get(&entry.group()) else {
            return Vec::new();
        };
        let Some(self_key) = self.member_key(entry) else {
            return Vec::new();
        };
        let count = ((members.len() - 1) as u32).min(self.fanout) as usize;
        members
            .range((
                std::ops::Bound::Excluded(self_key.clone()),
                std::ops::Bound::Unbounded,
            ))
            .chain(members.iter())
            .filter(|candidate| **candidate != self_key)
            .take(count)
            .map(|(_, id)| id.clone())
            .collect()
    }

    /// The `(ring key, id)` pair under which a node is stored in its group.
    fn member_key(&self, entry: &NodeEntry) -> Option<(u64, PeerId)> {
        let members = self.groups.get(&entry.group())?;
        members
            .iter()
            .find(|(key, _)| *key == entry.key)
            .map(|(key, id)| (*key, id.clone()))
    }

    /// Same-room in-degree: exactly `min(fanout, group_size - 1)`.
    ///
    /// In a cyclic ring where every member links to its next `k` successors, each
    /// member is the successor of exactly its `k` predecessors.
    fn same_room_indegree(&self, entry: &NodeEntry) -> u32 {
        match self.groups.get(&entry.group()) {
            Some(members) if members.len() > 1 => ((members.len() - 1) as u32).min(self.fanout),
            _ => 0,
        }
    }

    /// The uplink target of a node: its immediate successor in the parent-room
    /// union, when that successor sits one level above it.
    ///
    /// For a node at level `L`, the union holds the members of its parent room
    /// (level `L + 1`) together with every node at level `L` in a child room of
    /// that parent room. A node only gains an uplink when the very next entry in
    /// that order is a parent-room member, which makes the relation injective:
    /// each node in a parent room has at most one immediate predecessor, so it
    /// receives at most one uplink.
    fn uplink_of(&self, entry: &NodeEntry) -> Option<PeerId> {
        let (parent_level, parent_room) = entry.parent_group()?;
        let self_key = self.member_key(entry)?;
        let mut best: Option<(u64, PeerId)> = None;
        for group in self.union_groups(entry.level, parent_level, parent_room) {
            let Some(members) = self.groups.get(&group) else {
                continue;
            };
            if let Some(candidate) = members
                .range((
                    std::ops::Bound::Excluded(self_key.clone()),
                    std::ops::Bound::Unbounded,
                ))
                .next()
            {
                if best.as_ref().is_none_or(|current| candidate < current) {
                    best = Some(candidate.clone());
                }
            }
        }
        let (_, id) = best?;
        // Only a node at the parent level can be an uplink target; anything else
        // is simply the next node in the merged ring, and no edge is created.
        if self.nodes.get(&id).map(|candidate| candidate.level) == Some(parent_level) {
            Some(id)
        } else {
            None
        }
    }

    /// The node one level below this one whose uplink points here, if any.
    ///
    /// This is the immediate predecessor of the node inside *its own* room's
    /// union (the node's room at its level, plus that room's child rooms one level
    /// down), which is exactly the union an uplinking child computes.
    fn incoming_uplink_predecessor(&self, entry: &NodeEntry) -> Option<NodeEntry> {
        if entry.level < 2 {
            // Level-1 nodes have no child rooms, so nothing can uplink to them.
            return None;
        }
        let parent_room = entry.room_at(entry.level);
        let self_key = self.member_key(entry)?;
        let mut best: Option<(u64, PeerId)> = None;
        for group in self.union_groups(entry.level - 1, entry.level, parent_room) {
            let Some(members) = self.groups.get(&group) else {
                continue;
            };
            if let Some(candidate) = members.range(..self_key.clone()).next_back() {
                if best.as_ref().is_none_or(|current| candidate > current) {
                    best = Some(candidate.clone());
                }
            }
        }
        let (_, id) = best?;
        self.nodes.get(&id).copied()
    }

    /// The `(level, room)` groups that make up a node's parent-room union: the
    /// parent room itself at `parent_level`, and every child room at
    /// `child_level`.
    fn union_groups(&self, child_level: u8, parent_level: u8, parent_room: u64) -> Vec<(u8, u64)> {
        let mut groups = vec![(parent_level, parent_room)];
        // The parent room's children are the rooms that shift into it.
        let child_room = parent_room << ROOM_BITS;
        let siblings = 1u64 << ROOM_BITS;
        for offset in 0..siblings {
            groups.push((child_level, child_room | offset));
        }
        groups
    }
}

/// Order a pair of ids canonically so an undirected edge is counted once.
fn ordered_pair(a: &PeerId, b: &PeerId) -> (PeerId, PeerId) {
    if a <= b {
        (a.clone(), b.clone())
    } else {
        (b.clone(), a.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(name: &str) -> PeerId {
        PeerId::parse(name).expect("valid id")
    }

    #[test]
    fn fanout_is_bounded_at_construction() {
        assert!(LayeredTopology::new(0).is_err());
        assert!(LayeredTopology::new(1).is_ok());
        assert!(LayeredTopology::new(MAX_FANOUT).is_ok());
        assert!(LayeredTopology::new(MAX_FANOUT + 1).is_err());
    }

    #[test]
    fn join_is_idempotent_and_leave_reports_unknown_nodes() {
        let mut topology = LayeredTopology::new(2).expect("new");
        let a = id("node-a");
        topology.join(&a).expect("join");
        topology.join(&a).expect("rejoin is a no-op");
        assert_eq!(topology.node_count(), 1);
        assert!(topology.contains(&a));
        topology.leave(&a).expect("leave");
        assert_eq!(topology.node_count(), 0);
        assert!(matches!(
            topology.leave(&a).expect_err("unknown"),
            NauError::NotFound(_)
        ));
        assert!(!topology.contains(&a));
        assert_eq!(topology.fanin_of(&a), 0);
        assert_eq!(topology.route_hops(&a, &a), None);
    }

    #[test]
    fn level_and_room_are_pure_functions_of_the_id() {
        let topology = LayeredTopology::new(4).expect("new");
        let a = id("node-a");
        let level = topology.level_of(&a);
        assert!((1..=MAX_LEVEL).contains(&level));
        assert_eq!(
            level,
            topology.level_of(&a),
            "must not depend on call order"
        );
        assert_eq!(topology.room_of(&a), topology.room_of(&a));
        assert!(topology.room_of(&a) < ROOMS_AT_LEVEL_1);

        // A different membership must not change either value.
        let mut other = LayeredTopology::new(4).expect("new");
        for i in 0..50 {
            other.join(&id(&format!("filler-{i}"))).expect("join");
        }
        assert_eq!(other.level_of(&a), level);
        assert_eq!(other.room_of(&a), topology.room_of(&a));
    }

    #[test]
    fn consecutive_room_shifts_reach_a_single_root_room() {
        let a = id("node-a");
        let entry = NodeEntry::derive(&a);
        for level in entry.level..=MAX_LEVEL {
            assert!(entry.room_at(level) < ROOMS_AT_LEVEL_1);
        }
        assert_eq!(
            entry.room_at(MAX_LEVEL),
            0,
            "Lv7 must be the single root room, or two nodes could have no common ancestor"
        );

        // A node's own level is hash-derived, so `entry` is not necessarily the
        // root. What must hold is the structural property: every level below the
        // root has exactly one parent one level up, and the root has none.
        if entry.level < MAX_LEVEL {
            let (parent_level, parent_room) = entry
                .parent_group()
                .expect("a node below the root must uplink to a parent group");
            assert_eq!(parent_level, entry.level + 1);
            assert_eq!(
                parent_room,
                entry.room_at(entry.level + 1),
                "the parent room is this node's room shifted up one level"
            );
            // The uplink chain narrows monotonically and terminates at the root.
            let mut cursor = NodeEntry {
                level: entry.level,
                ..entry
            };
            let mut current_room = cursor.room_at(cursor.level);
            while let Some((next_level, next_room)) = cursor.parent_group() {
                assert!(
                    next_room <= current_room,
                    "each shift must not widen the room: {next_room} > {current_room}"
                );
                cursor.level = next_level;
                current_room = next_room;
            }
            assert_eq!(cursor.level, MAX_LEVEL, "the chain must end at Lv7");
            assert_eq!(current_room, 0, "the root room is 0");
        } else {
            assert_eq!(entry.level, MAX_LEVEL);
        }
        assert_eq!(
            NodeEntry {
                level: MAX_LEVEL,
                ..entry
            }
            .parent_group(),
            None,
            "the root level has no parent group"
        );
    }
}
