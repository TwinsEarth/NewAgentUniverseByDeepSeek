//! Topology invariants.
//!
//! Every assertion here is about *behaviour that must hold for any correct
//! implementation*, not about a constant the implementation also hardcodes.
//! Hop counts and fan-in are recomputed independently from the public
//! primitives ([`ring_key`], [`LayeredTopology::level_of`],
//! [`LayeredTopology::room_of`]) and compared with what the topology reports;
//! edge growth is *measured* rather than compared with a fixed threshold.

use std::collections::{BTreeMap, BTreeSet};

use nau_core::NauError;
use nau_net::topology::{ring_key, MAX_FANOUT, MAX_LEVEL, ROOMS_AT_LEVEL_1, ROOM_BITS};
use nau_net::{LayeredTopology, PeerId};

fn id(name: &str) -> PeerId {
    PeerId::parse(name).expect("valid id")
}

/// A deterministic set of distinct peer ids.
fn ids(count: usize) -> Vec<PeerId> {
    (0..count).map(|i| id(&format!("node-{i:06}"))).collect()
}

/// Ids from a disjoint namespace, for nodes that must not be members of the
/// topology built from [`ids`].
fn probe_ids(count: usize) -> Vec<PeerId> {
    (0..count).map(|i| id(&format!("probe-{i:06}"))).collect()
}

/// Deterministic permutations of `0..count` (never a dependency on hash order).
fn permutation(count: usize, stride: usize) -> Vec<usize> {
    let mut order: Vec<usize> = Vec::with_capacity(count);
    let mut seen = vec![false; count];
    let mut cursor = 0usize;
    for _ in 0..count {
        while seen[cursor] {
            cursor = (cursor + 1) % count;
        }
        seen[cursor] = true;
        order.push(cursor);
        cursor = (cursor + stride) % count;
    }
    order
}

fn build(fanout: u32, ids: &[PeerId], order: &[usize]) -> LayeredTopology {
    let mut topology = LayeredTopology::new(fanout).expect("fanout is valid");
    for index in order {
        topology.join(&ids[*index]).expect("join");
    }
    topology
}

/// The room a node occupies at `level`, derived only from the public API.
fn room_at(topology: &LayeredTopology, node: &PeerId, level: u8) -> u64 {
    topology.room_of(node) >> (ROOM_BITS * u32::from(level - 1))
}

/// An independent fan-in reference: same-room predecessors plus the uplink.
fn reference_fanin(
    topology: &LayeredTopology,
    nodes: &[PeerId],
    fanout: u32,
) -> BTreeMap<PeerId, u32> {
    // Group members per (level, room), ordered by ring key then id.
    let mut groups: BTreeMap<(u8, u64), BTreeSet<(u64, PeerId)>> = BTreeMap::new();
    for node in nodes {
        let level = topology.level_of(node);
        groups
            .entry((level, room_at(topology, node, level)))
            .or_default()
            .insert((ring_key(node), node.clone()));
    }

    let mut fanin: BTreeMap<PeerId, u32> = BTreeMap::new();
    for node in nodes {
        let level = topology.level_of(node);
        let key = (ring_key(node), node.clone());
        // Same-room predecessors: every member within `fanout` places before it.
        let same_room = groups
            .get(&(level, room_at(topology, node, level)))
            .map(|members| ((members.len() - 1) as u32).min(fanout))
            .unwrap_or(0);
        let mut total = same_room;

        if level >= 2 {
            // The union an uplinking child computes: this node's room at its own
            // level, plus that room's child rooms one level down.
            let room = room_at(topology, node, level);
            let mut union: BTreeSet<(u64, PeerId)> = BTreeSet::new();
            if let Some(members) = groups.get(&(level, room)) {
                union.extend(members.iter().cloned());
            }
            for offset in 0..(1u64 << ROOM_BITS) {
                if let Some(members) = groups.get(&(level - 1, (room << ROOM_BITS) | offset)) {
                    union.extend(members.iter().cloned());
                }
            }
            if let Some((_, predecessor)) = union.range(..key.clone()).next_back() {
                if topology.level_of(predecessor) + 1 == level {
                    total += 1;
                }
            }
        }
        fanin.insert(node.clone(), total);
    }
    fanin
}

/// upstream v2.5.6 defect: room assignment iterated a `HashMap`, so the topology
/// depended on insertion order and differed between runs.
#[test]
fn the_same_membership_in_two_orders_yields_the_same_topology() {
    const N: usize = 500;
    let nodes = ids(N);
    let forward: Vec<usize> = (0..N).collect();
    let shuffled = permutation(N, 137);

    let a = build(4, &nodes, &forward);
    let b = build(4, &nodes, &shuffled);
    assert_eq!(a.node_count(), N);
    assert_eq!(b.node_count(), N);
    assert_eq!(
        a.logical_edges(),
        b.logical_edges(),
        "edge count must not depend on order"
    );

    for node in &nodes {
        assert_eq!(
            a.room_of(node),
            b.room_of(node),
            "room assignment must be a pure function of the id"
        );
        assert_eq!(a.level_of(node), b.level_of(node));
        assert_eq!(
            a.fanin_of(node),
            b.fanin_of(node),
            "fan-in of {} must not depend on insertion order",
            node
        );
        assert!(a.room_of(node) < ROOMS_AT_LEVEL_1);
        assert!((1..=MAX_LEVEL).contains(&a.level_of(node)));
    }

    // Hop counts for a spread of pairs must be identical too.
    let mut distinct_hops = BTreeSet::new();
    for i in 0..N {
        for j in [1usize, 7, 53, 211] {
            let from = &nodes[i];
            let to = &nodes[(i * 3 + j) % N];
            assert_eq!(
                a.route_hops(from, to),
                b.route_hops(from, to),
                "hop count {from} -> {to} must not depend on insertion order"
            );
            if let Some(hops) = a.route_hops(from, to) {
                distinct_hops.insert(hops);
            }
        }
    }
    assert!(
        distinct_hops.len() >= 3,
        "hop counts must vary with the pair, saw {distinct_hops:?}"
    );
}

/// upstream v2.5.6 defect: `route_hops` returned the constant `Some(7)` for every
/// cross-room pair, and its test asserted the constant.
#[test]
fn hops_are_computed_from_the_room_tree_not_returned_as_a_constant() {
    const N: usize = 300;
    let nodes = ids(N);
    let topology = build(3, &nodes, &(0..N).collect::<Vec<_>>());

    let mut observed = BTreeSet::new();
    for i in 0..N {
        for j in 0..N {
            if i == j {
                continue;
            }
            let hops = topology
                .route_hops(&nodes[i], &nodes[j])
                .expect("both nodes are known");
            observed.insert(hops);
            // Symmetry is a property of a tree distance and of nothing else.
            assert_eq!(
                Some(hops),
                topology.route_hops(&nodes[j], &nodes[i]),
                "distance must be symmetric for {} / {}",
                nodes[i],
                nodes[j]
            );

            // Independent recomputation: the number of tree levels up from each
            // side to the deepest shared room, plus the final hop.
            let a = &nodes[i];
            let b = &nodes[j];
            let la = topology.level_of(a);
            let lb = topology.level_of(b);
            let mut lca = MAX_LEVEL;
            for level in la.max(lb)..=MAX_LEVEL {
                if room_at(&topology, a, level) == room_at(&topology, b, level) {
                    lca = level;
                    break;
                }
            }
            let expected = u32::from(lca - la) + u32::from(lca - lb) + 1;
            assert_eq!(hops, expected, "hop count for {a} -> {b}");
        }
    }
    assert!(
        observed.len() >= 3,
        "a real tree distance takes several values, saw {observed:?}"
    );
    assert!(
        *observed.iter().min().expect("non-empty") <= 2,
        "a nearby pair must be 1-2 hops, saw {observed:?}"
    );
    assert!(observed.contains(&1), "same-room pairs are one hop");

    // Unknown nodes are `None`; a node is zero hops from itself.
    let stranger = id("not-in-the-topology");
    assert_eq!(topology.route_hops(&stranger, &nodes[0]), None);
    assert_eq!(topology.route_hops(&nodes[0], &stranger), None);
    assert_eq!(topology.route_hops(&nodes[0], &nodes[0]), Some(0));

    // A pair that provably shares a room is exactly one hop, found by search
    // rather than by assuming which ids collide.
    let mut same_room_pair = None;
    let mut buckets: BTreeMap<(u8, u64), PeerId> = BTreeMap::new();
    for candidate in probe_ids(4_000) {
        let bucket = (
            topology.level_of(&candidate),
            room_at(&topology, &candidate, topology.level_of(&candidate)),
        );
        if let Some(previous) = buckets.get(&bucket) {
            same_room_pair = Some((previous.clone(), candidate.clone()));
            break;
        }
        buckets.insert(bucket, candidate);
    }
    let (first, second) = same_room_pair.expect("a collision must exist among 4000 ids");
    assert_eq!(
        topology.route_hops(&first, &second),
        None,
        "neither node has joined this topology"
    );
    let mut with_pair = build(3, &[first.clone(), second.clone()], &[0, 1]);
    assert_eq!(
        with_pair.route_hops(&first, &second),
        Some(1),
        "two nodes in one room are one hop apart"
    );
    with_pair.leave(&second).expect("leave");
    assert_eq!(with_pair.route_hops(&first, &second), None);
}

/// upstream v2.5.6 defect: the "sub-quadratic edges" test used a threshold that
/// could never fail. Here the growth is measured at N and 2N.
#[test]
fn edge_growth_is_sub_quadratic_when_measured() {
    const N: usize = 2_000;
    let nodes = ids(2 * N);
    let order_small = permutation(N, 911);
    let order_large = permutation(2 * N, 911);

    let small = build(4, &nodes[..N], &order_small);
    let large = build(4, &nodes[..2 * N], &order_large);

    let edges_small = small.logical_edges();
    let edges_large = large.logical_edges();
    assert!(edges_small > 0, "a real topology has edges");
    assert!(edges_large > edges_small);

    // Doubling the membership must not more than double-plus-a-half the edges; a
    // quadratic structure would multiply them by about four.
    let ratio = edges_large as f64 / edges_small as f64;
    assert!(
        ratio < 2.5,
        "edges(2N)/edges(N) = {ratio} (={edges_large}/{edges_small}) must be sub-quadratic"
    );
    // And the absolute count is far below the quadratic bound.
    let quadratic = (2 * N) as u64 * (2 * N) as u64;
    assert!(edges_large < quadratic / 100);
    // A node's own degree is bounded by its uplink plus its ring successors.
    for node in &nodes[..2 * N] {
        assert!(large.fanin_of(node) <= large.fanout() + 1);
    }
}

/// upstream v2.5.6 defect: `fanin_of` left out the uplink edge, so fan-in was
/// under-reported; and the sub-quadratic test never checked the bound.
#[test]
fn fanin_counts_same_room_peers_plus_the_uplink_and_stays_bounded() {
    const N: usize = 600;
    let nodes = ids(N);
    let topology = build(4, &nodes, &permutation(N, 53));
    let reference = reference_fanin(&topology, &nodes, 4);

    let mut nodes_with_uplink = 0usize;
    for node in &nodes {
        let reported = topology.fanin_of(node);
        assert_eq!(
            reported, reference[node],
            "fan-in of {node} must equal same-room predecessors plus its uplink"
        );
        assert!(
            reported <= topology.fanout() + 1,
            "fan-in of {node} is {reported}, above fanout + 1"
        );

        // Same-room predecessors are exactly min(fanout, group_size - 1); a
        // reported value above that can only come from the uplink.
        let level = topology.level_of(node);
        let same_room_members = nodes
            .iter()
            .filter(|other| {
                topology.level_of(other) == level
                    && room_at(&topology, other, level) == room_at(&topology, node, level)
            })
            .count();
        let same_room = ((same_room_members - 1) as u32).min(topology.fanout());
        assert!(reported >= same_room);
        if reported > same_room {
            nodes_with_uplink += 1;
        }
    }
    assert!(
        nodes_with_uplink > 0,
        "the uplink must actually contribute to some node's fan-in, \
         otherwise this test would pass for the upstream implementation too"
    );

    // An id that never joined has no in-edges at all.
    assert_eq!(topology.fanin_of(&id("never-joined")), 0);
}

#[test]
fn membership_is_incremental_and_caps_are_enforced() {
    let mut topology = LayeredTopology::with_limits(2, 2).expect("valid limits");
    assert_eq!(topology.max_nodes(), 2);
    let a = id("node-a");
    let b = id("node-b");
    let c = id("node-c");
    topology.join(&a).expect("join");
    topology.join(&b).expect("join");
    let err = topology.join(&c).expect_err("cap reached");
    assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
    assert_eq!(topology.node_count(), 2);
    assert!(!topology.contains(&c));

    // Re-joining is a no-op, which is what makes a replayed join log safe.
    topology.join(&a).expect("rejoin");
    assert_eq!(topology.node_count(), 2);

    topology.leave(&a).expect("leave");
    assert!(matches!(
        topology.leave(&a).expect_err("already gone"),
        NauError::NotFound(_)
    ));
    topology.join(&c).expect("a slot is free again");
    assert!(topology.contains(&c));

    assert!(LayeredTopology::with_limits(0, 10).is_err());
    assert!(LayeredTopology::with_limits(MAX_FANOUT + 1, 10).is_err());
    assert!(LayeredTopology::with_limits(1, 0).is_err());

    // An empty topology answers queries without panicking.
    let empty = LayeredTopology::new(1).expect("new");
    assert_eq!(empty.node_count(), 0);
    assert_eq!(empty.logical_edges(), 0);
    assert_eq!(empty.fanin_of(&a), 0);
    assert_eq!(empty.route_hops(&a, &a), None);
    assert!(!empty.contains(&a));
    // Level and room are pure id functions even for non-members.
    assert!((1..=MAX_LEVEL).contains(&empty.level_of(&a)));
    assert!(empty.room_of(&a) < ROOMS_AT_LEVEL_1);
}
