//! Relay pool behaviour: enforced capacity, monotone health, duplicate-probe
//! refusal and deterministic selection order.
//!
//! Each test names the upstream v2.5.6 defect it pins down. The selection test
//! asserts the specified *policy* (class priority, then failure count, then id)
//! and additionally re-derives the expected ordering from the nodes themselves,
//! so it cannot pass by agreeing with a hardcoded list that the implementation
//! happens to produce.

use nau_core::NauError;
use nau_net::{PeerId, RelayClass, RelayNode, RelayPool};

fn id(name: &str) -> PeerId {
    PeerId::parse(name).expect("valid id")
}

fn relay(name: &str, class: RelayClass) -> RelayNode {
    RelayNode::new(id(name), format!("10.0.0.1:{}", name.len()), class)
}

/// upstream v2.5.6 defect: capacity was checked and then inserted in two steps,
/// and other insert paths skipped the check entirely.
#[test]
fn capacity_is_enforced_inside_the_inserting_call() {
    let mut pool = RelayPool::new(3);
    assert_eq!(pool.capacity(), 3);
    for name in ["relay-a", "relay-b", "relay-c"] {
        pool.add(relay(name, RelayClass::General)).expect("add");
    }
    assert_eq!(pool.len(), 3);
    assert!(!pool.is_empty());

    for extra in ["relay-d", "relay-e"] {
        let err = pool
            .add(relay(extra, RelayClass::Dedicated))
            .expect_err("the pool is full");
        assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
        assert_eq!(pool.len(), 3, "a refused add must leave the pool unchanged");
        assert!(pool.get(&id(extra)).is_none());
    }

    // Re-adding a known relay is not an insert: it must not be refused, and it
    // must not consume a second slot.
    pool.add(relay("relay-a", RelayClass::SelfHosted))
        .expect("update in place");
    assert_eq!(pool.len(), 3);
    assert_eq!(
        pool.get(&id("relay-a")).expect("present").class,
        RelayClass::SelfHosted
    );

    // Freeing a slot makes room again.
    pool.remove(&id("relay-b")).expect("remove");
    pool.add(relay("relay-d", RelayClass::Dedicated))
        .expect("add");

    // A zero-capacity pool accepts nothing at all.
    let mut closed = RelayPool::new(0);
    assert!(closed.is_empty());
    assert!(matches!(
        closed
            .add(relay("relay-a", RelayClass::General))
            .expect_err("full"),
        NauError::Conflict(_)
    ));

    // An empty address is refused rather than stored unreachable.
    let mut pool = RelayPool::new(4);
    let mut blank = relay("relay-a", RelayClass::General);
    blank.addr = String::new();
    assert!(pool.add(blank).is_err());
    assert!(pool.remove(&id("never-added")).is_err());
}

/// upstream v2.5.6 defect: `upsert_relay` reset `healthy`/`fail_count`, so
/// re-announcing a dead relay resurrected it.
#[test]
fn re_adding_never_resets_health_or_failure_statistics() {
    let mut pool = RelayPool::new(4);
    let node = id("relay-a");
    pool.add(relay("relay-a", RelayClass::General))
        .expect("add");
    assert!(pool.get(&node).expect("present").healthy);
    assert_eq!(pool.get(&node).expect("present").fail_count, 0);
    assert_eq!(pool.get(&node).expect("present").last_check, None);

    pool.record_failure(&node, 5_000).expect("failure");
    pool.record_failure(&node, 5_060).expect("failure");
    pool.record_failure(&node, 5_120).expect("failure");
    let failed = pool.get(&node).expect("present");
    assert!(!failed.healthy);
    assert_eq!(failed.fail_count, 3);
    assert_eq!(failed.last_check, Some(5_120));
    assert!(!pool.healthy().iter().any(|node| node.id == id("relay-a")));

    // The upstream resurrection: a fresh node struct claiming perfect health.
    let mut resurrect = relay("relay-a", RelayClass::Dedicated);
    resurrect.healthy = true;
    resurrect.fail_count = 0;
    resurrect.last_check = None;
    pool.add(resurrect).expect("re-add");

    let after = pool.get(&node).expect("present");
    assert!(!after.healthy, "health may only change via record_*");
    assert_eq!(
        after.fail_count, 3,
        "statistics may only change via record_*"
    );
    assert_eq!(after.last_check, Some(5_120));
    assert_eq!(
        after.class,
        RelayClass::Dedicated,
        "the class is not health"
    );
    assert!(after.addr.ends_with(":7"));

    // Only an explicit success clears the failure streak.
    pool.record_success(&node, 6_000).expect("success");
    let healthy = pool.get(&node).expect("present");
    assert!(healthy.healthy);
    assert_eq!(healthy.fail_count, 0);
    assert_eq!(healthy.last_check, Some(6_000));

    // Unknown relays are reported, not invented.
    assert!(matches!(
        pool.record_failure(&id("ghost"), 1).expect_err("unknown"),
        NauError::NotFound(_)
    ));
    assert!(matches!(
        pool.record_success(&id("ghost"), 1).expect_err("unknown"),
        NauError::NotFound(_)
    ));
}

/// upstream v2.5.6 defect: probing the same `PeerId` twice overwrote the pending
/// entry, so a stale outcome was applied to the live probe.
#[test]
fn a_duplicate_probe_is_refused_and_never_evicts_the_pending_one() {
    let mut pool = RelayPool::new(2);
    let node = id("relay-a");
    pool.add(relay("relay-a", RelayClass::General))
        .expect("add");

    let first = pool.begin_probe(&node, 1_000).expect("first probe");
    assert_eq!(pool.pending_probe_count(), 1);
    let pending = pool.pending_probe(&node).expect("pending");
    assert_eq!(pending.token, first);
    assert_eq!(pending.started_at, 1_000);

    let err = pool.begin_probe(&node, 2_000).expect_err("duplicate probe");
    assert!(matches!(err, NauError::Conflict(_)), "got {err:?}");
    let still = pool.pending_probe(&node).expect("the first probe survives");
    assert_eq!(still.token, first, "the pending token must not be replaced");
    assert_eq!(still.started_at, 1_000);
    assert_eq!(pool.pending_probe_count(), 1);

    // A result from a probe that is not the pending one is refused.
    assert!(pool.end_probe(&node, first + 7).is_err());
    assert!(pool.pending_probe(&node).is_some());

    let concluded = pool.end_probe(&node, first).expect("the matching token");
    assert_eq!(concluded.token, first);
    assert!(pool.pending_probe(&node).is_none());
    assert!(pool.end_probe(&node, first).is_err(), "already concluded");

    // Probes for two different relays are independent, and tokens are unique.
    pool.add(relay("relay-b", RelayClass::General))
        .expect("add");
    let a = pool.begin_probe(&node, 3_000).expect("probe a");
    let b = pool.begin_probe(&id("relay-b"), 3_000).expect("probe b");
    assert_ne!(a, b);
    assert_eq!(pool.pending_probe_count(), 2);

    // Removing a relay drops its pending probe with it.
    pool.remove(&node).expect("remove");
    assert_eq!(pool.pending_probe_count(), 1);
    assert!(pool.pending_probe(&node).is_none());
    assert!(pool.end_probe(&node, a).is_err());
    assert!(pool.begin_probe(&id("never-added"), 1).is_err());
}

/// The specified policy: `Dedicated > SelfHosted > ThirdParty > General`, then
/// `fail_count`, then id — total, so selection is reproducible.
#[test]
fn selection_is_deterministic_class_then_failures_then_id() {
    let mut pool = RelayPool::new(32);
    // Deliberately inserted in an order that is neither the priority order nor
    // the id order.
    let plan = [
        ("relay-e", RelayClass::General, 0u32),
        ("relay-b", RelayClass::SelfHosted, 2),
        ("relay-d", RelayClass::ThirdParty, 0),
        ("relay-a", RelayClass::Dedicated, 1),
        ("relay-c", RelayClass::SelfHosted, 0),
        ("relay-f", RelayClass::Dedicated, 0),
    ];
    for (name, class, failures) in plan {
        // Preset the failure count directly rather than calling `record_failure`:
        // recording a failure also marks the relay **unhealthy**, and `select` only
        // returns healthy relays — which the companion test below asserts. What is
        // under test here is the ordering policy: class, then `fail_count`, then id.
        let mut node = relay(name, class);
        node.fail_count = failures;
        pool.add(node).expect("add");
    }

    let selected = pool.select(pool.len());
    assert_eq!(selected.len(), plan.len());
    let order: Vec<&str> = selected.iter().map(|node| node.id.as_str()).collect();
    assert_eq!(
        order,
        vec![
            "relay-f", // Dedicated, 0 failures
            "relay-a", // Dedicated, 1 failure
            "relay-c", // SelfHosted, 0 failures
            "relay-b", // SelfHosted, 2 failures
            "relay-d", // ThirdParty
            "relay-e", // General
        ]
    );

    // Re-derive the ordering from the nodes: the reported sequence must be
    // non-decreasing in (priority, fail_count, id) and must contain every healthy
    // relay exactly once.
    let mut previous: Option<(u8, u32, &str)> = None;
    for node in &selected {
        let key = (node.class.priority(), node.fail_count, node.id.as_str());
        if let Some(previous) = previous {
            assert!(
                previous <= key,
                "selection order broke at {previous:?} -> {key:?}"
            );
        }
        previous = Some(key);
    }
    let expected: Vec<PeerId> = selected.iter().map(|node| node.id.clone()).collect();
    let mut sorted_ids = expected.clone();
    sorted_ids.sort();
    let mut healthy_ids: Vec<PeerId> = pool.healthy().iter().map(|node| node.id.clone()).collect();
    healthy_ids.sort();
    assert_eq!(
        sorted_ids, healthy_ids,
        "selection must be a permutation of the healthy set"
    );

    // Truncation returns the best `count`, not an arbitrary subset.
    let best_two = pool.select(2);
    assert_eq!(
        best_two
            .iter()
            .map(|node| node.id.as_str())
            .collect::<Vec<_>>(),
        vec!["relay-f", "relay-a"]
    );
    assert!(pool.select(0).is_empty());

    // An unhealthy relay leaves the candidate set but keeps its slot.
    pool.record_failure(&id("relay-f"), 9_000).expect("fail");
    let after = pool.select(pool.len());
    assert!(!after.iter().any(|node| node.id == id("relay-f")));
    assert_eq!(
        pool.len(),
        plan.len(),
        "a failed relay still occupies its slot"
    );
    assert_eq!(pool.healthy().len(), plan.len() - 1);
    assert_eq!(
        pool.healthy()
            .iter()
            .map(|n| n.id.as_str())
            .collect::<Vec<_>>(),
        pool.select(pool.len())
            .iter()
            .map(|n| n.id.as_str())
            .collect::<Vec<_>>(),
        "healthy() and select() must agree on order"
    );
    assert_eq!(pool.capacity(), 32);

    // Selection is stable across repeated calls.
    for _ in 0..3 {
        assert_eq!(
            pool.select(3)
                .iter()
                .map(|n| n.id.clone())
                .collect::<Vec<_>>(),
            pool.select(3)
                .iter()
                .map(|n| n.id.clone())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn classes_have_a_stable_priority_and_label() {
    let classes = [
        (RelayClass::Dedicated, 0u8),
        (RelayClass::SelfHosted, 1),
        (RelayClass::ThirdParty, 2),
        (RelayClass::General, 3),
    ];
    for (class, priority) in classes {
        assert_eq!(class.priority(), priority);
        assert!(!class.label().is_empty());
    }
    assert!(RelayClass::Dedicated.priority() < RelayClass::SelfHosted.priority());
    assert!(RelayClass::SelfHosted.priority() < RelayClass::ThirdParty.priority());
    assert!(RelayClass::ThirdParty.priority() < RelayClass::General.priority());
}
