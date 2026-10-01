//! Layered / cross-generation memory tests.
//!
//! upstream v2.5.6 fix: upstream's `LayeredMemory` only counted entries per
//! level and its `IntergenMemory` chain hashed with `DefaultHasher` while
//! discarding the payload. Here each tier is a real, independently verifiable
//! SHA-256 chain, and the generational head is an actual cross-generation
//! pointer.

use nau_agent::{HashChain, LayeredMemory, MemoryTier, DEFAULT_TIER_CAPACITY};
use nau_core::NauError;

#[test]
fn each_tier_keeps_its_own_chain() {
    let mut memory = LayeredMemory::new();
    assert!(memory.is_empty());
    assert_eq!(memory.generational_head(), None);

    memory
        .record(MemoryTier::Individual, "I learned to retry", 10)
        .unwrap();
    memory
        .record(MemoryTier::Individual, "I learned to cache", 20)
        .unwrap();
    memory
        .record(MemoryTier::Group, "the group agreed on retries", 30)
        .unwrap();
    memory
        .record(
            MemoryTier::Generational,
            "generation 1: always pin versions",
            40,
        )
        .unwrap();

    assert_eq!(memory.len(MemoryTier::Individual), 2);
    assert_eq!(memory.len(MemoryTier::Group), 1);
    assert_eq!(memory.len(MemoryTier::Generational), 1);
    assert!(!memory.is_empty());

    // Tiers are independent: each chain starts from genesis.
    for tier in MemoryTier::ALL {
        assert_eq!(
            memory.chain(tier).links()[0].prev_digest,
            nau_agent::GENESIS_DIGEST
        );
    }
    assert!(memory.verify_all().is_ok());
}

#[test]
fn the_generational_head_is_a_real_cross_generation_pointer() {
    let mut memory = LayeredMemory::new();
    memory.record(MemoryTier::Generational, "gen 1", 1).unwrap();
    let first = memory.generational_head().expect("a head exists");

    memory.record(MemoryTier::Generational, "gen 2", 2).unwrap();
    let second = memory.generational_head().expect("a head exists");
    assert_ne!(first, second, "the pointer must move as generations accrue");

    // The pointer names the exact head link, and it is a SHA-256 digest.
    let head = memory
        .chain(MemoryTier::Generational)
        .head()
        .expect("generational chain has a head");
    assert_eq!(second, head.digest);
    assert_eq!(second.len(), 64);

    // It is a real pointer: the link it names is present in the chain.
    assert_eq!(
        memory
            .chain(MemoryTier::Generational)
            .links()
            .last()
            .map(|l| &l.digest),
        Some(&second)
    );
}

#[test]
fn verify_all_reports_the_broken_tier_and_index() {
    let mut memory = LayeredMemory::new();
    memory.record(MemoryTier::Individual, "one", 1).unwrap();
    memory.record(MemoryTier::Individual, "two", 2).unwrap();
    memory.record(MemoryTier::Group, "shared", 3).unwrap();
    memory
        .record(MemoryTier::Generational, "heritage", 4)
        .unwrap();
    assert!(memory.verify_all().is_ok());

    // Tamper with the group tier, through the serialized form (an attacker
    // editing the stored audit trail).
    let mut stored: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&memory).expect("serializes")).expect("parses");
    let tiers = stored
        .get_mut("chains")
        .and_then(|value| value.as_array_mut())
        .expect("chains is an array of three tiers");
    assert_eq!(tiers.len(), 3);
    let group = tiers
        .get_mut(MemoryTier::Group.index())
        .and_then(|value| value.get_mut("links"))
        .and_then(|value| value.as_array_mut())
        .expect("the group tier has links");
    group[0]["payload"] = serde_json::Value::String("forged group memory".into());

    let tampered: LayeredMemory = serde_json::from_value(stored).expect("deserializes");
    let err = tampered.verify_all().unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    let message = err.to_string();
    assert!(
        message.contains("group"),
        "the tier must be named: {message}"
    );
    assert!(
        message.contains("index 1"),
        "the index must be named: {message}"
    );
}

#[test]
fn an_empty_payload_is_refused() {
    let mut memory = LayeredMemory::new();
    for bad in ["", "   ", "\t\n"] {
        let err = memory.record(MemoryTier::Individual, bad, 1).unwrap_err();
        assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    }
    assert!(memory.is_empty());
}

#[test]
fn each_tier_is_bounded_and_says_so_instead_of_forgetting() {
    // upstream v2.5.6 fix: upstream had no bound at all, so the audit trail grew
    // without limit. The bound must be enforced, and hitting it must be an
    // explicit error rather than a silent drop of the oldest link.
    let mut memory = LayeredMemory::new().with_tier_capacity(3);
    assert_eq!(memory.tier_capacity(), 3);
    for index in 0..3u64 {
        memory
            .record(
                MemoryTier::Generational,
                &format!("generation {index}"),
                index,
            )
            .unwrap();
    }
    let err = memory
        .record(MemoryTier::Generational, "generation 3", 3)
        .unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert!(
        err.to_string().contains("full"),
        "a full tier must say it is full: {err}"
    );
    assert_eq!(memory.len(MemoryTier::Generational), 3);
    // Other tiers are unaffected by one tier being full.
    assert!(memory
        .record(MemoryTier::Group, "still room here", 3)
        .is_ok());
    assert!(memory.verify_all().is_ok());
}

#[test]
fn inserting_ten_times_the_tier_capacity_keeps_len_within_the_bound() {
    let capacity = 5usize;
    let mut memory = LayeredMemory::new().with_tier_capacity(capacity);
    let mut accepted = 0usize;
    for index in 0..(capacity * 10) {
        if memory
            .record(
                MemoryTier::Individual,
                &format!("entry {index}"),
                index as u64,
            )
            .is_ok()
        {
            accepted += 1;
        }
        assert!(memory.len(MemoryTier::Individual) <= capacity);
    }
    assert_eq!(accepted, capacity, "exactly capacity entries are accepted");
    assert_eq!(memory.len(MemoryTier::Individual), capacity);
}

#[test]
fn zero_tier_capacity_is_clamped_rather_than_losing_every_write() {
    let mut memory = LayeredMemory::new().with_tier_capacity(0);
    assert_eq!(memory.tier_capacity(), 1);
    assert!(memory.record(MemoryTier::Group, "only one", 1).is_ok());
    assert!(memory.record(MemoryTier::Group, "too many", 2).is_err());
}

#[test]
fn time_may_not_run_backwards_within_a_tier() {
    let mut memory = LayeredMemory::new();
    memory.record(MemoryTier::Individual, "first", 100).unwrap();
    assert!(memory.record(MemoryTier::Individual, "second", 99).is_err());
    assert!(memory.record(MemoryTier::Individual, "second", 100).is_ok());
    assert!(memory.verify_all().is_ok());
}

#[test]
fn tier_metadata_is_total_and_stable() {
    assert_eq!(MemoryTier::ALL.len(), 3);
    assert_eq!(MemoryTier::Individual.index(), 0);
    assert_eq!(MemoryTier::Group.index(), 1);
    assert_eq!(MemoryTier::Generational.index(), 2);
    assert_eq!(MemoryTier::Individual.label(), "individual");
    assert_eq!(MemoryTier::Group.label(), "group");
    assert_eq!(MemoryTier::Generational.label(), "generational");
    // The enum is ordered from narrowest to widest.
    assert!(MemoryTier::Individual < MemoryTier::Group);
    assert!(MemoryTier::Group < MemoryTier::Generational);
    // Checked at compile time: a runtime assertion on a constant is vacuous.
    const _: () = assert!(DEFAULT_TIER_CAPACITY > 0);

    // Every tier serializes to a stable snake_case label.
    for tier in MemoryTier::ALL {
        let encoded = serde_json::to_string(&tier).expect("serializes");
        assert_eq!(encoded, format!("\"{}\"", tier.label()));
    }
}

#[test]
fn a_generational_chain_can_be_read_back_and_re_verified() {
    let mut memory = LayeredMemory::new();
    for index in 1..=5u64 {
        memory
            .record(
                MemoryTier::Generational,
                &format!("generation {index} lesson"),
                index,
            )
            .unwrap();
    }
    let encoded = serde_json::to_string(&memory).expect("serializes");
    let decoded: LayeredMemory = serde_json::from_str(&encoded).expect("deserializes");
    assert_eq!(decoded, memory);
    assert!(decoded.verify_all().is_ok());
    assert_eq!(decoded.generational_head(), memory.generational_head());
    assert_eq!(decoded.len(MemoryTier::Generational), 5);

    // The tier chain is a `HashChain`, so the single-chain verifier works too.
    let chain: &HashChain = memory.chain(MemoryTier::Generational);
    assert!(chain.verify_chain().is_ok());
    assert_eq!(chain.len(), 5);
}
