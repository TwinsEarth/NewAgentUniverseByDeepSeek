//! Bounded-memory tests: real LRU (not LFU), capacity enforcement, integer-only
//! ordering.
//!
//! upstream v2.5.6 fix: `EnhancedMemory::write` evicted
//! `min_by_key(|(_, v)| v.access_count)` — a monotonic counter, i.e. **LFU** —
//! while its own comment claimed "LRU：淘汰 access_count 最小的". The test
//! `a_recently_used_entry_survives_and_a_heavily_used_old_one_is_evicted` below
//! fails under that rule, and
//! `the_upstream_lfu_rule_would_evict_the_wrong_entry` demonstrates the
//! difference explicitly so the fix cannot regress unnoticed.

use nau_agent::{AgentMemory, MemoryRecord, MAX_QUALITY_BPS};
use nau_core::NauError;

fn record(key: &str, quality: u16, at: u64) -> MemoryRecord {
    MemoryRecord::new(key, format!("payload for {key}"), quality, at)
}

#[test]
fn a_recently_used_entry_survives_and_a_heavily_used_old_one_is_evicted() {
    let mut memory = AgentMemory::new(2);

    // `old` is used 50 times, but long ago.
    let mut old = record("old", 9_000, 1_000);
    old.uses = 50;
    memory.remember(old).unwrap();
    // `recent` is used exactly once, but right now.
    let mut recent = record("recent", 9_000, 9_000);
    recent.uses = 1;
    memory.remember(recent).unwrap();

    assert_eq!(memory.len(), 2);
    // A third entry forces one eviction.
    memory.remember(record("incoming", 5_000, 10_000)).unwrap();
    assert_eq!(memory.len(), 2, "capacity must hold");

    assert!(
        memory.recall_exact("recent").is_some(),
        "the least-recently-used entry is the one used long ago, not the one used least"
    );
    assert!(
        memory.recall_exact("old").is_none(),
        "an entry used many times long ago is still the least recently used"
    );
    assert!(memory.recall_exact("incoming").is_some());
}

#[test]
fn the_upstream_lfu_rule_would_evict_the_wrong_entry() {
    // Model upstream's rule (minimum `access_count`) on the same input, and show
    // it disagrees with LRU. If this assertion ever flips, the upstream defect
    // stopped being a defect and the fix needs re-deriving.
    let records = [("old", 1_000u64, 50u64), ("recent", 9_000, 1)];
    let lfu_victim = records
        .iter()
        .min_by_key(|(_, _, access_count)| *access_count)
        .map(|(key, _, _)| *key);
    let lru_victim = records
        .iter()
        .min_by_key(|(_, last_used, uses)| (*last_used, *uses))
        .map(|(key, _, _)| *key);
    assert_eq!(
        lfu_victim,
        Some("recent"),
        "upstream's rule evicts the fresh entry"
    );
    assert_eq!(
        lru_victim,
        Some("old"),
        "the fixed rule evicts the stale entry"
    );
    assert_ne!(
        lfu_victim, lru_victim,
        "LRU and LFU must actually differ here"
    );
}

#[test]
fn eviction_uses_the_touch_timestamp_not_the_use_count() {
    let mut memory = AgentMemory::new(2);
    memory.remember(record("a", 5_000, 0)).unwrap();
    memory.remember(record("b", 5_000, 0)).unwrap();

    // Touch `a` far in the future, then `b` only slightly.
    assert!(memory.touch("a", 5_000));
    assert!(memory.touch("b", 100));
    // `a` also accumulates more uses, which must not make it the victim.
    assert!(memory.touch("a", 5_001));
    assert!(
        !memory.touch("missing", 5_002),
        "touching an unknown key reports false"
    );

    memory.remember(record("c", 5_000, 5_002)).unwrap();
    assert!(
        memory.recall_exact("a").is_some(),
        "a is the most recently used"
    );
    assert!(
        memory.recall_exact("b").is_none(),
        "b is the least recently used"
    );
}

#[test]
fn identical_stamps_fall_back_to_the_use_count_then_the_key() {
    let mut memory = AgentMemory::new(2);
    memory.remember(record("zebra", 5_000, 42)).unwrap();
    memory.remember(record("apple", 5_000, 42)).unwrap();
    // Same `last_used`; `apple` has never been touched, `zebra` has.
    assert!(memory.touch("zebra", 42));
    memory.remember(record("mango", 5_000, 43)).unwrap();
    assert!(memory.recall_exact("zebra").is_some());
    assert!(memory.recall_exact("apple").is_none());
}

#[test]
fn inserting_ten_times_the_capacity_keeps_len_within_the_bound() {
    for capacity in [1usize, 2, 5, 17, 100] {
        let mut memory = AgentMemory::new(capacity);
        assert_eq!(memory.capacity(), capacity.max(1));
        for index in 0..(capacity * 10) {
            memory
                .remember(record(&format!("key-{index}"), 5_000, index as u64))
                .unwrap();
            assert!(
                memory.len() <= capacity,
                "capacity {capacity} exceeded at insertion {index}: len={}",
                memory.len()
            );
        }
        assert_eq!(memory.len(), capacity);
        // The `capacity` most recently stamped entries are the survivors.
        let total = capacity * 10;
        for index in (total - capacity)..total {
            assert!(
                memory.recall_exact(&format!("key-{index}")).is_some(),
                "the newest entries must survive"
            );
        }
    }
}

#[test]
fn zero_capacity_is_clamped_to_one_rather_than_losing_every_write() {
    let mut memory = AgentMemory::new(0);
    assert_eq!(memory.capacity(), 1);
    memory.remember(record("only", 5_000, 1)).unwrap();
    assert_eq!(memory.len(), 1);
    memory.remember(record("next", 5_000, 2)).unwrap();
    assert_eq!(memory.len(), 1);
    assert!(memory.recall_exact("next").is_some());
}

#[test]
fn re_remembering_a_key_updates_in_place_and_accumulates_uses() {
    let mut memory = AgentMemory::new(3);
    let mut first = record("k", 1_000, 10);
    first.uses = 4;
    memory.remember(first).unwrap();

    let mut second = record("k", 9_000, 20);
    second.tags = vec!["updated".into()];
    second.uses = 6;
    memory.remember(second).unwrap();

    assert_eq!(
        memory.len(),
        1,
        "the same key must not consume a second slot"
    );
    let stored = memory.recall_exact("k").expect("record is present");
    assert_eq!(stored.quality_bps, 9_000);
    assert_eq!(stored.uses, 10, "uses accumulate across writes");
    assert_eq!(stored.last_used, 20);
    assert_eq!(stored.tags, vec!["updated".to_string()]);
}

#[test]
fn an_out_of_range_quality_is_rejected_not_clamped() {
    let mut memory = AgentMemory::new(4);
    let mut bad = record("bad", 0, 1);
    bad.quality_bps = MAX_QUALITY_BPS + 1;
    let err = memory.remember(bad).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert_eq!(memory.len(), 0);

    let err = memory.remember(record("  ", 5_000, 1)).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
}

#[test]
fn extreme_quality_values_never_panic() {
    // The upstream `partial_cmp(..).unwrap()` path panicked on `NaN`; the integer
    // path has no such value, and must survive the extremes of its own domain.
    let mut memory = AgentMemory::new(8);
    memory.remember(record("max", u16::MAX - 1, 1)).unwrap_err(); // over MAX_QUALITY_BPS
    memory.remember(record("zero", 0, 1)).unwrap();
    memory
        .remember(record("max-ok", MAX_QUALITY_BPS, 2))
        .unwrap();
    // `u16::MAX / 2` is 32767, which is itself above MAX_QUALITY_BPS and so is
    // rejected like `max` above; use the midpoint of the *valid* range instead.
    memory
        .remember(record("mid", MAX_QUALITY_BPS / 2, 3))
        .unwrap();
    memory
        .remember(record("over", MAX_QUALITY_BPS / 2 + 1, 4))
        .unwrap();

    let hits = memory.search("", 10);
    assert_eq!(hits.first().map(|r| r.key.as_str()), Some("max-ok"));
    // Ordering by quality then recency is total, so it is deterministic.
    let again = memory.search("", 10);
    let first: Vec<&str> = hits.iter().map(|r| r.key.as_str()).collect();
    let second: Vec<&str> = again.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(first, second, "search order must be deterministic");
}

#[test]
fn search_matches_tags_or_a_case_insensitive_substring() {
    let mut memory = AgentMemory::new(16);
    memory
        .remember(
            MemoryRecord::new("ocr-tess", "Tesseract OCR pipeline", 6_000, 1).with_tags(["ocr"]),
        )
        .unwrap();
    memory
        .remember(
            MemoryRecord::new("ocr-paddle", "PaddleOCR is faster", 9_000, 2).with_tags(["ocr"]),
        )
        .unwrap();
    memory
        .remember(MemoryRecord::new("asr", "Whisper transcription", 7_000, 3))
        .unwrap();

    let by_tag = memory.search("OCR", 10);
    assert_eq!(by_tag.len(), 2);
    assert_eq!(by_tag[0].key, "ocr-paddle", "higher quality first");
    assert_eq!(by_tag[1].key, "ocr-tess");

    let by_substring = memory.search("whisper", 10);
    assert_eq!(by_substring.len(), 1);
    assert_eq!(by_substring[0].key, "asr");

    assert_eq!(memory.search("nothing-matches-this", 10).len(), 0);
    assert_eq!(memory.search("", 1).len(), 1, "limit is applied");
    assert_eq!(memory.search("", 10).len(), 3, "an empty query matches all");
}

#[test]
fn search_orders_by_quality_then_recency_across_capacity() {
    let mut memory = AgentMemory::new(4);
    memory.remember(record("low-new", 1_000, 900)).unwrap();
    memory.remember(record("high-old", 9_000, 100)).unwrap();
    memory.remember(record("high-new", 9_000, 800)).unwrap();
    memory.remember(record("mid", 5_000, 500)).unwrap();

    let keys: Vec<&str> = memory
        .search("", 10)
        .iter()
        .map(|r| r.key.as_str())
        .collect();
    assert_eq!(keys, vec!["high-new", "high-old", "mid", "low-new"]);
}

#[test]
fn lru_eviction_keeps_the_store_bounded_under_a_long_mixed_workload() {
    let mut memory = AgentMemory::new(4);
    let mut clock = 0u64;
    for round in 0..200u64 {
        clock += 1;
        memory
            .remember(record(
                &format!("k{}", round % 7),
                (round % 10) as u16 * 1_000,
                clock,
            ))
            .unwrap();
        memory.touch(&format!("k{}", round % 7), clock);
        assert!(memory.len() <= 4, "len={} at round {round}", memory.len());
    }
    assert_eq!(memory.len(), 4);
    // Every survivor is individually retrievable and internally consistent.
    for stored in memory.records() {
        assert_eq!(
            memory.recall_exact(&stored.key).map(|r| r.key.as_str()),
            Some(stored.key.as_str())
        );
        assert!(stored.quality_bps <= MAX_QUALITY_BPS);
    }
}
