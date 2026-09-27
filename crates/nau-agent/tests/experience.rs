//! Swarm-memory tests: anti-pollution must be enforced by the store.
//!
//! upstream v2.5.6 fix: `SwarmMemory::publish` accepted a caller-supplied
//! `weight: f64`, and `best_strategy()` picked `max_by(weight)`, so a publisher
//! could self-declare `weight = 1.0` and win. `EnhancedMemory::shareable()`,
//! which was supposed to gate publication, had no callers at all. Here the score
//! is derived from recorded outcomes and the store refuses anything below its
//! threshold.

use nau_agent::{Experience, SharedMemory, MAX_QUALITY_BPS, MIN_SHARED_OBSERVATIONS};
use nau_core::{Identity, NauError};

fn author(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn experience(identity: &Identity, key: &str, successes: u32, failures: u32) -> Experience {
    Experience {
        author: identity.did(),
        key: key.to_string(),
        payload: format!("strategy for {key}: {} successes", successes),
        successes,
        failures,
        submitted_at: 1_000,
    }
}

#[test]
fn a_low_quality_experience_from_its_own_author_is_rejected() {
    let mut shared = SharedMemory::new(6_000, 64);
    let poor = author(1);

    // Enough observations to be considered at all, but a bad record.
    let low = experience(&poor, "ocr", 1, 3);
    assert!(
        low.quality_bps() < 6_000,
        "the fixture must actually be low quality, got {}",
        low.quality_bps()
    );
    let err = shared.publish(low).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert_eq!(shared.len(), 0, "a rejected experience must not be stored");
    assert!(shared.best_for("ocr").is_none());
}

#[test]
fn a_high_quality_experience_is_accepted() {
    let mut shared = SharedMemory::new(6_000, 64);
    let good = author(2);

    let strong = experience(&good, "ocr", 40, 1);
    assert!(strong.quality_bps() >= 6_000);
    shared.publish(strong.clone()).unwrap();

    assert_eq!(shared.len(), 1);
    let best = shared
        .best_for("ocr")
        .expect("the accepted entry is retrievable");
    assert_eq!(best.author, good.did());
    assert_eq!(best.successes, 40);
    assert_eq!(best.failures, 1);
    assert_eq!(shared.accepted_from(&good.did()), 1);
}

#[test]
fn an_author_with_too_few_observations_cannot_publish() {
    let mut shared = SharedMemory::new(0, 64);
    let newcomer = author(3);

    // Even a perfect record is refused while the sample is too small: one lucky
    // success is not evidence.
    let one = experience(&newcomer, "ocr", 1, 0);
    let err = shared.publish(one).unwrap_err();
    assert!(
        matches!(err, NauError::Unauthorized(_)),
        "an unproven author is an authorization failure, got {err:?}"
    );
    assert_eq!(shared.len(), 0);

    // A zero-observation entry cannot publish either.
    let none = experience(&newcomer, "ocr", 0, 0);
    assert!(matches!(
        shared.publish(none).unwrap_err(),
        NauError::Unauthorized(_)
    ));

    // Once the observation count reaches the floor, a good record is accepted.
    // The floor's own invariant is checked at COMPILE time rather than with a
    // runtime assertion on a constant (which clippy rightly rejects as vacuous).
    const _: () = assert!(MIN_SHARED_OBSERVATIONS >= 2);
    let proven = experience(&newcomer, "ocr", MIN_SHARED_OBSERVATIONS, 0);
    shared.publish(proven).unwrap();
    assert_eq!(shared.len(), 1);
}

#[test]
fn a_publisher_cannot_inflate_its_own_entry_with_a_supplied_score() {
    // `Experience` has no weight/score/quality field, so the only place a
    // publisher could try to inject one is the free-text payload. Prove that the
    // store ignores it completely.
    let mut shared = SharedMemory::new(6_000, 64);
    let cheat = author(4);

    let mut inflated = experience(&cheat, "ocr", 1, 3);
    let honest_quality = inflated.quality_bps();
    inflated.payload = concat!(
        r#"{"weight":1.0,"score":1.0,"quality_bps":10000,"trusted":true}"#,
        " my strategy is definitely the best"
    )
    .to_string();

    assert_eq!(
        inflated.quality_bps(),
        honest_quality,
        "quality must be derived from outcomes, not from anything in the payload"
    );
    let err = shared.publish(inflated).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert_eq!(shared.len(), 0, "the inflated entry must not be stored");

    // A `NaN`-looking payload is likewise inert: there is no float to compare.
    let mut nan_like = experience(&cheat, "ocr", 1, 3);
    nan_like.payload = "NaN Infinity -0.0".to_string();
    assert_eq!(nan_like.quality_bps(), honest_quality);
    assert!(shared.publish(nan_like).is_err());
}

#[test]
fn quality_is_a_pure_function_of_the_recorded_outcomes() {
    let identity = author(5);
    let mut exp = experience(&identity, "k", 0, 0);
    let mut seen: Vec<(u32, u32, u16)> = Vec::new();
    for successes in 0..12u32 {
        for failures in 0..12u32 {
            exp.successes = successes;
            exp.failures = failures;
            let quality = exp.quality_bps();
            assert!(
                quality <= MAX_QUALITY_BPS,
                "quality {quality} out of range for {successes}/{failures}"
            );
            seen.push((successes, failures, quality));
        }
    }
    // Recomputing in a different order gives identical results.
    for (successes, failures, quality) in &seen {
        exp.successes = *successes;
        exp.failures = *failures;
        assert_eq!(exp.quality_bps(), *quality, "quality must be deterministic");
    }
    // A larger sample of the same proportion is trusted more.
    let small = {
        exp.successes = 2;
        exp.failures = 0;
        exp.quality_bps()
    };
    let large = {
        exp.successes = 200;
        exp.failures = 0;
        exp.quality_bps()
    };
    assert!(
        small < large,
        "Wilson must punish small samples: 2/0 -> {small}, 200/0 -> {large}"
    );
    // Observed counts drive the score.
    let mostly_good = {
        exp.successes = 900;
        exp.failures = 100;
        exp.quality_bps()
    };
    let mostly_bad = {
        exp.successes = 100;
        exp.failures = 900;
        exp.quality_bps()
    };
    assert!(mostly_good > mostly_bad);
}

#[test]
fn extreme_observation_counts_do_not_panic_or_overflow() {
    // The upstream `partial_cmp(..).unwrap()` on `f64` panicked on `NaN`, and
    // `successes + failures` overflowed in debug builds. Both are structurally
    // impossible now, and this exercises the boundary.
    let identity = author(6);
    let mut shared = SharedMemory::new(0, 8);
    for (successes, failures) in [
        (u32::MAX, u32::MAX),
        (u32::MAX, 0),
        (0, u32::MAX),
        (u32::MAX, 1),
        (1, u32::MAX),
    ] {
        let mut exp = experience(&identity, "extreme", successes, failures);
        let quality = exp.quality_bps();
        assert!(quality <= MAX_QUALITY_BPS);
        exp.submitted_at = successes as u64;
        if quality == 0 {
            assert!(shared.publish(exp).is_err());
        } else {
            // Either outcome is fine; what matters is that neither panics.
            let _ = shared.publish(exp);
        }
    }
    assert!(shared.len() <= shared.capacity());
}

#[test]
fn an_empty_key_or_payload_is_refused() {
    let mut shared = SharedMemory::new(0, 8);
    let identity = author(7);
    let mut no_key = experience(&identity, "ok", 10, 0);
    no_key.key = "   ".to_string();
    assert!(matches!(
        shared.publish(no_key).unwrap_err(),
        NauError::Validation(_)
    ));
    let mut no_payload = experience(&identity, "ok", 10, 0);
    no_payload.payload = String::new();
    assert!(matches!(
        shared.publish(no_payload).unwrap_err(),
        NauError::Validation(_)
    ));
}

#[test]
fn best_for_picks_the_highest_derived_quality_and_breaks_ties_deterministically() {
    let mut shared = SharedMemory::new(0, 64);
    let weak = author(8);
    let strong = author(9);
    let tied = author(10);

    shared.publish(experience(&weak, "ocr", 5, 5)).unwrap();
    shared.publish(experience(&strong, "ocr", 50, 1)).unwrap();
    shared.publish(experience(&tied, "ocr", 50, 1)).unwrap();

    let best = shared.best_for("ocr").expect("an entry exists");
    assert_eq!(
        best.quality_bps(),
        experience(&strong, "ocr", 50, 1).quality_bps(),
        "the highest derived quality wins"
    );
    assert!(
        best.quality_bps() > experience(&weak, "ocr", 5, 5).quality_bps(),
        "the weak entry must not win"
    );

    // `strong` and `tied` have identical outcomes, so the tie-break decides.
    // It must be stable and must pick the smallest author DID.
    let expected_tie_winner = [strong.did(), tied.did()].into_iter().min();
    assert_eq!(Some(best.author.clone()), expected_tie_winner);

    let first = shared.best_for("ocr").map(|e| e.author.clone());
    let second = shared.best_for("ocr").map(|e| e.author.clone());
    assert_eq!(first, second, "best_for must be deterministic");
    assert!(shared.best_for("no-such-key").is_none());
}

#[test]
fn republishing_replaces_rather_than_stacks() {
    let mut shared = SharedMemory::new(0, 64);
    let identity = author(11);
    shared.publish(experience(&identity, "ocr", 10, 1)).unwrap();
    assert_eq!(shared.total_entries(), 1);
    shared
        .publish(experience(&identity, "ocr", 100, 1))
        .unwrap();
    assert_eq!(
        shared.total_entries(),
        1,
        "one author holds one slot per key"
    );
    assert_eq!(shared.len(), 1);
    assert_eq!(shared.accepted_from(&identity.did()), 2);
    let best = shared.best_for("ocr").expect("entry exists");
    assert_eq!(best.successes, 100, "the newer record replaced the old one");
}

#[test]
fn inserting_ten_times_the_capacity_keeps_len_within_the_bound() {
    let capacity = 8usize;
    let mut shared = SharedMemory::new(0, capacity);
    assert_eq!(shared.capacity(), capacity);
    for index in 0..(capacity * 10) {
        // A distinct author per key, so each key consumes a slot.
        let identity = Identity::from_seed(&[(index % 250) as u8 + 1; 32]);
        let mut exp = experience(&identity, &format!("key-{index}"), 20, 1);
        exp.submitted_at = index as u64;
        shared.publish(exp).unwrap();
        assert!(
            shared.len() <= capacity,
            "capacity {capacity} exceeded: len={}",
            shared.len()
        );
        assert!(shared.total_entries() <= capacity);
    }
    assert_eq!(shared.len(), capacity);
}

#[test]
fn the_weakest_key_is_the_one_evicted() {
    let capacity = 2usize;
    let mut shared = SharedMemory::new(0, capacity);
    let strong = author(20);
    let weak = author(21);
    let medium = author(22);

    shared.publish(experience(&weak, "weak", 4, 4)).unwrap();
    shared
        .publish(experience(&strong, "strong", 90, 1))
        .unwrap();
    shared
        .publish(experience(&medium, "medium", 30, 2))
        .unwrap();

    assert_eq!(shared.len(), capacity);
    assert!(shared.best_for("strong").is_some());
    assert!(shared.best_for("medium").is_some());
    assert!(
        shared.best_for("weak").is_none(),
        "the lowest-quality key is the eviction victim"
    );
}

#[test]
fn a_threshold_above_the_maximum_rejects_everything_rather_than_crashing() {
    // A nonsensical configuration must fail closed, not panic.
    let mut shared = SharedMemory::new(u16::MAX, 4);
    assert_eq!(shared.min_quality_bps(), MAX_QUALITY_BPS);
    let identity = author(30);
    assert!(shared
        .publish(experience(&identity, "k", 1_000, 0))
        .is_err());
    assert_eq!(shared.len(), 0);
}
