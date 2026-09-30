//! The test suite for `nau-erasure`.
//!
//! The centrepiece is [`exhaustive_recovery`]: for each `(k, m)` in
//! `{(2,1), (3,2), (4,2), (5,3)}` it enumerates **every** `k`-subset of the
//! `n` shard indices, erases the complement, decodes, and asserts the result
//! equals the original payload. The number of subsets actually exercised is
//! counted and asserted, so the suite cannot silently degrade into a single
//! happy-path case — which is exactly how upstream's integration test
//! (`tests/integration_test.rs:93-102`) managed to "prove" recovery while
//! never testing it.
//!
//! The module also pins down what the crate does **not** do: Reed-Solomon
//! corrects *erasures* (loss at known positions), not *errors* (corruption at
//! unknown positions). `corrupted_present_shard_*` assert that a corrupt shard
//! produces silently wrong output, because a checksum layer above this crate
//! is required to detect it.

use nau_core::NauError;

use crate::coder::MAX_TOTAL_SHARDS;
use crate::gf;
use crate::testutil::{assert_encoding_is_coherent, binomial, payload, subsets};
use crate::{ErasureCoder, Matrix};

/// The counts of `(configuration, payload, erased-set)` recovery cases the
/// exhaustive tests drive, in the order of [`CONFIGURATIONS`].
///
/// Each exhaustive test asserts the count **it** exercised against this table
/// before adding it, so the totals below are exact regardless of how many
/// tests run in parallel — this accounting is deliberately local rather than a
/// shared process-wide counter, because a shared counter makes the final
/// comparison depend on test scheduling.
const EXHAUSTIVE_SUBSET_COUNTS: [usize; 4] = [
    // (2, 1): C(3, 2) = 3 subsets, six payload lengths.
    18, // (3, 2): C(5, 3) = 10 subsets, six payload lengths.
    60, // (4, 2): C(6, 4) = 15 subsets, six payload lengths.
    90, // (5, 3): C(8, 5) = 56 subsets, six payload lengths.
    336,
];

/// Every `(k, m)` pair the exhaustive recovery test covers.
const CONFIGURATIONS: [(usize, usize); 4] = [(2, 1), (3, 2), (4, 2), (5, 3)];

/// The fixed payload lengths the exhaustive recovery test covers, on top of
/// the configuration-relative sizes `k - 1`, `k` and `k + 1` that each
/// individual test adds. `1` byte is the degenerate case where padding is
/// almost everything; `1000` and `4096` exercise multi-byte shards.
const EXHAUSTIVE_PAYLOAD_SIZES: [usize; 3] = [1, 1000, 4096];

/// The payload lengths for one configuration: the fixed sizes plus the
/// relative sizes `k - 1`, `k`, `k + 1`.
fn exhaustive_payload_lengths(k: usize) -> [usize; 6] {
    [
        EXHAUSTIVE_PAYLOAD_SIZES[0],
        k - 1,
        k,
        k + 1,
        EXHAUSTIVE_PAYLOAD_SIZES[1],
        EXHAUSTIVE_PAYLOAD_SIZES[2],
    ]
}

/// Erase every shard whose index is not in `keep`, from a fully present
/// codeword.
fn erase_except(shards: &[Vec<u8>], keep: &[usize]) -> Vec<Option<Vec<u8>>> {
    shards
        .iter()
        .enumerate()
        .map(|(index, shard)| {
            if keep.contains(&index) {
                Some(shard.clone())
            } else {
                None
            }
        })
        .collect()
}

/// Erase exactly the shards listed in `erase`.
fn erase(shards: &[Vec<u8>], erase: &[usize]) -> Vec<Option<Vec<u8>>> {
    shards
        .iter()
        .enumerate()
        .map(|(index, shard)| {
            if erase.contains(&index) {
                None
            } else {
                Some(shard.clone())
            }
        })
        .collect()
}

/// Count the data shard indices present in `slots`.
fn present_data_indices(slots: &[Option<Vec<u8>>], data_shards: usize) -> Vec<usize> {
    slots
        .iter()
        .enumerate()
        .filter(|(index, slot)| *index < data_shards && slot.is_some())
        .map(|(index, _)| index)
        .collect()
}

/// Exhaustive recovery for one configuration and one payload length.
///
/// Returns the number of `k`-subsets exercised: `C(k + m, k)`. The caller
/// asserts the return value so a broken enumeration fails loudly instead of
/// passing vacuously.
fn exhaustive_recovery(k: usize, m: usize, payload_len: usize) -> usize {
    let coder = ErasureCoder::new(k, m).expect("configuration is valid");
    let n = coder.total_shards();
    let data = payload(0x5eed_0000 ^ ((k as u64) << 8) ^ (m as u64), payload_len);
    let shards = coder.encode(&data).expect("payload is non-empty");
    assert_encoding_is_coherent(&coder, &data, &shards);
    let padded = coder
        .decode(&slots_all_present(&shards))
        .expect("a complete codeword always decodes");

    let combinations = subsets(n, k);
    let expected = binomial(n, k);
    assert_eq!(
        combinations.len(),
        expected,
        "subset enumeration for ({k}, {m}) produced the wrong count"
    );

    for keep in &combinations {
        assert_eq!(keep.len(), k);
        let slots = erase_except(&shards, keep);
        let recovered = coder.decode(&slots).unwrap_or_else(|error| {
            panic!("({k}, {m}) len {payload_len}: subset {keep:?} failed: {error}")
        });
        assert_eq!(
            recovered, padded,
            "({k}, {m}) len {payload_len}: wrong reconstruction from subset {keep:?}"
        );
    }

    combinations.len()
}

/// Every slot present, as `Some`.
fn slots_all_present(shards: &[Vec<u8>]) -> Vec<Option<Vec<u8>>> {
    shards.iter().cloned().map(Some).collect()
}

// ---------------------------------------------------------------------------
// Systematic property
// ---------------------------------------------------------------------------

#[test]
fn first_k_shards_are_the_padded_input() {
    for (k, m) in CONFIGURATIONS {
        let coder = ErasureCoder::new(k, m).expect("valid");
        for len in [
            1usize,
            2,
            k.saturating_sub(1).max(1),
            k,
            k + 1,
            37,
            1000,
            4096,
        ] {
            let data = payload(0xa5a5 ^ len as u64, len);
            let shards = coder.encode(&data).expect("non-empty payload");
            assert_eq!(shards.len(), k + m);
            // Systematic: the identity block of the distribution matrix means
            // shards 0..k are the payload, zero-padded to a common length.
            assert_encoding_is_coherent(&coder, &data, &shards);
        }
    }
}

#[test]
fn systematic_output_is_exactly_zero_padded_not_reordered() {
    let coder = ErasureCoder::new(3, 2).expect("valid");
    let shards = coder.encode(b"abcdefg").expect("encodes");
    // 7 bytes over k = 3 shards: 3 bytes each, last byte zero padding.
    assert_eq!(shards[0], b"abc");
    assert_eq!(shards[1], b"def");
    assert_eq!(shards[2], b"g\0\0");
    assert!(shards[3].len() == 3 && shards[4].len() == 3);
    // The parity shards must not be identical to any data shard, or "parity"
    // would be decoration (the upstream defect).
    assert_ne!(shards[3], shards[0]);
    assert_ne!(shards[4], shards[1]);
}

#[test]
fn parity_shards_are_not_merely_checksums_of_the_data_shards() {
    // A SHA-256 style "parity" (upstream's approach) cannot be combined
    // linearly to rebuild data. Real parity must satisfy
    // D * data == shards for the full matrix, and in particular a parity shard
    // must change when any single data shard changes.
    let coder = ErasureCoder::new(3, 2).expect("valid");
    let mut first = coder.encode(b"aaaaaa").expect("encodes");
    let mut second = coder.encode(b"baaaaa").expect("encodes");
    assert_ne!(first[3], second[3]);
    assert_ne!(first[4], second[4]);
    first.truncate(5);
    second.truncate(5);
}

// ---------------------------------------------------------------------------
// Exhaustive recovery — every k-subset, for four configurations
// ---------------------------------------------------------------------------

#[test]
fn exhaustive_recovery_2_1() {
    let (k, m) = (2, 1);
    let mut total = 0usize;
    for len in exhaustive_payload_lengths(k) {
        let tested = exhaustive_recovery(k, m, len);
        assert_eq!(
            tested, 3,
            "(2,1) must exercise C(3,2) = 3 subsets per payload"
        );
        total += tested;
    }
    assert_eq!(total, EXHAUSTIVE_SUBSET_COUNTS[0]);
}

#[test]
fn exhaustive_recovery_3_2() {
    let (k, m) = (3, 2);
    let mut total = 0usize;
    for len in exhaustive_payload_lengths(k) {
        let tested = exhaustive_recovery(k, m, len);
        assert_eq!(
            tested, 10,
            "(3,2) must exercise C(5,3) = 10 subsets per payload"
        );
        total += tested;
    }
    assert_eq!(total, EXHAUSTIVE_SUBSET_COUNTS[1]);
}

#[test]
fn exhaustive_recovery_4_2() {
    let (k, m) = (4, 2);
    let mut total = 0usize;
    for len in exhaustive_payload_lengths(k) {
        let tested = exhaustive_recovery(k, m, len);
        assert_eq!(
            tested, 15,
            "(4,2) must exercise C(6,4) = 15 subsets per payload"
        );
        total += tested;
    }
    assert_eq!(total, EXHAUSTIVE_SUBSET_COUNTS[2]);
}

#[test]
fn exhaustive_recovery_5_3() {
    let (k, m) = (5, 3);
    let mut total = 0usize;
    for len in exhaustive_payload_lengths(k) {
        let tested = exhaustive_recovery(k, m, len);
        assert_eq!(
            tested, 56,
            "(5,3) must exercise C(8,5) = 56 subsets per payload"
        );
        total += tested;
    }
    assert_eq!(total, EXHAUSTIVE_SUBSET_COUNTS[3]);
}

#[test]
fn exhaustive_totals_are_exact_and_match_the_binomial_coefficients() {
    // 6 payload lengths per configuration: the three fixed sizes plus the
    // configuration-relative sizes k - 1, k and k + 1.
    let payload_lengths = EXHAUSTIVE_PAYLOAD_SIZES.len() + 3;
    assert_eq!(payload_lengths, 6);

    // Per-configuration totals.
    for (index, (k, m)) in CONFIGURATIONS.into_iter().enumerate() {
        let subsets_per_payload = binomial(k + m, k);
        let expected = subsets_per_payload * payload_lengths;
        assert_eq!(
            EXHAUSTIVE_SUBSET_COUNTS[index], expected,
            "({k}, {m}): the accounted total must equal {subsets_per_payload} subsets \
             x {payload_lengths} payload lengths = {expected}"
        );
    }

    // Grand total: 6 x (C(3,2) + C(5,3) + C(6,4) + C(8,5)).
    let per_payload = binomial(3, 2) + binomial(5, 3) + binomial(6, 4) + binomial(8, 5);
    assert_eq!(per_payload, 84);
    let grand_total: usize = EXHAUSTIVE_SUBSET_COUNTS.iter().sum();
    assert_eq!(grand_total, per_payload * payload_lengths);
    assert_eq!(grand_total, 504);

    // And re-drive every case right here, counting as we go, so that the
    // headline number in the test output is produced by this test itself
    // rather than depending on how other tests are scheduled.
    let mut exercised = 0usize;
    for (k, m) in CONFIGURATIONS {
        for len in exhaustive_payload_lengths(k) {
            exercised += exhaustive_recovery(k, m, len);
        }
    }
    assert_eq!(
        exercised, grand_total,
        "the exhaustive recovery sweep must exercise exactly {grand_total} \
         (configuration, payload, erased-set) cases"
    );
    println!(
        "exhaustive recovery: {exercised} erasure subsets exercised across {} \
         configurations and {payload_lengths} payload lengths each",
        CONFIGURATIONS.len()
    );
}

// ---------------------------------------------------------------------------
// Recovery shapes: parity only, parity mixed in, and the loss patterns that
// matter most
// ---------------------------------------------------------------------------

#[test]
fn recovery_with_only_parity_shards_present() {
    // The case upstream could never handle: every data shard gone.
    for (k, m) in [(2usize, 2usize), (2, 3), (3, 3), (4, 4)] {
        let coder = ErasureCoder::new(k, m).expect("valid");
        let data = payload(0xdead ^ k as u64, 512);
        let shards = coder.encode(&data).expect("encodes");
        let padded = coder.decode(&slots_all_present(&shards)).expect("decodes");

        // Keep only parity shards, and only k of them.
        let parity_indices: Vec<usize> = (k..(k + m)).collect();
        for keep in subsets(m, k) {
            let keep: Vec<usize> = keep
                .into_iter()
                .map(|offset| parity_indices[offset])
                .collect();
            let slots = erase_except(&shards, &keep);
            let present = present_data_indices(&slots, k);
            assert!(
                present.is_empty(),
                "this test must have no data shard available, found {present:?}"
            );
            let recovered = coder.decode(&slots).expect("parity alone must reconstruct");
            assert_eq!(recovered, padded, "k = {k}, m = {m}, keep = {keep:?}");
        }
    }
}

#[test]
fn recovery_with_parity_shards_where_every_data_shard_but_one_is_lost() {
    let coder = ErasureCoder::new(4, 2).expect("valid");
    let data = payload(7, 333);
    let shards = coder.encode(&data).expect("encodes");
    let padded = coder.decode(&slots_all_present(&shards)).expect("decodes");

    // Keep data shard 1 plus both parity shards: 3 shards for k = 4, so add
    // one more data shard to reach k. Try every choice of the extra shard.
    for extra in [0usize, 2, 3] {
        let keep = vec![1usize, 4, 5, extra];
        let slots = erase_except(&shards, &keep);
        let present = present_data_indices(&slots, 4);
        let lost: Vec<usize> = (0..6).filter(|index| !keep.contains(index)).collect();
        assert_eq!(present.len(), 2, "expected two data shards present");
        assert_eq!(lost.len(), 2, "expected two shards lost");
        assert_eq!(
            coder.decode(&slots).expect("decodes"),
            padded,
            "keep = {keep:?}"
        );
    }
}

#[test]
fn recovery_prefers_availability_over_shard_kind() {
    // Erase every possible pair of shard positions for (4, 2) and check
    // recovery in all 15 cases, with the loss set named explicitly rather
    // than derived from a keep-set. Both data-only and parity-containing
    // losses are covered here.
    let coder = ErasureCoder::new(4, 2).expect("valid");
    let data = payload(11, 128);
    let shards = coder.encode(&data).expect("encodes");
    let padded = coder.decode(&slots_all_present(&shards)).expect("decodes");

    let mut tested = 0usize;
    for first in 0..6usize {
        for second in (first + 1)..6usize {
            let slots = erase(&shards, &[first, second]);
            let present: Vec<usize> = (0..6)
                .filter(|i| ![*i].contains(&first) && *i != second)
                .collect();
            assert_eq!(present.len(), 4);
            assert_eq!(
                coder.decode(&slots).expect("decodes"),
                padded,
                "lost shards {first} and {second}"
            );
            tested += 1;
        }
    }
    assert_eq!(tested, 15, "must cover every loss pair");
}

#[test]
fn recovery_when_the_parity_shards_are_the_ones_lost() {
    let coder = ErasureCoder::new(4, 2).expect("valid");
    let (shards, original_len) = coder
        .encode_with_length(b"parity is the redundant part")
        .expect("encodes");
    let slots = erase(&shards, &[4, 5]);
    assert_eq!(
        coder
            .decode_with_length(&slots, original_len)
            .expect("data shards alone are enough"),
        b"parity is the redundant part"
    );
}

#[test]
fn recovery_with_all_data_shards_lost_and_exactly_k_parity_shards() {
    let coder = ErasureCoder::new(3, 3).expect("valid");
    let (shards, original_len) = coder
        .encode_with_length(b"nothing but parity survives")
        .expect("encodes");
    // All three data shards go, leaving exactly k = 3 parity shards.
    let slots = erase(&shards, &[0, 1, 2]);
    assert!(present_data_indices(&slots, 3).is_empty());
    assert_eq!(
        coder
            .decode_with_length(&slots, original_len)
            .expect("parity-only reconstruction"),
        b"nothing but parity survives"
    );
}

// ---------------------------------------------------------------------------
// Failure modes: typed errors, never panics, never silently wrong bytes
// ---------------------------------------------------------------------------

#[test]
fn fewer_than_k_shards_is_a_typed_error_never_a_panic() {
    let coder = ErasureCoder::new(4, 2).expect("valid");
    let shards = coder.encode(b"0123456789").expect("encodes");

    // 0..k-1 present shards, in every "keep the first n" shape.
    for present_count in 0..4usize {
        let keep: Vec<usize> = (0..present_count).collect();
        let slots = erase_except(&shards, &keep);
        let result = coder.decode(&slots);
        match result {
            Err(NauError::Validation(message)) => {
                assert!(
                    message.contains("cannot reconstruct"),
                    "message should explain the failure, got: {message}"
                );
                let missing = 4 - present_count;
                assert!(
                    message.contains(&format!("{missing} more shard(s) required")),
                    "message should name how many are missing, got: {message}"
                );
                assert!(
                    message.contains(" of 4 data shards"),
                    "message should name how many data shards are present, got: {message}"
                );
            }
            other => panic!("expected NauError::Validation, got {other:?}"),
        }
    }
}

#[test]
fn losing_more_than_m_shards_is_a_typed_error_not_wrong_bytes() {
    // Beyond the code's tolerance the shards are simply insufficient; the
    // decoder must refuse rather than invent bytes.
    let coder = ErasureCoder::new(3, 2).expect("valid");
    let shards = coder.encode(b"exactly the limit").expect("encodes");
    // m + 1 = 3 losses leaves k - 1 = 2 shards.
    let slots = erase(&shards, &[0, 1, 2]);
    assert!(matches!(coder.decode(&slots), Err(NauError::Validation(_))));
    // m losses are fine.
    let slots = erase(&shards, &[0, 1]);
    assert!(coder.decode(&slots).is_ok());
}

#[test]
fn mismatched_shard_lengths_are_a_typed_error() {
    let coder = ErasureCoder::new(2, 2).expect("valid");
    let shards = coder.encode(b"abcdefgh").expect("encodes");
    assert_eq!(shards[0].len(), 4);

    // Truncate one present shard.
    let mut slots = slots_all_present(&shards);
    slots[1] = Some(vec![0u8; 3]);
    match coder.decode(&slots) {
        Err(NauError::Validation(message)) => assert!(
            message.contains("different lengths"),
            "message should explain the length mismatch, got: {message}"
        ),
        other => panic!("expected a length-mismatch error, got {other:?}"),
    }

    // Lengthen one present shard.
    let mut slots = slots_all_present(&shards);
    slots[2] = Some(vec![0u8; 5]);
    assert!(matches!(coder.decode(&slots), Err(NauError::Validation(_))));

    // A mismatch between an erased shard and a present one is invisible (the
    // erased shard has no length at all) and must not be reported.
    let mut slots = slots_all_present(&shards);
    slots[0] = None;
    assert!(coder.decode(&slots).is_ok());
}

#[test]
fn empty_shards_are_rejected() {
    let coder = ErasureCoder::new(2, 1).expect("valid");
    let slots = vec![Some(Vec::new()), Some(Vec::new()), None];
    assert!(matches!(coder.decode(&slots), Err(NauError::Validation(_))));
}

#[test]
fn wrong_number_of_slots_is_a_typed_error() {
    let coder = ErasureCoder::new(3, 2).expect("valid");
    for count in [0usize, 1, 4, 6, 100] {
        let slots: Vec<Option<Vec<u8>>> = (0..count).map(|_| Some(vec![1, 2, 3])).collect();
        match coder.decode(&slots) {
            Err(NauError::Validation(message)) => assert!(
                message.contains("shard slots"),
                "message should name the slot count, got: {message}"
            ),
            other => panic!("expected a slot-count error for {count} slots, got {other:?}"),
        }
    }
}

#[test]
fn empty_payloads_are_rejected_everywhere() {
    let coder = ErasureCoder::new(4, 2).expect("valid");
    assert!(matches!(coder.encode(&[]), Err(NauError::Validation(_))));
    assert!(matches!(
        coder.encode_with_length(&[]),
        Err(NauError::Validation(_))
    ));
    assert!(matches!(
        coder.encoded_shard_len(0),
        Err(NauError::Validation(_))
    ));
}

#[test]
fn a_claimed_original_length_longer_than_the_payload_is_rejected() {
    let coder = ErasureCoder::new(2, 1).expect("valid");
    let (shards, original_len) = coder.encode_with_length(b"abcd").expect("encodes");
    assert_eq!(original_len, 4);
    let slots = slots_all_present(&shards);
    assert!(coder.decode_with_length(&slots, 5).is_err());
    assert_eq!(
        coder.decode_with_length(&slots, 4).expect("exact length"),
        b"abcd"
    );
    // A shorter claim truncates, which is legal: the caller may know the real
    // payload was a prefix.
    assert_eq!(
        coder.decode_with_length(&slots, 2).expect("prefix length"),
        b"ab"
    );
}

#[test]
fn construction_rejects_degenerate_and_oversized_codes() {
    for (k, m) in [
        (0usize, 1usize),
        (0, 0),
        (1, 0),
        (255, 0),
        (200, 56),
        (255, 1),
        (256, 0),
        (usize::MAX, 1),
        (1, usize::MAX),
        (usize::MAX, usize::MAX),
    ] {
        let result = ErasureCoder::new(k, m);
        assert!(result.is_err(), "({k}, {m}) must not construct a coder");
        assert!(
            matches!(result, Err(NauError::Validation(_))),
            "({k}, {m}) must fail with a typed validation error"
        );
    }

    for (k, m) in [
        (1usize, 1usize),
        (1, 254),
        (200, 55),
        (255 - 1, 1),
        (127, 128),
    ] {
        assert!(
            ErasureCoder::new(k, m).is_ok(),
            "({k}, {m}) is within the GF(2^8) bound and must construct"
        );
    }
}

#[test]
fn error_messages_distinguish_missing_from_required_shards() {
    let coder = ErasureCoder::new(5, 3).expect("valid");
    let shards = coder.encode(b"0123456789abcde").expect("encodes");
    // Keep data shards 0 and 3 only: 2 of 5 present, 6 of 8 lost, 3 missing.
    let slots = erase(&shards, &[1, 2, 4, 5, 6, 7]);
    match coder.decode(&slots) {
        Err(NauError::Validation(message)) => {
            assert!(message.contains("3 more shard(s) required"), "{message}");
            assert!(message.contains("have 2 of 5 data shards"), "{message}");
            assert!(message.contains("6 of 8 shards lost"), "{message}");
            assert!(message.contains("tolerates at most 3 losses"), "{message}");
        }
        other => panic!("expected a typed error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Corruption: erasures yes, error correction NO. Say so, and prove it.
// ---------------------------------------------------------------------------

#[test]
fn corrupted_present_shard_yields_wrong_output_and_is_not_detected() {
    // Read this test as a specification, not as a bug report.
    //
    // Reed-Solomon distinguishes two failure modes:
    //
    //   * an ERASURE — the receiver knows *which* shard is gone (`None`);
    //   * an ERROR   — a shard is present but its bytes are corrupt, and the
    //                  receiver does not know which shard is lying.
    //
    // This crate implements erasure recovery only. It has no syndrome
    // computation, no Berlekamp-Massey and no Forney step, so it cannot
    // locate or repair an error, and it makes no attempt to detect one: every
    // byte string is a valid message, so there is nothing in the field
    // arithmetic to notice.
    //
    // The honest contract is therefore: a corrupt shard produces silently
    // WRONG bytes, and the caller must add a checksum/MAC layer above this
    // crate to turn an error into an erasure (verify the digest *before*
    // handing the shard to `decode`). Upstream half-built exactly that layer
    // — it hashed shards with SHA-256 — but never checked the digests on the
    // decode path either.
    let coder = ErasureCoder::new(4, 2).expect("valid");
    let data = payload(0xc0ffee, 256);
    let shards = coder.encode(&data).expect("encodes");
    let padded = coder.decode(&slots_all_present(&shards)).expect("decodes");

    // Case 1: corrupt a data shard, with one shard erased so that the corrupt
    // shard is necessarily used in reconstruction.
    let mut slots = erase(&shards, &[3]);
    let target = slots[0].as_mut().expect("shard 0 is present");
    target[0] ^= 0x01;
    let recovered = coder
        .decode(&slots)
        .expect("the decoder happily accepts a corrupt shard");
    assert_ne!(
        recovered, padded,
        "a corrupt present shard must not be silently 'corrected'"
    );
    assert_ne!(&recovered[..data.len()], &data[..]);
    // Specifically: no error was reported, and the bytes are wrong. This is
    // the assertion that documents the absence of error correction.
    assert_eq!(
        recovered.len(),
        padded.len(),
        "the decoder cannot even tell that the codeword is inconsistent"
    );

    // Case 2: corrupt a *parity* shard instead, with data shards missing.
    let mut slots = erase(&shards, &[0, 1]);
    let target = slots[4].as_mut().expect("parity shard 4 is present");
    target[7] ^= 0x80;
    let recovered = coder.decode(&slots).expect("still no detection");
    assert_ne!(recovered, padded);
}

#[test]
fn a_corrupt_shard_is_corrected_only_if_it_is_declared_lost() {
    // The distinction, demonstrated directly: give the decoder the same
    // physical damage twice, once as a `Some(..)` with wrong bytes (an error
    // it cannot handle) and once as `None` (an erasure it can).
    let coder = ErasureCoder::new(3, 2).expect("valid");
    let data = payload(0x1234, 90);
    let shards = coder.encode(&data).expect("encodes");
    let padded = coder.decode(&slots_all_present(&shards)).expect("decodes");

    // Flip one bit in data shard 1 and drop shard 0 as well, to force shard 1
    // to be used.
    let mut damaged = shards.clone();
    damaged[1][3] ^= 0x40;
    let as_error = erase(&damaged, &[0]);
    let as_erasure = erase(&shards, &[0, 1]);

    let error_result = coder.decode(&as_error).expect("no error detection");
    let erasure_result = coder.decode(&as_erasure).expect("erasures recover");
    assert_ne!(
        error_result, padded,
        "error (present-but-corrupt) produces wrong output"
    );
    assert_eq!(
        erasure_result, padded,
        "the same damage declared as an erasure recovers exactly"
    );

    // And to be explicit about what is missing: `as_error` did not fail.
    assert!(coder.decode(&as_error).is_ok());
}

// ---------------------------------------------------------------------------
// Lengths, determinism, boundaries
// ---------------------------------------------------------------------------

#[test]
fn every_payload_length_round_trips_exactly() {
    for (k, m) in CONFIGURATIONS {
        let coder = ErasureCoder::new(k, m).expect("valid");
        for len in 1..=(k * 5) {
            let data = payload(len as u64, len);
            let (shards, original_len) = coder.encode_with_length(&data).expect("encodes");
            assert_eq!(original_len, len);
            // Lose exactly m shards, the worst case the code tolerates.
            let lost: Vec<usize> = (0..m).collect();
            let slots = erase(&shards, &lost);
            let recovered = coder
                .decode_with_length(&slots, original_len)
                .expect("decodes");
            assert_eq!(
                recovered, data,
                "({k}, {m}) length {len} did not round-trip once {m} shards were lost"
            );
        }
    }
}

#[test]
fn padding_is_stripped_exactly_for_non_multiple_lengths() {
    let coder = ErasureCoder::new(4, 2).expect("valid");
    for (len, shard_len) in [
        (1usize, 1usize),
        (4, 1),
        (5, 2),
        (8, 2),
        (9, 3),
        (1000, 250),
    ] {
        let data = payload(len as u64, len);
        let (shards, original_len) = coder.encode_with_length(&data).expect("encodes");
        assert_eq!(original_len, len);
        assert_eq!(coder.encoded_shard_len(len).expect("non-empty"), shard_len);
        for shard in &shards {
            assert_eq!(shard.len(), shard_len);
        }
        // Round-trip after losing the two parity shards.
        let slots = erase(&shards, &[4, 5]);
        let recovered = coder
            .decode_with_length(&slots, original_len)
            .expect("decodes");
        assert_eq!(recovered.len(), len, "padding was not stripped exactly");
        assert_eq!(recovered, data);
    }
}

#[test]
fn encoding_is_deterministic_for_identical_input() {
    for (k, m) in CONFIGURATIONS {
        let coder = ErasureCoder::new(k, m).expect("valid");
        for len in [1usize, 7, 64, 1000] {
            let data = payload(0xbeef, len);
            let first = coder.encode(&data).expect("encodes");
            let second = coder.encode(&data).expect("encodes");
            let third = ErasureCoder::new(k, m)
                .expect("valid")
                .encode(&data)
                .expect("encodes");
            assert_eq!(first, second, "({k}, {m}) len {len}: not deterministic");
            assert_eq!(
                first, third,
                "({k}, {m}) len {len}: two equivalent coders disagree"
            );
        }
    }
}

#[test]
fn encoding_is_deterministic_across_erasure_patterns() {
    // Determinism must not depend on which shards are present later.
    let coder = ErasureCoder::new(4, 2).expect("valid");
    let data = payload(3, 257);
    let shards = coder.encode(&data).expect("encodes");
    for keep in subsets(6, 4) {
        let slots = erase_except(&shards, &keep);
        let once = coder.decode(&slots).expect("decodes");
        let twice = coder.decode(&slots).expect("decodes");
        assert_eq!(once, twice, "keep = {keep:?}");
    }
}

#[test]
fn the_255_shard_boundary_encodes_and_decodes() {
    // k + m == 255 is the widest code GF(2^8) admits. This proves the tables
    // are sized correctly (no wrap at exponent 255) and the bound is not
    // exceeded.
    let (k, m) = (200usize, 55usize);
    assert_eq!(k + m, MAX_TOTAL_SHARDS);
    let coder = ErasureCoder::new(k, m).expect("255 shards is allowed");
    assert_eq!(coder.total_shards(), 255);

    let data = payload(0xf00d, k - 1); // k - 1 bytes => one byte per shard
    let (shards, original_len) = coder.encode_with_length(&data).expect("encodes");
    assert_eq!(shards.len(), 255);
    assert!(shards.iter().all(|shard| shard.len() == 1));

    // All present: decodes.
    let padded = coder.decode(&slots_all_present(&shards)).expect("decodes");
    assert_eq!(padded.len(), k);
    assert_eq!(
        coder
            .decode_with_length(&slots_all_present(&shards), original_len)
            .expect("decodes"),
        data
    );

    // Lose the maximum 55 shards, including the first 40 data shards; only
    // 160 data + 55 parity = 215 shards survive, which is >= k = 200.
    let lost: Vec<usize> = (0..40).chain(200..215).collect();
    assert_eq!(lost.len(), 55);
    let slots = erase(&shards, &lost);
    assert_eq!(
        coder
            .decode_with_length(&slots, original_len)
            .expect("200 of 255 shards suffice"),
        data
    );

    // One more loss than the code tolerates must be a typed error.
    let too_many = erase(&shards, (0..56).collect::<Vec<usize>>().as_slice());
    assert!(matches!(
        coder.decode(&too_many),
        Err(NauError::Validation(_))
    ));
}

#[test]
fn the_boundary_configuration_has_the_expected_matrix_shape() {
    let coder = ErasureCoder::new(200, 55).expect("valid");
    let matrix = coder.distribution_matrix().expect("builds");
    assert_eq!(matrix.rows(), 255);
    assert_eq!(matrix.cols(), 200);
    // Systematic block: a spot check of the diagonal and off-diagonal.
    for index in [0usize, 1, 99, 199] {
        assert_eq!(matrix.get(index, index), Some(1));
        assert_eq!(matrix.get(index, (index + 1) % 200), Some(0));
    }
    // The parity rows must be non-trivial.
    assert_ne!(matrix.row(254).expect("row exists"), vec![0u8; 200]);
}

#[test]
fn single_data_shard_and_many_parity_shards_work() {
    // k = 1 means every shard is a copy of the payload; the parity shards are
    // still real field multiples, and any single shard recovers.
    for m in [1usize, 2, 7, 254] {
        let coder = ErasureCoder::new(1, m).expect("valid");
        let data = payload(m as u64, 33);
        let shards = coder.encode(&data).expect("encodes");
        assert_eq!(shards.len(), 1 + m);
        for index in 0..(1 + m) {
            let slots = erase_except(&shards, &[index]);
            let recovered = coder.decode(&slots).expect("any single shard recovers");
            assert_eq!(recovered, data, "m = {m}, kept shard {index}");
        }
    }
}

// ---------------------------------------------------------------------------
// Field and matrix behaviour reachable through the public API
// ---------------------------------------------------------------------------

#[test]
fn the_field_used_is_the_documented_primitive_polynomial() {
    assert_eq!(crate::PRIMITIVE_POLYNOMIAL, 0x11d);
    // Multiplying by x = 2 is a left shift; when bit 8 appears it is reduced
    // modulo x^8 + x^4 + x^3 + x^2 + 1, i.e. by XORing 0x11d (equivalently
    // the low byte 0x1d).
    assert_eq!(gf::mul(0x02, 0x40), 0x80, "2 * 64 = 128, no reduction yet");
    assert_eq!(
        gf::mul(0x02, 0x80),
        0x1d,
        "2 * 128 overflows bit 8 and reduces"
    );
    // 2^8 = x^8, which is 0x11d itself, and 0x11d is used as 0x1d because the
    // 9th bit is folded back.
    assert_eq!(gf::pow(0x02, 8), 0x1d);
    assert_eq!(gf::exp(8), 0x1d);
    assert_eq!(gf::pow(0x02, 255), 1);
    assert_eq!(gf::exp(0), 1);
    assert_eq!(gf::exp(1), 2);
}

#[test]
fn gf_division_by_zero_is_an_error_through_the_public_api() {
    assert!(gf::div(1, 0).is_err());
    assert!(gf::try_inverse(0).is_err());
    assert_eq!(gf::mul(0, 255), 0);
    assert_eq!(gf::inverse(0), 0);
    assert_eq!(gf::log(0), None);
    // Exponents beyond 255 wrap rather than panic.
    assert_eq!(gf::exp(255), 1);
    assert_eq!(gf::pow(2, 255), 1);
    assert_eq!(gf::pow(0, 0), 1);
}

#[test]
fn matrix_multiplication_by_the_distribution_matrix_reproduces_encode() {
    let coder = ErasureCoder::new(3, 2).expect("valid");
    let data = payload(0x77, 30); // 10 bytes per data shard
    let shards = coder.encode(&data).expect("encodes");
    let matrix = coder.distribution_matrix().expect("builds");
    for byte_index in 0..10 {
        let column: Vec<u8> = (0..3).map(|shard| shards[shard][byte_index]).collect();
        let expected = matrix.mul_vec(&column).expect("dimensions match");
        for (index, value) in expected.into_iter().enumerate() {
            assert_eq!(
                shards[index][byte_index], value,
                "shard {index} byte {byte_index}"
            );
        }
    }
}

#[test]
fn matrix_api_reports_errors_instead_of_panicking() {
    assert!(Matrix::zeros(0, 4).is_err());
    assert!(Matrix::from_rows(2, 2, vec![1, 2, 3]).is_err());
    let matrix = Matrix::zeros(2, 2).expect("2x2");
    assert!(matrix.invert().is_err(), "the zero matrix is singular");
    assert!(matrix.mul_vec(&[1, 2, 3]).is_err());
    assert!(matrix.row(5).is_err());
    assert!(Matrix::from_rows(1, 2, vec![1, 2])
        .expect("1x2")
        .invert()
        .is_err());
}

// ---------------------------------------------------------------------------
// A property-style sweep that is still fully deterministic
// ---------------------------------------------------------------------------

#[test]
fn a_deterministic_sweep_of_lengths_and_loss_patterns_always_round_trips() {
    // 60 deterministic cases: every configuration, lengths 1..=6 plus a few
    // larger ones, and a rotating erasure pattern.
    let mut cases = 0usize;
    for (k, m) in CONFIGURATIONS {
        let coder = ErasureCoder::new(k, m).expect("valid");
        for len in [1usize, 2, 3, 4, 5, 6, 13, 64, 255, 1000] {
            let data = payload(((len as u64) << 8) | (k as u64), len);
            let (shards, original_len) = coder.encode_with_length(&data).expect("encodes");
            let total = coder.total_shards();
            for offset in 0..m {
                // Lose m shards spaced by `offset`, wrapping.
                let lost: Vec<usize> = (0..m).map(|i| (i * 3 + offset) % total).collect();
                let slots = erase(&shards, &lost);
                let present = slots.iter().filter(|slot| slot.is_some()).count();
                assert!(
                    present >= k,
                    "the pattern must leave at least k shards, left {present}"
                );
                let recovered = coder
                    .decode_with_length(&slots, original_len)
                    .expect("decodes");
                assert_eq!(recovered, data, "({k}, {m}) len {len} lost {lost:?}");
                cases += 1;
            }
        }
    }
    assert!(
        cases >= 60,
        "the sweep must cover at least 60 cases, got {cases}"
    );
}
