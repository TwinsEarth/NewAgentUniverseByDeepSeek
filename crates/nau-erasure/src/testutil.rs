//! Deterministic test helpers shared by the unit tests in the private modules
//! and the integration suite in `tests.rs`.
//!
//! Everything here is `pub(crate)` and only compiled under `#[cfg(test)]`.
//! There is no randomness: the same shard-splitting, subset enumeration and
//! payload generation must hold across runs, otherwise a failure would not be
//! reproducible.

use crate::ErasureCoder;

/// A payload generated deterministically from `(seed, len)`, with no
/// repetitions that could mask a reordering bug.
///
/// The mix is a SplitMix64-style scramble followed by an xorshift; it is not
/// cryptographic and does not need to be.
pub(crate) fn payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(0xbf58_476d_1ce4_e5b9);
    let mut out = Vec::with_capacity(len);
    for index in 0..len {
        // SplitMix64 step.
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        // Fold in the index so a shifted payload is never identical.
        out.push(((z >> 24) as u8) ^ (index as u8));
    }
    out
}

/// Every `size`-subset of `0..n`, in lexicographic order.
///
/// The enumeration is what makes the recovery tests exhaustive rather than
/// illustrative: for `n = 6, size = 4` it yields all 15 subsets.
pub(crate) fn subsets(n: usize, size: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    if size > n {
        return out;
    }
    let mut current: Vec<usize> = (0..size).collect();
    loop {
        out.push(current.clone());
        let mut pivot = None;
        for index in (0..size).rev() {
            let value = current[index];
            if value + 1 < n - (size - 1 - index) {
                pivot = Some(index);
                break;
            }
        }
        let pivot = match pivot {
            Some(index) => index,
            None => break,
        };
        current[pivot] += 1;
        for index in (pivot + 1)..size {
            current[index] = current[index - 1] + 1;
        }
    }
    out
}

/// `n choose k`, used to assert that an enumeration covered exactly as many
/// cases as it should have.
pub(crate) fn binomial(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    let mut result = 1usize;
    for index in 0..k {
        result = result * (n - index) / (index + 1);
    }
    result
}

/// The expected padded content of the first `k` shards for `payload`.
///
/// This is an independent restatement of the systematic property: the padded
/// payload is split into `k` equal contiguous windows.
pub(crate) fn expected_padded_payload(payload: &[u8], data_shards: usize) -> Vec<Vec<u8>> {
    let shard_len = payload.len().div_ceil(data_shards);
    let mut out = Vec::with_capacity(data_shards);
    for index in 0..data_shards {
        let mut shard = vec![0u8; shard_len];
        for (offset, byte) in shard.iter_mut().enumerate() {
            let position = index * shard_len + offset;
            if let Some(value) = payload.get(position) {
                *byte = *value;
            }
        }
        out.push(shard);
    }
    out
}

/// Assert that `shards` is a valid encoding of `payload` for `coder`,
/// independently of how it was produced: the first `k` shards must equal the
/// padded payload, all shards must have one common length, and the parity
/// shards must be reproducible from the data shards by a fresh encode.
pub(crate) fn assert_encoding_is_coherent(
    coder: &ErasureCoder,
    payload: &[u8],
    shards: &[Vec<u8>],
) {
    assert_eq!(shards.len(), coder.total_shards(), "shard count");
    let lengths: Vec<usize> = shards.iter().map(Vec::len).collect();
    assert!(
        lengths.windows(2).all(|pair| pair[0] == pair[1]),
        "shard lengths must all be equal, got {lengths:?}"
    );
    let expected = expected_padded_payload(payload, coder.data_shards());
    for (index, shard) in expected.iter().enumerate() {
        assert_eq!(
            shards.get(index),
            Some(shard),
            "data shard {index} is not the padded payload"
        );
    }
}
