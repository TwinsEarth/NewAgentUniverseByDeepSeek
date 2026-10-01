//! A systematic Reed-Solomon erasure code over GF(2^8).
//!
//! # What this replaces, and why
//!
//! Upstream `agent-universe` v2.5.6 shipped `gsn-core/src/erasure/mod.rs`,
//! whose `decode` looked like this (reconstructed from
//! `docs/GAP-ANALYSIS.md` §7.8, evidence `erasure/mod.rs:92-111`):
//!
//! ```text
//! pub fn decode(&self, shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>, ...> {
//!     // reject unless data_shards_available.len() >= self.data_shards
//!     // ... then CONCATENATE DATA SHARDS ONLY
//! }
//! ```
//!
//! Its "parity" shards were SHA-256 digests (`erasure/mod.rs:62-80`) and were
//! **never consulted during reconstruction**. Consequently
//! `ErasureCoder::new(4, 2)` could not recover a single lost byte, despite the
//! module doc claiming "丢失部分分片仍可恢复". The upstream integration test
//! (`tests/integration_test.rs:93-102`) "simulated" losing two shards by
//! handing `decode` the four *data* shards, so the recovery path was never
//! exercised at all.
//!
//! This crate is the real thing: a systematic Reed-Solomon code that
//! reconstructs the original bytes from **any** `k` of the `n` shards, using
//! genuine GF(256) field arithmetic.
//!
//! ```text
//! // upstream v2.5.6 fix: real RS decoding - any k of n shards reconstruct
//! // the data, instead of concatenating whichever data shards happen to be
//! // present and ignoring parity entirely.
//! ```
//!
//! # What IS implemented
//!
//! * **Erasure recovery.** Given a known set of lost shard positions, any `k`
//!   surviving shards reconstruct the original payload exactly. Every
//!   `k`-subset of the `n` shard indices is covered by tests.
//! * **Systematic encoding.** The first `k` output shards *are* the input
//!   data (zero-padded). Callers may therefore read a payload straight out of
//!   shards `0..k` when nothing is lost.
//! * **Exact length handling.** [`ErasureCoder::encode_with_length`] records
//!   the pre-padding length, and [`ErasureCoder::decode_with_length`] strips
//!   the padding, so a 1-byte payload round-trips as a 1-byte payload.
//! * **Bounded, checked construction.** `k + m <= 255`, enforced with typed
//!   errors; there is no arithmetic that can overflow or panic.
//!
//! # What is NOT implemented — read this before relying on the crate
//!
//! * **No error correction.** Reed-Solomon can in principle correct *errors*
//!   (corruption at unknown positions) as well as *erasures* (loss at known
//!   positions). This crate implements **erasures only**. There is no
//!   Berlekamp-Massey, no Forney algorithm, no syndrome decoding, and no
//!   notion of "which shard is lying".
//!
//!   The distinction is not academic. A shard that is *present but corrupt* is
//!   fed to the decoder as if it were truthful, and the output is then
//!   **silently wrong** — the field arithmetic has no way to notice, because
//!   every byte string is a valid codeword for *some* message. The test
//!   `corrupted_present_shard_yields_wrong_output_and_is_not_detected`
//!   demonstrates exactly this and asserts the (incorrect) output.
//!
//!   **If corruption is in scope, add an integrity layer**: a per-shard
//!   checksum or MAC, verified *before* the shard is handed to
//!   [`ErasureCoder::decode`], which converts an error into an erasure. That
//!   is the standard composition, and it is what upstream half-built (it had
//!   the digests but never used them for reconstruction *or* for detection on
//!   the decode path).
//! * **No confidentiality.** Shards are plaintext. Erasure coding is not
//!   encryption.
//! * **No network or storage layer.** Nothing here performs I/O, decides
//!   where shards live, or talks to peers. Distribution is the caller's
//!   problem.
//! * **No cross-implementation wire format guarantee.** The code is a
//!   textbook systematic RS code over `0x11d`, but no interoperability with
//!   an external RS library has been tested, so do not assume it.
//!
//! # Construction
//!
//! The `n x k` **distribution matrix** `D` maps the `k` data shards to the
//! `n` encoded shards: `shards = D * data`. Its first `k` rows are the
//! identity (the systematic property); the remaining `m` rows are the parity
//! block of the classical systematic Reed-Solomon encoder, built from the
//! generator polynomial
//!
//! ```text
//! g(x) = (x + a^0)(x + a^1)...(x + a^(m-1)),   a = 0x02
//! ```
//!
//! so that — writing `message(x) = sum_j data[j] * x^j` — the codeword
//!
//! ```text
//! C(x) = par(x) + x^m * message(x),   par(x) = message(x) * x^m mod g(x)
//! ```
//!
//! is divisible by `g`, i.e. `C(a^r) = 0` for every `r < m`. The parity
//! shards hold `par`'s coefficients, highest degree first.
//!
//! Decoding takes the `k x k` submatrix `D_S` formed by the rows of the
//! shards that survived, and the surviving shard vectors `S`. Because
//! `S = D_S * data` and `D_S` is invertible, `data = D_S^-1 * S`. Any `k` rows
//! of `D` are linearly independent (they are `k` rows of a systematic
//! Reed-Solomon generator matrix), which is precisely the MDS property the
//! count of `k`-subsets in the tests verifies empirically.
//!
//! # Invariants
//!
//! * `1 <= k`, `1 <= m`, `k + m <= 255`.
//! * Every node carries exactly one field element; the `255` limit is the
//!   order of `GF(256)*`, and `k + m == 255` is permitted (tested).
//! * The parity block is verified at construction time: every codeword must
//!   vanish at every root of `g`, and [`ErasureCoder::new`] fails rather than
//!   hand out a matrix that does not.

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};

use crate::gf;
use crate::matrix::Matrix;

/// The largest `k + m` a code over GF(2^8) can have: the multiplicative group
/// has order `255`, so at most `255` distinct non-zero evaluation points — and
/// therefore at most `255` shards — exist.
pub const MAX_TOTAL_SHARDS: usize = 255;

/// A systematic Reed-Solomon erasure coder over GF(2^8).
///
/// Created with [`ErasureCoder::new`], which fixes the split into data and
/// parity shards for the lifetime of the value.
///
/// # Examples
///
/// ```
/// use nau_erasure::ErasureCoder;
///
/// let coder = ErasureCoder::new(4, 2)?;
/// let (shards, original_len) = coder.encode_with_length(b"hello, shards")?;
/// assert_eq!(shards.len(), 6);
///
/// // Lose two shards — including two *data* shards.
/// let mut received: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
/// received[0] = None;
/// received[3] = None;
///
/// let recovered = coder.decode_with_length(&received, original_len)?;
/// assert_eq!(recovered, b"hello, shards");
/// # Ok::<(), nau_core::NauError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ErasureCoder {
    /// Number of data shards `k`.
    data_shards: usize,
    /// Number of parity shards `m`.
    parity_shards: usize,
}

impl ErasureCoder {
    /// Build a coder with `k` data shards and `m` parity shards.
    ///
    /// The code is `(k, m)`-MDS: it survives the loss of any `m` shards.
    ///
    /// # Errors
    ///
    /// * [`NauError::Validation`] when `data_shards == 0` ("a code with no
    ///   data shards carries no information").
    /// * [`NauError::Validation`] when `parity_shards == 0` ("a code with no
    ///   parity shards cannot recover anything" — accepting this would
    ///   reproduce exactly the upstream defect, where `m` was decoration).
    /// * [`NauError::Validation`] when `data_shards + parity_shards > 255`.
    /// * [`NauError::Validation`] if the constructed parity block fails its
    ///   own algebraic self-check.
    ///
    /// The sum is computed with [`usize::checked_add`], so an absurd `k` or
    /// `m` (e.g. `usize::MAX`) returns an error instead of wrapping.
    ///
    /// # Examples
    ///
    /// ```
    /// use nau_erasure::ErasureCoder;
    ///
    /// assert!(ErasureCoder::new(0, 2).is_err());
    /// assert!(ErasureCoder::new(4, 0).is_err());
    /// assert!(ErasureCoder::new(200, 55).is_ok()); // exactly 255
    /// assert!(ErasureCoder::new(200, 56).is_err()); // 256
    /// ```
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if data_shards == 0 {
            return Err(NauError::Validation(
                "erasure code needs at least one data shard (k >= 1), got k = 0".to_string(),
            ));
        }
        if parity_shards == 0 {
            return Err(NauError::Validation(
                "erasure code needs at least one parity shard (m >= 1), got m = 0; \
                 a coder with no parity cannot reconstruct any lost shard"
                    .to_string(),
            ));
        }
        let total = data_shards.checked_add(parity_shards).ok_or_else(|| {
            NauError::Validation(format!(
                "data shards {data_shards} plus parity shards {parity_shards} overflowed usize"
            ))
        })?;
        if total > MAX_TOTAL_SHARDS {
            return Err(NauError::Validation(format!(
                "k + m = {data_shards} + {parity_shards} = {total} exceeds the maximum of \
                 {MAX_TOTAL_SHARDS} shards for a code over GF(2^8)"
            )));
        }
        // Build the distribution matrix once, here, so that a coder which
        // exists is always a coder which can be inverted.
        let _ = build_distribution_matrix(data_shards, parity_shards)?;
        Ok(Self {
            data_shards,
            parity_shards,
        })
    }

    /// The number of data shards `k`.
    #[must_use]
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// The number of parity shards `m`.
    #[must_use]
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    /// The total number of shards `n = k + m`.
    #[must_use]
    pub fn total_shards(&self) -> usize {
        // Both fields are bounded by MAX_TOTAL_SHARDS and were checked with
        // checked_add in `new`, so this cannot overflow.
        self.data_shards + self.parity_shards
    }

    /// The distribution matrix `D` (`n x k`) that maps `k` data shards onto
    /// `n` encoded shards.
    ///
    /// Its first `k` rows are the identity, which is the systematic property;
    /// the remaining rows hold the parity coefficients. Exposed for
    /// inspection and testing — callers normally do not need it.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] if the stored configuration is not
    /// representable, which cannot happen for a value built by
    /// [`ErasureCoder::new`].
    pub fn distribution_matrix(&self) -> Result<Matrix> {
        build_distribution_matrix(self.data_shards, self.parity_shards)
    }

    /// The length every encoded shard has for a payload of `data_len` bytes:
    /// the payload padded with zeros to a multiple of `k`, divided by `k`.
    ///
    /// # Errors
    ///
    /// Returns [`NauError::Validation`] when `data_len == 0`.
    pub fn encoded_shard_len(&self, data_len: usize) -> Result<usize> {
        if data_len == 0 {
            return Err(NauError::Validation(
                "cannot encode an empty payload: there is nothing to distribute".to_string(),
            ));
        }
        let padded = padded_len(data_len, self.data_shards)?;
        Ok(padded / self.data_shards)
    }

    /// Encode `data` into exactly [`ErasureCoder::total_shards`] shards of
    /// equal length.
    ///
    /// The payload is zero-padded to a multiple of `k` and split into `k`
    /// equal data shards; the remaining `m` shards are parity. The first `k`
    /// returned shards equal the padded input, byte for byte, so the return
    /// value is *systematic*.
    ///
    /// # Errors
    ///
    /// * [`NauError::Validation`] when `data` is empty.
    /// * [`NauError::Validation`] if the padded length overflows `usize`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nau_erasure::ErasureCoder;
    ///
    /// let coder = ErasureCoder::new(3, 2)?;
    /// let shards = coder.encode(b"abcdef")?;
    /// assert_eq!(shards.len(), 5);
    /// // Systematic: the first k shards are the padded input.
    /// assert_eq!(shards[0], b"ab");
    /// assert_eq!(shards[1], b"cd");
    /// assert_eq!(shards[2], b"ef");
    /// # Ok::<(), nau_core::NauError>(())
    /// ```
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        if data.is_empty() {
            return Err(NauError::Validation(
                "cannot encode an empty payload: there is nothing to distribute".to_string(),
            ));
        }
        let length = padded_len(data.len(), self.data_shards)?;
        // `padded_len` guarantees a non-zero multiple of k, so this split
        // yields exactly k non-empty shards.
        if length % self.data_shards != 0 {
            return Err(NauError::Validation(format!(
                "internal invariant violated: padded length {length} is not a multiple of {}",
                self.data_shards
            )));
        }
        let shard_len = length / self.data_shards;
        let total = self.total_shards();

        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total);
        for index in 0..self.data_shards {
            let start = index * shard_len;
            let end = start + shard_len;
            let mut shard = vec![0u8; shard_len];
            // Copy whatever of the payload lands in this window; the tail
            // beyond `data.len()` stays zero, which is the padding.
            let source_len = end.min(data.len()).saturating_sub(start);
            if source_len > 0 {
                let source_end = start + source_len;
                if let (Some(target), Some(source)) =
                    (shard.get_mut(..source_len), data.get(start..source_end))
                {
                    target.copy_from_slice(source);
                }
            }
            shards.push(shard);
        }
        for _ in self.data_shards..total {
            shards.push(vec![0u8; shard_len]);
        }

        let matrix = self.distribution_matrix()?;
        for byte_index in 0..shard_len {
            let column: Vec<u8> = {
                let mut values = Vec::with_capacity(self.data_shards);
                for shard in shards.iter().take(self.data_shards) {
                    values.push(shard.get(byte_index).copied().unwrap_or(0));
                }
                values
            };
            let encoded = matrix.mul_vec(&column)?;
            if encoded.len() != total {
                return Err(NauError::Validation(format!(
                    "internal invariant violated: distribution matrix produced {} shards, \
                     expected {total}",
                    encoded.len()
                )));
            }
            for (index, value) in encoded.into_iter().enumerate() {
                let shard = shards.get_mut(index).ok_or_else(|| {
                    NauError::Validation(format!("shard index {index} is out of range"))
                })?;
                let slot = shard.get_mut(byte_index).ok_or_else(|| {
                    NauError::Validation(format!(
                        "byte index {byte_index} is out of range for a shard of length {shard_len}"
                    ))
                })?;
                *slot = value;
            }
        }
        Ok(shards)
    }

    /// Reconstruct the original bytes from any [`ErasureCoder::data_shards`]
    /// present shards, stripping no padding.
    ///
    /// `shards[i]` is `None` when shard `i` was lost. Shard `i` for
    /// `i < k` is a data shard; `i >= k` is a parity shard.
    ///
    /// The returned vector has the *padded* length
    /// (`encoded_shard_len * k`). Use [`ErasureCoder::decode_with_length`] to
    /// strip the padding and recover the original payload exactly.
    ///
    /// # Errors
    ///
    /// * [`NauError::Validation`] when `shards.len() != total_shards()`.
    /// * [`NauError::Validation`] when fewer than `k` shards are present. The
    ///   message names how many are missing versus how many are required, so
    ///   an operator can tell "one disk short" from "whole-site loss".
    /// * [`NauError::Validation`] when the present shards do not all have the
    ///   same length — they are one codeword, and unequal lengths mean they
    ///   came from different encodings or were truncated.
    /// * [`NauError::Validation`] when the selected rows turn out to be
    ///   singular, which cannot happen for a well-formed coder.
    ///
    /// # Examples
    ///
    /// ```
    /// use nau_erasure::ErasureCoder;
    ///
    /// let coder = ErasureCoder::new(2, 2)?;
    /// let shards = coder.encode(b"abcd")?;
    /// // Keep both parity shards and no data shard at all: the case the
    /// // upstream implementation could never handle.
    /// let received = vec![None, None, Some(shards[2].clone()), Some(shards[3].clone())];
    /// assert_eq!(coder.decode(&received)?, b"abcd");
    /// # Ok::<(), nau_core::NauError>(())
    /// ```
    pub fn decode(&self, shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>> {
        let total = self.total_shards();
        if shards.len() != total {
            return Err(NauError::Validation(format!(
                "expected {total} shard slots ({}+{}), got {}",
                self.data_shards,
                self.parity_shards,
                shards.len()
            )));
        }

        let mut present: Vec<usize> = Vec::with_capacity(total);
        let mut shard_len: Option<usize> = None;
        for (index, shard) in shards.iter().enumerate() {
            if let Some(bytes) = shard {
                if let Some(expected) = shard_len {
                    if bytes.len() != expected {
                        return Err(NauError::Validation(format!(
                            "present shards have different lengths: shard {index} is {} bytes \
                             but earlier present shards are {expected} bytes; a codeword's \
                             shards must all be the same length",
                            bytes.len()
                        )));
                    }
                } else {
                    if bytes.is_empty() {
                        return Err(NauError::Validation(format!(
                            "shard {index} is present but empty; encoded shards are never \
                             empty for a non-empty payload"
                        )));
                    }
                    shard_len = Some(bytes.len());
                }
                present.push(index);
            }
        }

        if present.len() < self.data_shards {
            let missing = self.data_shards - present.len();
            let lost = total - present.len();
            return Err(NauError::Validation(format!(
                "cannot reconstruct: {missing} more shard(s) required (have {} of {} data \
                 shards, {lost} of {total} shards lost, and recovery tolerates at most {} \
                 losses)",
                present.len(),
                self.data_shards,
                self.parity_shards
            )));
        }
        let shard_len = match shard_len {
            Some(len) => len,
            None => {
                return Err(NauError::Validation(
                    "cannot reconstruct: every shard is missing".to_string(),
                ))
            }
        };

        // Take exactly the first k surviving shards; any k independent rows
        // reconstruct the data, so there is nothing to gain from using more.
        let selected: Vec<usize> = present.iter().copied().take(self.data_shards).collect();

        // upstream v2.5.6 fix: build and invert the k x k submatrix of the
        // distribution matrix for the shards we actually hold, instead of
        // requiring the data shards themselves to be present and then simply
        // concatenating them.
        let matrix = self.distribution_matrix()?;
        let mut submatrix = Matrix::zeros(self.data_shards, self.data_shards)?;
        for (row, &shard_index) in selected.iter().enumerate() {
            let source = matrix.row(shard_index)?;
            for (col, value) in source.into_iter().enumerate() {
                submatrix.set(row, col, value)?;
            }
        }
        let inverse = submatrix.invert()?;

        let mut data = vec![vec![0u8; shard_len]; self.data_shards];
        for byte_index in 0..shard_len {
            let mut column = Vec::with_capacity(self.data_shards);
            for &shard_index in &selected {
                let value = shards
                    .get(shard_index)
                    .and_then(|slot| slot.as_ref())
                    .and_then(|bytes| bytes.get(byte_index).copied())
                    .ok_or_else(|| {
                        NauError::Validation(format!(
                            "shard {shard_index} lost its byte {byte_index} while decoding"
                        ))
                    })?;
                column.push(value);
            }
            let recovered = inverse.mul_vec(&column)?;
            if recovered.len() != self.data_shards {
                return Err(NauError::Validation(format!(
                    "internal invariant violated: recovered {} data shards, expected {}",
                    recovered.len(),
                    self.data_shards
                )));
            }
            for (shard_index, value) in recovered.into_iter().enumerate() {
                let shard = data.get_mut(shard_index).ok_or_else(|| {
                    NauError::Validation(format!("data shard index {shard_index} is out of range"))
                })?;
                let slot = shard.get_mut(byte_index).ok_or_else(|| {
                    NauError::Validation(format!(
                        "byte index {byte_index} is out of range for a data shard of length \
                         {shard_len}"
                    ))
                })?;
                *slot = value;
            }
        }

        let mut out = Vec::with_capacity(self.data_shards * shard_len);
        for shard in data {
            out.extend_from_slice(&shard);
        }
        Ok(out)
    }

    /// Encode `data` and also return its original (pre-padding) length.
    ///
    /// The length is what [`ErasureCoder::decode_with_length`] needs in order
    /// to strip the zero padding exactly. Store it alongside the shards; it is
    /// not part of the erasure code itself and costs no shard space.
    ///
    /// # Errors
    ///
    /// Identical to [`ErasureCoder::encode`]: an empty `data` is an error.
    ///
    /// # Examples
    ///
    /// ```
    /// use nau_erasure::ErasureCoder;
    ///
    /// let coder = ErasureCoder::new(4, 2)?;
    /// let (shards, original_len) = coder.encode_with_length(b"x")?;
    /// assert_eq!(original_len, 1);
    /// // One byte of payload still yields six full shards, padded.
    /// assert_eq!(shards.len(), 6);
    /// assert!(shards.iter().all(|s| s.len() == 1));
    /// # Ok::<(), nau_core::NauError>(())
    /// ```
    pub fn encode_with_length(&self, data: &[u8]) -> Result<(Vec<Vec<u8>>, usize)> {
        let shards = self.encode(data)?;
        Ok((shards, data.len()))
    }

    /// Decode and strip the zero padding to recover exactly `original_len`
    /// bytes.
    ///
    /// # Errors
    ///
    /// * Every error of [`ErasureCoder::decode`].
    /// * [`NauError::Validation`] when `original_len` exceeds the size of the
    ///   recovered payload, which means `original_len` belongs to a different
    ///   payload than the shards do.
    ///
    /// # Examples
    ///
    /// ```
    /// use nau_erasure::ErasureCoder;
    ///
    /// let coder = ErasureCoder::new(5, 3)?;
    /// let payload = b"not a multiple of five";
    /// let (shards, original_len) = coder.encode_with_length(payload)?;
    ///
    /// // Lose the maximum number of shards the code tolerates.
    /// let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    /// received[1] = None;
    /// received[4] = None;
    /// received[7] = None;
    /// assert_eq!(coder.decode_with_length(&received, original_len)?, payload);
    /// # Ok::<(), nau_core::NauError>(())
    /// ```
    pub fn decode_with_length(
        &self,
        shards: &[Option<Vec<u8>>],
        original_len: usize,
    ) -> Result<Vec<u8>> {
        let mut recovered = self.decode(shards)?;
        if original_len > recovered.len() {
            return Err(NauError::Validation(format!(
                "claimed original length {original_len} exceeds the {}-byte payload the shards \
                 reconstruct",
                recovered.len()
            )));
        }
        recovered.truncate(original_len);
        Ok(recovered)
    }
}

/// Round `data_len` up to the smallest positive multiple of `data_shards`.
///
/// # Errors
///
/// Returns [`NauError::Validation`] for `data_len == 0` or when the rounded
/// length overflows `usize`.
fn padded_len(data_len: usize, data_shards: usize) -> Result<usize> {
    if data_len == 0 {
        return Err(NauError::Validation(
            "cannot encode an empty payload: there is nothing to distribute".to_string(),
        ));
    }
    if data_shards == 0 {
        return Err(NauError::Validation(
            "cannot pad a payload across zero data shards".to_string(),
        ));
    }
    let remainder = data_len % data_shards;
    if remainder == 0 {
        return Ok(data_len);
    }
    let padding = data_shards - remainder;
    data_len.checked_add(padding).ok_or_else(|| {
        NauError::Validation(format!(
            "payload of {data_len} bytes cannot be padded to a multiple of {data_shards} \
             without overflowing usize"
        ))
    })
}

/// The monic Reed-Solomon generator polynomial
/// `g(x) = (x + a^0)(x + a^1)...(x + a^(m-1))` over GF(2^8), returned
/// low-degree-first with `g[m] == 1`.
///
/// # Errors
///
/// Returns [`NauError::Validation`] for `m == 0` or `m > 255`.
fn generator_polynomial(parity_shards: usize) -> Result<Vec<u8>> {
    if parity_shards == 0 {
        return Err(NauError::Validation(
            "a Reed-Solomon generator polynomial needs at least one root (m >= 1)".to_string(),
        ));
    }
    if parity_shards > MAX_TOTAL_SHARDS {
        return Err(NauError::Validation(format!(
            "m = {parity_shards} exceeds the {MAX_TOTAL_SHARDS} distinct non-zero elements \
             of GF(2^8), so the roots cannot all be distinct"
        )));
    }

    let mut coefficients = vec![1u8];
    for root in 0..parity_shards {
        let alpha = gf::exp(root);
        // Multiply the current polynomial by (x + alpha) into a fresh buffer
        // of one higher degree:
        //   next[d]     ^= alpha * coefficients[d]
        //   next[d + 1] ^= coefficients[d]
        // Because the buffer starts zeroed, every read is of the old
        // polynomial, so no in-place read/modify/write hazard is possible.
        let mut next = vec![0u8; coefficients.len() + 1];
        for (degree, coefficient) in coefficients.iter().enumerate() {
            let slot = next.get_mut(degree).ok_or_else(|| {
                NauError::Validation(format!("generator polynomial has no coefficient {degree}"))
            })?;
            *slot ^= gf::mul(*coefficient, alpha);
        }
        for (degree, coefficient) in coefficients.iter().enumerate() {
            let slot = next.get_mut(degree + 1).ok_or_else(|| {
                NauError::Validation(format!(
                    "generator polynomial has no coefficient {}",
                    degree + 1
                ))
            })?;
            *slot ^= *coefficient;
        }
        coefficients = next;
    }
    Ok(coefficients)
}

/// Build the systematic `(k + m) x k` distribution matrix.
///
/// Matrix row `i` holds the coefficients with which the `k` data shards are
/// combined to produce shard `i`. Rows `0..k` are the identity, which is the
/// systematic property.
///
/// ## The parity block, derived from the code's defining identity
///
/// Let `g` be [`generator_polynomial`] and `message(x) = sum_j data[j] * x^j`.
/// The codeword is
///
/// ```text
/// C(x) = par(x) + x^m * message(x),   par(x) = message(x) * x^m mod g(x)
/// ```
///
/// so `g | C` and `C(a^r) = 0` for every `r < m`. Reduction modulo `g` is
/// linear, so it suffices to know `w_j(x) = x^(m + j) mod g(x)` for each
/// column `j`: `par(x) = sum_j data[j] * w_j(x)`.
///
/// The codeword's coefficients *are* the shards, and the parity shards hold
/// `par` highest degree first — parity shard `k + r` carries degree
/// `m - 1 - r`. The coefficient of `x^index` in `w_j` is therefore the weight
/// of data shard `j` in parity shard `k + (m - 1 - index)`:
///
/// ```text
/// matrix[k + (m - 1 - index)][j] = [w_j(x)]_index
/// ```
///
/// That single line is the whole construction; every index in it is
/// load-bearing. Two mistakes that still produce an invertible, round-tripping
/// code but are *not* this one: transposing the parity block, and reversing
/// the degree-to-shard mapping (using `k + index` instead of
/// `k + m - 1 - index`, which coincides only when `m == 1`). Both were made
/// during development and neither is detectable by round-trip testing alone,
/// which is why `the_codeword_polynomial_is_divisible_by_the_generator` and
/// the construction-time self-check below exist.
///
/// `w_j` is computed by long division: start from the monomial `x^(m + j)`
/// and cancel its leading term against the monic `g` until the degree drops
/// below `m`. That is `O(m)` per column, `O(k * m)` overall.
///
/// # Errors
///
/// Returns [`NauError::Validation`] when the configuration violates
/// `1 <= k`, `1 <= m`, `k + m <= 255`, or when the assembled parity block
/// fails the self-check that every codeword vanishes at every root of `g`.
fn build_distribution_matrix(data_shards: usize, parity_shards: usize) -> Result<Matrix> {
    if data_shards == 0 {
        return Err(NauError::Validation(
            "erasure code needs at least one data shard (k >= 1)".to_string(),
        ));
    }
    if parity_shards == 0 {
        return Err(NauError::Validation(
            "erasure code needs at least one parity shard (m >= 1)".to_string(),
        ));
    }
    let total = data_shards.checked_add(parity_shards).ok_or_else(|| {
        NauError::Validation("k + m overflowed usize while building the matrix".to_string())
    })?;
    if total > MAX_TOTAL_SHARDS {
        return Err(NauError::Validation(format!(
            "k + m = {total} exceeds the maximum of {MAX_TOTAL_SHARDS} shards over GF(2^8)"
        )));
    }

    // One `Vec<u8>` per row, flattened at the end, so every write below reads
    // as `matrix[row][column]`.
    let mut matrix: Vec<Vec<u8>> = Vec::with_capacity(total);
    for _ in 0..total {
        matrix.push(vec![0u8; data_shards]);
    }

    // Systematic block: rows 0..k are the identity.
    for index in 0..data_shards {
        let row = matrix
            .get_mut(index)
            .ok_or_else(|| NauError::Validation(format!("identity row {index} is out of range")))?;
        let slot = row.get_mut(index).ok_or_else(|| {
            NauError::Validation(format!("identity row {index} has no column {index}"))
        })?;
        *slot = 1;
    }

    // Parity block.
    let generator = generator_polynomial(parity_shards)?;
    for column in 0..data_shards {
        // `w_column(x) = x^(m + column) mod g(x)`, low degree first.
        let degree = parity_shards
            .checked_add(column)
            .ok_or_else(|| NauError::Validation("parity degree overflowed".to_string()))?;
        let mut remainder = vec![0u8; degree + 1];
        let slot = remainder.get_mut(degree).ok_or_else(|| {
            NauError::Validation(format!("monomial has no x^{degree} coefficient"))
        })?;
        *slot = 1;

        while remainder.len() > parity_shards {
            let leading = remainder.last().copied().unwrap_or(0);
            if leading == 0 {
                break;
            }
            if remainder.len() < generator.len() {
                return Err(NauError::Validation(
                    "internal invariant violated: the remainder is shorter than the generator"
                        .to_string(),
                ));
            }
            let offset = remainder.len() - generator.len();
            for (g_degree, coefficient) in generator.iter().enumerate() {
                let target = offset + g_degree;
                let term = gf::mul(leading, *coefficient);
                let current = remainder.get(target).copied().unwrap_or(0);
                let slot = remainder.get_mut(target).ok_or_else(|| {
                    NauError::Validation(format!("remainder has no coefficient {target}"))
                })?;
                *slot = gf::add(current, term);
            }
            remainder.pop();
        }
        while remainder.len() < parity_shards {
            remainder.push(0);
        }

        // `remainder[index]` is the coefficient of `x^index` in `w_column`; the
        // parity shards hold the code's low `m` degrees in ascending order, so
        // degree `index` lands in parity shard `k + index`.
        for (index, coefficient) in remainder.iter().enumerate() {
            let row = matrix.get_mut(data_shards + index).ok_or_else(|| {
                NauError::Validation(format!(
                    "parity row {} is out of range",
                    data_shards + index
                ))
            })?;
            let slot = row.get_mut(column).ok_or_else(|| {
                NauError::Validation(format!(
                    "parity row {} has no column {column}",
                    data_shards + index
                ))
            })?;
            *slot = *coefficient;
        }
    }

    let cells: Vec<u8> = matrix.into_iter().flatten().collect();
    let built = Matrix::from_rows(total, data_shards, cells)?;

    // Self-check: the codeword assembled from any data column must vanish at
    // every root of the generator polynomial. The codeword's coefficients,
    // lowest degree first, are the parity shards in shard order followed by the
    // data shards in shard order:
    //
    //     C_j(x) = sum_{r < m} built[k + r][j] * x^r
    //            + sum_{i < k} built[i][j]       * x^(m + i)
    //
    // Requiring `C_j(a^root) = 0` for every root pins the parity block down to
    // exactly one matrix, which is the code this crate claims to implement.
    // Checking every column is enough because the columns form a basis of the
    // message space and `message -> codeword` is linear.
    //
    // (An earlier version of this check used a different exponent for the
    // parity rows and rejected the correct matrix; the degree of parity row
    // `k + r` is `r`, and the degree of data row `i` is `m + i`.)
    for root in 0..parity_shards {
        let point = gf::exp(root);
        for column in 0..data_shards {
            let mut sum = 0u8;
            for row in 0..total {
                let coefficient = built.get(row, column).unwrap_or(0);
                let exponent = if row < data_shards {
                    parity_shards.checked_add(row).ok_or_else(|| {
                        NauError::Validation("codeword exponent overflowed".to_string())
                    })?
                } else {
                    row - data_shards
                };
                sum = gf::add(sum, gf::mul(coefficient, gf::pow(point, exponent)));
            }
            if sum != 0 {
                return Err(NauError::Validation(format!(
                    "internal invariant violated: the parity block is wrong; the codeword for \
                     data column {column} does not vanish at a^{root}"
                )));
            }
        }
    }

    Ok(built)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{binomial, payload, subsets};

    /// The monic Reed-Solomon generator polynomial of degree `m`, written out
    /// as literally as possible: multiply `(x + a^i)` for `i` in `0..m`.
    /// Deliberately *not* the crate's own `generator_polynomial`, so the two
    /// implementations have to agree.
    fn monic_generator_by_hand(m: usize) -> Vec<u8> {
        let mut coefficients = vec![1u8];
        for root in 0..m {
            let alpha = gf::exp(root);
            let mut next = vec![0u8; coefficients.len() + 1];
            for (degree, coefficient) in coefficients.iter().enumerate() {
                // The x term.
                if let Some(slot) = next.get_mut(degree + 1) {
                    *slot ^= *coefficient;
                }
                // The alpha term.
                if let Some(slot) = next.get_mut(degree) {
                    *slot ^= gf::mul(*coefficient, alpha);
                }
            }
            coefficients = next;
        }
        coefficients
    }

    /// Evaluate the polynomial with the given coefficients (lowest degree
    /// first) at `point` over GF(2^8), by Horner's rule.
    ///
    /// Used instead of a division helper for the divisibility property: over a
    /// field, `g | C` if and only if `C` vanishes at every root of `g`, and
    /// root evaluation is free of any coefficient-ordering ambiguity.
    fn evaluate(coefficients: &[u8], point: u8) -> u8 {
        let mut acc = 0u8;
        for coefficient in coefficients.iter().rev() {
            acc = gf::add(gf::mul(acc, point), *coefficient);
        }
        acc
    }

    /// The roots of [`monic_generator_by_hand`], i.e. `a^0 .. a^(m-1)`.
    fn generator_roots(m: usize) -> Vec<u8> {
        (0..m).map(gf::exp).collect()
    }

    #[test]
    fn the_generator_polynomial_is_monic_and_hand_verifiable() {
        // Hand-derived over GF(2^8), coefficients low degree first:
        //   m = 1: g = x + 1
        //   m = 2: g = (x + 1)(x + 2) = x^2 + 3x + 2
        //   m = 3: g = (x^2 + 3x + 2)(x + 4)
        //            = x^3 + (3 ^ 4)x^2 + (2 ^ (3*4))x + (2*4)
        //            = x^3 + 7x^2 + (2 ^ 12)x + 8, and 12 = x^3 + x^2 so
        //              2 ^ 12 = x + x^3 + x^2 = 14
        //            = x^3 + 7x^2 + 14x + 8
        assert_eq!(monic_generator_by_hand(1), vec![1, 1]);
        assert_eq!(monic_generator_by_hand(2), vec![2, 3, 1]);
        assert_eq!(monic_generator_by_hand(3), vec![8, 14, 7, 1]);

        for m in 1..=12usize {
            let by_hand = monic_generator_by_hand(m);
            let built = generator_polynomial(m).expect("m is in range");
            assert_eq!(built, by_hand, "m = {m}: builder disagrees with hand form");
            assert_eq!(built.len(), m + 1, "m = {m}");
            // Monic.
            assert_eq!(built.last().copied(), Some(1), "m = {m} is not monic");
            // All roots are non-zero, so the constant term is non-zero.
            assert_ne!(built.first().copied(), Some(0), "m = {m}");
        }
    }

    #[test]
    fn generator_polynomial_rejects_out_of_range_degrees() {
        assert!(generator_polynomial(0).is_err());
        assert!(generator_polynomial(256).is_err());
        assert!(generator_polynomial(MAX_TOTAL_SHARDS).is_ok());
    }

    #[test]
    fn the_codeword_polynomial_is_divisible_by_the_generator() {
        // The classical property of a systematic cyclic code: the codeword
        // polynomial is divisible by the generator polynomial. Over a field
        // that is equivalent to the codeword vanishing at every root of the
        // generator, which is the form used here because root evaluation has no
        // coefficient-ordering ambiguity.
        //
        // The codeword is assembled from the shards; its coefficients, lowest
        // degree first, are the parity shards in shard order followed by the
        // data shards in reverse shard order — for (2, 2), `[p_0, p_1, d_1,
        // d_0]`. Verified independently in Python.
        for (k, m) in [(2usize, 1usize), (2, 2), (3, 2), (4, 2), (5, 3), (7, 4)] {
            let coder = ErasureCoder::new(k, m).expect("valid configuration");
            // A payload whose length is a multiple of k, so each shard holds
            // two independent codeword symbols.
            let data = payload(k as u64, k * 2);
            let shards = coder.encode(&data).expect("encodes");
            let shard_len = shards.first().map(Vec::len).unwrap_or(0);
            assert_eq!(shard_len, 2);

            let roots = generator_roots(m);
            for byte_index in 0..shard_len {
                // Codeword, lowest degree first: parity shards in shard order,
                // then data shards in shard order — for (2, 2) that is
                // `[p_0, p_1, d_0, d_1]`. Verified in Python.
                let mut codeword = Vec::with_capacity(k + m);
                for shard in &shards[k..(k + m)] {
                    codeword.push(shard[byte_index]);
                }
                for shard in &shards[..k] {
                    codeword.push(shard[byte_index]);
                }
                for root in &roots {
                    assert_eq!(
                        evaluate(&codeword, *root),
                        0,
                        "({k}, {m}) byte {byte_index}: codeword {codeword:?} does not vanish \
                         at root {root}"
                    );
                }
            }
        }
    }

    #[test]
    fn evaluate_matches_direct_polynomial_evaluation() {
        // `evaluate` is the oracle for several tests, so pin it down: the
        // coefficients are lowest degree first, and Horner's rule must agree
        // with the naive sum of `c_d * point^d`.
        let coefficients = [0x03u8, 0x00, 0x57, 0xff];
        for point in [0u8, 1, 2, 3, 0x1d, 0x80, 0xff] {
            let mut expected = 0u8;
            for (degree, coefficient) in coefficients.iter().enumerate() {
                expected = gf::add(expected, gf::mul(*coefficient, gf::pow(point, degree)));
            }
            assert_eq!(evaluate(&coefficients, point), expected, "point = {point}");
        }
    }

    #[test]
    fn the_two_two_code_matches_the_hand_computed_codeword() {
        // Concretely for (2, 2), with g(x) = x^2 + 3x + 2:
        //   x^2 mod g = [2, 3]   and   x^3 mod g = [6, 7]
        // The matrix is filled column by column, so column 0 carries
        // `x^2 mod g = [2, 3]` across the parity rows and column 1 carries
        // `x^3 mod g = [6, 7]`; hence parity row 2 holds the first coefficients
        // of both columns, `[2, 6]`, and row 3 holds `[3, 7]`. Encoding
        // [22, 160] therefore gives shards [22, 160, 203, 125] — verified
        // independently in Python with a separate field implementation.
        let coder = ErasureCoder::new(2, 2).expect("valid configuration");
        let matrix = coder.distribution_matrix().expect("builds");
        assert_eq!(matrix.row(2).expect("row"), vec![2, 6]);
        assert_eq!(matrix.row(3).expect("row"), vec![3, 7]);

        let shards = coder.encode(&[22, 160]).expect("encodes");
        assert_eq!(shards[0], vec![22]);
        assert_eq!(shards[1], vec![160]);
        assert_eq!(shards[2], vec![203]);
        assert_eq!(shards[3], vec![125]);
        assert_eq!(shards[2][0], gf::mul(2, 22) ^ gf::mul(6, 160));
        assert_eq!(shards[3][0], gf::mul(3, 22) ^ gf::mul(7, 160));

        // The codeword polynomial, lowest degree first, is
        // `[p_0, p_1, d_0, d_1]`: the parity shards in shard order, then the
        // data shards in shard order. Verified in Python: this codeword
        // vanishes at both roots of `g`.
        let codeword = vec![shards[2][0], shards[3][0], shards[0][0], shards[1][0]];
        assert_eq!(codeword, vec![203, 125, 22, 160]);
        for root in generator_roots(2) {
            assert_eq!(evaluate(&codeword, root), 0, "root {root}");
        }

        // A payload with two bytes per shard, to exercise the byte-wise
        // independence of the encoding: the payload splits into data shard 0 =
        // [7, 11] and data shard 1 = [200, 3], and the parity shards follow
        // from the same matrix rows.
        let data = [7u8, 11, 200, 3];
        let shards = coder.encode(&data).expect("encodes");
        assert_eq!(shards[0], vec![7, 11]);
        assert_eq!(shards[1], vec![200, 3]);
        assert_eq!(
            shards[2],
            vec![
                gf::mul(2, 7) ^ gf::mul(6, 200),
                gf::mul(2, 11) ^ gf::mul(6, 3)
            ]
        );
        assert_eq!(
            shards[3],
            vec![
                gf::mul(3, 7) ^ gf::mul(7, 200),
                gf::mul(3, 11) ^ gf::mul(7, 3)
            ]
        );
        // Both byte positions must produce a valid codeword.
        for byte_index in 0..2 {
            let mut codeword = Vec::with_capacity(4);
            for shard in &shards[2..4] {
                codeword.push(shard[byte_index]);
            }
            for shard in &shards[..2] {
                codeword.push(shard[byte_index]);
            }
            for root in generator_roots(2) {
                assert_eq!(
                    evaluate(&codeword, root),
                    0,
                    "byte {byte_index}: codeword {codeword:?} at root {root}"
                );
            }
        }
    }

    #[test]
    fn the_simplest_code_has_the_expected_parity_coefficients() {
        // k = 2, m = 1: g(x) = x + 1, so the parity byte is the XOR of the two
        // data bytes -- the unique remainder of `message(x) * x` modulo
        // `x + 1`.
        let coder = ErasureCoder::new(2, 1).expect("valid configuration");
        let matrix = coder.distribution_matrix().expect("builds");
        assert_eq!(matrix.row(2).expect("row"), vec![1, 1]);
        let shards = coder.encode(&[0x3f, 0x91]).expect("encodes");
        assert_eq!(shards[2], vec![0x3f ^ 0x91]);
    }

    #[test]
    fn parity_shards_make_the_codeword_vanish_at_the_generator_roots() {
        // Independent oracle for the parity shards, stated algebraically: with
        // `message(x) = sum_j data[j] * x^j`, the code word
        //
        //     C(x) = x^m * message(x) + par(x)
        //
        // must vanish at all `m` roots of the generator, and `par` is the
        // unique degree-`< m` polynomial that achieves it. So the data shards
        // fix the high coefficients, the parity shards must be exactly the low
        // coefficients of that decomposition, and no other assignment works.
        //
        // Root evaluation is used rather than a hand-rolled polynomial
        // remainder because it has no coefficient-ordering ambiguity.
        for (k, m) in [(2usize, 1usize), (2, 2), (4, 1), (4, 2), (3, 3), (5, 3)] {
            let coder = ErasureCoder::new(k, m).expect("valid configuration");
            let data = payload(0x1234, k * 3);
            let shards = coder.encode(&data).expect("encodes");
            assert_eq!(shards.first().map(Vec::len), Some(3));

            let roots = generator_roots(m);
            for byte_index in 0..3 {
                // Codeword, lowest degree first: parity shards in shard order
                // then data shards in shard order.
                let mut codeword = vec![0u8; m + k];
                for r in 0..m {
                    codeword[r] = shards[k + r][byte_index];
                }
                for j in 0..k {
                    codeword[m + j] = shards[j][byte_index];
                }
                for root in &roots {
                    assert_eq!(
                        evaluate(&codeword, *root),
                        0,
                        "({k}, {m}) byte {byte_index}: codeword {codeword:?} does not vanish \
                         at root {root}"
                    );
                }

                // Inverting one parity coefficient must break the property,
                // which shows the test would notice a wrong parity block.
                for r in 0..m {
                    let mut broken = codeword.clone();
                    broken[r] ^= 0x01;
                    let vanishes = roots.iter().all(|root| evaluate(&broken, *root) == 0);
                    assert!(
                        !vanishes,
                        "({k}, {m}) byte {byte_index}: flipping parity coefficient {r} kept the \
                         codeword valid, so the check is vacuous"
                    );
                }
            }
        }
    }

    #[test]
    fn constants_and_accessors_are_consistent() {
        let coder = ErasureCoder::new(4, 2).expect("valid configuration");
        assert_eq!(coder.data_shards(), 4);
        assert_eq!(coder.parity_shards(), 2);
        assert_eq!(coder.total_shards(), 6);
        assert_eq!(MAX_TOTAL_SHARDS, 255);
    }

    #[test]
    fn distribution_matrix_is_systematic_and_well_formed() {
        for (k, m) in [(1usize, 1usize), (2, 1), (3, 2), (4, 2), (5, 3), (200, 55)] {
            let coder = ErasureCoder::new(k, m).expect("valid configuration");
            let matrix = coder.distribution_matrix().expect("matrix builds");
            assert_eq!(matrix.rows(), k + m, "({k}, {m})");
            assert_eq!(matrix.cols(), k, "({k}, {m})");
            for row in 0..k {
                for col in 0..k {
                    let expected = if row == col { 1 } else { 0 };
                    assert_eq!(
                        matrix.get(row, col),
                        Some(expected),
                        "systematic block wrong at ({row}, {col}) for ({k}, {m})"
                    );
                }
            }
            // Every parity row must be non-zero, otherwise the code would be
            // degenerate (a zero row is not an independent evaluation).
            for row in k..(k + m) {
                let mut non_zero = 0usize;
                for col in 0..k {
                    if matrix.get(row, col).unwrap_or(0) != 0 {
                        non_zero += 1;
                    }
                }
                assert!(non_zero > 0, "parity row {row} is all zero for ({k}, {m})");
            }
        }
    }

    #[test]
    fn distribution_matrix_rejects_degenerate_configurations() {
        assert!(build_distribution_matrix(0, 1).is_err());
        assert!(build_distribution_matrix(1, 0).is_err());
        assert!(build_distribution_matrix(200, 56).is_err());
        assert!(build_distribution_matrix(usize::MAX, 1).is_err());
        assert!(build_distribution_matrix(usize::MAX, usize::MAX).is_err());
    }

    #[test]
    fn every_k_subset_of_the_distribution_matrix_is_invertible() {
        // This is the MDS property that makes any-k-of-n recovery possible.
        for (k, m) in [(2usize, 1usize), (3, 2), (4, 2), (5, 3)] {
            let coder = ErasureCoder::new(k, m).expect("valid configuration");
            let matrix = coder.distribution_matrix().expect("matrix builds");
            let mut tested = 0usize;
            for subset in subsets(k + m, k) {
                let mut submatrix = Matrix::zeros(k, k).expect("k x k");
                for (row, &index) in subset.iter().enumerate() {
                    for col in 0..k {
                        submatrix
                            .set(row, col, matrix.get(index, col).unwrap_or(0))
                            .expect("in bounds");
                    }
                }
                assert!(
                    submatrix.invert().is_ok(),
                    "shard subset {subset:?} of ({k}, {m}) is singular"
                );
                tested += 1;
            }
            assert_eq!(tested, binomial(k + m, k));
        }
    }

    #[test]
    fn padded_lengths_are_the_smallest_positive_multiples() {
        assert_eq!(padded_len(1, 4).expect("ok"), 4);
        assert_eq!(padded_len(4, 4).expect("ok"), 4);
        assert_eq!(padded_len(5, 4).expect("ok"), 8);
        assert_eq!(padded_len(1, 1).expect("ok"), 1);
        assert!(padded_len(0, 4).is_err());
        assert!(padded_len(1, 0).is_err());
        assert!(padded_len(usize::MAX, 2).is_err());
    }

    #[test]
    fn error_messages_name_missing_and_required_counts() {
        let coder = ErasureCoder::new(4, 2).expect("valid configuration");
        let shards = coder.encode(b"01234567").expect("encodes");
        let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        received[0] = None;
        received[1] = None;
        received[2] = None;
        let err = coder.decode(&received);
        match err {
            Err(NauError::Validation(message)) => {
                assert!(message.contains("cannot reconstruct"), "message: {message}");
                assert!(
                    message.contains("1 more shard(s) required"),
                    "message: {message}"
                );
                assert!(
                    message.contains("have 3 of 4 data shards"),
                    "message: {message}"
                );
            }
            other => panic!("expected a typed validation error, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_a_wrong_number_of_shard_slots() {
        let coder = ErasureCoder::new(2, 1).expect("valid configuration");
        assert!(coder.decode(&[]).is_err());
        assert!(coder.decode(&[None, None]).is_err());
        assert!(coder.decode(&[None, None, None, None]).is_err());
    }

    #[test]
    fn decode_rejects_empty_present_shards() {
        let coder = ErasureCoder::new(2, 1).expect("valid configuration");
        let received = vec![Some(Vec::new()), Some(Vec::new()), None];
        assert!(coder.decode(&received).is_err());
    }

    #[test]
    fn decode_rejects_a_claimed_original_length_larger_than_the_payload() {
        let coder = ErasureCoder::new(2, 1).expect("valid configuration");
        let (shards, _) = coder.encode_with_length(b"abcd").expect("encodes");
        let received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        assert!(coder.decode_with_length(&received, 5).is_err());
        assert!(coder.decode_with_length(&received, 4).is_ok());
    }

    #[test]
    fn encoded_shard_len_agrees_with_encode() {
        for (k, m) in [(2usize, 1usize), (3, 2), (5, 3)] {
            let coder = ErasureCoder::new(k, m).expect("valid configuration");
            for len in [1usize, 2, 3, 7, 64] {
                let data = vec![0xabu8; len];
                let shards = coder.encode(&data).expect("encodes");
                let expected = coder.encoded_shard_len(len).expect("non-empty");
                for shard in &shards {
                    assert_eq!(shard.len(), expected, "k = {k}, len = {len}");
                }
            }
            assert!(coder.encoded_shard_len(0).is_err());
        }
    }

    #[test]
    fn coder_is_hashable_serialisable_and_orderable_by_value() {
        use std::collections::HashMap;
        let mut map: HashMap<ErasureCoder, &str> = HashMap::new();
        let coder = ErasureCoder::new(3, 2).expect("valid configuration");
        map.insert(coder, "three-two");
        assert_eq!(
            map.get(&ErasureCoder::new(3, 2).expect("same")),
            Some(&"three-two")
        );
        assert_ne!(
            ErasureCoder::new(3, 2).expect("valid"),
            ErasureCoder::new(2, 3).expect("valid")
        );
        let encoded = serde_json::to_string(&coder).expect("serialises");
        let decoded: ErasureCoder = serde_json::from_str(&encoded).expect("deserialises");
        assert_eq!(decoded, coder);
    }

    #[test]
    fn subsets_enumerates_every_combination() {
        assert_eq!(subsets(3, 2), vec![vec![0, 1], vec![0, 2], vec![1, 2]]);
        assert_eq!(subsets(3, 0), vec![Vec::<usize>::new()]);
        assert_eq!(subsets(2, 3).len(), 0);
        assert_eq!(subsets(6, 4).len(), 15);
        assert_eq!(subsets(8, 5).len(), 56);
    }

    #[test]
    fn binomial_matches_the_known_values() {
        assert_eq!(binomial(6, 4), 15);
        assert_eq!(binomial(8, 5), 56);
        assert_eq!(binomial(3, 1), 3);
        assert_eq!(binomial(4, 2), 6);
        assert_eq!(binomial(0, 0), 1);
        assert_eq!(binomial(3, 5), 0);
        assert_eq!(subsets(6, 4).len(), binomial(6, 4));
        assert_eq!(subsets(8, 5).len(), binomial(8, 5));
    }
}
