//! # nau-erasure — real Reed-Solomon erasure coding over GF(2^8)
//!
//! This crate replaces upstream `agent-universe` v2.5.6's
//! `gsn-core/src/erasure/mod.rs`, whose confirmed defect is documented in
//! `docs/GAP-ANALYSIS.md` §7.8 (evidence `erasure/mod.rs:92-111`) and restated
//! in `ATTRIBUTION.md` §2.3:
//!
//! ```text
//! pub fn decode(&self, shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>, ...> {
//!     // requires data_shards_available.len() >= self.data_shards
//!     // ... then CONCATENATES DATA SHARDS ONLY
//! }
//! ```
//!
//! Upstream built "parity" shards out of SHA-256 digests that were **never
//! used for reconstruction**. `ErasureCoder::new(4, 2)` therefore could not
//! recover a single lost byte even though its own module doc promised
//! "丢失部分分片仍可恢复", and its integration test "simulated" the loss of two
//! shards by handing `decode` the four *data* shards — so the recovery path
//! was never executed. See [`ErasureCoder`].
//!
//! ```text
//! // upstream v2.5.6 fix: real RS decoding - any k of the n shards
//! // reconstruct the data, instead of concatenating whichever data shards
//! // happen to be present and ignoring parity entirely.
//! ```
//!
//! ## Honest scope
//!
//! **Implemented:**
//!
//! * systematic Reed-Solomon encoding over `GF(2^8)` with primitive
//!   polynomial `0x11d` (the Backblaze / ISA-L / `zfec` polynomial);
//! * reconstruction from **any `k` of `n`** shards, data or parity, via
//!   Gauss-Jordan inversion of the `k x k` submatrix of the distribution
//!   matrix — verified for *every* `k`-subset of `(k, m)` in
//!   `{(2,1), (3,2), (4,2), (5,3)}`;
//! * exact payload lengths through [`ErasureCoder::encode_with_length`] and
//!   [`ErasureCoder::decode_with_length`];
//! * the full `k + m <= 255` range, including the `k = 200, m = 55` boundary.
//!
//! **NOT implemented:**
//!
//! * **Error correction.** Reed-Solomon can correct *errors* (corruption at
//!   unknown positions) as well as *erasures* (loss at known positions). This
//!   crate implements **erasures only**. There is no Berlekamp-Massey, no
//!   Forney algorithm and no syndrome table. A shard that is *present but
//!   corrupt* is taken at face value and produces **silently wrong output**:
//!   see the test
//!   `corrupted_present_shard_yields_wrong_output_and_is_not_detected`, which
//!   asserts that wrongness on purpose. Detecting corruption requires a
//!   checksum or MAC layer *above* this crate, verified before `decode`, which
//!   promotes an error into an erasure.
//! * **Confidentiality.** Shards are plaintext; erasure coding is not
//!   encryption.
//! * **Any I/O, networking or shard placement.** Distribution is the caller's
//!   problem. This crate is pure computation.
//! * **Cross-implementation interoperability.** The construction is textbook
//!   systematic RS over `0x11d`, but no external RS library was cross-checked,
//!   so do not assume byte compatibility with one.
//!
//! ## Design rules
//!
//! 1. **No `unsafe`.** `#![forbid(unsafe_code)]` is enforced crate-wide.
//! 2. **No panics on any input.** There is no `unwrap`, `expect` or `panic!`
//!    outside `#[cfg(test)]`. Division by zero in GF(256) — the only operation
//!    with no field answer — returns [`nau_core::NauError::Validation`].
//! 3. **No floating point.** Every value is a byte or a `usize` count.
//! 4. **Tables built once.** `exp`/`log`/`inverse` live behind a
//!    [`OnceLock`](std::sync::OnceLock), so construction cost is paid at most
//!    once per process.
//! 5. **Typed failure.** Every public fallible method returns
//!    [`nau_core::Result`].
//!
//! ## Example
//!
//! ```
//! use nau_erasure::ErasureCoder;
//!
//! let coder = ErasureCoder::new(4, 2)?; // survives any 2 losses
//! let payload = b"distribute me across six shards";
//! let (shards, original_len) = coder.encode_with_length(payload)?;
//!
//! // Lose two data shards: exactly what upstream could not survive.
//! let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
//! received[0] = None;
//! received[2] = None;
//!
//! assert_eq!(coder.decode_with_length(&received, original_len)?, payload);
//! # Ok::<(), nau_core::NauError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod coder;
pub mod gf;
pub mod matrix;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
#[cfg(test)]
mod testutil;

pub use coder::{ErasureCoder, MAX_TOTAL_SHARDS};
pub use gf::PRIMITIVE_POLYNOMIAL;
pub use matrix::Matrix;
