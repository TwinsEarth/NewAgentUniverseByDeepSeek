//! Image manifests and content addressing.
//!
//! The unit an AUSec sandbox is created from. AUSec's premise is that an agent touches
//! only a small fraction of its image, so a manifest describes the image as **chunks**
//! that can be fetched one at a time rather than as one blob that must arrive whole.
//!
//! # What is here and what is not
//!
//! This module is pure data and no I/O, which is what [`crate`] is for. It defines what
//! an image *is* and how a chunk is *addressed*; it does not fetch anything. The reader
//! that resolves a chunk against a source arrives with A-05, and the source trait with
//! A-06 — deliberately after the vocabulary, because a manifest whose chunks have no
//! addresses cannot be fetched correctly no matter how good the fetcher is.
//!
//! # Content addressing, and why the digest is validated rather than trusted
//!
//! A chunk is named by the SHA-256 of its bytes. That makes two properties true by
//! construction, and both are load-bearing:
//!
//! * **The same content has one name.** Two images sharing a layer share its chunks, so
//!   the second one fetches nothing for the part it has in common.
//! * **A name cannot be satisfied by different content.** A source that returns the wrong
//!   bytes for a digest produces a verification failure rather than a silently corrupted
//!   sandbox — which is the whole reason to address by content instead of by index.
//!
//! A digest arriving from a manifest is therefore parsed, not assumed: [`ChunkDigest`]
//! cannot hold anything but 64 lowercase hex characters, so a malformed address is
//! refused at the boundary instead of failing later as a lookup miss.

use serde::{Deserialize, Serialize};

use crate::error::{NauError, Result};
use crate::identity::canonical::payload_digest_hex;

/// The number of hexadecimal characters in a SHA-256 digest.
const DIGEST_HEX_LEN: usize = 64;

/// A content address: the SHA-256 of a chunk's bytes, lowercase hex.
///
/// Constructed through [`ChunkDigest::of`] (from content) or [`ChunkDigest::parse`]
/// (from a manifest), never from an arbitrary string — see the module documentation for
/// why the distinction matters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChunkDigest(String);

impl ChunkDigest {
    /// The content address of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hex::encode(hasher.finalize()))
    }

    /// Parse a digest that came from outside this process.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] naming what is wrong with it. Uppercase is refused rather
    /// than folded: two spellings of one address would be two cache keys for one chunk,
    /// and the first symptom of that is a cache that misses on the content it already has.
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() != DIGEST_HEX_LEN {
            return Err(NauError::Validation(format!(
                "a chunk digest is {DIGEST_HEX_LEN} hex characters, got {}",
                text.len()
            )));
        }
        if !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(NauError::Validation(
                "a chunk digest is lowercase hexadecimal; this one is not".to_string(),
            ));
        }
        Ok(Self(text.to_string()))
    }

    /// The address as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ChunkDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where one chunk lives inside the image blob.
///
/// `offset` and `length` are redundant with the content — a reader could find the chunk by
/// scanning — and are carried anyway, because fetching a byte range is what the transport
/// can actually do. Verification does not trust them: the bytes a source returns are
/// hashed and compared against [`ChunkRef::digest`], so a wrong offset is caught the same
/// way wrong content is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    /// The chunk's content address.
    pub digest: ChunkDigest,
    /// Byte offset of the chunk within the image.
    pub offset: u64,
    /// Length of the chunk in bytes.
    pub length: u64,
}

impl ChunkRef {
    /// The half-open byte range this chunk occupies.
    ///
    /// # Errors
    ///
    /// [`NauError::Overflow`] when `offset + length` does not fit in a `u64`, which a
    /// manifest can ask for and a caller should learn about here rather than at fetch
    /// time under a partly-populated sandbox.
    pub fn range(&self) -> Result<std::ops::Range<u64>> {
        let end = self
            .offset
            .checked_add(self.length)
            .ok_or(NauError::Overflow("chunk offset + length"))?;
        Ok(self.offset..end)
    }
}

/// An image, described as ordered chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifest {
    /// The image's name, e.g. `python-3.12-slim`.
    pub name: String,
    /// Total size of the assembled image in bytes.
    pub total_bytes: u64,
    /// The chunks, in image order.
    pub chunks: Vec<ChunkRef>,
}

impl ImageManifest {
    /// Build a manifest from a whole image, chunking it into `chunk_size` pieces.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `chunk_size` is zero — a zero-size chunk would make
    /// the chunk count unbounded while covering no bytes, so it is refused rather than
    /// treated as "one big chunk" or "no chunking".
    pub fn from_bytes(name: &str, bytes: &[u8], chunk_size: usize) -> Result<Self> {
        if chunk_size == 0 {
            return Err(NauError::Validation(
                "chunk size must be greater than zero".to_string(),
            ));
        }
        let mut chunks = Vec::new();
        let mut offset = 0_u64;
        for piece in bytes.chunks(chunk_size) {
            let length = piece.len() as u64;
            chunks.push(ChunkRef {
                digest: ChunkDigest::of(piece),
                offset,
                length,
            });
            offset += length;
        }
        Ok(Self {
            name: name.to_string(),
            total_bytes: bytes.len() as u64,
            chunks,
        })
    }

    /// Check the manifest is internally consistent.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] for an empty name, an empty chunk list, a chunk that
    /// reaches past `total_bytes`, a zero-length chunk, chunks that are not in
    /// non-decreasing offset order, an overlapping pair, or chunks that do not cover
    /// `total_bytes` exactly.
    ///
    /// Coverage is checked as *exact* rather than as "within bounds". A manifest whose
    /// chunks stop short of the total describes an image with a hole in it, and a sandbox
    /// assembled from it would fail somewhere unrelated to the manifest — which is the
    /// expensive way to find out.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(NauError::Validation("an image needs a name".to_string()));
        }
        if self.chunks.is_empty() {
            return Err(NauError::Validation(format!(
                "image `{}` lists no chunks",
                self.name
            )));
        }

        let mut expected_offset = 0_u64;
        for (index, chunk) in self.chunks.iter().enumerate() {
            if chunk.length == 0 {
                return Err(NauError::Validation(format!(
                    "image `{}` chunk {index} is zero bytes long",
                    self.name
                )));
            }
            if chunk.offset != expected_offset {
                return Err(NauError::Validation(format!(
                    "image `{}` chunk {index} starts at {} but the previous chunk ended at {}",
                    self.name, chunk.offset, expected_offset
                )));
            }
            let range = chunk.range()?;
            if range.end > self.total_bytes {
                return Err(NauError::Validation(format!(
                    "image `{}` chunk {index} ends at {} which is past the declared total of {}",
                    self.name, range.end, self.total_bytes
                )));
            }
            expected_offset = range.end;
        }

        if expected_offset != self.total_bytes {
            return Err(NauError::Validation(format!(
                "image `{}` declares {} bytes but its chunks cover {}",
                self.name, self.total_bytes, expected_offset
            )));
        }
        Ok(())
    }

    /// The manifest's own content address.
    ///
    /// Computed over the canonical payload rather than over `serde_json`'s default output,
    /// so two processes that build the same manifest agree on its name. This is the value
    /// a later release signs, which is why it must be derived from the canonical form and
    /// not from whatever key order a `HashMap` happened to produce.
    ///
    /// # Errors
    ///
    /// [`NauError::Canonical`] if the manifest cannot be canonicalised.
    pub fn digest_hex(&self) -> Result<String> {
        payload_digest_hex(self).map_err(NauError::from)
    }

    /// Total bytes the chunks account for, whether or not it matches `total_bytes`.
    ///
    /// Reported separately from [`ImageManifest::validate`] because "how much do the chunks
    /// cover" is the number a reader wants when a manifest fails validation, and computing
    /// it from a `Result` that just refused would mean reimplementing the loop that refused.
    #[must_use]
    pub fn covered_bytes(&self) -> u64 {
        self.chunks.iter().map(|c| c.length).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_of(name: &str, bytes: &[u8], size: usize) -> ImageManifest {
        ImageManifest::from_bytes(name, bytes, size).expect("chunks")
    }

    #[test]
    fn the_same_content_has_the_same_address() {
        // Criterion 2 of A-04, and the property the whole deduplication story rests on: two
        // images sharing a layer must name its chunks identically, or the second one fetches
        // bytes it already has.
        let a = ChunkDigest::of(b"the same bytes");
        let b = ChunkDigest::of(b"the same bytes");
        assert_eq!(a, b);

        let one = manifest_of("a", b"0123456789abcdef", 8);
        let two = manifest_of("b", b"0123456789ABCDEF".to_ascii_lowercase().as_slice(), 8);
        assert_eq!(
            one.chunks[0].digest, two.chunks[0].digest,
            "a shared chunk must have one address"
        );
    }

    #[test]
    fn different_content_has_a_different_address() {
        assert_ne!(ChunkDigest::of(b"alpha"), ChunkDigest::of(b"beta"));
        // A one-bit change must move the address; this is what makes verification mean
        // anything.
        assert_ne!(ChunkDigest::of(b"alpha"), ChunkDigest::of(b"alphb"));
    }

    #[test]
    fn a_malformed_digest_is_refused_rather_than_stored() {
        // Criterion 3. Each of these is a shape a hand-written or corrupted manifest can
        // contain, and each must fail at parse time rather than as a lookup miss later.
        for bad in [
            "",
            "abc",
            &"a".repeat(63),
            &"a".repeat(65),
            &"A".repeat(64), // uppercase: two spellings of one address would be two cache keys
            &"g".repeat(64), // not hex
            &format!("{} ", "a".repeat(63)), // trailing space
        ] {
            assert!(
                ChunkDigest::parse(bad).is_err(),
                "{bad:?} must not parse as a digest"
            );
        }
        assert!(ChunkDigest::parse(&"0".repeat(64)).is_ok());
        assert!(ChunkDigest::parse(&"abcdef0123456789".repeat(4)).is_ok());
    }

    #[test]
    fn a_well_formed_manifest_validates_and_covers_its_total() {
        let m = manifest_of("python-3.12-slim", &[7_u8; 100], 32);
        m.validate().expect("valid");
        assert_eq!(
            m.chunks.len(),
            4,
            "100 bytes in 32-byte chunks is four chunks"
        );
        assert_eq!(m.covered_bytes(), 100);
        assert_eq!(m.total_bytes, 100);
        // Chunks are contiguous from zero.
        assert_eq!(m.chunks[0].offset, 0);
        assert_eq!(m.chunks[1].offset, 32);
        assert_eq!(m.chunks[3].range().expect("range").end, 100);
    }

    #[test]
    fn a_manifest_that_does_not_cover_its_total_is_refused() {
        // The hole case: chunks stop short. Assembling this would fail somewhere unrelated
        // to the manifest, which is the expensive way to learn about it.
        let mut m = manifest_of("holed", &[1_u8; 100], 32);
        m.total_bytes = 200;
        let err = m.validate().expect_err("must refuse");
        assert!(
            format!("{err}").contains("cover"),
            "the refusal must say what is uncovered, got: {err}"
        );
    }

    #[test]
    fn a_gap_between_chunks_is_refused() {
        let mut m = manifest_of("gapped", &[1_u8; 100], 32);
        m.chunks[2].offset += 1;
        let err = m.validate().expect_err("must refuse");
        assert!(
            format!("{err}").contains("starts at"),
            "the refusal must name the gap, got: {err}"
        );
    }

    #[test]
    fn a_chunk_reaching_past_the_total_is_refused() {
        let mut m = manifest_of("long", &[1_u8; 100], 32);
        m.chunks[3].length += 1;
        let err = m.validate().expect_err("must refuse");
        assert!(
            format!("{err}").contains("past the declared total"),
            "the refusal must name the overrun, got: {err}"
        );
    }

    #[test]
    fn an_empty_image_and_a_nameless_one_are_refused() {
        let empty = manifest_of("", &[1_u8; 10], 4);
        assert!(
            empty.validate().is_err(),
            "a nameless image must be refused"
        );
        let none = manifest_of("nothing", b"", 4);
        assert!(
            none.validate().is_err(),
            "an image with no chunks must be refused"
        );
    }

    #[test]
    fn a_zero_length_chunk_is_refused() {
        let mut m = manifest_of("zero", &[1_u8; 8], 4);
        m.chunks[1].length = 0;
        let err = m.validate().expect_err("must refuse");
        assert!(
            format!("{err}").contains("zero bytes"),
            "the refusal must say the chunk is empty, got: {err}"
        );
    }

    #[test]
    fn a_zero_chunk_size_is_refused_rather_than_read_as_one_chunk() {
        let err = ImageManifest::from_bytes("x", b"abc", 0).expect_err("must refuse");
        assert!(format!("{err}").contains("greater than zero"), "got: {err}");
    }

    #[test]
    fn the_manifest_digest_is_stable_and_content_sensitive() {
        // Criterion 1, and the reason the digest is computed over the canonical payload:
        // this value is what a later release signs, so two processes building the same
        // manifest must agree on it.
        let a = manifest_of("img", &[3_u8; 64], 16);
        let b = manifest_of("img", &[3_u8; 64], 16);
        assert_eq!(
            a.digest_hex().expect("digest"),
            b.digest_hex().expect("digest")
        );

        let c = manifest_of("img", &[4_u8; 64], 16);
        assert_ne!(
            a.digest_hex().expect("digest"),
            c.digest_hex().expect("digest"),
            "different content must give a different manifest digest"
        );

        // The digest is also sensitive to chunking: the same bytes split differently is a
        // different fetch plan, so it is a different manifest.
        let d = manifest_of("img", &[3_u8; 64], 8);
        assert_ne!(
            a.digest_hex().expect("digest"),
            d.digest_hex().expect("digest")
        );
    }

    #[test]
    fn a_range_that_would_overflow_is_refused() {
        let chunk = ChunkRef {
            digest: ChunkDigest::of(b"x"),
            offset: u64::MAX,
            length: 1,
        };
        assert!(chunk.range().is_err(), "offset + length must not wrap");
    }

    #[test]
    fn a_manifest_survives_a_round_trip_through_json() {
        // It is a wire type: the daemon will read it from a source and a plugin may carry
        // it in a message, so the serialised form has to come back as the same value.
        let m = manifest_of("round", &[9_u8; 40], 16);
        let text = serde_json::to_string(&m).expect("serialise");
        let back: ImageManifest = serde_json::from_str(&text).expect("deserialise");
        assert_eq!(m, back);
        back.validate().expect("still valid");
        assert_eq!(m.digest_hex().expect("a"), back.digest_hex().expect("b"));
    }
}
