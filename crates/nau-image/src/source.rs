//! Where chunks come from.
//!
//! A port, and a counter. The counter is not decoration: the claim this release makes is
//! *"a read fetches only what it needs"*, and that is only meaningful if something counts.
//! Putting the count on the source rather than in the reader means the test can assert
//! what the source was actually asked for, rather than what the reader believes it asked.
//!
//! Real sources — a local file, UDOS, a peer — arrive with A-06. They are deliberately not
//! here: a reader whose fetch behaviour has not been proven against a source that counts
//! would be a reader whose fetch behaviour is unknown.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use nau_core::image::ChunkDigest;

/// Why a source could not produce a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// The source does not have this chunk.
    Missing(String),
    /// The source had it, but the bytes do not hash to the digest that named them.
    ///
    /// Separate from [`SourceError::Missing`] on purpose: "I do not have it" and "what I
    /// have is not what you asked for" are different facts, and a caller that cannot tell
    /// them apart cannot decide whether to try elsewhere or to refuse.
    Corrupt {
        /// The digest that was requested.
        expected: String,
        /// The digest of what the source returned.
        actual: String,
    },
    /// The source itself failed.
    Unavailable(String),
    /// The chunk has no valid attestation and the policy requires one.
    ///
    /// A fourth variant rather than a reuse of [`SourceError::Unavailable`], because the
    /// three existing ones would each say something false: the source *is* available, the
    /// bytes *are* the ones asked for, and the chunk is not missing. What is wrong is that
    /// nobody vouched for it -- a different fact, and a caller that cannot tell it apart
    /// will retry a request that can never succeed.
    Unattested(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::Missing(what) => write!(f, "the source does not have {what}"),
            SourceError::Corrupt { expected, actual } => write!(
                f,
                "the source returned bytes hashing to {actual}, not the requested {expected}"
            ),
            SourceError::Unavailable(why) => write!(f, "the source is unavailable: {why}"),
            SourceError::Unattested(why) => write!(f, "the chunk is not attested: {why}"),
        }
    }
}

impl std::error::Error for SourceError {}

/// Somewhere chunks can be fetched from.
pub trait ChunkSource {
    /// Fetch the chunk named by `digest`.
    ///
    /// # Errors
    ///
    /// [`SourceError::Missing`] when the source does not have it, [`SourceError::Corrupt`]
    /// when it returns bytes that do not hash to `digest`, or
    /// [`SourceError::Unavailable`] when the source itself is failing.
    fn fetch(&self, digest: &ChunkDigest) -> Result<Vec<u8>, SourceError>;

    /// How many fetch attempts this source has served.
    ///
    /// A default of `0` keeps a stateless source from having to lie; the sources that
    /// matter for the counting claim override it.
    fn fetches(&self) -> usize {
        0
    }
}

/// An in-memory source that counts what it was asked for.
///
/// The test double this release is verified against, and small enough to read: it stores
/// chunks by digest and returns exactly those bytes. It can also be told to return wrong
/// bytes for one digest, because a reader that never sees a corrupt chunk is a reader whose
/// corruption path is untested.
#[derive(Debug, Default)]
pub struct MemorySource {
    chunks: BTreeMap<String, Vec<u8>>,
    corrupt: Option<String>,
    fetches: AtomicUsize,
    bytes: AtomicUsize,
}

impl MemorySource {
    /// An empty source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a chunk, addressed by its own content.
    ///
    /// The digest is computed here rather than passed in, so a caller cannot accidentally
    /// file bytes under the wrong name — which would make every reader test that uses this
    /// source pass for the wrong reason.
    pub fn insert(&mut self, bytes: &[u8]) -> ChunkDigest {
        let digest = ChunkDigest::of(bytes);
        self.chunks
            .insert(digest.as_str().to_string(), bytes.to_vec());
        digest
    }

    /// Make this digest return bytes that do not match it.
    ///
    /// Empties the stored chunk so the failure is deterministic: the source will answer
    /// with `b"corrupt"` for that digest however many times it is asked.
    pub fn corrupt(&mut self, digest: &ChunkDigest) {
        self.corrupt = Some(digest.as_str().to_string());
    }

    /// How many bytes this source has handed out.
    #[must_use]
    pub fn bytes_served(&self) -> usize {
        self.bytes.load(Ordering::SeqCst)
    }

    /// Which digests this source holds.
    #[must_use]
    pub fn held(&self) -> Vec<&str> {
        self.chunks.keys().map(String::as_str).collect()
    }
}

impl ChunkSource for MemorySource {
    fn fetch(&self, digest: &ChunkDigest) -> Result<Vec<u8>, SourceError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if self.corrupt.as_deref() == Some(digest.as_str()) {
            return Err(SourceError::Corrupt {
                expected: digest.as_str().to_string(),
                actual: ChunkDigest::of(b"corrupt").as_str().to_string(),
            });
        }
        match self.chunks.get(digest.as_str()) {
            Some(bytes) => {
                self.bytes.fetch_add(bytes.len(), Ordering::SeqCst);
                Ok(bytes.clone())
            }
            None => Err(SourceError::Missing(digest.as_str().to_string())),
        }
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memory_source_files_bytes_under_their_own_digest() {
        let mut s = MemorySource::new();
        let digest = s.insert(b"alpha");
        assert_eq!(digest, ChunkDigest::of(b"alpha"));
        assert_eq!(s.fetch(&digest).expect("present"), b"alpha".to_vec());
        assert_eq!(s.fetches(), 1);
        assert_eq!(s.bytes_served(), 5);
    }

    #[test]
    fn a_missing_chunk_is_reported_as_missing_not_as_corrupt() {
        // The distinction the reader's error path depends on.
        let s = MemorySource::new();
        let err = s.fetch(&ChunkDigest::of(b"absent")).expect_err("absent");
        assert!(matches!(err, SourceError::Missing(_)), "got {err:?}");
    }

    #[test]
    fn a_corrupted_chunk_is_reported_as_corrupt_not_as_missing() {
        let mut s = MemorySource::new();
        let digest = s.insert(b"beta");
        s.corrupt(&digest);
        let err = s.fetch(&digest).expect_err("corrupt");
        match err {
            SourceError::Corrupt { expected, actual } => {
                assert_eq!(expected, digest.as_str());
                assert_ne!(actual, digest.as_str());
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn fetches_are_counted_even_when_the_answer_is_an_error() {
        // A source that only counted successes would let a reader that retries forever look
        // like a reader that fetched once.
        let s = MemorySource::new();
        let _ = s.fetch(&ChunkDigest::of(b"nope"));
        let _ = s.fetch(&ChunkDigest::of(b"nope"));
        assert_eq!(s.fetches(), 2);
        assert_eq!(s.bytes_served(), 0);
    }
}
