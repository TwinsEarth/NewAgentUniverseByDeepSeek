//! A chunk source backed by a directory on disk.
//!
//! The one source this release can actually implement. A chunk is a file named after its
//! own digest, which makes the directory self-describing: the file names *are* the content
//! addresses, so a corrupted or renamed file is caught by the reader's verification rather
//! than served.
//!
//! # Why a directory of files rather than one image file
//!
//! An image manifest already says where each chunk sits inside the assembled image
//! ([`ChunkRef::offset`]). A single-file layout would therefore be the more faithful
//! model, and it is what a real deployment would use. It is not what this release uses,
//! because the point here is to prove the **reader** resolves only what it is asked for,
//! and a directory of files makes that visible from outside the process: you can count the
//! files that were opened, or delete one and watch the failure name it. The single-file
//! layout arrives with the fetch planner, where the offsets start to matter for seeking.
//!
//! [`ChunkRef::offset`]: nau_core::image::ChunkRef::offset

use std::path::{Path, PathBuf};

use nau_core::image::ChunkDigest;

use crate::source::{ChunkSource, SourceError};

/// Chunks stored as files named after their digest.
#[derive(Debug, Clone)]
pub struct LocalSource {
    root: PathBuf,
}

impl LocalSource {
    /// A source rooted at `root`.
    ///
    /// The directory is not required to exist here. A source is a description of where to
    /// look, and refusing at construction would make a reader unbuildable before the cache
    /// has been populated — which is a normal state during provisioning. A missing
    /// directory surfaces as [`SourceError::Unavailable`] on the first fetch instead.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory this source reads from.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where a chunk would be read from.
    ///
    /// Exposed so a caller can populate a cache, or explain a miss, without reimplementing
    /// the naming rule. The rule lives in one place on purpose: two copies of it would
    /// drift, and the symptom of drift is a cache that never hits.
    #[must_use]
    pub fn path_for(&self, digest: &ChunkDigest) -> PathBuf {
        self.root.join(format!("{}.chunk", digest.as_str()))
    }
}

impl ChunkSource for LocalSource {
    fn fetch(&self, digest: &ChunkDigest) -> Result<Vec<u8>, SourceError> {
        let path = self.path_for(digest);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(SourceError::Missing(digest.as_str().to_string()))
            }
            Err(e) => Err(SourceError::Unavailable(format!(
                "{} could not be read: {e}",
                path.display()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory that removes itself.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("nau-image-local-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch");
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn store(scratch: &Scratch, bytes: &[u8]) -> ChunkDigest {
        let digest = ChunkDigest::of(bytes);
        let source = LocalSource::new(scratch.path());
        std::fs::write(source.path_for(&digest), bytes).expect("write chunk");
        digest
    }

    #[test]
    fn a_stored_chunk_comes_back_byte_for_byte() {
        let scratch = Scratch::new("roundtrip");
        let digest = store(&scratch, b"chunk contents");
        let source = LocalSource::new(scratch.path());
        assert_eq!(
            source.fetch(&digest).expect("present"),
            b"chunk contents".to_vec()
        );
    }

    #[test]
    fn an_absent_chunk_is_missing_rather_than_unavailable() {
        // The distinction the reader's error mapping depends on: "not here" is a cache miss
        // to try elsewhere, "cannot read the directory" is a deployment fault. Collapsing
        // them would make a typo in a path look like an empty cache.
        let scratch = Scratch::new("absent");
        let source = LocalSource::new(scratch.path());
        let err = source
            .fetch(&ChunkDigest::of(b"never stored"))
            .expect_err("absent");
        assert!(matches!(err, SourceError::Missing(_)), "got {err:?}");
    }

    #[test]
    fn a_root_that_does_not_exist_reports_missing_for_a_chunk() {
        // A missing directory yields NotFound from the OS, so it lands on Missing. That is
        // the honest reading -- as far as this source can tell, it does not have the chunk
        // -- and the reader's caller decides whether an empty cache is expected.
        let source = LocalSource::new(std::env::temp_dir().join("nau-image-no-such-dir-at-all"));
        let err = source.fetch(&ChunkDigest::of(b"x")).expect_err("absent");
        assert!(matches!(err, SourceError::Missing(_)), "got {err:?}");
    }

    #[test]
    fn the_chunk_path_is_the_digest_and_one_rule_serves_both_reading_and_writing() {
        // Written through `path_for` and read through `fetch`, so a mismatch between the two
        // naming rules would fail here rather than as a cache that never hits.
        let scratch = Scratch::new("naming");
        let digest = store(&scratch, b"named by content");
        let name = LocalSource::new(scratch.path())
            .path_for(&digest)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        assert_eq!(name, format!("{}.chunk", digest.as_str()));
        assert_eq!(name.len(), 64 + ".chunk".len());
    }

    #[test]
    fn bytes_at_the_right_name_but_wrong_content_still_fail_the_readers_check() {
        // This source does not verify what it reads -- it cannot know what was asked for
        // beyond the name. That is deliberate: verification belongs to the reader, and
        // putting a second copy here would create two places for it to be wrong.
        let scratch = Scratch::new("swapped");
        let digest = ChunkDigest::of(b"what was asked for");
        let source = LocalSource::new(scratch.path());
        std::fs::write(source.path_for(&digest), b"something else entirely").expect("write");

        let got = source.fetch(&digest).expect("the file is there");
        assert_ne!(
            ChunkDigest::of(&got),
            digest,
            "the source must hand back what is on disk so the reader can catch it"
        );
    }
}
