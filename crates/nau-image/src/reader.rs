//! The reader: turn a byte range into chunks, fetch only the ones that are missing, measure
//! how long each fetch took.
//!
//! # What a read does
//!
//! [`ChunkReader::read`] takes a byte range and resolves **the chunks that cover it**, in
//! order. It does not fetch the image, and it does not fetch the chunks before or after the
//! range: that is the entire point of addressing by manifest rather than by blob, and it is
//! asserted by count rather than described.
//!
//! # The cache, and what it is not
//!
//! A fetched chunk is kept, so a second read over the same bytes costs nothing. The cache is
//! unbounded here on purpose: this release is about **what a read fetches**, and a cache
//! with an eviction policy would make the counting test depend on that policy. Sizing and
//! eviction belong with the resource accounting in a later release, where the number they
//! trade against exists.
//!
//! # Latency, and why it is reported as a percentile of a sample rather than as a guarantee
//!
//! [`Metrics::p50_micros`] and [`Metrics::p99_micros`] are computed from the per-chunk fetch
//! durations actually observed. They are a measurement of the machine and the source the
//! reader ran against — useful for the plan's acceptance criterion, which asks for a
//! single-step p99 against a full pull, and useless as a claim about any other machine. The
//! tests assert **counts** and assert only that a percentile lies within the recorded range,
//! because a test that asserted a duration would be asserting the runner's load.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

use nau_core::error::{NauError, Result};
use nau_core::image::{ChunkDigest, ChunkRef, ImageManifest};

use crate::source::{ChunkSource, SourceError};

/// What one read did.
///
/// Returned rather than only recorded, so a caller can see the fetch plan for the read it
/// just made without reaching into shared metrics — and so a test can assert on the read it
/// performed instead of on a total that other reads have contributed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReadReport {
    /// Chunks the requested range covers.
    pub chunks: usize,
    /// Of those, how many had to be fetched from the source.
    pub fetched: usize,
    /// Of those, how many were already cached.
    pub cached: usize,
    /// Bytes actually taken from the source.
    pub bytes_fetched: usize,
}

/// Per-chunk fetch durations, and the totals a fetch plan is judged by.
#[derive(Debug, Default)]
struct Inner {
    reads: usize,
    chunks_fetched: usize,
    bytes_fetched: usize,
    cache_hits: usize,
    micros: Vec<u64>,
}

/// What the reader has done so far.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Metrics {
    /// Reads served.
    pub reads: usize,
    /// Chunks fetched from the source, across all reads.
    pub chunks_fetched: usize,
    /// Bytes fetched from the source.
    pub bytes_fetched: usize,
    /// Chunks served from the cache instead of the source.
    pub cache_hits: usize,
    /// Median per-chunk fetch duration, in microseconds.
    pub p50_micros: u64,
    /// 99th-percentile per-chunk fetch duration, in microseconds.
    pub p99_micros: u64,
}

/// Resolves an [`ImageManifest`] against a source, chunk by chunk.
#[derive(Debug)]
pub struct ChunkReader<S: ChunkSource> {
    manifest: ImageManifest,
    source: S,
    cache: Mutex<BTreeMap<String, Vec<u8>>>,
    inner: Mutex<Inner>,
}

impl<S: ChunkSource> ChunkReader<S> {
    /// A reader over `manifest`, fetching missing chunks from `source`.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] if the manifest does not validate. Checked here rather than
    /// per read: a manifest with a hole in it cannot be served correctly by any number of
    /// reads, so accepting it would only move the failure somewhere less informative.
    pub fn new(manifest: ImageManifest, source: S) -> Result<Self> {
        manifest.validate()?;
        Ok(Self {
            manifest,
            source,
            cache: Mutex::new(BTreeMap::new()),
            inner: Mutex::new(Inner::default()),
        })
    }

    /// The manifest this reader serves.
    #[must_use]
    pub fn manifest(&self) -> &ImageManifest {
        &self.manifest
    }

    /// Read `length` bytes starting at `offset`.
    ///
    /// Fetches only the chunks that cover the range and are not already cached.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the range reaches past the image, and
    /// [`NauError::NotFound`] / [`NauError::Validation`] when a chunk cannot be fetched or
    /// does not match its digest.
    pub fn read(&self, offset: u64, length: u64) -> Result<(Vec<u8>, ReadReport)> {
        let end = offset
            .checked_add(length)
            .ok_or(NauError::Overflow("read offset + length"))?;
        if end > self.manifest.total_bytes {
            return Err(NauError::Validation(format!(
                "read of {offset}..{end} reaches past the image's {} bytes",
                self.manifest.total_bytes
            )));
        }

        // Only the chunks that intersect the range. This is the fetch plan, and it is the
        // reason the reader exists: a whole-image read here would be a correct answer to a
        // different question.
        let covering: Vec<&ChunkRef> = self
            .manifest
            .chunks
            .iter()
            .filter(|c| {
                let start = c.offset;
                let stop = c.offset.saturating_add(c.length);
                start < end && stop > offset
            })
            .collect();

        let mut report = ReadReport {
            chunks: covering.len(),
            ..ReadReport::default()
        };
        let mut out = Vec::with_capacity(length as usize);

        for chunk in covering {
            let key = chunk.digest.as_str().to_string();
            let bytes = match self.cached(&key) {
                Some(hit) => {
                    report.cached += 1;
                    hit
                }
                None => {
                    let started = Instant::now();
                    let fetched = self.fetch(chunk)?;
                    let micros = started.elapsed().as_micros() as u64;
                    self.record_fetch(micros, fetched.len());
                    self.remember(&key, &fetched);
                    report.fetched += 1;
                    report.bytes_fetched += fetched.len();
                    fetched
                }
            };

            // The sub-range of this chunk that the caller asked for. Clamped rather than
            // assumed, because the first and last covering chunks are partly outside the
            // range by construction.
            let chunk_end = chunk.offset + chunk.length;
            let from = offset.max(chunk.offset) - chunk.offset;
            let to = end.min(chunk_end) - chunk.offset;
            let (from, to) = (from as usize, to as usize);
            if to > bytes.len() || from > to {
                return Err(NauError::Validation(format!(
                    "chunk {} is {} bytes but the manifest covers {from}..{to} of it",
                    chunk.digest,
                    bytes.len()
                )));
            }
            out.extend_from_slice(&bytes[from..to]);
        }

        self.count_read(report.cached);
        Ok((out, report))
    }

    /// What the reader has done so far.
    #[must_use]
    pub fn metrics(&self) -> Metrics {
        let inner = self.lock_inner();
        let mut micros = inner.micros.clone();
        micros.sort_unstable();
        Metrics {
            reads: inner.reads,
            chunks_fetched: inner.chunks_fetched,
            bytes_fetched: inner.bytes_fetched,
            cache_hits: inner.cache_hits,
            p50_micros: percentile(&micros, 50),
            p99_micros: percentile(&micros, 99),
        }
    }

    /// Fetch one chunk and check it against the digest that named it.
    fn fetch(&self, chunk: &ChunkRef) -> Result<Vec<u8>> {
        let bytes = self.source.fetch(&chunk.digest).map_err(|e| match e {
            SourceError::Missing(what) => NauError::NotFound(format!("image chunk {what}")),
            SourceError::Corrupt { expected, actual } => NauError::Validation(format!(
                "image chunk {expected} arrived hashing to {actual}; refusing to assemble a \
                 sandbox out of bytes that are not the ones that were asked for"
            )),
            SourceError::Unavailable(why) => NauError::NotFound(format!("image source: {why}")),
        })?;

        // Belt and braces: the source is supposed to verify, but a source is exactly the
        // thing this project does not trust. A chunk that arrives wrong is caught here even
        // if the source claimed success.
        let actual = ChunkDigest::of(&bytes);
        if actual != chunk.digest {
            return Err(NauError::Validation(format!(
                "image chunk {} arrived hashing to {actual}",
                chunk.digest
            )));
        }
        Ok(bytes)
    }

    /// A cached chunk, if present. Poisoning is recovered from rather than propagated: the
    /// map is a cache, and a panicked writer cannot have left it in a state that makes a
    /// wrong answer more likely than a miss.
    fn cached(&self, key: &str) -> Option<Vec<u8>> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.get(key).cloned()
    }

    fn remember(&self, key: &str, bytes: &[u8]) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(key.to_string(), bytes.to_vec());
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn record_fetch(&self, micros: u64, bytes: usize) {
        let mut inner = self.lock_inner();
        inner.chunks_fetched += 1;
        inner.bytes_fetched += bytes;
        inner.micros.push(micros);
    }

    fn count_read(&self, hits: usize) {
        let mut inner = self.lock_inner();
        inner.reads += 1;
        inner.cache_hits += hits;
    }

    /// The source, so a test can assert what it was asked for rather than what the reader
    /// believes it asked for.
    #[must_use]
    pub fn source(&self) -> &S {
        &self.source
    }
}

/// The `p`th percentile of a sorted sample, nearest-rank.
///
/// Nearest-rank rather than interpolated: with a handful of samples, an interpolated p99
/// invents a value between two real measurements, and the number this feeds is compared
/// against another measurement.
fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p * sorted.len()).div_ceil(100);
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;

    /// A 100-byte image in 20-byte chunks, and a source holding all five.
    fn reader() -> (ChunkReader<MemorySource>, Vec<u8>) {
        let bytes: Vec<u8> = (0..100_u8).collect();
        let manifest = ImageManifest::from_bytes("test", &bytes, 20).expect("manifest");
        let mut source = MemorySource::new();
        for piece in bytes.chunks(20) {
            source.insert(piece);
        }
        (ChunkReader::new(manifest, source).expect("reader"), bytes)
    }

    #[test]
    fn a_read_fetches_only_the_chunks_it_covers() {
        // A-05's first acceptance criterion, asserted as a count: reading four bytes out of
        // a five-chunk image must ask the source for one chunk, not five.
        let (r, bytes) = reader();
        let (got, report) = r.read(4, 4).expect("read");
        assert_eq!(got, bytes[4..8].to_vec());
        assert_eq!(report.chunks, 1, "one chunk covers 4..8");
        assert_eq!(report.fetched, 1);
        assert_eq!(
            report.bytes_fetched, 20,
            "the whole chunk, not the four bytes"
        );
        assert_eq!(r.metrics().chunks_fetched, 1, "the source saw one fetch");
    }

    #[test]
    fn a_read_spanning_a_boundary_fetches_exactly_the_two_chunks_it_needs() {
        let (r, bytes) = reader();
        // 18..26 crosses the boundary at 20.
        let (got, report) = r.read(18, 8).expect("read");
        assert_eq!(got, bytes[18..26].to_vec());
        assert_eq!(report.chunks, 2);
        assert_eq!(report.fetched, 2);
        assert_eq!(r.metrics().chunks_fetched, 2);
        assert!(
            r.metrics().chunks_fetched < r.manifest().chunks.len(),
            "a boundary read must not become a whole-image read"
        );
    }

    #[test]
    fn reading_the_whole_image_fetches_every_chunk_exactly_once() {
        let (r, bytes) = reader();
        let (got, report) = r.read(0, 100).expect("read");
        assert_eq!(got, bytes);
        assert_eq!(report.chunks, 5);
        assert_eq!(report.fetched, 5);
        assert_eq!(report.cached, 0);
        assert_eq!(r.metrics().chunks_fetched, 5);
        assert_eq!(r.metrics().bytes_fetched, 100);
    }

    #[test]
    fn a_second_read_over_the_same_bytes_fetches_nothing() {
        let (r, _) = reader();
        let _ = r.read(4, 4).expect("first");
        let (_, report) = r.read(4, 4).expect("second");
        assert_eq!(report.fetched, 0, "the chunk is already held");
        assert_eq!(report.cached, 1);
        assert_eq!(
            r.metrics().chunks_fetched,
            1,
            "the source was asked once, total"
        );
        assert_eq!(r.source().fetches(), 1);
    }

    #[test]
    fn a_read_past_the_end_is_refused_rather_than_clamped() {
        // Clamping would return short data and look like success, which is the failure mode
        // a partly-populated sandbox produces much later.
        let (r, _) = reader();
        let err = r.read(95, 10).expect_err("past the end");
        assert!(format!("{err}").contains("past the image"), "got: {err}");
        assert_eq!(r.metrics().reads, 0, "a refused read is not a read");
    }

    #[test]
    fn a_read_that_would_overflow_is_refused() {
        let (r, _) = reader();
        assert!(r.read(u64::MAX, 2).is_err());
    }

    #[test]
    fn a_missing_chunk_surfaces_as_not_found_and_the_read_produces_nothing() {
        let bytes: Vec<u8> = (0..40_u8).collect();
        let manifest = ImageManifest::from_bytes("sparse", &bytes, 20).expect("manifest");
        let mut source = MemorySource::new();
        source.insert(&bytes[0..20]); // the second chunk is deliberately absent
        let r = ChunkReader::new(manifest, source).expect("reader");

        let err = r.read(0, 40).expect_err("the second chunk is missing");
        assert!(format!("{err}").contains("not found"), "got: {err}");
    }

    #[test]
    fn a_lying_source_is_caught_by_the_reader_itself() {
        // The source is the thing this project does not trust. `MemorySource` verifies what
        // it hands out, so it cannot exercise the reader's own check -- this double returns
        // the wrong bytes and reports success, which is exactly what a compromised or buggy
        // real source would do.
        #[derive(Debug)]
        struct Lying;
        impl ChunkSource for Lying {
            fn fetch(&self, _digest: &ChunkDigest) -> std::result::Result<Vec<u8>, SourceError> {
                Ok(b"not the bytes you asked for".to_vec())
            }
        }

        let bytes: Vec<u8> = (0..40_u8).collect();
        let manifest = ImageManifest::from_bytes("lying", &bytes, 20).expect("manifest");
        let r = ChunkReader::new(manifest, Lying).expect("reader");

        let err = r.read(0, 20).expect_err("the source is lying");
        assert!(
            format!("{err}").contains("hashing to"),
            "the refusal must say the bytes did not match, got: {err}"
        );
    }

    #[test]
    fn the_metrics_report_a_percentile_inside_the_observed_range() {
        // The counts are exact; the timings are not, and this test does not pretend
        // otherwise. Its first version asserted `p50_micros == 0` on the reasoning that an
        // in-memory source is sub-microsecond -- which is a claim about the machine, and it
        // was wrong by 8 microseconds on this one. The module documentation says a test that
        // asserts a duration asserts the runner's load; the test then went and did it.
        let (r, _) = reader();
        let _ = r.read(0, 100).expect("read");
        let m = r.metrics();
        assert_eq!(m.reads, 1);
        assert_eq!(m.chunks_fetched, 5);
        assert_eq!(m.bytes_fetched, 100);
        assert_eq!(m.cache_hits, 0);
        assert!(m.p99_micros >= m.p50_micros, "p99 must not be below p50");
        assert!(
            m.p99_micros < 1_000_000,
            "five in-memory chunk fetches should not take a second, got {}us",
            m.p99_micros
        );
    }

    #[test]
    fn a_cached_read_is_counted_as_a_cache_hit() {
        // The metric that says the fetch plan worked: a second read of the same bytes has
        // hits and no fetches.
        let (r, _) = reader();
        let _ = r.read(4, 4).expect("first");
        let _ = r.read(4, 4).expect("second");
        let m = r.metrics();
        assert_eq!(m.reads, 2);
        assert_eq!(m.chunks_fetched, 1);
        assert_eq!(m.cache_hits, 1);
        assert_eq!(m.bytes_fetched, 20, "the source served one chunk, once");
    }

    #[test]
    fn metrics_with_no_fetches_are_zero_rather_than_a_division_by_zero() {
        let (r, _) = reader();
        let m = r.metrics();
        assert_eq!(m, Metrics::default());
    }

    #[test]
    fn percentile_of_a_known_sample_is_the_nearest_rank() {
        // The helper, tested directly: with five samples, p50 is the third and p99 is the
        // fifth. Nearest-rank, so no value is invented between two measurements.
        let sample = [10_u64, 20, 30, 40, 50];
        assert_eq!(percentile(&sample, 50), 30);
        assert_eq!(percentile(&sample, 99), 50);
        assert_eq!(percentile(&sample, 1), 10);
        assert_eq!(percentile(&[], 99), 0);
        assert_eq!(percentile(&[7], 99), 7);
    }

    #[test]
    fn a_manifest_with_a_hole_is_refused_before_any_read() {
        let bytes: Vec<u8> = (0..40_u8).collect();
        let mut manifest = ImageManifest::from_bytes("holed", &bytes, 20).expect("manifest");
        manifest.total_bytes = 100;
        let source = MemorySource::new();
        let err = ChunkReader::new(manifest, source).expect_err("must refuse");
        assert!(format!("{err}").contains("cover"), "got: {err}");
    }
}
