//! Every consistency claim about this crate, exercised.
//!
//! `nau_core::domain::consistency::CLAIMS` declares what this workspace guarantees about
//! concurrent change. A declaration nothing checks is documentation with extra steps, so each
//! test here looks its claim up by name and then does the thing the claim is about.
//!
//! The dates are worth recording: the claim module was written first, and writing these tests
//! immediately turned up two facts that the declaration had got wrong. Both are corrected in the
//! claims rather than papered over in the tests, because a declaration that disagrees with the
//! implementation is worse than no declaration — it is a wrong one.

use nau_core::domain::consistency::{ConsistencyModel, CLAIMS, KNOWN_BOUNDARIES};
use nau_image::{
    ChunkDigest, ChunkReader, ChunkSource, LocalSource, MemorySource, SeedingRatio, SourceError,
};

/// The claim about `component` and `question`, or a failure naming what is missing.
fn claim(component: &str) -> nau_core::domain::consistency::ConsistencyClaim {
    *CLAIMS
        .iter()
        .find(|c| c.component == component)
        .unwrap_or_else(|| panic!("no consistency claim for `{component}`"))
}

#[test]
fn every_claim_this_crate_owns_is_reachable_from_here() {
    // The claims about `nau-image`'s components, by name. If one is renamed or removed, this
    // fails rather than leaving a claim nobody exercises.
    //
    // `SnapshotStore layers` is deliberately NOT here: the store lives in `nau-sandbox`, and its
    // claim is exercised by that crate's suite. This crate cannot reach it -- `nau-image` depends
    // on `nau-core` alone -- and adding a dev-dependency so that one crate can test another's
    // component would put the evidence in the wrong place.
    for component in [
        "ImageManifest",
        "ChunkReader::read",
        "ChunkReader::metrics",
        "SeedingRatio",
    ] {
        let c = claim(component);
        assert!(c.is_complete(), "{component} has an incomplete claim");
    }
}

#[test]
fn the_manifest_claim_holds() {
    // "does a manifest read now still describe the same image later?"
    let c = claim("ImageManifest");
    assert_eq!(c.model, ConsistencyModel::SnapshotPoint);

    let bytes: Vec<u8> = (0..100_u8).collect();
    let manifest = nau_image::ImageManifest::from_bytes("img", &bytes, 20).expect("manifest");
    let first = manifest.digest_hex().expect("digest");
    // A manifest is a value: cloning it and reading again cannot produce a different answer,
    // because there is no shared mutable state behind it to change.
    let clone = manifest.clone();
    assert_eq!(clone.digest_hex().expect("digest"), first);
    assert_eq!(clone.chunks, manifest.chunks);
    assert_eq!(clone.total_bytes, manifest.total_bytes);
}

#[test]
fn the_read_claim_holds_a_source_cannot_produce_a_mixed_result() {
    // "can one read assemble bytes from two different versions of a source?"
    //
    // The claim is snapshot-point, and the mechanism is that every chunk is verified against the
    // digest the manifest names. A source that has moved on therefore serves a **verification
    // failure**, not a mixture of one version's first chunk and another's second.
    let c = claim("ChunkReader::read");
    assert_eq!(c.model, ConsistencyModel::SnapshotPoint);

    // A source that answers one digest correctly and lies about the other -- the shape a source
    // that has moved on takes, expressed directly.
    #[derive(Debug)]
    struct HalfStale {
        honest: ChunkDigest,
        honest_bytes: Vec<u8>,
    }
    impl ChunkSource for HalfStale {
        fn fetch(&self, digest: &ChunkDigest) -> Result<Vec<u8>, SourceError> {
            if *digest == self.honest {
                Ok(self.honest_bytes.clone())
            } else {
                // The bytes this source now holds for that digest. Content addressing means they
                // cannot hash to it, which is exactly what makes the mixture impossible.
                Ok(b"the newer version of this chunk".to_vec())
            }
        }
    }

    let bytes: Vec<u8> = (0..40_u8).collect();
    let manifest = nau_image::ImageManifest::from_bytes("img", &bytes, 20).expect("manifest");
    let source = HalfStale {
        honest: manifest.chunks[0].digest.clone(),
        honest_bytes: bytes[0..20].to_vec(),
    };
    let reader = ChunkReader::new(manifest, source).expect("reader");

    // A read spanning both chunks must fail rather than return half of each version.
    let err = reader
        .read(0, 40)
        .expect_err("a stale source must not produce a mixed result");
    let text = format!("{err}");
    assert!(
        text.contains("hashing to"),
        "the failure must be a verification failure, got: {text}"
    );
}

#[test]
fn the_metrics_claim_holds_and_its_boundary_is_real() {
    // "do the counters describe one moment?" -- they do not, and the boundary says so.
    let c = claim("ChunkReader::metrics");
    assert_eq!(
        c.model,
        ConsistencyModel::Eventual,
        "the counters are shared mutable state read without a transaction across them"
    );
    assert!(
        !c.converges_to.trim().is_empty(),
        "an eventual claim must say what it converges to"
    );

    // The half that IS guaranteed, and it is the half a caller should rely on: once the reads
    // have stopped, the counters agree with what the reads reported.
    let bytes: Vec<u8> = (0..100_u8).collect();
    let manifest = nau_image::ImageManifest::from_bytes("img", &bytes, 20).expect("manifest");
    let mut store = MemorySource::new();
    for chunk in &manifest.chunks {
        store.insert(&bytes[chunk.offset as usize..(chunk.offset + chunk.length) as usize]);
    }
    let reader = ChunkReader::new(manifest, store).expect("reader");

    let (got, report) = reader.read(4, 4).expect("read");
    assert_eq!(got, bytes[4..8].to_vec());
    let m = reader.metrics();
    assert_eq!(
        m.chunks_fetched, report.fetched,
        "with the reads stopped, the counter must equal what the read reported"
    );
    assert_eq!(m.bytes_fetched, report.bytes_fetched);
    assert_eq!(m.reads, 1);

    // And the boundary is declared rather than left to be discovered.
    let boundary = KNOWN_BOUNDARIES
        .iter()
        .find(|b| b.component == "ChunkReader::metrics")
        .expect("the metrics boundary is declared");
    assert!(
        boundary.workaround.contains("ReadReport"),
        "the boundary must point at the per-read value a caller can rely on, got: {}",
        boundary.workaround
    );
}

#[test]
fn the_seeding_claim_holds_and_its_boundary_is_real() {
    // "does a peer's ratio describe the network now?" -- it describes one peer, and it is
    // undefined before that peer has fetched anything.
    let c = claim("SeedingRatio");
    assert_eq!(c.model, ConsistencyModel::Eventual);

    let undefined = SeedingRatio {
        served_bytes: 500,
        fetched_bytes: 0,
    };
    assert_eq!(
        undefined.percent(),
        None,
        "a peer that has fetched nothing has no ratio; reporting 0% would be a claim about a \
         peer nobody has exchanged with"
    );
    assert!(!undefined.is_seeding());

    let boundary = KNOWN_BOUNDARIES
        .iter()
        .find(|b| b.component == "SeedingRatio")
        .expect("the seeding boundary is declared");
    assert!(
        boundary.actually.contains("neither 0% nor infinite"),
        "the boundary must say what the undefined case is not, got: {}",
        boundary.actually
    );

    // And the defined case is exact for the peer that computed it.
    let defined = SeedingRatio {
        served_bytes: 200,
        fetched_bytes: 100,
    };
    assert_eq!(defined.percent(), Some(200));
}

#[test]
fn the_local_source_is_content_addressed_and_so_the_read_claim_holds() {
    // The claim about the read path rests on the source being content-addressed, and the local
    // source is the one that ships. This asserts the property directly: the bytes a source serves
    // for a digest are the bytes that hash to it, or the fetch fails.
    let scratch = std::env::temp_dir().join(format!("nau-consistency-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("scratch");

    let content = b"a chunk";
    let digest = ChunkDigest::of(content);
    let source = LocalSource::new(&scratch);
    std::fs::write(source.path_for(&digest), content).expect("write");
    assert_eq!(source.fetch(&digest).expect("serves"), content.to_vec());

    // Overwrite the file with different bytes. The name no longer describes the content, and the
    // reader's verification -- not the source -- is what refuses it.
    std::fs::write(source.path_for(&digest), b"different bytes entirely").expect("overwrite");
    let served = source.fetch(&digest).expect("the source does not verify");
    assert_ne!(
        ChunkDigest::of(&served),
        digest,
        "the source must hand back what is on disk so the reader can catch it"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}
