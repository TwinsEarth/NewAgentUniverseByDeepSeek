//! The consistency suite: one set of assertions, run against every source.
//!
//! A-06's first acceptance criterion is that the three sources share one trait and one
//! suite of tests. This is that suite, and it is an integration test rather than a unit test
//! so that it exercises the crate the way a caller does — through the public API only.
//!
//! # What the suite can assert, given that only one source works
//!
//! It cannot assert that all three return bytes: two of them refuse every fetch by design
//! (see [`nau_image::remote`]). What it *can* assert is the property that matters, which is
//! the same for all three and is the reason the trait exists:
//!
//! > **A fetch either returns bytes that hash to the digest that named them, or it fails
//! > with a typed error. It never returns `Ok` with the wrong bytes, and never returns
//! > `Ok(vec![])`.**
//!
//! That property holds for a working source and for a refusing one, and it is exactly the
//! property a reader depends on. So the suite runs the same loop over all three and reports
//! per-source which of the two outcomes it produced — refusing is an outcome, not a
//! failure.
//!
//! A second, sharper assertion follows from it: whatever a source does, it must do it
//! **consistently**. Asking twice for the same digest must not produce "missing" and then
//! "unavailable", because a caller that retries would see a transient problem where there
//! is a permanent one.

use nau_image::{
    ChunkDigest, ChunkSource, LocalSource, P2pSource, SourceError, SourceKind, UdosSource,
};

/// What a source did with one fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Served,
    Missing,
    Unavailable,
    Corrupt,
}

/// Classify one fetch, asserting the property that must hold for every source.
fn classify(source: &dyn ChunkSource, digest: &ChunkDigest) -> Outcome {
    match source.fetch(digest) {
        Ok(bytes) => {
            // The property. `Ok` with the wrong bytes would let a corrupted sandbox be
            // assembled; `Ok(vec![])` would be indistinguishable from corruption further
            // down and would make a misconfigured reader look like a working one.
            assert!(
                !bytes.is_empty(),
                "a source returned Ok with no bytes; that is not a miss, it is a lie"
            );
            assert_eq!(
                ChunkDigest::of(&bytes),
                *digest,
                "a source returned bytes that do not hash to the digest that named them"
            );
            Outcome::Served
        }
        Err(SourceError::Missing(_)) => Outcome::Missing,
        Err(SourceError::Unavailable(_)) => Outcome::Unavailable,
        Err(SourceError::Corrupt { .. }) => Outcome::Corrupt,
    }
}

/// Every source, with a label, as a boxed trait object.
///
/// Boxed because the suite's point is that the behaviour is asserted through the trait: a
/// per-source test written three times would prove three things, and this proves the one
/// thing they share.
fn all_sources(scratch: &std::path::Path) -> Vec<(SourceKind, Box<dyn ChunkSource>)> {
    vec![
        (SourceKind::Local, Box::new(LocalSource::new(scratch))),
        (SourceKind::Udos, Box::new(UdosSource)),
        (SourceKind::P2p, Box::new(P2pSource)),
    ]
}

#[test]
fn every_source_is_either_serving_or_refusing_and_never_lying() {
    let scratch =
        std::env::temp_dir().join(format!("nau-image-consistency-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("scratch");

    // One chunk, stored where a local source will find it and nowhere else.
    let content = b"the only chunk in this test";
    let digest = ChunkDigest::of(content);
    std::fs::write(LocalSource::new(&scratch).path_for(&digest), content).expect("store");

    let mut served = 0;
    let mut refused = 0;
    for (kind, source) in all_sources(&scratch) {
        let outcome = classify(source.as_ref(), &digest);
        println!("  {:8} -> {outcome:?}", kind.label());

        match outcome {
            Outcome::Served => {
                served += 1;
                assert_eq!(
                    kind,
                    SourceKind::Local,
                    "only the local source has anything to serve in this build"
                );
            }
            Outcome::Missing | Outcome::Unavailable | Outcome::Corrupt => refused += 1,
        }
    }

    assert_eq!(served, 1, "exactly one source works");
    assert_eq!(
        refused, 2,
        "the other two refuse, and are counted as refusing"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn a_source_answers_the_same_way_twice() {
    // Consistency, which is what a retrying caller depends on. A source that said "missing"
    // and then "unavailable" would look like a transient fault where there is a permanent
    // one, and a caller would retry forever.
    let scratch =
        std::env::temp_dir().join(format!("nau-image-consistency2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("scratch");

    let absent = ChunkDigest::of(b"nothing stores this");
    for (kind, source) in all_sources(&scratch) {
        let first = classify(source.as_ref(), &absent);
        let second = classify(source.as_ref(), &absent);
        assert_eq!(
            first,
            second,
            "{} answered {first:?} and then {second:?}",
            kind.label()
        );
    }

    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn the_unavailable_sources_name_a_working_alternative() {
    // Through the trait, not through `SourceKind`: the suite is about what a caller holding
    // a `dyn ChunkSource` can learn from a refusal.
    let digest = ChunkDigest::of(b"x");
    for (kind, source) in [
        (
            SourceKind::Udos,
            Box::new(UdosSource) as Box<dyn ChunkSource>,
        ),
        (SourceKind::P2p, Box::new(P2pSource) as Box<dyn ChunkSource>),
    ] {
        match source.fetch(&digest) {
            Err(SourceError::Unavailable(why)) => {
                assert!(
                    why.contains("local"),
                    "{} must point at the source that works, got: {why}",
                    kind.label()
                );
            }
            other => panic!(
                "{} must refuse with Unavailable, got {other:?}",
                kind.label()
            ),
        }
    }
}

#[test]
fn a_local_source_serves_through_the_reader_end_to_end() {
    // The one source that works, exercised the way a caller uses it: build a store, point a
    // reader at it, read a range, and check that only the covering chunk was fetched.
    use nau_core::image::ImageManifest;
    use nau_image::ChunkReader;

    let scratch = std::env::temp_dir().join(format!("nau-image-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("scratch");

    let bytes: Vec<u8> = (0..100_u8).collect();
    let manifest = ImageManifest::from_bytes("e2e", &bytes, 20).expect("manifest");
    let store = LocalSource::new(&scratch);
    for chunk in &manifest.chunks {
        let slice = &bytes[chunk.offset as usize..(chunk.offset + chunk.length) as usize];
        std::fs::write(store.path_for(&chunk.digest), slice).expect("store");
    }

    let reader = ChunkReader::new(manifest, LocalSource::new(&scratch)).expect("reader");
    let (got, report) = reader.read(4, 4).expect("read");
    assert_eq!(got, bytes[4..8].to_vec());
    assert_eq!(report.chunks, 1);
    assert_eq!(report.fetched, 1);
    assert_eq!(report.bytes_fetched, 20, "a whole chunk off the disk");

    let _ = std::fs::remove_dir_all(&scratch);
}
