//! Peers: asking one for a chunk, answering as one, and counting what was exchanged.
//!
//! # The two halves
//!
//! [`PeerSource`] is the asking side. It implements [`ChunkSource`], so a reader cannot tell
//! a peer from a disk — which is the point of the port — and it **re-hashes whatever comes
//! back**, because a response is exactly the thing this project does not trust.
//!
//! [`ChunkServer`] is the answering side. It answers from a store it already has, and it
//! counts: how many chunks it served, how many bytes, how many it did not have, how many it
//! refused.
//!
//! # Seeding, measured rather than asserted
//!
//! The AUSec design says an image is "a seed at over 1000% health". That is a BitTorrent
//! seeding ratio — bytes uploaded over bytes downloaded — and this release makes it a
//! **number that is computed from what happened**, not a property a source claims.
//!
//! [`SeedingRatio::percent`] returns an [`Option`] rather than a number, and the `None` case
//! is the interesting one: a peer that has fetched nothing has no ratio, because `0/0` is
//! undefined. It is neither `0%` (which would read as "not seeding") nor infinite (which
//! would read as "perfect"). A design that promises a healthy image without saying what
//! happens before anyone has downloaded anything has skipped this case.
//!
//! # What is not here
//!
//! The libp2p carriage. [`ChunkTransport`] is a port, and the only implementation in this
//! build is [`Loopback`], which answers from a [`ChunkServer`] in the same process. A
//! libp2p-backed transport needs a request/response behaviour, and `nau-libp2p` currently
//! carries GossipSub frames — pub/sub, no request/response. So the exchange is real and
//! exercised between two peers; the wire it will eventually run over is a named, separate
//! piece of work rather than something this release pretends to have done.

use std::sync::atomic::{AtomicUsize, Ordering};

use nau_core::image::ChunkDigest;

use crate::protocol::{ChunkRequest, ChunkResponse};
use crate::source::{ChunkSource, SourceError};

/// A way of asking a peer something.
pub trait ChunkTransport {
    /// Send a request and get an answer.
    ///
    /// # Errors
    ///
    /// [`SourceError::Unavailable`] when the peer cannot be reached at all. A peer that
    /// answers "I do not have it" or "I will not serve it" is **not** an error at this
    /// layer: those are answers, and collapsing them into a transport failure is how a
    /// policy decision starts to look like a network problem.
    fn request(&self, request: &ChunkRequest) -> Result<ChunkResponse, SourceError>;
}

/// The asking side: a peer reached over a transport.
#[derive(Debug, Clone)]
pub struct PeerSource<T: ChunkTransport> {
    transport: T,
    peer: String,
}

impl<T: ChunkTransport> PeerSource<T> {
    /// A source that asks `peer` over `transport`.
    pub fn new(peer: impl Into<String>, transport: T) -> Self {
        Self {
            transport,
            peer: peer.into(),
        }
    }

    /// Which peer this asks.
    #[must_use]
    pub fn peer(&self) -> &str {
        &self.peer
    }
}

impl<T: ChunkTransport> ChunkSource for PeerSource<T> {
    fn fetch(&self, digest: &ChunkDigest) -> Result<Vec<u8>, SourceError> {
        match self.transport.request(&ChunkRequest::get(digest.clone()))? {
            ChunkResponse::Data(bytes) => {
                // Verified here rather than trusted. A peer is the thing this project does
                // not trust, and a response that hashes to something else must not become a
                // sandbox.
                let actual = ChunkDigest::of(&bytes);
                if actual == *digest {
                    Ok(bytes)
                } else {
                    Err(SourceError::Corrupt {
                        expected: digest.as_str().to_string(),
                        actual: actual.as_str().to_string(),
                    })
                }
            }
            ChunkResponse::NotFound => Err(SourceError::Missing(digest.as_str().to_string())),
            ChunkResponse::Refused(why) => {
                // An empty reason is treated as a protocol violation rather than as a
                // refusal: a refusal the requester cannot act on is worse than one that says
                // nothing, because it looks actionable.
                if why.trim().is_empty() {
                    Err(SourceError::Unavailable(format!(
                        "peer {} returned an empty refusal reason, which is a protocol \
                         violation rather than an answer",
                        self.peer
                    )))
                } else {
                    Err(SourceError::Unavailable(format!(
                        "peer {} refused: {why}",
                        self.peer
                    )))
                }
            }
        }
    }
}

/// What a peer served, and what it could not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeedingStats {
    /// Chunks served.
    pub served_chunks: usize,
    /// Bytes served.
    pub served_bytes: usize,
    /// Requests for chunks this peer does not have.
    pub not_found: usize,
    /// Requests this peer declined to serve.
    pub refused: usize,
}

impl SeedingStats {
    /// Requests answered, of any kind.
    #[must_use]
    pub fn answered(&self) -> usize {
        self.served_chunks + self.not_found + self.refused
    }
}

/// The answering side: a store, plus the counts.
#[derive(Debug)]
pub struct ChunkServer<S: ChunkSource> {
    store: S,
    served_chunks: AtomicUsize,
    served_bytes: AtomicUsize,
    not_found: AtomicUsize,
    refused: AtomicUsize,
}

impl<S: ChunkSource> ChunkServer<S> {
    /// A server answering from `store`.
    pub fn new(store: S) -> Self {
        Self {
            store,
            served_chunks: AtomicUsize::new(0),
            served_bytes: AtomicUsize::new(0),
            not_found: AtomicUsize::new(0),
            refused: AtomicUsize::new(0),
        }
    }

    /// Answer one request.
    ///
    /// A store miss becomes [`ChunkResponse::NotFound`], not an error: from the requester's
    /// side "this peer does not have it" is a normal outcome of asking a peer that holds a
    /// different subset of the image.
    pub fn answer(&self, request: &ChunkRequest) -> ChunkResponse {
        match self.store.fetch(request.digest()) {
            Ok(bytes) => {
                self.served_chunks.fetch_add(1, Ordering::SeqCst);
                self.served_bytes.fetch_add(bytes.len(), Ordering::SeqCst);
                ChunkResponse::Data(bytes)
            }
            Err(SourceError::Missing(_)) => {
                self.not_found.fetch_add(1, Ordering::SeqCst);
                ChunkResponse::NotFound
            }
            Err(SourceError::Corrupt { expected, actual }) => {
                // This peer's own store is inconsistent. Refusing is the honest answer: it
                // has the bytes and they are not the ones asked for, which is neither a miss
                // nor a successful service.
                self.refused.fetch_add(1, Ordering::SeqCst);
                ChunkResponse::Refused(format!("stored bytes for {expected} hash to {actual}"))
            }
            Err(SourceError::Unavailable(why)) => {
                self.refused.fetch_add(1, Ordering::SeqCst);
                ChunkResponse::Refused(why)
            }
            Err(SourceError::Unattested(why)) => {
                // A store guarded by attestations declined this chunk. The peer *has* the
                // bytes, so `NotFound` would be a lie and would send the requester looking
                // for a chunk that exists; `Refused` is what happened.
                self.refused.fetch_add(1, Ordering::SeqCst);
                ChunkResponse::Refused(format!("this peer will not serve {why}"))
            }
        }
    }

    /// What this peer has served so far.
    #[must_use]
    pub fn stats(&self) -> SeedingStats {
        SeedingStats {
            served_chunks: self.served_chunks.load(Ordering::SeqCst),
            served_bytes: self.served_bytes.load(Ordering::SeqCst),
            not_found: self.not_found.load(Ordering::SeqCst),
            refused: self.refused.load(Ordering::SeqCst),
        }
    }
}

/// A seeding ratio: what a peer uploaded against what it downloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedingRatio {
    /// Bytes this peer served to others.
    pub served_bytes: u64,
    /// Bytes this peer fetched from others.
    pub fetched_bytes: u64,
}

impl SeedingRatio {
    /// The ratio as a percentage, or `None` when it is undefined.
    ///
    /// `None` when nothing has been fetched, because `served / 0` has no value. Reporting
    /// `0%` there would read as "not seeding" and infinity as "perfect", and both would be
    /// wrong answers to a question that has none. This is the case the design's "1000%
    /// health" claim does not cover: it describes a steady state and says nothing about a
    /// peer that has not downloaded anything yet.
    #[must_use]
    pub fn percent(&self) -> Option<u64> {
        if self.fetched_bytes == 0 {
            return None;
        }
        Some(self.served_bytes.saturating_mul(100) / self.fetched_bytes)
    }

    /// Whether this peer is a net contributor.
    ///
    /// `false` when the ratio is undefined: a peer that has exchanged nothing is not yet
    /// contributing, and saying otherwise would be a claim about a peer nobody has asked.
    #[must_use]
    pub fn is_seeding(&self) -> bool {
        self.percent().is_some_and(|p| p >= 100)
    }
}

/// A transport that answers from a [`ChunkServer`] in the same process.
///
/// The in-memory stand-in `nau-net` uses for its own transport, applied here: it lets the
/// exchange, both ends, be tested without a network, and it is what a single-process
/// deployment would use.
#[derive(Debug)]
pub struct Loopback<S: ChunkSource> {
    server: ChunkServer<S>,
}

impl<S: ChunkSource> Loopback<S> {
    /// A transport backed by `server`.
    pub fn new(server: ChunkServer<S>) -> Self {
        Self { server }
    }

    /// The server behind this transport.
    #[must_use]
    pub fn server(&self) -> &ChunkServer<S> {
        &self.server
    }
}

impl<S: ChunkSource> ChunkTransport for Loopback<S> {
    fn request(&self, request: &ChunkRequest) -> Result<ChunkResponse, SourceError> {
        Ok(self.server.answer(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;

    fn store_with(chunks: &[&[u8]]) -> (ChunkServer<MemorySource>, Vec<ChunkDigest>) {
        let mut store = MemorySource::new();
        let digests = chunks.iter().map(|c| store.insert(c)).collect();
        (ChunkServer::new(store), digests)
    }

    #[test]
    fn a_peer_serves_a_chunk_that_verifies() {
        // A-07's first acceptance criterion: fetch from a peer, and check it.
        let (server, digests) = store_with(&[b"first chunk", b"second chunk"]);
        let source = PeerSource::new("peer-a", Loopback::new(server));

        let bytes = source.fetch(&digests[1]).expect("served");
        assert_eq!(bytes, b"second chunk".to_vec());
        assert_eq!(ChunkDigest::of(&bytes), digests[1]);
    }

    #[test]
    fn a_peer_that_lacks_the_chunk_answers_not_found_rather_than_failing() {
        let (server, _) = store_with(&[b"only this"]);
        let source = PeerSource::new("peer-a", Loopback::new(server));
        let err = source
            .fetch(&ChunkDigest::of(b"never stored"))
            .expect_err("absent");
        assert!(matches!(err, SourceError::Missing(_)), "got {err:?}");
    }

    #[test]
    fn a_lying_peer_is_caught_by_the_asking_side() {
        // A transport that returns the wrong bytes and claims success: exactly what a
        // compromised peer would do, and the reason `PeerSource` re-hashes.
        #[derive(Debug)]
        struct Lying;
        impl ChunkTransport for Lying {
            fn request(&self, _r: &ChunkRequest) -> Result<ChunkResponse, SourceError> {
                Ok(ChunkResponse::Data(b"not your chunk".to_vec()))
            }
        }
        let source = PeerSource::new("liar", Lying);
        let err = source
            .fetch(&ChunkDigest::of(b"wanted"))
            .expect_err("lying");
        assert!(matches!(err, SourceError::Corrupt { .. }), "got {err:?}");
    }

    #[test]
    fn an_empty_refusal_reason_is_a_protocol_violation_not_an_answer() {
        // A refusal the requester cannot act on is worse than no answer, because it looks
        // actionable.
        #[derive(Debug)]
        struct Rude;
        impl ChunkTransport for Rude {
            fn request(&self, _r: &ChunkRequest) -> Result<ChunkResponse, SourceError> {
                Ok(ChunkResponse::Refused(String::new()))
            }
        }
        let err = PeerSource::new("rude", Rude)
            .fetch(&ChunkDigest::of(b"x"))
            .expect_err("must refuse");
        assert!(
            format!("{err}").contains("protocol violation"),
            "got: {err}"
        );
    }

    #[test]
    fn a_peer_that_refuses_with_a_reason_passes_it_on() {
        #[derive(Debug)]
        struct Busy;
        impl ChunkTransport for Busy {
            fn request(&self, _r: &ChunkRequest) -> Result<ChunkResponse, SourceError> {
                Ok(ChunkResponse::Refused("over quota".to_string()))
            }
        }
        let err = PeerSource::new("busy", Busy)
            .fetch(&ChunkDigest::of(b"x"))
            .expect_err("refused");
        let text = format!("{err}");
        assert!(
            text.contains("busy") && text.contains("over quota"),
            "got: {text}"
        );
    }

    #[test]
    fn the_server_counts_what_it_served_and_what_it_lacked() {
        let (server, digests) = store_with(&[b"one"]);
        let source = PeerSource::new("p", Loopback::new(server));
        let _ = source.fetch(&digests[0]).expect("served");
        let _ = source.fetch(&digests[0]).expect("served again");
        let _ = source
            .fetch(&ChunkDigest::of(b"absent"))
            .expect_err("absent");

        let stats = source.transport.server().stats();
        assert_eq!(stats.served_chunks, 2);
        assert_eq!(stats.served_bytes, 6);
        assert_eq!(stats.not_found, 1);
        assert_eq!(stats.refused, 0);
        assert_eq!(stats.answered(), 3);
    }

    #[test]
    fn a_seeding_ratio_is_undefined_before_anything_was_fetched() {
        // The case the design's "1000% health" does not cover. `0/0` is neither 0% nor
        // infinite, and reporting either would be a claim about a peer nobody has asked.
        let ratio = SeedingRatio {
            served_bytes: 0,
            fetched_bytes: 0,
        };
        assert_eq!(ratio.percent(), None);
        assert!(
            !ratio.is_seeding(),
            "nothing exchanged is not yet contributing"
        );

        // And serving without ever having fetched is still undefined: the denominator is
        // what has been downloaded, and this peer has downloaded nothing.
        let pure_source = SeedingRatio {
            served_bytes: 1_000_000,
            fetched_bytes: 0,
        };
        assert_eq!(pure_source.percent(), None);
    }

    #[test]
    fn a_seeding_ratio_is_measured_from_what_happened() {
        let ratio = SeedingRatio {
            served_bytes: 2000,
            fetched_bytes: 200,
        };
        assert_eq!(ratio.percent(), Some(1000), "ten times out, so 1000%");
        assert!(ratio.is_seeding());

        let stingy = SeedingRatio {
            served_bytes: 50,
            fetched_bytes: 200,
        };
        assert_eq!(stingy.percent(), Some(25));
        assert!(!stingy.is_seeding());
    }

    #[test]
    fn a_cold_image_leaves_the_ratio_undefined_and_that_is_recorded() {
        // A-07's third acceptance criterion. A peer holding nothing serves nothing, and the
        // honest answer about its health is "no ratio yet" -- not 0%, and certainly not the
        // 1000% the design promises for a steady state. The design's claim and this case are
        // not in conflict once the case is stated: a cold image has no seeders because
        // nobody has the bytes yet.
        let (server, _) = store_with(&[]);
        let source = PeerSource::new("cold", Loopback::new(server));
        let _ = source
            .fetch(&ChunkDigest::of(b"wanted"))
            .expect_err("nothing to serve");

        let stats = source.transport.server().stats();
        assert_eq!(stats.served_chunks, 0);
        assert_eq!(
            stats.not_found, 1,
            "a cold peer answers not-found, not refused"
        );

        let ratio = SeedingRatio {
            served_bytes: stats.served_bytes as u64,
            fetched_bytes: 0,
        };
        assert_eq!(
            ratio.percent(),
            None,
            "a cold image has no seeding ratio; saying 1000% would be a claim about a peer \
             nobody has downloaded from"
        );
    }
}
