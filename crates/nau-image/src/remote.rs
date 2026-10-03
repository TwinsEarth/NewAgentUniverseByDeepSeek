//! The remote sources: what this build can reach, and what it cannot.
//!
//! # UDOS: declared and refused
//!
//! **UDOS** is a separate distributed filesystem. This repository contains no client for it,
//! no interface definition, and no address. Writing `UdosSource` against an interface
//! invented here would produce code that compiles, passes its own tests, and has never
//! spoken to UDOS — which is precisely the "written but not wired" failure this project
//! audits other people for.
//!
//! So it is declared for the reason [`nau_plugin::RuntimeKind`] declares `MicroVm`: a caller
//! can **ask and be refused with a reason**, rather than asking a source that does not exist
//! and getting an empty answer that looks like an empty cache.
//!
//! # P2P: this changed in A-07
//!
//! A-06 refused a peer source too, because **the chunk-exchange protocol was not defined**.
//! A-07 defined it ([`crate::protocol`]) and implemented both ends ([`crate::peer`]), so the
//! stub that used to live here is gone and [`SourceKind::P2p`] is now available.
//!
//! What remains unimplemented is the **carriage**: `nau-libp2p` carries GossipSub frames,
//! which is pub/sub and not request/response, so there is no existing behaviour to hang a
//! chunk exchange on. That gap is named in [`crate::peer`] rather than modelled as an
//! unavailable source, because the exchange itself works — over any transport, including
//! the in-process one.
//!
//! [`nau_plugin::RuntimeKind`]: https://docs.rs/nau-plugin

use nau_core::image::ChunkDigest;

use crate::source::{ChunkSource, SourceError};

/// Which source a reader was configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceKind {
    /// Chunks on the local filesystem.
    Local,
    /// Chunks in a UDOS distributed filesystem.
    Udos,
    /// Chunks fetched from peers.
    P2p,
}

impl SourceKind {
    /// Every kind.
    ///
    /// Exhaustive, so adding a source cannot happen without naming it and deciding its
    /// availability.
    pub const ALL: [SourceKind; 3] = [SourceKind::Local, SourceKind::Udos, SourceKind::P2p];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SourceKind::Local => "local",
            SourceKind::Udos => "udos",
            SourceKind::P2p => "p2p",
        }
    }

    /// Why this source cannot be used, or `None` when it can.
    ///
    /// The same shape as `RuntimeKind::unavailability`, deliberately: one vocabulary for
    /// "declared but not available, and here is why" serves both.
    #[must_use]
    pub fn unavailability(self) -> Option<&'static str> {
        match self {
            SourceKind::Local | SourceKind::P2p => None,
            SourceKind::Udos => Some(
                "UDOS is a separate distributed filesystem and this repository contains no \
                 client for it; binding to an interface invented here would produce code that \
                 compiles and has never spoken to UDOS, so a UDOS source is refused rather \
                 than faked -- use `local` (or a peer, from A-07) until a UDOS client exists",
            ),
        }
    }

    /// Whether this build can serve chunks from this source.
    #[must_use]
    pub fn is_available(self) -> bool {
        self.unavailability().is_none()
    }
}

/// A UDOS source. Every fetch is refused, with a reason.
#[derive(Debug, Clone, Copy, Default)]
pub struct UdosSource;

impl ChunkSource for UdosSource {
    fn fetch(&self, _digest: &ChunkDigest) -> Result<Vec<u8>, SourceError> {
        Err(SourceError::Unavailable(
            SourceKind::Udos
                .unavailability()
                .unwrap_or("UDOS is unavailable")
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_and_peer_are_available_and_udos_is_not() {
        // P2P moved from unavailable to available in A-07, when the protocol it was missing
        // got defined. The test moved with it.
        assert!(SourceKind::Local.is_available());
        assert!(SourceKind::P2p.is_available());
        assert!(!SourceKind::Udos.is_available());
    }

    #[test]
    fn udos_says_why_and_what_to_use_instead() {
        let why = SourceKind::Udos
            .unavailability()
            .expect("must explain itself");
        assert!(why.contains("refused rather than faked"), "{why}");
        assert!(
            why.contains("local"),
            "it must name a source that works, got: {why}"
        );
    }

    #[test]
    fn every_declared_kind_is_classified() {
        assert_eq!(SourceKind::ALL.len(), 3);
        let unavailable = SourceKind::ALL.iter().filter(|k| !k.is_available()).count();
        assert_eq!(unavailable, 1, "only UDOS is still unavailable");
        for kind in SourceKind::ALL {
            assert!(!kind.label().is_empty());
        }
    }

    #[test]
    fn the_udos_stub_refuses_every_fetch_rather_than_returning_nothing() {
        // An empty `Ok(vec![])` would be indistinguishable from a corrupt chunk downstream
        // and would let a misconfigured reader look like it was working.
        let err = UdosSource
            .fetch(&ChunkDigest::of(b"anything"))
            .expect_err("must refuse");
        match err {
            SourceError::Unavailable(why) => assert!(!why.trim().is_empty()),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }
}
