//! The remote sources: declared, and honest about not being implemented.
//!
//! # Why these are declarations rather than implementations
//!
//! A-06's plan names three sources — local, UDOS, P2P — and says to do centralised reading
//! first. Local is done ([`crate::local`]). The other two are **not**, and the reason is
//! not effort:
//!
//! * **UDOS** is a separate distributed filesystem. This repository contains no client for
//!   it, no interface definition, and no address. Writing `UdosSource` against an interface
//!   invented here would produce code that compiles, passes its own tests, and has never
//!   spoken to UDOS — which is precisely the "written but not wired" failure this project
//!   audits other people for.
//! * **P2P** chunk exchange is not defined either. `nau-libp2p` provides transport, and an
//!   image protocol on top of it is a protocol that has to be designed before it can be
//!   implemented.
//!
//! So they are declared for the reason [`nau_plugin::RuntimeKind`] declares `MicroVm`: a
//! caller can **ask and be refused with a reason**, rather than asking a source that does
//! not exist and getting an empty answer that looks like an empty cache. The difference
//! between "this chunk is not there" and "this source cannot be used here" is the
//! difference between trying elsewhere and reporting a deployment fault.
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
    /// "declared but not available, and here is why" serves both, and a reader who has met
    /// it once will recognise it here.
    #[must_use]
    pub fn unavailability(self) -> Option<&'static str> {
        match self {
            SourceKind::Local => None,
            SourceKind::Udos => Some(
                "UDOS is a separate distributed filesystem and this repository contains no \
                 client for it; binding to an interface invented here would produce code that \
                 compiles and has never spoken to UDOS, so a UDOS source is refused rather \
                 than faked -- use `local` until a UDOS client exists",
            ),
            SourceKind::P2p => Some(
                "an image chunk protocol over the peer transport is not defined; nau-libp2p \
                 provides transport, not chunk exchange, so a P2P source is refused rather \
                 than faked -- use `local` until the protocol exists",
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

/// A peer source. Every fetch is refused, with a reason.
#[derive(Debug, Clone, Copy, Default)]
pub struct P2pSource;

impl ChunkSource for P2pSource {
    fn fetch(&self, _digest: &ChunkDigest) -> Result<Vec<u8>, SourceError> {
        Err(SourceError::Unavailable(
            SourceKind::P2p
                .unavailability()
                .unwrap_or("peer fetching is unavailable")
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_is_available_and_the_other_two_are_not() {
        assert!(SourceKind::Local.is_available());
        assert!(!SourceKind::Udos.is_available());
        assert!(!SourceKind::P2p.is_available());
    }

    #[test]
    fn an_unavailable_source_says_why_and_what_to_do_instead() {
        // The message is the whole value of declaring these. A refusal that does not name a
        // next step leaves the reader exactly where they were.
        for kind in [SourceKind::Udos, SourceKind::P2p] {
            let why = kind.unavailability().expect("must explain itself");
            assert!(why.contains("refused rather than faked"), "{kind:?}: {why}");
            assert!(
                why.contains("local"),
                "{kind:?} must name the source that does work, got: {why}"
            );
        }
        assert!(SourceKind::Local.unavailability().is_none());
    }

    #[test]
    fn every_declared_kind_is_classified() {
        // The totality check: `ALL` is exhaustive, so a new source cannot be added without
        // appearing here and being decided about.
        assert_eq!(SourceKind::ALL.len(), 3);
        let unavailable = SourceKind::ALL.iter().filter(|k| !k.is_available()).count();
        assert_eq!(
            unavailable, 2,
            "local works; the two remote kinds do not yet"
        );
        for kind in SourceKind::ALL {
            assert!(!kind.label().is_empty());
        }
    }

    #[test]
    fn a_stub_source_refuses_every_fetch_rather_than_returning_nothing() {
        // An empty `Ok(vec![])` would be indistinguishable from a corrupt chunk downstream
        // and would let a misconfigured reader look like it was working.
        let digest = ChunkDigest::of(b"anything");
        for err in [
            UdosSource.fetch(&digest).expect_err("must refuse"),
            P2pSource.fetch(&digest).expect_err("must refuse"),
        ] {
            match err {
                SourceError::Unavailable(why) => assert!(!why.trim().is_empty()),
                other => panic!("expected Unavailable, got {other:?}"),
            }
        }
    }
}
