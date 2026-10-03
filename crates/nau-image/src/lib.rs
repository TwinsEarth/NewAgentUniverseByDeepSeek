//! # nau-image — resolving an image manifest's chunks on demand
//!
//! AUSec's premise is that an agent touches a small fraction of its image, so an image is
//! fetched chunk by chunk rather than as one blob. [`nau_core::image`] defines the
//! vocabulary — a [`ChunkDigest`] names content, a [`ChunkRef`] says where it sits, an
//! [`ImageManifest`] is the whole — and this crate is the thing that **resolves** them.
//!
//! # What this crate is, and what it deliberately is not
//!
//! It is a **reader**: given a manifest and a source, it answers "give me bytes
//! `[offset, offset+length)`" by fetching the chunks that cover that range and nothing
//! else. It is not a connection, a protocol, or a peer. The source is a port
//! ([`ChunkSource`]) with an in-memory implementation here and real ones to follow, so the
//! reader's behaviour — what it fetches, what it caches, what it measures — is testable
//! without a network.
//!
//! # Why the counts matter more than the timings
//!
//! The claim this release has to make good on is *"a read fetches only what it needs"*,
//! and that is a **count**, not a duration: `nau-image` records how many chunks each read
//! asked the source for, and a test asserts the number. Latency is recorded too
//! ([`Metrics::p50_micros`], [`Metrics::p99_micros`]) because the plan's acceptance
//! criterion asks for a single-step p99 against a full pull — but a timing is a
//! measurement of the machine it ran on, and a test that asserted one would be asserting
//! the runner's load.
//!
//! # No I/O in the types
//!
//! The reader performs no I/O of its own. Everything that touches the outside world goes
//! through [`ChunkSource`], which is why the crate compiles and its tests run with no
//! filesystem, no sockets and no async runtime.
//!
//! [`ChunkDigest`]: nau_core::image::ChunkDigest
//! [`ChunkRef`]: nau_core::image::ChunkRef
//! [`ImageManifest`]: nau_core::image::ImageManifest

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod local;
pub mod peer;
pub mod protocol;
pub mod reader;
pub mod remote;
pub mod source;
pub mod verified;

pub use local::LocalSource;
pub use peer::{ChunkServer, ChunkTransport, Loopback, PeerSource, SeedingRatio, SeedingStats};
pub use protocol::{ChunkRequest, ChunkResponse};
pub use reader::{ChunkReader, Metrics, ReadReport};
pub use remote::{SourceKind, UdosSource};
pub use source::{ChunkSource, MemorySource, SourceError};
pub use verified::{VerificationStats, VerifiedSource};

// The manifest vocabulary, re-exported. It is defined in `nau-core` -- which is where it
// belongs, as pure data -- but a caller holding a reader needs it in the same breath, and
// making them add a second dependency to name the thing they are reading would be a
// distinction without a purpose. The types are not redefined here; there remains exactly one
// `ChunkDigest` in the workspace.
pub use nau_core::image::{
    ChunkAttestation, ChunkDigest, ChunkRef, ImageManifest, SignaturePolicy,
};
