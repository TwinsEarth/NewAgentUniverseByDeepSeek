//! # nau-net — real transport, deterministic topology, relay pool
//!
//! This crate replaces upstream `agent-universe` v2.5.6 `gsn-core/src/net/*`,
//! `src/topology/*` and `src/relay_pool/mod.rs`.
//!
//! ## What was wrong upstream, and what is done here
//!
//! **Transport.** Upstream exported three in-memory mocks named exactly like the
//! services they stood in for (`net/dht.rs::KademliaClient`,
//! `net/gossip.rs::GossipSub`, `net/libp2p_node.rs::GsnNode`), each backed by a
//! `HashMap`, so integration tests "proved" networking against a map. Here there
//! is one port, [`Transport`], a substitute that says so in its name
//! ([`MemoryTransport`]), and a real socket implementation
//! ([`TcpTransport`]) with a 4-byte big-endian length prefix, an 8 MiB frame cap
//! checked *before* allocation, and read timeouts — exercised by sending frames
//! between two live endpoints on `127.0.0.1:0`.
//!
//! **Topology.** Upstream was non-deterministic (room assignment iterated a
//! `HashMap`), claimed "≤ 7 hops" while `route_hops` returned the constant
//! `Some(7)` for every cross-room pair, omitted the uplink edge from `fanin_of`,
//! asserted sub-quadratic edges with a threshold that could never fail, and
//! rebuilt every level on each insert (O(N²) construction). [`LayeredTopology`]
//! derives level and room from a pure hash of the node id, computes hops from the
//! real room tree, counts the uplink in `fanin_of`, adds incrementally, and is
//! proven order-independent and sub-quadratic by measurement in `tests/`.
//!
//! **Relay pool.** Upstream's capacity was advisory (checked, then inserted
//! non-atomically, with other insert paths skipping the check), re-adding a relay
//! resurrected it by resetting `healthy`/`fail_count`, and probing the same
//! `PeerId` twice overwrote the pending entry so a stale result could mark a
//! healthy relay dead. [`RelayPool`] enforces capacity inside the inserting call,
//! changes health only through `record_failure`/`record_success`, and refuses a
//! duplicate probe while keeping the first.
//!
//! **NAT traversal.** Upstream `nat/mod.rs` returned hard-coded constants
//! (`nat_type` was always `PortRestrictedCone`, `connect` always `Connected`) and
//! its tests asserted them, so the suite locked the simulation in. [`stun`] is a
//! real RFC 5389 codec (padded TLVs, `XOR-MAPPED-ADDRESS` for IPv4 and IPv6,
//! transaction-id matching) that sends Binding Requests over UDP, and [`nat`]
//! classifies mapping and filtering behaviour by *comparing the transport
//! addresses that servers actually report*. When nothing is reachable the answer
//! is `Unknown` with the failure recorded — never a fabricated NAT type. See the
//! module docs for exactly what is and is not claimed.
//!
//! ## Example
//!
//! ```no_run
//! # async fn demo() -> nau_core::Result<()> {
//! use nau_net::{Frame, PeerId, TcpTransport, Transport};
//!
//! let server = TcpTransport::bind("127.0.0.1:0").await?;
//! let client = TcpTransport::bind("127.0.0.1:0").await?;
//! let peer = client.connect(&server.local_addr()?).await?;
//! client.send(&peer, Frame(b"hello".to_vec())).await?;
//! let (from, frame) = server
//!     .recv(std::time::Duration::from_secs(5))
//!     .await?
//!     .expect("a frame arrives");
//! assert_eq!(frame.as_slice(), b"hello");
//! server.send(&from, Frame(b"ack".to_vec())).await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod memory;
pub mod nat;
pub mod peer;
pub mod relay;
pub mod stun;
pub mod tcp;
pub mod topology;
pub mod transport;

mod lock;

pub use memory::MemoryTransport;
pub use nat::{
    classify_filtering, classify_mapping, FilteringBehavior, MappingBehavior, NatProbe, NatProfile,
    Observation, ObservationAttempts, ObservationSet, Probed, StunProbe,
};
pub use peer::{Frame, PeerId, MAX_PEER_ID_LEN};
pub use relay::{PendingProbe, RelayClass, RelayNode, RelayPool};
pub use stun::{
    binding_request, BindingReply, BindingRequest, BindingResponse, ChangeRequest, MappedAddress,
    ReflexiveAddress, StunError, StunMessage, TransactionId, XorMappedAddress,
};
pub use tcp::{TcpTransport, DEFAULT_READ_TIMEOUT};
pub use topology::LayeredTopology;
pub use transport::{
    check_frame_len, encode_frame, Transport, FRAME_PREFIX_BYTES, MAX_FRAME_BYTES,
};
