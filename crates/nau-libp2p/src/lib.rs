//! # nau-libp2p — the real libp2p stack behind the `libp2p` feature
//!
//! `README.md` and `docs/ARCHITECTURE.md` state that the libp2p stack is *not*
//! implemented and that this project offers a `Transport` port, a real TCP
//! transport, an explicitly-named in-memory double and real STUN/NAT measurement
//! instead. This crate is the change to that statement. It provides the real stack
//! — Kademlia DHT, GossipSub, Circuit Relay v2, AutoNAT and DCUtR — composed into
//! one swarm and adapted onto the **existing** [`nau_net::Transport`] port, so the
//! TCP and memory transports and this one are interchangeable at the port and
//! nothing above it has to know which is in use.
//!
//! ## The feature is off by default, and that is the design
//!
//! ```toml
//! [features]
//! default = []
//! libp2p = ["dep:libp2p", "dep:tokio", "dep:futures"]
//! ```
//!
//! `libp2p` is an optional dependency, so `cargo build --workspace` — which runs on
//! three operating systems in CI and on the 16 GB machine this was developed on —
//! does not pay for it. `cargo test -p nau-libp2p` with no features still runs the
//! feature-independent half of this crate for real:
//!
//! * [`identity`] — the `did:nau:` ↔ libp2p `PeerId` derivation, including its own
//!   base58btc and multihash implementation;
//! * [`naming`] — Kademlia protocol name, room topic names and record keys;
//! * [`codec`] — the wire format, with the frame cap enforced before allocation;
//! * [`config`] — every validation rule, including its own multiaddr parser.
//!
//! The cost of that arrangement is stated where it applies: the local base58,
//! multihash and multiaddr implementations are cross-checked against libp2p's own
//! only when the feature is on. See the module docs of [`identity`] and [`config`].
//!
//! ## MSRV: 1.85, and the lock file does *not* fall out of `generate-lockfile`
//!
//! The workspace MSRV is **1.85** and is not raised by this crate. Getting a
//! libp2p dependency tree to build on 1.85 required pinning five transitive
//! crates, because **plain `cargo generate-lockfile` produces a lock that does not
//! build on 1.85**, and it does so silently — the crates involved declare
//! `rust-version = 1.81`–`1.83` while using APIs that only exist later. Whoever
//! regenerates the lock must re-apply these pins:
//!
//! | pin | why |
//! |---|---|
//! | `libp2p 0.56.0` | `0.57.0` declares `rust-version = 1.88`. `0.56.0` declares 1.83. |
//! | `zerovec 0.11.5`, `yoke 0.8.2`, `yoke-derive 0.8.2` | `yoke-derive 0.8.3` fails on 1.85 with `error[E0599]: no function or associated item named from_utf8 found for type str`. `str::from_utf8` as a module path is 1.87+; `yoke` 0.8.2 declares MSRV 1.82, so this is an undeclared-MSRV break upstream, not a mistake here. `zerovec 0.11.6`+ requires `yoke ^0.8.3`, so `zerovec` has to come down with it. |
//! | `multibase 0.9.2` | `multibase 0.9.3` depends on `base45 ^3.2.0`, which uses the unstable `slice_as_chunks` (`error[E0658]`). `0.9.2` has no `base45` dependency at all. |
//! | `idna_adapter 1.2.1`, `icu_* 2.1.x` | `idna_adapter 1.2.2` needs `icu_* ^2.2` and declares 1.86; `icu_* 2.3.x` declares 1.88. The 2.1.x line declares 1.83. |
//!
//! The exact commands that reproduce them, from the workspace root:
//!
//! ```text
//! cargo update -p zerovec --precise 0.11.5
//! cargo update -p yoke --precise 0.8.2
//! cargo update -p yoke-derive --precise 0.8.2
//! cargo update -p multibase --precise 0.9.2
//! cargo update -p idna_adapter --precise 1.2.1
//! cargo update -p icu_normalizer --precise 2.1.1
//! cargo update -p icu_properties --precise 2.1.2
//! ```
//!
//! A faster and more reliable alternative, when the lock is being regenerated
//! anyway, is cargo's MSRV-aware resolver, which selects all of these in one pass:
//!
//! ```text
//! # with `[resolver] incompatible-rust-versions = "fallback"` in .cargo/config.toml
//! cargo +1.85.0 update
//! ```
//!
//! `--locked` is what makes the committed `Cargo.lock` authoritative in CI; these
//! notes are what make it repairable.
//!
//! ## Functional limits of the shipped feature set, stated plainly
//!
//! The libp2p feature set is written out rather than using upstream's `full`,
//! because `full` enables `websocket`, `webtransport-websys`, `quic`, `tls` and
//! `dns`, which pull `rustls`/`webpki`/`x509-parser`/`time` and the `idna` chain
//! above 1.85. The consequences are real and are not footnotes:
//!
//! * **No QUIC.** The transport is TCP + Noise + Yamux only.
//! * **No DNS resolution.** `bootstrap` and `relay_reservations` must be
//!   **IP-based** multiaddrs (`/ip4/…` or `/ip6/…`); a `/dns4/…` or `/dnsaddr/…`
//!   address parses and validates but will not resolve, so the dial fails.
//! * No WebSocket or WebTransport transports.
//!
//! Enabled: TCP, Noise, Yamux, Kademlia, GossipSub, Circuit Relay v2 (client *and*
//! server), AutoNAT, DCUtR, identify and ping.
//!
//! ## Three operational facts that are not obvious, and are load-bearing
//!
//! 1. **A node that should serve DHT records must be configured with
//!    [`config::KadMode::Server`].** A Kademlia node in `Client` mode does not add
//!    connected peers to its routing table, so a two-node network of clients
//!    connects, identifies and gossips perfectly while `put_record` answers
//!    `QuorumFailed` and `get_record` on the other node cannot find the record.
//!    `Client` is still the default, because a node behind a NAT genuinely should
//!    not advertise itself as a DHT server and `KadMode` has to have *a* default —
//!    but a deployment that wants a working DHT must ask for `Server`.
//! 2. **A relay reservation is a `listen_on`, not a `dial`.** Listening on
//!    `/<relay>/p2p/<relay id>/p2p-circuit` is what makes the Circuit Relay v2
//!    client send a HOP reserve request. Dialling the relay's plain address does
//!    not request anything. [`swarm::Libp2pNode::reserve_relay`] builds the right
//!    address from the one the caller supplies.
//! 3. **A DHT record is limited to [`swarm::DHT_MAX_VALUE_BYTES`] (65 KiB), which
//!    is smaller than the 8 MiB frame cap.** A payload this transport is happy to
//!    carry over GossipSub can be too large to store in Kademlia. Both limits are
//!    named in the error a caller gets, so the asymmetry is discoverable rather
//!    than mysterious.
//!
//! ## What a two-node test proves, and what it does not
//!
//! `tests/two_node.rs` runs real swarms on `127.0.0.1` in one process and asserts
//! dial + identify, a GossipSub message travelling from one node to another, a
//! Kademlia record put on one node and retrieved by the other, and a relay
//! reservation granted by a relay node. `tests/transport_adapter.rs` asserts the
//! [`nau_net::Transport`] contract through the port, `tests/libp2p_identity_agreement.rs`
//! asserts the identity derivation against libp2p's own, and
//! `tests/feature_independent.rs` covers the half of the crate that needs no
//! libp2p.
//!
//! **Not verified end to end:** DCUtR hole punching and AutoNAT reachability. Both
//! behaviours are constructed and wired, and both are deliberately untested against
//! a real peer — the reason is stated in `tests/two_node.rs` rather than hidden
//! behind a test that would pass for an unrelated reason. The AutoNAT verdict *is*
//! asserted to be `Unknown` when no server is configured, which is the honest
//! answer for a loopback-only node.
//!
//! ## Example
//!
//! ```no_run
//! # #[cfg(feature = "libp2p")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use nau_libp2p::config::{Libp2pConfig, Multiaddr};
//! use nau_libp2p::identity::NauIdentity;
//! use nau_libp2p::swarm::Libp2pNode;
//!
//! let seed = [7u8; 32];
//! let identity = NauIdentity::from_seed(&seed);
//! let config = Libp2pConfig::new(&identity, Multiaddr::parse("/ip4/127.0.0.1/tcp/0")?)
//!     .with_seed(seed)?
//!     .with_room("room-0000000000000001");
//! config.validate()?;
//!
//! let node = Libp2pNode::spawn(config).await?;
//! let topic = "nau/room/room-0000000000000001";
//! let delivered_to = node.publish(topic, &nau_net::Frame::new(b"hello".to_vec())).await?;
//! // Zero is a real answer: the message was accepted and nobody was subscribed.
//! println!("queued for {delivered_to} peers");
//! node.shutdown().await;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod codec;
pub mod config;
pub mod identity;
pub mod naming;

#[cfg(feature = "libp2p")]
pub mod behaviour;
#[cfg(feature = "libp2p")]
pub mod swarm;
#[cfg(feature = "libp2p")]
pub mod transport;

#[cfg(feature = "libp2p")]
pub use behaviour::{
    build_gossipsub, kademlia_config, to_libp2p_peer_id, BehaviourError, DcutrBehaviour,
    GossipSubBehaviour, IdentifyBehaviour, KademliaBehaviour, Libp2pBehaviour, NatStatus, NauEvent,
    PingBehaviour, RelayClient, RelayServer,
};
#[cfg(feature = "libp2p")]
pub use swarm::{
    Libp2pNode, Replication, SwarmError, SwarmStats, COMMAND_CHANNEL_CAPACITY,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_HOLE_PUNCH_TIMEOUT, DEFAULT_PUT_TIMEOUT,
    DEFAULT_RECORD_TIMEOUT, DEFAULT_RESERVATION_TIMEOUT, DHT_MAX_VALUE_BYTES,
    INBOUND_QUEUE_CAPACITY, LISTEN_CONFIRM_TIMEOUT,
};
#[cfg(feature = "libp2p")]
pub use transport::{peer_from_label, Libp2pTransport, TransportStats, LABEL_PREFIX};

pub use codec::{
    check_nonce_len, decode_envelope, decode_envelope_with_budget, encode_envelope, encoded_len,
    CodecError, Envelope, HEADER_BYTES, MAX_PAYLOAD_BYTES, NONCE_BYTES, PROTOCOL_VERSION,
};
pub use config::{
    is_loopback_or_memory, validate_multiaddr, ConfigError, ConfigProblem, KadMode, Libp2pConfig,
    Multiaddr, MAX_AUTONAT_SERVERS, MAX_BOOTSTRAP_PEERS, MAX_DCUTR_PEERS, MAX_LISTEN_ADDRS,
    MAX_MULTIADDR_BYTES, MAX_RELAY_RESERVATIONS,
};
pub use identity::{
    base58_decode, base58_encode, describe_identity, did_for_public_key, encode_ed25519_public_key,
    peer_id_for_did, peer_id_string, IdentityError, NauIdentity, PeerId, ED25519_PEER_ID_BYTES,
    ED25519_PUBLIC_KEY_BYTES,
};
pub use naming::{
    record_key, room_from_topic, room_topic, NameError, RoomName, KAD_PROTOCOL,
    MAX_RECORD_KEY_BYTES, MAX_ROOM_NAME_BYTES, RECORD_KEY_PREFIX, ROOM_TOPIC_PREFIX,
};

/// This crate's version, from the workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Whether the real libp2p stack was compiled in.
///
/// A caller can check this at run time instead of discovering it from a build
/// failure. A build without the feature has no `swarm` module at all, so this is
/// the only way to branch on it in code that must compile either way.
pub const LIBP2P_ENABLED: bool = cfg!(feature = "libp2p");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crate_reports_whether_the_stack_is_present() {
        // The two must agree: `LIBP2P_ENABLED` is only honest if the feature
        // really gates the modules.
        assert_eq!(LIBP2P_ENABLED, cfg!(feature = "libp2p"));
        assert_eq!(VERSION, "1.1.1");
    }

    #[test]
    fn the_feature_independent_surface_is_always_available() {
        // These are what `cargo test -p nau-libp2p` with no features exercises, so
        // they must not be behind the feature gate.
        let identity = NauIdentity::from_seed(&[1u8; 32]);
        assert_eq!(identity.did().as_str(), "did:nau:34750f98bd59fcfc");
        assert_eq!(identity.peer_id().to_string().len(), 52);
        let room = RoomName::parse("room-0000000000000001").expect("valid room");
        assert_eq!(room.topic(), "nau/room/room-0000000000000001");
        assert_eq!(record_key("k").expect("valid key"), b"nau/rec/k".to_vec());
        let frame = nau_net::Frame::new(b"x".to_vec());
        let encoded =
            encode_envelope(&identity.peer_id(), [0u8; NONCE_BYTES], &frame).expect("encodes");
        assert_eq!(
            decode_envelope(&encoded).expect("decodes").payload(),
            &frame
        );
        let config = Libp2pConfig::new(
            &identity,
            Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid"),
        );
        // Without a seed the configuration is incomplete, and that is a problem
        // this build can report without libp2p.
        assert!(config.problems().contains(&ConfigProblem::MissingSeed));
        assert_eq!(KAD_PROTOCOL, "/nau/kad/1.0.0");
        assert_eq!(MAX_PAYLOAD_BYTES, nau_net::MAX_FRAME_BYTES);
    }
}
