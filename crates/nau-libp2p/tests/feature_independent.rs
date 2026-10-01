//! Integration tests for the feature-independent half of the crate.
//!
//! This file has **no** `cfg(feature = "libp2p")` gate on purpose. It is what
//! `cargo test -p nau-libp2p` runs on a machine that cannot build libp2p at all,
//! and it is the reason the crate's design puts the identity mapping, the naming
//! rules, the codec and the configuration validation on the feature-independent
//! side of the line: those four are exactly the parts that must be verifiable
//! without the dependency.
//!
//! Unit tests in `src/` cover each module in isolation; these cover them *together*,
//! through the crate's public API, which is how a caller sees them.

use std::time::Duration;

use nau_libp2p::codec::{
    decode_envelope, decode_envelope_with_budget, encode_envelope, CodecError, HEADER_BYTES,
    MAX_PAYLOAD_BYTES, NONCE_BYTES, PROTOCOL_VERSION,
};
use nau_libp2p::config::{ConfigProblem, KadMode, Libp2pConfig, Multiaddr};
use nau_libp2p::identity::{base58_decode, base58_encode, IdentityError, NauIdentity, PeerId};
use nau_libp2p::naming::{record_key, room_from_topic, room_topic, RoomName, KAD_PROTOCOL};
use nau_net::{Frame, MAX_FRAME_BYTES};

/// The fixed seed every conformance vector in every language uses.
const CONFORMANCE_SEED: [u8; 32] = [1u8; 32];

#[test]
fn the_did_and_the_peer_id_are_two_views_of_one_key() {
    // The seam that makes the two stacks interoperable, exercised end to end.
    let seed = CONFORMANCE_SEED;
    let identity = NauIdentity::from_seed(&seed);

    // The DID is the one the rest of the workspace uses.
    assert_eq!(identity.did().as_str(), "did:nau:34750f98bd59fcfc");
    assert_eq!(identity.fingerprint(), "34750f98bd59fcfc");

    // The peer id is derived from the same key, deterministically.
    let again = NauIdentity::from_seed(&seed);
    assert_eq!(again.peer_id(), identity.peer_id());
    assert_eq!(
        identity.peer_id().to_string(),
        "12D3KooWK99VoVxNE7XzyBwXEzW7xhK7Gpv85r9F3V3fyKSUKPH5",
        "an inline (identity-multihash) Ed25519 peer id"
    );

    // It round-trips through the textual form that goes on the wire.
    let text = identity.peer_id().to_string();
    let parsed = PeerId::parse(&text).expect("its own rendering parses");
    assert_eq!(parsed, identity.peer_id());
    assert_eq!(parsed.to_string(), text);

    // A different key is a different identity, in both views.
    let other = NauIdentity::from_seed(&[2u8; 32]);
    assert_ne!(other.did(), identity.did());
    assert_ne!(other.peer_id(), identity.peer_id());

    // The pairing check refuses a mismatched (DID, key) pair in both directions.
    assert!(matches!(
        NauIdentity::from_did_and_public_key(other.did().as_str(), *identity.public_key())
            .unwrap_err(),
        IdentityError::DidKeyMismatch { .. }
    ));
    assert!(matches!(
        NauIdentity::from_did_and_public_key("not-a-did", *identity.public_key()).unwrap_err(),
        IdentityError::InvalidDid { .. }
    ));
    // And the legacy prefix still binds to the same key.
    let migrated =
        NauIdentity::from_did_and_public_key("did:aip:34750f98bd59fcfc", *identity.public_key())
            .expect("the upstream prefix migrates");
    assert_eq!(migrated.peer_id(), identity.peer_id());
}

#[test]
fn base58_round_trips_every_byte_value_and_the_reference_vectors() {
    for byte in 0u16..=255 {
        let input = [byte as u8];
        assert_eq!(
            base58_decode(&base58_encode(&input)).expect("round trip"),
            input.to_vec()
        );
    }
    // Bitcoin Core's reference vectors.
    for (bytes, text) in [
        (vec![], ""),
        (vec![0x61], "2g"),
        (vec![0x00], "1"),
        (vec![0x00, 0x61], "12g"),
        (vec![0xff], "5Q"),
        (vec![0xff, 0xff], "LUv"),
        (vec![0x01, 0x02, 0x03], "Ldp"),
    ] {
        assert_eq!(base58_encode(&bytes), text);
        assert_eq!(base58_decode(text).expect("decode"), bytes);
    }
    // The empty string decodes to nothing, and is still not a peer id.
    assert!(base58_decode("").expect("decodes").is_empty());
    assert!(PeerId::parse("").is_err());
}

#[test]
fn the_namespace_keeps_this_application_out_of_the_shared_dht() {
    // The protocol name and the key prefix are a compatibility surface.
    assert_eq!(KAD_PROTOCOL, "/nau/kad/1.0.0");
    assert_eq!(
        record_key("agent/alice").expect("a valid key"),
        b"nau/rec/agent/alice".to_vec()
    );

    // A room becomes a topic, and the topic becomes the room again.
    let room = RoomName::parse("room-0000000000000007").expect("a valid room");
    assert_eq!(room.topic(), "nau/room/room-0000000000000007");
    assert_eq!(room_topic("x9_-"), "nau/room/x9_-");
    assert_eq!(
        room_from_topic("nau/room/room-0000000000000007").expect("round trip"),
        room
    );

    // The separator that used to make two rooms collide is refused.
    assert!(RoomName::parse("room-a/b").is_err());
    assert!(RoomName::parse("room:a").is_err());
    assert!(room_from_topic("nau/room/a/b").is_err());
    assert!(room_from_topic("other/topic").is_err());
}

#[test]
fn a_frame_crosses_the_codec_and_the_cap_is_enforced_before_allocating() {
    let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);
    let frame = Frame::new(b"a payload".to_vec());
    let encoded = encode_envelope(&identity.peer_id(), [9u8; NONCE_BYTES], &frame).expect("encode");

    assert_eq!(encoded[0], PROTOCOL_VERSION);
    assert_eq!(encoded.len(), HEADER_BYTES + frame.len());
    let decoded = decode_envelope(&encoded).expect("decode");
    assert_eq!(decoded.sender(), &identity.peer_id());
    assert_eq!(decoded.nonce(), &[9u8; NONCE_BYTES]);
    assert_eq!(decoded.payload(), &frame);

    // The codec's cap is the transport port's cap, so anything storable is
    // transmittable and anything else is refused on both sides of the boundary.
    assert_eq!(MAX_PAYLOAD_BYTES, MAX_FRAME_BYTES);
    assert!(encode_envelope(
        &identity.peer_id(),
        [0u8; NONCE_BYTES],
        &Frame::new(vec![0u8; MAX_PAYLOAD_BYTES + 1])
    )
    .is_err());

    // Every truncation short of the header is refused without indexing.
    for len in 0..HEADER_BYTES {
        assert!(decode_envelope(&encoded[..len]).is_err(), "length {len}");
    }

    // A caller's budget is honoured and cannot be raised past the hard cap.
    let over = [&encoded[..HEADER_BYTES], &[0u8; 64][..]].concat();
    assert!(matches!(
        decode_envelope_with_budget(&over, 63).expect_err("over budget"),
        CodecError::OverBudget { .. }
    ));
    assert!(decode_envelope_with_budget(&over, usize::MAX).is_ok());
}

#[test]
fn a_configuration_is_validated_all_at_once() {
    let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);

    // A configuration without a key is invalid: a peer id cannot sign.
    let keyless = Libp2pConfig::new(
        &identity,
        Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid"),
    );
    assert_eq!(
        keyless.problems(),
        vec![ConfigProblem::MissingSeed],
        "one problem, reported once"
    );
    assert!(keyless.validate().is_err());

    // With the key it is valid, and adding a room does not change that.
    let base = keyless
        .with_seed(CONFORMANCE_SEED)
        .expect("the seed is that identity's key");
    assert_eq!(base.problems(), Vec::new());
    assert!(base.validate().is_ok());
    let with_room = base.clone().with_room("room-0000000000000001");
    assert!(with_room.validate().is_ok());
    assert_eq!(
        with_room.topics(),
        vec![room_topic("room-0000000000000001")]
    );

    // Every rejection rule, in one call.
    let mut broken = base.clone();
    broken.listen.clear();
    broken.kad_protocol = "/other/kad/1.0.0".to_string();
    broken.kad_mode = KadMode::Server;
    broken = broken.with_dcutr();
    broken.rejected_bootstrap.push("nonsense".to_string());
    let problems = broken.problems();
    assert!(problems.len() >= 4, "got {problems:?}");
    assert!(problems
        .iter()
        .any(|p| matches!(p, ConfigProblem::EmptyListenSet)));
    assert!(problems
        .iter()
        .any(|p| matches!(p, ConfigProblem::WrongKadProtocol { .. })));
    assert!(problems
        .iter()
        .any(|p| matches!(p, ConfigProblem::DcutrWithoutServer)));
    // The rendered error names every problem rather than the first.
    let rendered = broken.validate().expect_err("invalid").to_string();
    for problem in &problems {
        assert!(rendered.contains(&problem.to_string()), "{rendered}");
    }
}

#[test]
fn a_bootstrap_list_cannot_contain_this_node() {
    let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);
    let base = Libp2pConfig::new(
        &identity,
        Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid"),
    )
    .with_seed(CONFORMANCE_SEED)
    .expect("the seed is that identity's key");

    // Dialling yourself is a loop, not a bootstrap.
    let own = format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", identity.peer_id());
    let self_bootstrap = base.clone().with_bootstrap(&own);
    assert_eq!(
        self_bootstrap.problems(),
        vec![ConfigProblem::BootstrapContainsSelf {
            peer_id: identity.peer_id().to_string()
        }]
    );

    // A bootstrap entry with no peer component names a host but no peer.
    let no_peer = base.clone().with_bootstrap("/ip4/127.0.0.1/tcp/4001");
    assert!(matches!(
        no_peer.problems()[0],
        ConfigProblem::BootstrapWithoutPeerId { .. }
    ));

    // A malformed entry is reported rather than dropped silently.
    let malformed = base.clone().with_bootstrap("/ip4/127.0.0.1/tpc/4001");
    assert!(matches!(
        malformed.problems()[0],
        ConfigProblem::MalformedMultiaddr { .. }
    ));

    // A genuine other peer is accepted.
    let other = NauIdentity::from_seed(&[7u8; 32]);
    let good = base.with_bootstrap(&format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", other.peer_id()));
    assert_eq!(good.problems(), Vec::new());
}

#[test]
fn relay_autonat_and_dcutr_are_refused_without_a_server() {
    let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);
    let base = Libp2pConfig::new(
        &identity,
        Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid"),
    )
    .with_seed(CONFORMANCE_SEED)
    .expect("the seed is that identity's key");
    let server = format!(
        "/ip4/127.0.0.1/tcp/4001/p2p/{}",
        NauIdentity::from_seed(&[8u8; 32]).peer_id()
    );

    // DCUtR needs a third party to coordinate through.
    assert_eq!(
        base.clone().with_dcutr().problems(),
        vec![ConfigProblem::DcutrWithoutServer]
    );
    // With a server it is fine, and the predicate agrees with validation.
    let ok = base.clone().with_dcutr().with_autonat_server(&server);
    assert_eq!(ok.problems(), Vec::new());
    assert!(ok.dcutr_enabled());
    assert!(ok.autonat_enabled());

    // A relay reservation naming no peer has nothing to reserve on.
    let mut relay = base.clone();
    relay
        .relay_reservations
        .push(Multiaddr::parse("/ip4/127.0.0.1/tcp/4001").expect("valid address"));
    assert!(matches!(
        relay.problems()[0],
        ConfigProblem::RelayWithoutServer { .. }
    ));
    assert!(!relay.relay_enabled() || relay.validate().is_err());

    // A reservation naming a peer is accepted.
    let mut relay_ok = base;
    relay_ok
        .relay_reservations
        .push(Multiaddr::parse(&server).expect("valid"));
    assert_eq!(relay_ok.problems(), Vec::new());
    assert!(relay_ok.relay_enabled());
}

#[test]
fn the_configuration_type_never_prints_its_secret() {
    let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);
    let config = Libp2pConfig::new(
        &identity,
        Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid"),
    )
    .with_seed(CONFORMANCE_SEED)
    .expect("the seed is that identity's key");
    let rendered = format!("{config:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(!rendered.contains(&hex::encode(CONFORMANCE_SEED)));
    assert!(!rendered.contains("1, 1, 1"));
    // The summary is short and contains no addresses.
    let summary = config.describe();
    assert!(summary.contains("listen=1"));
    assert!(!summary.contains("127.0.0.1"));
}

#[test]
fn the_frame_cap_is_the_same_number_on_both_sides_of_the_boundary() {
    // If these ever diverge, a frame that `nau_net` accepts cannot be published,
    // or one that the codec accepts exceeds the transport's cap.
    assert_eq!(MAX_PAYLOAD_BYTES, MAX_FRAME_BYTES);
    assert_eq!(MAX_FRAME_BYTES, 8 * 1024 * 1024);
    // The port's own arithmetic still agrees after this crate's use of it.
    assert!(nau_net::check_frame_len(MAX_FRAME_BYTES).is_ok());
    assert!(nau_net::check_frame_len(MAX_FRAME_BYTES + 1).is_err());
    // And a recv timeout is expressible, which is what the adapter needs.
    let _ = Duration::from_millis(1);
}
