//! Cross-check: this crate's `PeerId` derivation against libp2p's own.
//!
//! `src/identity.rs` implements base58btc, the multihash prefix and the protobuf
//! wrapper itself, so that `cargo test -p nau-libp2p` with no features still
//! exercises the real DID ↔ `PeerId` mapping instead of a stub. The cost of that
//! choice is that a mistake in the local encoding is invisible without libp2p.
//!
//! This file is that missing check, and it is the *only* reason it needs the
//! `libp2p` feature: every claim `src/identity.rs` makes about the wire format is
//! compared here against `libp2p::identity::PeerId::from_public_key`, which is the
//! implementation every real libp2p node uses.
//!
//! Without this file the tests passed while the derivation was wrong: an earlier
//! version hashed the protobuf encoding with SHA-256, which produces a valid
//! multihash and a plausible-looking `Qm…` peer id that no libp2p node would accept.
//! The tests in `src/identity.rs` could not see the difference; the first line of
//! [`every_seed_derives_the_peer_id_libp2p_derives`] can.

#![cfg(feature = "libp2p")]

use nau_libp2p::identity::{NauIdentity, PeerId, ED25519_PEER_ID_BYTES};

/// Seeds chosen to cover the byte values that tend to expose encoding bugs: all
/// zeroes (the base58 leading-`1` case), all ones, an extreme, and values that
/// produce a high and a low first digit.
const SEEDS: &[[u8; 32]] = &[
    [0x00; 32], [0x01; 32], [0x7f; 32], [0x80; 32], [0xfe; 32], [0xff; 32],
];

/// The libp2p keypair for a seed, which is the same Ed25519 key.
fn libp2p_keypair(seed: &[u8; 32]) -> libp2p::identity::Keypair {
    libp2p::identity::Keypair::ed25519_from_bytes(*seed).expect("a 32-byte seed is a valid key")
}

#[test]
fn every_seed_derives_the_peer_id_libp2p_derives() {
    for seed in SEEDS {
        let identity = NauIdentity::from_seed(seed);
        let theirs = libp2p_keypair(seed).public().to_peer_id();
        let ours = identity.peer_id();

        assert_eq!(
            ours.to_string(),
            theirs.to_string(),
            "the local derivation must match libp2p's for seed {:02x?}",
            seed
        );
        // Byte-for-byte, not merely as strings: two spellings that compare equal as
        // text could still be different multihashes if either renderer were wrong.
        assert_eq!(
            ours.as_bytes().as_slice(),
            theirs.to_bytes().as_slice(),
            "the raw multihash must match for seed {seed:02x?}"
        );
        assert_eq!(ours.as_bytes().len(), ED25519_PEER_ID_BYTES);

        // And the reverse direction: libp2p's textual form parses here.
        let parsed = PeerId::parse(&theirs.to_string()).expect("libp2p's own id parses");
        assert_eq!(parsed, ours);
    }
}

#[test]
fn the_did_and_the_libp2p_peer_id_are_two_views_of_one_key() {
    // This is the seam the whole crate rests on. If these ever disagree, a node
    // signs with one identity and is dialled as another.
    for seed in SEEDS {
        let identity = NauIdentity::from_seed(seed);
        let keypair = libp2p_keypair(seed);

        // The key bytes are the same.
        assert_eq!(
            identity.public_key().as_slice(),
            keypair
                .public()
                .try_into_ed25519()
                .expect("an ed25519 key")
                .to_bytes()
                .as_slice()
        );

        // The DID fingerprints that key, and the PeerId is that key's id.
        let from_did =
            NauIdentity::from_did_and_public_key(identity.did().as_str(), *identity.public_key())
                .expect("the DID and the key agree");
        assert_eq!(
            from_did.peer_id().to_string(),
            keypair.public().to_peer_id().to_string(),
            "the DID-derived identity must produce libp2p's peer id"
        );

        // The legacy prefix maps onto the same id, so a migrated upstream identity
        // keeps its place on the wire.
        let legacy = format!("did:aip:{}", identity.did().fingerprint());
        let migrated = NauIdentity::from_did_and_public_key(&legacy, *identity.public_key())
            .expect("the legacy prefix binds to the same fingerprint");
        assert_eq!(migrated.peer_id(), identity.peer_id());
    }
}

#[test]
fn a_libp2p_peer_id_for_a_different_key_is_refused() {
    // The pairing check is what stops a peer claiming someone else's id.
    let mine = NauIdentity::from_seed(&[0x11; 32]);
    let theirs = libp2p_keypair(&[0x22; 32]).public().to_peer_id();
    let their_typed = PeerId::parse(&theirs.to_string()).expect("parses");
    assert_ne!(their_typed, mine.peer_id());
    assert!(mine.verify_peer_id(&their_typed).is_err());
    assert!(mine.verify_peer_id(&mine.peer_id()).is_ok());
}

#[test]
fn the_multiaddr_parser_agrees_with_libp2p() {
    // `config::Multiaddr` is this crate's own parser, so validation works with the
    // `libp2p` feature off. This asserts the two accept the same strings: a
    // disagreement in either direction is a bug in the local parser (a valid
    // bootstrap address refused at startup, or an unusable one accepted and then
    // failing at dial time).
    let valid = [
        "/ip4/127.0.0.1/tcp/9000",
        "/ip4/0.0.0.0/tcp/0",
        "/ip6/::1/tcp/9000",
        "/ip4/127.0.0.1/udp/9000/quic-v1",
        "/ip4/127.0.0.1/tcp/9000/ws",
        "/p2p-circuit",
        "/ip4/127.0.0.1/tcp/9000/p2p-circuit",
        "/memory/1234",
    ];
    for addr in valid {
        assert!(
            addr.parse::<libp2p::Multiaddr>().is_ok(),
            "{addr} should be valid for libp2p"
        );
        let ours = nau_libp2p::config::Multiaddr::parse(addr)
            .unwrap_or_else(|e| panic!("{addr} should be valid locally: {e}"));
        assert!(
            ours.accepted_by_libp2p(),
            "{addr} should be accepted by libp2p"
        );
    }

    let invalid = [
        "127.0.0.1:9000",
        "/ip4",
        "/tpc/9000",
        "/ip4/127.0.0.1/tpc/9000",
        "/ip4//tcp/9000",
        "/ip4/127.0.0.1/tcp/",
        "/",
        "/ip4/127.0.0.1/tcp/9000\n",
        "/ip4/ 127.0.0.1/tcp/9000",
    ];
    for addr in invalid {
        assert!(
            addr.parse::<libp2p::Multiaddr>().is_err(),
            "{addr:?} should be invalid for libp2p"
        );
        assert!(
            nau_libp2p::config::Multiaddr::parse(addr).is_err(),
            "{addr:?} should be invalid locally"
        );
    }

    // The one deliberate disagreement, asserted so it stays deliberate.
    //
    // `""` parses for libp2p as the empty multiaddr — a zero-component address,
    // which is representable and is what `/p2p-circuit` degrades to. It is refused
    // here, because a configuration entry that is the empty string is a missing
    // value (an unset environment variable, a blank line in a config file), and
    // accepting it would turn "no bootstrap peers" into "one empty address" and
    // then fail at dial time with nothing to point at.
    assert!("".parse::<libp2p::Multiaddr>().is_ok());
    assert!(nau_libp2p::config::Multiaddr::parse("").is_err());
}

#[test]
fn a_peer_id_extracted_from_a_multiaddr_is_a_libp2p_peer_id() {
    // The `/p2p/` component is how a bootstrap address names a peer; the local
    // extraction must produce something libp2p can dial.
    for seed in SEEDS {
        let identity = NauIdentity::from_seed(seed);
        let addr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", identity.peer_id());
        let parsed = nau_libp2p::config::Multiaddr::parse(&addr).expect("a valid address");
        let extracted = parsed.peer_id().expect("a valid peer id").expect("present");
        assert_eq!(extracted, identity.peer_id());
        assert_eq!(
            extracted.to_string(),
            libp2p_keypair(seed).public().to_peer_id().to_string()
        );
        // libp2p parses the same text, which is what makes the address dialable.
        assert!(addr.parse::<libp2p::Multiaddr>().is_ok());
    }
}
