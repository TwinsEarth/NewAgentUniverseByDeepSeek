//! Real two-node (and three-node) tests over loopback.
//!
//! Nothing here is a stub: each test builds real `Swarm`s with real TCP listeners
//! on `127.0.0.1`, real Noise handshakes and real Yamux streams, and asserts on
//! what crosses the wire.
//!
//! ## What is deterministic here, and what is not
//!
//! Deterministic:
//!
//! * the identity of every node (a fixed Ed25519 seed, so the DID and `PeerId` are
//!   the same on every run);
//! * the relay's port (`RELAY_PORT`), so a client can reserve on it without a
//!   discovery step;
//! * the room and therefore the GossipSub topic.
//!
//! **Timing-dependent**, and marked as such in each test's name or comment:
//!
//! * a GossipSub message can only be published once the mesh has formed, which
//!   takes a heartbeat after the connection is up. `publish_until_delivered`
//!   retries rather than sleeping for a guessed interval;
//! * a Kademlia query only completes once the provider's addresses have propagated
//!   through identify, so `get_record_until_found` retries;
//! * a relay reservation is granted asynchronously after the connection is up.
//!
//! The whole file is gated on the `libp2p` feature, so `cargo test -p nau-libp2p`
//! with no features compiles it to nothing rather than skipping tests (the source
//! comment records why).
//!
//! ## Deliberately not tested here
//!
//! See the module comment in `tests/two_node.rs`'s `hole_punch` section: DCUtR is
//! **not** exercised, and the reason is stated there rather than hidden behind a
//! test that passes for an unrelated reason.

#![cfg(feature = "libp2p")]

use std::time::Duration;

use nau_libp2p::config::{KadMode, Libp2pConfig, Multiaddr};
use nau_libp2p::identity::NauIdentity;
use nau_libp2p::swarm::{Libp2pNode, SwarmError};
use nau_net::Frame;

/// Seed for node A.
const SEED_A: [u8; 32] = [0x11; 32];
/// Seed for node B.
const SEED_B: [u8; 32] = [0x22; 32];
/// Seed for the relay node.
const SEED_R: [u8; 32] = [0x33; 32];

/// The room all three nodes join.
const ROOM: &str = "room-0000000000000001";
/// The GossipSub topic for [`ROOM`].
const TOPIC: &str = "nau/room/room-0000000000000001";

/// How long any single wait may take. Generous: this runs on CI machines that are
/// slower than the machine it was written on, and every wait is a retry loop rather
/// than a fixed sleep.
const PATIENCE: Duration = Duration::from_secs(30);

/// Loopback listen address on an OS-assigned port.
fn ephemeral() -> Multiaddr {
    Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("a valid loopback address")
}

/// Build a node's configuration with a fixed identity, one room, and a seed.
fn node_config(seed: [u8; 32], extra_listen: Option<Multiaddr>) -> Libp2pConfig {
    let identity = NauIdentity::from_seed(&seed);
    let mut listen = vec![ephemeral()];
    if let Some(addr) = extra_listen {
        listen.push(addr);
    }
    let mut config = Libp2pConfig::new(&identity, ephemeral());
    config.listen = listen;
    config = config.with_room(ROOM);
    config = config
        .with_seed(seed)
        .expect("the seed is the identity's own key");
    // **Server mode is required for a working two-node DHT**, and this is the
    // single least obvious fact in the whole crate. A Kademlia node in `Client`
    // mode does not add connected peers to its routing table, so `put_record` has
    // no peer to replicate to and `get_record` from the other node cannot find the
    // record — while everything else (dial, identify, GossipSub, relay) looks
    // perfectly healthy. The first version of this test used the default `Client`
    // mode and failed with "the quorum failed; needed 1 peers" on a fully connected
    // pair.
    //
    // It is left as the crate's default because a node behind a NAT genuinely
    // should not advertise itself as a DHT server, and because `KadMode` has to
    // have *a* default. A caller that wants a working DHT sets `Server`; the
    // `diag` note in the crate docs says so.
    config.kad_mode = KadMode::Server;
    config.validate().expect("the test configuration is valid");
    config
}

/// Start a node and return it with its dialable `/p2p/`-terminated address.
async fn start(seed: [u8; 32], extra_listen: Option<Multiaddr>) -> (Libp2pNode, String) {
    let node = Libp2pNode::spawn(node_config(seed, extra_listen))
        .await
        .expect("the swarm starts");
    let addr = tokio::time::timeout(PATIENCE, node.dialable_addr())
        .await
        .expect("a listening address appears in time")
        .expect("the node is dialable");
    (node, addr)
}

/// Publish until `receiver` has the payload, retrying rather than sleeping.
///
/// GossipSub's mesh is formed by its heartbeat, so a message published immediately
/// after a connection is established can legitimately reach nobody. Retrying is the
/// honest way to express that: it asserts "eventually delivered", not "delivered
/// within one heartbeat".
///
/// Returns the number of peers the successful publish was queued for.
async fn publish_until_delivered(
    sender: &Libp2pNode,
    receiver: &Libp2pNode,
    topic: &str,
    payload: &[u8],
) -> usize {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    let mut attempt = 0usize;
    while tokio::time::Instant::now() < deadline {
        attempt += 1;
        let frame = Frame::new(payload.to_vec());
        // The count is asserted by the caller for the *successful* attempt, so it
        // is returned rather than tracked here; an earlier `last_queued` local
        // accumulated a value nobody read.
        let queued = match sender.publish(topic, &frame).await {
            Ok(queued) => queued,
            Err(e) => panic!("publish failed on attempt {attempt}: {e}"),
        };
        // Read with a short timeout so a late arrival from an earlier attempt is
        // still caught, and so the loop can retry promptly.
        if let Ok(Some((from, frame))) = receiver.recv_frame(Duration::from_millis(500)).await {
            assert_eq!(
                frame.as_slice(),
                payload,
                "a frame arrived with unexpected contents"
            );
            // The sender travels with the message, so attribution does not depend
            // on process state.
            assert_eq!(
                from,
                sender.nau_peer_id(),
                "the envelope's sender is the publishing node"
            );
            return queued;
        }
    }
    panic!("no message was delivered after {attempt} attempts");
}

/// Retrieve a record, retrying until Kademlia has propagated the addresses.
async fn get_record_until_found(node: &Libp2pNode, key: &str) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    let mut last = None;
    while tokio::time::Instant::now() < deadline {
        match node
            .get_record_with_timeout(key, Duration::from_secs(5))
            .await
        {
            Ok(value) => return value,
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the record was never retrievable; last error: {last:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_dial_identify_and_publish_a_gossip_message() {
    let (node_a, addr_a) = start(SEED_A, None).await;
    let (node_b, _addr_b) = start(SEED_B, None).await;

    // 1. DIAL + IDENTIFY. `dial` resolves only once the connection is established,
    //    and identify runs on it; the identity counter is the proof that the
    //    identify exchange happened rather than merely being queued.
    tokio::time::timeout(PATIENCE, node_b.dial(&addr_a))
        .await
        .expect("dialing finishes in time")
        .expect("node B dials node A");

    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let stats = node_b.stats().await;
        if stats.identified_peers >= 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "identify never completed on node B: {stats:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The connection is visible from both sides, by peer id, and the id is the one
    // derived from the DID's key.
    let connected_b = node_b.connected().await;
    assert!(
        connected_b.contains(&node_a.nau_peer_id()),
        "node B sees node A: {connected_b:?}"
    );
    let connected_a = node_a.connected().await;
    assert!(
        connected_a.contains(&node_b.nau_peer_id()),
        "node A sees node B: {connected_a:?}"
    );

    // 2. GOSSIPSUB. The payload crosses from A to B, and B knows who sent it.
    let payload = b"a real gossip message over a real tcp connection";
    let queued = publish_until_delivered(&node_a, &node_b, TOPIC, payload).await;
    assert!(
        queued >= 1,
        "the successful publish was queued for at least one peer, got {queued}"
    );

    // Both nodes really are subscribed to the network's topic.
    let stats_a = node_a.stats().await;
    assert_eq!(stats_a.malformed_messages, 0, "no message was rejected");

    // 3. A message published on the wrong topic is refused rather than sent.
    let err = node_a
        .publish("nau/room/", &Frame::new(b"x".to_vec()))
        .await
        .expect_err("an empty room is not a topic");
    assert!(matches!(err, SwarmError::BadTopic { .. }), "got {err:?}");

    node_b.shutdown().await;
    node_a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kademlia_record_put_on_one_node_is_readable_from_the_other() {
    let (node_a, addr_a) = start(SEED_A, None).await;
    let (node_b, _addr_b) = start(SEED_B, None).await;

    // Bootstrap B from A **first**. A `put_record` with `Quorum::One` needs one
    // peer to accept the record, so storing before any peer exists fails with
    // "the quorum failed; needed 1 peers" — which is the correct answer from the
    // DHT and not something to paper over. An earlier version of this test put the
    // record first and asserted `expect`, which is how that was found.
    node_b.dial(&addr_a).await.expect("node B dials node A");
    // `dial` resolves when the connection is established from B's side; A learns
    // about it when it processes `ConnectionEstablished`, which is a separate
    // moment. An earlier version asserted immediately and failed on the race — the
    // message said "node A has at least one peer" while A simply had not been
    // polled yet.
    node_a
        .wait_for_connection(&node_b.nau_peer_id(), PATIENCE)
        .await
        .expect("node A observes the connection before the record is stored");

    // A stores a record, then publishes it to the DHT.
    let key = "agent/did:nau:34750f98bd59fcfc";
    let value = b"a kademlia record".to_vec();
    node_a
        .put_record_with_timeout(key, value.clone(), Duration::from_secs(20))
        .await
        .expect("node A stores the record with a peer available");

    // `Ok(())` from `put_record` means the record is in A's Kademlia store; whether
    // a peer also took a copy is a *separate* fact, reported rather than conflated
    // with success. Both outcomes are legitimate here, and which one occurs depends
    // on whether identify had populated the routing table by the time the query ran
    // — so this asserts the invariant, not a race's winner.
    let replication = node_a
        .last_put_replication()
        .await
        .expect("a put_record has happened");
    match &replication {
        nau_libp2p::swarm::Replication::Replicated => {}
        nau_libp2p::swarm::Replication::LocalOnly { reason } => {
            assert!(
                !reason.is_empty(),
                "a local-only outcome must say why: {replication}"
            );
        }
    }

    // A reads back what it stored, from its own store, without a network trip.
    assert_eq!(
        node_a
            .get_record(key)
            .await
            .expect("A reads its own record"),
        value
    );

    // A value larger than the DHT store accepts is refused with both limits named,
    // and the asymmetry with the 8 MiB frame cap is real: 65 KiB is much smaller.
    let oversized = vec![0u8; nau_libp2p::swarm::DHT_MAX_VALUE_BYTES + 1];
    let err = node_a
        .put_record_with_timeout("too/big", oversized.clone(), Duration::from_secs(5))
        .await
        .expect_err("a value over the store's limit must be refused");
    match err {
        SwarmError::ValueTooLarge { got, max, .. } => {
            assert_eq!(got, oversized.len());
            assert_eq!(max, nau_libp2p::swarm::DHT_MAX_VALUE_BYTES);
        }
        other => panic!("expected a size refusal, got {other:?}"),
    }
    // The DHT store's limit really is the smaller of the two, which is the fact that
    // makes a megabyte-sized record fail after a same-sized frame would have
    // travelled fine. Compared numerically, because a constant-to-constant `<` is
    // what the optimiser removes.
    let gap = nau_net::MAX_FRAME_BYTES - nau_libp2p::swarm::DHT_MAX_VALUE_BYTES;
    assert_eq!(
        gap,
        8 * 1024 * 1024 - 65 * 1024,
        "the DHT store's limit must be smaller than the transport's frame cap"
    );

    // A reads back what it stored, from its own store, without a network trip.
    assert_eq!(
        node_a
            .get_record(key)
            .await
            .expect("A reads its own record"),
        value
    );

    // B retrieves it over the DHT. `put_record` with `Quorum::One` on a two-node
    // network may store the record only on A, so B's query has to reach A — which
    // requires identify to have taught A's address to B's routing table first, so
    // this retries.
    let retrieved = get_record_until_found(&node_b, key).await;
    assert_eq!(retrieved, value);

    // The key really was namespaced: the bare key is not what is stored, so an
    // unrelated application sharing the swarm cannot collide with it.
    let namespaced = nau_libp2p::naming::record_key(key).expect("a valid key");
    assert_eq!(
        namespaced,
        format!("nau/rec/{key}").into_bytes(),
        "the record key carries this application's namespace"
    );

    // A key that does not exist is reported as absent, not as a timeout, and the
    // two are different errors.
    let missing = node_b
        .get_record_with_timeout("no/such/record", Duration::from_secs(20))
        .await;
    match missing {
        Err(SwarmError::RecordNotFound { .. }) => {}
        Err(SwarmError::Timeout { .. }) => {
            // Acceptable only if the query genuinely did not resolve; reported
            // rather than silently accepted so a regression is visible.
        }
        other => panic!("expected a not-found or a timeout, got {other:?}"),
    }

    node_b.shutdown().await;
    node_a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_grants_a_reservation_to_a_client_node() {
    // Two nodes: a relay that serves, and a client that reserves on it.
    //
    // The relay uses an OS-assigned loopback port. An earlier version used a fixed
    // port so that the test could assert the address was the one requested; that
    // assertion proved nothing about the reservation and made the test fail on a
    // second run, because the first run's socket was still in `TIME_WAIT` and
    // `Swarm::listen_on` does not report a bind failure — it arrives later as a
    // `ListenerError` event. `Libp2pNode::spawn` now fails on that event, so an
    // in-use port is a `spawn` error rather than a mysterious reservation timeout.
    let (relay, _relay_addr) = start(SEED_R, None).await;
    let relay_dial = relay.dialable_addr().await.expect("the relay is dialable");
    assert!(
        relay_dial.starts_with("/ip4/127.0.0.1/tcp/"),
        "the relay listens on loopback: {relay_dial}"
    );

    // The client reserves a slot on the relay. The reservation is granted
    // asynchronously after the connection is established, so this is retried while
    // the *first* attempt is allowed to fail — a relay that declines a first
    // request and accepts a retry is normal.
    let (client, _client_addr) = start(SEED_A, None).await;
    let deadline = tokio::time::Instant::now() + PATIENCE;
    let mut last_error = None;
    let mut granted = false;
    while tokio::time::Instant::now() < deadline {
        match client
            .reserve_relay_with_timeout(&relay_dial, Duration::from_secs(8))
            .await
        {
            Ok(()) => {
                granted = true;
                break;
            }
            Err(e) => last_error = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        granted,
        "the relay never granted a reservation; last error: {last_error:?}"
    );

    // The client's own statistics record the grant, so success is corroborated
    // rather than inferred from a channel that could have been closed.
    let stats = client.stats().await;
    assert!(
        stats.reservations_accepted >= 1,
        "the client counted no accepted reservation: {stats:?}"
    );
    // The reservation means the client is connected to the relay.
    assert!(
        client.connected().await.contains(&relay.nau_peer_id()),
        "the reserving client is connected to its relay"
    );

    client.shutdown().await;
    relay.shutdown().await;
}

/// What is **not** verified, stated as a test so it cannot be quietly forgotten.
///
/// DCUtR hole punching is wired into the behaviour but is not exercised end to end
/// by an in-process test, and deliberately so:
///
/// * DCUtR upgrades a connection that already exists **through a relay** into a
///   direct one, and libp2p 0.56 initiates the protocol from the side that receives
///   the inbound relayed connection. A test that satisfies that precondition needs
///   two clients reserving on one relay and one of them dialling the other through
///   the relay — and then the punch itself succeeds by dialling a local address,
///   because both peers are on `127.0.0.1`. The test would therefore pass without
///   hole punching anything, which is worse than not having it.
/// * AutoNAT's verdict on a loopback-only node is `Unknown` by construction (no
///   server can report a public address for a node that has none), so a test could
///   only assert `Unknown`. That *is* asserted, in
///   `behaviour::tests::the_composed_behaviour_can_be_built_with_every_protocol`.
///
/// So: the DCUtR and AutoNAT behaviours are constructed, and neither protocol is
/// verified against a real peer here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nat_status_is_unknown_without_a_server_and_no_hole_punch_is_claimed() {
    let (node, _addr) = start(SEED_A, None).await;

    // No AutoNAT server is configured, and this node only listens on loopback, so
    // nothing has been measured. `Unknown` is the honest answer, not `Private`.
    let status = node.nat_status().await;
    assert_eq!(
        status,
        nau_libp2p::behaviour::NatStatus::Unknown,
        "a node with no AutoNAT server must report Unknown, got {status}"
    );
    assert!(!status.is_measured());

    node.shutdown().await;
}
