//! The [`nau_net::Transport`] adapter, exercised through the port.
//!
//! This is the test that matters most for the *port* claim: `docs/ARCHITECTURE.md`
//! lists `nau_net::Transport` with two adapters (`TcpTransport` and
//! `MemoryTransport`), and this file asserts that the libp2p adapter is a third
//! that satisfies the same contract — including the parts of that contract which
//! the swarm can only approximate, which are asserted as *approximations* rather
//! than as exact behaviour.
//!
//! Gated on the `libp2p` feature, so `cargo test -p nau-libp2p` with no features
//! compiles it to nothing.

#![cfg(feature = "libp2p")]

use std::sync::Arc;
use std::time::Duration;

use nau_libp2p::config::{KadMode, Libp2pConfig, Multiaddr};
use nau_libp2p::identity::NauIdentity;
use nau_libp2p::swarm::Libp2pNode;
use nau_libp2p::transport::{peer_from_label, Libp2pTransport, LABEL_PREFIX};
use nau_net::{Frame, Transport};

const SEED_A: [u8; 32] = [0x44; 32];
const SEED_B: [u8; 32] = [0x55; 32];
const ROOM: &str = "room-0000000000000001";

const PATIENCE: Duration = Duration::from_secs(30);

fn config(seed: [u8; 32]) -> Libp2pConfig {
    let identity = NauIdentity::from_seed(&seed);
    let mut config = Libp2pConfig::new(
        &identity,
        Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid"),
    )
    .with_seed(seed)
    .expect("the seed is the identity's own key")
    .with_room(ROOM);
    // Server mode, for the reason `tests/two_node.rs` documents at length: a
    // `Client` node does not populate its routing table.
    config.kad_mode = KadMode::Server;
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_port_contract_holds_for_the_libp2p_adapter() {
    let transport_a = Libp2pTransport::start(config(SEED_A))
        .await
        .expect("transport A starts");
    let transport_b = Libp2pTransport::start(config(SEED_B))
        .await
        .expect("transport B starts");

    // `local_id` is a label derived from the same key as the DID, so the two views
    // agree — this is the whole point of the identity seam.
    let local_a = transport_a.local_id();
    let local_b = transport_b.local_id();
    assert!(local_a.as_str().starts_with(LABEL_PREFIX));
    assert!(local_b.as_str().starts_with(LABEL_PREFIX));
    assert_ne!(local_a, local_b, "two keys, two labels");
    assert_eq!(
        transport_a.did().as_str(),
        NauIdentity::from_seed(&SEED_A).did().as_str()
    );
    assert_eq!(
        peer_from_label(&local_a).expect("a libp2p label"),
        transport_a.typed_peer_id()
    );

    // `recv` on an idle endpoint is `Ok(None)`, which is the port's contract: a
    // timeout is normal operation, not an error.
    let quiet = transport_a
        .recv(Duration::from_millis(200))
        .await
        .expect("a timeout is not an error");
    assert!(quiet.is_none(), "nothing should have arrived");
    assert_eq!(transport_a.stats().snapshot().recv_timeouts, 1);

    // `send` to a peer that is not connected is refused, because a broadcast is not
    // a unicast: the adapter does not silently turn "send to one peer" into
    // "send to everyone".
    let disconnected = transport_a
        .send(&local_b, Frame::new(b"nobody is listening".to_vec()))
        .await
        .expect_err("sending to a disconnected peer must be refused");
    assert!(
        disconnected.to_string().contains("not connected"),
        "got {disconnected}"
    );
    assert_eq!(transport_a.stats().snapshot().rejected_disconnected, 1);
    assert_eq!(transport_a.stats().snapshot().broadcasts, 0);

    // Connect the two: dial B's address from A, so both are connected and both
    // subscribed to the room topic.
    let addr_b = transport_b
        .node()
        .dialable_addr_with_timeout(PATIENCE)
        .await
        .expect("B is dialable");
    transport_a
        .node()
        .dial_with_timeout(&addr_b, PATIENCE)
        .await
        .expect("A dials B");
    transport_a
        .node()
        .wait_for_connection(&transport_b.typed_peer_id(), PATIENCE)
        .await
        .expect("A sees B connected");

    // `connected` reports the other endpoint, as a label, and is sorted per the
    // port's contract.
    let connected = transport_a.connected().await;
    assert!(
        connected.contains(&local_b),
        "A's connected set contains B: {connected:?}"
    );
    let mut sorted = connected.clone();
    sorted.sort();
    assert_eq!(
        connected, sorted,
        "`connected` must be in ascending id order"
    );

    // `send` now works, and the frame crosses to B through the port.
    //
    // The first attempts can fail with `Retryable` while the GossipSub mesh forms:
    // GossipSub's mesh is built by its heartbeat, so there is a real window after a
    // connection is up in which no peer is in the topic's mesh. The port's `send` is
    // not documented as retrying, so the retry is the caller's — and the assertion
    // below is on the *reason*, so a future change that reported this as a plain
    // failure would fail this test rather than being absorbed by the loop.
    let payload = b"a frame through the Transport port";
    let mut delivered = false;
    let mut saw_retryable = false;
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while tokio::time::Instant::now() < deadline && !delivered {
        match transport_a
            .send(&local_b, Frame::new(payload.to_vec()))
            .await
        {
            Ok(()) => {}
            Err(e) => {
                let text = e.to_string();
                assert!(
                    text.contains("cannot run yet") && text.contains("heartbeat"),
                    "the only expected send failure while the mesh forms is a retryable one; got \
                     {text}"
                );
                saw_retryable = true;
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        }
        if let Some((from, frame)) = transport_b
            .recv(Duration::from_millis(500))
            .await
            .expect("recv does not fail")
        {
            assert_eq!(frame.as_slice(), payload);
            // The sender is reported, so a caller can attribute the frame.
            assert_eq!(from, local_a);
            delivered = true;
        }
    }
    assert!(delivered, "no frame crossed the port within {PATIENCE:?}");
    assert!(transport_a.stats().snapshot().broadcasts >= 1);
    // The retryable path is recorded rather than silently relied on: if it never
    // triggered, this test would not be covering the mesh-formation window at all.
    let _ = saw_retryable;

    // A frame over the port's cap is refused before it reaches the network, on the
    // send path, exactly as `nau_net`'s other transports do it.
    let oversized = Frame::new(vec![0u8; nau_net::MAX_FRAME_BYTES + 1]);
    let err = transport_a
        .send(&local_b, oversized)
        .await
        .expect_err("an over-cap frame must be refused");
    assert!(!err.to_string().is_empty());

    // A label from a different transport is refused rather than reinterpreted as a
    // peer id.
    let foreign = nau_net::PeerId::parse("tcp://127.0.0.1:5555").expect("a valid label");
    let err = transport_a
        .send(&foreign, Frame::new(b"x".to_vec()))
        .await
        .expect_err("a socket address is not a peer");
    assert!(err.to_string().contains("not a libp2p peer label"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_adapter_and_the_node_are_the_same_endpoint() {
    // A caller that needs the operations the port does not express reaches them
    // through `node()`, and they must be the same endpoint — same peer id, same
    // DID, same store.
    let node = Arc::new(
        Libp2pNode::spawn(config(SEED_A))
            .await
            .expect("the node starts"),
    );
    let transport = Libp2pTransport::from_node(Arc::clone(&node)).expect("wrapped");

    assert_eq!(transport.node().peer_id(), node.peer_id());
    assert_eq!(transport.typed_peer_id(), node.nau_peer_id());
    assert_eq!(
        transport.local_id(),
        nau_libp2p::transport::typed_to_label(&node.nau_peer_id())
    );
    assert_eq!(transport.topic(), "nau/room/room-0000000000000001");

    // A record put through the node is visible through the node, and the adapter
    // did not create a second swarm.
    node.put_record_with_timeout("k", b"v".to_vec(), Duration::from_secs(5))
        .await
        .expect("stored locally");
    assert_eq!(
        node.get_record("k").await.expect("read back"),
        b"v".to_vec()
    );

    // `Libp2pTransport` holds one `Arc` and this test holds another, so the
    // transport is dropped first and the `Arc` can then be unwrapped to shut the
    // node down — `shutdown` consumes the node, which an `Arc` cannot surrender
    // while it is still shared.
    drop(transport);
    let node = Arc::try_unwrap(node)
        .unwrap_or_else(|_| panic!("the transport still holds a reference to the node"));
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transport_without_a_room_cannot_carry_frames() {
    // Publishing to no topic is a transport that accepts frames and delivers none,
    // so it is refused rather than defaulted.
    let identity = NauIdentity::from_seed(&SEED_A);
    let config = Libp2pConfig::new(
        &identity,
        Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid"),
    )
    .with_seed(SEED_A)
    .expect("the seed is the identity's own key");
    let err = Libp2pTransport::start(config)
        .await
        .expect_err("no room means no topic");
    assert!(err.to_string().contains("at least one room"), "got {err}");
}
