//! Transport behaviour tests.
//!
//! The TCP half of this file is the point: upstream v2.5.6's "network" was three
//! `HashMap` mocks that shared the names of the services they replaced
//! (`KademliaClient`, `GossipSub`, `GsnNode`), so no test ever opened a socket.
//! Here two real endpoints on `127.0.0.1:0` exchange frames in both directions,
//! and the size cap, the read timeout and the "unknown peer" path are each
//! exercised against a live socket.

use std::time::Duration;

use nau_core::NauError;
use nau_net::{
    check_frame_len, Frame, MemoryTransport, PeerId, TcpTransport, Transport, MAX_FRAME_BYTES,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SHORT: Duration = Duration::from_millis(150);
const PATIENCE: Duration = Duration::from_secs(5);

/// Wait (bounded) until `transport` reports at least `want` connected peers.
///
/// Accepting a connection happens on a background task, so "the peer is visible"
/// is eventual, never instantaneous.
async fn wait_for_peers(transport: &TcpTransport, want: usize) -> Vec<PeerId> {
    let mut observed = transport.connected().await;
    for _ in 0..80 {
        if observed.len() >= want {
            return observed;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        observed = transport.connected().await;
    }
    observed
}

#[tokio::test]
async fn memory_transport_delivers_in_both_directions() {
    let a_id = PeerId::parse("node-a").expect("id");
    let b_id = PeerId::parse("node-b").expect("id");
    let (a, b) = MemoryTransport::pair(&a_id, &b_id);

    assert_eq!(a.local_id(), a_id);
    assert_eq!(a.connected().await, vec![b_id.clone()]);
    assert_eq!(b.connected().await, vec![a_id.clone()]);

    a.send(&b_id, Frame::new(b"ping".to_vec()))
        .await
        .expect("send a->b");
    b.send(&a_id, Frame::new(b"pong".to_vec()))
        .await
        .expect("send b->a");

    let (from, frame) = b.recv(SHORT).await.expect("recv").expect("a frame");
    assert_eq!(from, a_id, "the sender is reported with the frame");
    assert_eq!(frame.as_slice(), b"ping");

    let (from, frame) = a.recv(SHORT).await.expect("recv").expect("a frame");
    assert_eq!(from, b_id);
    assert_eq!(frame.as_slice(), b"pong");

    // An empty queue is not an error.
    assert_eq!(a.recv(SHORT).await.expect("recv"), None);
}

#[tokio::test]
async fn memory_transport_rejects_unknown_peers_and_oversized_frames() {
    let a_id = PeerId::parse("node-a").expect("id");
    let b_id = PeerId::parse("node-b").expect("id");
    let (a, _b) = MemoryTransport::pair(&a_id, &b_id);

    let stranger = PeerId::parse("node-c").expect("id");
    let err = a
        .send(&stranger, Frame::new(b"x".to_vec()))
        .await
        .expect_err("unknown peer");
    assert!(matches!(err, NauError::NotFound(_)), "got {err:?}");

    let err = a
        .send(&b_id, Frame(vec![0u8; MAX_FRAME_BYTES + 1]))
        .await
        .expect_err("over the cap");
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
}

#[tokio::test]
async fn tcp_transport_exchanges_frames_between_two_live_endpoints() {
    let server = TcpTransport::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let client = TcpTransport::bind("127.0.0.1:0")
        .await
        .expect("bind client");

    let server_addr = server.local_addr().expect("addr");
    assert!(
        server_addr.parse::<std::net::SocketAddr>().is_ok(),
        "local_addr must be a real socket address, got {server_addr}"
    );
    assert_ne!(server.local_id(), client.local_id());

    let peer = client.connect(&server_addr).await.expect("connect");
    assert_eq!(client.connected().await, vec![peer.clone()]);

    // client -> server
    client
        .send(&peer, Frame::new(b"hello server".to_vec()))
        .await
        .expect("send");
    let (server_side_peer, frame) = server
        .recv(PATIENCE)
        .await
        .expect("recv")
        .expect("a frame must arrive");
    assert_eq!(frame.as_slice(), b"hello server");
    assert_ne!(
        server_side_peer,
        client.local_id(),
        "the server sees the ephemeral source port, not the client's listen address"
    );
    assert_eq!(
        wait_for_peers(&server, 1).await,
        vec![server_side_peer.clone()],
        "the accepted connection must be registered under the observed address"
    );

    // server -> client, replying to the observed peer id
    server
        .send(&server_side_peer, Frame::new(b"hello client".to_vec()))
        .await
        .expect("reply");
    let (from_client_side, reply) = client
        .recv(PATIENCE)
        .await
        .expect("recv")
        .expect("a reply must arrive");
    assert_eq!(reply.as_slice(), b"hello client");
    assert_eq!(from_client_side, peer);

    // A large-but-legal frame survives the round trip byte for byte.
    let big = Frame(vec![0x5a; 512 * 1024]);
    let expected_len = big.len();
    client.send(&peer, big.clone()).await.expect("send big");
    let mut received = None;
    for _ in 0..8 {
        match server.recv(PATIENCE).await.expect("recv") {
            Some((_, frame)) if frame.len() == expected_len => {
                received = Some(frame);
                break;
            }
            Some(_) => continue,
            None => break,
        }
    }
    assert_eq!(
        received.expect("the large frame must arrive"),
        big,
        "the body must be byte-identical"
    );

    // Sending to a peer that was never connected is a NotFound, not a panic.
    let ghost = PeerId::parse("tcp://127.0.0.1:1").expect("id");
    let err = client
        .send(&ghost, Frame::new(b"x".to_vec()))
        .await
        .expect_err("unknown peer");
    assert!(matches!(err, NauError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn tcp_transport_refuses_an_oversized_frame_before_sending_it() {
    let transport = TcpTransport::bind("127.0.0.1:0").await.expect("bind");
    let own =
        PeerId::parse(&format!("tcp://{}", transport.local_addr().expect("addr"))).expect("id");
    let err = transport
        .send(&own, Frame(vec![0u8; MAX_FRAME_BYTES + 1]))
        .await
        .expect_err("over the cap");
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    assert!(check_frame_len(MAX_FRAME_BYTES + 1).is_err());
    assert!(check_frame_len(MAX_FRAME_BYTES).is_ok());
}

/// A peer that announces 4 GiB in its header must be closed, not allocated for.
#[tokio::test]
async fn tcp_transport_drops_a_peer_that_announces_an_impossible_frame() {
    let server = TcpTransport::bind("127.0.0.1:0").await.expect("bind");
    let addr = server.local_addr().expect("addr");

    let mut hostile = TcpStream::connect(&addr).await.expect("connect");
    let hostile_addr = hostile.local_addr().expect("the client's own address");
    let hostile_peer = PeerId::parse(&format!("tcp://{hostile_addr}")).expect("id");
    hostile
        .write_all(&[0xff, 0xff, 0xff, 0xff])
        .await
        .expect("write the hostile header");
    hostile.flush().await.expect("flush");

    // The server must close the connection: reading it back yields EOF. That is
    // only possible if the header was inspected and refused.
    let mut probe = [0u8; 1];
    let read = tokio::time::timeout(PATIENCE, hostile.read(&mut probe))
        .await
        .expect("the server must close an over-cap connection")
        .expect("read");
    assert_eq!(read, 0, "expected an orderly close after the bad header");

    // Unregistering happens before the socket is closed, so the peer is gone by
    // now, and no frame was ever produced from the hostile header.
    assert!(!server.connected().await.contains(&hostile_peer));
    assert_eq!(
        server.recv(Duration::from_millis(200)).await.expect("recv"),
        None,
        "an over-cap header must never become a frame"
    );

    // The listener survives: a well-behaved peer is still served afterwards.
    let good = TcpTransport::bind("127.0.0.1:0").await.expect("bind");
    let good_peer = good.connect(&addr).await.expect("connect");
    good.send(&good_peer, Frame::new(b"still alive".to_vec()))
        .await
        .expect("send");
    let (_, frame) = server
        .recv(PATIENCE)
        .await
        .expect("recv")
        .expect("the listener must still serve peers");
    assert_eq!(frame.as_slice(), b"still alive");
    assert_eq!(wait_for_peers(&server, 1).await.len(), 1);
}

/// A connection that produces nothing is closed after the read timeout, so a
/// silent peer cannot pin a task forever.
#[tokio::test]
async fn tcp_transport_applies_a_read_timeout() {
    let timeout_ms = Duration::from_millis(120);
    let server = TcpTransport::bind_with_read_timeout("127.0.0.1:0", timeout_ms)
        .await
        .expect("bind");
    assert_eq!(server.read_timeout(), timeout_ms);
    let addr = server.local_addr().expect("addr");

    let silent = TcpStream::connect(&addr).await.expect("connect");
    let accepted = wait_for_peers(&server, 1).await;
    assert_eq!(accepted.len(), 1, "the silent peer must first be accepted");

    tokio::time::sleep(timeout_ms * 4).await;
    assert!(
        server.connected().await.is_empty(),
        "a silent peer must be dropped once the read timeout elapses"
    );
    drop(silent);

    assert!(
        TcpTransport::bind_with_read_timeout("127.0.0.1:0", Duration::ZERO)
            .await
            .is_err(),
        "a zero read timeout is refused rather than busy-looping"
    );
}
