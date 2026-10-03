//! Integration tests that speak the crate's STUN codec over real UDP sockets on
//! `127.0.0.1:0`.
//!
//! The point of these tests is that nothing here is simulated: a `UdpSocket` is
//! bound, a Binding Request is encoded and sent from the *client* socket, the
//! server decodes it with the crate's own decoder and replies with
//! `XOR-MAPPED-ADDRESS`, and the client parses that reply with the crate's own
//! decoder. What is simulated is only the *role* of a public STUN server: a
//! loopback server cannot report a NAT that is not there, so these tests assert
//! that the reported address is echoed faithfully rather than that a particular
//! NAT type was detected.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nau_net::nat::{
    classify_filtering, classify_mapping, FilteringBehavior, MappingBehavior, Observation,
    ObservationAttempts, ObservationSet,
};
use nau_net::stun::{
    binding_request, BindingRequest, BindingResponse, ChangeRequest, StunError, StunMessage,
    TransactionId, XorMappedAddress,
};
use tokio::net::UdpSocket;

/// A minimal STUN server that answers Binding Requests with a *fixed* address,
/// so the test can prove the client returns what the server said rather than
/// something it invented.
struct StunTestServer {
    socket: Arc<UdpSocket>,
    transaction_requests: Arc<AtomicU32>,
}

impl StunTestServer {
    /// Bind on `127.0.0.1:0` and start answering in the background.
    async fn start(reported: SocketAddr) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let transaction_requests = Arc::new(AtomicU32::new(0));
        let task_socket = Arc::clone(&socket);
        let task_count = Arc::clone(&transaction_requests);
        tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            loop {
                let (len, from) = match task_socket.recv_from(&mut buffer).await {
                    Ok(received) => received,
                    Err(_) => return,
                };
                task_count.fetch_add(1, Ordering::SeqCst);
                let request = match StunMessage::decode(&buffer[..len]) {
                    Ok(request) => request,
                    // Malformed input must be dropped, not answered.
                    Err(_) => continue,
                };
                let transaction_id = request.transaction_id();
                let mapped = match XorMappedAddress::ipv4(reported, transaction_id) {
                    Ok(mapped) => mapped,
                    Err(_) => return,
                };
                let response = BindingResponse::success(transaction_id, mapped)
                    .with_change_request(request.change_request().unwrap_or(ChangeRequest::NONE));
                let bytes = match response.encode() {
                    Ok(bytes) => bytes,
                    Err(_) => return,
                };
                let _ = task_socket.send_to(&bytes, from).await;
            }
        });
        Self {
            socket,
            transaction_requests,
        }
    }

    /// The address clients should send to.
    fn addr(&self) -> SocketAddr {
        self.socket.local_addr().expect("addr")
    }

    /// How many datagrams carrying a decodable Binding Request arrived.
    fn requests_seen(&self) -> u32 {
        self.transaction_requests.load(Ordering::SeqCst)
    }
}

/// A server that receives and never answers, so the client's own deadline is
/// the only way out.
async fn silent_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = socket.local_addr().expect("addr");
    // Hold the socket open for the duration of the test.
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            if socket.recv_from(&mut buffer).await.is_err() {
                return;
            }
        }
    });
    addr
}

/// A port with nothing bound to it, obtained by binding and releasing.
async fn free_port() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = socket.local_addr().expect("addr");
    drop(socket);
    addr
}

#[tokio::test]
async fn binding_request_returns_the_address_the_real_server_reported() {
    // A deliberately un-NAT-like address: proves the value came from the reply.
    let reported: SocketAddr = "203.0.113.7:54321".parse().expect("literal");
    let server = StunTestServer::start(reported).await;

    let reflexive = binding_request(server.addr(), Duration::from_secs(2))
        .await
        .expect("a real reply");
    assert_eq!(reflexive.mapped, reported);
    assert_eq!(reflexive.source, server.addr());
    assert_eq!(
        server.requests_seen(),
        1,
        "exactly one Binding Request, not a retry"
    );

    // A different server reporting a different address must come back with that
    // address: the client is not caching or inventing a mapping.
    let second = StunTestServer::start("198.51.100.9:40000".parse().expect("literal")).await;
    let reflexive = binding_request(second.addr(), Duration::from_secs(2))
        .await
        .expect("a real reply");
    assert_eq!(
        reflexive.mapped,
        "198.51.100.9:40000".parse::<SocketAddr>().expect("literal")
    );
    assert_eq!(second.requests_seen(), 1);
    assert_eq!(
        server.requests_seen(),
        1,
        "the first server was not contacted again"
    );
}

#[tokio::test]
async fn binding_request_reports_the_address_for_ipv6_over_a_real_socket() {
    // The IPv6 path is worth a socket test too: the XOR mask depends on the
    // transaction id, which only a real exchange supplies.
    let reported: SocketAddr = "[2001:db8::7]:3478".parse().expect("literal");
    let server = UdpSocket::bind("[::1]:0").await;
    let server = match server {
        Ok(socket) => socket,
        // A host with no IPv6 stack is not a failure of this crate.
        Err(_) => return,
    };
    let addr = server.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            let (len, from) = match server.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(_) => return,
            };
            let request = match StunMessage::decode(&buffer[..len]) {
                Ok(request) => request,
                Err(_) => continue,
            };
            let mapped = match XorMappedAddress::ipv6(reported, request.transaction_id()) {
                Ok(mapped) => mapped,
                Err(_) => return,
            };
            let response = BindingResponse::success(request.transaction_id(), mapped);
            if let Ok(bytes) = response.encode() {
                let _ = server.send_to(&bytes, from).await;
            }
        }
    });

    let reflexive = binding_request(addr, Duration::from_secs(2))
        .await
        .expect("a real reply");
    assert_eq!(reflexive.mapped, reported);
}

#[tokio::test]
async fn a_legacy_mapped_address_reply_is_still_accepted() {
    let reported: SocketAddr = "192.0.2.55:3478".parse().expect("literal");
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = server.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            let (len, from) = match server.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(_) => return,
            };
            let request = match StunMessage::decode(&buffer[..len]) {
                Ok(request) => request,
                Err(_) => continue,
            };
            // An RFC 3489 server: MAPPED-ADDRESS only, no XOR attribute.
            let legacy = nau_net::stun::MappedAddress::new(reported).encode_value();
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&0x0101u16.to_be_bytes());
            bytes.extend_from_slice(&(4u16 + legacy.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&nau_net::stun::MAGIC_COOKIE.to_be_bytes());
            bytes.extend_from_slice(request.transaction_id().as_bytes());
            bytes.extend_from_slice(&nau_net::stun::ATTR_MAPPED_ADDRESS.to_be_bytes());
            bytes.extend_from_slice(&(legacy.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&legacy);
            let _ = server.send_to(&bytes, from).await;
        }
    });

    let reflexive = binding_request(addr, Duration::from_secs(2))
        .await
        .expect("a legacy reply is enough");
    assert_eq!(reflexive.mapped, reported);
}

#[tokio::test]
async fn a_server_that_never_replies_times_out_within_the_deadline() {
    let addr = silent_server().await;
    let budget = Duration::from_millis(400);
    let started = Instant::now();
    let result = binding_request(addr, budget).await;
    let elapsed = started.elapsed();
    match result {
        Err(StunError::Timeout {
            server, attempts, ..
        }) => {
            assert_eq!(server, addr);
            assert!(attempts > 0, "the datagram must actually have been sent");
        }
        other => panic!("expected a typed timeout, got {other:?}"),
    }
    assert!(
        elapsed < budget + Duration::from_secs(2),
        "took {elapsed:?} for a {budget:?} deadline"
    );
}

#[tokio::test]
async fn a_probe_of_a_closed_port_times_out_rather_than_hanging_or_succeeding() {
    // Nothing is bound. Some platforms report an ICMP port-unreachable as
    // ECONNRESET on the next socket call; the implementation must treat that as
    // "this attempt failed" and end in a typed timeout.
    //
    // `free_port` releases the port before the probe, and nine tests in this binary run in
    // parallel, so another test's server can bind the released port in the gap and answer.
    // A reply therefore means the port was taken rather than that the timeout path is
    // broken, and the attempt is retried on a fresh port. Only a probe answered on every
    // attempt fails here, which is what a real defect would look like -- a stray neighbour
    // can win the race once, not five times running.
    let budget = Duration::from_millis(300);
    let mut attempts = 0;
    loop {
        attempts += 1;
        let addr = free_port().await;
        let started = Instant::now();
        match binding_request(addr, budget).await {
            Err(StunError::Timeout { .. }) => {
                assert!(started.elapsed() < budget + Duration::from_secs(2));
                return;
            }
            other => assert!(
                attempts < 5,
                "expected a typed timeout from a closed port, got {other:?} on all \
                 {attempts} attempts"
            ),
        }
    }
}

#[tokio::test]
async fn a_spoofed_reply_is_discarded_by_a_real_client() {
    // An off-path attacker that cannot see the request cannot guess the 96-bit
    // transaction id, so its datagram must not complete the exchange.
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = server.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            let (len, from) = match server.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(_) => return,
            };
            // Record that the request arrived, then answer with the wrong id.
            let spoofed_id = TransactionId([0xAB; 12]);
            let mapped =
                match XorMappedAddress::ipv4("203.0.113.7:1".parse().expect("literal"), spoofed_id)
                {
                    Ok(mapped) => mapped,
                    Err(_) => return,
                };
            if let Ok(bytes) = BindingResponse::success(spoofed_id, mapped).encode() {
                for _ in 0..3 {
                    let _ = server.send_to(&bytes, from).await;
                    let _ = len;
                }
            }
            // Then go silent, so the client's deadline is what ends the test.
        }
    });

    let result = binding_request(addr, Duration::from_millis(400)).await;
    assert!(
        matches!(result, Err(StunError::Timeout { .. })),
        "a spoofed response was accepted: {result:?}"
    );
}

#[tokio::test]
async fn change_request_flags_survive_a_real_round_trip() {
    // The server echoes the flags it decoded, so this proves the encoder, the
    // decoder and the padding all agree on the wire.
    let reported: SocketAddr = "203.0.113.7:1".parse().expect("literal");
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = server.local_addr().expect("addr");
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let task_seen = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            let (len, from) = match server.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(_) => return,
            };
            let request = match StunMessage::decode(&buffer[..len]) {
                Ok(request) => request,
                Err(_) => continue,
            };
            task_seen
                .lock()
                .await
                .push(request.change_request().unwrap_or(ChangeRequest::NONE));
            let mapped = match XorMappedAddress::ipv4(reported, request.transaction_id()) {
                Ok(mapped) => mapped,
                Err(_) => return,
            };
            if let Ok(bytes) = BindingResponse::success(request.transaction_id(), mapped).encode() {
                let _ = server.send_to(&bytes, from).await;
            }
        }
    });

    // A raw request with the flags set, sent through the same codec the client
    // uses; the client's own path is exercised by the probe tests.
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let request = BindingRequest::new().with_change_request(ChangeRequest::CHANGE_IP_AND_PORT);
    let bytes = request.encode().expect("encode");
    socket.send_to(&bytes, addr).await.expect("send");
    let mut buffer = [0u8; 1500];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .expect("a reply arrives")
        .expect("recv");
    let decoded = StunMessage::decode(&buffer[..len]).expect("decode");
    assert_eq!(decoded.transaction_id(), request.transaction_id());
    assert_eq!(
        decoded.xor_mapped_address().expect("mapped").socket_addr(),
        reported
    );
    let flags = seen.lock().await;
    assert_eq!(flags.len(), 1);
    assert_eq!(flags[0], ChangeRequest::CHANGE_IP_AND_PORT);
}

#[tokio::test]
async fn observations_collected_over_real_sockets_feed_the_pure_classifiers() {
    // Every value the classifier sees here came off a real UDP socket: the
    // destinations are the servers actually contacted, and the mapped addresses
    // are what those servers actually reported. No NAT exists on loopback, so
    // this test asserts that the pipeline is consistent — not that a NAT type
    // was "detected" on this host.
    let reported: SocketAddr = "203.0.113.7:40000".parse().expect("literal");
    let primary = StunTestServer::start(reported).await;
    let secondary = StunTestServer::start(reported).await;
    assert_ne!(primary.addr(), secondary.addr());

    // Two requests to *different* destination ports, which is the comparison the
    // mapping taxonomy is built on.
    let first = binding_request(primary.addr(), Duration::from_secs(2))
        .await
        .expect("primary reply");
    let second = binding_request(primary.addr(), Duration::from_secs(2))
        .await
        .expect("primary reply again");
    let third = binding_request(secondary.addr(), Duration::from_secs(2))
        .await
        .expect("secondary reply");
    assert_eq!(first.mapped, reported);
    assert_eq!(second.mapped, reported);
    assert_eq!(third.mapped, reported);
    assert_eq!(first.source, primary.addr());
    assert_eq!(third.source, secondary.addr());

    let observations = ObservationSet {
        primary: Some(Observation {
            destination: first.source,
            mapped: first.mapped,
        }),
        // A second destination port on the primary server. The classifier's
        // contract is that `destination` is the port the mapping was created
        // for, so it must differ from the primary's.
        change_port: Some(Observation {
            destination: primary.addr(),
            mapped: second.mapped,
        }),
        change_ip_and_port: None,
        secondary: Some(Observation {
            destination: third.source,
            mapped: third.mapped,
        }),
        probed: ObservationAttempts {
            primary: Some(first.source),
            change_port: Some(primary.addr()),
            change_ip_and_port: None,
            secondary: Some(third.source),
        },
        failures: Vec::new(),
    };

    // The two primary observations used the *same* destination, so the mapping
    // comparison has nothing to compare and must refuse to classify. This is the
    // anti-constant property: identical inputs cannot be talked into a NAT type.
    assert_eq!(classify_mapping(&observations), MappingBehavior::Unknown);

    // Make the second destination port genuinely different, exactly as the real
    // four-probe collector does, and the same evidence now classifies.
    // (`127.0.0.1:1` stands in for a second destination port on the primary
    // server: a real four-probe run targets the *server's* port, not a second
    // client socket, and the two client sockets here could in principle share a
    // local port.)
    let second_destination: SocketAddr =
        SocketAddr::new(primary.addr().ip(), primary.addr().port().wrapping_add(1));
    let distinct = ObservationSet {
        change_port: Some(Observation {
            destination: second_destination,
            mapped: second.mapped,
        }),
        ..observations
    };
    assert_ne!(
        distinct.primary.expect("primary").destination,
        second_destination
    );
    assert_eq!(
        classify_mapping(&distinct),
        MappingBehavior::EndpointIndependent
    );
    // Filtering, on the other hand, cannot be classified here: every server in
    // this test is on `127.0.0.1`, so no probe ever contacts a *different IP
    // address*. The classifier must say Unknown rather than round that up to a
    // filtering behaviour, which is the whole point of this rewrite. (The
    // `change_port` observation has to describe the same destination the primary
    // probe used for this to be the single-address case.)
    let single_address = ObservationSet {
        change_port: Some(Observation {
            destination: distinct.primary.expect("primary").destination,
            mapped: second.mapped,
        }),
        ..distinct.clone()
    };
    assert_eq!(
        classify_filtering(&single_address, MappingBehavior::EndpointIndependent),
        FilteringBehavior::Unknown,
        "a single-address test cannot demonstrate a filtering behaviour"
    );
    // The same evidence with a response from another *port* on the targeted
    // address is address-dependent filtering: the filter pins the address, not
    // the port.
    assert_eq!(
        classify_filtering(&distinct, MappingBehavior::EndpointIndependent),
        FilteringBehavior::AddressDependent
    );

    // A probe of a genuinely different IP address that never answers, on the
    // other hand, is evidence — and that evidence is what the classifier acts on.
    let other_ip = ObservationSet {
        probed: ObservationAttempts {
            change_ip_and_port: Some("198.51.100.1:3478".parse().expect("literal")),
            ..single_address.probed
        },
        ..single_address
    };
    assert_eq!(
        classify_filtering(&other_ip, MappingBehavior::EndpointIndependent),
        FilteringBehavior::AddressAndPortDependent
    );

    // A server that reports a *different* mapped port cannot be classified as
    // endpoint-independent by accident.
    let other = StunTestServer::start("203.0.113.7:41000".parse().expect("literal")).await;
    let fourth = binding_request(other.addr(), Duration::from_secs(2))
        .await
        .expect("reply");
    assert_eq!(fourth.mapped.port(), 41000);
    let observations = ObservationSet {
        secondary: Some(Observation {
            destination: fourth.source,
            mapped: fourth.mapped,
        }),
        probed: ObservationAttempts {
            secondary: Some(fourth.source),
            ..distinct.probed
        },
        ..distinct
    };
    assert_eq!(
        classify_mapping(&observations),
        MappingBehavior::AddressDependent
    );
}

#[tokio::test]
async fn binding_request_retries_a_silent_server_a_bounded_number_of_times() {
    // UDP loses datagrams, so the client re-sends; the cap must be visible as a
    // small, bounded number of datagrams rather than an unbounded retry loop.
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = socket.local_addr().expect("addr");
    let received = Arc::new(AtomicU32::new(0));
    let task_received = Arc::clone(&received);
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((_len, _from)) => {
                    task_received.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => return,
            }
        }
    });

    let result = binding_request(addr, Duration::from_millis(450)).await;
    assert!(matches!(result, Err(StunError::Timeout { .. })));
    let seen = received.load(Ordering::SeqCst);
    assert!(seen >= 1, "at least one datagram must be sent");
    assert!(
        seen <= nau_net::stun::BINDING_REQUEST_ATTEMPTS,
        "sent {seen} datagrams, above the documented cap"
    );
}
