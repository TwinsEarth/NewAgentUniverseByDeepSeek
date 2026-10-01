//! The libp2p bridge: what this node shares with peers, and what it accepts back.
//!
//! `nau-daemon` is a market behind a loopback HTTP port — reachable only by
//! whoever can open a socket to `127.0.0.1`. This module is the change to that
//! statement: the same node also joins a real libp2p swarm (TCP + Noise + Yamux +
//! Kademlia + GossipSub) and gossips its **signed** agent registry to the room.
//!
//! ## Why only the agent registry
//!
//! Agents are the one part of the market that is already a self-contained,
//! signed, portable object: an [`AgentCard`] carries `owner`, `owner_key` and an
//! Ed25519 `signature` over its canonical payload, so a peer can verify a card it
//! received from a stranger without trusting the sender at all.
//!
//! Balances and settlement are deliberately **not** replicated. Moving money
//! between nodes is a consensus question (who may mint, how a double-spend is
//! refused, which node's ledger wins) that this project has not answered, and
//! replicating a ledger without answering it would be exactly the "documented
//! promise larger than the code" the audit criticises upstream for. A card that
//! arrives over the wire enters [`NetworkDirectory`], never the local market's
//! staked registry.
//!
//! ## What a peer cannot do
//!
//! A received card is admitted only if [`Verifiable::verify`] accepts it, which
//! checks the signature *and* that the key fingerprints the DID it claims. A
//! forger who invents a card for someone else's DID is refused; a peer cannot
//! register an agent on this node, cannot move funds, and cannot alter local
//! market state — the directory is a separate, read-only view.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nau_core::{AgentCard, Verifiable};
use nau_libp2p::config::{KadMode, Libp2pConfig, Multiaddr};
use nau_libp2p::identity::NauIdentity;
use nau_libp2p::naming::room_topic;
use nau_libp2p::swarm::Libp2pNode;
use nau_net::Frame;

/// Seconds since the Unix epoch, or 0 if the clock is before it.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One peer this node has exchanged frames with.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PeerRecord {
    /// The libp2p `PeerId`, base58.
    pub peer_id: String,
    /// When a frame from this peer was last seen (Unix seconds).
    pub last_seen: u64,
}

/// Everything this node knows about the network beyond itself.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct NetworkDirectory {
    /// This node's own libp2p `PeerId`.
    pub local_peer_id: String,
    /// This node's own `did:nau:`.
    pub local_did: String,
    /// Frames this node published.
    pub frames_published: u64,
    /// Frames received from peers.
    pub frames_received: u64,
    /// Received frames that carried nothing verifiable.
    pub frames_rejected: u64,
    /// Peers seen, by `PeerId`.
    pub peers: BTreeMap<String, PeerRecord>,
    /// Agent cards gossiped by peers and verified locally, by DID.
    pub agents: BTreeMap<String, serde_json::Value>,
}

/// Shared handle to the [`NetworkDirectory`].
///
/// Cloning shares the same directory; the mutex is never held across an `await`.
#[derive(Clone, Default)]
pub struct Directory(Arc<Mutex<NetworkDirectory>>);

impl Directory {
    /// An empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `f` under the lock, recovering from a poisoned mutex.
    ///
    /// The directory is a cache of verified public data: a panic in one updater
    /// must not wedge the HTTP route that reads it.
    fn update<R>(&self, f: impl FnOnce(&mut NetworkDirectory) -> R) -> R {
        let mut guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }

    /// A consistent copy, for a JSON response.
    pub fn snapshot(&self) -> NetworkDirectory {
        self.update(|d| d.clone())
    }

    /// Record this node's own identity.
    pub fn set_local(&self, peer_id: String, did: String) {
        self.update(|d| {
            d.local_peer_id = peer_id;
            d.local_did = did;
        });
    }

    /// Note that these peers are connected.
    pub fn note_peers(&self, peers: &[String], now: u64) {
        self.update(|d| {
            for peer in peers {
                d.peers.insert(
                    peer.clone(),
                    PeerRecord {
                        peer_id: peer.clone(),
                        last_seen: now,
                    },
                );
            }
        });
    }

    /// Count a published frame.
    pub fn note_published(&self) {
        self.update(|d| d.frames_published += 1);
    }

    /// Count a received frame; `accepted` is false when nothing in it verified.
    pub fn note_received(&self, accepted: bool) {
        self.update(|d| {
            d.frames_received += 1;
            if !accepted {
                d.frames_rejected += 1;
            }
        });
    }

    /// Store a verified card for `did`. Returns whether it was new.
    pub fn accept_agent(&self, did: String, card: serde_json::Value) -> bool {
        self.update(|d| {
            if d.agents.contains_key(&did) {
                return false;
            }
            d.agents.insert(did, card);
            true
        })
    }
}

/// How this node joins the network.
#[derive(Debug, Clone)]
pub struct P2pOptions {
    /// Listen multiaddr, e.g. `/ip4/0.0.0.0/tcp/4001`.
    pub listen: String,
    /// The GossipSub room all nodes must share to see each other.
    pub room: String,
    /// The 32-byte seed behind both the `did:nau:` and the libp2p `PeerId`.
    pub seed: [u8; 32],
    /// Peers to dial at startup.
    pub bootstrap: Vec<String>,
}

/// Start the swarm, or return a human-readable reason it did not start.
pub async fn start_swarm(options: &P2pOptions) -> Result<Arc<Libp2pNode>, String> {
    let identity = NauIdentity::from_seed(&options.seed);
    let listen = Multiaddr::parse(&options.listen).map_err(|e| format!("--listen: {e}"))?;
    let mut config = Libp2pConfig::new(&identity, listen);
    config = config.with_room(&options.room);
    config = config
        .with_seed(options.seed)
        .map_err(|e| format!("seed: {e}"))?;
    // Server mode is what makes the DHT carry records: in the default `Client`
    // mode a node never adds connected peers to its routing table, so everything
    // looks healthy while replication reaches nobody.
    config.kad_mode = KadMode::Server;
    config
        .validate()
        .map_err(|e| format!("libp2p configuration: {e}"))?;

    let swarm = Libp2pNode::spawn(config)
        .await
        .map_err(|e| format!("cannot start the libp2p swarm: {e}"))?;
    for addr in &options.bootstrap {
        if let Err(e) = swarm.dial(addr).await {
            tracing::warn!(bootstrap = %addr, error = %e, "bootstrap dial failed");
        }
    }
    Ok(Arc::new(swarm))
}

/// Publish this node's registered agents to the room, forever.
///
/// The payload is the cards themselves, not a summary: a receiver must be able to
/// verify each one, and a summary would carry no signature to check.
///
/// `room` is the bare room name; the GossipSub topic is derived from it. Passing
/// the bare name to `publish` is refused as a bad topic, so the derivation happens
/// here rather than at each call site.
pub async fn publish_loop(
    swarm: Arc<Libp2pNode>,
    directory: Directory,
    node: Arc<Mutex<crate::Node>>,
    room: String,
    interval: Duration,
) {
    let topic = room_topic(&room);
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;

        // Keep the peer view current even when no frame has arrived yet.
        let peers: Vec<String> = swarm
            .connected()
            .await
            .iter()
            .map(ToString::to_string)
            .collect();
        directory.note_peers(&peers, unix_now());

        let cards: Vec<serde_json::Value> = {
            let guard = match node.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard
                .market()
                .agents()
                .into_iter()
                .filter_map(|card| serde_json::to_value(card).ok())
                .collect()
        };
        let envelope = serde_json::json!({ "kind": "agents", "cards": cards });
        let Ok(bytes) = serde_json::to_vec(&envelope) else {
            continue;
        };
        match swarm.publish(&topic, &Frame::new(bytes)).await {
            Ok(_) => directory.note_published(),
            // Silently swallowing this is how the bare-room-name bug hid: the node
            // looked healthy while nothing was ever sent.
            Err(e) => tracing::warn!(error = %e, "publish failed"),
        }
    }
}

/// Accept agent cards from peers, verifying every one before it is stored.
pub async fn receive_loop(swarm: Arc<Libp2pNode>, directory: Directory, local_did: String) {
    loop {
        match swarm.recv_frame(Duration::from_secs(1)).await {
            Ok(Some((peer, frame))) => {
                let peer_id = peer.to_string();
                directory.note_peers(std::slice::from_ref(&peer_id), unix_now());
                let accepted = accept_envelope(&directory, frame.as_slice(), &local_did);
                directory.note_received(accepted);
            }
            // A quiet second is normal, not a failure.
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "libp2p receive failed");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

/// Verify an envelope's cards and store the valid ones.
///
/// Returns whether the frame carried at least one card whose signature verified.
fn accept_envelope(directory: &Directory, payload: &[u8], local_did: &str) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
        return false;
    };
    let Some(cards) = value.get("cards").and_then(|c| c.as_array()) else {
        return false;
    };

    let mut verified_any = false;
    for raw in cards {
        let Ok(card) = serde_json::from_value::<AgentCard>(raw.clone()) else {
            continue;
        };
        // The signature is the whole reason a stranger's claim can be believed:
        // it proves the card was authored by the key that fingerprints its DID.
        if card.verify().is_err() {
            tracing::warn!(did = %card.owner, "refused an agent card with an invalid signature");
            continue;
        }
        verified_any = true;
        // Our own card comes back through the mesh; it is already local.
        if card.owner.as_str() == local_did {
            continue;
        }
        if directory.accept_agent(card.owner.to_string(), raw.clone()) {
            tracing::info!(did = %card.owner, name = %card.name, "learned an agent over P2P");
        }
    }
    verified_any
}
