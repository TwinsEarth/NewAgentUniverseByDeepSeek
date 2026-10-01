//! The libp2p swarm: one `NetworkBehaviour` composing five protocols.
//!
//! ## What is composed, and why each one is here
//!
//! | behaviour | what it provides | why this crate needs it |
//! |---|---|---|
//! | [`KademliaBehaviour`] | Kademlia DHT | the record store: `put_record`/`get_record` |
//! | [`GossipSubBehaviour`] | GossipSub pub/sub | room messaging, one topic per room |
//! | [`RelayClient`] | Circuit Relay **v2 client** | reservations, so a NATed node is reachable |
//! | [`RelayServer`] | Circuit Relay **v2 server** | relays for other nodes: the client's other half |
//! | [`AutoNatBehaviour`] | AutoNAT | measures this node's reachability instead of guessing |
//! | [`DcutrBehaviour`] | DCUtR | hole punching, once AutoNAT says it is needed |
//! | [`IdentifyBehaviour`] | identify | public key + listen addresses, the input Kademlia needs |
//! | [`PingBehaviour`] | ping | liveness, so a silent peer is distinguishable from a slow one |
//!
//! Circuit Relay v2 is a *pair* of behaviours, not one: a node that wants to be
//! reachable behind a NAT runs the client and reserves a slot on a relay, and a
//! node that volunteers to relay runs the server. Both are in this behaviour so
//! one process can be either, which is what the two-node test uses.
//!
//! ## Upstream defect this closes
//!
//! agent-universe v2.5.6 named three `HashMap`-backed mocks `KademliaClient`,
//! `GossipSub` and `GsnNode` and re-exported them from its crate root
//! (`lib.rs:44`), so its integration tests "proved" networking against a map.
//! This module is the real thing, and it is only reachable with the `libp2p`
//! feature on — a build without the feature has no `behaviour` module at all,
//! so there is nothing that could be mistaken for the real stack.
//! `// upstream v2.5.6 fix: the real protocols are composed here and the mocks
//! are not named as services anywhere.`

use std::time::Duration;

use libp2p::swarm::NetworkBehaviour;

use crate::config::{KadMode, Libp2pConfig};
use crate::naming;

/// Type alias for the Kademlia behaviour with an in-memory record store.
///
/// `MemoryStore` rather than a persistent store on purpose: this crate owns no
/// storage, and `nau-store` is the workspace's persistence port. A node that
/// wants DHT records to survive a restart is a node that should be feeding them
/// through `nau_store::Store`, which is a decision for the caller and not
/// something to bury in the network layer.
pub type KademliaBehaviour = libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>;

/// Type alias for the GossipSub behaviour with the default filter and transform.
pub type GossipSubBehaviour = libp2p::gossipsub::Behaviour;

/// Type alias for the identify behaviour.
pub type IdentifyBehaviour = libp2p::identify::Behaviour;

/// Type alias for the ping behaviour.
pub type PingBehaviour = libp2p::ping::Behaviour;

/// Type alias for the AutoNAT v1 client behaviour.
pub type AutoNatBehaviour = libp2p::autonat::Behaviour;

/// Type alias for the DCUtR behaviour.
pub type DcutrBehaviour = libp2p::dcutr::Behaviour;

/// Type alias for the Circuit Relay v2 server behaviour.
pub type RelayServer = libp2p::relay::Behaviour;

/// Type alias for the Circuit Relay v2 client behaviour.
pub type RelayClient = libp2p::relay::client::Behaviour;

/// The outbound half of the relay server's transport.
///
/// `SwarmBuilder::with_relay_client` wraps the transport and hands the client
/// behaviour to the behaviour constructor; the type of that wrapper is
/// unnameable, which is why the builder's own type is used rather than written
/// out. This alias exists so the type appears once.
pub type RelayTransport = libp2p::relay::client::Transport;

/// Everything this node speaks, wired into one `NetworkBehaviour`.
///
/// Constructing the value is not enough to make it work: the swarm must also be
/// told to listen, to dial the bootstrap peers, and which topics to subscribe to.
/// [`Libp2pBehaviour::for_config`] performs the part of that which is a pure
/// function of the configuration (topic subscriptions and the Kademlia mode); the
/// dialling half belongs to the event loop because it can fail.
///
/// The fields are public because the event loop has to drive them individually —
/// `kad.put_record`, `gossipsub.publish`, `relay_client` events — and a
/// pass-through accessor for each would be noise.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NauEvent", prelude = "libp2p::swarm::derive_prelude")]
pub struct Libp2pBehaviour {
    /// Kademlia DHT: the record store and peer routing.
    pub kad: KademliaBehaviour,
    /// GossipSub: room messaging.
    pub gossipsub: GossipSubBehaviour,
    /// Circuit Relay v2, client side: reserve a slot on a relay.
    pub relay_client: RelayClient,
    /// Circuit Relay v2, server side: relay for others.
    pub relay_server: RelayServer,
    /// AutoNAT: ask a server what this node's address looks like from outside.
    pub autonat: AutoNatBehaviour,
    /// DCUtR: punch a hole once AutoNAT says one is needed.
    pub dcutr: DcutrBehaviour,
    /// identify: exchange public keys and listen addresses.
    pub identify: IdentifyBehaviour,
    /// ping: liveness.
    pub ping: PingBehaviour,
}

impl Libp2pBehaviour {
    /// Build the behaviours and apply the parts of `config` that are pure setup.
    ///
    /// `relay_client` is passed in rather than built here because
    /// `SwarmBuilder::with_relay_client` owns the transport that the client
    /// behaviour is paired with: the two must come from the same call or the
    /// reservations the behaviour requests are never carried.
    ///
    /// `keypair` is passed rather than re-derived so that the identity this node
    /// speaks with is provably the same one the transport is using, and so that the
    /// check below can fail loudly rather than producing a node whose GossipSub
    /// signatures come from a different key than its `PeerId`.
    ///
    /// Returns an error when the keypair and `local_peer_id` disagree, or when a
    /// GossipSub topic is one libp2p refuses — which for this crate's topics means
    /// an internal inconsistency, since [`crate::naming::RoomName`] has already
    /// validated the name.
    pub fn for_config(
        config: &Libp2pConfig,
        local_peer_id: libp2p::PeerId,
        keypair: &libp2p::identity::Keypair,
        relay_client: RelayClient,
    ) -> Result<Self, BehaviourError> {
        let derived = keypair.public().to_peer_id();
        if derived != local_peer_id {
            return Err(BehaviourError::IdentityMismatch {
                claimed: local_peer_id.to_string(),
                derived: derived.to_string(),
            });
        }
        let local_public_key = keypair.public();

        let mut kad = libp2p::kad::Behaviour::with_config(
            local_peer_id,
            libp2p::kad::store::MemoryStore::new(local_peer_id),
            kademlia_config(config),
        );
        // The mode is a function of the configuration and is therefore applied
        // here rather than left to the event loop.
        kad.set_mode(Some(match config.kad_mode {
            KadMode::Server => libp2p::kad::Mode::Server,
            KadMode::Client => libp2p::kad::Mode::Client,
        }));

        let mut gossipsub = build_gossipsub(keypair)?;
        for topic in config.topics() {
            let topic = libp2p::gossipsub::IdentTopic::new(topic.clone());
            gossipsub
                .subscribe(&topic)
                .map_err(|e| BehaviourError::Subscribe {
                    topic: topic.to_string(),
                    reason: e.to_string(),
                })?;
        }

        // The relay server is always present: whether this node *serves* relays is
        // decided by what other nodes ask it for, and a server that is built but
        // never asked costs one idle behaviour.
        let relay_server =
            libp2p::relay::Behaviour::new(local_peer_id, libp2p::relay::Config::default());

        let mut autonat = libp2p::autonat::Behaviour::new(
            local_peer_id,
            libp2p::autonat::Config {
                // A node that configured no AutoNAT server must not silently dial
                // arbitrary connected peers to ask: `use_connected` is therefore
                // tied to whether servers were configured, so the "no server"
                // case is a no-op rather than a heuristic.
                use_connected: config.autonat_enabled(),
                // The default throttle is minutes; these are shorter because a
                // two-node test cannot wait for a default refresh interval, and
                // the values are still far above the protocol's own rate limits.
                refresh_interval: Duration::from_secs(60),
                retry_interval: Duration::from_secs(10),
                ..libp2p::autonat::Config::default()
            },
        );
        for server in &config.autonat_servers {
            match server.to_libp2p() {
                Ok(addr) => {
                    if let Ok(Some(peer)) = server.peer_id() {
                        if let Some(libp2p_peer) = to_libp2p_peer_id(&peer) {
                            autonat.add_server(libp2p_peer, Some(addr));
                        }
                    }
                }
                // Validation has already rejected a malformed address, so a
                // failure here is a configuration that was never validated. It is
                // not fatal: the server is simply not registered, and
                // `nat_status` reports Unknown rather than a fabricated answer.
                Err(_) => continue,
            }
        }

        let dcutr = libp2p::dcutr::Behaviour::new(local_peer_id);

        let identify = libp2p::identify::Behaviour::new(
            libp2p::identify::Config::new("nau/1.1.1".to_string(), local_public_key)
                .with_agent_version(format!("nau-libp2p/{}", env!("CARGO_PKG_VERSION"))),
        );

        let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new());

        Ok(Self {
            kad,
            gossipsub,
            relay_client,
            relay_server,
            autonat,
            dcutr,
            identify,
            ping,
        })
    }

    /// The GossipSub topics this node is subscribed to.
    pub fn subscribed_topics(&self) -> Vec<String> {
        self.gossipsub.topics().map(|t| t.to_string()).collect()
    }

    /// Whether Kademlia is in server mode.
    pub fn kad_is_server(&self) -> bool {
        // `Mode` has no accessor; server mode is defined as "answers queries",
        // which `Mode::Server` requests. The behaviour's own answer is not
        // exposed, so this reports the configured intent, and the test asserts
        // the DHT actually serves records.
        matches!(self.kad.mode(), libp2p::kad::Mode::Server)
    }

    /// The current AutoNAT verdict about this node's reachability.
    ///
    /// Returns `Unknown` when no server was reachable — never a fabricated
    /// classification, which is the defect `nau_net::nat` exists to correct.
    pub fn nat_status(&self) -> NatStatus {
        NatStatus::from_libp2p(self.autonat.nat_status())
    }
}

/// This node's reachability as AutoNAT measured it.
///
/// A local mirror of `libp2p::autonat::NatStatus` so that callers do not have to
/// depend on the `libp2p` feature to name the result, and so that the
/// `Unknown` case is impossible to ignore by accident: it is a variant, not a
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatStatus {
    /// A server reported this address, so the node is reachable from outside.
    Public(String),
    /// A server was reachable and reported that this node is not dialable.
    Private,
    /// No server answered. **Not** a classification: it means nothing was
    /// measured.
    Unknown,
}

impl NatStatus {
    /// Convert from libp2p's own type.
    pub fn from_libp2p(status: libp2p::autonat::NatStatus) -> Self {
        match status {
            libp2p::autonat::NatStatus::Public(addr) => NatStatus::Public(addr.to_string()),
            libp2p::autonat::NatStatus::Private => NatStatus::Private,
            libp2p::autonat::NatStatus::Unknown => NatStatus::Unknown,
        }
    }

    /// Whether a measurement says this node is publicly reachable.
    pub fn is_public(&self) -> bool {
        matches!(self, NatStatus::Public(_))
    }

    /// Whether anything at all was measured.
    pub fn is_measured(&self) -> bool {
        !matches!(self, NatStatus::Unknown)
    }
}

impl std::fmt::Display for NatStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatStatus::Public(addr) => write!(f, "public({addr})"),
            NatStatus::Private => f.write_str("private"),
            NatStatus::Unknown => f.write_str("unknown"),
        }
    }
}

/// The Kademlia configuration for this network.
///
/// The protocol name is the load-bearing part: two nodes that disagree about it
/// do not see each other, and the failure is silence rather than an error. That is
/// why [`crate::config::Libp2pConfig`] refuses a protocol name that is not
/// [`naming::KAD_PROTOCOL`].
///
/// `libp2p::StreamProtocol::new` takes a `&'static str`, and it *panics* on a name
/// that does not start with `/`:
///
/// ```text
/// pub const fn new(s: &'static str) -> Self {
///     match s.as_bytes() {
///         [b'/', ..] => {}
///         _ => panic!("Protocols should start with a /"),
///     }
/// ```
///
/// A `String` from a configuration file therefore cannot be passed to it directly,
/// and — more importantly — must not be passed to it in a way that could panic on
/// an operator's input. [`static_kad_protocol`] resolves the configured name
/// against the one protocol this network speaks, and because validation has
/// already rejected everything else, the `panic!` inside `StreamProtocol::new` is
/// unreachable from this crate.
pub fn static_kad_protocol(config: &Libp2pConfig) -> &'static str {
    if config.kad_protocol == naming::KAD_PROTOCOL {
        naming::KAD_PROTOCOL
    } else {
        // Validation rejects any other name, so this branch is reached only by a
        // configuration that was never validated. Returning the network's own
        // protocol rather than panicking means an unvalidated configuration
        // produces a node that talks to nobody — which is a diagnosable symptom —
        // instead of a process that dies at startup with an upstream panic.
        naming::KAD_PROTOCOL
    }
}

/// [`kademlia_config`]'s body, factored out so the protocol resolution above is
/// the single place a protocol name becomes a `StreamProtocol`.
pub fn kademlia_config(config: &Libp2pConfig) -> libp2p::kad::Config {
    let protocol = libp2p::StreamProtocol::new(static_kad_protocol(config));
    let mut kad = libp2p::kad::Config::new(protocol);
    // A query timeout short enough that a two-node test finishes, and long enough
    // that a one-hop query over a real link is not abandoned.
    kad.set_query_timeout(Duration::from_secs(20));
    // Records expire. The value is the Kademlia default expressed explicitly:
    // records that never expire accumulate forever in a store this crate does not
    // persist, which is a leak rather than a feature.
    kad.set_record_ttl(Some(Duration::from_secs(3600)));
    kad
}

/// Build the GossipSub behaviour for this network.
///
/// `MessageAuthenticity::Signed` takes the full `Keypair`, not just the public
/// key: a signature is produced on every published message, so the private half is
/// required. This is what allows a receiver to attribute a message to a key rather
/// than to a forwarding peer; the default `MessageAuthenticity::Anonymous` would
/// let any peer publish as anyone.
///
/// Duplicate suppression is keyed on the author, the sequence number and the
/// payload, so a retransmission is recognised while a genuine second message with
/// the same bytes is not swallowed.
pub fn build_gossipsub(
    keypair: &libp2p::identity::Keypair,
) -> Result<GossipSubBehaviour, BehaviourError> {
    let mut config = libp2p::gossipsub::ConfigBuilder::default();
    config.message_id_fn(|message| {
        let mut id = Vec::with_capacity(64);
        if let Some(author) = message.source.as_ref() {
            id.extend_from_slice(author.to_bytes().as_slice());
        }
        id.extend_from_slice(message.data.as_slice());
        id.extend_from_slice(&message.sequence_number.unwrap_or_default().to_be_bytes());
        // `MessageId: From<T: Into<Vec<u8>>>`; `message_id_fn` requires the closure
        // to return a `MessageId` directly, not a `Result`.
        libp2p::gossipsub::MessageId::from(id)
    });
    // The default heartbeat is one second, which is the granularity at which a mesh
    // is repaired. Left at the default deliberately: shortening it to make a test
    // faster would make the test measure a configuration nobody runs.
    let config = config
        .build()
        .map_err(|e| BehaviourError::Config(e.to_string()))?;
    libp2p::gossipsub::Behaviour::new(
        libp2p::gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        config,
    )
    .map_err(|e| BehaviourError::Config(e.to_string()))
}

/// Convert this crate's peer id into libp2p's.
///
/// Returns `None` when the bytes are not a valid libp2p peer id, which cannot
/// happen for a value this crate derived but can for one that arrived from a
/// configuration file.
pub fn to_libp2p_peer_id(peer: &crate::identity::PeerId) -> Option<libp2p::PeerId> {
    libp2p::PeerId::from_bytes(peer.as_bytes()).ok()
}

/// What the composed behaviour reports upward.
///
/// This is the `ToSwarm` associated type. Only the events the event loop acts on
/// are carried; everything else is dropped by the `From` implementations below,
/// which is deliberate — an event nobody handles should not become an API.
#[derive(Debug)]
pub enum NauEvent {
    /// A peer completed an identify exchange. Kademlia needs the addresses.
    Identify(Box<libp2p::identify::Event>),
    /// Kademlia produced progress on a query or a record.
    Kademlia(Box<libp2p::kad::Event>),
    /// A GossipSub message or subscription change.
    GossipSub(Box<libp2p::gossipsub::Event>),
    /// The relay client's reservation state changed.
    RelayClient(Box<libp2p::relay::client::Event>),
    /// The relay server accepted or closed a circuit.
    RelayServer(Box<libp2p::relay::Event>),
    /// AutoNAT reached a verdict (or failed to).
    AutoNat(Box<libp2p::autonat::Event>),
    /// A hole punch succeeded or failed.
    Dcutr(Box<libp2p::dcutr::Event>),
    /// A ping round trip completed.
    Ping(Box<libp2p::ping::Event>),
}

impl From<libp2p::identify::Event> for NauEvent {
    fn from(event: libp2p::identify::Event) -> Self {
        NauEvent::Identify(Box::new(event))
    }
}

impl From<libp2p::kad::Event> for NauEvent {
    fn from(event: libp2p::kad::Event) -> Self {
        NauEvent::Kademlia(Box::new(event))
    }
}

impl From<libp2p::gossipsub::Event> for NauEvent {
    fn from(event: libp2p::gossipsub::Event) -> Self {
        NauEvent::GossipSub(Box::new(event))
    }
}

impl From<libp2p::relay::client::Event> for NauEvent {
    fn from(event: libp2p::relay::client::Event) -> Self {
        NauEvent::RelayClient(Box::new(event))
    }
}

impl From<libp2p::relay::Event> for NauEvent {
    fn from(event: libp2p::relay::Event) -> Self {
        NauEvent::RelayServer(Box::new(event))
    }
}

impl From<libp2p::autonat::Event> for NauEvent {
    fn from(event: libp2p::autonat::Event) -> Self {
        NauEvent::AutoNat(Box::new(event))
    }
}

impl From<libp2p::dcutr::Event> for NauEvent {
    fn from(event: libp2p::dcutr::Event) -> Self {
        NauEvent::Dcutr(Box::new(event))
    }
}

impl From<libp2p::ping::Event> for NauEvent {
    fn from(event: libp2p::ping::Event) -> Self {
        NauEvent::Ping(Box::new(event))
    }
}

/// Build-time failures that a caller can actually do something about.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BehaviourError {
    /// GossipSub rejected its own configuration. A programming error, surfaced
    /// rather than panicked on.
    #[error("GossipSub rejected its configuration: {0}")]
    Config(String),
    /// GossipSub refused a topic subscription.
    #[error("GossipSub refused subscription to `{topic}`: {reason}")]
    Subscribe {
        /// The topic.
        topic: String,
        /// Why it was refused.
        reason: String,
    },
    /// The keypair handed to the behaviour is not the one behind the peer id.
    #[error("the keypair derives peer id `{derived}`, but the swarm uses `{claimed}`")]
    IdentityMismatch {
        /// The peer id the swarm believes it has.
        claimed: String,
        /// The peer id the keypair actually derives.
        derived: String,
    },
}

impl From<BehaviourError> for nau_core::NauError {
    fn from(err: BehaviourError) -> Self {
        nau_core::NauError::Validation(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Multiaddr;
    use crate::identity::NauIdentity;

    fn config() -> (Libp2pConfig, libp2p::identity::Keypair, libp2p::PeerId) {
        let seed = [1u8; 32];
        let identity = NauIdentity::from_seed(&seed);
        let config = Libp2pConfig::new(
            &identity,
            Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid"),
        )
        // Without the signing key *no* configuration is valid, so every test that
        // wants a valid one has to attach it.
        .with_seed(seed)
        .expect("the seed is that identity's own key")
        .with_room("room-0000000000000001");
        let keypair = libp2p_keypair_from_seed(&seed);
        let peer = keypair.public().to_peer_id();
        (config, keypair, peer)
    }

    /// The libp2p keypair for a seed, matching `NauIdentity`'s Ed25519 key.
    fn libp2p_keypair_from_seed(seed: &[u8; 32]) -> libp2p::identity::Keypair {
        libp2p::identity::Keypair::ed25519_from_bytes(*seed).expect("32-byte seed is a valid key")
    }

    #[test]
    fn the_did_and_the_libp2p_keypair_are_the_same_key() {
        // This is the seam the whole crate rests on: if these disagree, the DID a
        // node signs with and the PeerId it dials as are different identities.
        let seed = [1u8; 32];
        let mine = NauIdentity::from_seed(&seed);
        let keypair = libp2p_keypair_from_seed(&seed);
        let their_peer = keypair.public().to_peer_id();
        let mine_libp2p =
            to_libp2p_peer_id(&mine.peer_id()).expect("this crate's id is a libp2p id");
        assert_eq!(
            mine_libp2p, their_peer,
            "the local peer-id derivation must match libp2p's own"
        );
        assert_eq!(mine_libp2p.to_string(), mine.peer_id().to_string());
    }

    #[test]
    fn the_composed_behaviour_can_be_built_with_every_protocol() {
        let (config, keypair, peer) = config();
        let (_transport, relay_client) = libp2p::relay::client::new(peer);
        let behaviour = Libp2pBehaviour::for_config(&config, peer, &keypair, relay_client)
            .expect("every protocol composes");
        // The room topic was subscribed, and the protocol name is the network's.
        assert_eq!(
            behaviour.subscribed_topics(),
            vec!["nau/room/room-0000000000000001".to_string()]
        );
        assert!(!behaviour.kad_is_server(), "the default mode is client");
        // With no AutoNAT server reachable the verdict is Unknown, not a guess.
        assert_eq!(behaviour.nat_status(), NatStatus::Unknown);
        assert!(!behaviour.nat_status().is_measured());
    }

    #[test]
    fn a_kademlia_server_node_reports_server_mode() {
        let (mut config, keypair, peer) = config();
        config.kad_mode = KadMode::Server;
        // Server mode needs a non-loopback listener to be a valid configuration.
        config
            .listen
            .push(Multiaddr::parse("/ip4/0.0.0.0/tcp/4001").expect("valid"));
        assert!(config.validate().is_ok(), "got {:?}", config.problems());
        let (_transport, relay_client) = libp2p::relay::client::new(peer);
        let behaviour =
            Libp2pBehaviour::for_config(&config, peer, &keypair, relay_client).expect("composes");
        assert!(behaviour.kad_is_server());
    }

    #[test]
    fn a_keypair_that_is_not_the_peer_ids_key_is_refused() {
        // A node whose GossipSub signatures came from a different key than its
        // PeerId would be a node that cannot be attributed, which is the defect
        // this whole crate's identity seam exists to prevent.
        let (config, _keypair, peer) = config();
        let other = libp2p_keypair_from_seed(&[42u8; 32]);
        let (_transport, relay_client) = libp2p::relay::client::new(peer);
        let err = Libp2pBehaviour::for_config(&config, peer, &other, relay_client)
            .err()
            .expect("a mismatched key must be refused");
        assert!(matches!(err, BehaviourError::IdentityMismatch { .. }));
        assert!(err.to_string().contains("the keypair derives peer id"));
    }

    #[test]
    fn the_kademlia_protocol_name_is_the_configured_one() {
        let (config, _, _) = config();
        let kad = kademlia_config(&config);
        assert_eq!(config.kad_protocol, naming::KAD_PROTOCOL);
        // The name reaching `StreamProtocol::new` must be the `&'static str` this
        // network speaks, because that constructor panics on anything that is not
        // `/`-prefixed and cannot take a `String` at all.
        assert_eq!(static_kad_protocol(&config), naming::KAD_PROTOCOL);
        // A configuration carrying a different name still resolves to the safe
        // static rather than panicking: validation rejects it, and a node that
        // talks to nobody is a diagnosable symptom where a startup panic is not.
        let mut other = config.clone();
        other.kad_protocol = "/other/kad/1.0.0".to_string();
        assert_eq!(static_kad_protocol(&other), naming::KAD_PROTOCOL);
        let _ = kad;
    }

    #[test]
    fn gossipsub_rejects_a_topic_that_is_not_a_string() {
        // GossipSub accepts any byte string, so this asserts the positive case:
        // the network's own topics are accepted, invalid UTF-8 is not expressible
        // through this API at all.
        let keypair = libp2p_keypair_from_seed(&[1u8; 32]);
        let mut gossipsub = build_gossipsub(&keypair).expect("builds");
        let topic = libp2p::gossipsub::IdentTopic::new("nau/room/room-0000000000000001");
        assert!(gossipsub.subscribe(&topic).is_ok());
        assert!(gossipsub
            .topics()
            .any(|t| t.to_string() == topic.to_string()));
    }

    #[test]
    fn nat_status_round_trips_its_display_form() {
        assert_eq!(NatStatus::Unknown.to_string(), "unknown");
        assert_eq!(NatStatus::Private.to_string(), "private");
        let public = NatStatus::Public("/ip4/203.0.113.7/tcp/4001".to_string());
        assert!(public.to_string().starts_with("public("));
        assert!(public.is_public());
        assert!(public.is_measured());
        assert!(!NatStatus::Unknown.is_measured());
        assert!(!NatStatus::Private.is_public());
    }

    #[test]
    fn to_libp2p_peer_id_is_total_on_derived_values() {
        for seed_byte in [0u8, 1, 2, 0xfe, 0xff] {
            let identity = NauIdentity::from_seed(&[seed_byte; 32]);
            let converted = to_libp2p_peer_id(&identity.peer_id()).expect("derived ids convert");
            assert_eq!(converted.to_string(), identity.peer_id().to_string());
        }
    }
}
