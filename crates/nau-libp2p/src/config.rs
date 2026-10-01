//! Validated configuration for the libp2p-backed transport.
//!
//! ## Why validation is a separate step and not a `Result` in the constructor
//!
//! A node's network configuration is assembled from several places — a config
//! file, command-line flags, environment variables, other peers' advertisements —
//! and the interesting failures are combinations, not single fields: a bootstrap
//! list that contains this node, a relay reservation asked for with no relay
//! configured, an empty listen set that makes the node silently unreachable. So
//! [`Libp2pConfig::problems`] returns *every* problem it can find at once, and
//! [`Libp2pConfig::validate`] turns that list into an error. A caller fixing one
//! problem at a time is a caller who runs the program seven times.
//!
//! ## Multiaddrs are parsed here, and cross-checked against libp2p
//!
//! [`Multiaddr`] is this crate's own parser, so validation works with the
//! `libp2p` feature **off** — the default `cargo test -p nau-libp2p` really does
//! exercise these rules. When the feature is on, `Multiaddr::accepted_by_libp2p`
//! asks libp2p's own parser the same question, and the crate's tests assert that
//! the two agree over a corpus of valid and invalid addresses. Without the
//! feature, a mistake in the local parser would not be caught here.
//!
//! ## Upstream defect this closes
//!
//! agent-universe v2.5.6 read `listen_addr` straight into `Swarm::listen_on`
//! with no validation, and its bootstrap list was a `Vec<String>` that it parsed
//! at dial time, so a typo in one entry produced a rejected future per connection
//! attempt and never a startup error. `Multiaddr` is parsed once, up front, and a
//! malformed one is a startup failure.
//! `// upstream v2.5.6 fix: addresses are validated at configuration time, and a
//! self-referential bootstrap peer is refused rather than dialled in a loop.`

use std::fmt;

use nau_net::PeerId;

use crate::identity::{self, IdentityError};
use crate::naming::{NameError, RoomName, KAD_PROTOCOL, MAX_ROOM_NAME_BYTES};

/// Maximum number of listening addresses accepted.
pub const MAX_LISTEN_ADDRS: usize = 32;

/// Maximum number of bootstrap peers accepted.
pub const MAX_BOOTSTRAP_PEERS: usize = 256;

/// Maximum number of relay reservations accepted.
pub const MAX_RELAY_RESERVATIONS: usize = 16;

/// Maximum number of AutoNAT servers accepted.
pub const MAX_AUTONAT_SERVERS: usize = 16;

/// Maximum number of DCUtR peer hints accepted.
pub const MAX_DCUTR_PEERS: usize = 16;

/// The Kademlia operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KadMode {
    /// Accept and answer queries; store records. For infrastructure nodes.
    Server,
    /// Ask, do not answer. The right default for a node behind a NAT or one that
    /// does not want to be a DHT participant.
    #[default]
    Client,
}

impl KadMode {
    /// The wire name, which is also what a config file writes.
    pub fn as_str(self) -> &'static str {
        match self {
            KadMode::Server => "server",
            KadMode::Client => "client",
        }
    }

    /// Parse the wire name, case-insensitively.
    pub fn parse(s: &str) -> Result<Self, ConfigProblem> {
        match s.trim().to_ascii_lowercase().as_str() {
            "server" => Ok(KadMode::Server),
            "client" => Ok(KadMode::Client),
            other => Err(ConfigProblem::UnknownKadMode {
                value: other.to_string(),
            }),
        }
    }
}

impl fmt::Display for KadMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for KadMode {
    type Err = ConfigProblem;
    fn from_str(s: &str) -> Result<Self, ConfigProblem> {
        Self::parse(s)
    }
}

/// One concrete problem with a configuration.
///
/// Separate from [`ConfigError`] so that a caller can print all of them. Every
/// message names the offending value, because "invalid configuration" is not a
/// message anybody can act on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigProblem {
    /// No listening address was configured.
    #[error("no listen address configured: the node would be unreachable and could not accept relay reservations")]
    EmptyListenSet,
    /// More listen addresses than [`MAX_LISTEN_ADDRS`].
    #[error("{got} listen addresses exceeds the limit of {MAX_LISTEN_ADDRS}")]
    TooManyListenAddrs {
        /// How many were supplied.
        got: usize,
    },
    /// More bootstrap peers than [`MAX_BOOTSTRAP_PEERS`].
    #[error("{got} bootstrap peers exceeds the limit of {MAX_BOOTSTRAP_PEERS}")]
    TooManyBootstrapPeers {
        /// How many were supplied.
        got: usize,
    },
    /// A multiaddr did not parse.
    #[error("`{addr}` is not a valid multiaddr: {reason}")]
    MalformedMultiaddr {
        /// The rejected address.
        addr: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A bootstrap entry did not end in a `/p2p/<peer-id>` component, so there is
    /// no peer to dial, only an address.
    #[error("bootstrap peer `{addr}` has no trailing `/p2p/<peer-id>` component, so there is no peer to dial")]
    BootstrapWithoutPeerId {
        /// The rejected entry.
        addr: String,
    },
    /// The local node appears in its own bootstrap list.
    #[error("bootstrap list contains this node itself (`{peer_id}`): dialling self is a loop, not a bootstrap")]
    BootstrapContainsSelf {
        /// The local peer id, as configured.
        peer_id: String,
    },
    /// A room topic failed validation.
    #[error("room `{room}` is not usable as a topic: {reason}")]
    InvalidRoom {
        /// The rejected room.
        room: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The same topic was configured twice.
    #[error("topic `{topic}` is configured more than once")]
    DuplicateTopic {
        /// The duplicated topic.
        topic: String,
    },
    /// Relay reservations were asked for with no relay configured.
    #[error("relay reservations are configured ({count}) but no relay peer is listed; add one to `relay_reservations` or disable relay")]
    RelayWithoutServer {
        /// How many reservations were requested.
        count: usize,
    },
    /// AutoNAT was enabled with no servers configured.
    #[error("AutoNAT is enabled but no AutoNAT server is configured; AutoNAT has nothing to ask, so it would only ever report Unknown")]
    AutonatWithoutServer,
    /// DCUtR was enabled with no way to coordinate.
    #[error("DCUtR is enabled but neither an AutoNAT server nor a DCUtR peer is configured; hole punching needs a third party to coordinate through")]
    DcutrWithoutServer,
    /// Too many relay reservations.
    #[error("{got} relay reservations exceeds the limit of {MAX_RELAY_RESERVATIONS}")]
    TooManyRelayReservations {
        /// How many were supplied.
        got: usize,
    },
    /// Too many AutoNAT servers.
    #[error("{got} AutoNAT servers exceeds the limit of {MAX_AUTONAT_SERVERS}")]
    TooManyAutonatServers {
        /// How many were supplied.
        got: usize,
    },
    /// Too many DCUtR peer hints.
    #[error("{got} DCUtR peers exceeds the limit of {MAX_DCUTR_PEERS}")]
    TooManyDcutrPeers {
        /// How many were supplied.
        got: usize,
    },
    /// The Kademlia protocol name was empty or not `/`-prefixed.
    #[error("Kademlia protocol `{got}` must be non-empty and start with `/`")]
    BadKadProtocol {
        /// The configured protocol name.
        got: String,
    },
    /// The configured Kademlia protocol name is not the one this network speaks.
    ///
    /// A mismatch is not an error the network reports — it is silence — so it is
    /// caught here, at configuration time, instead.
    #[error(
        "Kademlia protocol `{got}` is not `{KAD_PROTOCOL}`; a mismatch is silence, not an error"
    )]
    WrongKadProtocol {
        /// The configured protocol name.
        got: String,
    },
    /// An unknown Kademlia mode string.
    #[error("`{value}` is not a Kademlia mode (expected `server` or `client`)")]
    UnknownKadMode {
        /// The value that was supplied.
        value: String,
    },
    /// The configuration carries no signing key.
    #[error("no Ed25519 seed is configured, so this node has no key to sign with and would advertise an identity it cannot answer as")]
    MissingSeed,
    /// The seed derives a different peer id from the one the configuration claims.
    #[error(
        "the configured seed derives peer id `{derived}`, but the configuration claims `{claimed}`"
    )]
    SeedDoesNotMatchPeerId {
        /// The peer id the configuration claims.
        claimed: String,
        /// The peer id the seed actually derives.
        derived: String,
    },
}

impl From<ConfigProblem> for nau_core::NauError {
    fn from(problem: ConfigProblem) -> Self {
        nau_core::NauError::Validation(problem.to_string())
    }
}

/// The aggregated validation failure.
///
/// Carries every problem, not just the first, and renders them as a list so that
/// one run tells the operator everything that is wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("libp2p configuration is invalid:\n{}", render_problems(.0))]
pub struct ConfigError(
    /// Every problem found, in the order they were discovered.
    pub Vec<ConfigProblem>,
);

impl ConfigError {
    /// The individual problems.
    pub fn problems(&self) -> &[ConfigProblem] {
        &self.0
    }
}

impl From<ConfigError> for nau_core::NauError {
    fn from(err: ConfigError) -> Self {
        nau_core::NauError::Validation(err.to_string())
    }
}

/// Render problems as an indented list.
fn render_problems(problems: &[ConfigProblem]) -> String {
    if problems.is_empty() {
        return "no problems".to_string();
    }
    let mut out = String::new();
    for (index, problem) in problems.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str("  - ");
        out.push_str(&problem.to_string());
    }
    out
}

/// A multiaddr, parsed and validated without libp2p.
///
/// Holds the canonical text form that was supplied. Equality is on that text, so
/// two spellings of the same address compare unequal — which is deliberate: this
/// type exists to catch *spelling* differences between a config file and a peer's
/// advertisement, and normalising them away would hide exactly that bug.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Multiaddr(String);

impl Multiaddr {
    /// Parse and validate a multiaddr string.
    pub fn parse(s: &str) -> Result<Self, ConfigProblem> {
        validate_multiaddr(s)?;
        Ok(Self(s.to_string()))
    }

    /// The address as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The trailing `/p2p/<peer-id>` component, if there is one.
    ///
    /// Returns `None` for an address with no peer component, and an error for one
    /// whose peer component is not a well-formed Ed25519 peer id — the two are
    /// different mistakes and a caller wants to tell them apart.
    pub fn peer_id(&self) -> Result<Option<crate::identity::PeerId>, IdentityError> {
        match trailing_p2p(&self.0) {
            None => Ok(None),
            Some(raw) => match crate::identity::PeerId::parse(raw) {
                Ok(peer) => Ok(Some(peer)),
                // A peer id that is syntactically fine base58btc but not an
                // Ed25519 multihash is still a peer component; report it as
                // present-but-invalid rather than absent.
                Err(e) => Err(e),
            },
        }
    }

    /// Ask libp2p's own parser whether it accepts this address.
    ///
    /// Available only with the `libp2p` feature; the crate's tests assert that it
    /// agrees with [`Multiaddr::parse`] over a corpus.
    #[cfg(feature = "libp2p")]
    pub fn accepted_by_libp2p(&self) -> bool {
        self.0.parse::<libp2p::multiaddr::Multiaddr>().is_ok()
    }

    /// Convert to libp2p's own type.
    #[cfg(feature = "libp2p")]
    pub fn to_libp2p(&self) -> Result<libp2p::multiaddr::Multiaddr, ConfigProblem> {
        self.0.parse::<libp2p::multiaddr::Multiaddr>().map_err(|e| {
            ConfigProblem::MalformedMultiaddr {
                addr: self.0.clone(),
                reason: e.to_string(),
            }
        })
    }
}

impl fmt::Display for Multiaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Multiaddr {
    type Err = ConfigProblem;
    fn from_str(s: &str) -> Result<Self, ConfigProblem> {
        Self::parse(s)
    }
}

/// Protocol codes accepted in a multiaddr, with whether they carry a value.
///
/// This is the subset libp2p actually uses for dialable addresses. Rejecting an
/// unknown code is the point: a typo like `/ip4/1.2.3.4/tpc/9000` must be an
/// error at configuration time, not a dial that never succeeds.
const KNOWN_PROTOCOLS: &[(&str, bool)] = &[
    ("ip4", true),
    ("ip6", true),
    ("dns", true),
    ("dns4", true),
    ("dns6", true),
    ("dnsaddr", true),
    ("tcp", true),
    ("udp", true),
    ("quic", false),
    ("quic-v1", false),
    ("ws", false),
    ("wss", false),
    ("p2p", true),
    ("p2p-circuit", false),
    ("memory", true),
    ("unix", true),
    ("onion", true),
    ("onion3", true),
    ("webrtc-direct", false),
    ("tls", false),
    ("noise", false),
];

/// Validate a multiaddr string.
///
/// The grammar is `/code[/value]…`: an address must start with `/`, every protocol
/// code must be known, and every code that carries a value must have one.
///
/// The first version of this function rejected **every** address, because it
/// treated a protocol's *value* as if it had to be another protocol code — so
/// `/ip4/127.0.0.1` failed on `127.0.0.1`. `a_malformed_multiaddr_is_rejected_at_parse_time`
/// is what caught it; the state machine below tracks a pending value explicitly.
pub fn validate_multiaddr(s: &str) -> Result<(), ConfigProblem> {
    let reject = |reason: &str| ConfigProblem::MalformedMultiaddr {
        addr: s.to_string(),
        reason: reason.to_string(),
    };
    if s.is_empty() {
        return Err(reject("the empty string is not an address"));
    }
    if !s.starts_with('/') {
        return Err(reject("a multiaddr starts with `/`"));
    }
    if s.len() > MAX_MULTIADDR_BYTES {
        return Err(reject("address is longer than the accepted maximum"));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(reject("address contains whitespace or a control character"));
    }
    let mut components = s.split('/');
    // A leading `/` produces an empty first component.
    if components.next() != Some("") {
        return Err(reject("a multiaddr starts with `/`"));
    }
    let mut saw_protocol = false;
    // Set while a protocol that carries a value is waiting for it.
    let mut awaiting_value = false;
    for code in components {
        if code.is_empty() {
            // `/ip4//tcp/9000` and a trailing `/` both land here.
            return Err(reject("empty component: a protocol that takes a value has none, or the address has a trailing separator"));
        }
        if awaiting_value {
            // This component is the value. Values are opaque here: validating
            // that `127.0.0.1` is an IPv4 literal is libp2p's job, and doing it
            // twice would mean two places to disagree.
            awaiting_value = false;
            continue;
        }
        match KNOWN_PROTOCOLS.iter().find(|(name, _)| *name == code) {
            Some((_, takes_value)) => {
                saw_protocol = true;
                awaiting_value = *takes_value;
            }
            None => {
                return Err(reject(&format!("`{code}` is not a known protocol code")));
            }
        }
    }
    if awaiting_value {
        return Err(reject(
            "the address ends with a protocol that takes a value",
        ));
    }
    if !saw_protocol {
        return Err(reject("address contains no protocol code"));
    }
    Ok(())
}

/// Longest accepted multiaddr, in bytes.
pub const MAX_MULTIADDR_BYTES: usize = 1024;

/// The trailing `/p2p/<id>` component of an address, if present.
fn trailing_p2p(addr: &str) -> Option<&str> {
    let index = addr.rfind("/p2p/")?;
    let rest = &addr[index + "/p2p/".len()..];
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(rest)
}

/// The whole configuration for the libp2p transport.
///
/// Construct with [`Libp2pConfig::new`] for the defaults, then set fields, then
/// call [`Libp2pConfig::validate`]. `Default` is deliberately **not** a valid
/// configuration: there is no sensible default listen address, and pretending
/// there is is how a node ends up listening on the wrong interface.
#[derive(Clone, PartialEq, Eq)]
pub struct Libp2pConfig {
    /// Addresses to listen on. Must not be empty.
    pub listen: Vec<Multiaddr>,
    /// Peers to dial and add to the Kademlia routing table.
    pub bootstrap: Vec<Multiaddr>,
    /// Kademlia mode.
    pub kad_mode: KadMode,
    /// Kademlia protocol identifier. Must equal [`KAD_PROTOCOL`].
    pub kad_protocol: String,
    /// Rooms to subscribe to.
    pub rooms: Vec<RoomName>,
    /// Relays to reserve a slot on. Non-empty means "act as a relay client".
    pub relay_reservations: Vec<Multiaddr>,
    /// AutoNAT servers. Non-empty means "measure reachability".
    pub autonat_servers: Vec<Multiaddr>,
    /// Whether to enable DCUtR hole punching.
    pub dcutr: bool,
    /// Peers to attempt hole punching against when DCUtR is enabled and no AutoNAT
    /// server is available.
    pub dcutr_peers: Vec<Multiaddr>,
    /// This node's own peer id, for the self-reference check.
    pub local_peer_id: crate::identity::PeerId,
    /// The Ed25519 seed this node signs with.
    ///
    /// A peer id is a public fingerprint and cannot sign, so a configuration that
    /// carries only a peer id describes an identity the node cannot use. The seed
    /// is therefore part of the configuration, and [`Libp2pConfig::validate`]
    /// refuses a configuration without one: a node with no key would advertise one
    /// identity and answer as another.
    ///
    /// Public because a caller assembling a configuration from a stored secret has
    /// to put it here. It is the one secret in this type; `Debug` is implemented
    /// by hand so it never reaches a log line.
    pub seed: Option<[u8; 32]>,
    /// Room names that failed to parse when they were added.
    ///
    /// Kept so that the mistake is reported by [`Libp2pConfig::problems`] instead
    /// of being silently dropped by a builder that cannot represent it. Public
    /// because a caller assembling a config by hand must be able to populate it,
    /// and because hiding it would make the error appear from nowhere.
    pub rejected_rooms: Vec<String>,
    /// Bootstrap entries that failed to parse when they were added, same reason.
    pub rejected_bootstrap: Vec<String>,
}

impl Libp2pConfig {
    /// A configuration with the given identity, one listen address and no rooms.
    ///
    /// Not yet valid — [`Libp2pConfig::validate`] will still reject it if the
    /// listen address is unusable.
    pub fn new(local: &identity::NauIdentity, listen: Multiaddr) -> Self {
        Self {
            listen: vec![listen],
            bootstrap: Vec::new(),
            kad_mode: KadMode::default(),
            kad_protocol: KAD_PROTOCOL.to_string(),
            rooms: Vec::new(),
            relay_reservations: Vec::new(),
            autonat_servers: Vec::new(),
            dcutr: false,
            dcutr_peers: Vec::new(),
            local_peer_id: local.peer_id(),
            seed: None,
            rejected_rooms: Vec::new(),
            rejected_bootstrap: Vec::new(),
        }
    }

    /// Attach the Ed25519 seed this node signs with.
    ///
    /// Refuses a seed whose derived peer id is not [`Libp2pConfig::local_peer_id`],
    /// because that pairing is the one thing a configuration must not get wrong:
    /// the node would advertise one identity and answer as another.
    pub fn with_seed(mut self, seed: [u8; 32]) -> Result<Self, ConfigProblem> {
        let derived = identity::NauIdentity::from_seed(&seed).peer_id();
        if derived != self.local_peer_id {
            return Err(ConfigProblem::SeedDoesNotMatchPeerId {
                claimed: self.local_peer_id.to_string(),
                derived: derived.to_string(),
            });
        }
        self.seed = Some(seed);
        Ok(self)
    }

    /// Add a room to subscribe to.
    ///
    /// Returns the configuration unchanged when the room name is invalid, so the
    /// failure surfaces from `problems`/`validate` as
    /// [`ConfigProblem::InvalidRoom`] rather than being dropped silently.
    pub fn with_room(mut self, room: &str) -> Self {
        if let Ok(name) = RoomName::parse(room) {
            self.rooms.push(name);
        } else {
            // Record the rejection so validation reports it. A room that failed
            // to parse cannot become a `RoomName`, so it is kept in a side list.
            self.rejected_rooms.push(room.to_string());
        }
        self
    }

    /// Add a bootstrap peer, parsing the address.
    pub fn with_bootstrap(mut self, addr: &str) -> Self {
        match Multiaddr::parse(addr) {
            Ok(parsed) => self.bootstrap.push(parsed),
            Err(_) => self.rejected_bootstrap.push(addr.to_string()),
        }
        self
    }

    /// Add a relay to reserve on, parsing the address.
    pub fn with_relay(mut self, addr: &str) -> Self {
        if let Ok(parsed) = Multiaddr::parse(addr) {
            self.relay_reservations.push(parsed);
        }
        self
    }

    /// Add an AutoNAT server, parsing the address.
    pub fn with_autonat_server(mut self, addr: &str) -> Self {
        if let Ok(parsed) = Multiaddr::parse(addr) {
            self.autonat_servers.push(parsed);
        }
        self
    }

    /// Enable DCUtR.
    pub fn with_dcutr(mut self) -> Self {
        self.dcutr = true;
        self
    }

    /// Every problem with this configuration.
    ///
    /// Runs all checks rather than stopping at the first, so one run reports
    /// everything. Never panics, and never dials or binds: this is pure.
    pub fn problems(&self) -> Vec<ConfigProblem> {
        let mut problems = Vec::new();

        // 1. The listen set.
        if self.listen.is_empty() {
            problems.push(ConfigProblem::EmptyListenSet);
        } else if self.listen.len() > MAX_LISTEN_ADDRS {
            problems.push(ConfigProblem::TooManyListenAddrs {
                got: self.listen.len(),
            });
        }

        // 2. Bootstrap peers: count, missing peer component, self-reference.
        if self.bootstrap.len() > MAX_BOOTSTRAP_PEERS {
            problems.push(ConfigProblem::TooManyBootstrapPeers {
                got: self.bootstrap.len(),
            });
        }
        for addr in &self.bootstrap {
            match addr.peer_id() {
                Ok(None) => problems.push(ConfigProblem::BootstrapWithoutPeerId {
                    addr: addr.to_string(),
                }),
                Ok(Some(peer)) if peer == self.local_peer_id => {
                    problems.push(ConfigProblem::BootstrapContainsSelf {
                        peer_id: peer.to_string(),
                    });
                }
                Ok(Some(_)) => {}
                Err(e) => problems.push(ConfigProblem::MalformedMultiaddr {
                    addr: addr.to_string(),
                    reason: e.to_string(),
                }),
            }
        }
        // Addresses that failed to parse at the builder are reports too.
        for addr in &self.rejected_bootstrap {
            problems.push(ConfigProblem::MalformedMultiaddr {
                addr: addr.clone(),
                reason: "rejected when it was added to the configuration".to_string(),
            });
        }

        // 3. Rooms.
        for room in &self.rejected_rooms {
            let reason = RoomName::parse(room)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            problems.push(ConfigProblem::InvalidRoom {
                room: room.clone(),
                reason,
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for room in &self.rooms {
            let topic = room.topic();
            if !seen.insert(topic.clone()) {
                problems.push(ConfigProblem::DuplicateTopic { topic });
            }
        }

        // 4. Kademlia protocol name.
        if !self.kad_protocol.starts_with('/') || self.kad_protocol.len() < 2 {
            problems.push(ConfigProblem::BadKadProtocol {
                got: self.kad_protocol.clone(),
            });
        } else if self.kad_protocol != KAD_PROTOCOL {
            problems.push(ConfigProblem::WrongKadProtocol {
                got: self.kad_protocol.clone(),
            });
        }

        // 5. Kademlia server mode. There is deliberately **no** check that a server
        // has a non-loopback listener. An earlier version added one and it was
        // wrong: `KadMode::Server` is what makes a node answer queries and accept
        // records, and it is required for a two-node DHT on loopback — which is
        // exactly how the crate's own tests, and any two processes on one host,
        // need to work. Refusing it would have made the mode unusable in the only
        // setting where it can be tested, and it is a reachability judgement that
        // AutoNAT exists to make, not a configuration error.

        // 6. The signing key.
        match self.seed {
            None => problems.push(ConfigProblem::MissingSeed),
            Some(seed) => {
                let derived = identity::NauIdentity::from_seed(&seed).peer_id();
                if derived != self.local_peer_id {
                    problems.push(ConfigProblem::SeedDoesNotMatchPeerId {
                        claimed: self.local_peer_id.to_string(),
                        derived: derived.to_string(),
                    });
                }
            }
        }

        // 7. Relay, AutoNAT and DCUtR all need a third party.
        if self.relay_reservations.len() > MAX_RELAY_RESERVATIONS {
            problems.push(ConfigProblem::TooManyRelayReservations {
                got: self.relay_reservations.len(),
            });
        }
        if !self.relay_reservations.is_empty() {
            // A reservation target with no `/p2p/` component names a host but not
            // a peer, and a relay reservation is addressed to a peer.
            for addr in &self.relay_reservations {
                if addr.peer_id().ok().flatten().is_none() {
                    problems.push(ConfigProblem::RelayWithoutServer {
                        count: self.relay_reservations.len(),
                    });
                    break;
                }
            }
        }
        if self.autonat_servers.len() > MAX_AUTONAT_SERVERS {
            problems.push(ConfigProblem::TooManyAutonatServers {
                got: self.autonat_servers.len(),
            });
        }
        if self.dcutr_peers.len() > MAX_DCUTR_PEERS {
            problems.push(ConfigProblem::TooManyDcutrPeers {
                got: self.dcutr_peers.len(),
            });
        }
        if self.dcutr && self.autonat_servers.is_empty() && self.dcutr_peers.is_empty() {
            problems.push(ConfigProblem::DcutrWithoutServer);
        }

        problems
    }

    /// Validate, returning every problem or `Ok(())`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let problems = self.problems();
        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError(problems))
        }
    }

    /// Whether AutoNAT is enabled (a server was configured).
    pub fn autonat_enabled(&self) -> bool {
        !self.autonat_servers.is_empty()
    }

    /// Whether a relay reservation was requested.
    pub fn relay_enabled(&self) -> bool {
        !self.relay_reservations.is_empty()
    }

    /// Whether DCUtR is enabled *and* has something to coordinate through.
    ///
    /// `dcutr` alone is not enough: without AutoNAT or an explicit peer there is
    /// nothing to ask, which is why
    /// [`ConfigProblem::DcutrWithoutServer`] exists. This predicate therefore
    /// agrees with validation rather than with the raw flag.
    pub fn dcutr_enabled(&self) -> bool {
        self.dcutr && (!self.autonat_servers.is_empty() || !self.dcutr_peers.is_empty())
    }

    /// The topics this node subscribes to.
    pub fn topics(&self) -> Vec<String> {
        self.rooms.iter().map(RoomName::topic).collect()
    }

    /// The peer id a bootstrap entry points at.
    pub fn bootstrap_peer_id(
        addr: &Multiaddr,
    ) -> Result<Option<crate::identity::PeerId>, IdentityError> {
        addr.peer_id()
    }

    /// A one-line summary for logs, containing no addresses beyond the first.
    pub fn describe(&self) -> String {
        format!(
            "listen={} bootstrap={} rooms={} kad={} relay={} autonat={} dcutr={}",
            self.listen.len(),
            self.bootstrap.len(),
            self.rooms.len(),
            self.kad_mode,
            self.relay_reservations.len(),
            self.autonat_servers.len(),
            self.dcutr_enabled(),
        )
    }
    /// The longest accepted room name, re-exported for callers building configs.
    pub const fn max_room_name_bytes() -> usize {
        MAX_ROOM_NAME_BYTES
    }

    /// The listen addresses that are not loopback, which is what a node must have
    /// to be dialable by anyone else.
    pub fn non_loopback_listen(&self) -> Vec<&Multiaddr> {
        self.listen
            .iter()
            .filter(|a| !is_loopback_or_memory(a.as_str()))
            .collect()
    }

    /// The local peer id as a string, for the `/p2p/` component of a dial address.
    pub fn local_peer_id_string(&self) -> String {
        self.local_peer_id.to_string()
    }

    /// Build the dialable address for this node on loopback, for tests and for a
    /// node that only ever talks to processes on the same host.
    pub fn loopback_dial_addr(&self, port: u16) -> String {
        format!(
            "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
            self.local_peer_id_string()
        )
    }

    /// The `nau_net::PeerId` label for this node's libp2p id, for code that keys
    /// on the existing transport port's identifier type.
    pub fn local_peer_id_label(&self) -> Result<PeerId, NameError> {
        let label = format!("libp2p:{}", self.local_peer_id);
        PeerId::parse(&label).map_err(|e| NameError::NotAPeerId {
            value: label,
            reason: e.to_string(),
        })
    }
}

impl fmt::Debug for Libp2pConfig {
    /// Render the configuration without the secret.
    ///
    /// Written by hand rather than derived: a derived `Debug` would print the
    /// Ed25519 seed, and a configuration ends up in log lines and panic messages.
    /// The seed is rendered as presence only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Libp2pConfig")
            .field("listen", &self.listen)
            .field("bootstrap", &self.bootstrap)
            .field("kad_mode", &self.kad_mode)
            .field("kad_protocol", &self.kad_protocol)
            .field("rooms", &self.rooms)
            .field("relay_reservations", &self.relay_reservations)
            .field("autonat_servers", &self.autonat_servers)
            .field("dcutr", &self.dcutr)
            .field("dcutr_peers", &self.dcutr_peers)
            .field("local_peer_id", &self.local_peer_id)
            .field(
                "seed",
                &match self.seed {
                    Some(_) => "Some(<redacted 32-byte Ed25519 seed>)",
                    None => "None",
                },
            )
            .field("rejected_rooms", &self.rejected_rooms)
            .field("rejected_bootstrap", &self.rejected_bootstrap)
            .finish()
    }
}

/// Whether an address refers to this host only.
pub fn is_loopback_or_memory(addr: &str) -> bool {
    addr.starts_with("/ip4/127.")
        || addr.starts_with("/ip6/::1")
        || addr.contains("/ip4/127.0.0.1/")
        || addr.starts_with("/memory/")
        || addr.starts_with("/unix/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed seed every conformance vector in every language uses.
    const SEED: [u8; 32] = [1u8; 32];

    fn identity() -> identity::NauIdentity {
        identity::NauIdentity::from_seed(&SEED)
    }

    /// A minimal valid configuration: one loopback listener, no rooms, and the
    /// signing key, without which nothing else can be valid.
    fn base() -> Libp2pConfig {
        Libp2pConfig::new(
            &identity(),
            Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid listen addr"),
        )
        .with_seed(SEED)
        .expect("the SEED identity matches its own peer id")
    }

    #[test]
    fn a_configuration_without_a_signing_key_is_refused() {
        // A peer id cannot sign, so a configuration that carries only one
        // describes an identity the node cannot use.
        let keyless = Libp2pConfig::new(
            &identity(),
            Multiaddr::parse("/ip4/127.0.0.1/tcp/0").expect("valid"),
        );
        assert!(keyless.seed.is_none());
        let problems = keyless.problems();
        assert!(
            problems.contains(&ConfigProblem::MissingSeed),
            "got {problems:?}"
        );
        assert!(keyless.validate().is_err());

        // A seed belonging to a different key is refused at the builder, because
        // the node would advertise one identity and answer as another.
        let other = [9u8; 32];
        let err = base()
            .with_seed(other)
            .expect_err("a mismatched seed must be refused");
        assert!(matches!(err, ConfigProblem::SeedDoesNotMatchPeerId { .. }));
        assert!(err.to_string().contains("the configured seed derives"));

        // A matching seed is accepted and the summary is unchanged.
        let with_seed = base();
        assert_eq!(with_seed.seed, Some(SEED));
        assert!(with_seed.validate().is_ok());
    }

    #[test]
    fn debug_output_never_contains_the_seed() {
        let config = base();
        let rendered = format!("{config:?}");
        assert!(rendered.contains("redacted"), "got {rendered}");
        // The seed is 32 bytes of 0x01; its hex form must not appear.
        assert!(!rendered.contains(&hex::encode(SEED)));
        assert!(!rendered.contains("1, 1, 1,"));
    }

    /// Another node's `/p2p/`-terminated address, for bootstrap entries.
    fn other_peer_addr() -> String {
        let other = identity::NauIdentity::from_seed(&[9u8; 32]);
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", other.peer_id())
    }

    #[test]
    fn a_minimal_configuration_validates() {
        let config = base();
        assert_eq!(config.problems(), Vec::new());
        assert!(config.validate().is_ok());
        assert!(!config.relay_enabled());
        assert!(!config.autonat_enabled());
        assert!(!config.dcutr_enabled());
        assert!(config.describe().contains("kad=client"));
    }

    #[test]
    fn an_empty_listen_set_is_rejected() {
        let mut config = base();
        config.listen.clear();
        let problems = config.problems();
        assert_eq!(problems, vec![ConfigProblem::EmptyListenSet]);
        let err = config.validate().expect_err("must fail");
        assert!(err.to_string().contains("no listen address"));
        assert_eq!(err.problems().len(), 1);
    }

    #[test]
    fn a_bootstrap_peer_that_is_self_is_rejected() {
        let me = identity();
        let mut config = base();
        // The distinctive mistake: this node's own /p2p/ address in its own
        // bootstrap list. Dialling it is a loop, not a bootstrap.
        config.bootstrap.push(
            Multiaddr::parse(&format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", me.peer_id()))
                .expect("valid"),
        );
        let problems = config.problems();
        assert_eq!(problems.len(), 1, "got {problems:?}");
        assert!(matches!(
            problems[0],
            ConfigProblem::BootstrapContainsSelf { .. }
        ));
        assert!(config.validate().is_err());

        // A *different* peer at the same address is fine.
        config.bootstrap.clear();
        config
            .bootstrap
            .push(Multiaddr::parse(&other_peer_addr()).expect("valid"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_bootstrap_entry_without_a_peer_id_is_rejected() {
        let mut config = base();
        config
            .bootstrap
            .push(Multiaddr::parse("/ip4/127.0.0.1/tcp/4001").expect("a valid address"));
        let problems = config.problems();
        assert!(
            matches!(problems[0], ConfigProblem::BootstrapWithoutPeerId { .. }),
            "got {problems:?}"
        );
    }

    #[test]
    fn a_malformed_multiaddr_is_rejected_at_parse_time() {
        let good = [
            "/ip4/127.0.0.1/tcp/9000",
            "/ip4/0.0.0.0/tcp/0",
            "/ip6/::1/tcp/9000",
            "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
            "/dnsaddr/bootstrap.example.com",
            "/ip4/127.0.0.1/udp/9000/quic-v1",
            "/ip4/127.0.0.1/tcp/9000/ws",
            "/p2p-circuit",
            "/ip4/127.0.0.1/tcp/9000/p2p-circuit",
            "/memory/1234",
        ];
        for addr in good {
            assert!(
                Multiaddr::parse(addr).is_ok(),
                "{addr} should be accepted by the local parser"
            );
        }
        let bad = [
            "",
            "127.0.0.1:9000",
            "/ip4",                      // missing value
            "/tpc/9000",                 // typo'd protocol code
            "/ip4/127.0.0.1/tpc/9000",   // typo'd protocol code
            "/ip4//tcp/9000",            // empty component
            "/ip4/127.0.0.1/tcp/",       // trailing separator with no value
            "/ip4/127.0.0.1/tcp/9000/",  // ditto
            "/ip4/127.0.0.1/tcp/9000\n", // control character
            "/ip4/ 127.0.0.1/tcp/9000",  // whitespace
            "/",                         // no protocol at all
        ];
        for addr in bad {
            assert!(
                Multiaddr::parse(addr).is_err(),
                "{addr:?} should be refused by the local parser"
            );
        }
    }

    #[test]
    fn relay_autonat_and_dcutr_are_refused_without_a_server() {
        // DCUtR with nothing to coordinate through.
        let problem = base().with_dcutr().problems();
        assert_eq!(problem, vec![ConfigProblem::DcutrWithoutServer]);

        // DCUtR with a peer hint is accepted.
        let mut ok = base().with_dcutr();
        ok.dcutr_peers
            .push(Multiaddr::parse(&other_peer_addr()).expect("valid"));
        assert!(ok.problems().is_empty(), "got {:?}", ok.problems());
        assert!(ok.dcutr_enabled());

        // DCUtR with an AutoNAT server is accepted too.
        let ok2 = base().with_dcutr().with_autonat_server(&other_peer_addr());
        assert!(ok2.problems().is_empty(), "got {:?}", ok2.problems());
        assert!(ok2.autonat_enabled());

        // A relay reservation naming no peer is refused.
        let mut relay = base();
        relay
            .relay_reservations
            .push(Multiaddr::parse("/ip4/127.0.0.1/tcp/4001").expect("valid address"));
        assert!(matches!(
            relay.problems()[0],
            ConfigProblem::RelayWithoutServer { .. }
        ));

        // A relay reservation naming a peer is accepted.
        let mut relay_ok = base();
        relay_ok
            .relay_reservations
            .push(Multiaddr::parse(&other_peer_addr()).expect("valid"));
        assert!(
            relay_ok.problems().is_empty(),
            "got {:?}",
            relay_ok.problems()
        );
        assert!(relay_ok.relay_enabled());
    }

    #[test]
    fn every_problem_is_reported_at_once_not_one_per_run() {
        // A caller fixing one thing at a time runs the program once per mistake.
        let mut config = base();
        config.listen.clear();
        config
            .bootstrap
            .push(Multiaddr::parse("/ip4/127.0.0.1/tcp/1").expect("valid"));
        config.bootstrap.push(
            Multiaddr::parse(&format!(
                "/ip4/127.0.0.1/tcp/2/p2p/{}",
                identity().peer_id()
            ))
            .expect("valid"),
        );
        config.kad_protocol = "/other/kad/1.0.0".to_string();
        // `with_dcutr` is a consuming builder method, so the result is rebound
        // rather than discarded.
        config = config.with_dcutr();
        let problems = config.problems();
        assert!(problems.len() >= 5, "got {problems:?}");
        assert!(problems
            .iter()
            .any(|p| matches!(p, ConfigProblem::EmptyListenSet)));
        assert!(problems
            .iter()
            .any(|p| matches!(p, ConfigProblem::BootstrapWithoutPeerId { .. })));
        assert!(problems
            .iter()
            .any(|p| matches!(p, ConfigProblem::BootstrapContainsSelf { .. })));
        assert!(problems
            .iter()
            .any(|p| matches!(p, ConfigProblem::WrongKadProtocol { .. })));
        assert!(problems
            .iter()
            .any(|p| matches!(p, ConfigProblem::DcutrWithoutServer)));
        // The rendered error names every problem, so one log line is enough to act
        // on. Each problem's own message is asserted to be present rather than
        // counting separators, because a message may itself span lines.
        let rendered = config.validate().expect_err("invalid").to_string();
        assert_eq!(problems.len(), 5, "got {problems:?}");
        assert!(rendered.starts_with("libp2p configuration is invalid:"));
        for problem in &problems {
            assert!(
                rendered.contains(&problem.to_string()),
                "the rendering omits {problem:?}:\n{rendered}"
            );
        }
        assert_eq!(rendered.matches("  - ").count(), problems.len());
        assert!(rendered.contains("no listen address"));
    }

    #[test]
    fn the_kademlia_protocol_name_is_checked() {
        let mut config = base();
        config.kad_protocol = String::new();
        assert!(matches!(
            config.problems()[0],
            ConfigProblem::BadKadProtocol { .. }
        ));
        config.kad_protocol = "nau/kad/1.0.0".to_string();
        assert!(matches!(
            config.problems()[0],
            ConfigProblem::BadKadProtocol { .. }
        ));
        config.kad_protocol = "/nau/kad/2.0.0".to_string();
        assert!(matches!(
            config.problems()[0],
            ConfigProblem::WrongKadProtocol { .. }
        ));
        config.kad_protocol = KAD_PROTOCOL.to_string();
        assert!(config.problems().is_empty());
        // The mismatch message says why it matters.
        config.kad_protocol = "/nau/kad/2.0.0".to_string();
        assert!(config
            .validate()
            .expect_err("mismatch")
            .to_string()
            .contains("silence, not an error"));
    }

    #[test]
    fn kademlia_server_mode_is_allowed_on_loopback() {
        // An earlier version refused this, on the grounds that a loopback-only
        // server advertises records it cannot serve. That conflated reachability
        // (AutoNAT's job) with configuration, and it made server mode unusable in
        // the only setting where a two-node DHT can be tested: one host. Both modes
        // are therefore valid on loopback, and both are valid with a wildcard
        // listener.
        let mut config = base();
        config.kad_mode = KadMode::Server;
        assert_eq!(config.problems(), Vec::new(), "got {:?}", config.problems());
        assert!(config.non_loopback_listen().is_empty());

        config
            .listen
            .push(Multiaddr::parse("/ip4/0.0.0.0/tcp/4001").expect("valid"));
        assert_eq!(config.problems(), Vec::new(), "got {:?}", config.problems());
        assert_eq!(config.non_loopback_listen().len(), 1);

        config.kad_mode = KadMode::Client;
        assert_eq!(config.problems(), Vec::new());
    }

    #[test]
    fn kad_mode_parses_its_wire_names() {
        assert_eq!(KadMode::parse("server").expect("server"), KadMode::Server);
        assert_eq!(KadMode::parse("SERVER").expect("case"), KadMode::Server);
        assert_eq!(KadMode::parse(" Client ").expect("trim"), KadMode::Client);
        assert!(matches!(
            KadMode::parse("full").expect_err("unknown"),
            ConfigProblem::UnknownKadMode { .. }
        ));
        assert_eq!(KadMode::default(), KadMode::Client);
        assert_eq!(KadMode::Server.to_string(), "server");
        assert_eq!(
            "client".parse::<KadMode>().expect("FromStr"),
            KadMode::Client
        );
    }

    #[test]
    fn rooms_topic_and_duplicates() {
        let config = base()
            .with_room("room-0000000000000001")
            .with_room("room-0000000000000002");
        assert_eq!(config.rooms.len(), 2);
        assert_eq!(
            config.topics(),
            vec![
                "nau/room/room-0000000000000001".to_string(),
                "nau/room/room-0000000000000002".to_string()
            ]
        );
        assert!(config.problems().is_empty());

        // A duplicate room is one topic configured twice.
        let dup = config.clone().with_room("room-0000000000000001");
        let problems = dup.problems();
        assert!(
            matches!(problems[0], ConfigProblem::DuplicateTopic { .. }),
            "got {problems:?}"
        );

        // An invalid room is reported rather than dropped.
        let bad = base().with_room("room-a/b");
        let problems = bad.problems();
        assert!(
            matches!(problems[0], ConfigProblem::InvalidRoom { .. }),
            "got {problems:?}"
        );
        assert!(bad.rooms.is_empty(), "the invalid room was not admitted");
        assert!(bad.validate().is_err());
    }

    #[test]
    fn limits_are_enforced() {
        let mut config = base();
        config.listen = std::iter::repeat(Multiaddr::parse("/ip4/127.0.0.1/tcp/1").expect("valid"))
            .take(MAX_LISTEN_ADDRS + 1)
            .collect();
        assert!(matches!(
            config.problems()[0],
            ConfigProblem::TooManyListenAddrs { .. }
        ));

        let mut relays = base();
        relays.relay_reservations =
            std::iter::repeat(Multiaddr::parse(&other_peer_addr()).expect("valid"))
                .take(MAX_RELAY_RESERVATIONS + 1)
                .collect();
        assert!(matches!(
            relays.problems()[0],
            ConfigProblem::TooManyRelayReservations { .. }
        ));

        let mut autonat = base();
        autonat.autonat_servers =
            std::iter::repeat(Multiaddr::parse(&other_peer_addr()).expect("valid"))
                .take(MAX_AUTONAT_SERVERS + 1)
                .collect();
        assert!(matches!(
            autonat.problems()[0],
            ConfigProblem::TooManyAutonatServers { .. }
        ));

        let mut dcutr = base().with_dcutr();
        dcutr.dcutr_peers = std::iter::repeat(Multiaddr::parse(&other_peer_addr()).expect("valid"))
            .take(MAX_DCUTR_PEERS + 1)
            .collect();
        assert!(matches!(
            dcutr.problems()[0],
            ConfigProblem::TooManyDcutrPeers { .. }
        ));
    }

    #[test]
    fn builder_methods_record_what_they_could_not_parse() {
        let config = base()
            .with_bootstrap("not-an-address")
            .with_bootstrap(&other_peer_addr())
            .with_room("x")
            .with_room("room-0000000000000003");
        assert_eq!(config.bootstrap.len(), 1, "only the valid one is stored");
        assert_eq!(config.rejected_bootstrap.len(), 1);
        assert_eq!(config.rooms.len(), 1);
        assert_eq!(config.rejected_rooms.len(), 1);
        let problems = config.problems();
        assert!(problems
            .iter()
            .any(|p| matches!(p, ConfigProblem::MalformedMultiaddr { .. })));
        assert!(problems
            .iter()
            .any(|p| matches!(p, ConfigProblem::InvalidRoom { .. })));
    }

    #[test]
    fn peer_id_extraction_and_self_detection_are_consistent() {
        let addr = Multiaddr::parse(&other_peer_addr()).expect("valid");
        let peer = addr.peer_id().expect("valid id").expect("present");
        assert_eq!(peer, identity::NauIdentity::from_seed(&[9u8; 32]).peer_id());
        // An address with no peer component reports absence, not error.
        let bare = Multiaddr::parse("/ip4/127.0.0.1/tcp/4001").expect("valid");
        assert!(bare.peer_id().expect("no error").is_none());
        // An address whose peer component is malformed reports an error.
        let odd = Multiaddr::parse("/ip4/127.0.0.1/tcp/4001/p2p/!!!").expect("syntactically fine");
        assert!(odd.peer_id().is_err());
    }

    #[test]
    fn loopback_detection_is_conservative() {
        for loopback in [
            "/ip4/127.0.0.1/tcp/9000",
            "/ip4/127.5.5.5/tcp/9000",
            "/ip6/::1/tcp/9000",
            "/memory/1",
            "/unix/tmp/sock",
        ] {
            assert!(is_loopback_or_memory(loopback), "{loopback}");
        }
        for public in [
            "/ip4/0.0.0.0/tcp/9000",
            "/ip4/8.8.8.8/tcp/9000",
            "/ip6/2001:db8::1/tcp/1",
        ] {
            assert!(!is_loopback_or_memory(public), "{public}");
        }
    }

    #[test]
    fn the_local_peer_label_is_parseable_by_the_existing_port() {
        // The adapter has to report a nau_net::PeerId; the label must therefore be
        // inside that type's charset.
        let config = base();
        let label = config.local_peer_id_label().expect("valid label");
        assert!(label.as_str().starts_with("libp2p:"));
        assert!(label.as_str().contains(&config.local_peer_id_string()));
        // The dial address for this node carries the same id.
        let dial = config.loopback_dial_addr(4001);
        assert!(dial.ends_with(&config.local_peer_id_string()));
        assert!(Multiaddr::parse(&dial).is_ok());
    }

    #[test]
    fn the_default_kad_protocol_is_the_networks_protocol() {
        assert_eq!(base().kad_protocol, KAD_PROTOCOL);
        assert_eq!(Libp2pConfig::max_room_name_bytes(), MAX_ROOM_NAME_BYTES);
    }
}
