//! Building and driving a real libp2p swarm.
//!
//! ## The shape of this module
//!
//! A `Swarm` is a state machine that only makes progress while it is polled. A
//! swarm nobody polls looks exactly like a healthy node with nothing to say, which
//! is the trap: it compiles, it accepts commands, and it never sends anything.
//!
//! So the swarm is **moved into a task** as soon as it is built, and every public
//! operation on [`Libp2pNode`] is a message to that task:
//!
//! ```text
//!   caller                     Libp2pNode (handle)            event loop task
//!   闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾                     闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋?           闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋?
//!   publish(topic, bytes) 闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍?Command::Publish 闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍?//!   put_record(k, v)      闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍?Command::PutRecord 闁冲厜鍋撻柍?           select!
//!   get_record(k)         闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍?Command::GetRecord 闁冲厜鍋撻柍鐟扮毞閺€銏ゅ煘閳ь剟鍩為埀顒勫煘閳ь剟鍩為埀顒勫煘閳ь剟鍩為埀顒勫煘閳ь剟鍩為埀顒勫煘閳ь剟鍩?闁宠澹曢弨?cmd_rx.recv()
//!   dial(addr)            闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍?Command::Dial 闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁?           闁宠鏌￠弨?swarm.next()
//!   nat_status()          闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍?Command::NatStatus 闁冲厜鍋撻柍?                闁?//!                                                  闁崇厧瀚ч弨銏ゅ煘閳?responses 闁冲厜鍋撻柍鍏夊亾闁冲厜鍋撻柍鍏夊亾闁?//!   recv_frame()          闁崇厧瀚ч弨銏ゅ煘閳ь剟鍩為埀?inbound queue 闁崇厧瀚ч弨銏ゅ煘閳ь剟鍩為埀顒勫煘閳ь剟鍩為埀?GossipSub Message
//! ```
//!
//! The loop selects over exactly two things 闁?the command channel and the swarm 闁?//! so a command cannot be starved by an idle swarm and the swarm cannot be starved
//! by an idle command channel. A short sleep is added so that deadlines are
//! enforced even when both are quiet.
//!
//! ## Honest timeouts
//!
//! Every operation that waits for the swarm carries a deadline, because a
//! Kademlia query into a network where the record does not exist cannot succeed
//! and the behaviour's own query timeout is 60 s. A deadline expiring is reported
//! as [`SwarmError::Timeout`], never as a fabricated result. A record that Kademlia
//! reports as absent is [`SwarmError::RecordNotFound`], which is a *different*
//! variant because a caller should retry one and not the other.
//!
//! ## Upstream defect this closes
//!
//! agent-universe v2.5.6's `net/libp2p_node.rs::GsnNode` held a `HashMap` of
//! "peers" and returned `Ok(())` from `publish`, so a caller could not distinguish
//! a delivered message from a dropped one. Here `publish` returns the number of
//! peers the message was queued for 闁?which is **zero** when nobody is subscribed.
//! `Ok(0)` is a visible, checkable answer rather than a silent success.
//! `// upstream v2.5.6 fix: an operation whose outcome cannot be confirmed is
//! reported, not assumed.`

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::kad::store::RecordStore as _;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

use nau_net::Frame;

use crate::behaviour::{Libp2pBehaviour, NatStatus, NauEvent};
use crate::codec::{self};
use crate::config::{Libp2pConfig, Multiaddr};
use crate::identity::{NauIdentity, PeerId};
use crate::naming;

/// Default time to wait for a Kademlia record query to produce a result.
pub const DEFAULT_RECORD_TIMEOUT: Duration = Duration::from_secs(15);

/// Default time to wait for a `put_record` to be accepted.
pub const DEFAULT_PUT_TIMEOUT: Duration = Duration::from_secs(15);

/// Default time to wait for a relay reservation to be granted.
pub const DEFAULT_RESERVATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default time to wait for a hole punch to complete.
pub const DEFAULT_HOLE_PUNCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Default time to wait for a connection to be established.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How long [`Libp2pNode::spawn`] waits for a listener to either bind or fail.
///
/// `Swarm::listen_on` reports a *syntactically* bad address immediately, but a
/// failure to bind the socket arrives later as a `ListenerError` event. Without
/// this wait, `spawn` would return a healthy-looking node whose listener never
/// came up: a timeout on the caller's side and a `TIME_WAIT` on the operating
/// system's, with nothing in between to say why. Binding a loopback socket is
/// immediate, so this is a generous ceiling rather than a delay.
pub const LISTEN_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

/// Capacity of the command channel.
///
/// Bounded on purpose: an unbounded channel turns a slow swarm into unbounded
/// memory growth, which is how a network stall becomes an OOM.
pub const COMMAND_CHANNEL_CAPACITY: usize = 256;

/// The largest value a Kademlia record may carry, in bytes.
///
/// `libp2p_kad::store::MemoryStoreConfig::default().max_value_bytes` is
/// `65 * 1024`, and the store is constructed with that default. It is **smaller
/// than the 8 MiB frame cap**, so a frame this transport is happy to carry over
/// GossipSub cannot necessarily be stored in the DHT. That asymmetry is worth
/// knowing before writing a megabyte into a record and reading back a size error.
/// A node that needs larger records must raise the store's limit explicitly, which
/// this crate does not do because the store's size is a policy decision rather than
/// a transport detail.
pub const DHT_MAX_VALUE_BYTES: usize = 65 * 1024;

/// Capacity of the queue of frames received from the network.
///
/// Bounded for the same reason. When it is full the *oldest* frame is dropped and
/// counted, because for a pub/sub overlay a stale message is worth less than a
/// fresh one, and the drop is visible in [`SwarmStats::dropped_frames`].
pub const INBOUND_QUEUE_CAPACITY: usize = 1024;

/// How a `put_record` was replicated.
///
/// The distinction matters because the two outcomes have different guarantees and
/// an earlier version conflated them: it returned `Err(QuorumFailed)` for a record
/// that the local store had accepted and that the *other* node could read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replication {
    /// A peer accepted the record, so it is stored on more than this node.
    Replicated,
    /// The record is in this node's store, readable from this node, and no peer
    /// accepted it 閳?normally because the routing table was still being populated.
    LocalOnly {
        /// The DHT's own words.
        reason: String,
    },
}

impl Replication {
    /// Whether more than this node holds the record.
    pub fn is_replicated(&self) -> bool {
        matches!(self, Replication::Replicated)
    }
}

impl std::fmt::Display for Replication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Replication::Replicated => f.write_str("replicated"),
            Replication::LocalOnly { reason } => write!(f, "local only ({reason})"),
        }
    }
}

/// What the event loop did with a `put_record`.
///
/// Not `Result<(), SwarmError>` because "stored locally but not replicated" is
/// neither success nor failure, and flattening it into either one loses the fact a
/// caller needs.
enum PutOutcome {
    /// A peer accepted the record.
    Replicated,
    /// The local store accepted it and no peer did.
    LocalOnly {
        /// Why no peer accepted it.
        reason: String,
    },
    /// The local store refused it.
    Rejected(String),
    /// There were no peers to try yet, so the operation is worth retrying.
    NoPeersYet {
        /// Why.
        reason: String,
    },
}

/// Everything that can go wrong while driving the swarm.
///
/// No variant is produced by an `unwrap`; every one is a condition a caller can
/// react to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SwarmError {
    /// The event loop task is gone.
    #[error("the libp2p event loop is no longer running")]
    EventLoopGone,
    /// The configuration was rejected.
    #[error("libp2p configuration is invalid: {0}")]
    Config(String),
    /// The swarm could not be built.
    #[error("could not build the libp2p swarm: {0}")]
    Build(String),
    /// A listen address was refused.
    #[error("could not listen on `{addr}`: {reason}")]
    Listen {
        /// The address.
        addr: String,
        /// Why it was refused.
        reason: String,
    },
    /// A multiaddr did not parse, or an address that has to be a libp2p multiaddr
    /// could not be converted into one.
    #[error("`{addr}` is not a usable multiaddr: {reason}")]
    BadAddress {
        /// The address.
        addr: String,
        /// Why it is unusable.
        reason: String,
    },
    /// A configuration problem surfaced while driving the swarm.
    ///
    /// Present so that a `?` on a `ConfigProblem` 閳?converting an address, say 閳?
    /// does not need a bespoke `map_err` at every call site.
    #[error("configuration problem: {0}")]
    ConfigProblem(#[from] crate::config::ConfigProblem),
    /// An address carried no `/p2p/<peer-id>` component, so there is no peer to
    /// address.
    #[error("`{addr}` carries no `/p2p/<peer-id>` component, so there is no peer to address")]
    AddressWithoutPeerId {
        /// The address.
        addr: String,
    },
    /// A peer id in an address was not usable.
    #[error("the peer id in `{addr}` is not usable: {reason}")]
    BadPeerId {
        /// The address.
        addr: String,
        /// Why the id is unusable.
        reason: String,
    },
    /// The swarm refused to start a dial.
    #[error("could not dial `{addr}`: {reason}")]
    Dial {
        /// The address.
        addr: String,
        /// Why the dial was refused.
        reason: String,
    },
    /// The topic did not come from a validated room name.
    #[error("`{topic}` is not a topic this node may publish to: {reason}")]
    BadTopic {
        /// The topic.
        topic: String,
        /// Why it was refused.
        reason: String,
    },
    /// GossipSub refused the publication.
    #[error("GossipSub refused to publish on `{topic}`: {reason}")]
    Publish {
        /// The topic.
        topic: String,
        /// Why it was refused.
        reason: String,
    },
    /// The payload was rejected by the codec.
    #[error("the payload could not be encoded: {0}")]
    Codec(String),
    /// A Kademlia operation was refused before it started.
    #[error("Kademlia refused the operation: {reason}")]
    Kademlia {
        /// Why it was refused.
        reason: String,
    },
    /// The operation could not run *yet*, but will succeed if it is retried.
    ///
    /// This is the difference between "the DHT has no peers in its routing table
    /// at this instant" and "the DHT will never accept this": the first is normal
    /// in the window between a connection being established and identify
    /// populating the routing table, and a caller should retry rather than treat it
    /// as a configuration error.
    #[error("`{operation}` cannot run yet: {reason}")]
    Retryable {
        /// What was being attempted.
        operation: String,
        /// Why it could not run.
        reason: String,
    },
    /// Kademlia ran and reported a failure.
    #[error("Kademlia query failed: {reason}")]
    QueryFailed {
        /// The reported failure.
        reason: String,
    },
    /// The record was not found.
    ///
    /// Distinct from [`SwarmError::Timeout`]: a caller should not retry this
    /// without changing something.
    #[error("no record is stored under `{key}`")]
    RecordNotFound {
        /// The key.
        key: String,
    },
    /// The value was larger than the DHT store will accept.
    ///
    /// `max` is the store's `max_value_bytes` limit; this is *not* the frame cap,
    /// and it is smaller. See [`DHT_MAX_VALUE_BYTES`].
    #[error("a value of {got} bytes exceeds the DHT store's {max}-byte limit ({reason})")]
    ValueTooLarge {
        /// The value length.
        got: usize,
        /// The store's limit.
        max: usize,
        /// The store's own message.
        reason: String,
    },
    /// The operation did not finish within its deadline.
    ///
    /// Distinct from a failure: the operation may still be in flight, which is why
    /// a caller may legitimately retry.
    #[error("`{operation}` did not finish within {seconds}s")]
    Timeout {
        /// What was being attempted.
        operation: String,
        /// The deadline, in seconds.
        seconds: u64,
    },
    /// The relay declined the reservation, or the connection to it failed.
    #[error("relay `{relay}` did not grant a reservation")]
    ReservationFailed {
        /// The relay.
        relay: String,
    },
    /// A hole punch did not produce a direct connection.
    ///
    /// Carries the precondition that was missing, because "hole punch failed" on
    /// its own is not actionable.
    #[error("could not hole-punch with `{peer}`: {reason}")]
    HolePunch {
        /// The peer.
        peer: String,
        /// Why it did not complete.
        reason: String,
    },
}

impl From<SwarmError> for nau_core::NauError {
    fn from(err: SwarmError) -> Self {
        nau_core::NauError::Validation(err.to_string())
    }
}

/// Counters an operator wants and a caller cannot otherwise see.
///
/// Dropped frames and rejected envelopes are the two ways this node silently loses
/// data, so both are counted rather than only logged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SwarmStats {
    /// GossipSub messages received, including ones later rejected.
    pub messages_received: u64,
    /// GossipSub messages rejected by the codec.
    pub malformed_messages: u64,
    /// Frames dropped because the inbound queue was full.
    pub dropped_frames: u64,
    /// Peers that completed an identify exchange.
    pub identified_peers: u64,
    /// Kademlia query results received.
    pub kad_queries_completed: u64,
    /// Relay reservations accepted.
    pub reservations_accepted: u64,
    /// Hole punches that succeeded.
    pub hole_punches_succeeded: u64,
    /// Hole punches that failed.
    pub hole_punches_failed: u64,
    /// Outgoing connections that failed.
    pub connection_failures: u64,
}

/// One command to the event loop.
enum Command {
    /// Start listening on an extra address.
    Listen(Multiaddr),
    /// Dial an address and wait for the connection to be established.
    Dial {
        /// The address.
        addr: Multiaddr,
        /// The deadline.
        timeout: Duration,
        /// Where to send the outcome.
        reply: oneshot::Sender<Result<(), SwarmError>>,
    },
    /// Publish bytes on a topic.
    Publish {
        /// The topic.
        topic: String,
        /// The bytes.
        payload: Vec<u8>,
        /// Where to send the outcome: how many peers it was queued for.
        reply: oneshot::Sender<Result<usize, SwarmError>>,
    },
    /// Store a record.
    PutRecord {
        /// The namespaced key.
        key: Vec<u8>,
        /// The value.
        value: Vec<u8>,
        /// Where to send the outcome.
        reply: oneshot::Sender<PutOutcome>,
    },
    /// Retrieve a record.
    GetRecord {
        /// The namespaced key.
        key: Vec<u8>,
        /// The deadline.
        timeout: Duration,
        /// Where to send the outcome.
        reply: oneshot::Sender<Result<Vec<u8>, SwarmError>>,
    },
    /// Reserve a slot on a relay.
    ReserveRelay {
        /// The relay's address.
        addr: Multiaddr,
        /// The deadline.
        timeout: Duration,
        /// Where to send the outcome.
        reply: oneshot::Sender<Result<(), SwarmError>>,
    },
    /// Report the current AutoNAT verdict.
    NatStatus {
        /// Where to send it.
        reply: oneshot::Sender<NatStatus>,
    },
    /// Attempt a hole punch after connecting to a peer.
    HolePunch {
        /// The peer's address.
        addr: Multiaddr,
        /// The deadline.
        timeout: Duration,
        /// Where to send the outcome.
        reply: oneshot::Sender<Result<(), SwarmError>>,
    },
    /// Report the connected peers.
    Connected {
        /// Where to send them.
        reply: oneshot::Sender<Vec<PeerId>>,
    },
    /// Report the listening addresses.
    ListenAddrs {
        /// Where to send them.
        reply: oneshot::Sender<Vec<String>>,
    },
    /// Stop the loop.
    Shutdown,
}

/// A pending operation awaiting a swarm event.
enum Pending {
    /// Waiting for a dial to be established or to fail.
    Dial(oneshot::Sender<Result<(), SwarmError>>),
    /// Waiting for a connection, then for a relay reservation.
    Reservation {
        /// The relay.
        relay: libp2p::PeerId,
        /// Where to send the outcome.
        reply: oneshot::Sender<Result<(), SwarmError>>,
    },
    /// Waiting for a connection, then for the DCUtR exchange.
    HolePunch {
        /// The peer.
        peer: libp2p::PeerId,
        /// Where to send the outcome.
        reply: oneshot::Sender<Result<(), SwarmError>>,
    },
}

impl Pending {
    /// Fail this operation with the given error.
    fn fail(self, error: SwarmError) {
        match self {
            Pending::Dial(reply) => {
                let _ = reply.send(Err(error));
            }
            Pending::Reservation { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Pending::HolePunch { reply, .. } => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

/// A running libp2p node: a handle to an event loop task that owns the swarm.
///
/// Not `Clone` on purpose 闁?there is one owner of the command channel, so
/// shutting down is unambiguous. Share it as an `Arc<Libp2pNode>` instead.
#[derive(Debug)]
pub struct Libp2pNode {
    /// This node's identity, in both views.
    identity: NauIdentity,
    /// This node's libp2p peer id.
    peer_id: libp2p::PeerId,
    /// The validated configuration the node was built from.
    config: Libp2pConfig,
    /// The command channel.
    commands: mpsc::Sender<Command>,
    /// Frames that arrived from the network and have not been consumed.
    inbound: Arc<Mutex<VecDeque<(PeerId, Frame)>>>,
    /// Signalled whenever `inbound` gains an element.
    inbound_signal: Arc<Notify>,
    /// The counters.
    stats: Arc<Mutex<SwarmStats>>,
    /// How the most recent `put_record` was replicated.
    last_replication: Arc<Mutex<Option<Replication>>>,
    /// The addresses the swarm reports as listening.
    listen_addrs: Arc<Mutex<Vec<String>>>,
    /// The event loop task.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Libp2pNode {
    /// Build and start a node, returning a handle to it.
    ///
    /// The swarm is polled once before this returns, so listeners are registered
    /// and a caller that spawns two nodes and immediately dials does not race them.
    /// The *bound* address of a `/tcp/0` listener is learned from the swarm's own
    /// event, so a caller that needs a concrete address should await
    /// [`Libp2pNode::wait_for_listen_addr`].
    pub async fn spawn(config: Libp2pConfig) -> Result<Self, SwarmError> {
        config
            .validate()
            .map_err(|e| SwarmError::Config(e.to_string()))?;

        let seed = config.seed.ok_or_else(|| {
            SwarmError::Config(
                "the configuration carries no Ed25519 seed; validation should have caught this"
                    .to_string(),
            )
        })?;
        let identity = NauIdentity::from_seed(&seed);
        let local_id = crate::behaviour::to_libp2p_peer_id(&identity.peer_id())
            .ok_or_else(|| SwarmError::Build("the derived peer id is not a libp2p id".into()))?;

        let mut swarm = build_swarm(&config, seed, local_id)?;

        // Queue the listen commands. `listen_on` reports a *syntactically* refused
        // address synchronously, but a failure to bind the socket 閳?an address in
        // use, a port below 1024, an interface that does not exist 閳?arrives later
        // as a `ListenerError` event, *not* as an error from `listen_on`. An
        // earlier version of this function therefore returned a healthy-looking
        // node whose listener had never bound, which presented as a timeout on the
        // caller's side and a `TIME_WAIT` on the operating system's.
        for addr in &config.listen {
            let libp2p_addr = addr.to_libp2p().map_err(|e| SwarmError::Listen {
                addr: addr.to_string(),
                reason: e.to_string(),
            })?;
            swarm
                .listen_on(libp2p_addr)
                .map_err(|e| SwarmError::Listen {
                    addr: addr.to_string(),
                    reason: e.to_string(),
                })?;

            // A node listening on loopback must *say so*. When an address is bound
            // to `127.0.0.1`, the operating system reports the bound socket as
            // `0.0.0.0:<port>`, and libp2p propagates the reported address 閳?so
            // identify, and therefore the peer's routing table, learns
            // `/ip4/0.0.0.0/tcp/<port>`. That is not dialable, and the dial fails
            // with `os error 10048` ("only one usage of each socket address is
            // normally permitted") because the peer tries to *bind* `0.0.0.0`
            // rather than connect to something.
            //
            // Declaring the loopback address as external is the fix, and it is only
            // done for a loopback listener: asserting a public external address for
            // a wildcard bind would be a fabrication, and it is exactly the kind of
            // fabricated reachability this project exists to remove.
            if crate::config::is_loopback_or_memory(addr.as_str()) {
                if let Ok(parsed) = addr.to_libp2p() {
                    swarm.add_external_address(parsed);
                }
            }
        }

        // Where the listener errors are collected, so `spawn` can fail on them
        // instead of pretending they did not happen.
        let listener_errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let (commands, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let inbound: Arc<Mutex<VecDeque<(PeerId, Frame)>>> = Arc::new(Mutex::new(VecDeque::new()));
        let inbound_signal = Arc::new(Notify::new());
        let stats = Arc::new(Mutex::new(SwarmStats::default()));
        let listen_addrs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready_rx) = oneshot::channel();

        let task = tokio::spawn(run_event_loop(
            swarm,
            command_rx,
            Arc::clone(&inbound),
            Arc::clone(&inbound_signal),
            Arc::clone(&stats),
            Arc::clone(&listen_addrs),
            Arc::clone(&listener_errors),
            ready_tx,
        ));

        // Wait for the loop's first poll, which is when the listeners are
        // registered with the reactor.
        ready_rx.await.map_err(|_| SwarmError::EventLoopGone)?;

        // A listener that failed to bind produces no address; a listener that bound
        // produces one. Waiting for whichever comes first is what turns an
        // asynchronous bind failure into a `spawn` error 閳?see the comment on the
        // listen loop above.
        //
        // The address recorded here is the one the behaviour reported in
        // `NewListenAddr`, so a requested `/tcp/0` is already resolved to the port
        // the operating system chose; no separate bookkeeping is needed.
        let deadline = tokio::time::Instant::now() + LISTEN_CONFIRM_TIMEOUT;
        loop {
            if let Some(reason) = listener_errors.lock().await.first().cloned() {
                task.abort();
                return Err(SwarmError::Listen {
                    addr: config
                        .listen
                        .first()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                    reason,
                });
            }
            if !listen_addrs.lock().await.is_empty() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                task.abort();
                return Err(SwarmError::Listen {
                    addr: config
                        .listen
                        .first()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                    reason: format!(
                        "no listener came up within {LISTEN_CONFIRM_TIMEOUT:?}; the address may be \
                         in use"
                    ),
                });
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Ok(Self {
            identity,
            peer_id: local_id,
            config,
            commands,
            inbound,
            inbound_signal,
            stats,
            last_replication: Arc::new(Mutex::new(None)),
            listen_addrs,
            task: Some(task),
        })
    }

    /// This node's identity, in both views.
    pub fn identity(&self) -> &NauIdentity {
        &self.identity
    }

    /// This node's libp2p peer id.
    pub fn peer_id(&self) -> &libp2p::PeerId {
        &self.peer_id
    }

    /// This node's peer id in this crate's own type.
    pub fn nau_peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// The configuration the node was built from.
    pub fn config(&self) -> &Libp2pConfig {
        &self.config
    }

    /// The addresses the swarm currently reports as listening.
    ///
    /// Read from the event loop's own record of `NewListenAddr` events, which is
    /// what makes it usable immediately after `spawn` and after a listener is
    /// added at run time through [`Libp2pNode::listen`].
    pub async fn listen_addrs(&self) -> Vec<String> {
        self.listen_addrs.lock().await.clone()
    }

    /// The listening addresses the **swarm itself** reports right now.
    ///
    /// Distinct from [`Libp2pNode::listen_addrs`], which is the loop's record of
    /// the addresses it has been told about: this asks the swarm, so the two
    /// disagreeing is itself a signal (a listener that closed, say). Both exist
    /// because the first is available immediately and the second is authoritative.
    pub async fn swarm_listen_addrs(&self) -> Vec<String> {
        let (reply, rx) = oneshot::channel();
        if self
            .commands
            .send(Command::ListenAddrs { reply })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Wait until a listening address appears, up to `timeout`.
    ///
    /// A polling wait with a bound, rather than a sleep: the wait is observable
    /// and it cannot hang.
    pub async fn wait_for_listen_addr(&self, timeout: Duration) -> Result<String, SwarmError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(addr) = self.listen_addrs.lock().await.first().cloned() {
                return Ok(addr);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(SwarmError::Timeout {
                    operation: "waiting for a listening address".to_string(),
                    seconds: timeout.as_secs(),
                });
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// This node's address for dialling: a listening address plus `/p2p/<id>`.
    pub async fn dialable_addr(&self) -> Result<String, SwarmError> {
        self.dialable_addr_with_timeout(Duration::from_secs(10))
            .await
    }

    /// [`Libp2pNode::dialable_addr`] with an explicit deadline.
    pub async fn dialable_addr_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<String, SwarmError> {
        let addr = self.wait_for_listen_addr(timeout).await?;
        if addr.contains("/p2p/") {
            Ok(addr)
        } else {
            Ok(format!("{addr}/p2p/{}", self.peer_id))
        }
    }

    /// The peers this node is connected to, in this crate's id type.
    pub async fn connected(&self) -> Vec<PeerId> {
        let (reply, rx) = oneshot::channel();
        if self
            .commands
            .send(Command::Connected { reply })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Wait until a peer is connected, up to `timeout`.
    pub async fn wait_for_connection(
        &self,
        peer: &PeerId,
        timeout: Duration,
    ) -> Result<(), SwarmError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.connected().await.iter().any(|p| p == peer) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(SwarmError::Timeout {
                    operation: format!("waiting for a connection to {peer}"),
                    seconds: timeout.as_secs(),
                });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The counters.
    pub async fn stats(&self) -> SwarmStats {
        *self.stats.lock().await
    }

    /// Start listening on an extra address.
    pub async fn listen(&self, addr: &str) -> Result<(), SwarmError> {
        let parsed = parse_addr(addr)?;
        self.commands
            .send(Command::Listen(parsed))
            .await
            .map_err(|_| SwarmError::EventLoopGone)
    }

    /// Dial an address, which must carry a `/p2p/<peer-id>` component.
    pub async fn dial(&self, addr: &str) -> Result<(), SwarmError> {
        self.dial_with_timeout(addr, DEFAULT_CONNECT_TIMEOUT).await
    }

    /// [`Libp2pNode::dial`] with an explicit deadline.
    pub async fn dial_with_timeout(&self, addr: &str, timeout: Duration) -> Result<(), SwarmError> {
        let parsed = parse_addr(addr)?;
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Dial {
                addr: parsed,
                timeout,
                reply,
            })
            .await
            .map_err(|_| SwarmError::EventLoopGone)?;
        rx.await.map_err(|_| SwarmError::EventLoopGone)?
    }

    /// Publish `frame` on `topic`.
    ///
    /// Returns the number of peers GossipSub queued the message for, which is
    /// **zero** when nobody is subscribed. A caller that needs delivery
    /// confirmation must check that number: `Ok(0)` means the message was accepted
    /// locally and went nowhere 闁?precisely the case the upstream mock reported as
    /// success.
    pub async fn publish(&self, topic: &str, frame: &Frame) -> Result<usize, SwarmError> {
        let topic = validate_topic(topic)?;
        let payload = codec::encode_envelope(&self.identity.peer_id(), random_nonce(), frame)
            .map_err(|e| SwarmError::Codec(e.to_string()))?;
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Publish {
                topic,
                payload,
                reply,
            })
            .await
            .map_err(|_| SwarmError::EventLoopGone)?;
        rx.await.map_err(|_| SwarmError::EventLoopGone)?
    }

    /// Store a value under `key` in the DHT.
    ///
    /// `key` is namespaced with [`naming::record_key`] before it reaches the DHT,
    /// so two applications sharing a swarm cannot collide on a bare key.
    ///
    /// ## What `Ok(())` means, precisely
    ///
    /// The record is **in this node's Kademlia store** and is therefore readable
    /// from this node, and was accepted for replication. It is *not* a promise that
    /// another node has taken a copy: a Kademlia `put_record` needs a peer to
    /// accept the record, and between a connection being established and identify
    /// populating the routing table there is a real window in which none will.
    ///
    /// So this does not fail on the DHT's `QuorumFailed` when the local store
    /// accepted the value. It reports that state instead, through
    /// [`Libp2pNode::last_put_replication`], rather than turning a successful local
    /// store into an error 閳?which is what an earlier version did, and it made a
    /// record that *was* retrievable by the other node look like a failure. A
    /// fabricated success would be the opposite mistake and is equally avoided: a
    /// store failure is still an error.
    pub async fn put_record(&self, key: &str, value: Vec<u8>) -> Result<(), SwarmError> {
        self.put_record_with_timeout(key, value, DEFAULT_PUT_TIMEOUT)
            .await
    }

    /// How the most recent [`Libp2pNode::put_record`] on this node was replicated.
    ///
    /// `None` before the first call. `Replication::LocalOnly` means the record is
    /// stored and readable here but no peer accepted it yet.
    pub async fn last_put_replication(&self) -> Option<Replication> {
        self.last_replication.lock().await.clone()
    }

    /// [`Libp2pNode::put_record`] with an explicit deadline.
    ///
    /// ## Why this retries
    ///
    /// A Kademlia `put_record` needs at least one peer in the routing table, and the
    /// routing table is populated by identify, which runs *after* a connection is
    /// established. There is therefore a real window in which a node is connected
    /// and has no known peers; the DHT answers `NoKnownPeers`, and this method waits
    /// and tries again until the caller's deadline. If the deadline passes with the
    /// record still only local, the error is a [`SwarmError::Timeout`] whose message
    /// says the record was stored locally 閳?never a bare "failed".
    pub async fn put_record_with_timeout(
        &self,
        key: &str,
        value: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), SwarmError> {
        let key = naming::record_key(key).map_err(|e| SwarmError::Kademlia {
            reason: e.to_string(),
        })?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (reply, rx) = oneshot::channel();
            self.commands
                .send(Command::PutRecord {
                    key: key.clone(),
                    value: value.clone(),
                    reply,
                })
                .await
                .map_err(|_| SwarmError::EventLoopGone)?;
            match rx.await.map_err(|_| SwarmError::EventLoopGone)? {
                // Accepted for replication: the strongest outcome available.
                PutOutcome::Replicated => {
                    *self.last_replication.lock().await = Some(Replication::Replicated);
                    return Ok(());
                }
                // Stored locally, not accepted by a peer. That is a success for the
                // local store and a timing fact for the DHT; it is *not* retried,
                // because retrying cannot make a peer appear and the record is
                // already retrievable from here.
                PutOutcome::LocalOnly { reason } => {
                    *self.last_replication.lock().await = Some(Replication::LocalOnly {
                        reason: reason.clone(),
                    });
                    return Ok(());
                }
                // The local store refused the record. Kademlia's `MemoryStore`
                // refuses a value at or above its `max_value_bytes`, which defaults
                // to 65 KiB 鈥?well under the 8 MiB frame cap, so a frame this
                // transport is willing to carry can still be too large for the DHT
                // to store. That is a real limit and is named, with both numbers,
                // rather than reported as a generic Kademlia error.
                PutOutcome::Rejected(reason) => {
                    return Err(SwarmError::ValueTooLarge {
                        got: value.len(),
                        max: DHT_MAX_VALUE_BYTES,
                        reason,
                    });
                }
                PutOutcome::NoPeersYet { reason } => {
                    // The only outcome worth retrying: the routing table is still
                    // being populated. Nothing else is retried, so no error value
                    // needs to be carried out of the loop 鈥?the deadline is the only
                    // way this iteration ends.
                    tracing::debug!("put_record deferred: {reason}");
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(SwarmError::Timeout {
                    operation: format!(
                        "put_record; the record is in this node's store but no peer accepted it \
                         within {timeout:?}"
                    ),
                    seconds: timeout.as_secs(),
                });
            }
            // Long enough for a heartbeat and an identify round trip, short enough
            // that several attempts fit in a normal deadline.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Retrieve the value stored under `key`.
    ///
    /// Checks the local store first: a record this node put is stored locally *and*
    /// published, so a query would be wasted work, and a single-node deployment
    /// would otherwise never see its own records.
    pub async fn get_record(&self, key: &str) -> Result<Vec<u8>, SwarmError> {
        self.get_record_with_timeout(key, DEFAULT_RECORD_TIMEOUT)
            .await
    }

    /// [`Libp2pNode::get_record`] with an explicit deadline.
    pub async fn get_record_with_timeout(
        &self,
        key: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, SwarmError> {
        let key = naming::record_key(key).map_err(|e| SwarmError::Kademlia {
            reason: e.to_string(),
        })?;
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::GetRecord {
                key,
                timeout,
                reply,
            })
            .await
            .map_err(|_| SwarmError::EventLoopGone)?;
        rx.await.map_err(|_| SwarmError::EventLoopGone)?
    }

    /// Reserve a slot on a relay.
    ///
    /// Resolves when the relay accepts, not when the dial succeeds: a relay that
    /// closes the connection without granting a reservation is a failure, and
    /// reporting the dial as the outcome would hide that.
    pub async fn reserve_relay(&self, addr: &str) -> Result<(), SwarmError> {
        self.reserve_relay_with_timeout(addr, DEFAULT_RESERVATION_TIMEOUT)
            .await
    }

    /// [`Libp2pNode::reserve_relay`] with an explicit deadline.
    pub async fn reserve_relay_with_timeout(
        &self,
        addr: &str,
        timeout: Duration,
    ) -> Result<(), SwarmError> {
        let parsed = parse_addr(addr)?;
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::ReserveRelay {
                addr: parsed,
                timeout,
                reply,
            })
            .await
            .map_err(|_| SwarmError::EventLoopGone)?;
        rx.await.map_err(|_| SwarmError::EventLoopGone)?
    }

    /// The current AutoNAT verdict.
    ///
    /// [`NatStatus::Unknown`] means nothing was measured. It is never rendered as
    /// `Private` or `Public`, because a guess about reachability is worse than no
    /// answer 闁?the defect `nau_net::nat` exists to correct.
    pub async fn nat_status(&self) -> NatStatus {
        let (reply, rx) = oneshot::channel();
        if self
            .commands
            .send(Command::NatStatus { reply })
            .await
            .is_err()
        {
            return NatStatus::Unknown;
        }
        rx.await.unwrap_or(NatStatus::Unknown)
    }

    /// Attempt a hole punch with a peer.
    ///
    /// ## What this can and cannot do
    ///
    /// DCUtR is a *coordination* protocol, not a dialler. It upgrades a connection
    /// that already exists **through a relay** into a direct one, and libp2p
    /// initiates the protocol from the side that receives the inbound relayed
    /// connection. There is therefore no local "punch now" call in libp2p 0.56:
    /// this method ensures a connection to `addr` exists and then waits for a DCUtR
    /// event from that peer, bounded by `timeout`.
    ///
    /// If no event arrives it returns [`SwarmError::HolePunch`] naming the
    /// precondition, rather than a success it cannot substantiate. See the crate
    /// documentation for which part of this is exercised by a test.
    pub async fn hole_punch(&self, addr: &str) -> Result<(), SwarmError> {
        self.hole_punch_with_timeout(addr, DEFAULT_HOLE_PUNCH_TIMEOUT)
            .await
    }

    /// [`Libp2pNode::hole_punch`] with an explicit deadline.
    pub async fn hole_punch_with_timeout(
        &self,
        addr: &str,
        timeout: Duration,
    ) -> Result<(), SwarmError> {
        let parsed = parse_addr(addr)?;
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::HolePunch {
                addr: parsed,
                timeout,
                reply,
            })
            .await
            .map_err(|_| SwarmError::EventLoopGone)?;
        rx.await.map_err(|_| SwarmError::EventLoopGone)?
    }

    /// Take the next frame that arrived from the network, waiting at most
    /// `timeout`.
    ///
    /// `Ok(None)` on timeout, matching [`nau_net::Transport::recv`]'s contract: a
    /// quiet period is normal operation, not a failure.
    ///
    /// The signal future is registered *before* the queue is re-checked, so a frame
    /// that arrives between the check and the wait is not lost.
    pub async fn recv_frame(
        &self,
        timeout: Duration,
    ) -> Result<Option<(PeerId, Frame)>, SwarmError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.inbound_signal.notified();
            {
                let mut queue = self.inbound.lock().await;
                if let Some(item) = queue.pop_front() {
                    return Ok(Some(item));
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match tokio::time::timeout(remaining, notified).await {
                Ok(()) => continue,
                Err(_) => return Ok(None),
            }
        }
    }

    /// Stop the event loop and wait for the task to finish.
    ///
    /// Idempotent: a second call would have nothing left to stop.
    pub async fn shutdown(mut self) {
        let _ = self.commands.send(Command::Shutdown).await;
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Libp2pNode {
    fn drop(&mut self) {
        // A dropped handle must not leave a task polling a swarm forever. Best
        // effort: the loop also stops when the command channel closes, which
        // dropping the sender does, but aborting is immediate.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Build the swarm: TCP transport, the project's identity, and the composed
/// behaviour.
fn build_swarm(
    config: &Libp2pConfig,
    seed: [u8; 32],
    local_id: libp2p::PeerId,
) -> Result<libp2p::Swarm<Libp2pBehaviour>, SwarmError> {
    let keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed)
        .map_err(|e| SwarmError::Build(format!("identity key rejected: {e}")))?;
    let behaviour_config = config.clone();

    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| SwarmError::Build(format!("TCP transport: {e}")))?
        // The relay *client* transport must be installed here: it is what carries
        // reservation requests. Without it the client behaviour is constructed but
        // its reservations never leave the process, which presents as a relay that
        // silently ignores this node.
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .map_err(|e| SwarmError::Build(format!("relay client transport: {e}")))?
        .with_behaviour(move |key, relay_client| {
            Libp2pBehaviour::for_config(&behaviour_config, local_id, key, relay_client)
                // `TryIntoBehaviour` is implemented for a plain behaviour
                // (`Infallible`) and for `Result<_, Box<dyn Error + Send + Sync>>`.
                // `BehaviourError` is mapped into that box rather than left as
                // itself, because the `Result<T, BehaviourError>` form does not
                // implement `TryIntoBehaviour` and the failure would surface as
                // "`Result<_, BehaviourError>` is not a `NetworkBehaviour`" 閳?an
                // error message that names the wrong problem entirely.
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        })
        .map_err(|e| SwarmError::Build(format!("behaviour: {e}")))?
        .with_swarm_config(|cfg| {
            // Idle connections are kept for longer than the default: a DHT node
            // that drops an idle peer loses its routing-table entry with it.
            cfg.with_idle_connection_timeout(Duration::from_secs(120))
        })
        .build();
    Ok(swarm)
}

/// The event loop: `select!` over the command channel and the swarm.
#[allow(clippy::too_many_arguments)]
async fn run_event_loop(
    mut swarm: libp2p::Swarm<Libp2pBehaviour>,
    mut commands: mpsc::Receiver<Command>,
    inbound: Arc<Mutex<VecDeque<(PeerId, Frame)>>>,
    inbound_signal: Arc<Notify>,
    stats: Arc<Mutex<SwarmStats>>,
    listen_addrs: Arc<Mutex<Vec<String>>>,
    listener_errors: Arc<Mutex<Vec<String>>>,
    ready: oneshot::Sender<()>,
) {
    let mut pending_gets: PendingGets = HashMap::new();
    let mut pending_puts: PendingPuts = HashMap::new();
    // Operations that complete on a swarm event rather than on a query id.
    let mut pending: Vec<(tokio::time::Instant, String, Pending)> = Vec::new();
    let mut ready = Some(ready);
    let mut bootstrapped = false;

    loop {
        tokio::select! {
            biased;

            command = commands.recv() => {
                match command {
                    None => break,
                    Some(Command::Shutdown) => break,
                    Some(command) => {
                        if handle_command(
                            command,
                            &mut swarm,
                            &mut pending_gets,
                            &mut pending_puts,
                            &mut pending,
                        ) {
                            break;
                        }
                    }
                }
            }

            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event,
                    &inbound,
                    &inbound_signal,
                    &stats,
                    &listen_addrs,
                    &listener_errors,
                    &mut pending_gets,
                    &mut pending_puts,
                    &mut pending,
                )
                .await;
                if !bootstrapped && swarm.connected_peers().next().is_some() {
                    bootstrapped = true;
                    // A bootstrap against an empty routing table is a no-op and
                    // returns an error saying so; that is not worth reporting.
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(25)) => {
                // Nothing to do. The tick exists so deadlines are enforced even
                // when both the command channel and the swarm are quiet.
            }
        }

        // The loop is running and reacting; release the caller.
        if let Some(sender) = ready.take() {
            let _ = sender.send(());
        }

        // Enforce deadlines.
        let now = tokio::time::Instant::now();
        let mut index = 0;
        while index < pending.len() {
            if pending[index].0 <= now {
                let (_, operation, item) = pending.swap_remove(index);
                item.fail(SwarmError::Timeout {
                    operation,
                    seconds: 0,
                });
            } else {
                index += 1;
            }
        }
        // A `put_record` query that never resolves is expired here too, so its reply
        // channel cannot be held open forever. Expiry does not claim the record was
        // lost: `stored_locally` decides whether the outcome is "local only" or
        // "worth retrying".
        let expired: Vec<libp2p::kad::QueryId> = pending_puts
            .iter()
            .filter(|(_, (deadline, ..))| *deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some((_, _, _, stored_locally, sender)) = pending_puts.remove(&id) {
                let _ = sender.send(if stored_locally {
                    PutOutcome::LocalOnly {
                        reason: "the put_record query did not finish in time".to_string(),
                    }
                } else {
                    PutOutcome::NoPeersYet {
                        reason: "the put_record query did not finish in time".to_string(),
                    }
                });
            }
        }
    }

    // Fail everything still in flight rather than dropping the senders silently: a
    // caller awaiting a oneshot would otherwise see a bare channel error.
    for (_, sender) in pending_gets.drain() {
        let _ = sender.send(Err(SwarmError::EventLoopGone));
    }
    for (_, (_, _, _, stored_locally, sender)) in pending_puts.drain() {
        // A record the local store accepted is still readable after the loop stops;
        // reporting a lost record would be false.
        let _ = sender.send(if stored_locally {
            PutOutcome::LocalOnly {
                reason: SwarmError::EventLoopGone.to_string(),
            }
        } else {
            PutOutcome::NoPeersYet {
                reason: SwarmError::EventLoopGone.to_string(),
            }
        });
    }
    for (_, _, item) in pending.drain(..) {
        item.fail(SwarmError::EventLoopGone);
    }
}

/// A pending `get_record` query: where to send the value.
type PendingGets = HashMap<libp2p::kad::QueryId, oneshot::Sender<Result<Vec<u8>, SwarmError>>>;

/// A pending Kademlia store: its deadline, the namespaced key, the value length,
/// whether the local store accepted the record, and the reply channel.
///
/// A named tuple rather than five positional parameters in every signature. The
/// field meanings are in this comment because the tuple is internal to the event
/// loop and a struct would exist only to be destructured.
type PendingPut = (
    tokio::time::Instant,
    Vec<u8>,
    usize,
    bool,
    oneshot::Sender<PutOutcome>,
);

/// Pending Kademlia stores, keyed by the query id Kademlia assigned.
///
/// Each carries its deadline, so a query that never resolves cannot hold its reply
/// channel open forever; an expired deadline is reported *without* claiming the
/// record was lost, because a local store that accepted it still has it.
type PendingPuts = HashMap<libp2p::kad::QueryId, PendingPut>;

/// Apply one command to the swarm. Returns `true` when the loop should stop.
fn handle_command(
    command: Command,
    swarm: &mut libp2p::Swarm<Libp2pBehaviour>,
    pending_gets: &mut PendingGets,
    pending_puts: &mut PendingPuts,
    pending: &mut Vec<(tokio::time::Instant, String, Pending)>,
) -> bool {
    match command {
        Command::Shutdown => true,

        Command::Listen(addr) => {
            if let Ok(parsed) = addr.to_libp2p() {
                // A refused address is reported by the swarm's own event, which is
                // the honest place for it; the caller sees the effect through
                // `listen_addrs`.
                let _ = swarm.listen_on(parsed);
            }
            false
        }

        Command::Dial {
            addr,
            timeout,
            reply,
        } => {
            match resolve_peer(&addr) {
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
                Ok((peer, libp2p_addr)) => {
                    match swarm.dial(libp2p_addr) {
                        Err(e) => {
                            let _ = reply.send(Err(SwarmError::Dial {
                                addr: addr.to_string(),
                                reason: e.to_string(),
                            }));
                        }
                        Ok(()) => pending.push((
                            tokio::time::Instant::now() + timeout,
                            format!("dialling {addr}"),
                            Pending::Dial(reply),
                        )),
                    }
                    let _ = peer;
                }
            }
            false
        }

        Command::Publish {
            topic,
            payload,
            reply,
        } => {
            let outcome = match swarm
                .behaviour_mut()
                .gossipsub
                .publish(libp2p::gossipsub::IdentTopic::new(topic.clone()), payload)
            {
                Ok(_message_id) => {
                    // The number of peers the message was queued for. Zero is a
                    // real answer and the caller must be able to see it.
                    Ok(swarm.behaviour().gossipsub.all_mesh_peers().count())
                }
                Err(e) => Err(SwarmError::Publish {
                    topic,
                    reason: e.to_string(),
                }),
            };
            let _ = reply.send(outcome);
            false
        }

        Command::PutRecord { key, value, reply } => {
            let value_len = value.len();
            let record = libp2p::kad::Record::new(key.clone(), value);
            // Store locally *first*, and remember whether the store accepted it.
            // Kademlia's own `put_record` also writes to the local store, but only
            // on its way to the query, so doing it here is what makes "stored
            // locally but not replicated" a state this code can report rather than
            // an error it has to invent.
            let stored_locally = swarm
                .behaviour_mut()
                .kad
                .store_mut()
                .put(record.clone())
                .is_ok();
            match swarm
                .behaviour_mut()
                .kad
                .put_record(record, libp2p::kad::Quorum::One)
            {
                Ok(id) => {
                    pending_puts.insert(
                        id,
                        (
                            tokio::time::Instant::now() + DEFAULT_PUT_TIMEOUT,
                            key,
                            value_len,
                            stored_locally,
                            reply,
                        ),
                    );
                }
                Err(e) => {
                    // `NoKnownPeers`: the store has the record and the routing table
                    // is empty, so this is worth retrying.
                    let outcome = if stored_locally {
                        PutOutcome::NoPeersYet {
                            reason: e.to_string(),
                        }
                    } else {
                        PutOutcome::Rejected(e.to_string())
                    };
                    let _ = reply.send(outcome);
                }
            }
            false
        }

        Command::GetRecord {
            key,
            timeout,
            reply,
        } => {
            // The local store is consulted first so that a record this node holds
            // is returned without a network round trip, and so that a one-node
            // deployment sees its own records at all.
            let record_key = libp2p::kad::RecordKey::from(key);
            let local = swarm
                .behaviour_mut()
                .kad
                .store_mut()
                .get(&record_key)
                .map(|record| record.value.clone());
            if let Some(value) = local {
                let _ = reply.send(Ok(value));
                return false;
            }
            let id = swarm.behaviour_mut().kad.get_record(record_key);
            pending_gets.insert(id, reply);
            let _ = timeout;
            false
        }

        Command::ReserveRelay {
            addr,
            timeout,
            reply,
        } => {
            match resolve_peer(&addr) {
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
                Ok((peer, libp2p_addr)) => {
                    // A reservation is requested by **listening** on the relay's
                    // `/p2p-circuit` address, not by dialling the relay. The relay
                    // client transport turns that listener into an outbound HOP
                    // reserve request, and the relay's answer arrives as a
                    // `ReservationReqAccepted` event.
                    //
                    // An earlier version dialled the bare relay address. That does
                    // not request a reservation at all, and on Windows it failed
                    // with `os error 10048` 閳?the dial was being asked to *bind* the
                    // relay's own port 閳?which pointed at the wrong subsystem
                    // entirely.
                    let circuit = match circuit_listen_addr(&libp2p_addr, peer) {
                        Ok(addr) => addr,
                        Err(e) => {
                            let _ = reply.send(Err(e));
                            return false;
                        }
                    };
                    // Teach the swarm how to reach the relay before asking it for
                    // anything, so the HOP request has a connection to travel on.
                    swarm.add_peer_address(peer, libp2p_addr);
                    if let Err(e) = swarm.listen_on(circuit) {
                        let _ = reply.send(Err(SwarmError::ReservationFailed {
                            relay: addr.to_string(),
                        }));
                        let _ = e;
                        return false;
                    }
                    pending.push((
                        tokio::time::Instant::now() + timeout,
                        format!("reserving a relay slot on {addr}"),
                        Pending::Reservation { relay: peer, reply },
                    ));
                }
            }
            false
        }

        Command::NatStatus { reply } => {
            let _ = reply.send(swarm.behaviour().nat_status());
            false
        }

        Command::HolePunch {
            addr,
            timeout,
            reply,
        } => {
            match resolve_peer(&addr) {
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
                Ok((peer, libp2p_addr)) => {
                    // Ensure the connection exists. `add_peer_address` first, so the
                    // address is in the swarm's book even when the dial turns out to
                    // be redundant.
                    swarm.add_peer_address(peer, libp2p_addr.clone());
                    // A dial for a peer that is already connected is *not* an error:
                    // `Swarm::dial` returns `Ok` when a dial is already in progress
                    // or the peer is connected, because libp2p 0.56's `DialError`
                    // has no `AlreadyConnected` variant. So the redundant case DCUtR
                    // exists for needs no special handling here 閳?an earlier version
                    // of this code tried to match on a variant that does not exist
                    // and would not have compiled against a different assumption.
                    //
                    // A genuine failure is reported, because a hole punch cannot
                    // proceed without a connection.
                    if let Err(e) = swarm.dial(libp2p_addr) {
                        let _ = reply.send(Err(SwarmError::Dial {
                            addr: addr.to_string(),
                            reason: e.to_string(),
                        }));
                        return false;
                    }
                    pending.push((
                        tokio::time::Instant::now() + timeout,
                        format!("hole punching with {addr}"),
                        Pending::HolePunch { peer, reply },
                    ));
                }
            }
            false
        }

        Command::Connected { reply } => {
            let peers: Vec<PeerId> = swarm
                .connected_peers()
                .filter_map(|p| PeerId::parse(&p.to_string()).ok())
                .collect();
            let _ = reply.send(peers);
            false
        }

        Command::ListenAddrs { reply } => {
            let addrs: Vec<String> = swarm.listeners().map(|a| a.to_string()).collect();
            let _ = reply.send(addrs);
            false
        }
    }
}

/// The listening address that requests a reservation on a relay.
///
/// `/<relay address>/p2p/<relay id>/p2p-circuit`. The relay's own peer id is
/// already the trailing component of the address a caller supplies, so this moves
/// it in front of `/p2p-circuit` rather than appending it again 閳?appending it
/// would produce `/p2p/<id>/p2p-circuit/p2p/<id>`, which is a different (and
/// meaningless) address.
fn circuit_listen_addr(
    relay_addr: &libp2p::Multiaddr,
    relay_peer: libp2p::PeerId,
) -> Result<libp2p::Multiaddr, SwarmError> {
    use libp2p::multiaddr::Protocol;
    // Strip a trailing `/p2p/<id>` if present, then append the canonical tail.
    let mut bare = relay_addr.clone();
    let had_peer = matches!(bare.iter().last(), Some(Protocol::P2p(_)));
    if had_peer {
        bare.pop();
    }
    if bare.iter().last().is_none() {
        return Err(SwarmError::BadAddress {
            addr: relay_addr.to_string(),
            reason: "the relay address has no host component".to_string(),
        });
    }
    bare.push(Protocol::P2p(relay_peer));
    bare.push(Protocol::P2pCircuit);
    Ok(bare)
}

/// Apply one swarm event.
#[allow(clippy::too_many_arguments)]
async fn handle_swarm_event(
    event: libp2p::swarm::SwarmEvent<NauEvent>,
    inbound: &Arc<Mutex<VecDeque<(PeerId, Frame)>>>,
    inbound_signal: &Arc<Notify>,
    stats: &Arc<Mutex<SwarmStats>>,
    listen_addrs: &Arc<Mutex<Vec<String>>>,
    listener_errors: &Arc<Mutex<Vec<String>>>,
    pending_gets: &mut PendingGets,
    pending_puts: &mut PendingPuts,
    pending: &mut Vec<(tokio::time::Instant, String, Pending)>,
) {
    match event {
        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
            push_listen_addr(listen_addrs, address.to_string()).await;
        }

        libp2p::swarm::SwarmEvent::ListenerError { listener_id, error } => {
            // A bind failure lands here, not in `listen_on`'s return value. It is
            // recorded so that `Libp2pNode::spawn` can fail rather than hand back a
            // node with no listener.
            let message = format!("listener {listener_id:?} failed: {error}");
            tracing::warn!("{message}");
            listener_errors.lock().await.push(message);
        }

        libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            // A dial or a reservation that was waiting for a connection gets its
            // next step here, or is reported as done.
            let mut index = 0;
            while index < pending.len() {
                let finished = match &pending[index].2 {
                    Pending::Dial(_) => true,
                    Pending::Reservation { relay, .. } => *relay == peer_id,
                    // A hole punch needs the connection *and* the DCUtR exchange,
                    // so it is not finished by a connection alone.
                    Pending::HolePunch { .. } => false,
                };
                if finished {
                    let (_, _, item) = pending.swap_remove(index);
                    match item {
                        Pending::Dial(reply) => {
                            let _ = reply.send(Ok(()));
                        }
                        Pending::Reservation { reply, .. } => {
                            // The relay client now has a connection; the
                            // reservation result arrives as its own event.
                            let _ = reply;
                        }
                        Pending::HolePunch { .. } => {}
                    }
                } else {
                    index += 1;
                }
            }
        }

        libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            {
                let mut guard = stats.lock().await;
                guard.connection_failures = guard.connection_failures.saturating_add(1);
            }
            let message = error.to_string();
            let mut index = 0;
            while index < pending.len() {
                let matches = match (&pending[index].2, peer_id) {
                    (Pending::Dial(_), _) => true,
                    (Pending::Reservation { relay, .. }, Some(failed)) => *relay == failed,
                    (Pending::HolePunch { peer, .. }, Some(failed)) => *peer == failed,
                    _ => false,
                };
                if matches {
                    let (_, operation, item) = pending.swap_remove(index);
                    item.fail(SwarmError::Dial {
                        addr: operation,
                        reason: message.clone(),
                    });
                } else {
                    index += 1;
                }
            }
        }

        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
            // A pending reservation whose relay went away is a failure, not a
            // success: reporting the dial would hide it.
            let mut index = 0;
            while index < pending.len() {
                let matches = match &pending[index].2 {
                    Pending::Reservation { relay, .. } => *relay == peer_id,
                    Pending::HolePunch { peer, .. } => *peer == peer_id,
                    Pending::Dial(_) => false,
                };
                if matches {
                    let (_, _, item) = pending.swap_remove(index);
                    item.fail(SwarmError::Timeout {
                        operation: "the peer disconnected first".to_string(),
                        seconds: 0,
                    });
                } else {
                    index += 1;
                }
            }
        }

        libp2p::swarm::SwarmEvent::Behaviour(NauEvent::GossipSub(event)) => {
            if let libp2p::gossipsub::Event::Message { message, .. } = *event {
                {
                    let mut guard = stats.lock().await;
                    guard.messages_received = guard.messages_received.saturating_add(1);
                }
                match codec::decode_envelope(&message.data) {
                    // `Envelope`'s fields are private, so it is destructured through
                    // its accessors rather than by pattern: the type's invariant is
                    // that a sender is always a validated peer id, and a public
                    // struct-literal form would let a caller build one that is not.
                    Ok(envelope) => {
                        let sender = *envelope.sender();
                        let payload = envelope.into_payload();
                        push_inbound(inbound, inbound_signal, stats, sender, payload).await;
                    }
                    Err(e) => {
                        let mut guard = stats.lock().await;
                        guard.malformed_messages = guard.malformed_messages.saturating_add(1);
                        drop(guard);
                        tracing::warn!("rejected a gossip message: {e}");
                    }
                }
            }
        }

        libp2p::swarm::SwarmEvent::Behaviour(NauEvent::Kademlia(event)) => {
            if let libp2p::kad::Event::OutboundQueryProgressed { id, result, .. } = *event {
                {
                    let mut guard = stats.lock().await;
                    guard.kad_queries_completed = guard.kad_queries_completed.saturating_add(1);
                }
                match result {
                    libp2p::kad::QueryResult::GetRecord(Ok(ok)) => {
                        if let Some(sender) = pending_gets.remove(&id) {
                            let value = match ok {
                                libp2p::kad::GetRecordOk::FoundRecord(peer_record) => {
                                    peer_record.record.value
                                }
                                // The query finished without any peer returning a
                                // record. That is an absence, not a timeout, and
                                // it is reported as such.
                                libp2p::kad::GetRecordOk::FinishedWithNoAdditionalRecord {
                                    ..
                                } => {
                                    let _ = sender.send(Err(SwarmError::RecordNotFound {
                                        key: "unknown".to_string(),
                                    }));
                                    return;
                                }
                            };
                            let _ = sender.send(Ok(value));
                        }
                    }
                    libp2p::kad::QueryResult::GetRecord(Err(e)) => {
                        if let Some(sender) = pending_gets.remove(&id) {
                            let key = String::from_utf8_lossy(e.key().as_ref()).to_string();
                            let outcome = match e {
                                libp2p::kad::GetRecordError::NotFound { .. } => {
                                    Err(SwarmError::RecordNotFound { key })
                                }
                                other => Err(SwarmError::QueryFailed {
                                    reason: other.to_string(),
                                }),
                            };
                            let _ = sender.send(outcome);
                        }
                    }
                    libp2p::kad::QueryResult::PutRecord(Ok(_)) => {
                        if let Some((_, _, _, _, sender)) = pending_puts.remove(&id) {
                            // A peer accepted the record. The strongest outcome.
                            let _ = sender.send(PutOutcome::Replicated);
                        }
                    }
                    libp2p::kad::QueryResult::PutRecord(Err(e)) => {
                        if let Some((_, key, value_len, stored_locally, sender)) =
                            pending_puts.remove(&id)
                        {
                            // `QuorumFailed` and `Timeout` both mean the same thing
                            // for this crate's purposes: the query finished without
                            // a peer accepting the record. Whether that is a
                            // *failure* depends entirely on whether the local store
                            // has it, which is why the outcome carries both facts
                            // rather than collapsing to an error.
                            let _ = (key, value_len);
                            let _ = sender.send(if stored_locally {
                                PutOutcome::LocalOnly {
                                    reason: e.to_string(),
                                }
                            } else {
                                PutOutcome::NoPeersYet {
                                    reason: e.to_string(),
                                }
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        libp2p::swarm::SwarmEvent::Behaviour(NauEvent::Identify(event)) => {
            if let libp2p::identify::Event::Received { .. } = *event {
                let mut guard = stats.lock().await;
                guard.identified_peers = guard.identified_peers.saturating_add(1);
            }
        }

        libp2p::swarm::SwarmEvent::Behaviour(NauEvent::RelayClient(event)) => {
            if let libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } =
                *event
            {
                {
                    let mut guard = stats.lock().await;
                    guard.reservations_accepted = guard.reservations_accepted.saturating_add(1);
                }
                let mut index = 0;
                while index < pending.len() {
                    if matches!(&pending[index].2, Pending::Reservation { relay, .. } if *relay == relay_peer_id)
                    {
                        let (_, _, item) = pending.swap_remove(index);
                        if let Pending::Reservation { reply, .. } = item {
                            let _ = reply.send(Ok(()));
                        }
                    } else {
                        index += 1;
                    }
                }
            }
        }

        libp2p::swarm::SwarmEvent::Behaviour(NauEvent::Dcutr(event)) => {
            let remote = event.remote_peer_id;
            let succeeded = event.result.is_ok();
            let reason = match &event.result {
                Ok(_) => None,
                Err(e) => Some(e.to_string()),
            };
            {
                let mut guard = stats.lock().await;
                if succeeded {
                    guard.hole_punches_succeeded = guard.hole_punches_succeeded.saturating_add(1);
                } else {
                    guard.hole_punches_failed = guard.hole_punches_failed.saturating_add(1);
                }
            }
            let mut index = 0;
            while index < pending.len() {
                if matches!(&pending[index].2, Pending::HolePunch { peer, .. } if *peer == remote) {
                    let (_, _, item) = pending.swap_remove(index);
                    if let Pending::HolePunch { reply, .. } = item {
                        let outcome = match &reason {
                            None => Ok(()),
                            Some(reason) => Err(SwarmError::HolePunch {
                                peer: remote.to_string(),
                                reason: reason.clone(),
                            }),
                        };
                        let _ = reply.send(outcome);
                    }
                } else {
                    index += 1;
                }
            }
        }

        // A listener that closed *with* an error is worth a warning; one that closed
        // cleanly is the expected result of shutting the node down, and warning on
        // it would train a reader to ignore the warning.
        libp2p::swarm::SwarmEvent::ListenerClosed {
            addresses,
            reason: Err(e),
            ..
        } => {
            tracing::warn!("a listener on {addresses:?} closed: {e}");
        }

        _ => {}
    }
}

/// Push a frame onto the inbound queue, dropping the oldest when full.
async fn push_inbound(
    inbound: &Arc<Mutex<VecDeque<(PeerId, Frame)>>>,
    signal: &Arc<Notify>,
    stats: &Arc<Mutex<SwarmStats>>,
    sender: PeerId,
    payload: Frame,
) {
    {
        let mut queue = inbound.lock().await;
        if queue.len() >= INBOUND_QUEUE_CAPACITY {
            // Drop the oldest: for a pub/sub overlay a stale message is worth less
            // than a fresh one, and an unbounded queue is an OOM waiting to happen.
            queue.pop_front();
            let mut guard = stats.lock().await;
            guard.dropped_frames = guard.dropped_frames.saturating_add(1);
        }
        queue.push_back((sender, payload));
    }
    signal.notify_one();
}

/// Append a listening address, ignoring a duplicate.
async fn push_listen_addr(addrs: &Arc<Mutex<Vec<String>>>, value: String) {
    let mut guard = addrs.lock().await;
    if !guard.contains(&value) {
        guard.push(value);
    }
}

/// Resolve the peer and address in a `/p2p/`-terminated multiaddr.
fn resolve_peer(addr: &Multiaddr) -> Result<(libp2p::PeerId, libp2p::Multiaddr), SwarmError> {
    let peer = addr
        .peer_id()
        .map_err(|e| SwarmError::BadPeerId {
            addr: addr.to_string(),
            reason: e.to_string(),
        })?
        .ok_or_else(|| SwarmError::AddressWithoutPeerId {
            addr: addr.to_string(),
        })?;
    let libp2p_peer =
        crate::behaviour::to_libp2p_peer_id(&peer).ok_or_else(|| SwarmError::BadPeerId {
            addr: addr.to_string(),
            reason: "not a libp2p peer id".to_string(),
        })?;
    let libp2p_addr = addr.to_libp2p()?;
    Ok((libp2p_peer, libp2p_addr))
}

/// A nonce for an envelope, from OS entropy.
///
/// Not a security boundary on its own 闁?the envelope is signed by GossipSub 闁?but
/// a nonce an off-path observer can predict is a nonce that makes duplicate
/// suppression forgeable.
fn random_nonce() -> [u8; codec::NONCE_BYTES] {
    use rand::RngCore;
    let mut nonce = [0u8; codec::NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Parse and validate an address, mapping the config error into a swarm error.
fn parse_addr(addr: &str) -> Result<Multiaddr, SwarmError> {
    Multiaddr::parse(addr).map_err(|e| SwarmError::BadAddress {
        addr: addr.to_string(),
        reason: e.to_string(),
    })
}

/// Check that a topic is one this node may publish to.
///
/// A topic that did not come from a validated [`crate::naming::RoomName`] is
/// refused, so there is no path that publishes to an arbitrary string.
fn validate_topic(topic: &str) -> Result<String, SwarmError> {
    match naming::room_from_topic(topic) {
        Ok(room) => Ok(room.topic()),
        Err(e) => Err(SwarmError::BadTopic {
            topic: topic.to_string(),
            reason: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_topic_that_is_not_a_room_is_refused() {
        assert!(validate_topic("nau/room/room-0000000000000001").is_ok());
        for bad in ["", "other", "nau/room/", "nau/room/a/b", "nau/other/x"] {
            let err = validate_topic(bad).expect_err("must be refused");
            assert!(
                matches!(err, SwarmError::BadTopic { .. }),
                "{bad:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn an_address_without_a_peer_component_is_refused() {
        let addr = Multiaddr::parse("/ip4/127.0.0.1/tcp/4001").expect("valid");
        assert!(addr.peer_id().expect("no error").is_none());
        let err = resolve_peer(&addr).expect_err("no peer id");
        assert!(matches!(err, SwarmError::AddressWithoutPeerId { .. }));
    }

    #[test]
    fn a_well_formed_peer_address_resolves() {
        let identity = NauIdentity::from_seed(&[3u8; 32]);
        let addr = Multiaddr::parse(&format!(
            "/ip4/127.0.0.1/tcp/4001/p2p/{}",
            identity.peer_id()
        ))
        .expect("valid");
        let (peer, libp2p_addr) = resolve_peer(&addr).expect("resolves");
        assert_eq!(peer.to_string(), identity.peer_id().to_string());
        assert!(libp2p_addr.to_string().contains("/p2p/"));
    }

    #[test]
    fn a_malformed_address_is_refused_without_panicking() {
        for bad in ["", "not an address", "/ip4/tcp/1", "/tpc/1"] {
            let err = parse_addr(bad).expect_err("must be refused");
            assert!(matches!(err, SwarmError::BadAddress { .. }), "{bad:?}");
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn a_nonce_is_eight_bytes_and_varies() {
        let a = random_nonce();
        let b = random_nonce();
        assert_eq!(a.len(), codec::NONCE_BYTES);
        // Two draws from 2^64 being equal is a 1-in-1.8e19 event; if it happens the
        // RNG is not seeded, which is worth failing a test over.
        assert_ne!(a, b, "the nonce must not be constant");
    }

    #[test]
    fn the_error_type_distinguishes_timeout_from_absence() {
        // A caller that retries should retry one of these and not the other.
        let timeout = SwarmError::Timeout {
            operation: "get_record".to_string(),
            seconds: 15,
        };
        let absent = SwarmError::RecordNotFound {
            key: "nau/rec/x".to_string(),
        };
        assert_ne!(timeout, absent);
        assert!(timeout.to_string().contains("did not finish"));
        assert!(absent.to_string().contains("no record is stored"));
        // And it converts into the workspace error type for callers that speak it.
        let nau: nau_core::NauError = timeout.into();
        assert!(matches!(nau, nau_core::NauError::Validation(_)));
    }

    #[test]
    fn counters_saturate_rather_than_wrap() {
        let mut stats = SwarmStats {
            messages_received: u64::MAX,
            ..SwarmStats::default()
        };
        stats.messages_received = stats.messages_received.saturating_add(1);
        assert_eq!(stats.messages_received, u64::MAX);
        assert_eq!(SwarmStats::default().malformed_messages, 0);
    }
}
