//! The [`nau_net::Transport`] adapter over the libp2p swarm.
//!
//! ## Which port operations map onto a swarm, and which do not
//!
//! [`nau_net::Transport`] was written for a *connection-oriented* transport
//! ([`TcpTransport`](nau_net::TcpTransport)) where `send` addresses one peer over
//! one socket. A swarm is not that, and pretending otherwise is how an adapter
//! starts lying. Here is the mapping, operation by operation, including the parts
//! that are approximations:
//!
//! | port operation | swarm operation | fidelity |
//! |---|---|---|
//! | [`Transport::local_id`] | `PeerId` derived from the same Ed25519 key as the DID | **exact** — see [`crate::identity`] |
//! | [`Transport::send`] | GossipSub publish on the configured room topic | **approximated**: pub/sub is one-to-many, so a send is delivered to every subscriber, not only `to` |
//! | [`Transport::recv`] | the next decoded GossipSub envelope | **exact** for the payload; the returned sender is the envelope's *claimed* origin, not the forwarding peer |
//! | [`Transport::connected`] | `Swarm::connected_peers` | **approximated**: "connected" is a live libp2p connection, which is stricter than "can be gossiped to" |
//!
//! ### `send` and the `to` argument
//!
//! `send(&to, frame)` publishes on the room topic and **rejects** the send when
//! `to` is not currently connected. That check is what keeps the approximation
//! honest: a caller cannot use this transport to send a unicast frame to an
//! arbitrary peer, only to a peer it is actually connected to, and even then the
//! frame is broadcast to the whole topic. A caller that needs real unicast needs a
//! request/response protocol, which this crate does not provide and does not
//! pretend to.
//!
//! Documenting this is the point. The defect this project exists to correct was a
//! `HashMap` named `GossipSub`; an adapter that quietly turned broadcast into
//! something called "send to one peer" would be the same shape of mistake with
//! better manners.
//!
//! ## The `PeerId` type mismatch, and why it is not papered over
//!
//! `nau_net::PeerId` is an opaque *label*, validated to ASCII letters, digits and
//! `-_.:/`. A libp2p peer id is a 36-byte multihash. They are different types with
//! the same name, and both are needed here:
//!
//! * the label form is `libp2p:<base58-encoded peer id>`, produced by
//!   [`peer_label`], so the port's charset rules are satisfied and a label is
//!   recognisable as a libp2p id in a log line;
//! * the *typed* form is [`crate::identity::PeerId`], which is what
//!   [`crate::identity::NauIdentity`] derives and what maps to a DID.
//!
//! [`peer_label`] and [`peer_from_label`] convert between them, and a label that
//! was not produced by `peer_label` (a `tcp://` address, say) is refused rather
//! than silently reinterpreted.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use nau_core::Result as NauResult;
use nau_net::{Frame, Transport};

use crate::config::Libp2pConfig;
use crate::identity;
use crate::swarm::{Libp2pNode, SwarmError};

/// Prefix that marks a [`nau_net::PeerId`] label as a libp2p peer id.
pub const LABEL_PREFIX: &str = "libp2p:";

/// Counters specific to the adapter, on top of [`crate::swarm::SwarmStats`].
///
/// `broadcasts` rather than `sends` is deliberate: every successful `send` on this
/// adapter is a broadcast, and naming the counter after what happened makes the
/// approximation visible in telemetry rather than only in a doc comment.
#[derive(Debug, Default)]
pub struct TransportStats {
    /// Sends rejected because the target peer was not connected.
    pub rejected_disconnected: AtomicU64,
    /// Frames actually published.
    pub broadcasts: AtomicU64,
    /// Callers that asked for a frame and got a timeout.
    pub recv_timeouts: AtomicU64,
}

impl TransportStats {
    /// A snapshot, for assertions and for logging.
    pub fn snapshot(&self) -> TransportStatsSnapshot {
        TransportStatsSnapshot {
            rejected_disconnected: self.rejected_disconnected.load(Ordering::Relaxed),
            broadcasts: self.broadcasts.load(Ordering::Relaxed),
            recv_timeouts: self.recv_timeouts.load(Ordering::Relaxed),
        }
    }
}

/// A consistent read of [`TransportStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportStatsSnapshot {
    /// Sends rejected because the target peer was not connected.
    pub rejected_disconnected: u64,
    /// Frames actually published.
    pub broadcasts: u64,
    /// Receive calls that timed out.
    pub recv_timeouts: u64,
}

/// The `nau_net::Transport` implementation backed by a real libp2p swarm.
///
/// One room topic carries the frames, so a caller must configure at least one room
/// in the [`Libp2pConfig`] the transport was built from; constructing one without
/// a room fails rather than defaulting to a topic nobody is subscribed to.
pub struct Libp2pTransport {
    /// The running node.
    node: Arc<Libp2pNode>,
    /// The topic frames are published on.
    topic: String,
    /// This endpoint's label.
    local_label: nau_net::PeerId,
    /// Counters.
    stats: Arc<TransportStats>,
}

impl std::fmt::Debug for Libp2pTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Libp2pTransport")
            .field("local_id", &self.local_label)
            .field("topic", &self.topic)
            .field("peer_id", &self.node.peer_id().to_string())
            .finish()
    }
}

impl Libp2pTransport {
    /// Start a node and wrap it as a transport.
    ///
    /// Uses the room named by `config.rooms[0]` as the frame topic. A configuration
    /// with no room is refused: publishing to no topic is a transport that accepts
    /// frames and delivers none.
    pub async fn start(config: Libp2pConfig) -> Result<Arc<Self>, SwarmError> {
        let topic = config.topics().first().cloned().ok_or_else(|| {
            SwarmError::Config(
                "the transport needs at least one room to carry frames, and none is configured"
                    .to_string(),
            )
        })?;
        let node = Arc::new(Libp2pNode::spawn(config).await?);
        let local_label = peer_label(node.peer_id());
        Ok(Arc::new(Self {
            node,
            topic,
            local_label,
            stats: Arc::new(TransportStats::default()),
        }))
    }

    /// Wrap an already-running node.
    pub fn from_node(node: Arc<Libp2pNode>) -> Result<Arc<Self>, SwarmError> {
        let topic = node.config().topics().first().cloned().ok_or_else(|| {
            SwarmError::Config(
                "the transport needs at least one room to carry frames, and none is configured"
                    .to_string(),
            )
        })?;
        let local_label = peer_label(node.peer_id());
        Ok(Arc::new(Self {
            node,
            topic,
            local_label,
            stats: Arc::new(TransportStats::default()),
        }))
    }

    /// The underlying node, for the operations the port does not express
    /// (records, relay reservations, NAT status, hole punching).
    pub fn node(&self) -> &Arc<Libp2pNode> {
        &self.node
    }

    /// The topic frames are carried on.
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// The adapter counters.
    pub fn stats(&self) -> &Arc<TransportStats> {
        &self.stats
    }

    /// This endpoint's peer id in this crate's typed form.
    pub fn typed_peer_id(&self) -> identity::PeerId {
        self.node.nau_peer_id()
    }

    /// This endpoint's `did:nau:` identifier, the other view of the same key.
    pub fn did(&self) -> nau_core::Did {
        self.node.identity().did()
    }
}

#[async_trait]
impl Transport for Libp2pTransport {
    /// Publish `frame`, provided `to` is connected.
    ///
    /// Rejects a `to` that is not connected — a broadcast that claims to be a
    /// unicast is the approximation this adapter refuses to hide.
    ///
    /// ## `NoPeersSubscribedToTopic`
    ///
    /// GossipSub's mesh is formed by its heartbeat, so there is a short window after
    /// two peers connect in which neither has the other in its mesh for this topic.
    /// Publishing in that window fails with `NoPeersSubscribedToTopic`, which is a
    /// *timing* answer rather than a delivery failure. It is mapped to
    /// [`SwarmError::Retryable`] with a message that says so, instead of being
    /// reported as a plain publish failure — a caller that cannot tell the two apart
    /// will either give up on a working network or retry forever on a broken one.
    async fn send(&self, to: &nau_net::PeerId, frame: Frame) -> NauResult<()> {
        let target = peer_from_label(to)?;
        let connected = self
            .node
            .connected()
            .await
            .iter()
            .any(|peer| *peer == target);
        if !connected {
            self.stats
                .rejected_disconnected
                .fetch_add(1, Ordering::Relaxed);
            return Err(swarm_to_nau(SwarmError::Dial {
                addr: to.to_string(),
                reason: "not connected, and this transport refuses to broadcast on behalf of a \
                         peer it is not connected to"
                    .to_string(),
            }));
        }
        match self.node.publish(&self.topic, &frame).await {
            Ok(_queued) => {
                self.stats.broadcasts.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(SwarmError::Publish { topic, reason })
                if reason.contains("NoPeersSubscribedToTopic") =>
            {
                Err(swarm_to_nau(SwarmError::Retryable {
                    operation: format!("publish on {topic}"),
                    reason: "no peer is in this topic's GossipSub mesh yet; the mesh is formed by \
                             the heartbeat, so this is a timing answer and the send should be \
                             retried"
                        .to_string(),
                }))
            }
            Err(e) => Err(swarm_to_nau(e)),
        }
    }

    /// Take the next frame, waiting at most `timeout`.
    ///
    /// `Ok(None)` on timeout, which is the port's contract: a quiet period is
    /// normal operation, not a failure. The returned peer is the label of the
    /// envelope's claimed origin.
    async fn recv(&self, timeout: Duration) -> NauResult<Option<(nau_net::PeerId, Frame)>> {
        match self.node.recv_frame(timeout).await {
            Ok(Some((sender, frame))) => Ok(Some((typed_to_label(&sender), frame))),
            Ok(None) => {
                self.stats.recv_timeouts.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            }
            Err(e) => Err(swarm_to_nau(e)),
        }
    }

    /// This endpoint's label.
    ///
    /// The label is `libp2p:<peer id>`; the `did:nau:` identifier for the same key
    /// is available from [`Libp2pTransport::did`], and
    /// [`crate::identity::NauIdentity::from_did_and_public_key`] checks that the
    /// two really describe one key rather than trusting the pairing.
    fn local_id(&self) -> nau_net::PeerId {
        self.local_label.clone()
    }

    /// The connected peers, as labels, in ascending order.
    async fn connected(&self) -> Vec<nau_net::PeerId> {
        let mut labels: Vec<nau_net::PeerId> = self
            .node
            .connected()
            .await
            .iter()
            .map(typed_to_label)
            .collect();
        // The port says "in ascending id order"; `nau_net::PeerId` is `Ord`.
        labels.sort();
        labels
    }
}

/// The `nau_net::PeerId` label for a typed peer id.
pub fn typed_to_label(peer: &identity::PeerId) -> nau_net::PeerId {
    peer_label_from_str(&peer.to_string())
}

/// The `nau_net::PeerId` label for a libp2p peer id.
pub fn peer_label(peer: &libp2p::PeerId) -> nau_net::PeerId {
    peer_label_from_str(&peer.to_string())
}

/// Build a label from a bare peer-id string.
///
/// A base58 peer id is already inside the port's accepted charset, but the prefix
/// is added anyway so that a label in a log line says which transport produced it.
///
/// `nau_net::PeerId::parse` rejects only the empty string, anything over 255 bytes,
/// and non-`[A-Za-z0-9-_.:/]` characters. `libp2p:` plus a base58btc peer id is
/// 7 + 46 = 53 characters of that charset, so the parse cannot fail for a value
/// this module produces; [`fallback_label`] is nevertheless used instead of an
/// `expect` so that no path here panics, and
/// `the_fallback_label_parses` proves the fallback is valid.
fn peer_label_from_str(peer_id: &str) -> nau_net::PeerId {
    let label = format!("{LABEL_PREFIX}{peer_id}");
    match nau_net::PeerId::parse(&label) {
        Ok(label) => label,
        Err(_) => fallback_label(),
    }
}

/// A label that is always valid, used when a peer id cannot be rendered.
///
/// Unreachable for values this crate derives — see [`peer_label_from_str`] — but a
/// total function is preferable to a panic in a library, and a label that names the
/// problem is more useful in a log line than a crash.
fn fallback_label() -> nau_net::PeerId {
    match nau_net::PeerId::parse("libp2p:unrepresentable-peer-id") {
        Ok(label) => label,
        Err(_) => empty_safe_label(),
    }
}

/// A label with no characters at all that could be rejected.
///
/// Still unreachable: `parse` accepts this input. It exists only so that
/// [`fallback_label`] is total.
fn empty_safe_label() -> nau_net::PeerId {
    match nau_net::PeerId::parse("libp2p:x") {
        Ok(label) => label,
        Err(_) => {
            // `parse` cannot reject a non-empty ASCII token; if it ever does, the
            // process is in a state this crate cannot describe, and returning a
            // wrong label would be worse than stopping. Reaching here is provably
            // impossible, which is asserted by `the_fallback_label_parses`.
            std::process::abort()
        }
    }
}

/// Turn a label back into a typed peer id.
///
/// Refuses a label that was not produced by [`peer_label`], rather than
/// reinterpreting a `tcp://` address as a peer id and dialling nothing.
pub fn peer_from_label(label: &nau_net::PeerId) -> NauResult<identity::PeerId> {
    let raw = label.as_str().strip_prefix(LABEL_PREFIX).ok_or_else(|| {
        nau_core::NauError::Validation(format!(
            "`{label}` is not a libp2p peer label (expected a `{LABEL_PREFIX}` prefix); a \
                 `tcp://` address is a socket, not a peer id"
        ))
    })?;
    identity::PeerId::parse(raw).map_err(|e| nau_core::NauError::Validation(e.to_string()))
}

/// Map a swarm error into the workspace error type, keeping the message.
fn swarm_to_nau(err: SwarmError) -> nau_core::NauError {
    nau_core::NauError::Validation(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_round_trips_through_the_port_type() {
        let typed = identity::NauIdentity::from_seed(&[1u8; 32]).peer_id();
        let label = typed_to_label(&typed);
        assert!(label.as_str().starts_with(LABEL_PREFIX));
        assert!(label.as_str().contains(&typed.to_string()));
        assert_eq!(peer_from_label(&label).expect("round trip"), typed);
    }

    #[test]
    fn a_label_from_another_transport_is_refused() {
        // The TCP transport labels a connection with its socket address. Feeding
        // that to this adapter must be an error, not an attempt to dial a "peer"
        // called `tcp://127.0.0.1:1`.
        let label = nau_net::PeerId::parse("tcp://127.0.0.1:5555").expect("valid label");
        let err = peer_from_label(&label).expect_err("not a libp2p label");
        assert!(err.to_string().contains("is not a libp2p peer label"));
        // An opaque token is refused too.
        let opaque = nau_net::PeerId::parse("node-7").expect("valid label");
        assert!(peer_from_label(&opaque).is_err());
    }

    #[test]
    fn a_malformed_peer_id_inside_a_label_is_refused() {
        // Every one of these satisfies `nau_net::PeerId`'s charset (so the label
        // reaches this adapter) and is not a 38-byte identity multihash (so the
        // conversion refuses it). A case that fails the *charset* never gets here
        // at all, which is itself worth knowing: `libp2p:!!!` is rejected by
        // `nau_net::PeerId::parse`, not by this function.
        for bad in [
            "libp2p:",
            "libp2p:x",
            "libp2p:1111",
            "libp2p:not-a-real-peer-id",
            "libp2p:QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
        ] {
            let label = nau_net::PeerId::parse(bad).unwrap_or_else(|e| panic!("{bad}: {e}"));
            assert!(peer_from_label(&label).is_err(), "{bad} must be refused");
        }
        // And a label that cannot even be built is refused earlier, by the port.
        assert!(nau_net::PeerId::parse("libp2p:!!!").is_err());
    }

    #[test]
    fn counters_start_at_zero_and_are_readable() {
        let stats = TransportStats::default();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.broadcasts, 0);
        assert_eq!(snapshot.rejected_disconnected, 0);
        assert_eq!(snapshot.recv_timeouts, 0);
        stats.broadcasts.fetch_add(3, Ordering::Relaxed);
        assert_eq!(stats.snapshot().broadcasts, 3);
    }

    #[test]
    fn the_fallback_label_parses() {
        // This is what makes `empty_safe_label`'s unreachable branch unreachable,
        // which is what makes `std::process::abort()` there dead code rather than a
        // live hazard.
        let fallback = fallback_label();
        assert_eq!(fallback.as_str(), "libp2p:unrepresentable-peer-id");
        assert!(nau_net::PeerId::parse("libp2p:x").is_ok());
        // The fallback is not mistaken for a real peer: it carries no valid id.
        assert!(peer_from_label(&fallback).is_err());
    }

    #[test]
    fn the_label_helper_is_total() {
        // Every derived peer id must produce a parseable label: the transport's
        // `local_id` has no way to report an error.
        for seed_byte in [0u8, 1, 2, 0x7f, 0xff] {
            let typed = identity::NauIdentity::from_seed(&[seed_byte; 32]).peer_id();
            let label = typed_to_label(&typed);
            assert!(peer_from_label(&label).is_ok());
            assert!(label.as_str().len() <= nau_net::MAX_PEER_ID_LEN);
        }
    }
}
