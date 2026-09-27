//! Protocol and topic names: the strings that decide who can talk to whom.
//!
//! ## Why names are a module and not a `const`
//!
//! Every libp2p protocol is identified by a string, and two nodes that disagree
//! about that string simply never see each other — the failure is a silent
//! timeout, not an error. Three separate things have to agree, and each of them
//! is derived here rather than written out at the call site:
//!
//! | what | value | who must agree |
//! |---|---|---|
//! | Kademlia protocol | [`KAD_PROTOCOL`] (`/nau/kad/1.0.0`) | every node on this network |
//! | GossipSub topic | [`room_topic`] (`nau/room/<room>`) | every node in that room |
//! | record key namespace | [`record_key`] (`nau/rec/…`) | every node storing that record |
//!
//! ## Upstream defect this closes
//!
//! agent-universe v2.5.6 constructed topic strings with
//! `format!("room-{}", room)` at several call sites and never validated the room
//! component. A room name containing the separator therefore produced topics that
//! *looked* like one room and behaved as another (`room-a/b` collides with the
//! `room-a` prefix of a two-level scheme), and a room name containing whitespace
//! or a newline reached the wire and the logs unescaped.
//! `// upstream v2.5.6 fix: room and topic names are validated, and the
//! validation rejects the separator that made two rooms collide.`

use std::fmt;

use nau_net::PeerId;

use crate::identity;

/// The Kademlia protocol identifier this network speaks.
///
/// The leading `/` is libp2p's convention for an application protocol. Both nodes
/// must use the same string; a mismatch is not an error, it is silence.
pub const KAD_PROTOCOL: &str = "/nau/kad/1.0.0";

/// Prefix for GossipSub topics carrying room traffic.
pub const ROOM_TOPIC_PREFIX: &str = "nau/room/";

/// Prefix for Kademlia record keys, keeping this application's records in their
/// own keyspace inside the shared DHT.
pub const RECORD_KEY_PREFIX: &str = "nau/rec/";

/// Longest accepted room name, in bytes.
pub const MAX_ROOM_NAME_BYTES: usize = 128;

/// Longest accepted record key, in bytes.
pub const MAX_RECORD_KEY_BYTES: usize = 256;

/// Longest accepted topic name, in bytes (the full `nau/room/…` string).
pub const MAX_TOPIC_BYTES: usize = ROOM_TOPIC_PREFIX.len() + MAX_ROOM_NAME_BYTES;

/// Every way a name can be rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// The room name was empty.
    #[error("room name must not be empty")]
    EmptyRoom,
    /// The room name exceeded [`MAX_ROOM_NAME_BYTES`].
    #[error("room name of {got} bytes exceeds the {MAX_ROOM_NAME_BYTES}-byte limit")]
    RoomTooLong {
        /// The offending length.
        got: usize,
    },
    /// The room name was too short to be a meaningful grouping.
    #[error("room name `{room}` is shorter than the {min}-byte minimum")]
    RoomTooShort {
        /// The offending room name.
        room: String,
        /// The minimum.
        min: usize,
    },
    /// The room name contained a character that is not allowed.
    #[error(
        "room name `{room}` may only contain ASCII letters, digits and `-_`; found `{found}` \
         (the `/` and `:` separators are refused because they make two room names collide)"
    )]
    RoomCharset {
        /// The offending room name.
        room: String,
        /// The first offending character, escaped for display.
        found: String,
    },
    /// The record key was empty.
    #[error("record key must not be empty")]
    EmptyRecordKey,
    /// The record key exceeded [`MAX_RECORD_KEY_BYTES`].
    #[error("record key of {got} bytes exceeds the {MAX_RECORD_KEY_BYTES}-byte limit")]
    RecordKeyTooLong {
        /// The offending length.
        got: usize,
    },
    /// The record key contained a control character or whitespace.
    #[error("record key contains a control character or whitespace")]
    RecordKeyControl,
    /// A topic string arrived that does not start with [`ROOM_TOPIC_PREFIX`].
    #[error("`{topic}` is not a nau room topic (expected a `{ROOM_TOPIC_PREFIX}` prefix)")]
    NotARoomTopic {
        /// The rejected topic.
        topic: String,
    },
    /// A string that is not a usable [`nau_net::PeerId`] label.
    ///
    /// Used both for room names and, by [`crate::config`], for peer-id labels: the
    /// label type is the same in both cases and the charset rule is what is being
    /// reported.
    #[error("`{value}` does not map onto a valid peer id label: {reason}")]
    NotAPeerId {
        /// The offending value.
        value: String,
        /// Why the mapping failed.
        reason: String,
    },
}

/// A validated room name.
///
/// Constructing one is the only way to get a topic string, so there is no path
/// that publishes to an unvalidated topic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoomName(String);

impl RoomName {
    /// Validate and wrap a room name.
    ///
    /// Allowed: ASCII letters, digits, `-` and `_`, at least 4 and at most
    /// [`MAX_ROOM_NAME_BYTES`] bytes. `_` and `-` are allowed because room names
    /// are generated from the topology's room id, and both appear in the shapes
    /// humans write. `/` and `:` are refused because they are the separators that
    /// make two distinct rooms produce one topic.
    pub fn parse(room: &str) -> Result<Self, NameError> {
        if room.is_empty() {
            return Err(NameError::EmptyRoom);
        }
        if room.len() > MAX_ROOM_NAME_BYTES {
            return Err(NameError::RoomTooLong { got: room.len() });
        }
        if room.len() < MIN_ROOM_NAME_BYTES {
            return Err(NameError::RoomTooShort {
                room: room.to_string(),
                min: MIN_ROOM_NAME_BYTES,
            });
        }
        if let Some(bad) = room
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
        {
            return Err(NameError::RoomCharset {
                room: room.to_string(),
                found: bad.escape_default().to_string(),
            });
        }
        Ok(Self(room.to_string()))
    }

    /// Derive the room name for a node, from the same hash the overlay topology
    /// uses, so that the room a node publishes in is the room the topology places
    /// it in.
    ///
    /// `nau_net::LayeredTopology::room_of` is the single source of truth for room
    /// membership; this only renders its result as a name, with a fixed width so
    /// that room `7` and room `007` cannot be different strings.
    ///
    /// The topology is built with the maximum fanout on purpose: the fanout bounds
    /// how many neighbours a node keeps within its room, not which room it belongs
    /// to, so the room assignment is the same for every fanout. Building it with a
    /// smaller value would make this function's answer depend on a parameter that
    /// does not affect it.
    pub fn for_node(node: &PeerId) -> Result<Self, NameError> {
        let topology =
            nau_net::LayeredTopology::new(nau_net::topology::MAX_FANOUT).map_err(|e| {
                NameError::NotAPeerId {
                    value: node.to_string(),
                    reason: format!("could not build the reference topology: {e}"),
                }
            })?;
        let room = topology.room_of(node);
        let name = format!("room-{room:016x}");
        // `room-` plus 16 hex digits is always in the accepted charset and inside
        // the length limit, so this cannot fail; it returns a `Result` so that the
        // conversion has no panic path.
        Self::parse(&name)
    }

    /// The room name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The GossipSub topic for this room.
    pub fn topic(&self) -> String {
        room_topic(&self.0)
    }

    /// The `nau_net::PeerId` label for this room, so that room-keyed maps in the
    /// existing overlay code can be reused unchanged.
    pub fn as_peer_id(&self) -> Result<PeerId, NameError> {
        PeerId::parse(&self.0).map_err(|e| NameError::NotAPeerId {
            value: self.0.clone(),
            reason: e.to_string(),
        })
    }
}

impl fmt::Display for RoomName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Shortest accepted room name, in bytes.
pub const MIN_ROOM_NAME_BYTES: usize = 4;

impl std::str::FromStr for RoomName {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Self, NameError> {
        Self::parse(s)
    }
}

/// The GossipSub topic for a room name.
///
/// Does not validate: callers that have a `&str` from outside should build a
/// [`RoomName`] first. Kept public because the topic format is part of the wire
/// contract, and a test needs to assert it.
pub fn room_topic(room: &str) -> String {
    format!("{ROOM_TOPIC_PREFIX}{room}")
}

/// Recover the room name from a topic string.
pub fn room_from_topic(topic: &str) -> Result<RoomName, NameError> {
    let room = topic
        .strip_prefix(ROOM_TOPIC_PREFIX)
        .ok_or_else(|| NameError::NotARoomTopic {
            topic: topic.to_string(),
        })?;
    RoomName::parse(room)
}

/// The Kademlia record key for an application key, in this network's keyspace.
///
/// Returns bytes because that is what `libp2p_kad::Record::new` takes. The key is
/// `nau/rec/<key>`; the prefix keeps this application's records out of the shared
/// DHT keyspace so that an unrelated `libp2p` application cannot read or clobber
/// them by publishing the same bare key.
pub fn record_key(key: &str) -> Result<Vec<u8>, NameError> {
    validate_record_key(key)?;
    Ok(format!("{RECORD_KEY_PREFIX}{key}").into_bytes())
}

/// Reject a record key that cannot safely round-trip through the DHT.
fn validate_record_key(key: &str) -> Result<(), NameError> {
    if key.is_empty() {
        return Err(NameError::EmptyRecordKey);
    }
    if key.len() > MAX_RECORD_KEY_BYTES {
        return Err(NameError::RecordKeyTooLong { got: key.len() });
    }
    if key
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || !c.is_ascii())
    {
        return Err(NameError::RecordKeyControl);
    }
    Ok(())
}

/// The peer id string this node advertises, derived from its Ed25519 key.
///
/// A thin re-export so callers building bootstrap multiaddrs do not have to reach
/// into [`crate::identity`] to name the trailing `/p2p/…` component.
pub fn peer_id_string(public_key: &[u8; identity::ED25519_PUBLIC_KEY_BYTES]) -> String {
    identity::peer_id_string(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_protocol_and_prefixes_are_what_the_wire_expects() {
        // These strings are a compatibility surface: changing one silently
        // partitions the network, so they are asserted rather than described.
        assert_eq!(KAD_PROTOCOL, "/nau/kad/1.0.0");
        assert!(
            KAD_PROTOCOL.starts_with('/'),
            "libp2p app protocols start with `/`"
        );
        assert_eq!(ROOM_TOPIC_PREFIX, "nau/room/");
        assert_eq!(RECORD_KEY_PREFIX, "nau/rec/");
        assert_eq!(
            room_topic("room-0000000000000001"),
            "nau/room/room-0000000000000001"
        );
    }

    #[test]
    fn room_names_are_validated() {
        for good in ["room-1", "ROOM_9", "a_b-c9", "abcdef"] {
            let room = RoomName::parse(good).unwrap_or_else(|e| panic!("{good} rejected: {e}"));
            assert_eq!(room.as_str(), good);
            assert_eq!(room.topic(), format!("nau/room/{good}"));
            assert_eq!(good.parse::<RoomName>().expect("FromStr agrees"), room);
            // A room name must survive the trip through the peer-id charset,
            // because room-keyed maps use nau_net::PeerId.
            assert_eq!(room.as_peer_id().expect("valid peer id").as_str(), good);
        }
    }

    #[test]
    fn the_separator_that_made_two_rooms_collide_is_refused() {
        // `room-a/b` used to render the topic `nau/room/room-a/b`, which a
        // two-level scheme would read as room `room-a` with a sub-room `b`.
        for bad in [
            "room-a/b",
            "room:a",
            "a b",
            "a\nb",
            "emoji-🦀",
            "a\u{0}b",
            "",
        ] {
            let err = RoomName::parse(bad).expect_err("must be refused");
            assert!(!err.to_string().is_empty());
        }
        assert!(matches!(
            RoomName::parse("room-a/b").expect_err("separator"),
            NameError::RoomCharset { .. }
        ));
        assert!(matches!(
            RoomName::parse("").expect_err("empty"),
            NameError::EmptyRoom
        ));
        assert!(matches!(
            RoomName::parse("abc").expect_err("too short"),
            NameError::RoomTooShort {
                min: MIN_ROOM_NAME_BYTES,
                ..
            }
        ));
        assert!(matches!(
            RoomName::parse(&"a".repeat(MAX_ROOM_NAME_BYTES + 1)).expect_err("too long"),
            NameError::RoomTooLong { .. }
        ));
    }

    #[test]
    fn a_topic_round_trips_back_to_its_room() {
        let room = RoomName::parse("room-0000000000000007").expect("valid");
        let topic = room.topic();
        assert_eq!(room_from_topic(&topic).expect("round trip"), room);
        assert!(matches!(
            room_from_topic("other/topic").expect_err("foreign topic"),
            NameError::NotARoomTopic { .. }
        ));
        // A topic whose room part is invalid is refused at parse, not accepted.
        assert!(room_from_topic("nau/room/a/b").is_err());
    }

    #[test]
    fn a_nodes_room_is_the_topology_room() {
        // The topic a node publishes to must be the room the overlay places it
        // in, or gossip and routing disagree about the same node.
        let node = PeerId::parse("did:nau:34750f98bd59fcfc").expect("valid");
        let room = RoomName::for_node(&node).expect("derivable");
        assert!(room.as_str().starts_with("room-"));
        assert_eq!(room.as_str().len(), "room-".len() + 16);
        let topology = nau_net::LayeredTopology::new(nau_net::topology::MAX_FANOUT)
            .expect("the maximum fanout is a valid fanout");
        assert_eq!(
            room.as_str(),
            format!("room-{:016x}", topology.room_of(&node))
        );
        // Deterministic: the same node is always in the same room.
        assert_eq!(RoomName::for_node(&node).expect("derivable"), room);
    }

    #[test]
    fn record_keys_are_namespaced_and_validated() {
        assert_eq!(
            record_key("agent/did:nau:34750f98bd59fcfc").expect("valid"),
            b"nau/rec/agent/did:nau:34750f98bd59fcfc".to_vec()
        );
        for bad in ["", "has space", "has\ttab", "has\nnewline", "unicode-🦀"] {
            assert!(record_key(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(matches!(
            record_key("").expect_err("empty"),
            NameError::EmptyRecordKey
        ));
        assert!(matches!(
            record_key(&"k".repeat(MAX_RECORD_KEY_BYTES + 1)).expect_err("too long"),
            NameError::RecordKeyTooLong { .. }
        ));
        // The namespaced key itself is within the same limit only if the input
        // was; this documents the relationship rather than asserting a bound the
        // DHT does not impose.
        assert!(record_key(&"k".repeat(MAX_RECORD_KEY_BYTES)).is_ok());
    }

    #[test]
    fn peer_id_string_agrees_with_the_identity_module() {
        let identity = identity::NauIdentity::from_seed(&[1u8; 32]);
        assert_eq!(
            peer_id_string(identity.public_key()),
            identity.peer_id().to_string()
        );
    }
}
