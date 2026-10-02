//! `com.twinsearth.sys.net.dht` — `nau-net`'s deterministic overlay topology, reported,
//! plus a peer-id pre-flight that joins nothing and dials nothing.
//!
//! # What it delegates to
//!
//! Every number and every rule in an answer is `nau-net`'s:
//!
//! | Question | `nau-net` item |
//! |---|---|
//! | how many overlay levels exist | [`MAX_LEVEL`] |
//! | how the room tree is shaped | [`ROOM_BITS`], [`ROOMS_AT_LEVEL_1`] |
//! | how large a topology view may be | [`MAX_FANOUT`], [`MAX_NODES`] |
//! | where a peer id sits in the tree | [`ring_key`], [`LayeredTopology::level_of`], [`LayeredTopology::room_of`] |
//! | whether a described view is acceptable | [`LayeredTopology::with_limits`] |
//! | whether a peer id is an id at all | [`PeerId::parse`], [`MAX_PEER_ID_LEN`] |
//!
//! Not one of those values is restated here. A second copy of `MAX_FANOUT` would be a
//! second answer to "how many neighbours may a node hold", and the two would disagree
//! the first time one moved — the failure mode the `plugin-invariants` gate exists to
//! make visible in the wiring, and the same discipline in the values.
//!
//! [`MAX_LEVEL`], [`ROOM_BITS`], [`ROOMS_AT_LEVEL_1`], [`MAX_FANOUT`], [`MAX_NODES`] and
//! [`ring_key`] are `nau_net::topology`'s; [`PeerId`] and [`MAX_PEER_ID_LEN`] are
//! `nau_net::peer`'s.
//!
//! # What this door does not do, and says so in every answer
//!
//! * **No membership view.** [`LayeredTopology::route_hops`] is real, and it answers only
//!   for nodes that have joined a view. This plugin holds none, so it reports no hop count
//!   anywhere: `limits` answers `route_hops_available: false` with the reason, and
//!   `precheck` answers the pure derivations (`ring_key`, `level`, `room`) without adding
//!   a single node. A caller that wants hop counts wants a node with a membership feed,
//!   not a system plugin.
//! * **No DHT record.** There is no `get`, no `put` and no record store, because
//!   `nau-net` has none: its topology is a deterministic function of the member set, not a
//!   key-value overlay. Inventing a store here would be exactly the same-named `HashMap`
//!   stand-in that `nau-net`'s own module docs describe upstream v2.5.6 shipping.
//! * **No socket.** `precheck` opens none — it parses a string and hashes it — so
//!   `legal: true` means the checks passed, never that a peer is reachable.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `limits` | — | `max_level`, `room_bits`, `rooms_at_level_1`, `max_fanout`, `max_nodes`, `ring_key_bytes`, `max_peer_id_len`, `nodes_held`, `route_hops_available`, `route_hops_note`, `connects` |
//! | `precheck` | `peer`, optional `fanout`, optional `max_nodes` | `peer`, `legal`, `peer_id`, `reason`, `derivation` (`ring_key`, `level`, `room`), `view`, `joined`, `connects` |
//!
//! Both operations require the request to declare `net:dht:read`: this is the DHT door, so
//! a caller that wants an answer from it declares the capability that names DHT reads, and
//! the bus checks that declaration against the caller's own token before delivery. The
//! plugin declares the same capability because [`crate::host::SystemPluginHost::register`]
//! refuses a plugin that declares more than its manifest grants — the declaration is the
//! door's name, not a claim that a read happened; every answer says which checks ran.
//!
//! A peer id that fails `nau-net`'s rule is a **well-formed question whose answer is "no"**
//! — `legal: false` with the crate's own reason — not a refusal. Only a malformed *request*
//! is an `Err`, which is the same split [`crate::plugins::transport`] documents.

use nau_net::topology::{
    ring_key, LayeredTopology, MAX_FANOUT, MAX_LEVEL, MAX_NODES, ROOMS_AT_LEVEL_1, ROOM_BITS,
};
use nau_net::{PeerId, MAX_PEER_ID_LEN};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: `nau-net` refused the topology view the request described.
pub const CODE_TOPOLOGY_REFUSED: &str = "dht_topology_refused";

/// The operations this plugin implements, for the unknown-operation refusal.
pub const OPERATIONS: &[&str] = &["limits", "precheck"];

/// The DHT/topology system plugin.
pub struct DhtPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl DhtPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.net.dht";

    /// The capabilities the plugin declares: the basic set, plus `net:dht:read`.
    ///
    /// The extra capability is the door's name rather than a claim about this process:
    /// every operation here requires a request that declares `net:dht:read`, so the bus
    /// checks the *caller's* token for it before delivery, and
    /// [`PluginGrant::require_operation`] checks the declaration again at the door. The
    /// plugin itself opens no socket, joins no view and reads no record — see the module
    /// documentation for what each answer states.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::DhtRead,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if [`DhtPlugin::ID`] is not a valid plugin name,
    /// which cannot happen for this constant but is returned rather than asserted.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for DhtPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        ctx.log(
            LogLevel::Info,
            "net.dht ready: topology limits and peer derivation come from nau-net::topology; \
             no membership view is held and no socket is opened",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        // 1. The message's declared capability must be one this plugin holds. The bus
        //    checks this too, and it is repeated here because a T0 plugin is in-process:
        //    the refusal must not depend on which door was used.
        let declared = self.grant.require_declared(msg)?;
        // 2. This is the DHT door, so every operation of it needs a request that declares
        //    `net:dht:read` — the capability the bus then checks against the caller.
        self.grant
            .require_operation(declared, Capability::DhtRead)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "limits" => Ok(self.limits()),
            "precheck" => self.precheck(&msg.payload),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        // Nothing to release: this plugin holds no state between calls — not even a node
        // in a view — and giving up the grant is what makes a call after shutdown a typed
        // refusal rather than one that still has authority behind it.
        self.grant.release();
        Ok(())
    }
}

impl DhtPlugin {
    /// `limits`: what `nau-net`'s topology permits, read from its own items.
    fn limits(&self) -> Value {
        payload::answer(
            Self::ID,
            "limits",
            json!({
                "max_level": MAX_LEVEL,
                "room_bits": ROOM_BITS,
                "rooms_at_level_1": ROOMS_AT_LEVEL_1,
                "max_fanout": MAX_FANOUT,
                "max_nodes": MAX_NODES,
                // Read from the type `ring_key` returns rather than written as "8": a
                // width restated as a literal is a second answer to the same question.
                "ring_key_bytes": std::mem::size_of::<u64>(),
                "max_peer_id_len": MAX_PEER_ID_LEN,
                // This plugin holds no membership view, and says so rather than
                // reporting a level of zero nodes.
                "nodes_held": 0,
                "route_hops_available": false,
                "route_hops_note": "nau-net derives a hop count from the room tree \
                    (LayeredTopology::route_hops), and it answers only for nodes that have \
                    joined a membership view. This plugin holds none, so no hop count is \
                    reported; the level and room a peer id derives to are pure functions of \
                    the id and are available from `precheck`.",
                "connects": false,
            }),
        )
    }

    /// `precheck`: apply `nau-net`'s peer-id rule and topology derivations, and report the
    /// result without joining a view or opening a socket.
    ///
    /// # Errors
    ///
    /// [`payload::CODE_MISSING_FIELD`] / [`payload::CODE_FIELD_TYPE`] for a malformed
    /// request. A peer id that fails a rule is an *answer*, not a refusal: `legal` is
    /// `false` and `nau-net`'s own reason is named.
    fn precheck(&self, request: &Value) -> Result<Value> {
        let peer = payload::string_field(request, "peer")?;
        let (peer_id, peer_legal, reason, derivation) = match PeerId::parse(peer) {
            Ok(id) => {
                // `level_of` and `room_of` are documented as pure functions of the id, so
                // an empty view computes exactly what a populated one would. The view is
                // built rather than asserted because `with_limits` is the constructor and
                // a failure here is a typed refusal, not a panic.
                let view = layered_view(MAX_FANOUT, MAX_NODES)?;
                let derived = json!({
                    "ring_key": ring_key(&id),
                    "level": view.level_of(&id),
                    "room": view.room_of(&id),
                });
                (Some(id.as_str().to_string()), true, None, derived)
            }
            Err(err) => (None, false, Some(err.to_string()), Value::Null),
        };

        Ok(payload::answer(
            Self::ID,
            "precheck",
            json!({
                "peer": peer,
                "legal": peer_legal,
                "peer_id": peer_id,
                "reason": reason,
                "derivation": derivation,
                "view": self.view_question(request)?,
                "joined": false,
                "connects": false,
                "note": "this operation is a pre-flight: it applies nau-net's peer-id rule and \
                    computes the derivations the topology defines, and it adds no node to any \
                    view and opens no socket, so `legal: true` means the checks passed, not \
                    that a peer is reachable or present",
            }),
        ))
    }

    /// The optional `fanout` / `max_nodes` view question, answered by `nau-net`'s own
    /// constructor.
    ///
    /// # Errors
    ///
    /// [`payload::CODE_FIELD_TYPE`] for a field that is not a non-negative integer.
    fn view_question(&self, request: &Value) -> Result<Value> {
        let fanout = optional_u64(request, "fanout")?;
        let max_nodes = optional_u64(request, "max_nodes")?;
        if fanout.is_none() && max_nodes.is_none() {
            return Ok(json!({
                "checked": false,
                "fanout": Value::Null,
                "max_nodes": Value::Null,
                "defaults_applied": false,
                "accepted": Value::Null,
                "reason": Value::Null,
                "note": "no view was described: supply `fanout` and/or `max_nodes` to have \
                    nau-net validate one",
            }));
        }
        // An omitted field takes nau-net's own maximum rather than a number chosen here:
        // the maximum is the most permissive view the crate accepts, so an omission can
        // only make the answer more likely to be `accepted: true`, never less.
        let effective_fanout = fanout.unwrap_or(u64::from(MAX_FANOUT));
        let effective_max_nodes = max_nodes.unwrap_or(MAX_NODES as u64);
        // A value that does not fit the target type cannot be one nau-net accepts, so
        // saturating can only turn "absurd" into "refused", never into "accepted".
        let fanout_u32 = u32::try_from(effective_fanout).unwrap_or(u32::MAX);
        let max_nodes_usize = usize::try_from(effective_max_nodes).unwrap_or(usize::MAX);

        let checked_by = "LayeredTopology::with_limits";
        match layered_view(fanout_u32, max_nodes_usize) {
            Ok(view) => Ok(json!({
                "checked": true,
                "fanout": view.fanout(),
                "max_nodes": view.max_nodes(),
                "defaults_applied": fanout.is_none() || max_nodes.is_none(),
                "accepted": true,
                "reason": Value::Null,
                "checked_by": checked_by,
                "note": "the view was accepted and then dropped: this plugin holds no nodes",
            })),
            Err(err) => Ok(json!({
                "checked": true,
                "fanout": effective_fanout,
                "max_nodes": effective_max_nodes,
                "defaults_applied": fanout.is_none() || max_nodes.is_none(),
                "accepted": false,
                "reason": err.to_string(),
                "checked_by": checked_by,
                "note": "nau-net refused this view configuration; no view was created",
            })),
        }
    }
}

/// Build a `nau-net` topology view, mapping its refusal onto the kernel's taxonomy.
///
/// # Errors
///
/// [`CODE_TOPOLOGY_REFUSED`] carrying `nau-net`'s own message.
fn layered_view(fanout: u32, max_nodes: usize) -> Result<LayeredTopology> {
    LayeredTopology::with_limits(fanout, max_nodes)
        .map_err(|error| payload::protocol(CODE_TOPOLOGY_REFUSED, error))
}

/// An optional non-negative integer field.
///
/// Local rather than in [`crate::payload`] because that module is outside this change's
/// write scope; if a second plugin needs it, the one copy belongs there so that "an
/// integer field" has one rule.
///
/// # Errors
///
/// [`payload::CODE_NOT_OBJECT`] when the payload is not an object,
/// [`payload::CODE_FIELD_TYPE`] when the key is present and is neither a non-negative
/// integer nor `null`.
// `optional_u64` used to be defined here, and again in `net_gossip.rs`. Two copies of one
// shape rule means two places to change and a third plugin that copies whichever it read
// first, so it now lives in `payload.rs` beside `optional_string`.
fn optional_u64(request: &Value, key: &str) -> Result<Option<u64>> {
    payload::optional_u64(request, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::lifecycle::PluginState;
    use nau_plugin::{CapabilityToken, Tier};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_750_000_000;
    /// The host's own T0 publisher key seed, as `tests/common/mod.rs` documents it.
    const HOST_SEED: u8 = 3;
    /// The trusted vendor key seed that counter-signs a system manifest.
    const VENDOR_SEED: u8 = 9;

    fn token(caps: &[Capability]) -> CapabilityToken {
        CapabilityToken::issue(DhtPlugin::ID, Tier::System, caps, DIGEST, NOW).expect("issuable")
    }

    /// The plugin, initialised through the framework with `caps`.
    fn plugin(caps: &[Capability]) -> DhtPlugin {
        let mut plugin = DhtPlugin::new().expect("valid id");
        let mut ctx = HostContext::new(token(caps), HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.sys.policy").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(DhtPlugin::ID.to_string()),
            Capability::parse(capability).expect("known capability"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    #[test]
    fn the_plugin_registers_reaches_running_and_reports_nau_nets_topology_limits() {
        let verified = crate::sign::verified_system(
            DhtPlugin::ID,
            DhtPlugin::CAPABILITIES,
            &crate::sign::fixture_key(HOST_SEED),
            &crate::sign::fixture_key(VENDOR_SEED),
        )
        .expect("a system manifest verifies");
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(
            Box::new(DhtPlugin::new().expect("valid id")),
            &verified,
            NOW,
        )
        .expect("registers");
        host.init(DhtPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(DhtPlugin::ID), Some(PluginState::Running));

        let answer = host
            .handle(&request("net:dht:read", json!({ "op": "limits" })))
            .expect("answers");
        assert_eq!(answer["plugin"], json!(DhtPlugin::ID));
        assert_eq!(answer["max_level"], json!(MAX_LEVEL));
        assert_eq!(answer["room_bits"], json!(ROOM_BITS));
        assert_eq!(answer["rooms_at_level_1"], json!(ROOMS_AT_LEVEL_1));
        assert_eq!(answer["max_fanout"], json!(MAX_FANOUT));
        assert_eq!(answer["max_nodes"], json!(MAX_NODES));
        assert_eq!(answer["ring_key_bytes"], json!(std::mem::size_of::<u64>()));
        assert_eq!(answer["max_peer_id_len"], json!(MAX_PEER_ID_LEN));
        assert_eq!(
            answer["route_hops_available"],
            json!(false),
            "hop counts need a membership view, and this plugin holds none"
        );
        assert_eq!(answer["nodes_held"], json!(0));
        assert_eq!(answer["connects"], json!(false));
    }

    #[test]
    fn a_peer_is_preflighted_by_nau_nets_own_derivation_without_joining_a_view() {
        let mut plugin = plugin(DhtPlugin::CAPABILITIES);
        let peer = PeerId::parse("node-7").expect("valid peer id");

        let answer = plugin
            .handle(&request(
                "net:dht:read",
                json!({ "op": "precheck", "peer": "node-7" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(true));
        assert_eq!(answer["peer_id"], json!("node-7"));
        assert_eq!(answer["reason"], json!(null));
        assert_eq!(answer["joined"], json!(false));
        assert_eq!(
            answer["connects"],
            json!(false),
            "the pre-flight must state that it opened no socket"
        );

        // The derivation is compared against nau-net's own functions, so this test pins
        // "the numbers come from the crate" rather than "the numbers are these literals".
        let view = LayeredTopology::with_limits(MAX_FANOUT, MAX_NODES).expect("a valid view");
        assert_eq!(answer["derivation"]["ring_key"], json!(ring_key(&peer)));
        assert_eq!(answer["derivation"]["level"], json!(view.level_of(&peer)));
        assert_eq!(answer["derivation"]["room"], json!(view.room_of(&peer)));

        // The derivation is a pure function of the id: the same id answers the same way
        // with no node ever added.
        let again = plugin
            .handle(&request(
                "net:dht:read",
                json!({ "op": "precheck", "peer": "node-7" }),
            ))
            .expect("answers");
        assert_eq!(again["derivation"], answer["derivation"]);
    }

    #[test]
    fn a_peer_id_outside_nau_nets_rule_is_a_no_answer_not_a_refusal() {
        let mut plugin = plugin(DhtPlugin::CAPABILITIES);

        let answer = plugin
            .handle(&request(
                "net:dht:read",
                json!({ "op": "precheck", "peer": "has space" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert_eq!(answer["peer_id"], json!(null));
        assert_eq!(answer["derivation"], json!(null));
        assert!(
            answer["reason"]
                .as_str()
                .is_some_and(|text| text.contains("may only contain")),
            "{answer}"
        );

        // The length cap is nau-net's, and one byte over it is refused by that cap.
        let long = "x".repeat(MAX_PEER_ID_LEN + 1);
        let answer = plugin
            .handle(&request(
                "net:dht:read",
                json!({ "op": "precheck", "peer": long }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert!(
            answer["reason"]
                .as_str()
                .is_some_and(|text| text.contains("exceeds the")),
            "{answer}"
        );

        // An empty id is refused by the crate too, rather than read as "no peer".
        let answer = plugin
            .handle(&request(
                "net:dht:read",
                json!({ "op": "precheck", "peer": "" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert!(
            answer["reason"]
                .as_str()
                .is_some_and(|text| text.contains("must not be empty")),
            "{answer}"
        );
    }

    #[test]
    fn a_view_nau_net_refuses_is_reported_as_a_no_answer() {
        let mut plugin = plugin(DhtPlugin::CAPABILITIES);

        // No view was described: the question is reported as unasked, not as accepted.
        let answer = plugin
            .handle(&request(
                "net:dht:read",
                json!({ "op": "precheck", "peer": "node-7" }),
            ))
            .expect("answers");
        assert_eq!(answer["view"]["checked"], json!(false));
        assert_eq!(answer["view"]["accepted"], json!(null));

        // A fanout of zero is refused by nau-net's own constructor.
        let answer = plugin
            .handle(&request(
                "net:dht:read",
                json!({ "op": "precheck", "peer": "node-7", "fanout": 0 }),
            ))
            .expect("answers");
        assert_eq!(
            answer["legal"],
            json!(true),
            "the peer is legal; the view is a separate question"
        );
        assert_eq!(answer["view"]["accepted"], json!(false));
        assert!(
            answer["view"]["reason"]
                .as_str()
                .is_some_and(|text| text.contains("fanout must be at least 1")),
            "{answer}"
        );

        // Over the cap, and under the node floor, both by nau-net's rule.
        for (payload, fragment) in [
            (
                json!({ "op": "precheck", "peer": "node-7", "fanout": MAX_FANOUT + 1 }),
                "exceeds the maximum of",
            ),
            (
                json!({ "op": "precheck", "peer": "node-7", "max_nodes": 0 }),
                "max_nodes must be at least 1",
            ),
        ] {
            let answer = plugin
                .handle(&request("net:dht:read", payload))
                .expect("answers");
            assert_eq!(answer["view"]["accepted"], json!(false));
            assert!(
                answer["view"]["reason"]
                    .as_str()
                    .is_some_and(|text| text.contains(fragment)),
                "{answer}"
            );
        }

        // A view nau-net accepts, with the omitted field taking the crate's maximum.
        let answer = plugin
            .handle(&request(
                "net:dht:read",
                json!({ "op": "precheck", "peer": "node-7", "fanout": 4 }),
            ))
            .expect("answers");
        assert_eq!(answer["view"]["accepted"], json!(true));
        assert_eq!(answer["view"]["fanout"], json!(4));
        assert_eq!(answer["view"]["max_nodes"], json!(MAX_NODES));
        assert_eq!(answer["view"]["defaults_applied"], json!(true));
    }

    #[test]
    fn a_request_the_plugin_may_not_serve_is_refused_by_name() {
        let mut plugin = plugin(DhtPlugin::CAPABILITIES);

        // A capability the plugin's token does not hold at all.
        let err = plugin
            .handle(&request("net:dht:write", json!({ "op": "limits" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("net:dht:write"), "{err}");
        assert!(err.to_string().contains(DhtPlugin::ID), "{err}");

        // A capability it *does* hold, declared for an operation it is not the door for.
        let err = plugin
            .handle(&request("plugin:message:send", json!({ "op": "limits" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("net:dht:read"), "{text}");
        assert!(text.contains("plugin:message:send"), "{text}");

        // And an operation it does not implement lists the ones it does.
        let err = plugin
            .handle(&request("net:dht:read", json!({ "op": "lookup" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("precheck"), "{text}");

        // A request field of the wrong type is a typed protocol refusal, not a panic.
        let err = plugin
            .handle(&request(
                "net:dht:read",
                json!({ "op": "precheck", "peer": "node-7", "fanout": "many" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_FIELD_TYPE), "{text}");
        assert!(text.contains("`fanout`"), "{text}");
    }
}
