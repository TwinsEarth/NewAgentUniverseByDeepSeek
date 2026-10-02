//! `com.twinsearth.sys.net.gossip` — what this build can honestly say about broadcast and
//! subscription, and a pre-flight that subscribes to nothing.
//!
//! # The finding this file is written around: `nau-net` has no pub/sub surface
//!
//! `nau-net` ships eight modules — `memory`, `nat`, `peer`, `relay`, `stun`, `tcp`,
//! `topology`, `transport` — and **none of them has a topic type, a subscription registry,
//! a fan-out cap or a broadcast entry point**. That absence is deliberate and is recorded
//! in `nau-net`'s own crate documentation: upstream v2.5.6 shipped
//! `net/gossip.rs::GossipSub` as a `HashMap` stand-in carrying the same name as the real
//! service, so no integration test revealed that nothing was ever published, and the
//! replacement crate has no gossip module rather than a second mock.
//!
//! So this door **reports the absence** instead of inventing limits. `limits` answers
//! `subscription_surface: "absent"` and `null` for every subscription-specific cap, with a
//! note saying why; `precheck` says `subscribed: false` and lists what it did not check. A
//! number here would be a limit nothing enforces, which is the defect this project exists
//! to refuse.
//!
//! # What is real, and therefore what this door does answer
//!
//! A broadcast in this workspace would be **a frame on `nau-net`'s transport**, and the
//! limits that are real are transport limits. They are read from the crate's own constants
//! and reported: the frame cap ([`MAX_FRAME_BYTES`], [`FRAME_PREFIX_BYTES`]), the per-peer
//! queue caps ([`OUTBOUND_QUEUE_CAP`], [`INBOUND_QUEUE_CAP`]), the in-process delivery
//! queue ([`MEMORY_QUEUE_CAP`]), the read timeout ([`DEFAULT_READ_TIMEOUT`]) and the
//! peer-id cap ([`MAX_PEER_ID_LEN`]).
//!
//! `precheck` applies exactly three rules and names which is whose:
//!
//! | Check | Whose rule |
//! |---|---|
//! | the topic is not empty | **this door's** — `nau-net` defines no topic rule at all |
//! | topic + payload fit one frame | `nau_net::check_frame_len` ([`MAX_FRAME_BYTES`]) |
//! | a subscriber label is a peer id | `nau_net::PeerId::parse` ([`MAX_PEER_ID_LEN`]) |
//!
//! The empty-topic rule is stated as this door's own in the answer (`topic_rule`) rather
//! than presented as `nau-net`'s, because attributing a rule to a crate that does not have
//! it is how a fabricated limit starts.
//!
//! # The topic rule that does exist elsewhere, and why it is not used here
//!
//! The only real topic rule in this workspace is `nau_libp2p::naming` — `ROOM_TOPIC_PREFIX`,
//! `MAX_TOPIC_BYTES` and `RoomName::parse`. This crate does **not** depend on `nau-libp2p`,
//! a T0 plugin's dependencies are compiled into the host, and this change's write scope
//! excludes `Cargo.toml`. Approximating that rule with a copy would be a second
//! implementation of exactly the kind this project refuses, so the door reports the
//! narrowing in `subscription_surface_note` and in `not_checked` instead. If the host ever
//! compiles libp2p in, the pre-check should delegate to `naming::RoomName::parse` and the
//! `null`s below should become that crate's numbers.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `limits` | — | `max_frame_bytes`, `frame_prefix_bytes`, `outbound_queue_cap`, `inbound_queue_cap`, `memory_queue_cap`, `default_read_timeout_secs`, `max_peer_id_len`, `subscription_surface`, `max_subscribers_per_topic`, `max_topics`, `max_topic_bytes`, `subscription_surface_note`, `connects` |
//! | `precheck` | `topic`, optional `payload_len`, optional `subscriber` | `topic`, `legal`, `topic_ok`, `topic_reason`, `topic_rule`, `message`, `subscriber`, `subscribed`, `subscription_surface`, `subscription_surface_note`, `not_checked`, `connects` |
//!
//! Both operations require the request to declare `net:gossip:subscribe`: this is the
//! subscription door, so the bus checks the *caller's* token for that capability before
//! delivery and [`PluginGrant::require_operation`] checks the declaration again here. A
//! topic or subscriber that fails a rule is a **well-formed question whose answer is "no"**
//! — `legal: false` with the reason named — not a refusal; only a malformed *request* is an
//! `Err`.

use nau_net::memory::MEMORY_QUEUE_CAP;
use nau_net::tcp::{DEFAULT_READ_TIMEOUT, INBOUND_QUEUE_CAP, OUTBOUND_QUEUE_CAP};
use nau_net::{check_frame_len, PeerId, FRAME_PREFIX_BYTES, MAX_FRAME_BYTES, MAX_PEER_ID_LEN};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements, for the unknown-operation refusal.
pub const OPERATIONS: &[&str] = &["limits", "precheck"];

/// The one-word answer to "what subscription surface does this build have?".
pub const SUBSCRIPTION_SURFACE: &str = "absent";

/// Why the subscription caps are `null`, in the answer that reports them.
pub const SUBSCRIPTION_SURFACE_NOTE: &str = "nau-net exposes no publish/subscribe surface: no \
     topic type, no subscription registry, no fan-out or subscriber cap, and no broadcast entry \
     point (upstream v2.5.6 shipped net/gossip.rs::GossipSub as a HashMap stand-in; nau-net \
     deliberately does not replace it with a second mock). The only real topic rule in this \
     workspace is nau_libp2p::naming (ROOM_TOPIC_PREFIX, MAX_TOPIC_BYTES, RoomName::parse), and \
     this crate does not depend on nau-libp2p, so this door reports no subscription limits rather \
     than copying that rule. A number here would be a limit nothing enforces.";

/// What this door does not decide, listed in every `precheck` answer.
pub const NOT_CHECKED: &[&str] = &[
    "topic naming, length and versioning rules (nau-net defines none)",
    "how many subscribers one topic may have, and how many topics one node may follow",
    "message ids, de-duplication, ordering and delivery guarantees",
    "whether any peer is subscribed, or reachable at all",
    "nau_libp2p::naming's RoomName rule, which this crate cannot reach (no dependency)",
];

/// The gossip/subscription system plugin.
pub struct GossipPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl GossipPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.net.gossip";

    /// The capabilities the plugin declares: the basic set, plus `net:gossip:subscribe`.
    ///
    /// The extra capability is the door's name rather than a claim about this process:
    /// every operation here requires a request that declares `net:gossip:subscribe`, so the
    /// bus checks the *caller's* token for it, and the plugin declares it because
    /// [`crate::host::SystemPluginHost::register`] refuses a plugin that declares more than
    /// its manifest grants. The plugin itself subscribes to nothing — there is nothing to
    /// subscribe to — and every answer says so.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::GossipSubscribe,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if [`GossipPlugin::ID`] is not a valid plugin
    /// name, which cannot happen for this constant but is returned rather than asserted.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for GossipPlugin {
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
            "net.gossip ready: transport limits come from nau-net and the subscription caps are \
             reported as absent rather than invented; nothing is subscribed",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        // 1. The message's declared capability must be one this plugin holds. The bus
        //    checks this too, and it is repeated here because a T0 plugin is in-process:
        //    the refusal must not depend on which door was used.
        let declared = self.grant.require_declared(msg)?;
        // 2. This is the subscription door, so every operation of it needs a request that
        //    declares `net:gossip:subscribe` — the capability the bus checks against the
        //    caller.
        self.grant
            .require_operation(declared, Capability::GossipSubscribe)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "limits" => Ok(self.limits()),
            "precheck" => self.precheck(&msg.payload),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        // Nothing to release: this plugin holds no subscription between calls, and giving
        // up the grant is what makes a call after shutdown a typed refusal rather than one
        // that still has authority behind it.
        self.grant.release();
        Ok(())
    }
}

impl GossipPlugin {
    /// `limits`: the transport limits a broadcast must obey, and the subscription limits
    /// that do not exist.
    fn limits(&self) -> Value {
        payload::answer(
            Self::ID,
            "limits",
            json!({
                // A broadcast is a frame on nau-net's transport, so these are the caps that
                // actually bound it. Read from the crate, never restated.
                "max_frame_bytes": MAX_FRAME_BYTES,
                "frame_prefix_bytes": FRAME_PREFIX_BYTES,
                "outbound_queue_cap": OUTBOUND_QUEUE_CAP,
                "inbound_queue_cap": INBOUND_QUEUE_CAP,
                "memory_queue_cap": MEMORY_QUEUE_CAP,
                "default_read_timeout_secs": DEFAULT_READ_TIMEOUT.as_secs(),
                "max_peer_id_len": MAX_PEER_ID_LEN,
                // Deliberately null, and the note is the answer rather than an omission.
                "subscription_surface": SUBSCRIPTION_SURFACE,
                "max_subscribers_per_topic": Value::Null,
                "max_topics": Value::Null,
                "max_topic_bytes": Value::Null,
                "subscription_surface_note": SUBSCRIPTION_SURFACE_NOTE,
                "connects": false,
            }),
        )
    }

    /// `precheck`: apply the two `nau-net` rules that are real to a topic and its message,
    /// and report the result without subscribing to anything.
    ///
    /// # Errors
    ///
    /// [`payload::CODE_MISSING_FIELD`] / [`payload::CODE_FIELD_TYPE`] for a malformed
    /// request. A topic or subscriber that fails a rule is an *answer*, not a refusal:
    /// `legal` is `false` and the reason is named.
    fn precheck(&self, request: &Value) -> Result<Value> {
        let topic = payload::string_field(request, "topic")?;
        let payload_len = optional_u64(request, "payload_len")?;
        let subscriber = payload::optional_string(request, "subscriber")?;

        // This door's own rule, and named as such in the answer: nau-net has no topic rule
        // to delegate to, and an empty topic is not a topic.
        let topic_ok = !topic.is_empty();
        let topic_reason = if topic_ok {
            None
        } else {
            Some("a topic must not be empty: a subscriber cannot subscribe to nothing")
        };

        // A broadcast travels as one frame: the topic and the payload together. The rule is
        // nau_net::check_frame_len's, and the length is the frame *body* (the 4-byte prefix
        // is counted separately in `wire_bytes`).
        let declared_bytes = usize::try_from(payload_len.unwrap_or(0)).unwrap_or(usize::MAX);
        let message_bytes = topic.len().saturating_add(declared_bytes);
        let (message_ok, message_reason) = match check_frame_len(message_bytes) {
            Ok(()) => (true, None),
            Err(err) => (false, Some(err.to_string())),
        };

        let (subscriber_supplied, subscriber_legal, subscriber_id, subscriber_reason) =
            match &subscriber {
                None => (false, None, None, None),
                Some(text) => match PeerId::parse(text) {
                    Ok(id) => (true, Some(true), Some(id.as_str().to_string()), None),
                    Err(err) => (true, Some(false), None, Some(err.to_string())),
                },
            };

        Ok(payload::answer(
            Self::ID,
            "precheck",
            json!({
                "topic": topic,
                "legal": topic_ok && message_ok && subscriber_legal.unwrap_or(true),
                "topic_ok": topic_ok,
                "topic_reason": topic_reason,
                "topic_rule": "non-empty — this door's rule: nau-net defines no topic rule",
                "message": {
                    "bytes": message_bytes,
                    "wire_bytes": message_bytes.saturating_add(FRAME_PREFIX_BYTES),
                    "ok": message_ok,
                    "reason": message_reason,
                    "checked_by": "nau_net::check_frame_len",
                },
                "subscriber": {
                    "supplied": subscriber_supplied,
                    "legal": subscriber_legal,
                    "peer_id": subscriber_id,
                    "reason": subscriber_reason,
                    "checked_by": "nau_net::PeerId::parse",
                },
                "subscribed": false,
                "subscription_surface": SUBSCRIPTION_SURFACE,
                "subscription_surface_note": SUBSCRIPTION_SURFACE_NOTE,
                "not_checked": NOT_CHECKED,
                "connects": false,
                "note": "this operation is a pre-flight: it applies the transport frame cap that \
                    any broadcast payload must obey and nothing was subscribed, because there is \
                    no subscription surface to subscribe to",
            }),
        ))
    }
}

/// An optional non-negative integer field.
///
/// Local rather than in [`crate::payload`] because that module is outside this change's
/// write scope; if a third plugin needs it, the one copy belongs there so that "an integer
/// field" has one rule.
///
/// # Errors
///
/// [`payload::CODE_NOT_OBJECT`] when the payload is not an object,
/// [`payload::CODE_FIELD_TYPE`] when the key is present and is neither a non-negative
/// integer nor `null`.
/// An optional integer field, via the one rule in [`crate::payload`].
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
        CapabilityToken::issue(GossipPlugin::ID, Tier::System, caps, DIGEST, NOW).expect("issuable")
    }

    /// The plugin, initialised through the framework with `caps`.
    fn plugin(caps: &[Capability]) -> GossipPlugin {
        let mut plugin = GossipPlugin::new().expect("valid id");
        let mut ctx = HostContext::new(token(caps), HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.sys.policy").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(GossipPlugin::ID.to_string()),
            Capability::parse(capability).expect("known capability"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    #[test]
    fn the_plugin_registers_reaches_running_and_reports_the_absence_of_a_pub_sub_surface() {
        let verified = crate::sign::verified_system(
            GossipPlugin::ID,
            GossipPlugin::CAPABILITIES,
            &crate::sign::fixture_key(HOST_SEED),
            &crate::sign::fixture_key(VENDOR_SEED),
        )
        .expect("a system manifest verifies");
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(
            Box::new(GossipPlugin::new().expect("valid id")),
            &verified,
            NOW,
        )
        .expect("registers");
        host.init(GossipPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(GossipPlugin::ID), Some(PluginState::Running));

        let answer = host
            .handle(&request("net:gossip:subscribe", json!({ "op": "limits" })))
            .expect("answers");
        // The transport limits a broadcast must obey are real and reported.
        assert_eq!(answer["max_frame_bytes"], json!(MAX_FRAME_BYTES));
        assert_eq!(answer["frame_prefix_bytes"], json!(FRAME_PREFIX_BYTES));
        assert_eq!(answer["outbound_queue_cap"], json!(OUTBOUND_QUEUE_CAP));
        assert_eq!(answer["inbound_queue_cap"], json!(INBOUND_QUEUE_CAP));
        assert_eq!(answer["memory_queue_cap"], json!(MEMORY_QUEUE_CAP));
        assert_eq!(
            answer["default_read_timeout_secs"],
            json!(DEFAULT_READ_TIMEOUT.as_secs())
        );
        assert_eq!(answer["max_peer_id_len"], json!(MAX_PEER_ID_LEN));

        // The subscription limits are not real, and the answer says so rather than
        // reporting a number nothing enforces.
        assert_eq!(answer["subscription_surface"], json!(SUBSCRIPTION_SURFACE));
        for cap in ["max_subscribers_per_topic", "max_topics", "max_topic_bytes"] {
            assert_eq!(
                answer[cap],
                json!(null),
                "{cap} must be null: nau-net has no pub/sub surface to bound"
            );
        }
        assert!(
            answer["subscription_surface_note"]
                .as_str()
                .is_some_and(|text| text.contains("nau-net exposes no publish/subscribe surface")),
            "{answer}"
        );
        assert_eq!(answer["connects"], json!(false));
    }

    #[test]
    fn a_topic_is_preflighted_against_nau_nets_frame_cap_without_subscribing() {
        let mut plugin = plugin(GossipPlugin::CAPABILITIES);

        let answer = plugin
            .handle(&request(
                "net:gossip:subscribe",
                json!({ "op": "precheck", "topic": "nau/room/general", "payload_len": 1024 }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(true));
        assert_eq!(answer["topic_ok"], json!(true));
        assert_eq!(answer["message"]["ok"], json!(true));
        assert_eq!(answer["message"]["bytes"], json!(16 + 1024));
        assert_eq!(
            answer["message"]["wire_bytes"],
            json!(16 + 1024 + FRAME_PREFIX_BYTES)
        );
        assert_eq!(
            answer["subscribed"],
            json!(false),
            "the pre-flight must state that it subscribed to nothing"
        );
        assert_eq!(answer["subscription_surface"], json!(SUBSCRIPTION_SURFACE));
        assert_eq!(answer["subscriber"]["supplied"], json!(false));
        assert_eq!(answer["subscriber"]["legal"], json!(null));

        // The cap is nau-net's, and one byte over it is refused by that cap — whether the
        // topic alone reaches it or the payload does.
        let oversized_topic = "t".repeat(MAX_FRAME_BYTES + 1);
        for payload in [
            json!({ "op": "precheck", "topic": "nau/x", "payload_len": MAX_FRAME_BYTES }),
            json!({ "op": "precheck", "topic": oversized_topic }),
        ] {
            let answer = plugin
                .handle(&request("net:gossip:subscribe", payload))
                .expect("answers");
            assert_eq!(answer["legal"], json!(false));
            assert_eq!(answer["message"]["ok"], json!(false));
            assert!(
                answer["message"]["reason"]
                    .as_str()
                    .is_some_and(|text| text.contains("exceeds the")),
                "{answer}"
            );
        }

        // An empty topic is this door's own "no", and the answer attributes it to this
        // door rather than to a crate that has no topic rule.
        let answer = plugin
            .handle(&request(
                "net:gossip:subscribe",
                json!({ "op": "precheck", "topic": "" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert_eq!(answer["topic_ok"], json!(false));
        assert!(
            answer["topic_reason"]
                .as_str()
                .is_some_and(|text| text.contains("must not be empty")),
            "{answer}"
        );
        assert!(
            answer["topic_rule"]
                .as_str()
                .is_some_and(|text| text.contains("nau-net defines no topic rule")),
            "{answer}"
        );
    }

    #[test]
    fn a_subscriber_label_is_preflighted_by_nau_nets_peer_id_rule() {
        let mut plugin = plugin(GossipPlugin::CAPABILITIES);

        let answer = plugin
            .handle(&request(
                "net:gossip:subscribe",
                json!({ "op": "precheck", "topic": "nau/x", "subscriber": "node-7" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(true));
        assert_eq!(answer["subscriber"]["legal"], json!(true));
        assert_eq!(answer["subscriber"]["peer_id"], json!("node-7"));
        assert_eq!(
            answer["subscriber"]["checked_by"],
            json!("nau_net::PeerId::parse")
        );

        // A label outside nau-net's charset: a "no" answer with the crate's own reason.
        let answer = plugin
            .handle(&request(
                "net:gossip:subscribe",
                json!({ "op": "precheck", "topic": "nau/x", "subscriber": "has space" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert_eq!(answer["subscriber"]["peer_id"], json!(null));
        assert!(
            answer["subscriber"]["reason"]
                .as_str()
                .is_some_and(|text| text.contains("may only contain")),
            "{answer}"
        );
    }

    #[test]
    fn a_request_the_plugin_may_not_serve_is_refused_by_name() {
        let mut plugin = plugin(GossipPlugin::CAPABILITIES);

        // A capability the plugin's token does not hold at all. `net:gossip:publish` is a
        // real capability of this build and it is still not this door's.
        let err = plugin
            .handle(&request("net:gossip:publish", json!({ "op": "limits" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("net:gossip:publish"), "{err}");
        assert!(err.to_string().contains(GossipPlugin::ID), "{err}");

        // A capability it *does* hold, declared for an operation it is not the door for.
        let err = plugin
            .handle(&request("plugin:message:send", json!({ "op": "limits" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("net:gossip:subscribe"), "{text}");

        // And an operation it does not implement lists the ones it does.
        let err = plugin
            .handle(&request("net:gossip:subscribe", json!({ "op": "publish" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("precheck"), "{text}");

        // A request field of the wrong type is a typed protocol refusal, not a panic.
        let err = plugin
            .handle(&request(
                "net:gossip:subscribe",
                json!({ "op": "precheck", "topic": "nau/x", "payload_len": "many" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains(payload::CODE_FIELD_TYPE), "{err}");
    }
}
