//! `com.twinsearth.sys.net.transport` — the transport port's real limits, and an
//! address pre-flight that opens no socket.
//!
//! # What it delegates to
//!
//! `nau-net`'s transport port: [`MAX_FRAME_BYTES`], [`FRAME_PREFIX_BYTES`], the
//! per-peer queue caps and read timeout in `nau_net::tcp`, [`MAX_PEER_ID_LEN`] and
//! [`PeerId::parse`], and [`check_frame_len`]. Not one of those numbers is
//! restated here: a second copy of `MAX_FRAME_BYTES` is a second answer to "how
//! large may a frame be", and the two would drift the first time one moved.
//!
//! # Why there is no `connect` operation
//!
//! A T0 plugin runs inside the host, and `nau-net`'s real transport is
//! `tokio`-driven (`TcpTransport::connect` is `async`). Rather than pretending, this
//! plugin does the half that is *pure*: it answers what the port permits and
//! pre-flights an address through exactly the checks `nau-net` applies before it
//! dials — the peer-id rule and the frame-length cap — and states in the answer
//! that no connection was attempted. A caller that wants a real connection wants a
//! network node, not a system plugin.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `limits` | — | `max_frame_bytes`, `frame_prefix_bytes`, `outbound_queue_cap`, `inbound_queue_cap`, `default_read_timeout_secs`, `max_peer_id_len`, `connection_cap`, `peer_id_scheme` |
//! | `precheck` | `address`, optional `frame_len` | `address`, `legal`, `peer_id`, `address_reason`, `frame`, `connects` |
//!
//! **`connection_cap` is `null`, and that is the answer rather than an omission.**
//! `nau-net` bounds the frames queued per peer and the time a silent connection may
//! take, but it has no cap on how many connections an endpoint may hold; reporting a
//! number here would invent a limit the transport does not enforce.
//!
//! Both operations require the request to declare `plugin:message:send` — neither of
//! them touches the network, so neither asks the sender for a network capability.
//! `precheck` answers `legal: false` for an address that fails a check (that is a
//! well-formed question whose answer is "no", like `binds` in [`crate::plugins::identity`]);
//! it refuses only a malformed *request*.

use nau_net::tcp::{DEFAULT_READ_TIMEOUT, INBOUND_QUEUE_CAP, OUTBOUND_QUEUE_CAP};
use nau_net::{check_frame_len, PeerId, FRAME_PREFIX_BYTES, MAX_FRAME_BYTES, MAX_PEER_ID_LEN};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements, for the unknown-operation refusal.
pub const OPERATIONS: &[&str] = &["limits", "precheck"];

/// The scheme `nau-net`'s TCP transport labels a peer with, shown in the answer so
/// a caller can see the shape the peer-id rule was applied to.
pub const PEER_ID_SCHEME: &str = "tcp://<host>:<port>";

/// The transport system plugin.
pub struct TransportPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl TransportPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.net.transport";

    /// The capabilities the plugin declares: the basic set, and nothing else. It
    /// reports constants and validates strings; it opens no socket, so it asks for
    /// no network capability — a declaration it did not need would be a claim it
    /// could not justify.
    pub const CAPABILITIES: &'static [Capability] = &Capability::BASIC;

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if [`TransportPlugin::ID`] is not a valid
    /// plugin name, which cannot happen for this constant but is returned rather
    /// than asserted.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for TransportPlugin {
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
            "net.transport ready: limits and address pre-flight delegate to nau-net; no socket is opened",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        // 1. The message's declared capability must be one this plugin holds. The bus
        //    checks this too, and it is repeated here because a T0 plugin is
        //    in-process: the refusal must not depend on which door was used.
        let declared = self.grant.require_declared(msg)?;
        // 2. Both operations are pure computation, so that is the capability the
        //    operation needs — the same rule `identity` applies to its own.
        self.grant
            .require_operation(declared, Capability::MessageSend)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "limits" => Ok(self.limits()),
            "precheck" => self.precheck(&msg.payload),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        // Nothing to release: this plugin holds no state between calls, and giving up
        // the grant is what makes a call after shutdown a typed refusal rather than
        // one that still has authority behind it.
        self.grant.release();
        Ok(())
    }
}

impl TransportPlugin {
    /// `limits`: what `nau-net`'s transport port permits, read from its constants.
    fn limits(&self) -> Value {
        payload::answer(
            Self::ID,
            "limits",
            json!({
                "max_frame_bytes": MAX_FRAME_BYTES,
                "frame_prefix_bytes": FRAME_PREFIX_BYTES,
                "outbound_queue_cap": OUTBOUND_QUEUE_CAP,
                "inbound_queue_cap": INBOUND_QUEUE_CAP,
                "default_read_timeout_secs": DEFAULT_READ_TIMEOUT.as_secs(),
                "max_peer_id_len": MAX_PEER_ID_LEN,
                // Deliberately null: `nau-net` has no connection-count cap, and a
                // number here would be a limit nothing enforces.
                "connection_cap": Value::Null,
                "connection_cap_note": "nau-net bounds the frames queued per peer \
                    (outbound_queue_cap, inbound_queue_cap) and how long a silent connection may \
                    take (default_read_timeout_secs); it has no cap on the number of connections, \
                    so none is reported",
                "peer_id_scheme": PEER_ID_SCHEME,
            }),
        )
    }

    /// `precheck`: apply `nau-net`'s own address and frame-length checks, and report
    /// the result without connecting.
    ///
    /// # Errors
    ///
    /// [`payload::CODE_MISSING_FIELD`] / [`payload::CODE_FIELD_TYPE`] for a malformed
    /// request. An address or frame length that fails a check is an *answer*, not a
    /// refusal: `legal` is `false` and the reason is named.
    fn precheck(&self, request: &Value) -> Result<Value> {
        let address = payload::string_field(request, "address")?;
        let (peer_id, address_legal, address_reason) = match PeerId::parse(address) {
            Ok(id) => (Some(id.as_str().to_string()), true, None),
            Err(err) => (None, false, Some(err.to_string())),
        };

        let frame_len = match payload::object(request)?.get("frame_len") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                payload::protocol(
                    payload::CODE_FIELD_TYPE,
                    format!(
                        "`frame_len` must be a non-negative integer, found {}",
                        payload::kind_of(value)
                    ),
                )
            })?),
        };
        let (frame, frame_legal) = match frame_len {
            None => (Value::Null, true),
            Some(len) => {
                // A `u64` that does not fit a `usize` cannot be under the cap, so
                // saturating here can only turn "absurd" into "refused", never into
                // "accepted".
                let len_usize = usize::try_from(len).unwrap_or(usize::MAX);
                match check_frame_len(len_usize) {
                    Ok(()) => (
                        json!({ "len": len, "ok": true, "reason": Value::Null }),
                        true,
                    ),
                    Err(err) => (
                        json!({ "len": len, "ok": false, "reason": err.to_string() }),
                        false,
                    ),
                }
            }
        };

        Ok(payload::answer(
            Self::ID,
            "precheck",
            json!({
                "address": address,
                "legal": address_legal && frame_legal,
                "peer_id": peer_id,
                "address_reason": address_reason,
                "frame": frame,
                "connects": false,
                "connects_note": "this operation is a pre-flight: it applies nau-net's peer-id rule \
                    and frame-length cap and opens no socket, so `legal: true` means the checks \
                    passed, not that the address is reachable",
            }),
        ))
    }
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
        CapabilityToken::issue(TransportPlugin::ID, Tier::System, caps, DIGEST, NOW)
            .expect("issuable")
    }

    /// The plugin, initialised through the framework with `caps`.
    fn plugin(caps: &[Capability]) -> TransportPlugin {
        let mut plugin = TransportPlugin::new().expect("valid id");
        let mut ctx = HostContext::new(token(caps), HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.sys.policy").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(TransportPlugin::ID.to_string()),
            Capability::parse(capability).expect("known capability"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    #[test]
    fn the_plugin_registers_reaches_running_and_reports_nau_nets_limits() {
        let verified = crate::sign::verified_system(
            TransportPlugin::ID,
            TransportPlugin::CAPABILITIES,
            &crate::sign::fixture_key(HOST_SEED),
            &crate::sign::fixture_key(VENDOR_SEED),
        )
        .expect("a system manifest verifies");
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(
            Box::new(TransportPlugin::new().expect("valid id")),
            &verified,
            NOW,
        )
        .expect("registers");
        host.init(TransportPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(TransportPlugin::ID), Some(PluginState::Running));

        let answer = host
            .handle(&request("plugin:message:send", json!({ "op": "limits" })))
            .expect("answers");
        assert_eq!(answer["max_frame_bytes"], json!(MAX_FRAME_BYTES));
        assert_eq!(answer["frame_prefix_bytes"], json!(FRAME_PREFIX_BYTES));
        assert_eq!(answer["outbound_queue_cap"], json!(OUTBOUND_QUEUE_CAP));
        assert_eq!(answer["inbound_queue_cap"], json!(INBOUND_QUEUE_CAP));
        assert_eq!(
            answer["default_read_timeout_secs"],
            json!(DEFAULT_READ_TIMEOUT.as_secs())
        );
        assert_eq!(answer["max_peer_id_len"], json!(MAX_PEER_ID_LEN));
        assert_eq!(
            answer["connection_cap"],
            json!(null),
            "nau-net has no connection cap; reporting one would invent a limit"
        );
        assert_eq!(answer["peer_id_scheme"], json!(PEER_ID_SCHEME));
    }

    #[test]
    fn an_address_is_preflighted_by_nau_nets_own_rules_without_a_socket() {
        let mut plugin = plugin(TransportPlugin::CAPABILITIES);

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "precheck", "address": "tcp://127.0.0.1:1", "frame_len": 1024 }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(true));
        assert_eq!(answer["peer_id"], json!("tcp://127.0.0.1:1"));
        assert_eq!(answer["frame"]["ok"], json!(true));
        assert_eq!(
            answer["connects"],
            json!(false),
            "the pre-flight must state that it opened no socket"
        );

        // The cap is nau-net's, and one byte over it is refused by that cap.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "precheck",
                    "address": "tcp://127.0.0.1:1",
                    "frame_len": MAX_FRAME_BYTES + 1,
                }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert_eq!(answer["frame"]["ok"], json!(false));
        assert!(
            answer["frame"]["reason"]
                .as_str()
                .is_some_and(|text| text.contains("exceeds the")),
            "{answer}"
        );

        // An address outside the peer-id charset: a "no" answer, not a refusal.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "precheck", "address": "has space" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert_eq!(answer["peer_id"], json!(null));
        assert!(
            answer["address_reason"]
                .as_str()
                .is_some_and(|text| text.contains("may only contain")),
            "{answer}"
        );
    }

    #[test]
    fn a_request_the_plugin_may_not_serve_is_refused_by_name() {
        let mut plugin = plugin(TransportPlugin::CAPABILITIES);

        // A capability the plugin's token does not hold at all.
        let err = plugin
            .handle(&request("net:dht:read", json!({ "op": "limits" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("net:dht:read"), "{err}");
        assert!(err.to_string().contains(TransportPlugin::ID), "{err}");

        // A capability it *does* hold, declaring an operation it is not the door for.
        let err = plugin
            .handle(&request("plugin:storage:own", json!({ "op": "limits" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("plugin:message:send"), "{text}");

        // And an operation it does not implement lists the ones it does.
        let err = plugin
            .handle(&request("plugin:message:send", json!({ "op": "connect" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("precheck"), "{text}");
    }
}
