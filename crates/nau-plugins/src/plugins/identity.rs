//! `com.twinsearth.sys.identity` — DID derivation and signature verification.
//!
//! # What it actually does
//!
//! It is a door onto `nau-core`'s identity module, not a second implementation of it.
//! The DID is derived by `nau_core::identity::Did::from_public_key`, the signature is
//! verified by `nau_core::identity::PublicKey::verify`, and the DID↔key binding is
//! `nau_core::identity::Did::matches_public_key`. Writing another Ed25519 wrapper
//! here would be a second place for the fingerprint rule to be wrong — which is
//! exactly the duplication `nau-core`'s module documentation warns about, and the
//! reason the cross-language conformance vectors exist.
//!
//! # Why the binding check is its own operation
//!
//! A DID is a *fingerprint*, so it can never verify a signature on its own: the
//! verifier needs the public key, and it must check that the key really hashes to the
//! DID. `verify` therefore answers "is this signature valid under this key?", and
//! `binds` answers "is this key the one this DID names?". A caller that needs both
//! must ask both — a design that makes the impersonation bug (verifying against an
//! attacker-supplied key while trusting a different DID) visible at the call site
//! rather than hiding it inside one "verify" that quietly skips the binding.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `did_from_seed` | `seed_hex` (64 hex chars) | `did`, `legacy_did`, `public_key` |
//! | `did_from_public_key` | `public_key` (64 hex chars) | `did`, `legacy_did` |
//! | `verify` | `public_key`, `message`, `signature` (128 hex chars) | `valid` |
//! | `binds` | `public_key`, `did` | `bound` |
//!
//! Every operation requires the request to declare `plugin:message:send` — a request
//! *is* a message, so that is the capability the sender exercises, and the bus checks
//! it against the sender's token before delivery.

use nau_core::identity::{Did, Keypair, PublicKey, Signature64};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginError, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: a public key, seed or DID could not be parsed.
pub const CODE_KEY_INVALID: &str = "identity_key_invalid";
/// Error code: a signature did not verify.
pub const CODE_SIGNATURE_INVALID: &str = "identity_signature_invalid";

/// The operations this plugin implements, for the unknown-operation refusal.
pub const OPERATIONS: &[&str] = &["did_from_seed", "did_from_public_key", "verify", "binds"];

/// The identity system plugin.
pub struct IdentityPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl IdentityPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.identity";

    /// The capabilities the plugin declares: the basic set, and nothing else. It
    /// derives DIDs and verifies signatures; it does not read the chain, the network
    /// or another plugin's storage, so it declares nothing that would let it.
    pub const CAPABILITIES: &'static [Capability] = &Capability::BASIC;

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`IdentityPlugin::ID`] is not a valid plugin name,
    /// which cannot happen for this constant but is returned rather than asserted.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for IdentityPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        ctx.log(
            crate::host::LogLevel::Info,
            "identity ready: DID derivation and Ed25519 verification delegate to nau-core",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        // 1. The message's declared capability must be one this plugin holds. This is
        //    the bus's check too, and it is repeated here because a T0 plugin is
        //    in-process: the refusal must not depend on which door was used.
        let declared = self.grant.require_declared(msg)?;
        // 2. A request is a message, so that is the capability the operation needs.
        self.grant
            .require_operation(declared, Capability::MessageSend)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "did_from_seed" => self.did_from_seed(&msg.payload),
            "did_from_public_key" => self.did_from_public_key(&msg.payload),
            "verify" => self.verify(&msg.payload),
            "binds" => self.binds(&msg.payload),
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

impl IdentityPlugin {
    /// `did_from_seed`: derive the identity a 32-byte seed determines.
    ///
    /// This is the operation the cross-language conformance vectors use: the seed
    /// `01…01` must produce `did:nau:34750f98bd59fcfc`, which `nau-core`'s own test
    /// asserts against upstream's vector.
    fn did_from_seed(&self, request: &Value) -> Result<Value> {
        let seed = payload::string_field(request, "seed_hex")?;
        let keypair = Keypair::from_seed_hex(seed)
            .map_err(|e| key_error(CODE_KEY_INVALID, format!("seed_hex: {e}")))?;
        let public = keypair.public_key();
        Ok(payload::answer(
            Self::ID,
            "did_from_seed",
            json!({
                "did": keypair.did().to_string(),
                "legacy_did": public.legacy_did().to_string(),
                "public_key": public.to_hex(),
            }),
        ))
    }

    /// `did_from_public_key`: derive the DID a public key fingerprints.
    fn did_from_public_key(&self, request: &Value) -> Result<Value> {
        let key = parse_key(payload::string_field(request, "public_key")?)?;
        Ok(payload::answer(
            Self::ID,
            "did_from_public_key",
            json!({
                "did": key.did().to_string(),
                "legacy_did": key.legacy_did().to_string(),
            }),
        ))
    }

    /// `verify`: is this a valid signature by this key over this message?
    fn verify(&self, request: &Value) -> Result<Value> {
        let key = parse_key(payload::string_field(request, "public_key")?)?;
        let message = payload::string_field(request, "message")?;
        let signature_hex = payload::string_field(request, "signature")?;
        let signature = Signature64::from_hex(signature_hex).map_err(|e| {
            key_error(
                CODE_SIGNATURE_INVALID,
                format!("signature is not a hex Ed25519 signature: {e}"),
            )
        })?;
        key.verify(message.as_bytes(), signature.as_bytes())
            .map_err(|e| {
                key_error(
                    CODE_SIGNATURE_INVALID,
                    format!(
                        "the signature does not verify under {} for the message supplied: {e}",
                        key.to_hex()
                    ),
                )
            })?;
        Ok(payload::answer(
            Self::ID,
            "verify",
            json!({ "valid": true, "did": key.did().to_string() }),
        ))
    }

    /// `binds`: does this key hash to this DID?
    ///
    /// A `false` answer here is an answer, not a refusal: the caller asked a question
    /// whose answer can be "no". A malformed DID or key is the refusal.
    fn binds(&self, request: &Value) -> Result<Value> {
        let key = parse_key(payload::string_field(request, "public_key")?)?;
        let did_text = payload::string_field(request, "did")?;
        let did =
            Did::parse(did_text).map_err(|e| key_error(CODE_KEY_INVALID, format!("did: {e}")))?;
        Ok(payload::answer(
            Self::ID,
            "binds",
            json!({
                "bound": did.matches_public_key(&key),
                "did": did.to_string(),
                "public_key": key.to_hex(),
            }),
        ))
    }
}

/// Parse a hex Ed25519 public key, refusing a weak or malformed one.
fn parse_key(hex_key: &str) -> Result<PublicKey> {
    PublicKey::from_hex(hex_key)
        .map_err(|e| key_error(CODE_KEY_INVALID, format!("public_key: {e}")))
}

/// Build an identity refusal.
fn key_error(code: &str, detail: String) -> PluginError {
    PluginError::Signature(format!("{code}: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostLimits;
    use nau_core::identity::Identity;
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::{CapabilityToken, Tier};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn token(caps: &[Capability]) -> CapabilityToken {
        CapabilityToken::issue(
            IdentityPlugin::ID,
            Tier::System,
            caps,
            DIGEST,
            1_750_000_000,
        )
        .expect("issuable")
    }

    /// The plugin, initialised through the framework with `caps`.
    fn plugin(caps: &[Capability]) -> IdentityPlugin {
        let mut plugin = IdentityPlugin::new().expect("valid id");
        let mut ctx = HostContext::new(token(caps), HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.official.market").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(IdentityPlugin::ID.to_string()),
            Capability::parse(capability).expect("known capability"),
            PmbKind::Request,
            payload,
            1_750_000_000,
        )
    }

    #[test]
    fn the_plugin_is_not_serving_before_init_and_holds_nothing_after_shutdown() {
        let mut plugin = IdentityPlugin::new().expect("valid id");
        let msg = request("plugin:message:send", json!({ "op": "binds" }));
        assert!(plugin.handle(&msg).is_err(), "no token, no service");

        let mut ctx = HostContext::new(token(IdentityPlugin::CAPABILITIES), HostLimits::default())
            .expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin.shutdown().expect("shuts down");
        let err = plugin.handle(&msg).expect_err("refused");
        assert!(err.to_string().contains("capability token"), "{err}");
    }

    #[test]
    fn the_conformance_seed_derives_the_did_nau_core_pins() {
        let mut plugin = plugin(IdentityPlugin::CAPABILITIES);
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "did_from_seed", "seed_hex": "01".repeat(32) }),
            ))
            .expect("answers");
        assert_eq!(answer["did"], json!("did:nau:34750f98bd59fcfc"));
        assert_eq!(answer["legacy_did"], json!("did:aip:34750f98bd59fcfc"));
        assert_eq!(
            answer["public_key"],
            json!("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
        );
    }

    #[test]
    fn a_signature_is_verified_and_a_tampered_one_is_refused() {
        let identity = Identity::from_seed(&[1u8; 32]);
        let message = "the message the market signed";
        let signature = identity.sign_raw(message.as_bytes());
        let mut plugin = plugin(IdentityPlugin::CAPABILITIES);

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "verify",
                    "public_key": identity.public_key().to_hex(),
                    "message": message,
                    "signature": signature,
                }),
            ))
            .expect("verifies");
        assert_eq!(answer["valid"], json!(true));

        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "verify",
                    "public_key": identity.public_key().to_hex(),
                    "message": "a different message",
                    "signature": signature,
                }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains(CODE_SIGNATURE_INVALID), "{err}");
    }

    #[test]
    fn the_did_binding_is_answered_separately_from_the_signature() {
        let identity = Identity::from_seed(&[1u8; 32]);
        let other = Identity::from_seed(&[2u8; 32]);
        let mut plugin = plugin(IdentityPlugin::CAPABILITIES);

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "binds",
                    "public_key": identity.public_key().to_hex(),
                    "did": identity.did().to_string(),
                }),
            ))
            .expect("answers");
        assert_eq!(answer["bound"], json!(true));

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "binds",
                    "public_key": identity.public_key().to_hex(),
                    "did": other.did().to_string(),
                }),
            ))
            .expect("answers");
        assert_eq!(
            answer["bound"],
            json!(false),
            "a false binding is an answer"
        );
    }

    #[test]
    fn a_message_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let mut plugin = plugin(IdentityPlugin::CAPABILITIES);
        let err = plugin
            .handle(&request("net:dht:read", json!({ "op": "binds" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("net:dht:read"), "{err}");
        assert!(
            err.to_string().contains(IdentityPlugin::ID),
            "the refusal names the plugin: {err}"
        );
    }

    #[test]
    fn an_unknown_operation_lists_the_known_ones() {
        let mut plugin = plugin(IdentityPlugin::CAPABILITIES);
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "sign_for_me" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("did_from_seed"), "{text}");
    }

    #[test]
    fn a_malformed_key_is_refused_rather_than_treated_as_absent() {
        let mut plugin = plugin(IdentityPlugin::CAPABILITIES);
        for key in ["", "zz", &"ab".repeat(31)] {
            let err = plugin
                .handle(&request(
                    "plugin:message:send",
                    json!({ "op": "did_from_public_key", "public_key": key }),
                ))
                .expect_err("must be refused");
            assert!(err.to_string().contains(CODE_KEY_INVALID), "{err}");
        }
        // The all-zero key decompresses to a small-order point and is refused.
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "did_from_public_key", "public_key": "00".repeat(32) }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains(CODE_KEY_INVALID), "{err}");
    }

    #[test]
    fn a_payload_that_is_not_an_object_is_refused() {
        let mut plugin = plugin(IdentityPlugin::CAPABILITIES);
        let err = plugin
            .handle(&request("plugin:message:send", json!("just a string")))
            .expect_err("must be refused");
        assert!(err.to_string().contains(payload::CODE_NOT_OBJECT), "{err}");
    }
}
