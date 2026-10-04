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
pub const OPERATIONS: &[&str] = &[
    "did_from_seed",
    "did_from_public_key",
    "verify",
    "binds",
    // E-05: the anchor binding, and the refusal that is the point of it.
    "anchor",
];

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
            // E-05. The digest is produced and the ANCHOR is refused: this door holds the basic
            // capability set, so it has no way to send the transaction. Reporting a local-only
            // identity instead would be exactly the degradation E-05 forbids.
            "anchor" => {
                let card: nau_core::domain::AgentCard = serde_json::from_value(
                    payload::field(&msg.payload, "card")?.clone(),
                )
                .map_err(|e| {
                    payload::protocol(
                        "malformed_card",
                        format!("a card must be a well-formed AgentCard: {e}"),
                    )
                })?;
                let binding = AnchorBinding::of(&card)?;
                let refused_because = match AnchorBinding::support() {
                    AnchorSupport::Available { .. } => None,
                    AnchorSupport::Refused { reason } => Some(reason),
                };
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "cid_hash": binding.cid_hash,
                        "did_hash": binding.did_hash,
                        "did": binding.did,
                        "anchorable_here": AnchorBinding::is_anchorable_here(),
                        "refused_because": refused_because,
                        "fail_closed": "there is no variant meaning local-only: a caller that \
                                        wanted to carry on without the chain would have to invent \
                                        one, which is the point of not providing it",
                        "content_addressed": "the cid_hash is the SHA-256 of the card's CANONICAL \
                                              form -- the same one the workspace signs over -- so \
                                              two identical cards give one digest and a one-byte \
                                              change gives another",
                        "not_this_standard": "this is NOT an implementation of any external \
                                              agent-identity standard: what it binds to is this \
                                              repository's own contracts/src/AgentCardAnchor.sol",
                    }),
                ))
            }
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

/// How anchoring an `AgentCard` is provided, or why it is not.
///
/// # E-05's first criterion, and there is no third variant
///
/// "Anchoring is **fail-closed**: when the chain is unreachable, **refuse**; it must not degrade to
/// 'local identity only'."
///
/// The strongest form of that is a type with **no variant meaning local-only**. There is
/// `Available { via }` and `Refused { reason }` — the same two cases A-03's `EnforcementSupport` and
/// E-01's `RailSupport` use — and a caller that wanted to carry on without the chain would have to
/// invent a third case, which is the point of not providing one.
///
/// This plugin holds the basic capability set and nothing else: it derives DIDs and verifies
/// signatures and **cannot read a chain**. So the answer here is `Refused` on every platform, and the
/// refusal says exactly that rather than being a platform-dependent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorSupport {
    /// It exists, and here is what provides it.
    Available {
        /// What provides it, in terms that are in this repository.
        via: &'static str,
    },
    /// It does not, and here is what is missing.
    Refused {
        /// Why not. A sentence a caller can act on.
        reason: &'static str,
    },
}

/// An anchor binding: what an `AgentCard` would be committed to on-chain.
///
/// # E-05's third criterion: the content addressing is the card's own digest
///
/// `AgentCardAnchor.sol` keys its `_anchors` mapping by `cidHash` and exposes
/// `verify(cidHash, agentDidHash)`, so what an anchor commits to is **a digest** — the same
/// discipline D-06 applies to snapshots and v3.8.7 applies to reputation. Two cards that differ in
/// one byte must produce different digests and two identical cards the same one, and that is a
/// property a test can hold rather than a claim a document can make.
///
/// # E-05's second criterion, and the premise it needed corrected
///
/// The plan says `ERC-8004` has **zero hits** in this repository and that this is why no
/// compatibility may be claimed. **That was true when the plan was written and is not true now**:
/// v3.8.0's `REFUSED` table and v3.9.0's `SETTLEMENT_NOUNS` both name it.
///
/// **The conclusion survives** — nothing here implements that standard, and this binding is
/// explicitly the repository's **own** anchor contract — and the premise does not. The same
/// correction E-03 needed, for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorBinding {
    /// The digest an anchor would be filed under, hex.
    pub cid_hash: String,
    /// The `Did`'s own hash, hex, as the contract's second argument wants.
    pub did_hash: String,
    /// The `Did` this binding is about, for a reader.
    pub did: String,
}

impl AnchorBinding {
    /// Build a binding from a card's canonical bytes.
    ///
    /// # Errors
    ///
    /// [`PluginError::Protocol`] when the card's canonical form cannot be produced — the same
    /// function the rest of the workspace uses for signing payloads, so a card that cannot be
    /// canonicalised is one that could not be anchored **or** signed, and saying so here is better
    /// than producing a digest of something else.
    pub fn of(card: &nau_core::domain::AgentCard) -> Result<Self> {
        let value = serde_json::to_value(card).map_err(|e| {
            payload::protocol(
                "card_not_encodable",
                format!("the card did not encode: {e}"),
            )
        })?;
        // The workspace's canonical form, which requires a root object -- rule 1 of the canonical
        // JSON contract. Using it rather than `serde_json::to_string` is what makes the digest
        // reproducible across implementations, which is the whole of content addressing.
        let canonical = nau_core::canonical::canonical_object(&value).map_err(|e| {
            payload::protocol(
                "card_not_canonical",
                format!("the card has no canonical form: {e}"),
            )
        })?;
        Ok(Self {
            cid_hash: digest_hex(canonical.as_bytes()),
            did_hash: digest_hex(card.owner.as_str().as_bytes()),
            did: card.owner.as_str().to_string(),
        })
    }

    /// How this binding would be anchored, or why it cannot be.
    ///
    /// **Always `Refused`**, and the reason is the capability rather than the platform: this plugin
    /// holds the basic set, so it has no `chain:evm:write` and no way to send a transaction. The
    /// digest is still produced — it is the part a caller can use from anywhere — but **the anchor
    /// itself is refused rather than approximated locally.**
    #[must_use]
    pub fn support() -> AnchorSupport {
        AnchorSupport::Refused {
            reason:
                "anchoring writes to `contracts/src/AgentCardAnchor.sol`, and this plugin holds \
                     the basic capability set with no `chain:evm:*` -- so it cannot send the \
                     transaction. The digest below is what a caller WITH that capability would \
                     anchor; refusing here rather than reporting a local-only identity is E-05's \
                     fail-closed criterion.",
        }
    }

    /// Whether this could be anchored from here.
    #[must_use]
    pub fn is_anchorable_here() -> bool {
        matches!(Self::support(), AnchorSupport::Available { .. })
    }
}

/// A lowercase hex SHA-256 of `bytes`.
///
/// Local to this module rather than shared, because the workspace's existing digest helpers live
/// where they are used. A test holds it to its length and its alphabet, which is what keeps it from
/// being a digest of the wrong width.
fn digest_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod anchor_tests {
    use super::*;
    use nau_core::domain::Money;
    use nau_core::domain::{AgentCard, Skill};
    use nau_core::identity::Identity;

    /// A card built with the workspace's OWN constructor, not a hand-rolled literal.
    ///
    /// My first version of this fixture invented three shapes -- `AgentCategory::Compute`,
    /// `Skill { name, description }` and `AgentCard::default()` -- and none of the three exists.
    /// `AgentCard::draft` takes an `Identity`, and `Skill::new` takes an id and a version. That is
    /// the invented-shape defect for the sixth time in this project, and the fix is to read the
    /// constructor rather than to guess at the struct.
    fn card_from(seed: u8, name: &str) -> AgentCard {
        AgentCard::draft(
            &Identity::from_seed(&[seed; 32]),
            name,
            vec![Skill::new("inference", 1)],
            Money::from_minor(100),
            1_700_000_000,
            1,
        )
    }

    /// The common case: one deterministic identity, so a digest is reproducible across runs.
    fn card(name: &str) -> AgentCard {
        card_from(7, name)
    }
    #[test]
    fn anchoring_refuses_here_and_there_is_no_local_only_variant() {
        // E-05's first criterion, and the type is the proof: `AnchorSupport` has two cases and
        // neither of them means "carry on without the chain".
        assert!(!AnchorBinding::is_anchorable_here());
        match AnchorBinding::support() {
            AnchorSupport::Refused { reason } => {
                assert!(reason.contains("chain:evm"), "{reason}");
                assert!(
                    reason.contains("fail-closed"),
                    "the refusal must name the criterion it is satisfying: {reason}"
                );
                assert!(
                    reason.contains("local-only"),
                    "and must name the degradation it is refusing: {reason}"
                );
            }
            AnchorSupport::Available { .. } => {
                panic!("this plugin holds no chain capability, so it cannot anchor")
            }
        }
    }

    #[test]
    fn the_digest_is_content_addressed_and_a_single_character_changes_it() {
        // E-05's third criterion. Two cards differing in one byte must produce different digests,
        // and the digest must be the canonical form's -- the same one the workspace signs over.
        let a = AnchorBinding::of(&card("alpha")).expect("a binding");
        let b = AnchorBinding::of(&card("alphb")).expect("a binding");
        assert_ne!(
            a.cid_hash, b.cid_hash,
            "one character must change the digest"
        );

        // The same card twice gives the same digest, so a re-anchor of unchanged content is a no-op
        // rather than a second anchor.
        let mut same = card("alpha");
        let first = AnchorBinding::of(&same).expect("a binding");
        assert_eq!(
            first.cid_hash,
            AnchorBinding::of(&same).expect("a binding").cid_hash
        );
        // And it is stable across a round trip through JSON, which is what makes it reproducible
        // rather than merely repeatable within one process.
        let text = serde_json::to_string(&same).expect("encodes");
        let back: AgentCard = serde_json::from_str(&text).expect("decodes");
        assert_eq!(
            AnchorBinding::of(&back).expect("a binding").cid_hash,
            first.cid_hash
        );

        // Mutating one field changes it, so the digest commits to the whole card and not to a part.
        same.name = "beta".to_string();
        assert_ne!(
            AnchorBinding::of(&same).expect("a binding").cid_hash,
            first.cid_hash
        );
    }

    #[test]
    fn the_two_hashes_are_hex_and_the_right_lengths() {
        // `AgentCardAnchor.sol` takes two `bytes32` arguments, so both fields must be 64 hex
        // characters: a short one would be a digest of the wrong thing.
        let binding = AnchorBinding::of(&card("alpha")).expect("a binding");
        for (label, hash) in [("cid", &binding.cid_hash), ("did", &binding.did_hash)] {
            assert_eq!(hash.len(), 64, "{label} must be 32 bytes of hex");
            assert!(
                hash.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{label} must be lowercase hex: {hash}"
            );
        }
        // The DID hash is of the DID itself, so two cards owned by DIFFERENT identities differ
        // there too -- and the two identities come from different seeds, because the fixture is
        // deterministic rather than generated.
        //
        // My first version of this assertion said "each generated keypair has its own DID" and
        // failed, because the fixture used one fixed seed for both cards. The fixture was right and
        // the assertion's premise was wrong: a deterministic identity is what makes a digest
        // reproducible across runs, and differing hashes need differing seeds rather than a random
        // draw.
        let other = AnchorBinding::of(&card_from(8, "alpha")).expect("a binding");
        assert_ne!(
            binding.did_hash, other.did_hash,
            "two identities must have two DID hashes"
        );
        // The same seed twice gives the same DID hash, which is the property the fixture relies on.
        assert_eq!(
            binding.did_hash,
            AnchorBinding::of(&card("alpha"))
                .expect("a binding")
                .did_hash
        );
        assert!(binding.did.starts_with("did:nau:"));
    }

    #[test]
    fn it_does_not_claim_compatibility_with_any_external_standard() {
        // E-05's second criterion: what this anchors to is this repository's OWN contract, and the
        // plan's zero-hit premise for ERC-8004 is no longer true -- the conclusion is unchanged.
        let binding = AnchorBinding::of(&card("alpha")).expect("a binding");
        let rendered = format!("{binding:?}");
        for externality in ["ERC-8004", "ERC8004", "8004"] {
            assert!(
                !rendered.contains(externality),
                "the binding must not claim {externality} compatibility: {rendered}"
            );
        }
        // And the refusal, which is the answer a caller gets, names the local contract by path.
        if let AnchorSupport::Refused { reason } = AnchorBinding::support() {
            assert!(
                reason.contains("AgentCardAnchor.sol"),
                "the refusal must name THIS repository's contract by path: {reason}"
            );
        }
    }
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
