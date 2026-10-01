//! `com.twinsearth.sys.migrate` — an upstream v2.5.6 AgentCard, read and verified
//! through `nau-migrate`.
//!
//! # What it delegates to, and what it does not re-derive
//!
//! Every rule the answer depends on is `nau-migrate`'s:
//!
//! | Step | `nau-migrate` item |
//! |---|---|
//! | the text is one JSON value, verbatim | [`rawjson::root_slices`] |
//! | field lookup by every name the audit records | [`field::required_str`], [`field::find_present`], [`field::optional_str`], [`field::optional_u64`] |
//! | the DID is a DID, and its prefix is named | [`field::required_str`] + [`field::parse_did`] |
//! | a decimal is read from the bytes on disk, never through a float | [`field::money_field`] + [`rawjson`] |
//! | the legacy signature verifies under this project's canonical form | [`verify_legacy_record`] |
//! | a `DID → key` registry, because a DID is only a fingerprint | [`keys_from_json`] + [`KeyRegistry`] |
//!
//! What it does **not** do is construct `nau_core::AgentCard`. The authoritative
//! card→`AgentCard` conversion is `nau_migrate::plan_from_dir`, which reads a
//! *directory tree*; its per-record routine (`plan_card`) is private and a T0 plugin
//! holds no filesystem authority to spool a file into (see [`crate::host`]:
//! [`HostContext`] carries no path and no store). So this plugin does the half that
//! is expressible through `nau-migrate`'s public readers — read, verify, project —
//! and the answer says so in `authoritative_conversion` and lists what it did not
//! apply in `not_checked`. Nothing here is a second implementation of a *rule*; what
//! is not covered is named rather than silently assumed.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `card` | `card_json` (the verbatim AgentCard text), optional `keys` (`{"<did>": "<hex>"}`) | `legacy_did`, `legacy_prefix`, `name`, `capabilities`, `unit_price_minor`, `stake_minor`, `signed_at`, `nonce`, `expires_at`, `public_key`, `signature`, `canonical_payload`, `signature_verified`, `authoritative_conversion`, `not_checked` |
//!
//! The card arrives as **text**, not as a JSON value, because `nau-migrate` reads a
//! decimal from the literal bytes rather than from a parsed float; re-serializing a
//! caller's object here would replace those bytes with this process's rendering of
//! them. The operation requires the request to declare `plugin:message:send` — a
//! request *is* a message, so that is the capability the sender exercises.
//!
//! # Refusals
//!
//! Every refusal is named: [`CODE_CARD_NOT_JSON`] when the text is not exactly one
//! JSON object, and [`CODE_CARD_REJECTED`] followed by `nau-migrate`'s own
//! [`Finding`] code when a reader refuses the record — `signature_invalid`,
//! `missing_field`, `invalid_did`, `amount_not_exact`, `missing_public_key` and the
//! rest. A caller can branch on the code rather than on the prose.

use std::fmt::Display;

use nau_core::identity::PublicKey;
use nau_core::{Did, Money};
use nau_migrate::{
    field, keys_from_json, rawjson, verify_legacy_record, Defect, Finding, KeyRegistry, Warning,
};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginError, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: the `card_json` field is not exactly one JSON object.
pub const CODE_CARD_NOT_JSON: &str = "migrate_card_not_json";
/// Error code: `nau-migrate` refused the record; the message names its [`Finding`].
pub const CODE_CARD_REJECTED: &str = "migrate_card_rejected";

/// The operations this plugin implements, for the unknown-operation refusal.
pub const OPERATIONS: &[&str] = &["card"];

/// The label `nau-migrate`'s findings carry for a record that arrived in a request
/// rather than in a file. It stands where `read_record_sources` puts `agents.json`.
pub const REQUEST_SOURCE: &str = "request:card_json";

/// The label the optional `keys` object carries in a finding.
pub const REQUEST_KEYS_SOURCE: &str = "request:keys.json";

/// What the authoritative conversion does that this projection does not.
///
/// Reported in every answer so that "the card parsed" is never read as "the card
/// would migrate": the omissions are facts about this door, not about the input.
pub const NOT_CHECKED: &[&str] = &[
    "nau_core::AgentCard construction and AgentCard::validate (that is plan_from_dir's job)",
    "the object form of a capability entry ({id, version, description}); this door accepts the \
     string form only and refuses an object entry by name",
    "capability-id normalisation and the skill index",
    "endpoints, and the documented defaults the conversion fills in",
];

/// The migrate system plugin.
pub struct MigratePlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl MigratePlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.migrate";

    /// The capabilities the plugin declares: the basic set. It parses and verifies
    /// text; it reads no file, opens no socket and holds no store, so it declares
    /// nothing that would let it.
    pub const CAPABILITIES: &'static [Capability] = &Capability::BASIC;

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`MigratePlugin::ID`] is not a valid plugin name,
    /// which cannot happen for this constant but is returned rather than asserted.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for MigratePlugin {
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
            "migrate ready: an upstream v2.5.6 AgentCard is read and verified by nau-migrate's \
             readers; the card-to-AgentCard conversion stays in plan_from_dir",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        // 1. The message's declared capability must be one this plugin holds. The bus
        //    checks this too, and it is repeated here because a T0 plugin is
        //    in-process: the refusal must not depend on which door was used.
        let declared = self.grant.require_declared(msg)?;
        // 2. A request is a message, so that is the capability the operation needs.
        self.grant
            .require_operation(declared, Capability::MessageSend)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "card" => self.card(&msg.payload),
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

impl MigratePlugin {
    /// `card`: read one upstream AgentCard record and verify its legacy signature.
    ///
    /// # Errors
    ///
    /// [`CODE_CARD_NOT_JSON`] when `card_json` is not exactly one JSON object, and
    /// [`CODE_CARD_REJECTED`] naming the [`Finding`] when a reader refuses it.
    fn card(&self, request: &Value) -> Result<Value> {
        let card_json = payload::string_field(request, "card_json")?;

        // The verbatim slice, from nau-migrate's own scanner: the same entry point
        // `read_record_sources` uses on a file, so a card that is one JSON value here
        // is one JSON value there.
        let slices = rawjson::root_slices(card_json).map_err(|error| {
            named(
                CODE_CARD_NOT_JSON,
                format!("`card_json` is not one JSON value: {error}"),
            )
        })?;
        let Some(text) = slices.first() else {
            return Err(named(
                CODE_CARD_NOT_JSON,
                "`card_json` holds no JSON value".to_string(),
            ));
        };
        if slices.len() != 1 {
            return Err(named(
                CODE_CARD_NOT_JSON,
                format!(
                    "`card_json` holds {} top-level JSON values; one AgentCard record is required",
                    slices.len()
                ),
            ));
        }
        let value: Value = serde_json::from_str(text).map_err(|error| {
            named(
                CODE_CARD_NOT_JSON,
                format!("`card_json` is not valid JSON: {error}"),
            )
        })?;
        if !value.is_object() {
            return Err(named(
                CODE_CARD_NOT_JSON,
                format!(
                    "an AgentCard must be a JSON object, found {}",
                    field::kind_of(&value)
                ),
            ));
        }

        let did_text =
            field::required_str(REQUEST_SOURCE, &value, &["did", "agent_id"]).map_err(refused)?;
        let did = field::parse_did(REQUEST_SOURCE, "did", &did_text).map_err(refused)?;
        let legacy_prefix = did.prefix() == nau_core::DID_PREFIX_LEGACY;

        let registry = self.key_registry(request)?;
        let public_key = resolve_key(REQUEST_SOURCE, &value, &did, &registry)?;
        let verified = verify_legacy_record(REQUEST_SOURCE, &value, did.clone(), public_key)
            .map_err(refused)?;

        let name = field::required_str(REQUEST_SOURCE, &value, &["name"]).map_err(refused)?;
        let capabilities = field::string_list(
            REQUEST_SOURCE,
            &value,
            &["capabilities", "skills", "capability"],
        )
        .map_err(refused)?;
        // The two requirements `plan_card` adds on top of its readers, applied here so
        // that this door is never *more permissive* than the migration it stands in
        // for: an agent with no skill cannot be matched, and a card without a positive
        // stake cannot be admitted (upstream accepted a zero or negative stake and
        // even `NaN`, because `NaN < min_stake` is false).
        let capabilities = capabilities
            .filter(|list| !list.is_empty())
            .ok_or_else(|| {
                refused_missing(
                "required field `capabilities` is missing or empty: this project's AgentCard must \
                 declare at least one skill to be discoverable",
            )
            })?;
        let stake = field::money_field(REQUEST_SOURCE, text, &value, &["stake", "bond"])
            .map_err(refused)?
            .ok_or_else(|| {
                refused_missing(
                    "required field `stake` is missing: this project's AgentCard must carry a \
                     positive stake",
                )
            })?;
        if !stake.is_positive() {
            return Err(refused(Defect::new(
                Finding::NonPositiveAmount,
                REQUEST_SOURCE,
                format!(
                    "field `stake` = {} is not positive; upstream accepted a zero or negative stake \
                     and even `NaN`, this project does not",
                    stake.to_decimal_string()
                ),
            )));
        }
        let unit_price = field::money_field(
            REQUEST_SOURCE,
            text,
            &value,
            &["price_per_task", "price", "unit_price"],
        )
        .map_err(refused)?;
        let signed_at = field::optional_u64(REQUEST_SOURCE, &value, &["signed_at", "created_at"])
            .map_err(refused)?;
        let nonce = field::optional_u64(REQUEST_SOURCE, &value, &["nonce"]).map_err(refused)?;
        let expires_at =
            field::optional_u64(REQUEST_SOURCE, &value, &["expires_at"]).map_err(refused)?;

        Ok(payload::answer(
            Self::ID,
            "card",
            json!({
                "source": REQUEST_SOURCE,
                "legacy_did": did_text,
                "did": verified.did.to_string(),
                "legacy_prefix": legacy_prefix,
                "name": name,
                "capabilities": capabilities,
                "unit_price_minor": minor_of(unit_price),
                "unit_price": decimal_of(unit_price),
                "stake_minor": stake.minor(),
                "stake": stake.to_decimal_string(),
                "signed_at": signed_at,
                "nonce": nonce,
                "expires_at": expires_at,
                "public_key": verified.public_key.to_hex(),
                "signature": verified.signature,
                "canonical_payload": verified.canonical_payload,
                "signature_verified": true,
                "authoritative_conversion": "nau_migrate::plan_from_dir",
                "not_checked": NOT_CHECKED,
            }),
        ))
    }

    /// The optional `keys` object, read by `nau-migrate`'s own `keys.json` reader.
    ///
    /// # Errors
    ///
    /// [`CODE_CARD_REJECTED`] naming the finding when an entry is refused, because a
    /// registry that silently lost the key for this DID would turn into a
    /// `missing_public_key` refusal against the wrong cause.
    fn key_registry(&self, request: &Value) -> Result<KeyRegistry> {
        let Some(keys) = payload::object(request)?.get("keys") else {
            return Ok(KeyRegistry::new());
        };
        if keys.is_null() {
            return Ok(KeyRegistry::new());
        }
        let mut findings: Vec<Warning> = Vec::new();
        let registry = keys_from_json(REQUEST_KEYS_SOURCE, keys, &mut findings);
        if let Some(rejection) = findings.iter().find(|finding| finding.is_rejection()) {
            return Err(named(
                CODE_CARD_REJECTED,
                format!(
                    "{}: {}: {}",
                    rejection.code.as_str(),
                    REQUEST_KEYS_SOURCE,
                    rejection.detail
                ),
            ));
        }
        Ok(registry)
    }
}

/// Resolve the public key: inline in the record, or from the registry — the same
/// precedence, and the same field names, as `nau_migrate::plan::resolve_key`.
///
/// A DID is `sha256(public key)[..8]`, a fingerprint, so it can never verify a
/// signature by itself; a record that carries neither an inline key nor a registry
/// entry is refused by name rather than verified against nothing.
fn resolve_key(
    source: &str,
    value: &Value,
    did: &Did,
    registry: &KeyRegistry,
) -> Result<PublicKey> {
    let names = ["public_key", "owner_key", "requester_key", "pubkey"];
    if let Some((name, found)) = field::find_present(value, &names) {
        let text = found.as_str().ok_or_else(|| {
            refused(Defect::new(
                Finding::InvalidFieldType,
                source,
                format!(
                    "field `{name}` must be a hex string, found {}",
                    field::kind_of(found)
                ),
            ))
        })?;
        return PublicKey::from_hex(text).map_err(|error| {
            refused(Defect::new(
                Finding::InvalidFieldValue,
                source,
                format!("field `{name}` = `{text}` is not a public key: {error}"),
            ))
        });
    }
    match registry.get(did.as_str()) {
        Some(key) => Ok(key),
        None => Err(refused(Defect::new(
            Finding::MissingPublicKey,
            source,
            format!(
                "no public key for `{did}`: a DID is only the fingerprint `sha256(pubkey)[..8]`, so \
                 it cannot verify a signature by itself. Put the key in the record as `public_key`, \
                 or list it in the request's `keys` object as {{\"{did}\": \"<64 hex characters>\"}}"
            ),
        ))),
    }
}

/// The minor-unit value of an optional amount, or `null`.
fn minor_of(amount: Option<Money>) -> Value {
    match amount {
        Some(money) => json!(money.minor()),
        None => Value::Null,
    }
}

/// The decimal rendering of an optional amount, or `null`.
fn decimal_of(amount: Option<Money>) -> Value {
    match amount {
        Some(money) => json!(money.to_decimal_string()),
        None => Value::Null,
    }
}

/// Build a refusal that *names* `nau-migrate`'s finding code.
fn refused(defect: Defect) -> PluginError {
    named(
        CODE_CARD_REJECTED,
        format!(
            "{}: {}: {}",
            defect.code.as_str(),
            defect.source,
            defect.detail
        ),
    )
}

/// A refusal for a field this door requires and `plan_card` requires too.
fn refused_missing(detail: &str) -> PluginError {
    named(
        CODE_CARD_REJECTED,
        format!(
            "{}: {REQUEST_SOURCE}: {detail}",
            Finding::MissingField.as_str()
        ),
    )
}

/// Build a named refusal.
fn named(code: &str, detail: impl Display) -> PluginError {
    PluginError::Runtime(format!("{code}: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use nau_core::identity::Identity;
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
        CapabilityToken::issue(MigratePlugin::ID, Tier::System, caps, DIGEST, NOW)
            .expect("issuable")
    }

    /// The plugin, initialised through the framework with `caps`.
    fn plugin(caps: &[Capability]) -> MigratePlugin {
        let mut plugin = MigratePlugin::new().expect("valid id");
        let mut ctx = HostContext::new(token(caps), HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.sys.policy").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(MigratePlugin::ID.to_string()),
            Capability::parse(capability).expect("known capability"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    /// An upstream-shaped card, signed by a real key over this project's canonical
    /// form — the same construction `nau-migrate`'s own legacy tests use.
    fn signed_card(seed: u8) -> (Identity, Value) {
        let identity = Identity::from_seed(&[seed; 32]);
        let mut card = json!({
            "did": identity.public_key().legacy_did().as_str(),
            "name": "CrossLang",
            "capabilities": ["text-generation", "mcp"],
            "endpoint": "https://agents.example.invalid/crosslang",
            "price_per_task": "12.5",
            "stake": 100,
            "public_key": identity.public_key().to_hex(),
            "signature": "",
        });
        let signature = identity.sign_payload(&card).expect("signs");
        card["signature"] = json!(signature);
        (identity, card)
    }

    #[test]
    fn the_plugin_registers_reaches_running_and_reads_a_signed_card() {
        let verified = crate::sign::verified_system(
            MigratePlugin::ID,
            MigratePlugin::CAPABILITIES,
            &crate::sign::fixture_key(HOST_SEED),
            &crate::sign::fixture_key(VENDOR_SEED),
        )
        .expect("a system manifest verifies");
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(
            Box::new(MigratePlugin::new().expect("valid id")),
            &verified,
            NOW,
        )
        .expect("registers");
        host.init(MigratePlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(MigratePlugin::ID), Some(PluginState::Running));

        let (identity, card) = signed_card(1);
        let answer = host
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "card", "card_json": card.to_string() }),
            ))
            .expect("answers");
        assert_eq!(
            answer["legacy_did"],
            json!(identity.public_key().legacy_did().to_string())
        );
        assert_eq!(answer["legacy_prefix"], json!(true));
        assert_eq!(answer["name"], json!("CrossLang"));
        assert_eq!(answer["capabilities"], json!(["text-generation", "mcp"]));
        assert_eq!(answer["unit_price_minor"], json!(12_500_000));
        assert_eq!(answer["stake_minor"], json!(100_000_000));
        assert_eq!(answer["signature_verified"], json!(true));
        assert_eq!(
            answer["authoritative_conversion"],
            json!("nau_migrate::plan_from_dir"),
            "the answer must not pretend to be the conversion itself"
        );
        assert!(answer["not_checked"]
            .as_array()
            .is_some_and(|a| !a.is_empty()));
    }

    #[test]
    fn a_card_this_project_cannot_accept_is_refused_with_nau_migrates_finding_code() {
        let mut plugin = plugin(MigratePlugin::CAPABILITIES);

        // A signature that does not cover the record it is attached to.
        let (_, mut tampered) = signed_card(2);
        tampered["name"] = json!("CrossLane");
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "card", "card_json": tampered.to_string() }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(CODE_CARD_REJECTED), "{text}");
        assert!(text.contains("signature_invalid"), "{text}");

        // A card with no stake: refused by name, not migrated without one. The
        // signature is recomputed so that the refusal under test is the missing
        // field, not a signature that no longer covers the record.
        let (identity, mut unstaked) = signed_card(3);
        unstaked
            .as_object_mut()
            .expect("a card is an object")
            .remove("stake");
        let signature = identity.sign_payload(&unstaked).expect("signs");
        unstaked["signature"] = json!(signature);
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "card", "card_json": unstaked.to_string() }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("missing_field"), "{text}");
        assert!(text.contains("stake"), "{text}");

        // Text that is not one JSON object at all.
        for card_json in ["{", "[1, 2]", "\"a string\"", "{} {}"] {
            let err = plugin
                .handle(&request(
                    "plugin:message:send",
                    json!({ "op": "card", "card_json": card_json }),
                ))
                .expect_err("must be refused");
            assert!(err.to_string().contains(CODE_CARD_NOT_JSON), "{err}");
        }
    }

    #[test]
    fn a_key_from_the_requests_registry_is_used_and_a_missing_one_is_named() {
        let mut plugin = plugin(MigratePlugin::CAPABILITIES);
        let identity = Identity::from_seed(&[4u8; 32]);
        let did = identity.public_key().legacy_did().to_string();
        let mut card = json!({
            "did": did,
            "name": "RegistryKeyed",
            "capabilities": ["text-generation"],
            "stake": 1,
            "signature": "",
        });
        let signature = identity.sign_payload(&card).expect("signs");
        card["signature"] = json!(signature);

        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "card", "card_json": card.to_string() }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains("missing_public_key"), "{err}");

        // A computed key, so the object is built rather than written as a literal.
        let mut keys = serde_json::Map::new();
        keys.insert(did.clone(), json!(identity.public_key().to_hex()));
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "card",
                    "card_json": card.to_string(),
                    "keys": Value::Object(keys),
                }),
            ))
            .expect("answers");
        assert_eq!(answer["did"], json!(did));
        assert_eq!(answer["stake_minor"], json!(1_000_000));
    }

    #[test]
    fn a_message_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let mut plugin = plugin(MigratePlugin::CAPABILITIES);
        let err = plugin
            .handle(&request("chain:evm:write", json!({ "op": "card" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("chain:evm:write"), "{err}");

        // A capability it holds, declared for an operation that is not its door.
        let err = plugin
            .handle(&request("plugin:storage:own", json!({ "op": "card" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("plugin:message:send"), "{err}");
    }
}
