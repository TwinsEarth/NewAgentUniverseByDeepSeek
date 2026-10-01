//! `com.twinsearth.sys.chain` — the configuration contract a chain read needs, and a
//! pre-flight of its inputs. **No read is performed, and every answer says so.**
//!
//! # There is no Rust-side chain client in this workspace, and this door does not pretend
//! otherwise
//!
//! `contracts/` is a Solidity + Foundry tree: four contracts under `src/`, their tests, a
//! deploy script (`script/Deploy.s.sol`), a deploy config and a `VERSION` file. Nothing in
//! `crates/` speaks JSON-RPC, encodes ABI calldata or has an EVM address type — the string
//! `chain:evm:` appears in Rust only as the capability name and in fixtures that name it.
//!
//! So this plugin takes the branch the objective names for exactly this case: it reports
//! the **configuration contract** a read would need and **pre-checks the inputs** of one,
//! and it performs no read. `read_performed: false` is in every answer, `rpc_client` is
//! `null`, and `abi_encoder` is `null` with the reason. A plugin that reported a chain read
//! it cannot deliver is the defect this project exists to refuse.
//!
//! # What is delegated, and what is this door's own rule
//!
//! | Check | Whose rule |
//! |---|---|
//! | the RPC endpoint is a URL this build can speak | `nau_http::parse_url` — the client `nau-http` really has |
//! | the calldata is hex | `hex::decode` — the same crate `crate::sign` already uses |
//! | `to` is `0x` + exactly 40 hex digits | **this door's**, and named as such: the workspace has no EVM address type |
//! | `chain_id` is a decimal quantity or a `0x` hex quantity | **this door's**, modelled on JSON-RPC's quantity encoding |
//! | the deployed version the config must carry | `contracts/VERSION`, which `script/Deploy.s.sol` refuses to deploy against if it disagrees |
//!
//! The two local rules are labelled in the answer (`checked_by`) rather than attributed to
//! a crate that does not have them. `EIP-55` mixed-case checksum verification is **not**
//! performed, and `address_checksum` says so: no keccak-256 implementation is a dependency
//! of this crate, and a checksum that was not verified must not read as verified.
//!
//! The transport that could reach an endpoint exists — `nau-http` performs one GET, and
//! `com.twinsearth.sys.http` is the door that does it. This door sends nothing.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `config` | — | `read_performed`, `read_performed_note`, `requirements`, `expected_version`, `expected_version_note`, `sources`, `rpc_client`, `rpc_client_note`, `abi_encoder`, `abi_encoder_note`, `address_checksum`, `address_checksum_note`, `not_performed` |
//! | `precheck` | `rpc_url`, optional `chain_id`, optional `to`, optional `data` | `rpc_url`, `chain_id`, `to`, `data`, `legal`, `read_performed`, `read_performed_note`, `not_checked`, `connects` |
//!
//! Both operations require the request to declare `chain:evm:read`: this is the chain-read
//! door, so the bus checks the *caller's* token for that capability before delivery and
//! [`PluginGrant::require_operation`] checks the declaration again here. The plugin declares
//! it because [`crate::host::SystemPluginHost::register`] refuses a plugin that declares
//! more than its manifest grants — the declaration is the door's name, and the answer's
//! `read_performed: false` is what keeps it from reading as a claim that a read happened.
//!
//! An input that fails a rule is a **well-formed question whose answer is "no"** —
//! `legal: false`, with the failing field's own reason — not a refusal. Only a malformed
//! *request* is an `Err`.

use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements, for the unknown-operation refusal.
pub const OPERATIONS: &[&str] = &["config", "precheck"];

/// Hex digits in an EVM address (20 bytes), after the `0x` prefix.
pub const ADDRESS_DIGITS: usize = 40;

/// The prefix this door requires on addresses, calldata and hex quantities.
///
/// Lower case only, and that is a decision: `contracts/deploy.config.example.json` and
/// JSON-RPC's quantity encoding both write `0x`, and accepting a second spelling here would
/// make two strings mean one address without either being canonical.
pub const HEX_PREFIX: &str = "0x";

/// Hex digits a `chain_id` may have: sixteen, because a chain id is bounded to `u64`.
pub const MAX_CHAIN_ID_HEX_DIGITS: usize = 16;

/// The sentence every answer carries about the read that was not performed.
pub const READ_PERFORMED_NOTE: &str = "no Rust-side chain client exists in this workspace: \
     `contracts/` is Solidity and Foundry only, and no crate under `crates/` speaks JSON-RPC, \
     encodes ABI calldata or has an EVM address type. This door answers the configuration \
     contract a read needs and pre-checks the inputs of one; it builds no request, opens no \
     socket and reads nothing.";

/// What a `config` answer lists as not performed.
pub const NOT_PERFORMED: &[&str] = &[
    "no JSON-RPC request is built or sent",
    "no ABI is loaded and no calldata is built (a caller supplies the encoded call)",
    "the chain id an endpoint reports (eth_chainId) is never compared with the configured one",
    "no deployed bytecode is read, and no address is checked for code",
    "no EIP-55 checksum is verified (no keccak-256 is a dependency of this crate)",
];

/// The input checks a `precheck` answer did not make.
pub const NOT_CHECKED: &[&str] = &[
    "whether the endpoint answers, and what it answers with",
    "whether the configured chain id is the one the endpoint reports (that is `eth_chainId`, a read)",
    "whether the address has code, or holds the contract the caller believes it does",
    "whether the calldata matches any ABI, or selects a function that exists (no ABI encoder exists here)",
    "whether an EIP-55 mixed-case checksum is correct",
];

/// The chain-read system plugin.
pub struct ChainPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl ChainPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.chain";

    /// The capabilities the plugin declares: the basic set, plus `chain:evm:read`.
    ///
    /// The extra capability is the door's name rather than a claim about this process:
    /// every operation here requires a request that declares `chain:evm:read`, so the bus
    /// checks the *caller's* token for it, and the plugin declares it because
    /// [`crate::host::SystemPluginHost::register`] refuses a plugin that declares more than
    /// its manifest grants. The plugin itself performs no read — see the module docs.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::ChainEvmRead,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if [`ChainPlugin::ID`] is not a valid plugin name,
    /// which cannot happen for this constant but is returned rather than asserted.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for ChainPlugin {
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
            "chain ready: configuration contract and input pre-flight only; this build has no \
             chain client and no read is performed",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        // 1. The message's declared capability must be one this plugin holds. The bus
        //    checks this too, and it is repeated here because a T0 plugin is in-process:
        //    the refusal must not depend on which door was used.
        let declared = self.grant.require_declared(msg)?;
        // 2. This is the chain-read door, so every operation of it needs a request that
        //    declares `chain:evm:read` — the capability the bus checks against the caller.
        self.grant
            .require_operation(declared, Capability::ChainEvmRead)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "config" => Ok(self.config()),
            "precheck" => self.precheck(&msg.payload),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        // Nothing to release: this plugin holds no connection and no client — there is none
        // to hold — and giving up the grant is what makes a call after shutdown a typed
        // refusal rather than one that still has authority behind it.
        self.grant.release();
        Ok(())
    }
}

impl ChainPlugin {
    /// `config`: the configuration contract a chain read needs, and what this build does
    /// not have.
    fn config(&self) -> Value {
        payload::answer(
            Self::ID,
            "config",
            json!({
                "read_performed": false,
                "read_performed_note": READ_PERFORMED_NOTE,
                "requirements": [
                    {
                        "field": "rpc_url",
                        "shape": "an `http://` or `https://` URL",
                        "checked_by": "nau_http::parse_url",
                        "why": "a read has to reach an endpoint, and `nau-http` is the only \
                            HTTP client this build has (`com.twinsearth.sys.http` is the door \
                            that performs a GET)",
                    },
                    {
                        "field": "chain_id",
                        "shape": format!(
                            "decimal digits, or a `{HEX_PREFIX}` hex quantity with no leading \
                             zeros, bounded to {MAX_CHAIN_ID_HEX_DIGITS} hex digits (u64)"
                        ),
                        "checked_by": "this door's quantity rule (see `precheck.chain_id`)",
                        "why": "a contract address is meaningful on exactly one chain; a read \
                            whose chain id is not pinned cannot be attributed to a deployment",
                    },
                    {
                        "field": "to",
                        "shape": format!("`{HEX_PREFIX}` followed by exactly {ADDRESS_DIGITS} hex digits"),
                        "checked_by": "this door's address rule (see `precheck.to`)",
                        "why": "the shape contracts/deploy.config.example.json already uses for \
                            every address it carries",
                    },
                    {
                        "field": "data",
                        "shape": format!(
                            "`{HEX_PREFIX}` followed by an even number of hex digits, possibly \
                             zero for a plain value read"
                        ),
                        "checked_by": "hex::decode (see `precheck.data`)",
                        "why": "the calldata is supplied already encoded, because no ABI \
                            encoder exists in this workspace",
                    },
                    {
                        "field": "version",
                        "shape": "the deployed contract version, byte-identical to contracts/VERSION",
                        "checked_by": "contracts/script/Deploy.s.sol, at deploy time",
                        "why": "the deploy script refuses to deploy unless the config's \
                            `version` matches that file byte for byte, so a read's config can \
                            be tied to the deployment it belongs to",
                    },
                ],
                // `CARGO_PKG_VERSION` is the workspace version. contracts/VERSION is a copy
                // of the repository-root VERSION, which the CI `contracts` job holds
                // byte-identical (`diff -u VERSION contracts/VERSION`) and which
                // `crates/nau-core/tests/version_consistency.rs` asserts the workspace
                // version equal to — so this is the same value the deploy script checks, not
                // a second one written here.
                "expected_version": env!("CARGO_PKG_VERSION"),
                "expected_version_note": "contracts/VERSION is a copy of the repository-root \
                    VERSION: the CI `contracts` job holds the two byte-identical (`diff -u VERSION \
                    contracts/VERSION`), and crates/nau-core/tests/version_consistency.rs asserts \
                    the workspace version — this value — equal to that root VERSION. \
                    script/Deploy.s.sol reverts with `VersionMismatch` unless the deploy config's \
                    `version` matches contracts/VERSION",
                "sources": [
                    "contracts/README.md",
                    "contracts/deploy.config.example.json",
                    "contracts/VERSION",
                    "contracts/script/Deploy.s.sol",
                ],
                "rpc_client": Value::Null,
                "rpc_client_note": "this build has no JSON-RPC client; the request a read needs \
                    is not built, encoded or sent by anything in this workspace",
                "abi_encoder": Value::Null,
                "abi_encoder_note": "no ABI encoder exists here, so `data` is checked as hex \
                    and never constructed",
                "address_checksum": Value::Null,
                "address_checksum_note": "EIP-55 mixed-case checksum verification is NOT \
                    performed: no keccak-256 implementation is a dependency of this crate, and \
                    this door accepts lower-case, upper-case and mixed-case hex digits alike",
                "not_performed": NOT_PERFORMED,
            }),
        )
    }

    /// `precheck`: validate the inputs of a chain read, and perform none of it.
    ///
    /// # Errors
    ///
    /// [`payload::CODE_MISSING_FIELD`] / [`payload::CODE_FIELD_TYPE`] for a malformed
    /// request. A field that fails a rule is an *answer*, not a refusal: `legal` is `false`
    /// and that field's reason is named.
    fn precheck(&self, request: &Value) -> Result<Value> {
        let rpc_url = payload::string_field(request, "rpc_url")?;
        let chain_id = payload::optional_string(request, "chain_id")?;
        let to = payload::optional_string(request, "to")?;
        let data = payload::optional_string(request, "data")?;

        // Each check answers "is this input usable" for itself, so a "no" names the field
        // rather than making the whole answer one opaque refusal.
        let (endpoint_ok, endpoint) = endpoint_check(rpc_url);
        let (chain_ok, chain) = chain_id_check(chain_id.as_deref());
        let (address_ok, address) = address_check(to.as_deref());
        let (calldata_ok, calldata) = calldata_check(data.as_deref());

        Ok(payload::answer(
            Self::ID,
            "precheck",
            json!({
                "rpc_url": endpoint,
                "chain_id": chain,
                "to": address,
                "data": calldata,
                "legal": endpoint_ok && chain_ok && address_ok && calldata_ok,
                "read_performed": false,
                "read_performed_note": READ_PERFORMED_NOTE,
                "not_checked": NOT_CHECKED,
                "connects": false,
                "note": "this operation is a pre-flight: `legal: true` means the inputs have \
                    the shapes a read would need, not that the endpoint answers or that the \
                    address holds anything",
            }),
        ))
    }
}

/// Check the RPC endpoint's shape with `nau-http`'s own parser, which dials nothing.
fn endpoint_check(url: &str) -> (bool, Value) {
    match nau_http::parse_url(url) {
        Ok(parsed) => (
            true,
            json!({
                "supplied": true,
                "ok": true,
                "reason": Value::Null,
                "scheme": parsed.scheme,
                "host": parsed.host,
                "port": parsed.port,
                "path": parsed.path,
                "tls": parsed.tls,
                "checked_by": "nau_http::parse_url",
            }),
        ),
        Err(error) => (
            false,
            json!({
                "supplied": true,
                "ok": false,
                "reason": error.to_string(),
                "scheme": Value::Null,
                "host": Value::Null,
                "port": Value::Null,
                "path": Value::Null,
                "tls": Value::Null,
                "checked_by": "nau_http::parse_url",
            }),
        ),
    }
}

/// Check the chain id, and canonicalise it to decimal and hex.
fn chain_id_check(chain_id: Option<&str>) -> (bool, Value) {
    let Some(text) = chain_id else {
        return (
            true,
            json!({
                "supplied": false,
                "ok": Value::Null,
                "reason": Value::Null,
                "decimal": Value::Null,
                "hex": Value::Null,
                "known": Value::Null,
                "known_note": "this build has no chain registry: a chain id that parses is not \
                    thereby a chain this deployment knows",
                "checked_by": "this door's quantity rule",
            }),
        );
    };
    match parse_chain_id(text) {
        Ok(value) => (
            true,
            json!({
                "supplied": true,
                "ok": true,
                "reason": Value::Null,
                "decimal": value.to_string(),
                "hex": format!("{HEX_PREFIX}{value:x}"),
                "known": Value::Null,
                "known_note": "this build has no chain registry: a chain id that parses is not \
                    thereby a chain this deployment knows",
                "checked_by": "this door's quantity rule",
            }),
        ),
        Err(reason) => (
            false,
            json!({
                "supplied": true,
                "ok": false,
                "reason": reason,
                "decimal": Value::Null,
                "hex": Value::Null,
                "known": Value::Null,
                "known_note": "this build has no chain registry: a chain id that parses is not \
                    thereby a chain this deployment knows",
                "checked_by": "this door's quantity rule",
            }),
        ),
    }
}

/// A chain id as JSON-RPC writes one: decimal digits, or `0x` followed by hex digits.
///
/// `u64` is the bound EIP-2294 puts on the field, and a hex quantity may not carry leading
/// zeros — so `0x1` and `1` are the same id while `0x01` is refused as a second spelling of
/// it rather than silently accepted.
///
/// # Errors
///
/// A message naming what is wrong with the text. The text itself is not echoed: it is
/// caller-supplied and ends up in a log.
fn parse_chain_id(text: &str) -> std::result::Result<u64, String> {
    if let Some(digits) = text.strip_prefix(HEX_PREFIX) {
        if digits.is_empty() {
            return Err(format!(
                "a `{HEX_PREFIX}` chain id must carry at least one hex digit"
            ));
        }
        if digits.len() > MAX_CHAIN_ID_HEX_DIGITS {
            return Err(format!(
                "a chain id of {} hex digits is wider than the {MAX_CHAIN_ID_HEX_DIGITS}-digit \
                 (u64) bound",
                digits.len()
            ));
        }
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(
                "a hex quantity must not have leading zeros: `0x0` is the only form that may \
                 start with one"
                    .to_string(),
            );
        }
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "a `{HEX_PREFIX}` chain id may only contain hex digits"
            ));
        }
        return u64::from_str_radix(digits, 16)
            .map_err(|error| format!("the hex chain id does not fit in 64 bits: {error}"));
    }
    if text.is_empty() {
        return Err("a chain id must not be empty".to_string());
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "a chain id must be decimal digits, or a `{HEX_PREFIX}`-prefixed hex quantity"
        ));
    }
    text.parse::<u64>()
        .map_err(|error| format!("the decimal chain id does not fit in 64 bits: {error}"))
}

/// Check an address: `0x` followed by exactly [`ADDRESS_DIGITS`] hex digits.
fn address_check(address: Option<&str>) -> (bool, Value) {
    let Some(text) = address else {
        return (
            true,
            json!({
                "supplied": false,
                "ok": Value::Null,
                "reason": Value::Null,
                "address": Value::Null,
                "checksum_verified": false,
                "checked_by": "this door's address rule",
            }),
        );
    };
    match parse_address(text) {
        Ok(normalised) => (
            true,
            json!({
                "supplied": true,
                "ok": true,
                "reason": Value::Null,
                "address": normalised,
                "checksum_verified": false,
                "checked_by": "this door's address rule",
            }),
        ),
        Err(reason) => (
            false,
            json!({
                "supplied": true,
                "ok": false,
                "reason": reason,
                "address": Value::Null,
                "checksum_verified": false,
                "checked_by": "this door's address rule",
            }),
        ),
    }
}

/// An address as `0x` + [`ADDRESS_DIGITS`] hex digits, lower-cased.
///
/// This is **this door's** rule, not a crate's: the workspace has no EVM address type. The
/// digits are lower-cased in the answer so that two spellings of one address do not look
/// like two addresses; the checksum is not verified and the answer says so.
///
/// # Errors
///
/// A message naming what is wrong. The text itself is not echoed.
fn parse_address(text: &str) -> std::result::Result<String, String> {
    let Some(digits) = text.strip_prefix(HEX_PREFIX) else {
        return Err(format!(
            "an address must start with the lower-case `{HEX_PREFIX}` prefix, as \
             contracts/deploy.config.example.json writes them"
        ));
    };
    if digits.len() != ADDRESS_DIGITS {
        return Err(format!(
            "an address must carry exactly {ADDRESS_DIGITS} hex digits after `{HEX_PREFIX}`, \
             found {}",
            digits.len()
        ));
    }
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "an address may only contain hex digits after `{HEX_PREFIX}`"
        ));
    }
    Ok(format!("{HEX_PREFIX}{}", digits.to_ascii_lowercase()))
}

/// Check the calldata with `hex::decode`, which is the crate's rule for what hex is.
fn calldata_check(data: Option<&str>) -> (bool, Value) {
    let Some(text) = data else {
        return (
            true,
            json!({
                "supplied": false,
                "ok": Value::Null,
                "reason": Value::Null,
                "bytes": Value::Null,
                "checked_by": "hex::decode",
            }),
        );
    };
    let Some(digits) = text.strip_prefix(HEX_PREFIX) else {
        return (
            false,
            json!({
                "supplied": true,
                "ok": false,
                "reason": format!(
                    "calldata must start with the lower-case `{HEX_PREFIX}` prefix"
                ),
                "bytes": Value::Null,
                "checked_by": "hex::decode",
            }),
        );
    };
    match hex::decode(digits) {
        // An empty `0x` decodes to no bytes, which is what a plain value read has.
        Ok(bytes) => (
            true,
            json!({
                "supplied": true,
                "ok": true,
                "reason": Value::Null,
                "bytes": bytes.len(),
                "checked_by": "hex::decode",
            }),
        ),
        Err(error) => (
            false,
            json!({
                "supplied": true,
                "ok": false,
                "reason": error.to_string(),
                "bytes": Value::Null,
                "checked_by": "hex::decode",
            }),
        ),
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
    /// An address in the shape `contracts/deploy.config.example.json` uses.
    const ADDRESS: &str = "0x1111111111111111111111111111111111111111";

    fn token(caps: &[Capability]) -> CapabilityToken {
        CapabilityToken::issue(ChainPlugin::ID, Tier::System, caps, DIGEST, NOW).expect("issuable")
    }

    /// The plugin, initialised through the framework with `caps`.
    fn plugin(caps: &[Capability]) -> ChainPlugin {
        let mut plugin = ChainPlugin::new().expect("valid id");
        let mut ctx = HostContext::new(token(caps), HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.sys.policy").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(ChainPlugin::ID.to_string()),
            Capability::parse(capability).expect("known capability"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    #[test]
    fn the_plugin_registers_reaches_running_and_reports_the_config_without_reading() {
        let verified = crate::sign::verified_system(
            ChainPlugin::ID,
            ChainPlugin::CAPABILITIES,
            &crate::sign::fixture_key(HOST_SEED),
            &crate::sign::fixture_key(VENDOR_SEED),
        )
        .expect("a system manifest verifies");
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(
            Box::new(ChainPlugin::new().expect("valid id")),
            &verified,
            NOW,
        )
        .expect("registers");
        host.init(ChainPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(ChainPlugin::ID), Some(PluginState::Running));

        let answer = host
            .handle(&request("chain:evm:read", json!({ "op": "config" })))
            .expect("answers");
        assert_eq!(answer["plugin"], json!(ChainPlugin::ID));
        assert_eq!(
            answer["read_performed"],
            json!(false),
            "this build has no chain client, so the answer must not read as a read"
        );
        assert_eq!(answer["rpc_client"], json!(null));
        assert_eq!(answer["abi_encoder"], json!(null));
        assert_eq!(
            answer["address_checksum"],
            json!(null),
            "no keccak-256 is a dependency, so no checksum was verified"
        );
        assert_eq!(
            answer["expected_version"],
            json!(env!("CARGO_PKG_VERSION")),
            "the version the deploy script checks is the workspace version"
        );

        // Every requirement names the field, its shape, and who checks it — a configuration
        // contract that did not say who enforces it would be documentation, not a contract.
        let requirements = answer["requirements"]
            .as_array()
            .expect("requirements is an array");
        assert_eq!(requirements.len(), 5);
        for field in ["rpc_url", "chain_id", "to", "data", "version"] {
            let entry = requirements
                .iter()
                .find(|entry| entry["field"] == json!(field))
                .unwrap_or_else(|| panic!("`{field}` is missing from the contract"));
            assert!(
                entry["shape"].as_str().is_some_and(|s| !s.is_empty()),
                "{entry}"
            );
            assert!(
                entry["checked_by"].as_str().is_some_and(|s| !s.is_empty()),
                "{entry}"
            );
        }
        assert!(
            answer["not_performed"].as_array().is_some_and(|items| items
                .iter()
                .any(|item| item.as_str().is_some_and(|s| s.contains("JSON-RPC")))),
            "{answer}"
        );
    }

    #[test]
    fn a_read_is_preflighted_and_none_is_performed() {
        let mut plugin = plugin(ChainPlugin::CAPABILITIES);

        let answer = plugin
            .handle(&request(
                "chain:evm:read",
                json!({
                    "op": "precheck",
                    "rpc_url": "http://127.0.0.1:8545",
                    "chain_id": "0x1",
                    "to": ADDRESS,
                    "data": "0x70a08231",
                }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(true));
        assert_eq!(answer["read_performed"], json!(false));
        assert_eq!(answer["connects"], json!(false));
        assert_eq!(answer["rpc_url"]["ok"], json!(true));
        assert_eq!(answer["rpc_url"]["scheme"], json!("http"));
        assert_eq!(answer["rpc_url"]["port"], json!(8545));
        assert_eq!(answer["rpc_url"]["tls"], json!(false));
        assert_eq!(
            answer["rpc_url"]["checked_by"],
            json!("nau_http::parse_url")
        );
        assert_eq!(answer["chain_id"]["decimal"], json!("1"));
        assert_eq!(answer["chain_id"]["hex"], json!("0x1"));
        assert_eq!(
            answer["to"]["address"],
            json!(ADDRESS),
            "a legal address is echoed in its canonical lower-case form"
        );
        assert_eq!(answer["to"]["checksum_verified"], json!(false));
        assert_eq!(answer["data"]["bytes"], json!(4));

        // Optional fields that were not supplied are reported as unasked, not as failures.
        let answer = plugin
            .handle(&request(
                "chain:evm:read",
                json!({ "op": "precheck", "rpc_url": "http://127.0.0.1:8545" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(true));
        assert_eq!(answer["chain_id"]["supplied"], json!(false));
        assert_eq!(answer["chain_id"]["ok"], json!(null));
        assert_eq!(answer["to"]["supplied"], json!(false));
        assert_eq!(answer["data"]["supplied"], json!(false));
    }

    #[test]
    fn each_input_that_fails_its_rule_is_reported_with_its_own_reason() {
        let mut plugin = plugin(ChainPlugin::CAPABILITIES);

        // An endpoint `nau-http` cannot speak: refused by its parser, before any socket.
        let answer = plugin
            .handle(&request(
                "chain:evm:read",
                json!({ "op": "precheck", "rpc_url": "ftp://example.invalid/rpc" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert_eq!(answer["rpc_url"]["ok"], json!(false));
        assert!(
            answer["rpc_url"]["reason"]
                .as_str()
                .is_some_and(|text| text.contains("unsupported URL scheme")),
            "{answer}"
        );

        // A chain id with a leading zero is a second spelling of the same id, refused.
        let answer = plugin
            .handle(&request(
                "chain:evm:read",
                json!({ "op": "precheck", "rpc_url": "http://127.0.0.1:1", "chain_id": "0x01" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert!(
            answer["chain_id"]["reason"]
                .as_str()
                .is_some_and(|text| text.contains("leading zeros")),
            "{answer}"
        );

        // An address without the prefix, and one of the wrong width.
        for address in [
            "1111111111111111111111111111111111111111",
            "0x1111",
            "0xZZ111111111111111111111111111111111111",
        ] {
            let answer = plugin
                .handle(&request(
                    "chain:evm:read",
                    json!({ "op": "precheck", "rpc_url": "http://127.0.0.1:1", "to": address }),
                ))
                .expect("answers");
            assert_eq!(answer["legal"], json!(false), "{answer}");
            assert_eq!(answer["to"]["ok"], json!(false), "{answer}");
            assert!(answer["to"]["reason"].is_string(), "{answer}");
        }

        // Odd-length calldata is `hex::decode`'s refusal, not a rule written here.
        let answer = plugin
            .handle(&request(
                "chain:evm:read",
                json!({ "op": "precheck", "rpc_url": "http://127.0.0.1:1", "data": "0xabc" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(false));
        assert_eq!(answer["data"]["checked_by"], json!("hex::decode"));
        assert!(
            answer["data"]["reason"]
                .as_str()
                .is_some_and(|text| text.contains("Odd number of digits")),
            "{answer}"
        );

        // An empty `0x` is zero bytes, which a plain value read has: legal, not an error.
        let answer = plugin
            .handle(&request(
                "chain:evm:read",
                json!({ "op": "precheck", "rpc_url": "http://127.0.0.1:1", "data": "0x" }),
            ))
            .expect("answers");
        assert_eq!(answer["legal"], json!(true));
        assert_eq!(answer["data"]["bytes"], json!(0));
    }

    #[test]
    fn a_chain_id_is_canonicalised_without_claiming_a_chain_registry() {
        let mut plugin = plugin(ChainPlugin::CAPABILITIES);
        for (supplied, decimal, hex) in [("1", "1", "0x1"), ("137", "137", "0x89")] {
            let answer = plugin
                .handle(&request(
                    "chain:evm:read",
                    json!({ "op": "precheck", "rpc_url": "http://127.0.0.1:1", "chain_id": supplied }),
                ))
                .expect("answers");
            assert_eq!(answer["chain_id"]["decimal"], json!(decimal), "{answer}");
            assert_eq!(answer["chain_id"]["hex"], json!(hex), "{answer}");
            assert_eq!(
                answer["chain_id"]["known"],
                json!(null),
                "a chain id that parses is not thereby a chain this build knows"
            );
            assert!(
                answer["chain_id"]["known_note"]
                    .as_str()
                    .is_some_and(|text| text.contains("no chain registry")),
                "{answer}"
            );
        }

        // Wider than 64 bits, and not a quantity at all.
        for bad in ["not-a-number", "-1", "0x", "0x10000000000000000", ""] {
            let answer = plugin
                .handle(&request(
                    "chain:evm:read",
                    json!({ "op": "precheck", "rpc_url": "http://127.0.0.1:1", "chain_id": bad }),
                ))
                .expect("answers");
            assert_eq!(answer["legal"], json!(false), "`{bad}`: {answer}");
        }
    }

    #[test]
    fn a_request_the_plugin_may_not_serve_is_refused_by_name() {
        let mut plugin = plugin(ChainPlugin::CAPABILITIES);

        // A capability the plugin's token does not hold at all. `chain:evm:write` is a real
        // capability of this build and it is still not this door's.
        let err = plugin
            .handle(&request("chain:evm:write", json!({ "op": "config" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("chain:evm:write"), "{err}");
        assert!(err.to_string().contains(ChainPlugin::ID), "{err}");

        // A capability it *does* hold, declared for an operation it is not the door for.
        let err = plugin
            .handle(&request("plugin:message:send", json!({ "op": "config" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("chain:evm:read"), "{err}");

        // And an operation it does not implement lists the ones it does.
        let err = plugin
            .handle(&request("chain:evm:read", json!({ "op": "send" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("precheck"), "{text}");

        // A required field that is absent is a typed protocol refusal, not an empty answer.
        let err = plugin
            .handle(&request("chain:evm:read", json!({ "op": "precheck" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_MISSING_FIELD), "{text}");
        assert!(text.contains("`rpc_url`"), "{text}");
    }
}
