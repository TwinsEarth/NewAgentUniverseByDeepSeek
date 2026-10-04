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

use std::path::{Path, PathBuf};

use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginId, Result};
use nau_store::{FileStore, Store};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// A store failure, named so a caller can tell it from a protocol refusal.
fn store_error(what: &str, error: nau_core::NauError) -> nau_plugin::PluginError {
    match error {
        nau_core::NauError::Io(e) => payload::protocol(CODE_STORE, format!("{what}: {e}")),
        other => payload::protocol(CODE_STORE, format!("{what}: {other}")),
    }
}

/// The operations this plugin implements, for the unknown-operation refusal.
pub const OPERATIONS: &[&str] = &[
    "config",
    "precheck",
    "record_anchor",
    "list_anchors",
    // E-04: the reconciliation, and the shape that refuses to resolve anything.
    "reconcile",
];

/// Error code: the anchor log could not be read, written or encoded.
pub const CODE_ANCHOR_LOG: &str = "chain_anchor_log";

/// Error code: the anchor log is at its bound.
pub const CODE_ANCHOR_FULL: &str = "chain_anchor_log_full";

/// Error code: the store refused the operation.
pub const CODE_STORE: &str = "chain_store_refused";

/// The metadata key the anchor log lives under.
///
/// One key holding a JSON array, not one key per anchor: the log is read whole by
/// `list_anchors` and its length is the sequence number, so a key-per-anchor layout would need
/// a second key for the count and would let the two disagree.
pub const ANCHORS_KEY: &str = "chain_anchors";

/// The most anchors the log will hold.
///
/// A bound, not a policy. Reaching it is a **refusal**, never a silent eviction: dropping the
/// oldest anchor would make the log claim a continuity its beginning no longer supports, which
/// is the one thing a log exists to be able to deny.
pub const MAX_ANCHORS: usize = 4096;

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
    store: FileStore,
    dir: PathBuf,
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
        // Not decoration: `record_anchor` writes, and the bus checks the *caller's* token for
        // this, so a caller that may only read cannot append to the log.
        Capability::ChainEvmWrite,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if [`ChainPlugin::ID`] is not a valid plugin name,
    /// which cannot happen for this constant but is returned rather than asserted.
    /// Build the plugin over a directory of its own.
    ///
    /// # Errors
    ///
    /// As [`StoragePlugin::open`](crate::plugins::storage::StoragePlugin::open): the store
    /// must be openable, and [`ChainPlugin::ID`] must be a valid plugin name.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let store = FileStore::open(&dir).map_err(|e| store_error("open", e))?;
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            store,
            dir,
        })
    }

    /// The directory this plugin owns.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The anchor log, oldest first.
    ///
    /// A malformed log is an **error**, not an empty list: swallowing the parse failure would
    /// make "there are no anchors" and "the anchors cannot be read" the same answer, and the
    /// difference is the whole reason a caller asks.
    fn anchors(&self) -> Result<Vec<Value>> {
        match self
            .store
            .get_meta(ANCHORS_KEY)
            .map_err(|e| store_error("get_meta", e))?
        {
            Some(text) => serde_json::from_str(&text).map_err(|e| {
                payload::protocol(
                    CODE_ANCHOR_LOG,
                    format!("the anchor log under `{ANCHORS_KEY}` is not readable JSON: {e}"),
                )
            }),
            None => Ok(Vec::new()),
        }
    }

    /// `record_anchor`: append one local anchor and answer with what was written.
    fn record_anchor(&self, request: &Value) -> Result<Value> {
        let root = payload::string_field(request, "root")?;
        let kind = payload::optional_string(request, "kind")?
            .unwrap_or_else(|| "reputation-snapshot".to_string());
        let at = payload::optional_u64(request, "at")?.unwrap_or(0);
        let mut anchors = self.anchors()?;
        if anchors.len() >= MAX_ANCHORS {
            return Err(payload::protocol(
                CODE_ANCHOR_FULL,
                format!(
                    "the anchor log holds its bound of {MAX_ANCHORS} anchors; refusing rather                      than evicting the oldest, because an anchor log that drops its beginning                      claims a continuity it no longer has"
                ),
            ));
        }
        let seq = anchors.len();
        anchors.push(json!({
            "seq": seq,
            "root": root,
            "kind": kind,
            "at": at,
        }));
        let encoded = serde_json::to_string(&anchors).map_err(|e| {
            payload::protocol(CODE_ANCHOR_LOG, format!("cannot encode the log: {e}"))
        })?;
        self.store
            .set_meta(ANCHORS_KEY, &encoded)
            .map_err(|e| store_error("set_meta", e))?;
        Ok(payload::answer(
            Self::ID,
            "record_anchor",
            json!({
                "recorded": true,
                "seq": seq,
                "count": anchors.len(),
                // In every answer, because the risk of a door named "anchor" is a caller reading
                // it as a chain write.
                "on_chain": false,
                "note": READ_PERFORMED_NOTE,
            }),
        ))
    }

    /// `list_anchors`: the log, newest first.
    fn list_anchors(&self, request: &Value) -> Result<Value> {
        let limit = payload::optional_u64(request, "limit")?
            .map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
        let anchors = self.anchors()?;
        let count = anchors.len();
        let listed: Vec<Value> = anchors.into_iter().rev().take(limit).collect();
        Ok(payload::answer(
            Self::ID,
            "list_anchors",
            json!({
                "count": count,
                "returned": listed.len(),
                "anchors": listed,
                "on_chain": false,
                "note": READ_PERFORMED_NOTE,
            }),
        ))
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
        // 2. Each operation names the capability it needs, in its own arm.
        //
        //    This used to be one blanket `chain:evm:read` check above the match, which was
        //    right while every op was a read and became wrong the moment one of them wrote:
        //    `record_anchor` would have demanded read as well, and "this door requires
        //    `chain:evm:read`" would have been a false statement about the log. A capability
        //    check that covers more than the operation needs is a claim that the door is
        //    narrower than it is.
        let op = payload::operation(&msg.payload)?;
        match op {
            "config" => {
                self.grant
                    .require_operation(declared, Capability::ChainEvmRead)?;
                Ok(self.config())
            }
            "precheck" => {
                self.grant
                    .require_operation(declared, Capability::ChainEvmRead)?;
                self.precheck(&msg.payload)
            }
            "record_anchor" => {
                self.grant
                    .require_operation(declared, Capability::ChainEvmWrite)?;
                self.record_anchor(&msg.payload)
            }
            "list_anchors" => {
                self.grant
                    .require_operation(declared, Capability::ChainEvmRead)?;
                self.list_anchors(&msg.payload)
            }
            // E-04. The ledger's figure is REQUIRED and the chain's side is optional, which is the
            // direction of authority expressed in the signature: a caller cannot even ask this
            // question without saying what the ledger holds.
            "reconcile" => {
                let ledger_minor = i64::try_from(
                    payload::optional_u64(&msg.payload, "ledger_minor")?.ok_or_else(|| {
                        payload::protocol(
                            "ledger_side_required",
                            "`nau-ledger` is the source of truth, so its figure is required: a \
                                 reconciliation that did not know what the ledger says would have \
                                 nothing to reconcile against",
                        )
                    })?,
                )
                .unwrap_or(i64::MAX);
                // The chain side is optional BECAUSE this workspace has no Rust-side chain client.
                // Absent is not "assume fine": `reconcile` turns it into a refusal.
                //
                // The presence test is `Value::is_null` rather than a missing-key check, so that a
                // caller who wrote `"chain_events": null` and one who omitted the key both mean the
                // same thing: no chain side. Inventing a difference between those two spellings
                // would be a distinction nobody asked for, and `payload` has no optional-array
                // helper precisely because most callers want the required one.
                let chain_events = match msg.payload.get("chain_events") {
                    Some(value) if !value.is_null() => {
                        Some(payload::string_array(&msg.payload, "chain_events")?)
                    }
                    _ => None,
                };
                let chain_total_minor = payload::optional_u64(&msg.payload, "chain_total_minor")?
                    .map(|v| i64::try_from(v).unwrap_or(i64::MAX));
                let outcome = reconcile(ledger_minor, chain_events.as_deref(), chain_total_minor);
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "agreed": outcome.is_agreed(),
                        "blocks": outcome.blocks(),
                        "reason": outcome.reason(),
                        "detail": match &outcome {
                            Reconciliation::Agreed { amount_minor, events } => json!({
                                "amount_minor": amount_minor,
                                "events": events,
                            }),
                            Reconciliation::Mismatched {
                                ledger_minor,
                                chain_minor,
                                difference,
                            } => json!({
                                "ledger_minor": ledger_minor,
                                "chain_minor": chain_minor,
                                "difference": difference,
                            }),
                            Reconciliation::CannotReconcile { .. } => json!(null),
                        },
                        "no_third_way": "there is no variant that resolves a disagreement: trusting \
                                         the chain and trusting the ledger are both refused, \
                                         because `nau-ledger` is the source of truth and the chain \
                                         is execution",
                        "read_performed": false,
                        "why_no_read": "this workspace has no Rust-side chain client, so on-chain \
                                        events reach a caller from somewhere else entirely -- and \
                                        an absent side blocks rather than passing by omission",
                    }),
                ))
            }
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

/// What a reconciliation found, and there is no fourth answer.
///
/// # E-04's second criterion, and the shape it forces
///
/// "A reconciliation mismatch is **refused** (fail-closed); it must not resolve by trusting the chain
/// and must not resolve by trusting the local record."
///
/// The strongest form of that is a result type with **no variant that resolves anything**:
///
/// * [`Reconciliation::Agreed`] requires **both sides present and equal**. It is not a default.
/// * [`Reconciliation::Mismatched`] carries **both figures** and a description of the difference. It
///   has no field for a chosen value, because choosing one is the thing being refused.
/// * [`Reconciliation::CannotReconcile`] covers **the side that is missing** — and this is the case
///   that matters most in this workspace, because there is no Rust-side chain client here. "I have
///   nothing to compare against" is **not** agreement, and a type with an `Unknown` that callers
///   treated as fine would be one where the absent case passed by omission.
///
/// # E-04's first criterion
///
/// `nau-ledger` is the only source of truth and the chain is execution. That is why
/// [`Reconciliation::Mismatched`] names the ledger's figure **first** and the chain's second: the
/// order is the direction of authority, and a caller reading the struct meets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciliation {
    /// Both sides present, and equal.
    Agreed {
        /// The ledger's figure, which happens to equal the chain's here.
        amount_minor: i64,
        /// How many on-chain events were compared.
        events: usize,
    },
    /// Both sides present, and different. **Nothing is resolved.**
    Mismatched {
        /// What the ledger says, which is the authority.
        ledger_minor: i64,
        /// What the chain's events add up to.
        chain_minor: i64,
        /// What differs, in words, so a human can act without re-deriving it.
        difference: String,
    },
    /// One side is missing, so there is nothing to compare.
    CannotReconcile {
        /// Why not. A sentence a caller can act on.
        reason: String,
    },
}

impl Reconciliation {
    /// Whether this is agreement.
    ///
    /// **The only predicate that returns true**, so a caller that wants "may I proceed?" has exactly
    /// one thing to ask and cannot accidentally treat a mismatch or an absence as one.
    #[must_use]
    pub fn is_agreed(&self) -> bool {
        matches!(self, Reconciliation::Agreed { .. })
    }

    /// Whether this blocks.
    ///
    /// Everything that is not agreement blocks, which is the fail-closed direction: a variant added
    /// later blocks unless someone deliberately adds it to `is_agreed` as well.
    #[must_use]
    pub fn blocks(&self) -> bool {
        !self.is_agreed()
    }

    /// Why it blocks, or `None` when it does not.
    #[must_use]
    pub fn reason(&self) -> Option<String> {
        match self {
            Reconciliation::Agreed { .. } => None,
            Reconciliation::Mismatched {
                ledger_minor,
                chain_minor,
                difference,
            } => Some(format!(
                "the ledger says {ledger_minor} and the chain's events say {chain_minor}: \
                 {difference}. Nothing is resolved -- trusting either side would be choosing which \
                 book to believe, and `nau-ledger` is the source of truth while the chain is \
                 execution"
            )),
            Reconciliation::CannotReconcile { reason } => Some(reason.clone()),
        }
    }
}

/// Reconcile an off-chain figure against on-chain events.
///
/// # The signature is the design
///
/// `chain_events` is an `Option` **because this workspace has no Rust-side chain client** and a
/// caller may genuinely have nothing to hand. `None` is not "assume fine": it produces
/// [`Reconciliation::CannotReconcile`], which blocks.
///
/// `chain_total_minor` is passed in rather than computed here, because computing it would need to
/// decode logs — and this module's own documentation records that nothing in `crates/` speaks
/// JSON-RPC or encodes ABI calldata. A function that pretended to add up events it could not read
/// would be exactly the defect this door exists to refuse.
///
/// # E-04's third criterion
///
/// The invariants E-04 points at are `contracts/test/SettlementInvariant.t.sol`, and they are
/// **Solidity-side**: they hold the contract's own accounting to its conservation law. What this
/// function reconciles is the **pairing** of that accounting with the ledger's. The two are different
/// checks at different layers and neither substitutes for the other — a contract whose invariants
/// hold can still disagree with the ledger about what happened, and that disagreement is what this
/// refuses.
#[must_use]
pub fn reconcile(
    ledger_minor: i64,
    chain_events: Option<&[String]>,
    chain_total_minor: Option<i64>,
) -> Reconciliation {
    let (Some(events), Some(chain_minor)) = (chain_events, chain_total_minor) else {
        return Reconciliation::CannotReconcile {
            reason: "one side of the comparison is missing: this workspace has no Rust-side chain \
                     client, so on-chain events reach a caller from somewhere else entirely -- and \
                     an absent side is NOT agreement. Reconciling against data one does not have \
                     would be the failure this check exists to prevent."
                .to_string(),
        };
    };
    if events.is_empty() {
        return Reconciliation::CannotReconcile {
            reason:
                "the chain side is present but empty, which is not the same as agreeing: a task \
                     with no on-chain events is one the chain has no record of, and the ledger \
                     having a record of it is precisely a disagreement"
                    .to_string(),
        };
    }
    if ledger_minor == chain_minor {
        return Reconciliation::Agreed {
            amount_minor: ledger_minor,
            events: events.len(),
        };
    }
    Reconciliation::Mismatched {
        ledger_minor,
        chain_minor,
        difference: format!(
            "the difference is {} minor units over {} on-chain event(s)",
            (i128::from(ledger_minor) - i128::from(chain_minor)).abs(),
            events.len()
        ),
    }
}

#[cfg(test)]
mod reconciliation_tests {
    use super::*;

    fn events() -> Vec<String> {
        vec!["TaskSettled".to_string(), "TaskRefunded".to_string()]
    }

    #[test]
    fn agreement_requires_both_sides_present_and_equal() {
        // E-04's second criterion: `Agreed` is not a default and not an absence.
        let agreed = reconcile(1_000, Some(&events()), Some(1_000));
        assert!(agreed.is_agreed());
        assert!(!agreed.blocks());
        assert_eq!(agreed.reason(), None);
        match agreed {
            Reconciliation::Agreed {
                amount_minor,
                events,
            } => {
                assert_eq!(amount_minor, 1_000);
                assert_eq!(events, 2, "how many events were compared");
            }
            other => panic!("expected agreement, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_side_is_not_agreement() {
        // The case that matters most here, because there is no Rust-side chain client: "I have
        // nothing to compare against" must not pass by omission.
        for missing in [
            reconcile(1_000, None, Some(1_000)),
            reconcile(1_000, Some(&events()), None),
            reconcile(1_000, None, None),
        ] {
            assert!(missing.blocks(), "{missing:?} must block");
            assert!(!missing.is_agreed());
            let reason = missing.reason().expect("a reason");
            assert!(reason.contains("missing"), "{reason}");
            assert!(
                reason.contains("NOT agreement"),
                "and must say the absence is not agreement: {reason}"
            );
        }

        // An EMPTY chain side is also not agreement: a task the chain has no record of, which the
        // ledger does, is a disagreement rather than an absence of information.
        let empty = reconcile(1_000, Some(&[]), Some(0));
        assert!(empty.blocks());
        assert!(
            empty
                .reason()
                .expect("a reason")
                .contains("no on-chain events"),
            "{:?}",
            empty.reason()
        );
    }

    #[test]
    fn a_mismatch_names_both_figures_and_resolves_nothing() {
        // The criterion's actual wording: it must not resolve by trusting the chain and must not
        // resolve by trusting the local record. What it carries is both figures and a description --
        // there is no field for a chosen value, because choosing one is the thing being refused.
        let mismatch = reconcile(1_000, Some(&events()), Some(900));
        assert!(mismatch.blocks());
        let reason = mismatch.reason().expect("a reason");
        assert!(reason.contains("ledger says 1000"), "{reason}");
        assert!(reason.contains("chain's events say 900"), "{reason}");
        assert!(reason.contains("Nothing is resolved"), "{reason}");
        assert!(
            reason.contains("choosing which book to believe"),
            "and must say why resolving would be wrong: {reason}"
        );
        assert!(
            reason.contains("source of truth"),
            "and must name which book is which: {reason}"
        );
        match mismatch {
            Reconciliation::Mismatched {
                ledger_minor,
                chain_minor,
                difference,
            } => {
                assert_eq!(ledger_minor, 1_000);
                assert_eq!(chain_minor, 900);
                assert!(difference.contains("100 minor units"), "{difference}");
                assert!(difference.contains("2 on-chain event"), "{difference}");
            }
            other => panic!("expected a mismatch, got {other:?}"),
        }
    }

    #[test]
    fn the_direction_of_the_comparison_is_the_direction_of_authority() {
        // E-04's first criterion arriving in the shape: the ledger's figure is named first and the
        // struct's fields are in that order, so a caller reading them meets the authority first.
        let mismatch = reconcile(500, Some(&events()), Some(600));
        match mismatch {
            Reconciliation::Mismatched {
                ledger_minor,
                chain_minor,
                ..
            } => {
                assert_eq!(ledger_minor, 500, "the ledger's figure is the first field");
                assert_eq!(chain_minor, 600);
            }
            other => panic!("expected a mismatch, got {other:?}"),
        }
        // And the sign of the difference does not change the answer: a chain ahead of the ledger
        // blocks exactly as one behind it does.
        assert!(reconcile(500, Some(&events()), Some(600)).blocks());
        assert!(reconcile(500, Some(&events()), Some(400)).blocks());
    }

    #[test]
    fn everything_that_is_not_agreement_blocks() {
        // The fail-closed direction, asserted as a property rather than case by case: `blocks` is
        // defined as the negation of `is_agreed`, so a variant added later blocks unless someone
        // deliberately adds it to `is_agreed` too.
        for result in [
            reconcile(1_000, Some(&events()), Some(1_000)),
            reconcile(1_000, Some(&events()), Some(999)),
            reconcile(1_000, None, Some(1_000)),
            reconcile(0, Some(&events()), Some(0)),
        ] {
            assert_eq!(
                result.blocks(),
                !result.is_agreed(),
                "the two predicates must be exact negations: {result:?}"
            );
            assert_eq!(result.reason().is_none(), result.is_agreed(), "{result:?}");
        }
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

    /// A directory no other test shares.
    ///
    /// The process id is **not** enough: every test in this binary has the same one, and the
    /// whole suite runs in parallel. That was harmless while this plugin held no state -- and
    /// became a shared anchor log the moment it grew one, which showed up as a failure that
    /// only appeared when the whole suite ran together. A counter, not a guess at uniqueness.
    fn scratch(label: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("nau-chain-{label}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The plugin, initialised through the framework with `caps`.
    fn plugin(caps: &[Capability]) -> ChainPlugin {
        plugin_in(&scratch("plugin"), caps)
    }

    fn plugin_in(dir: &Path, caps: &[Capability]) -> ChainPlugin {
        let mut plugin = ChainPlugin::open(dir).expect("opens");
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
            Box::new(ChainPlugin::open(scratch("register")).expect("opens")),
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

    #[test]
    fn an_anchor_is_recorded_and_read_back_newest_first() {
        let dir = scratch("anchors");
        let mut plugin = plugin_in(&dir, &[Capability::ChainEvmRead, Capability::ChainEvmWrite]);

        // An empty log is empty, and says so -- it is not an error, and it is not `null`.
        let empty = plugin
            .handle(&request("chain:evm:read", json!({ "op": "list_anchors" })))
            .expect("lists");
        assert_eq!(empty["count"], 0, "{empty}");
        assert_eq!(
            empty["anchors"].as_array().map(Vec::len),
            Some(0),
            "{empty}"
        );

        for (i, root) in ["0xaa", "0xbb", "0xcc"].iter().enumerate() {
            let answer = plugin
                .handle(&request(
                    "chain:evm:write",
                    json!({ "op": "record_anchor", "root": root, "at": 1_000 + i as u64 }),
                ))
                .expect("records");
            assert_eq!(answer["recorded"], true, "{answer}");
            assert_eq!(answer["seq"], i as u64, "{answer}");
            assert_eq!(answer["count"], i as u64 + 1, "{answer}");
            // Every answer refuses the reading this door exists to prevent.
            assert_eq!(answer["on_chain"], false, "{answer}");
        }

        let listed = plugin
            .handle(&request("chain:evm:read", json!({ "op": "list_anchors" })))
            .expect("lists");
        assert_eq!(listed["count"], 3, "{listed}");
        let roots: Vec<&str> = listed["anchors"]
            .as_array()
            .expect("an array")
            .iter()
            .map(|a| a["root"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(
            roots,
            vec!["0xcc", "0xbb", "0xaa"],
            "newest first: {listed}"
        );
        assert_eq!(listed["on_chain"], false, "{listed}");

        // The log is on disk, not in the process: a second plugin over the same directory sees
        // the same anchors. Without this the test would pass for an in-memory vector.
        let mut reopened = plugin_in(&dir, &[Capability::ChainEvmRead]);
        let again = reopened
            .handle(&request("chain:evm:read", json!({ "op": "list_anchors" })))
            .expect("lists");
        assert_eq!(
            again["count"], 3,
            "the log must survive the process: {again}"
        );
    }

    #[test]
    fn recording_needs_the_write_capability_not_just_the_read_one() {
        let mut plugin = plugin_in(
            &scratch("caps"),
            &[Capability::ChainEvmRead, Capability::ChainEvmWrite],
        );

        // A caller holding only `chain:evm:read` may list. It may **not** append, and the
        // refusal has to be about the capability rather than about a malformed request.
        let err = plugin
            .handle(&request(
                "chain:evm:read",
                json!({ "op": "record_anchor", "root": "0xaa" }),
            ))
            .expect_err("a read-only caller must not append");
        let text = err.to_string();
        assert!(text.contains("chain:evm:write"), "{text}");

        // And the log is genuinely untouched by the attempt.
        let listed = plugin
            .handle(&request("chain:evm:read", json!({ "op": "list_anchors" })))
            .expect("lists");
        assert_eq!(listed["count"], 0, "{listed}");
    }

    #[test]
    fn a_log_that_cannot_be_read_is_an_error_not_an_empty_log() {
        let dir = scratch("corrupt");
        let mut plugin = plugin_in(&dir, &[Capability::ChainEvmRead]);
        // Write through the store the plugin itself uses, so the corruption is in the real
        // place rather than in a fixture that merely resembles it.
        let store = FileStore::open(&dir).expect("opens");
        store
            .set_meta(ANCHORS_KEY, "this is not json")
            .expect("writes");

        let err = plugin
            .handle(&request("chain:evm:read", json!({ "op": "list_anchors" })))
            .expect_err("a corrupt log must not read as empty");
        let text = err.to_string();
        assert!(text.contains(CODE_ANCHOR_LOG), "{text}");
    }
}
