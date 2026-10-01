//! `com.twinsearth.sys.erasure` — Reed-Solomon shards, through `nau_erasure`.
//!
//! # What it actually does
//!
//! It is a door onto [`nau_erasure::ErasureCoder`], not a second implementation of
//! erasure coding. Encoding is `ErasureCoder::encode_with_length`, decoding is
//! `ErasureCoder::decode_with_length`, and every refusal is the coder's own
//! [`nau_core::NauError`] mapped onto the kernel's taxonomy. Reimplementing GF(2^8)
//! arithmetic here would create a second place for the parity block to be wrong, which is
//! precisely the defect `nau-erasure` exists to remove: upstream v2.5.6 built "parity"
//! shards out of SHA-256 digests that `decode` never consulted, so a `(4, 2)` code could
//! not survive the loss of a single byte.
//!
//! # Honest scope, inherited from the coder
//!
//! * **Erasures, not errors.** The coder reconstructs from any `k` of the `n` shards when
//!   the *positions* of the losses are known. A shard that is present but corrupt is taken
//!   at face value and yields silently wrong output. Detecting corruption needs a checksum
//!   or MAC layer above this code, checked before `decode` — this plugin does not add one
//!   and does not claim to.
//! * **No confidentiality.** Shards are plaintext; erasure coding is not encryption.
//! * **No placement.** The shards travel back in the answer as hex; where they are stored
//!   or sent is the caller's problem.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `encode` | `data` (hex), `data_shards` (k), `parity_shards` (m) | `data_shards`, `parity_shards`, `total_shards`, `shard_len`, `original_len`, `shards` (hex, in shard order) |
//! | `decode` | `shards` (hex strings, `null` for a lost shard), `data_shards`, `parity_shards`, `original_len` | `data` (hex), `original_len`, `present`, `lost` |
//!
//! Both operations require the request to declare `plugin:message:send`: a request *is* a
//! message, so that is the capability the sender exercises, and the bus checks it against
//! the sender's token before delivery.
//!
//! # Size
//!
//! The plugin adds no input cap of its own: a shard array and a payload are already bounded
//! by the message the bus delivered, and a second, smaller limit here would refuse
//! legitimate erasure sets at a number nobody documented. What the coder does enforce is
//! `1 <= k`, `1 <= m`, `k + m <= 255`, and every one of those refusals comes back as a
//! typed [`CODE_ERASURE`] error.

use nau_erasure::ErasureCoder;
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginError, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: the coder refused, or the request did not describe a code.
pub const CODE_ERASURE: &str = "erasure_codec_refused";

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["encode", "decode"];

/// The erasure-coding system plugin.
pub struct ErasurePlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl ErasurePlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.erasure";

    /// The capabilities the plugin declares: the basic set, and nothing else. It computes
    /// over bytes it was handed; it does not read storage, the network or the chain, so it
    /// declares nothing that would let it.
    pub const CAPABILITIES: &'static [Capability] = &Capability::BASIC;

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if [`ErasurePlugin::ID`] is not a valid plugin
    /// name, which cannot happen for this constant but is returned rather than asserted.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }

    /// `encode`: split a payload into `k` data shards and `m` parity shards.
    fn encode(&self, request: &Value) -> Result<Value> {
        let data = hex_field(request, "data")?;
        let coder = parse_coder(request)?;
        let (shards, original_len) = coder
            .encode_with_length(&data)
            .map_err(|e| codec_error("encode", &e))?;
        let shard_len = shards.first().map(Vec::len).unwrap_or(0);
        let encoded: Vec<Value> = shards
            .iter()
            .map(|shard| json!(hex::encode(shard)))
            .collect();
        Ok(payload::answer(
            Self::ID,
            "encode",
            json!({
                "data_shards": coder.data_shards(),
                "parity_shards": coder.parity_shards(),
                "total_shards": coder.total_shards(),
                "shard_len": shard_len,
                "original_len": original_len,
                "shards": encoded,
            }),
        ))
    }

    /// `decode`: reconstruct the payload from any `k` of the `n` shards.
    fn decode(&self, request: &Value) -> Result<Value> {
        let coder = parse_coder(request)?;
        let original_len = count_field(request, "original_len")?;
        let shards = parse_shards(request, coder.total_shards())?;
        let present = shards.iter().filter(|slot| slot.is_some()).count();
        let data = coder
            .decode_with_length(&shards, original_len)
            .map_err(|e| codec_error("decode", &e))?;
        Ok(payload::answer(
            Self::ID,
            "decode",
            json!({
                "data": hex::encode(&data),
                "original_len": data.len(),
                "present": present,
                "lost": coder.total_shards() - present,
            }),
        ))
    }
}

impl SystemPlugin for ErasurePlugin {
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
            "erasure ready: encoding and decoding delegate to nau_erasure's Reed-Solomon coder",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        self.grant
            .require_operation(declared, Capability::MessageSend)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "encode" => self.encode(&msg.payload),
            "decode" => self.decode(&msg.payload),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

/// The `(k, m)` code a request names, built by the coder's own constructor.
///
/// # Errors
///
/// A protocol refusal when `data_shards`/`parity_shards` are absent or not integers, and
/// [`CODE_ERASURE`] when the coder refuses the pair (`k == 0`, `m == 0`, `k + m > 255`).
fn parse_coder(request: &Value) -> Result<ErasureCoder> {
    let data_shards = count_field(request, "data_shards")?;
    let parity_shards = count_field(request, "parity_shards")?;
    ErasureCoder::new(data_shards, parity_shards).map_err(|e| codec_error("new", &e))
}

/// A non-negative integer field, as a `usize`.
///
/// # Errors
///
/// [`payload::CODE_FIELD_TYPE`] when the field is absent, negative or not an integer;
/// [`CODE_ERASURE`] when it does not fit this platform's `usize`.
fn count_field(request: &Value, key: &str) -> Result<usize> {
    let value = payload::field(request, key)?;
    let number = value.as_u64().ok_or_else(|| {
        payload::protocol(
            payload::CODE_FIELD_TYPE,
            format!(
                "`{key}` must be a non-negative integer, found {}",
                payload::kind_of(value)
            ),
        )
    })?;
    usize::try_from(number).map_err(|_| {
        payload::protocol(
            CODE_ERASURE,
            format!("`{key}` = {number} does not fit this platform's usize"),
        )
    })
}

/// A hex-encoded byte-string field.
///
/// # Errors
///
/// [`payload::CODE_FIELD_TYPE`] when the field is absent or not a string, and
/// [`CODE_ERASURE`] when it is not valid hex.
fn hex_field(request: &Value, key: &str) -> Result<Vec<u8>> {
    let text = payload::string_field(request, key)?;
    hex::decode(text).map_err(|e| {
        payload::protocol(
            CODE_ERASURE,
            format!("`{key}` is not a hex-encoded byte string: {e}"),
        )
    })
}

/// The `shards` array: one entry per shard, `null` where a shard was lost.
///
/// The length is checked here rather than left to the coder so that the refusal names the
/// count the caller sent and the count the `(k, m)` pair implies; the coder would refuse the
/// same request, one step later and less specifically.
///
/// # Errors
///
/// [`payload::CODE_FIELD_TYPE`] for a non-array field or a non-string, non-null entry, and
/// [`CODE_ERASURE`] for a wrong entry count or an entry that is not hex.
fn parse_shards(request: &Value, expected: usize) -> Result<Vec<Option<Vec<u8>>>> {
    let value = payload::field(request, "shards")?;
    let entries = value.as_array().ok_or_else(|| {
        payload::protocol(
            payload::CODE_FIELD_TYPE,
            format!(
                "`shards` must be an array of hex strings and nulls, found {}",
                payload::kind_of(value)
            ),
        )
    })?;
    if entries.len() != expected {
        return Err(payload::protocol(
            CODE_ERASURE,
            format!(
                "`shards` carries {} slots but this code has {expected} shards; a codeword's \
                 slots are fixed by its (k, m) pair",
                entries.len()
            ),
        ));
    }
    let mut out = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        match entry {
            Value::Null => out.push(None),
            Value::String(text) => out.push(Some(hex::decode(text).map_err(|e| {
                payload::protocol(
                    CODE_ERASURE,
                    format!("shard {index} is not a hex-encoded byte string: {e}"),
                )
            })?)),
            other => {
                return Err(payload::protocol(
                    payload::CODE_FIELD_TYPE,
                    format!(
                        "every entry of `shards` must be a hex string or null, found {} at index \
                         {index}",
                        payload::kind_of(other)
                    ),
                ))
            }
        }
    }
    Ok(out)
}

/// Map a coder failure onto the kernel's error taxonomy.
///
/// The coder's refusals are all validation failures, so they all arrive as
/// [`PluginError::Runtime`] with [`CODE_ERASURE`] in front — the same shape
/// `plugins/storage.rs` uses for the store, so a caller can branch on the code without
/// matching prose.
fn codec_error(what: &str, error: &nau_core::NauError) -> PluginError {
    PluginError::Runtime(format!("{CODE_ERASURE}: {what}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use ed25519_dalek::SigningKey;
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::lifecycle::PluginState;
    use nau_plugin::{CapabilityToken, Tier, VerifiedManifest};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_750_000_000;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn verified_manifest(plugin: &impl SystemPlugin) -> VerifiedManifest {
        crate::sign::verified_system(
            plugin.id().as_str(),
            plugin.capabilities(),
            &signing_key(7),
            &signing_key(9),
        )
        .expect("the system manifest verifies")
    }

    fn started(caps: &[Capability]) -> ErasurePlugin {
        let mut plugin = ErasurePlugin::new().expect("valid id");
        let token = CapabilityToken::issue(ErasurePlugin::ID, Tier::System, caps, DIGEST, NOW)
            .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.official.market").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(ErasurePlugin::ID.to_string()),
            Capability::parse(capability).expect("known"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    #[test]
    fn the_plugin_registers_initialises_and_reaches_running() {
        let plugin = ErasurePlugin::new().expect("valid id");
        assert_eq!(plugin.id().as_str(), ErasurePlugin::ID);
        let verified = verified_manifest(&plugin);
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(Box::new(plugin), &verified, NOW)
            .expect("registers against its own system manifest");
        assert_eq!(host.state(ErasurePlugin::ID), Some(PluginState::Loaded));
        host.init(ErasurePlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(ErasurePlugin::ID), Some(PluginState::Running));
    }

    #[test]
    fn an_encoded_payload_is_recovered_after_two_shards_are_lost() {
        let mut plugin = started(ErasurePlugin::CAPABILITIES);
        let payload = b"distribute me across six shards";
        let payload_hex = hex::encode(payload);

        let encoded = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "encode",
                    "data": payload_hex,
                    "data_shards": 4,
                    "parity_shards": 2,
                }),
            ))
            .expect("answers");
        assert_eq!(encoded["data_shards"], json!(4));
        assert_eq!(encoded["parity_shards"], json!(2));
        assert_eq!(encoded["total_shards"], json!(6));
        assert_eq!(encoded["original_len"], json!(payload.len()));
        let shard_len = encoded["shard_len"].as_u64().expect("a number");
        assert!(
            shard_len * 4 >= payload.len() as u64,
            "four data shards hold the padded payload"
        );
        let shards = encoded["shards"].as_array().expect("an array").clone();
        assert_eq!(shards.len(), 6);

        // Lose two data shards -- including two *data* shards, which is exactly what the
        // upstream implementation could never survive.
        let mut received = shards;
        received[0] = json!(null);
        received[3] = json!(null);
        let recovered = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "decode",
                    "shards": received,
                    "data_shards": 4,
                    "parity_shards": 2,
                    "original_len": encoded["original_len"].clone(),
                }),
            ))
            .expect("answers");
        assert_eq!(recovered["data"], json!(payload_hex));
        assert_eq!(recovered["original_len"], json!(payload.len()));
        assert_eq!(recovered["present"], json!(4));
        assert_eq!(recovered["lost"], json!(2));
    }

    #[test]
    fn the_coders_own_refusals_come_back_as_typed_errors() {
        let mut plugin = started(ErasurePlugin::CAPABILITIES);

        // m = 0: a code with no parity cannot reconstruct anything, and the coder refuses it
        // rather than accepting a decoration (the upstream defect, restated).
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "encode",
                    "data": "00",
                    "data_shards": 4,
                    "parity_shards": 0,
                }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(CODE_ERASURE), "{text}");
        assert!(text.contains("parity shard"), "{text}");

        // An empty payload has nothing to distribute.
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "encode", "data": "", "data_shards": 2, "parity_shards": 1 }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains(CODE_ERASURE), "{err}");

        // Too few shards to reconstruct: the coder names how many more are needed.
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "decode",
                    "shards": [null, null, "00"],
                    "data_shards": 2,
                    "parity_shards": 1,
                    "original_len": 1,
                }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(CODE_ERASURE), "{text}");
        assert!(text.contains("required"), "{text}");
    }

    #[test]
    fn a_request_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let mut plugin = started(ErasurePlugin::CAPABILITIES);

        let err = plugin
            .handle(&request(
                "net:dht:write",
                json!({ "op": "encode", "data": "00", "data_shards": 1, "parity_shards": 1 }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains("net:dht:write"), "{err}");

        // Held, but not the capability this operation needs.
        let err = plugin
            .handle(&request(
                "plugin:storage:own",
                json!({ "op": "encode", "data": "00", "data_shards": 1, "parity_shards": 1 }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("plugin:message:send"), "{text}");
        assert!(text.contains("plugin:storage:own"), "{text}");
    }
}
