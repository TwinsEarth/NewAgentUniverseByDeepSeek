//! `com.twinsearth.sys.attest` — attestation envelopes, verified by `nau_attest`.
//!
//! # What a "yes" from this plugin would mean, and why it never says one today
//!
//! [`nau_attest::Verifier::verify`] parses the envelope structurally, hashes the canonical
//! payload, checks that `report_data` commits to it, checks the signature against a key
//! **pinned by the verifier**, checks the nonce and checks freshness — and then asks whether
//! the format's certificate chain was verified. It never was: no Intel or AMD root is
//! bundled, so the result is [`Verified::Unverified`] with
//! [`UnverifiedReason::ChainNotImplemented`] even when every other check passes.
//!
//! This plugin therefore answers `verdict: "unverified"` for every envelope, and reports
//! *which* checks passed alongside it. It does not collapse that into a boolean and it does
//! not upgrade it to "attested": the upstream defect this crate answers was exactly a
//! `tee_quote` string that nobody parsed being read as proof of hardware.
//!
//! # The clock is not read here
//!
//! A T0 plugin is given no clock — the host stamps time when it drains the log, so a plugin
//! cannot backdate its own audit trail — and `nau_attest` takes `now` as a parameter rather
//! than reading the ambient clock, so the freshness check is testable. The two rules meet
//! here: `now` is a **required request field**. That is a real limitation, stated rather
//! than hidden: a caller that lies about `now` defeats the freshness window, and nothing in
//! this plugin can detect it. The window itself is
//! [`AttestPlugin::with_roots`]'s constructor wiring, so a caller cannot widen its own
//! freshness per request.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `verify` | `envelope`, `nonce` (64 hex chars), `now` (Unix seconds) | `verdict`, `grade`, `reason_kind`, `reason`, `checks` (or, on the unreachable success path, the signed fields) |
//! | `roots` | — | `pinned_keys_total`, `formats`, `max_age_secs`, `max_achievable_grade`, `hardware_attested_reachable` |
//!
//! Both operations require the request to declare `plugin:message:send`.
//!
//! # Pinned keys
//!
//! [`AttestPlugin::new`] pins nothing, and that is the fail-closed default: an unpinned
//! verifier refuses every envelope as [`UnverifiedReason::SignerNotTrusted`], because a key
//! carried inside the envelope is a claim by whoever assembled it, not a trust decision. A
//! deployment pins keys through [`AttestPlugin::with_roots`]; `roots` is how an operator
//! checks whether that wiring actually happened.

use nau_attest::{
    label, AttestationEnvelope, SignedAttestation, TrustedRoots, UnverifiedReason, Verified,
    Verifier, MAX_ACHIEVABLE_GRADE, NONCE_LEN,
};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginError, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: the envelope or a request field could not be read.
pub const CODE_ATTEST_ENVELOPE: &str = "attest_envelope_invalid";
/// Error code: the request did not carry a usable `nonce` or `now`.
pub const CODE_ATTEST_REQUEST: &str = "attest_request_invalid";
/// Error code: the verifier could not be built from the roots it was given.
pub const CODE_ATTEST_ROOTS: &str = "attest_roots_refused";

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["verify", "roots"];

/// The label reported for a refusal reason this build does not recognise.
///
/// `UnverifiedReason` is `#[non_exhaustive]`, so a future variant must not fail to compile
/// here; it must also not be mistaken for one of the labels that *are* recognised, which is
/// why the fallback is its own word rather than a guess.
pub const UNRECOGNISED_REASON: &str = "unrecognised_reason";

/// The attestation system plugin.
pub struct AttestPlugin {
    id: PluginId,
    grant: PluginGrant,
    /// The verifier, with its pinned keys and freshness window. Constructor wiring: the
    /// context carries no key store, so the host decides what this deployment trusts.
    verifier: Verifier,
}

impl AttestPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.attest";

    /// The capabilities the plugin declares: the basic set, and nothing else. It verifies
    /// bytes it was handed against keys it was wired with; it does not read storage, the
    /// network or the chain.
    pub const CAPABILITIES: &'static [Capability] = &Capability::BASIC;

    /// The freshness window [`AttestPlugin::new`] uses:
    /// [`MAX_CLOCK_SKEW_SECS`](nau_attest::MAX_CLOCK_SKEW_SECS), the same skew the kernel
    /// allows a manifest's issue time.
    pub const DEFAULT_MAX_AGE_SECS: u64 = nau_attest::MAX_CLOCK_SKEW_SECS;

    /// Build the plugin with **no** pinned keys.
    ///
    /// Every envelope is then refused as [`UnverifiedReason::SignerNotTrusted`]; see the
    /// module documentation for why that is the honest default rather than an oversight.
    ///
    /// # Errors
    ///
    /// As [`AttestPlugin::with_roots`].
    pub fn new() -> Result<Self> {
        Self::with_roots(TrustedRoots::new(), Self::DEFAULT_MAX_AGE_SECS)
    }

    /// Build the plugin with an explicit pinned-key set and freshness window.
    ///
    /// # Errors
    ///
    /// [`CODE_ATTEST_ROOTS`] when `max_age_secs` is zero — a zero-second freshness window
    /// would refuse every envelope for a reason that has nothing to do with the envelope —
    /// and [`nau_plugin::PluginError::Name`] if [`AttestPlugin::ID`] is not a valid plugin
    /// name.
    pub fn with_roots(roots: TrustedRoots, max_age_secs: u64) -> Result<Self> {
        let verifier = Verifier::try_new(roots, max_age_secs)
            .map_err(|e| PluginError::Runtime(format!("{CODE_ATTEST_ROOTS}: {e}")))?;
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            verifier,
        })
    }

    /// The verifier this plugin holds, for a host that wants to compare it against the one
    /// it built.
    #[must_use]
    pub fn verifier(&self) -> &Verifier {
        &self.verifier
    }

    /// `verify`: run the envelope through the verifier and report what happened.
    fn verify(&self, request: &Value) -> Result<Value> {
        let envelope_value = payload::field(request, "envelope")?;
        let envelope: AttestationEnvelope = serde_json::from_value(envelope_value.clone())
            .map_err(|e| {
                payload::protocol(
                    CODE_ATTEST_ENVELOPE,
                    format!("`envelope` is not an attestation envelope: {e}"),
                )
            })?;
        let nonce = parse_nonce(payload::string_field(request, "nonce")?)?;
        let now_value = payload::field(request, "now")?;
        let now = now_value.as_u64().ok_or_else(|| {
            payload::protocol(
                CODE_ATTEST_REQUEST,
                format!(
                    "`now` must be a non-negative integer number of Unix seconds, found {}; a T0 \
                     plugin has no clock of its own, so the caller must supply one",
                    payload::kind_of(now_value)
                ),
            )
        })?;
        let outcome = self.verifier.verify(&envelope, nonce, now);
        Ok(payload::answer(Self::ID, "verify", verdict_json(&outcome)))
    }

    /// `roots`: what this deployment actually trusts.
    fn roots(&self) -> Value {
        let roots = self.verifier.roots();
        let formats: Vec<Value> = roots
            .formats()
            .map(|format| {
                json!({
                    "format": format.wire_name(),
                    "pinned_keys": roots.len_for(format),
                    "chain_implemented": format.chain_implemented(),
                })
            })
            .collect();
        json!({
            "pinned_keys_total": roots.len(),
            "formats": formats,
            "max_age_secs": self.verifier.max_age_secs(),
            "max_achievable_grade": label(MAX_ACHIEVABLE_GRADE),
            // Stated rather than inferred: no format's certificate chain is implemented, so
            // the top rung of the evidence ladder is unreachable in this build.
            "hardware_attested_reachable": false,
        })
    }
}

impl SystemPlugin for AttestPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        let roots = self.verifier.roots();
        ctx.log(
            LogLevel::Info,
            &format!(
                "attest ready: {} pinned key(s) across {} format(s), freshness window {}s; no \
                 certificate chain is implemented, so no envelope can grade above {}",
                roots.len(),
                roots.formats().count(),
                self.verifier.max_age_secs(),
                label(MAX_ACHIEVABLE_GRADE)
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        self.grant
            .require_operation(declared, Capability::MessageSend)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "verify" => self.verify(&msg.payload),
            "roots" => Ok(payload::answer(Self::ID, "roots", self.roots())),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

/// The verification outcome, as JSON.
///
/// Both arms are written out. The success arm is unreachable through
/// [`Verifier::verify`] today because no certificate chain is implemented, but it is not
/// dead code: it is the shape the answer must take the day one is, and writing it now keeps
/// this plugin from having to guess at a contract later.
#[must_use]
pub fn verdict_json(outcome: &Verified<SignedAttestation<'_>>) -> Value {
    match outcome {
        Verified::Verified(signed) => json!({
            "verdict": "verified",
            "grade": label(signed.grade()),
            "format": signed.format.wire_name(),
            "payload_digest": hex::encode(signed.payload_digest),
            "signer": signed.signer.to_hex(),
            "issued_at": signed.issued_at,
            "checks": checks_json(signed.checks()),
            "max_achievable_grade": label(MAX_ACHIEVABLE_GRADE),
        }),
        Verified::Unverified(refusal) => json!({
            "verdict": "unverified",
            "grade": label(refusal.grade()),
            "reason_kind": reason_kind(&refusal.reason),
            "reason": refusal.reason.to_string(),
            "checks": checks_json(refusal.checks),
            "failures": refusal
                .failures()
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<String>>(),
            "max_achievable_grade": label(MAX_ACHIEVABLE_GRADE),
            "hardware_attested_reachable": false,
        }),
    }
}

/// Which checks ran and which of them passed.
///
/// `nau_attest::ChecksPerformed` is the honest half of the answer: it lets a caller decide
/// to accept a `SignatureVerified`-shaped envelope for a policy reason while still seeing
/// that `hardware_chain` is false.
#[must_use]
pub fn checks_json(checks: nau_attest::ChecksPerformed) -> Value {
    json!({
        "structural": checks.structural,
        "signature": checks.signature,
        "nonce": checks.nonce,
        "freshness": checks.freshness,
        "report_data": checks.report_data,
        "hardware_chain": checks.hardware_chain,
        "all_implemented": checks.all_implemented(),
    })
}

/// A stable, machine-readable name for a refusal reason.
///
/// Hand-written rather than derived from `Debug`, so the wire name cannot drift with a
/// refactor of the enum's shape.
#[must_use]
pub fn reason_kind(reason: &UnverifiedReason) -> &'static str {
    match reason {
        UnverifiedReason::ChainNotImplemented { .. } => "chain_not_implemented",
        UnverifiedReason::StructurallyInvalid { .. } => "structurally_invalid",
        UnverifiedReason::SignerNotTrusted(_) => "signer_not_trusted",
        UnverifiedReason::SignatureInvalid(_) => "signature_invalid",
        UnverifiedReason::NonceMismatch(_) => "nonce_mismatch",
        UnverifiedReason::NotFresh(_) => "not_fresh",
        UnverifiedReason::ReportDataNotBound(_) => "report_data_not_bound",
        UnverifiedReason::PayloadInvalid(_) => "payload_invalid",
        // `UnverifiedReason` is `#[non_exhaustive]`.
        _ => UNRECOGNISED_REASON,
    }
}

/// Parse the verifier's nonce from hex.
///
/// # Errors
///
/// [`CODE_ATTEST_REQUEST`] when the text is not hex or is not exactly [`NONCE_LEN`] bytes.
fn parse_nonce(text: &str) -> Result<[u8; NONCE_LEN]> {
    let raw = hex::decode(text).map_err(|e| {
        payload::protocol(
            CODE_ATTEST_REQUEST,
            format!("`nonce` is not a hex-encoded byte string: {e}"),
        )
    })?;
    let bytes: [u8; NONCE_LEN] = raw.as_slice().try_into().map_err(|_| {
        payload::protocol(
            CODE_ATTEST_REQUEST,
            format!(
                "`nonce` must be exactly {NONCE_LEN} bytes ({} hex characters), found {} bytes",
                NONCE_LEN * 2,
                raw.len()
            ),
        )
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use ed25519_dalek::SigningKey;
    use nau_attest::{payload_binding, AttestationFormat};
    use nau_core::{PublicKey, Signature64};
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

    fn started(plugin: AttestPlugin) -> AttestPlugin {
        let mut plugin = plugin;
        let token = CapabilityToken::issue(
            AttestPlugin::ID,
            Tier::System,
            AttestPlugin::CAPABILITIES,
            DIGEST,
            NOW,
        )
        .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.official.market").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(AttestPlugin::ID.to_string()),
            Capability::parse(capability).expect("known"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    /// A synthetic envelope whose `report_data` really does commit to its payload.
    ///
    /// The signature field is zeroed: with no pinned roots the verifier refuses at the trust
    /// check before it ever looks at the signature, so a real signature would prove nothing
    /// extra about this plugin. The payload is produced by the kernel's own canonicaliser,
    /// so the "stored payload is not its own canonical form" refusal cannot fire by accident.
    fn bound_envelope(issued_at: u64) -> AttestationEnvelope {
        let payload = nau_core::canonical::canonical_object(&json!({ "answer": 42 }))
            .expect("the test payload canonicalises")
            .into_bytes();
        let binding = payload_binding(&payload, None);
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&binding);
        AttestationEnvelope {
            format: AttestationFormat::Opaque,
            payload,
            report_data,
            signer: PublicKey::from_bytes(signing_key(3).verifying_key().to_bytes()),
            signature: Signature64::from_bytes([0u8; 64]),
            nonce: [7u8; NONCE_LEN],
            issued_at,
        }
    }

    fn verify_request(envelope: &AttestationEnvelope) -> Value {
        json!({
            "op": "verify",
            "envelope": serde_json::to_value(envelope).expect("the envelope serialises"),
            "nonce": hex::encode(envelope.nonce),
            "now": NOW,
        })
    }

    #[test]
    fn the_plugin_registers_initialises_and_reaches_running() {
        let plugin = AttestPlugin::new().expect("valid id");
        assert_eq!(plugin.id().as_str(), AttestPlugin::ID);
        let verified = verified_manifest(&plugin);
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(Box::new(plugin), &verified, NOW)
            .expect("registers against its own system manifest");
        assert_eq!(host.state(AttestPlugin::ID), Some(PluginState::Loaded));
        host.init(AttestPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(AttestPlugin::ID), Some(PluginState::Running));
    }

    #[test]
    fn the_roots_report_says_that_nothing_is_pinned_and_that_the_top_grade_is_unreachable() {
        let mut plugin = started(AttestPlugin::new().expect("valid id"));
        let answer = plugin
            .handle(&request("plugin:message:send", json!({ "op": "roots" })))
            .expect("answers");
        assert_eq!(answer["pinned_keys_total"], json!(0));
        assert_eq!(answer["formats"], json!([]));
        assert_eq!(
            answer["max_age_secs"],
            json!(AttestPlugin::DEFAULT_MAX_AGE_SECS)
        );
        assert_eq!(answer["max_achievable_grade"], json!("signature-verified"));
        assert_eq!(answer["hardware_attested_reachable"], json!(false));

        // A key pinned for one format shows up for that format only, and never as a chain.
        let mut roots = TrustedRoots::new();
        roots.pin(
            AttestationFormat::Opaque,
            PublicKey::from_bytes(signing_key(5).verifying_key().to_bytes()),
        );
        let mut pinned =
            started(AttestPlugin::with_roots(roots, 600).expect("a positive freshness window"));
        let answer = pinned
            .handle(&request("plugin:message:send", json!({ "op": "roots" })))
            .expect("answers");
        assert_eq!(answer["pinned_keys_total"], json!(1));
        assert_eq!(answer["max_age_secs"], json!(600));
        let formats = answer["formats"].as_array().expect("an array");
        assert_eq!(formats.len(), 1);
        assert_eq!(formats[0]["format"], json!("opaque"));
        assert_eq!(formats[0]["pinned_keys"], json!(1));
        assert_eq!(
            formats[0]["chain_implemented"],
            json!(false),
            "no format's certificate chain is implemented, and the report must say so"
        );

        // A zero-second window is refused by the verifier's own constructor.
        assert!(AttestPlugin::with_roots(TrustedRoots::new(), 0).is_err());
    }

    #[test]
    fn an_envelope_with_no_pinned_signer_is_refused_and_the_checks_that_ran_are_reported() {
        let mut plugin = started(AttestPlugin::new().expect("valid id"));
        let envelope = bound_envelope(NOW);

        let answer = plugin
            .handle(&request("plugin:message:send", verify_request(&envelope)))
            .expect("answers");
        assert_eq!(answer["verdict"], json!("unverified"));
        assert_eq!(answer["grade"], json!("unverified"));
        assert_eq!(
            answer["reason_kind"],
            json!("signer_not_trusted"),
            "an unpinned key is a claim by the envelope, not a trust decision: {answer}"
        );
        assert_eq!(answer["checks"]["structural"], json!(true));
        assert_eq!(
            answer["checks"]["report_data"],
            json!(true),
            "the binding really was checked before the trust refusal"
        );
        assert_eq!(answer["checks"]["signature"], json!(false));
        assert_eq!(
            answer["checks"]["hardware_chain"],
            json!(false),
            "this crate never claims a hardware chain"
        );
        assert_eq!(
            answer["max_achievable_grade"],
            json!("signature-verified"),
            "the ceiling is reported, not implied"
        );

        // The verifier really ran: an envelope whose report_data does not bind its payload
        // is refused for *that*, one check earlier.
        let mut broken = bound_envelope(NOW);
        broken.report_data = [0u8; 64];
        let answer = plugin
            .handle(&request("plugin:message:send", verify_request(&broken)))
            .expect("answers");
        assert_eq!(answer["reason_kind"], json!("report_data_not_bound"));
        assert_eq!(answer["checks"]["report_data"], json!(false));

        // The freshness window is compared against the request's `now`, and the refusal is
        // the verifier's own.
        let stale = bound_envelope(1);
        let mut request_value = verify_request(&stale);
        request_value["now"] = json!(NOW);
        let answer = plugin
            .handle(&request("plugin:message:send", request_value))
            .expect("answers");
        assert_eq!(answer["checks"]["freshness"], json!(false));

        // A nonce that is not 32 bytes never reaches the verifier.
        let mut malformed = verify_request(&envelope);
        malformed["nonce"] = json!("00");
        let err = plugin
            .handle(&request("plugin:message:send", malformed))
            .expect_err("must be refused");
        assert!(err.to_string().contains(CODE_ATTEST_REQUEST), "{err}");
    }

    #[test]
    fn a_request_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let mut plugin = started(AttestPlugin::new().expect("valid id"));

        let err = plugin
            .handle(&request("economy:settle", json!({ "op": "roots" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("economy:settle"), "{err}");

        // Held, but not the capability this door needs.
        let err = plugin
            .handle(&request("plugin:lifecycle:read", json!({ "op": "roots" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("plugin:message:send"), "{text}");
        assert!(text.contains("plugin:lifecycle:read"), "{text}");
    }
}
