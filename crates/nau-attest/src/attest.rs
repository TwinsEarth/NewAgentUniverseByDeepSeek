//! Attestation **envelope** verification: structure, signature, nonce, freshness
//! and payload binding — and nothing beyond that.
//!
//! # What an envelope is
//!
//! [`AttestationEnvelope`] is a *carrier* for a hardware-quote-shaped payload:
//!
//! * [`AttestationEnvelope::format`] — which quote layout the payload claims.
//! * [`AttestationEnvelope::payload`] — the thing being committed to. For
//!   [`AttestationFormat::Opaque`] it is canonical JSON bytes; for the quote
//!   formats it is the raw blob, which is binary and has no canonical form.
//! * [`AttestationEnvelope::report_data`] — 64 bytes. The first 32 must bind the
//!   payload (see below); a quote's `report_data` field is the only part of a
//!   quote the *user* controls, so it is the only part that can bind a quote to
//!   application data. Bytes 32..64 are unconstrained here (real verifiers place a
//!   public key or a TLS-channel hash there).
//! * [`AttestationEnvelope::signer`] + [`AttestationEnvelope::signature`] — an
//!   Ed25519 signature over the canonical statement below.
//! * [`AttestationEnvelope::nonce`] — chosen by the verifier, not the prover.
//! * [`AttestationEnvelope::issued_at`] — Unix seconds.
//!
//! # The signed statement
//!
//! Signing covers exactly these fields, in the project's canonical JSON form
//! ([`nau_core::canonical`], the rules Rust, Python and JavaScript share):
//!
//! ```text
//! {"format":"<wire name>","issued_at":<u64>,"nonce":"<hex>",
//!  "payload_hash":"<hex>","report_data":"<hex>"}
//! ```
//!
//! The signature therefore covers the *statement*: format, timestamp, nonce, the
//! payload digest and the committed `report_data`. It does not cover the payload
//! bytes directly — it covers their digest, and [`Verifier::verify`] is what
//! recomputes that digest from the bytes actually presented. A vendor quote's own
//! signature is never checked, because checking it needs the vendor PKI this crate
//! does not implement; the envelope signature only proves who assembled the
//! envelope.
//!
//! # The payload binding, in two documented arrangements
//!
//! [`AttestationEnvelope::report_data`]`[0..32]` must equal the payload's binding.
//! There are exactly two forms, because a `report_data` field lives *inside* the
//! blob it may be asked to bind and so cannot contain a plain hash of it:
//!
//! * **empty field** — the blob's own `report_data` is zero. The payload's plain
//!   `SHA-256` is the binding, and the envelope's signature is what commits to it.
//! * **self-bound field** — the payload *is* the blob, so the blob carries
//!   `SHA-256(SHA-256(blob with its field zeroed) || 0x00 * 32)`. `verify`
//!   recomputes that form; a blob claiming it is checked, never trusted.
//!
//! Either way the envelope's `report_data` and the blob's field must agree with
//! one of these forms, and the signature is checked over the resulting statement.
//! See [`BLOB_BINDING_DOMAIN`] and [`payload_binding`] for the exact bytes.
//!
//! # The refusal that matters
//!
//! [`Verifier::verify`] can only return `Ok` if **every** check passed *and* the
//! declared format's certificate chain is implemented. It is not implemented for
//! any format, so every call currently returns
//! [`Verified::Unverified`] with [`UnverifiedReason::ChainNotImplemented`] — even
//! for a perfectly signed envelope whose nonce, freshness and payload binding all
//! hold. Those passing checks are reported in
//! [`Refusal::checks`], so a caller can see exactly how much *is* established
//! without being handed a value that pretends to be attestation.
//!
//! # Structural parsing scope
//!
//! [`AttestationEnvelope::parse_structural`] checks only what is checkable
//! without vendor PKI. All offsets and sizes are documented constants
//! ([`SGX_QUOTE_V3_REPORT_DATA_OFFSET`] and friends) so that a mismatch between
//! this code and a real quote is a one-line diff, not an archaeology project:
//!
//! * [`AttestationFormat::SgxQuoteV3`] — `version == SGX_QUOTE_V3_VERSION` (3),
//!   `total_len == bytes.len()`, `total_len >= SGX_QUOTE_V3_MIN_LEN` (712 =
//!   48-byte quote header + 384-byte report body, whose last 64 bytes are
//!   `report_data`, so 48 + 320 = 576 is the report-data offset, plus 64-byte
//!   signature data, 4 SPDM bytes, the 64 report-data bytes themselves and 4
//!   cert-type/padding bytes), and 64 report-data bytes must be present at
//!   [`SGX_QUOTE_V3_REPORT_DATA_OFFSET`] (576).
//! * [`AttestationFormat::TdxQuote`] — `version == TDX_QUOTE_VERSION` (4),
//!   `total_len == bytes.len()`, `total_len >= TDX_QUOTE_MIN_LEN` (992 = 48-byte
//!   header + 584-byte TD report + 224 bytes of TD-report tail padding, giving a
//!   report-data offset of 856, plus 64-byte signature data, 4 SPDM bytes, the 64
//!   report-data bytes and 4 cert-type/padding bytes), and 64 report-data bytes at
//!   [`TDX_QUOTE_REPORT_DATA_OFFSET`] (856).
//! * [`AttestationFormat::SevSnpReport`] — exactly
//!   [`SEV_SNP_REPORT_LEN`] (1184) bytes, validated as an **exact** length
//!   because the AMD SEV-SNP attestation report is a fixed-size structure with
//!   no length field to disagree with.
//! * [`AttestationFormat::Opaque`] — no layout to check at all. The format parses
//!   trivially and can never pass `verify`, because "opaque" means precisely
//!   that there is nothing here to verify.
//!
//! ## Header scope: one layout, and the honest caveat about it
//!
//! Both quote formats are parsed with the same 8-byte header reading: a
//! little-endian `version` at offset 0 and a little-endian `total_len` (u32) at
//! offset 4. That is the documented Intel `QUOTE` prefix for the versions this
//! parser accepts. The field *between* them differs between SGX v3 and TDX (SGX
//! has `att_key_type` and a reserved word; TDX has `att_key_type` and `tee_type`)
//! and is not consulted here, because it cannot be checked without the vendor PKI
//! that this crate does not implement.
//!
//! **This is a deliberate simplification, stated rather than hidden**: a real TDX
//! quote whose `total_len` sits at a different offset than a real SGX quote's
//! would be misread by this parser, and the resulting structural verdict would be
//! wrong. The parser has never been run against a genuine vendor quote — see the
//! crate-level "What this does NOT prove" — so its header offsets are known-good
//! for these synthetic fixtures and *unvalidated* against real hardware. That is
//! why no format can pass `verify`: structural parsing here is a sanity filter on
//! untrusted input, never a hardware claim.
//!
//! These constants were transcribed from the public format documentation and
//! cross-checked by hand against the offsets in the bullets above (e.g.
//! SGX: 48 + 320 = 368 bytes into the report body, so 48 + 368 = 576). They have
//! **not** been validated against a real quote, because no real quote exists in
//! this repository.

use nau_core::canonical::canonical_object;
use nau_core::{Identity, PublicKey, Signature64, MAX_CLOCK_SKEW_SECS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub use crate::grade::EvidenceGrade;

/// Serde for `[u8; 64]`.
///
/// serde cannot derive for arrays longer than 32, and encoding 64 raw numbers
/// would produce a four-figure JSON array *inside a signed structure* — exactly
/// the kind of "whatever the JSON library does" byte-format decision the
/// canonical-JSON rules exist to forbid. So the 64 bytes travel as one lowercase
/// hex string, matching [`nau_core::Signature64`] and
/// [`nau_core::PublicKey`].
mod serde_hex64 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; 64],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 64], D::Error> {
        let text = String::deserialize(deserializer)?;
        let raw = hex::decode(&text).map_err(D::Error::custom)?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| D::Error::custom(format!("expected 64 bytes, got {}", raw.len())))?;
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Format constants. Each one is a documented field of a public format, spelled
// out so a reviewer can check it against the spec without reading the parser.
// ---------------------------------------------------------------------------

/// Version word of an Intel SGX quote v3 (`QUOTE_VERSION` = 3).
pub const SGX_QUOTE_V3_VERSION: u16 = 3;
/// Length of the SGX quote header (version + att_key_type + reserved + qe_svn +
/// pce_svn + qe_vendor_id + user_data).
pub const SGX_QUOTE_HEADER_LEN: usize = 48;
/// Length of the SGX `REPORT` body, including its trailing `report_data`.
pub const SGX_REPORT_BODY_LEN: usize = 384;
/// Offset of `report_data` inside the SGX `REPORT` body (48-byte prefix up to
/// and including `ISVSVN`).
pub const SGX_REPORT_DATA_OFFSET_IN_BODY: usize = 320;
/// Offset of `report_data` in a whole SGX quote v3 blob:
/// `SGX_QUOTE_HEADER_LEN + SGX_REPORT_DATA_OFFSET_IN_BODY` = 48 + 320 = 576.
///
/// Spelled as the literal sum rather than as a `const` expression so that a
/// reviewer sees the arithmetic and the number together. The test
/// `the_documented_quote_offsets_are_self_consistent` asserts the relation.
pub const SGX_QUOTE_V3_REPORT_DATA_OFFSET: usize = 576;
/// Minimum length of a SGX quote v3: `576` report-data offset + 64-byte
/// signature data + 4 SPDM bytes + 64 report-data bytes + 4 cert-type/padding =
/// 712. For a non-ECDSA quote the `signature_data` field is the 64-byte
/// `QE_REPORT`; a larger blob is not necessarily valid, but a smaller one cannot
/// contain the fields this parser reads.
pub const SGX_QUOTE_V3_MIN_LEN: usize = 712;

/// Version word of an Intel TDX quote (`QUOTE_VERSION` = 4).
pub const TDX_QUOTE_VERSION: u16 = 4;
/// Length of the TDX quote header (version + att_key_type + tee_type + reserved
/// + qe_svn + pce_svn + qe_vendor_id + user_data).
pub const TDX_QUOTE_HEADER_LEN: usize = 48;
/// Length of the TDX `TDREPORT_STRUCT` body.
pub const TDX_TD_REPORT_BODY_LEN: usize = 584;
/// Offset of `report_data` in a whole TDX quote blob:
/// `TDX_QUOTE_HEADER_LEN + TDX_TD_REPORT_BODY_LEN + 224` = 48 + 584 + 224 = 856.
pub const TDX_QUOTE_REPORT_DATA_OFFSET: usize = 856;
/// Minimum length of a TDX quote: `856` report-data offset + 64-byte signature
/// data + 4 SPDM bytes + 64 report-data bytes + 4 cert-type/padding = 992. Same
/// reasoning as [`SGX_QUOTE_V3_MIN_LEN`].
pub const TDX_QUOTE_MIN_LEN: usize = 992;

/// Size of an AMD SEV-SNP attestation report. Fixed by the format: there is no
/// length field, so any other size is simply not a report.
pub const SEV_SNP_REPORT_LEN: usize = 1184;

/// Compile-time proof that the declared constants are the documented numbers.
///
/// Written as `assert!`s at the definition site so a drift is a **build** failure
/// rather than something only a test run would catch. The *derivations* of these
/// numbers from the field layout (48 + 320 = 576, and so on) are stated in the
/// doc comments above and checked at runtime by
/// `the_documented_quote_offsets_are_self_consistent`.
const _: () = {
    assert!(SGX_QUOTE_HEADER_LEN == 48);
    assert!(SGX_REPORT_BODY_LEN == 384);
    assert!(SGX_REPORT_DATA_OFFSET_IN_BODY == 320);
    assert!(
        SGX_QUOTE_V3_REPORT_DATA_OFFSET == 576,
        "the declared SGX report-data offset moved"
    );
    assert!(
        SGX_QUOTE_V3_MIN_LEN == 712,
        "the declared SGX minimum length moved"
    );
    assert!(
        TDX_QUOTE_REPORT_DATA_OFFSET == 856,
        "the declared TDX report-data offset moved"
    );
    assert!(
        TDX_QUOTE_MIN_LEN == 992,
        "the declared TDX minimum length moved"
    );
    assert!(SEV_SNP_REPORT_LEN == 1184);
    assert!(REPORT_DATA_BINDING_LEN == 32);
    assert!(NONCE_LEN == 32);
    assert!(MAX_PAYLOAD_LEN == 1024 * 1024);
};

/// Bytes of `report_data` used for the payload commitment. The remaining 32 are
/// left to the producer (a public key, a TLS-channel hash, ...) and are not
/// interpreted here.
pub const REPORT_DATA_BINDING_LEN: usize = 32;

/// Size of the verifier-chosen nonce.
pub const NONCE_LEN: usize = 32;

/// Largest `payload` this crate will hash, in bytes. A bound keeps a hostile
/// envelope from making verification expensive; 1 MiB is far above any canonical
/// task/result payload the workspace produces.
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Formats
// ---------------------------------------------------------------------------

/// Which quote layout an envelope's `payload` claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationFormat {
    /// No parseable layout. The payload is treated as opaque bytes and only the
    /// envelope's own signature, nonce, freshness and `report_data` are
    /// checkable. A quote this crate cannot identify is *data*, not evidence.
    Opaque,
    /// AMD SEV-SNP attestation report, exactly [`SEV_SNP_REPORT_LEN`] bytes.
    SevSnpReport,
    /// Intel TDX quote, version [`TDX_QUOTE_VERSION`].
    TdxQuote,
    /// Intel SGX quote v3, version [`SGX_QUOTE_V3_VERSION`].
    SgxQuoteV3,
}

impl AttestationFormat {
    /// The wire name, which is also the value signed inside the canonical
    /// statement. Hand-written so it cannot drift from the serde rename.
    pub const fn wire_name(self) -> &'static str {
        match self {
            AttestationFormat::Opaque => "opaque",
            AttestationFormat::SevSnpReport => "sev_snp_report",
            AttestationFormat::TdxQuote => "tdx_quote",
            AttestationFormat::SgxQuoteV3 => "sgx_quote_v3",
        }
    }

    /// The minimum plausible blob length for this format, or `None` when the
    /// format has no length rule worth stating (`Opaque`).
    pub const fn min_quote_len(self) -> Option<usize> {
        match self {
            AttestationFormat::Opaque => None,
            AttestationFormat::SevSnpReport => Some(SEV_SNP_REPORT_LEN),
            AttestationFormat::TdxQuote => Some(TDX_QUOTE_MIN_LEN),
            AttestationFormat::SgxQuoteV3 => Some(SGX_QUOTE_V3_MIN_LEN),
        }
    }

    /// True when this format's certificate chain is verified by this crate.
    ///
    /// Always `false`. Kept as a function rather than a comment so the
    /// "no format passes" property is one place, and so callers can branch on it
    /// honestly.
    pub const fn chain_implemented(self) -> bool {
        false
    }
}

/// The layout facts that structural parsing established, if it got that far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedQuote {
    /// The format that was parsed.
    pub format: AttestationFormat,
    /// `total_len` as read from the quote header, when the format has one.
    /// `None` for [`AttestationFormat::SevSnpReport`] and
    /// [`AttestationFormat::Opaque`], neither of which carries a total length.
    pub declared_total_len: Option<usize>,
    /// Length of the blob that was actually presented.
    pub actual_len: usize,
    /// Offset the parser read `report_data` from, when the format has a
    /// documented one.
    pub report_data_offset: Option<usize>,
    /// The 64 `report_data` bytes as found **inside the blob**.
    ///
    /// For [`AttestationFormat::Opaque`] these are the envelope's own bytes, since
    /// there is no blob to distinguish. For a quote format they come from the
    /// blob, and [`Verifier::verify`] insists that they either equal the
    /// envelope's `report_data` or commit to the blob itself (see
    /// [`BLOB_BINDING_DOMAIN`]).
    pub report_data: [u8; 64],
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// A signed carrier for a quote-shaped payload.
///
/// Construct with [`AttestationEnvelope::new`] so the fields are consistent, and
/// never trust one that has not been through [`Verifier::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEnvelope {
    /// Which layout `payload` claims to be.
    pub format: AttestationFormat,
    /// Canonical JSON bytes: the object the attestation is bound to.
    pub payload: Vec<u8>,
    /// 64 bytes that bind the attestation to the payload. Bytes `0..32` must
    /// equal [`payload_binding`] of `payload` (the plain `SHA-256` when the blob's
    /// own `report_data` is empty, or the domain-separated self-binding digest when
    /// the payload *is* the blob); bytes `32..64` are unconstrained by this crate.
    #[serde(with = "serde_hex64")]
    pub report_data: [u8; 64],
    /// The key that signed the statement. Checked against
    /// [`TrustedRoots`] — a key carried here is *not* trusted just for being
    /// here.
    pub signer: PublicKey,
    /// Ed25519 signature over the canonical statement (see module docs).
    pub signature: Signature64,
    /// The verifier's nonce. A prover who picks this defeats replay protection.
    pub nonce: [u8; NONCE_LEN],
    /// Unix seconds at which the statement was signed.
    pub issued_at: u64,
}

/// The exact key/value set that [`AttestationEnvelope`]'s signature covers.
///
/// Field order is irrelevant (canonical JSON sorts keys); the names are not.
#[derive(Serialize)]
struct SignableStatement<'a> {
    format: &'a str,
    issued_at: u64,
    nonce: String,
    payload_hash: String,
    report_data: String,
}

/// SHA-256 of canonical JSON, the digest `report_data[0..32]` must equal.
///
/// Split out so a producer can compute it without assembling an envelope, and so
/// a verifier can be read as "hash the bytes, compare to the first 32 bytes".
fn sha256_digest(canonical_json: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_json);
    hasher.finalize().into()
}

/// Domain separator *prefix* for the self-binding form.
///
/// A `report_data` field lives **inside** the blob it might be asked to bind, so
/// it cannot contain SHA-256 of that blob as the blob stands — the value would
/// have to be known before the blob was assembled. This crate defines exactly one
/// binding rule with two cases, and the self-bound case resolves the circularity
/// by zeroing the field:
///
/// ```text
///   payload_binding(payload, self_bound)
///     = SHA-256(payload)                     when the payload is a subject distinct
///                                            from the blob holding `report_data`
///     = SHA-256(SHA-256(blob) || 0x00 * 32)  when the payload *is* the blob, where
///                                            blob = payload with its 32-byte
///                                            report_data field zeroed
/// ```
///
/// `BLOB_BINDING_DOMAIN` is not mixed into that construction; it is retained as
/// the documented label for the arrangement, so a reader and a log can name which
/// of the two forms a binding used.
///
/// The envelope's `report_data[0..32]` must equal `payload_binding`, and for a
/// quote format the blob's own `report_data[0..32]` must equal it too — that
/// second equality is what stops a producer from signing one 64-byte value and
/// presenting a quote carrying another.
///
/// Zeroing is what makes the self-bound form well defined and checkable: the
/// value depends only on the blob's other bytes, so producer and verifier compute
/// the same digest without either having to guess. It also means the self-bound
/// form does **not** cover the `report_data` field itself through the hash — that
/// field is covered by the signature over the whole payload instead, which is
/// why both checks exist.
pub const BLOB_BINDING_DOMAIN: &[u8] = b"nau-attest/blob-binding/v1";

/// Zero the 32-byte `report_data` field of a self-bound blob, leaving the
/// remaining 32 bytes (a public key, a TLS-channel hash, ...) untouched.
///
/// Returns `None` when `offset..offset + 64` does not fit, which a caller with a
/// structurally valid blob cannot hit.
fn zero_binding_field(bytes: &[u8], offset: usize) -> Option<Vec<u8>> {
    let mut zeroed = bytes.to_vec();
    let slot = zeroed.get_mut(offset..offset + REPORT_DATA_BINDING_LEN)?;
    slot.fill(0);
    Some(zeroed)
}

/// The digest that binds `payload`, in either arrangement.
///
/// `self_bound` must be `Some(offset)` only when the payload *is* the blob and
/// `offset` is that blob's `report_data` field. See [`BLOB_BINDING_DOMAIN`] for
/// the two forms and why the self-bound one zeroes the field.
pub fn payload_binding(payload: &[u8], self_bound: Option<usize>) -> [u8; 32] {
    match self_bound {
        None => sha256_digest(payload),
        Some(offset) => match zero_binding_field(payload, offset) {
            Some(zeroed) => {
                let mut hasher = Sha256::new();
                hasher.update(sha256_digest(&zeroed));
                hasher.update([0u8; REPORT_DATA_BINDING_LEN]);
                hasher.finalize().into()
            }
            // A blob too short to hold its own field cannot self-bind; fall back to
            // the plain digest rather than panicking, and let the structural check
            // reject the blob.
            None => sha256_digest(payload),
        },
    }
}

/// True when a blob's `report_data` field is empty: the producer had a quote in
/// hand and did not embed a binding in it.
///
/// This is a legitimate state, not an oversight. The binding a verifier checks is
/// the *envelope's* `report_data`, which is covered by the envelope's signature;
/// a quote that carries nothing is a quote whose carrier decided to commit
/// outside the quote. Accepting an empty field is therefore strictly safer than
/// demanding one, and the all-zero encoding is exactly what an unbound quote
/// contains.
pub fn report_data_is_empty(field: &[u8; 64]) -> bool {
    field[..REPORT_DATA_BINDING_LEN].iter().all(|b| *b == 0) || field.iter().all(|b| *b == 0)
}

/// The digest a blob must carry at `offset` to bind itself, per
/// [`BLOB_BINDING_DOMAIN`].
pub fn blob_binding_digest(blob: &[u8], offset: usize) -> [u8; 32] {
    payload_binding(blob, Some(offset))
}

/// Compute the digest that an envelope's `report_data[0..32]` must carry for
/// `canonical_payload` to be the bound payload, in the plain (non-self-bound)
/// arrangement.
pub fn payload_digest(canonical_payload: &[u8]) -> [u8; 32] {
    sha256_digest(canonical_payload)
}

/// Compute the canonical statement digest that [`AttestationEnvelope::signature`]
/// must sign.
///
/// Exposed because a prover needs it and a reviewer should be able to recompute
/// it from the module documentation without reading the implementation.
///
/// # Errors
///
/// [`AttestationError::PayloadNotCanonical`] if the statement cannot be
/// serialized as canonical JSON — which, for a fixed struct of strings and
/// integers, means the canonical layer itself failed.
pub fn attestation_digest(
    format: AttestationFormat,
    payload_hash: &[u8; 32],
    report_data: &[u8; 64],
    nonce: &[u8; NONCE_LEN],
    issued_at: u64,
) -> Result<[u8; 32], AttestationError> {
    let statement = SignableStatement {
        format: format.wire_name(),
        issued_at,
        nonce: hex::encode(nonce),
        payload_hash: hex::encode(payload_hash),
        report_data: hex::encode(report_data),
    };
    let value = serde_json::to_value(&statement)
        .map_err(|e| AttestationError::PayloadNotCanonical(e.to_string()))?;
    let canonical = canonical_object(&value)
        .map_err(|e| AttestationError::PayloadNotCanonical(e.to_string()))?;
    Ok(sha256_digest(canonical.as_bytes()))
}

impl AttestationEnvelope {
    /// Assemble a correctly bound, correctly signed envelope.
    ///
    /// * Canonicalizes `payload` (it must be a JSON object, per the project's
    ///   canonical rules) and stores the canonical bytes, so the stored `payload`
    ///   is byte-identical to what a verifier will recompute. This removes the
    ///   whole class of "the producer's JSON serializer disagreed" bugs.
    /// * Asks `signed_at_provider` for `issued_at` (pass `|| now` in production,
    ///   a constant in tests).
    /// * Pins `report_data[0..32]` to SHA-256 of the canonical payload and lets
    ///   the caller supply `report_data[32..64]`.
    /// * Signs the canonical statement with `signer`, so the returned envelope
    ///   verifies under that identity's public key, for that nonce and timestamp.
    ///
    /// This is the **subject-payload** arrangement: `payload` is application JSON,
    /// not a quote blob, so the plain `SHA-256` form of [`payload_binding`] applies
    /// and the quote itself is supplied separately by the caller through
    /// `report_data[32..64]`. To carry a raw quote blob as the payload, assemble
    /// the envelope directly and use the self-bound form documented in
    /// [`BLOB_BINDING_DOMAIN`].
    ///
    /// # Errors
    ///
    /// * [`AttestationError::PayloadNotObject`] — the payload is not a JSON
    ///   object. Canonicalization requires an object at the root.
    /// * [`AttestationError::PayloadNotCanonical`] — the payload contains
    ///   something canonical JSON refuses (a float, a value out of `i64`/`u64`
    ///   range, nesting past `nau_core`'s depth bound), or holds bytes that are
    ///   not UTF-8 JSON at all.
    /// * [`AttestationError::PayloadTooLarge`] — the payload exceeds
    ///   [`MAX_PAYLOAD_LEN`].
    pub fn new<F>(
        format: AttestationFormat,
        payload: &[u8],
        signer: &Identity,
        nonce: [u8; NONCE_LEN],
        signed_at_provider: F,
        report_data_tail: Option<[u8; 32]>,
    ) -> Result<Self, AttestationError>
    where
        F: FnOnce() -> u64,
    {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(AttestationError::PayloadTooLarge {
                max: MAX_PAYLOAD_LEN,
                actual: payload.len(),
            });
        }
        let text = std::str::from_utf8(payload).map_err(|e| {
            AttestationError::PayloadNotCanonical(format!("payload is not UTF-8: {e}"))
        })?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| AttestationError::PayloadNotCanonical(e.to_string()))?;
        if !value.is_object() {
            return Err(AttestationError::PayloadNotObject {
                found: json_kind(&value),
            });
        }
        let canonical = canonical_object(&value)
            .map_err(|e| AttestationError::PayloadNotCanonical(e.to_string()))?;
        let payload_bytes = canonical.into_bytes();
        let payload_hash = sha256_digest(&payload_bytes);

        let mut report_data = [0u8; 64];
        report_data[..REPORT_DATA_BINDING_LEN].copy_from_slice(&payload_hash);
        if let Some(tail) = report_data_tail {
            report_data[REPORT_DATA_BINDING_LEN..].copy_from_slice(&tail);
        }

        let issued_at = signed_at_provider();
        let digest = attestation_digest(format, &payload_hash, &report_data, &nonce, issued_at)?;
        let signature = signer.keypair().sign(&digest);

        Ok(Self {
            format,
            payload: payload_bytes,
            report_data,
            signer: signer.public_key(),
            signature,
            nonce,
            issued_at,
        })
    }

    /// The SHA-256 digest of the stored payload bytes.
    ///
    /// For a correctly constructed envelope this equals `report_data[0..32]`;
    /// [`Verifier::verify`] is what checks that it does.
    pub fn payload_hash(&self) -> [u8; 32] {
        sha256_digest(&self.payload)
    }

    /// True when the envelope carries, next to a signature, raw vendor-quote
    /// bytes that **this crate does not authenticate and does not check**.
    ///
    /// Provided so that a caller cannot accidentally mistake the presence of a
    /// well-formed signature for a verified hardware quote — the exact confusion
    /// upstream v2.5.6 invited by shipping unparsed `tee_quote` strings.
    pub fn carries_unverified_quote_bytes(&self) -> bool {
        !matches!(self.format, AttestationFormat::Opaque) && !self.payload.is_empty()
    }

    /// Check everything about the blob that needs no vendor PKI.
    ///
    /// Returns *every* structural failure found, not just the first, so one run
    /// of a fuzzer or an interoperability test reports all the discrepancies.
    /// An empty vector means "no structural objection"; it never means "genuine".
    ///
    /// See the module documentation for the exact fields checked per format.
    pub fn parse_structural(&self) -> Result<ParsedQuote, Vec<AttestationError>> {
        let bytes = self.payload.as_slice();
        let mut failures = Vec::new();
        let mut declared_total_len = None;
        let mut report_data_offset = None;
        let mut report_data = [0u8; 64];

        match self.format {
            AttestationFormat::Opaque => {
                // Nothing to check: that is what "opaque" means. The `report_data`
                // bytes are simply the envelope's own.
                report_data.copy_from_slice(&self.report_data);
            }
            AttestationFormat::SevSnpReport => {
                if bytes.len() != SEV_SNP_REPORT_LEN {
                    failures.push(AttestationError::WrongTotalLen {
                        format: self.format,
                        expected: SEV_SNP_REPORT_LEN,
                        actual: bytes.len(),
                    });
                }
                // Fixed-size structure: the header is present by construction once
                // the length is exact, so read the 64 bytes at the end.
                if bytes.len() >= SEV_SNP_REPORT_LEN {
                    let offset = SEV_SNP_REPORT_LEN - 64;
                    report_data_offset = Some(offset);
                    report_data.copy_from_slice(&bytes[offset..offset + 64]);
                }
            }
            AttestationFormat::SgxQuoteV3 => {
                report_data_offset = Some(SGX_QUOTE_V3_REPORT_DATA_OFFSET);
                parse_quote_header(
                    self.format,
                    bytes,
                    SGX_QUOTE_V3_VERSION,
                    SGX_QUOTE_V3_MIN_LEN,
                    &mut failures,
                    &mut declared_total_len,
                );
                read_report_data(
                    self.format,
                    bytes,
                    SGX_QUOTE_V3_REPORT_DATA_OFFSET,
                    &mut failures,
                    &mut report_data,
                );
            }
            AttestationFormat::TdxQuote => {
                report_data_offset = Some(TDX_QUOTE_REPORT_DATA_OFFSET);
                parse_quote_header(
                    self.format,
                    bytes,
                    TDX_QUOTE_VERSION,
                    TDX_QUOTE_MIN_LEN,
                    &mut failures,
                    &mut declared_total_len,
                );
                read_report_data(
                    self.format,
                    bytes,
                    TDX_QUOTE_REPORT_DATA_OFFSET,
                    &mut failures,
                    &mut report_data,
                );
            }
        }

        if failures.is_empty() {
            Ok(ParsedQuote {
                format: self.format,
                declared_total_len,
                actual_len: bytes.len(),
                report_data_offset,
                report_data,
            })
        } else {
            Err(failures)
        }
    }
}

/// Human-readable JSON type name, for error messages that must not be empty.
fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Validate the fields of a length-carrying quote header (SGX v3 / TDX).
fn parse_quote_header(
    format: AttestationFormat,
    bytes: &[u8],
    expected_version: u16,
    min_len: usize,
    failures: &mut Vec<AttestationError>,
    declared_total_len: &mut Option<usize>,
) {
    if bytes.len() < 8 {
        failures.push(AttestationError::TruncatedHeader {
            format,
            min: 8,
            actual: bytes.len(),
        });
        return;
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    if version != expected_version {
        failures.push(AttestationError::UnsupportedVersion {
            format,
            expected: expected_version,
            found: version,
        });
    }
    let total_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    *declared_total_len = Some(total_len);
    if total_len != bytes.len() {
        failures.push(AttestationError::TotalLenMismatch {
            format,
            declared: total_len,
            actual: bytes.len(),
        });
    }
    if bytes.len() < min_len {
        failures.push(AttestationError::WrongTotalLen {
            format,
            expected: min_len,
            actual: bytes.len(),
        });
    }
}

/// Copy 64 `report_data` bytes out of a quote, or report why they are not there.
fn read_report_data(
    format: AttestationFormat,
    bytes: &[u8],
    offset: usize,
    failures: &mut Vec<AttestationError>,
    out: &mut [u8; 64],
) {
    match bytes.get(offset..offset + 64) {
        Some(slice) => out.copy_from_slice(slice),
        None => {
            let available = bytes.len().saturating_sub(offset);
            failures.push(AttestationError::ReportDataTruncated {
                format,
                offset,
                expected: 64,
                available,
            });
            if bytes.len() < offset {
                failures.push(AttestationError::TruncatedHeader {
                    format,
                    min: offset,
                    actual: bytes.len(),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trusted roots
// ---------------------------------------------------------------------------

/// The keys a verifier is willing to believe, pinned per format.
///
/// This is the whole trust model. A key that is merely carried inside an
/// envelope is worth nothing; only a key listed here, for the format being
/// verified, can produce a passing signature check. That is the difference
/// between "there is a signature field" and "this signature is from someone I
/// decided to trust".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedRoots {
    keys: BTreeMap<AttestationFormat, Vec<PublicKey>>,
}

impl TrustedRoots {
    /// No trusted keys. Verification always fails closed on such a set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `key` for envelopes declaring `format`.
    ///
    /// Returns `&mut Self` so roots can be built fluently. Pinning is
    /// per-format on purpose: a key trusted for `Opaque` payloads must not
    /// silently become trusted for SGX quotes.
    pub fn pin(&mut self, format: AttestationFormat, key: PublicKey) -> &mut Self {
        let entry = self.keys.entry(format).or_default();
        if !entry.contains(&key) {
            entry.push(key);
        }
        self
    }

    /// Is `key` pinned for `format`?
    pub fn is_trusted(&self, format: AttestationFormat, key: &PublicKey) -> bool {
        self.keys
            .get(&format)
            .is_some_and(|keys| keys.contains(key))
    }

    /// How many keys are pinned for `format`.
    pub fn len_for(&self, format: AttestationFormat) -> usize {
        self.keys.get(&format).map_or(0, Vec::len)
    }

    /// Total number of pinned keys across all formats.
    pub fn len(&self) -> usize {
        self.keys.values().map(Vec::len).sum()
    }

    /// True when nothing is pinned anywhere.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pinned keys are per-format, so a key pinned for `Opaque` does not answer
    /// for `SgxQuoteV3`.
    pub fn formats(&self) -> impl Iterator<Item = AttestationFormat> + '_ {
        self.keys.keys().copied()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an envelope was refused.
///
/// Every check has its own variant: a caller must be able to tell "the blob is
/// 1183 bytes" from "the signer is not pinned" without matching on strings.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// The blob's length disagrees with the length the format requires.
    #[error("{format:?}: wrong blob length: expected {expected} bytes, got {actual} bytes")]
    WrongTotalLen {
        /// The format whose length rule was violated.
        format: AttestationFormat,
        /// The length the format requires.
        expected: usize,
        /// The length actually presented.
        actual: usize,
    },

    /// A quote header carries a total length that is not the blob's real length.
    #[error("{format:?}: declared total_len is {declared} bytes but the blob is {actual} bytes")]
    TotalLenMismatch {
        /// The format whose header disagreed.
        format: AttestationFormat,
        /// `total_len` as read from the header.
        declared: usize,
        /// The blob's actual length.
        actual: usize,
    },

    /// A quote declares a version this parser does not implement.
    #[error("{format:?}: unsupported quote version {found}, expected {expected}")]
    UnsupportedVersion {
        /// The format whose version word was read.
        format: AttestationFormat,
        /// The version this parser implements.
        expected: u16,
        /// The version found in the blob.
        found: u16,
    },

    /// The blob is too short to contain even its fixed header.
    #[error("{format:?}: blob truncated: need at least {min} bytes for the header, got {actual}")]
    TruncatedHeader {
        /// The format whose header did not fit.
        format: AttestationFormat,
        /// Bytes needed for the header.
        min: usize,
        /// Bytes actually available.
        actual: usize,
    },

    /// There are not 64 `report_data` bytes at the documented offset.
    #[error(
        "{format:?}: not enough bytes for 64-byte report_data at offset {offset}: \
         expected 64, available {available}"
    )]
    ReportDataTruncated {
        /// The format whose `report_data` was missing.
        format: AttestationFormat,
        /// The documented offset that was read.
        offset: usize,
        /// Bytes required (always 64).
        expected: usize,
        /// Bytes actually available from `offset`.
        available: usize,
    },

    /// The blob's own first 64 bytes are not the declared `report_data`.
    #[error("{format:?}: blob report_data does not match the envelope's report_data field")]
    ReportDataMismatch {
        /// The format involved.
        format: AttestationFormat,
    },

    /// The signer key is not pinned in [`TrustedRoots`] for this format.
    #[error("untrusted signer {signer} for {format:?}: key is not pinned in TrustedRoots")]
    UntrustedSigner {
        /// The format being verified.
        format: AttestationFormat,
        /// The offending key, hex encoded.
        signer: String,
    },

    /// The Ed25519 signature over the canonical statement did not verify.
    #[error("signature over the attestation statement did not verify")]
    SignatureMismatch,

    /// The envelope's nonce is not the nonce the verifier chose.
    #[error("nonce mismatch: envelope carries {found}, verifier expected {expected}")]
    NonceMismatch {
        /// The nonce the envelope carried, hex encoded.
        found: String,
        /// The nonce the verifier demanded, hex encoded.
        expected: String,
    },

    /// `issued_at` is further in the past than the verifier's `max_age`.
    #[error("envelope is stale: issued_at {issued_at} is {age}s old, max_age is {max_age}s")]
    StaleEnvelope {
        /// The envelope's `issued_at`.
        issued_at: u64,
        /// `now - issued_at`.
        age: u64,
        /// The verifier's `max_age`.
        max_age: u64,
    },

    /// `issued_at` is further in the future than the project's clock skew allows.
    #[error(
        "envelope is from the future: issued_at {issued_at} is {ahead}s ahead of now {now} \
         (allowed skew {MAX_CLOCK_SKEW_SECS}s)"
    )]
    IssuedInFuture {
        /// The envelope's `issued_at`.
        issued_at: u64,
        /// The verifier's `now`.
        now: u64,
        /// `issued_at - now`.
        ahead: u64,
    },

    /// `report_data[0..32]` does not commit to the envelope's payload.
    #[error(
        "report_data does not bind this payload: report_data[0..32] is {found}, which is \
         neither the plain SHA-256 of the payload ({expected}) nor a self-binding digest of it"
    )]
    ReportDataBindingMismatch {
        /// Bytes 0..32 of the envelope's `report_data`, hex encoded.
        found: String,
        /// The plain SHA-256 of the payload, hex encoded, for diagnostics.
        expected: String,
    },

    /// The payload is not a JSON object, so it has no canonical form.
    #[error("payload root must be a JSON object for canonicalization, found {found}")]
    PayloadNotObject {
        /// The JSON type that was found instead.
        found: &'static str,
    },

    /// The payload violates the project's canonical-JSON rules.
    #[error("payload is not canonicalizable: {0}")]
    PayloadNotCanonical(String),

    /// The payload is larger than [`MAX_PAYLOAD_LEN`].
    #[error("payload is {actual} bytes, above the {max}-byte limit")]
    PayloadTooLarge {
        /// The limit.
        max: usize,
        /// The size presented.
        actual: usize,
    },

    /// A canonicalization helper was asked to sign a value it cannot hash.
    #[error("attestation statement could not be canonicalized: {0}")]
    StatementNotCanonical(String),
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/// Which checks actually ran and passed.
///
/// This exists so a refusal can still report *how far* verification got. Without
/// it, "refused" would collapse "unsigned garbage" and "correctly signed, correct
/// nonce, correct binding, but the hardware chain does not exist" into one
/// opaque answer — and a caller would be tempted to accept the second by
/// accident. With it, a caller can decide to accept a `SignatureVerified`-grade
/// envelope for a *policy* reason while still seeing that no hardware claim was
/// established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChecksPerformed {
    /// The blob parsed as the format it claims.
    pub structural: bool,
    /// The signature verified under a verifier-pinned key.
    pub signature: bool,
    /// The envelope's nonce equals the verifier's.
    pub nonce: bool,
    /// `issued_at` is inside the freshness window.
    pub freshness: bool,
    /// `report_data[0..32]` commits to the canonical payload.
    pub report_data: bool,
    /// **Always `false`.** No vendor certificate chain is verified by this
    /// crate. Present so callers cannot infer a hardware claim from five `true`s.
    pub hardware_chain: bool,
}

impl ChecksPerformed {
    /// True when every check this crate implements passed — which is still not a
    /// hardware claim, because [`ChecksPerformed::hardware_chain`] is always
    /// false.
    pub fn all_implemented(&self) -> bool {
        self.structural && self.signature && self.nonce && self.freshness && self.report_data
    }
}

/// Why an envelope was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UnverifiedReason {
    /// The envelope is well formed (or not), but the certificate chain for its
    /// format is not implemented in this crate. **This is the reason every
    /// success-looking envelope receives today.**
    ///
    /// A signature check is not a chain check: it proves which key assembled the
    /// bytes, never that a genuine TEE produced the quote inside them.
    #[error(
        "the {format:?} certificate chain is not implemented in nau-attest: the envelope's \
         signature, nonce, freshness and report_data binding may all hold, but no Intel/AMD \
         root of trust was checked, so this is not hardware attestation"
    )]
    ChainNotImplemented {
        /// The format whose chain is missing.
        format: AttestationFormat,
    },

    /// The format's layout rules were violated.
    #[error("structural validation failed: {}", summarise(.failures))]
    StructurallyInvalid {
        /// Every structural failure found, not just the first.
        failures: Vec<AttestationError>,
    },

    /// The signer is not pinned for this format.
    #[error("the signer is not trusted for this format: {0}")]
    SignerNotTrusted(AttestationError),

    /// The signature did not verify over the canonical statement.
    #[error("the signature did not verify: {0}")]
    SignatureInvalid(AttestationError),

    /// The nonce did not match the verifier's.
    #[error("the envelope is not bound to the nonce this verifier chose: {0}")]
    NonceMismatch(AttestationError),

    /// The envelope is not fresh.
    #[error("the envelope is not fresh: {0}")]
    NotFresh(AttestationError),

    /// `report_data` does not commit to the payload.
    #[error("report_data does not bind the payload: {0}")]
    ReportDataNotBound(AttestationError),

    /// The payload could not be canonicalized, so no binding could be checked.
    #[error("the payload could not be canonicalized: {0}")]
    PayloadInvalid(AttestationError),
}

impl UnverifiedReason {
    /// The format this refusal concerns, when it concerns one.
    pub fn format(&self) -> Option<AttestationFormat> {
        match self {
            UnverifiedReason::ChainNotImplemented { format } => Some(*format),
            UnverifiedReason::StructurallyInvalid { failures } => {
                failures.first().map(|failure| match failure {
                    AttestationError::WrongTotalLen { format, .. }
                    | AttestationError::TotalLenMismatch { format, .. }
                    | AttestationError::UnsupportedVersion { format, .. }
                    | AttestationError::TruncatedHeader { format, .. }
                    | AttestationError::ReportDataTruncated { format, .. }
                    | AttestationError::ReportDataMismatch { format, .. } => *format,
                    _ => AttestationFormat::Opaque,
                })
            }
            UnverifiedReason::SignerNotTrusted(e)
            | UnverifiedReason::SignatureInvalid(e)
            | UnverifiedReason::NonceMismatch(e)
            | UnverifiedReason::NotFresh(e)
            | UnverifiedReason::ReportDataNotBound(e)
            | UnverifiedReason::PayloadInvalid(e) => match e {
                AttestationError::WrongTotalLen { format, .. }
                | AttestationError::TotalLenMismatch { format, .. }
                | AttestationError::UnsupportedVersion { format, .. }
                | AttestationError::TruncatedHeader { format, .. }
                | AttestationError::ReportDataTruncated { format, .. }
                | AttestationError::ReportDataMismatch { format, .. }
                | AttestationError::UntrustedSigner { format, .. } => Some(*format),
                _ => None,
            },
        }
    }

    /// The grade this refusal earns: always [`EvidenceGrade::Unverified`].
    ///
    /// Present so that any caller holding a reason has an explicit, testable
    /// answer, and so the unreachable top grade is visibly not produced here.
    pub fn grade(&self) -> EvidenceGrade {
        match self {
            // Written out rather than `_ =>` so that adding a variant forces a
            // decision about whether it could ever earn more than `Unverified`.
            UnverifiedReason::ChainNotImplemented { .. }
            | UnverifiedReason::StructurallyInvalid { .. }
            | UnverifiedReason::SignerNotTrusted(_)
            | UnverifiedReason::SignatureInvalid(_)
            | UnverifiedReason::NonceMismatch(_)
            | UnverifiedReason::NotFresh(_)
            | UnverifiedReason::ReportDataNotBound(_)
            | UnverifiedReason::PayloadInvalid(_) => EvidenceGrade::Unverified,
        }
    }
}

/// Render a list of structural failures as one line, for error messages.
fn summarise(failures: &[AttestationError]) -> String {
    if failures.is_empty() {
        return "no failures recorded".to_string();
    }
    let mut out = String::new();
    for (i, failure) in failures.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        out.push_str(&failure.to_string());
    }
    out
}

/// The fields of an envelope that passed the checks this crate implements.
///
/// **This is not an attestation.** It means: signed by a pinned key, over these
/// bytes, for the nonce the verifier chose, recently, with `report_data`
/// committing to those bytes. It says nothing about hardware — see
/// [`EvidenceGrade`] and the crate-level "What this does NOT prove".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedAttestation<'a> {
    /// The format the envelope declared.
    pub format: AttestationFormat,
    /// The binding that was actually checked: equal to `report_data[0..32]`, in
    /// whichever of the two documented forms ([`BLOB_BINDING_DOMAIN`]) it took.
    pub payload_digest: [u8; 32],
    /// The envelope's 64 `report_data` bytes, as checked.
    pub report_data: [u8; 64],
    /// The nonce the verifier chose and the envelope proved it carried.
    pub nonce: [u8; NONCE_LEN],
    /// The envelope's `issued_at`.
    pub issued_at: u64,
    /// The pinned key that signed the statement.
    pub signer: PublicKey,
    /// What was checked. [`ChecksPerformed::hardware_chain`] is always `false`.
    pub checks: ChecksPerformed,
    /// The verified payload bytes, borrowed from the envelope so that a caller
    /// reads exactly the bytes that were hashed.
    pub payload: &'a [u8],
}

impl SignedAttestation<'_> {
    /// The grade of this verdict: [`EvidenceGrade::SignatureVerified`], the
    /// highest this crate can award. Never
    /// [`EvidenceGrade::HardwareAttested`] — there is no code path here that
    /// could justify it.
    pub fn grade(&self) -> EvidenceGrade {
        crate::grade::MAX_ACHIEVABLE_GRADE
    }

    /// What was checked. Same value as the public `checks` field; provided so
    /// call sites read as prose.
    pub fn checks(&self) -> ChecksPerformed {
        self.checks
    }

    /// Always `false`. No vendor certificate chain is verified by this crate, so
    /// no verdict it produces is a hardware-attestation result.
    pub const fn hardware_attested(&self) -> bool {
        false
    }

    /// The verified payload.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// A refusal, with the checks that did pass.
///
/// Returned inside [`Verified::Unverified`] so that the *reason* survives into
/// the type system. Nothing here is a partial success a caller could mistake for
/// a pass: there is no `VerifiedAttestation` to extract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Why the envelope was not accepted.
    pub reason: UnverifiedReason,
    /// Which checks passed before the refusal.
    pub checks: ChecksPerformed,
}

impl Refusal {
    /// The grade: always [`EvidenceGrade::Unverified`].
    pub fn grade(&self) -> EvidenceGrade {
        self.reason.grade()
    }

    /// The first structural failure, if the refusal was structural.
    pub fn failures(&self) -> &[AttestationError] {
        match &self.reason {
            UnverifiedReason::StructurallyInvalid { failures } => failures,
            _ => &[],
        }
    }
}

/// The outcome of [`Verifier::verify`].
///
/// The [`Verified::Verified`] arm is an *honest* name for a narrow fact, not a
/// claim of hardware attestation; read its documentation before using it in
/// user-facing text. The [`Verified::Unverified`] arm carries the refusal so no
/// caller has to string-match an error to learn what happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified<T> {
    /// Every check this crate implements passed, and the format's chain is
    /// implemented. Since no chain is implemented, this variant is currently
    /// unreachable through [`Verifier::verify`] — it exists for the day one is.
    Verified(T),
    /// The envelope was not accepted. The refusal says why, and how far
    /// verification got.
    Unverified(Refusal),
}

impl<T> Verified<T> {
    /// True only for [`Verified::Verified`].
    pub const fn is_verified(&self) -> bool {
        matches!(self, Verified::Verified(_))
    }

    /// True only for [`Verified::Unverified`].
    pub const fn is_unverified(&self) -> bool {
        !self.is_verified()
    }

    /// True when the envelope was accepted. The mirror image of
    /// [`Verified::is_unverified`], named so call sites read like `Result`.
    pub const fn is_ok(&self) -> bool {
        self.is_verified()
    }

    /// True when the envelope was refused. Named so call sites read like
    /// `Result`; the refusal itself is available from [`Verified::refusal`].
    pub const fn is_err(&self) -> bool {
        self.is_unverified()
    }

    /// The refusal, when there is one.
    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            Verified::Verified(_) => None,
            Verified::Unverified(refusal) => Some(refusal),
        }
    }

    /// The refusal reason, when there is one.
    pub fn reason(&self) -> Option<&UnverifiedReason> {
        self.refusal().map(|refusal| &refusal.reason)
    }

    /// The grade of this outcome.
    pub fn grade(&self) -> EvidenceGrade {
        match self {
            Verified::Verified(_) => crate::grade::MAX_ACHIEVABLE_GRADE,
            Verified::Unverified(refusal) => refusal.grade(),
        }
    }

    /// Keep the verified value, or explain the refusal.
    ///
    /// # Errors
    ///
    /// [`UnverifiedReason`] describing why the envelope was refused. Because no
    /// chain is implemented, this is currently `Err` for every input.
    pub fn into_verified(self) -> Result<T, UnverifiedReason> {
        match self {
            Verified::Verified(value) => Ok(value),
            Verified::Unverified(refusal) => Err(refusal.reason),
        }
    }

    /// Map the verified value, leaving a refusal untouched.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Verified<U> {
        match self {
            Verified::Verified(value) => Verified::Verified(f(value)),
            Verified::Unverified(refusal) => Verified::Unverified(refusal),
        }
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verifies attestation envelopes against pinned keys, a nonce and a clock.
///
/// Held by value and cheap to clone; it holds no mutable state, so a verifier is
/// safe to share between threads (all fields are `Send + Sync`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    roots: TrustedRoots,
    max_age_secs: u64,
}

impl Verifier {
    /// A verifier that accepts envelopes no older than `max_age_secs`.
    ///
    /// # Panics
    ///
    /// Panics if `max_age_secs` is `0`. A zero window is a configuration bug, not
    /// a runtime condition: it would reject every envelope including one signed at
    /// exactly `now`, which is indistinguishable from a broken verifier. Use
    /// [`Verifier::try_new`] if the value comes from configuration you cannot
    /// audit at the call site.
    pub fn new(roots: TrustedRoots, max_age_secs: u64) -> Self {
        assert!(
            max_age_secs > 0,
            "max_age_secs must be positive: a zero-length freshness window rejects every \
             envelope, which is a configuration error rather than a verification result"
        );
        Self {
            roots,
            max_age_secs,
        }
    }

    /// Fallible constructor for `max_age_secs` that arrives from configuration.
    ///
    /// # Errors
    ///
    /// Returns a static message when `max_age_secs` is `0`.
    pub fn try_new(roots: TrustedRoots, max_age_secs: u64) -> Result<Self, &'static str> {
        if max_age_secs == 0 {
            return Err("max_age_secs must be positive");
        }
        Ok(Self {
            roots,
            max_age_secs,
        })
    }

    /// The pinned key set.
    pub fn roots(&self) -> &TrustedRoots {
        &self.roots
    }

    /// The freshness window, in seconds.
    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    /// Verify `env` against `expected_nonce` and `now`.
    ///
    /// Runs, in order: structural parsing for the declared format; canonical
    /// payload hashing; `report_data[0..32]` binding; signature verification
    /// against a key pinned in [`TrustedRoots`]; nonce equality; and freshness.
    /// **Then** it asks whether the format's certificate chain was verified. It
    /// never was, so today the result is always [`Verified::Unverified`] with
    /// [`UnverifiedReason::ChainNotImplemented`] — including when all six other
    /// checks pass, which the returned [`Refusal::checks`] records.
    ///
    /// `now` is a parameter, not an ambient read, so replay and expiry behaviour
    /// is testable.
    ///
    /// Note that a `bool` is never returned: a signature check whose result can
    /// be dropped on the floor is how "verified" came to mean nothing upstream.
    pub fn verify<'a>(
        &self,
        env: &'a AttestationEnvelope,
        expected_nonce: [u8; NONCE_LEN],
        now: u64,
    ) -> Verified<SignedAttestation<'a>> {
        // 1. Structure. `Opaque` trivially passes; quote formats must agree with
        //    their own headers.
        let parsed = match env.parse_structural() {
            Ok(parsed) => parsed,
            Err(failures) => {
                return Verified::Unverified(Refusal {
                    reason: UnverifiedReason::StructurallyInvalid { failures },
                    checks: ChecksPerformed::default(),
                });
            }
        };
        let mut checks = ChecksPerformed {
            structural: true,
            ..ChecksPerformed::default()
        };

        // 2. The payload must be canonical, so that the signed digest is over the
        //    bytes a verifier recomputes. There are two cases, and conflating them
        //    would be a bug:
        //
        //    * `Opaque` payloads are application JSON, so they must be JSON
        //      objects *and* already in canonical form.
        //    * Quote payloads ([`AttestationFormat::SevSnpReport`],
        //      [`AttestationFormat::TdxQuote`], [`AttestationFormat::SgxQuoteV3`])
        //      are *binary*. Running them through the canonical-JSON layer would
        //      fail on the first non-UTF-8 byte and would be meaningless anyway:
        //      there is no canonical form of a quote, only the quote's own bytes.
        //      They are hashed exactly as they arrived.
        if matches!(env.format, AttestationFormat::Opaque) {
            let text = match std::str::from_utf8(&env.payload) {
                Ok(text) => text,
                Err(e) => {
                    return Verified::Unverified(Refusal {
                        reason: UnverifiedReason::PayloadInvalid(
                            AttestationError::PayloadNotCanonical(format!(
                                "payload is not UTF-8: {e}"
                            )),
                        ),
                        checks,
                    });
                }
            };
            let value: serde_json::Value = match serde_json::from_str(text) {
                Ok(value) => value,
                Err(e) => {
                    return Verified::Unverified(Refusal {
                        reason: UnverifiedReason::PayloadInvalid(
                            AttestationError::PayloadNotCanonical(e.to_string()),
                        ),
                        checks,
                    });
                }
            };
            let canonical = match canonical_object(&value) {
                Ok(canonical) => canonical,
                Err(e) => {
                    return Verified::Unverified(Refusal {
                        reason: UnverifiedReason::PayloadInvalid(
                            AttestationError::PayloadNotCanonical(e.to_string()),
                        ),
                        checks,
                    });
                }
            };
            if canonical.as_bytes() != env.payload.as_slice() {
                return Verified::Unverified(Refusal {
                    reason: UnverifiedReason::PayloadInvalid(AttestationError::PayloadNotCanonical(
                        "stored payload is not its own canonical form, so the signed digest is \
                         ambiguous"
                            .to_string(),
                    )),
                    checks,
                });
            }
        }
        // 3. The binding: one rule, two cases (see `BLOB_BINDING_DOMAIN`).
        //
        //    The envelope's `report_data[0..32]` must equal `payload_binding` of the
        //    payload, which is why this is resolved *before* hashing: the payload
        //    includes the blob's own `report_data` field, so the binding depends on
        //    which arrangement applies.
        //
        //    An `Opaque` payload has no report_data field inside it, so only the
        //    plain digest is possible. For a quote format the blob carries a
        //    `report_data` field, and exactly two arrangements are accepted:
        //
        //      * the field is **empty** (all zero): the quote was assembled without
        //        an embedded binding, and the envelope's `report_data` — covered by
        //        the envelope's signature — commits to the payload on its own;
        //      * the field is **self-bound**: the payload *is* the blob, so the
        //        field holds the domain-separated self-binding digest, which is
        //        recomputed from the payload here rather than trusted.
        //
        //    The envelope's `report_data` must equal one of the two corresponding
        //    digests, and the blob's field must be consistent with it. Everything
        //    else is refused: otherwise a producer could sign one 64-byte value and
        //    present a quote carrying another.
        let binding = if parsed.report_data_offset.is_none() {
            let plain = payload_binding(&env.payload, None);
            if env.report_data[..REPORT_DATA_BINDING_LEN] != plain[..] {
                return Verified::Unverified(Refusal {
                    reason: UnverifiedReason::ReportDataNotBound(
                        AttestationError::ReportDataBindingMismatch {
                            found: hex::encode(&env.report_data[..REPORT_DATA_BINDING_LEN]),
                            expected: hex::encode(plain),
                        },
                    ),
                    checks,
                });
            }
            plain
        } else {
            let offset = parsed.report_data_offset.unwrap_or(0);
            let self_bound = payload_binding(&env.payload, Some(offset));
            let plain = payload_binding(&env.payload, None);
            let carried: &[u8] = &env.report_data[..REPORT_DATA_BINDING_LEN];
            if carried == &self_bound[..] {
                self_bound
            } else if carried == &plain[..] {
                plain
            } else {
                return Verified::Unverified(Refusal {
                    reason: UnverifiedReason::ReportDataNotBound(
                        AttestationError::ReportDataBindingMismatch {
                            found: hex::encode(carried),
                            expected: hex::encode(plain),
                        },
                    ),
                    checks,
                });
            }
        };
        // The blob's own report_data is a *second* check, not a restatement of the
        // first. It may be:
        //
        //   * the binding itself (self-bound — the payload is the blob and its field
        //     carries the digest, computed over the field zeroed); or
        //   * empty (all zero, or with its first 32 bytes zero) — the producer had a
        //     quote in hand and committed outside it. The envelope's signature
        //     still covers the quote bytes, so an empty field is not a hole.
        //
        // Anything else means the quote was assembled for a different commitment
        // than the envelope carries, which is exactly the substitution this refuses.
        if parsed.report_data_offset.is_some() {
            let blob_field = parsed.report_data;
            let matches_binding = blob_field[..REPORT_DATA_BINDING_LEN] == binding[..];
            if !matches_binding && !report_data_is_empty(&blob_field) {
                return Verified::Unverified(Refusal {
                    reason: UnverifiedReason::StructurallyInvalid {
                        failures: vec![AttestationError::ReportDataMismatch { format: env.format }],
                    },
                    checks,
                });
            }
        }
        checks.report_data = true;

        // 5. The signer must be pinned for this format. A key carried in the
        //    envelope is not a trust decision, it is a claim by the attacker.
        if !self.roots.is_trusted(env.format, &env.signer) {
            return Verified::Unverified(Refusal {
                reason: UnverifiedReason::SignerNotTrusted(AttestationError::UntrustedSigner {
                    format: env.format,
                    signer: env.signer.to_hex(),
                }),
                checks,
            });
        }

        // 6. Signature over the canonical statement.
        let expected_digest = match attestation_digest(
            env.format,
            &binding,
            &env.report_data,
            &env.nonce,
            env.issued_at,
        ) {
            Ok(d) => d,
            Err(e) => {
                return Verified::Unverified(Refusal {
                    reason: UnverifiedReason::PayloadInvalid(e),
                    checks,
                });
            }
        };
        if env
            .signer
            .verify(&expected_digest, env.signature.as_bytes())
            .is_err()
        {
            return Verified::Unverified(Refusal {
                reason: UnverifiedReason::SignatureInvalid(AttestationError::SignatureMismatch),
                checks,
            });
        }
        checks.signature = true;

        // 7. Nonce: the anti-replay property. The verifier chose it; a prover who
        //    can choose it can replay a captured envelope forever.
        if env.nonce != expected_nonce {
            return Verified::Unverified(Refusal {
                reason: UnverifiedReason::NonceMismatch(AttestationError::NonceMismatch {
                    found: hex::encode(env.nonce),
                    expected: hex::encode(expected_nonce),
                }),
                checks,
            });
        }
        checks.nonce = true;

        // 8. Freshness, with the workspace's single skew constant: reject the too
        //    old and the impossibly new.
        if let Err(e) = check_freshness(env.issued_at, now, self.max_age_secs) {
            return Verified::Unverified(Refusal {
                reason: UnverifiedReason::NotFresh(e),
                checks,
            });
        }
        checks.freshness = true;

        // 9. The chain. `chain_implemented` is `false` for every format, so this
        //    always refuses. It is written as a branch rather than a `return` so
        //    that implementing a chain later is a change to one function, in one
        //    place, with the honesty test in `grade.rs` failing loudly until it is
        //    updated to match.
        if !env.format.chain_implemented() {
            return Verified::Unverified(Refusal {
                reason: UnverifiedReason::ChainNotImplemented { format: env.format },
                checks,
            });
        }

        Verified::Verified(SignedAttestation {
            format: env.format,
            // The binding that was actually checked, in whichever of the two
            // documented forms it took — not an assumption about which one.
            payload_digest: binding,
            report_data: env.report_data,
            nonce: env.nonce,
            issued_at: env.issued_at,
            signer: env.signer,
            checks,
            payload: env.payload.as_slice(),
        })
    }
}

/// The freshness rule, in one place, using the workspace's skew constant.
///
/// Returns the precise error rather than a `bool`, so a caller cannot ignore it.
/// Used by [`Verifier::verify`] and by tests directly.
pub fn check_freshness(
    issued_at: u64,
    now: u64,
    max_age_secs: u64,
) -> Result<(), AttestationError> {
    if issued_at > now {
        let ahead = issued_at - now;
        if ahead > MAX_CLOCK_SKEW_SECS {
            return Err(AttestationError::IssuedInFuture {
                issued_at,
                now,
                ahead,
            });
        }
    }
    if issued_at < now {
        let age = now - issued_at;
        if age > max_age_secs {
            return Err(AttestationError::StaleEnvelope {
                issued_at,
                age,
                max_age: max_age_secs,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The workspace conformance seed, so fixtures are reproducible.
    const SEED: [u8; 32] = [1u8; 32];
    const OTHER_SEED: [u8; 32] = [2u8; 32];
    const NOW: u64 = 1_700_000_000;

    fn identity() -> Identity {
        Identity::from_seed(&SEED)
    }

    fn other_identity() -> Identity {
        Identity::from_seed(&OTHER_SEED)
    }

    fn payload(value: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({ "kind": "result", "task": "t-1", "value": value }))
            .expect("json encodes")
    }

    fn roots_for(format: AttestationFormat, identity: &Identity) -> TrustedRoots {
        let mut roots = TrustedRoots::new();
        roots.pin(format, identity.public_key());
        roots
    }

    /// A well-formed synthetic SGX quote v3 blob: correct version, correct
    /// `total_len`, 64 report-data bytes at the documented offset.
    ///
    /// **Synthetic.** These bytes were assembled in this file; they are not a
    /// real quote and carry no Intel signature. They exercise the parser only.
    ///
    /// Takes `report_data` by reference because a 64-byte array argument is
    /// otherwise easy to mistake for a hex string at the call site.
    fn synthetic_sgx_quote(report_data: &[u8; 64]) -> Vec<u8> {
        let mut v = vec![0u8; SGX_QUOTE_V3_MIN_LEN];
        v[0..2].copy_from_slice(&SGX_QUOTE_V3_VERSION.to_le_bytes());
        v[2..4].copy_from_slice(&2u16.to_le_bytes()); // att_key_type = ECDSA
        v[4..8].copy_from_slice(&(SGX_QUOTE_V3_MIN_LEN as u32).to_le_bytes());
        v[SGX_QUOTE_V3_REPORT_DATA_OFFSET..SGX_QUOTE_V3_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(report_data);
        v
    }

    /// A well-formed synthetic TDX quote. **Synthetic**, as above.
    ///
    /// Uses the same 8-byte header layout as the SGX fixture
    /// ([`TDX_QUOTE_VERSION`] at offset 0, total length at offset 4), because that
    /// is the layout this parser implements for both formats — see the module
    /// documentation's note on header scope.
    fn synthetic_tdx_quote(report_data: &[u8; 64]) -> Vec<u8> {
        let mut v = vec![0u8; TDX_QUOTE_MIN_LEN];
        v[0..2].copy_from_slice(&TDX_QUOTE_VERSION.to_le_bytes());
        v[2..4].copy_from_slice(&2u16.to_le_bytes());
        v[4..8].copy_from_slice(&(TDX_QUOTE_MIN_LEN as u32).to_le_bytes());
        v[TDX_QUOTE_REPORT_DATA_OFFSET..TDX_QUOTE_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(report_data);
        v
    }

    /// A well-formed synthetic SEV-SNP report. **Synthetic**, as above.
    fn synthetic_sev_report(report_data: &[u8; 64]) -> Vec<u8> {
        let mut v = vec![0u8; SEV_SNP_REPORT_LEN];
        v[0..4].copy_from_slice(&2u32.to_le_bytes()); // version
        let offset = SEV_SNP_REPORT_LEN - 64;
        v[offset..offset + 64].copy_from_slice(report_data);
        v
    }

    /// Build a signed envelope around a quote-shaped blob, in one of the two
    /// documented arrangements.
    ///
    /// * `blob_is_payload = false` — the blob's `report_data` field is left
    ///   **empty** and the envelope's `report_data` carries the plain digest of the
    ///   payload. This is the arrangement a real quote carrier uses when it holds a
    ///   quote it did not bind itself.
    /// * `blob_is_payload = true` — the blob's field carries the self-binding digest
    ///   (taken over the blob with its field zeroed; see [`BLOB_BINDING_DOMAIN`]),
    ///   and the envelope carries the same value.
    ///
    /// The binding is computed once and written to both places, so the two cannot
    /// disagree — which is what `ReportDataMismatch` exists to catch.
    fn signed_blob(
        format: AttestationFormat,
        mut blob: Vec<u8>,
        blob_is_payload: bool,
        signed: &Identity,
        nonce: [u8; 32],
        issued_at: u64,
    ) -> AttestationEnvelope {
        let offset = match format {
            AttestationFormat::SgxQuoteV3 => Some(SGX_QUOTE_V3_REPORT_DATA_OFFSET),
            AttestationFormat::TdxQuote => Some(TDX_QUOTE_REPORT_DATA_OFFSET),
            AttestationFormat::SevSnpReport => Some(SEV_SNP_REPORT_LEN - 64),
            AttestationFormat::Opaque => None,
        };
        // Only the self-bound form has the payload's own field in the digest's
        // input, and only there is the field non-empty.
        let self_bound = if blob_is_payload { offset } else { None };
        let binding = payload_binding(&blob, self_bound);

        if blob_is_payload {
            if let Some(offset) = offset {
                let slot = blob
                    .get_mut(offset..offset + 64)
                    .expect("synthetic quote fixture is long enough for its report_data");
                slot[..REPORT_DATA_BINDING_LEN].copy_from_slice(&binding);
            }
        }
        let mut report_data = [0u8; 64];
        report_data[..REPORT_DATA_BINDING_LEN].copy_from_slice(&binding);

        let digest = attestation_digest(format, &binding, &report_data, &nonce, issued_at)
            .expect("statement is canonicalizable");
        AttestationEnvelope {
            format,
            payload: blob,
            report_data,
            signer: signed.public_key(),
            signature: signed.keypair().sign(&digest),
            nonce,
            issued_at,
        }
    }

    // -----------------------------------------------------------------------
    // Happy path (which is still a refusal, and must be)
    // -----------------------------------------------------------------------

    #[test]
    fn a_fully_valid_signed_envelope_is_refused_only_because_no_chain_exists() {
        let id = identity();
        let nonce = [4u8; 32];
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        let verifier = Verifier::new(roots_for(AttestationFormat::Opaque, &id), 300);

        let verdict = verifier.verify(&env, nonce, NOW);
        assert!(
            !verdict.is_verified(),
            "no chain is implemented: {verdict:?}"
        );
        let refusal = verdict.refusal().expect("a refusal carries its reason");
        assert_eq!(
            refusal.reason,
            UnverifiedReason::ChainNotImplemented {
                format: AttestationFormat::Opaque
            }
        );
        // Every check this crate implements passed. That is the honest result.
        assert!(refusal.checks.all_implemented(), "{:?}", refusal.checks);
        assert!(!refusal.checks.hardware_chain);
        assert_eq!(verdict.grade(), EvidenceGrade::Unverified);
        assert!(verdict.into_verified().is_err());
    }

    #[test]
    fn every_format_is_refused_even_with_a_correct_signature_and_binding() {
        for format in [
            AttestationFormat::Opaque,
            AttestationFormat::SevSnpReport,
            AttestationFormat::TdxQuote,
            AttestationFormat::SgxQuoteV3,
        ] {
            let id = identity();
            let nonce = [6u8; 32];
            let env = AttestationEnvelope::new(format, &payload(9), &id, nonce, || NOW, None)
                .expect("envelope builds");
            let verifier = Verifier::new(roots_for(format, &id), 300);
            let verdict = verifier.verify(&env, nonce, NOW);
            // Note: `new` fills `report_data[0..32]` from the payload digest, and
            // for the quote formats the payload is not a quote — so those fail
            // structurally, and `Opaque` falls through to the chain refusal. In
            // both cases the grade must be `Unverified`.
            assert!(!verdict.is_verified(), "{format:?}");
            assert_eq!(verdict.grade(), EvidenceGrade::Unverified, "{format:?}");
            assert!(matches!(
                verdict.reason(),
                Some(
                    UnverifiedReason::ChainNotImplemented { .. }
                        | UnverifiedReason::StructurallyInvalid { .. }
                        | UnverifiedReason::SignerNotTrusted(_)
                )
            ));
        }
    }

    #[test]
    fn quote_envelope_with_a_real_signature_still_refuses_on_the_chain() {
        for format in [AttestationFormat::SgxQuoteV3, AttestationFormat::TdxQuote] {
            let id = identity();
            let nonce = [8u8; 32];
            // Synthetic blob with its report_data field left zeroed, so it can be
            // bound in the self-bound arrangement.
            let blob = match format {
                AttestationFormat::SgxQuoteV3 => synthetic_sgx_quote(&[0u8; 64]),
                _ => synthetic_tdx_quote(&[0u8; 64]),
            };
            // The parser must read the blob's own report_data and its declared
            // total_len before anything is signed.
            let parsed = AttestationEnvelope {
                format,
                payload: blob.clone(),
                report_data: [0u8; 64],
                signer: id.public_key(),
                signature: Signature64::from_bytes([0u8; 64]),
                nonce,
                issued_at: NOW,
            }
            .parse_structural()
            .expect("synthetic blob parses");
            assert_eq!(parsed.report_data, [0u8; 64]);
            assert_eq!(parsed.declared_total_len, Some(blob.len()));

            // The blob is the payload, so the binding uses the self-bound form. The
            // blob itself is left exactly as built — the binding is derived from the
            // zeroed field, so the envelope's `report_data` and the blob's agree
            // without this test having to write anything.
            let env = signed_blob(format, blob.clone(), true, &id, nonce, NOW);

            let verifier = Verifier::new(roots_for(format, &id), 300);
            let verdict = verifier.verify(&env, nonce, NOW);
            let refusal = verdict.refusal().expect("chain is not implemented");
            assert_eq!(
                refusal.reason,
                UnverifiedReason::ChainNotImplemented { format },
                "{format:?} must refuse on the chain, not silently pass"
            );
            assert!(
                refusal.checks.all_implemented(),
                "{format:?}: signature/nonce/freshness/binding all genuinely held: {:?}",
                refusal.checks
            );
            assert_eq!(verdict.grade(), EvidenceGrade::Unverified);
        }
    }

    // -----------------------------------------------------------------------
    // Structural: truncation and oversize, per format
    // -----------------------------------------------------------------------

    #[test]
    fn sgx_quote_truncations_and_oversize_are_typed_errors_naming_both_lengths() {
        let good = synthetic_sgx_quote(&[0u8; 64]);
        assert_eq!(good.len(), SGX_QUOTE_V3_MIN_LEN);

        // One byte short of the minimum.
        let short = &good[..good.len() - 1];
        let mut env = envelope_raw(AttestationFormat::SgxQuoteV3, short.to_vec());
        let failures = env.parse_structural().expect_err("must be refused");
        assert!(
            failures.iter().any(|f| matches!(
                f,
                AttestationError::WrongTotalLen {
                    format: AttestationFormat::SgxQuoteV3,
                    expected,
                    actual,
                } if *expected == SGX_QUOTE_V3_MIN_LEN && *actual == good.len() - 1
            )),
            "expected a length error naming {SGX_QUOTE_V3_MIN_LEN} vs {}: {failures:?}",
            good.len() - 1
        );
        assert!(failures.iter().any(|f| matches!(
            f,
            AttestationError::TotalLenMismatch { declared, actual, .. }
                if *declared == SGX_QUOTE_V3_MIN_LEN && *actual == good.len() - 1
        )));

        // Truncated before the header even ends.
        let truncated = envelope_raw(AttestationFormat::SgxQuoteV3, good[..6].to_vec());
        let failures = truncated.parse_structural().expect_err("must be refused");
        assert!(failures.iter().any(|f| matches!(
            f,
            AttestationError::TruncatedHeader {
                min: 8,
                actual: 6,
                ..
            }
        )));

        // Oversize: append a byte, so `total_len` no longer matches.
        let mut oversized = good.clone();
        oversized.push(0);
        env = envelope_raw(AttestationFormat::SgxQuoteV3, oversized);
        let failures = env.parse_structural().expect_err("must be refused");
        assert!(
            failures.iter().any(|f| matches!(
                f,
                AttestationError::TotalLenMismatch { declared, actual, .. }
                    if *declared == SGX_QUOTE_V3_MIN_LEN && *actual == SGX_QUOTE_V3_MIN_LEN + 1
            )),
            "{failures:?}"
        );

        // Empty.
        let empty = envelope_raw(AttestationFormat::SgxQuoteV3, Vec::new());
        let failures = empty.parse_structural().expect_err("must be refused");
        assert!(failures
            .iter()
            .any(|f| matches!(f, AttestationError::TruncatedHeader { actual: 0, .. })));
    }

    #[test]
    fn tdx_quote_truncations_and_oversize_are_typed_errors_naming_both_lengths() {
        let good = synthetic_tdx_quote(&[0u8; 64]);
        assert_eq!(good.len(), TDX_QUOTE_MIN_LEN);

        let mut env = envelope_raw(AttestationFormat::TdxQuote, good[..good.len() - 1].to_vec());
        let failures = env.parse_structural().expect_err("must be refused");
        assert!(
            failures.iter().any(|f| matches!(
                f,
                AttestationError::WrongTotalLen {
                    format: AttestationFormat::TdxQuote,
                    expected,
                    actual,
                } if *expected == TDX_QUOTE_MIN_LEN && *actual == good.len() - 1
            )),
            "{failures:?}"
        );

        // Cut inside `report_data`: the header still reads, the report data does
        // not fit.
        let cut = envelope_raw(
            AttestationFormat::TdxQuote,
            good[..TDX_QUOTE_REPORT_DATA_OFFSET + 10].to_vec(),
        );
        let failures = cut.parse_structural().expect_err("must be refused");
        assert!(
            failures.iter().any(|f| matches!(
                f,
                AttestationError::ReportDataTruncated {
                    format: AttestationFormat::TdxQuote,
                    offset,
                    expected: 64,
                    available: 10,
                } if *offset == TDX_QUOTE_REPORT_DATA_OFFSET
            )),
            "{failures:?}"
        );

        // Oversize.
        let mut oversized = good.clone();
        oversized.extend_from_slice(&[0u8; 4]);
        env = envelope_raw(AttestationFormat::TdxQuote, oversized);
        let failures = env.parse_structural().expect_err("must be refused");
        assert!(failures
            .iter()
            .any(|f| matches!(f, AttestationError::TotalLenMismatch { .. })));

        // Empty.
        let empty = envelope_raw(AttestationFormat::TdxQuote, Vec::new());
        assert!(empty.parse_structural().is_err());
    }

    #[test]
    fn sev_snp_report_must_be_exactly_1184_bytes() {
        let good = synthetic_sev_report(&[0u8; 64]);
        assert_eq!(good.len(), SEV_SNP_REPORT_LEN);
        let parsed = envelope_raw(AttestationFormat::SevSnpReport, good.clone())
            .parse_structural()
            .expect("a synthetic 1184-byte report parses");
        assert_eq!(parsed.declared_total_len, None, "no length field to read");
        assert_eq!(parsed.report_data, [0u8; 64]);

        for (len, allowed) in [
            (0usize, false),
            (SEV_SNP_REPORT_LEN - 1, false),
            (SEV_SNP_REPORT_LEN, true),
            (SEV_SNP_REPORT_LEN + 1, false),
            (SEV_SNP_REPORT_LEN * 2, false),
        ] {
            let env = envelope_raw(AttestationFormat::SevSnpReport, vec![0u8; len]);
            let result = env.parse_structural();
            assert_eq!(result.is_ok(), allowed, "length {len}");
            if !allowed {
                let failures = result.expect_err("short or long report must be refused");
                assert!(
                    failures.iter().any(|f| matches!(
                        f,
                        AttestationError::WrongTotalLen {
                            format: AttestationFormat::SevSnpReport,
                            expected,
                            actual,
                        } if *expected == SEV_SNP_REPORT_LEN && *actual == len
                    )),
                    "length {len} must be named as expected-vs-actual: {failures:?}"
                );
            }
        }
    }

    #[test]
    fn wrong_quote_versions_are_typed_errors() {
        // SGX version 2 is a real historical version and must not be parsed as v3.
        let mut v2 = synthetic_sgx_quote(&[0u8; 64]);
        v2[0..2].copy_from_slice(&2u16.to_le_bytes());
        let failures = envelope_raw(AttestationFormat::SgxQuoteV3, v2)
            .parse_structural()
            .expect_err("version 2 is not v3");
        assert!(failures.iter().any(|f| matches!(
            f,
            AttestationError::UnsupportedVersion {
                format: AttestationFormat::SgxQuoteV3,
                expected: 3,
                found: 2,
            }
        )));

        // TDX version 5 is not implemented here.
        let mut v5 = synthetic_tdx_quote(&[0u8; 64]);
        v5[0..2].copy_from_slice(&5u16.to_le_bytes());
        let failures = envelope_raw(AttestationFormat::TdxQuote, v5)
            .parse_structural()
            .expect_err("version 5 is not v4");
        assert!(failures.iter().any(|f| matches!(
            f,
            AttestationError::UnsupportedVersion {
                format: AttestationFormat::TdxQuote,
                expected: 4,
                found: 5,
            }
        )));
    }

    #[test]
    fn opaque_format_has_no_structure_and_therefore_no_objection() {
        // "Opaque" means nothing is checkable. The envelope's own report_data is
        // taken as the report_data; the format can never pass `verify`.
        for len in [0usize, 1, 1183, 1184, 9999] {
            let env = envelope_raw(AttestationFormat::Opaque, vec![7u8; len]);
            let parsed = env.parse_structural().expect("opaque always parses");
            assert_eq!(parsed.report_data, [0u8; 64]);
            assert_eq!(parsed.declared_total_len, None);
        }
        assert!(!AttestationFormat::Opaque.chain_implemented());
    }

    // -----------------------------------------------------------------------
    // Signer trust
    // -----------------------------------------------------------------------

    #[test]
    fn an_untrusted_signer_is_rejected_even_with_a_perfect_signature() {
        let id = identity();
        let nonce = [1u8; 32];
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");

        // Nothing pinned at all.
        let empty = Verifier::new(TrustedRoots::new(), 300);
        let refusal = empty
            .verify(&env, nonce, NOW)
            .refusal()
            .cloned()
            .expect("refused");
        assert!(matches!(
            refusal.reason,
            UnverifiedReason::SignerNotTrusted(AttestationError::UntrustedSigner { .. })
        ));
        assert!(!refusal.checks.signature);
        assert!(refusal.checks.structural);

        // A different, genuine key is pinned: still untrusted, and this is the
        // classic impersonation case.
        let stranger = Verifier::new(roots_for(AttestationFormat::Opaque, &other_identity()), 300);
        let refusal = stranger
            .verify(&env, nonce, NOW)
            .refusal()
            .cloned()
            .expect("refused");
        match &refusal.reason {
            UnverifiedReason::SignerNotTrusted(AttestationError::UntrustedSigner {
                format,
                signer,
            }) => {
                assert_eq!(*format, AttestationFormat::Opaque);
                assert_eq!(*signer, id.public_key().to_hex());
            }
            other => panic!("expected a signer refusal, got {other:?}"),
        }

        // A key pinned for a *different* format does not vouch for this one.
        let wrong_format = Verifier::new(roots_for(AttestationFormat::SgxQuoteV3, &id), 300);
        let refusal = wrong_format
            .verify(&env, nonce, NOW)
            .refusal()
            .cloned()
            .expect("refused");
        assert!(matches!(
            refusal.reason,
            UnverifiedReason::SignerNotTrusted(_)
        ));
    }

    #[test]
    fn a_signature_by_the_pinned_key_over_different_bytes_is_rejected() {
        // Valid envelope, then tamper with the signed statement's inputs without
        // re-signing: the signature must fail (not merely the binding).
        let id = identity();
        let nonce = [1u8; 32];
        let mut env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        env.issued_at = NOW + 1; // covered by the signature, so this must break it
        let verifier = Verifier::new(roots_for(AttestationFormat::Opaque, &id), 300);
        let refusal = verifier
            .verify(&env, nonce, NOW)
            .refusal()
            .cloned()
            .expect("refused");
        assert_eq!(
            refusal.reason,
            UnverifiedReason::SignatureInvalid(AttestationError::SignatureMismatch)
        );
        assert!(!refusal.checks.signature);

        // And a signature lifted from another envelope.
        let other = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(2),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        let mut grafted = env.clone();
        grafted.issued_at = NOW;
        grafted.signature = other.signature;
        let refusal = verifier
            .verify(&grafted, nonce, NOW)
            .refusal()
            .cloned()
            .expect("refused");
        assert!(matches!(
            refusal.reason,
            UnverifiedReason::SignatureInvalid(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Nonce / replay
    // -----------------------------------------------------------------------

    #[test]
    fn replaying_a_previously_valid_envelope_with_a_fresh_nonce_is_rejected() {
        // The anti-replay property, tested the way an attacker would use it: the
        // envelope was valid once, so replay it against a verifier that has since
        // chosen a new nonce.
        let id = identity();
        let original_nonce = [1u8; 32];
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            original_nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        let verifier = Verifier::new(roots_for(AttestationFormat::Opaque, &id), 300);

        // It passes every implemented check for the nonce it was made for...
        let fresh = verifier.verify(&env, original_nonce, NOW);
        assert!(fresh.refusal().expect("refused").checks.all_implemented());

        // ...and the same bytes are refused for a fresh nonce, even though they
        // are still structurally fine, correctly signed, and fresh.
        let mut replay_nonce = [0u8; 32];
        replay_nonce[0] = 0xAB;
        let replayed = verifier.verify(&env, replay_nonce, NOW);
        let refusal = replayed.refusal().cloned().expect("refused");
        match &refusal.reason {
            UnverifiedReason::NonceMismatch(AttestationError::NonceMismatch {
                found,
                expected,
            }) => {
                assert_eq!(found, &hex::encode(original_nonce));
                assert_eq!(expected, &hex::encode(replay_nonce));
            }
            other => panic!("expected a nonce refusal, got {other:?}"),
        }
        assert!(refusal.checks.structural && refusal.checks.signature);
        assert!(
            !refusal.checks.nonce,
            "the nonce check is the one that failed"
        );
        assert_eq!(replayed.grade(), EvidenceGrade::Unverified);
    }

    #[test]
    fn a_prover_chosen_nonce_does_not_satisfy_the_verifier() {
        // Same shape, stated as its own claim: an attacker who signs an envelope
        // with a nonce of their own choosing cannot make it answer a verifier.
        let id = identity();
        let attacker_nonce = [0xFFu8; 32];
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            attacker_nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        let verifier = Verifier::new(roots_for(AttestationFormat::Opaque, &id), 300);
        let refusal = verifier
            .verify(&env, [0x01u8; 32], NOW)
            .refusal()
            .cloned()
            .expect("refused");
        assert!(matches!(refusal.reason, UnverifiedReason::NonceMismatch(_)));
        assert_eq!(refusal.grade(), EvidenceGrade::Unverified);
    }

    // -----------------------------------------------------------------------
    // Freshness, both directions, including inside/outside the skew window
    // -----------------------------------------------------------------------

    #[test]
    fn freshness_is_enforced_in_both_directions() {
        let max_age = 300u64;

        // Inside the window in the past.
        assert!(check_freshness(NOW, NOW, max_age).is_ok());
        assert!(check_freshness(NOW - max_age, NOW, max_age).is_ok());
        // One second outside.
        assert!(matches!(
            check_freshness(NOW - max_age - 1, NOW, max_age),
            Err(AttestationError::StaleEnvelope {
                age,
                max_age: m,
                ..
            }) if age == max_age + 1 && m == max_age
        ));

        // Inside the skew window in the future.
        assert!(check_freshness(NOW + MAX_CLOCK_SKEW_SECS, NOW, max_age).is_ok());
        // One second outside the skew constant, in the future.
        assert!(matches!(
            check_freshness(NOW + MAX_CLOCK_SKEW_SECS + 1, NOW, max_age),
            Err(AttestationError::IssuedInFuture { ahead, .. })
                if ahead == MAX_CLOCK_SKEW_SECS + 1
        ));

        // Exactly `now` and far in the future are both decided cases.
        assert!(check_freshness(NOW, NOW, max_age).is_ok());
        assert!(check_freshness(u64::MAX, NOW, max_age).is_err());
        // A clock at 0 with an old envelope must not underflow.
        assert!(check_freshness(0, u64::MAX, max_age).is_err());
    }

    #[test]
    fn verify_uses_the_same_skew_constant_and_reports_staleness_precisely() {
        let id = identity();
        let nonce = [1u8; 32];
        let verifier = Verifier::new(roots_for(AttestationFormat::Opaque, &id), 300);

        // Fresh envelope: refused only by the chain.
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        assert!(matches!(
            verifier.verify(&env, nonce, NOW).reason(),
            Some(UnverifiedReason::ChainNotImplemented { .. })
        ));

        // Stale: 301 seconds later, one past `max_age = 300`.
        let stale = verifier.verify(&env, nonce, NOW + 301);
        match stale.reason() {
            Some(UnverifiedReason::NotFresh(AttestationError::StaleEnvelope {
                issued_at,
                age,
                max_age,
            })) => {
                assert_eq!(*issued_at, NOW);
                assert_eq!(*age, 301);
                assert_eq!(*max_age, 300);
            }
            other => panic!("expected staleness, got {other:?}"),
        }
        // Exactly at the boundary: fresh.
        assert!(matches!(
            verifier.verify(&env, nonce, NOW + 300).reason(),
            Some(UnverifiedReason::ChainNotImplemented { .. })
        ));

        // Future-dated beyond the workspace skew constant.
        let future = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        // `now` far enough before `issued_at` to breach the skew window.
        let verdict = verifier.verify(&future, nonce, NOW - MAX_CLOCK_SKEW_SECS - 1);
        match verdict.reason() {
            Some(UnverifiedReason::NotFresh(AttestationError::IssuedInFuture {
                ahead, ..
            })) => assert_eq!(*ahead, MAX_CLOCK_SKEW_SECS + 1),
            other => panic!("expected a future-dating refusal, got {other:?}"),
        }
        // Inside the skew window: only the chain refuses.
        assert!(matches!(
            verifier
                .verify(&future, nonce, NOW - MAX_CLOCK_SKEW_SECS)
                .reason(),
            Some(UnverifiedReason::ChainNotImplemented { .. })
        ));
    }

    #[test]
    fn the_workspace_skew_constant_is_reused_not_redefined() {
        // If someone adds a second constant, this assertion stops describing the
        // code's behaviour and starts describing a bug.
        assert_eq!(MAX_CLOCK_SKEW_SECS, nau_core::MAX_CLOCK_SKEW_SECS);
        assert_eq!(MAX_CLOCK_SKEW_SECS, 300);
    }

    // -----------------------------------------------------------------------
    // report_data binding: payload swap
    // -----------------------------------------------------------------------

    #[test]
    fn swapping_the_payload_invalidates_the_attestation() {
        let id = identity();
        let nonce = [1u8; 32];
        let verifier = Verifier::new(roots_for(AttestationFormat::Opaque, &id), 300);
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");

        // Baseline: the binding holds, only the chain refuses.
        let baseline = verifier.verify(&env, nonce, NOW);
        assert!(baseline.refusal().expect("refused").checks.report_data);

        // Swap the payload for a different result of the same shape.
        let mut swapped = env.clone();
        swapped.payload = payload(2);
        assert_eq!(
            swapped.payload.len(),
            env.payload.len(),
            "same shape, same length: the digest is the only thing that can catch this"
        );
        let refusal = verifier
            .verify(&swapped, nonce, NOW)
            .refusal()
            .cloned()
            .expect("refused");
        match &refusal.reason {
            UnverifiedReason::ReportDataNotBound(AttestationError::ReportDataBindingMismatch {
                found,
                expected,
            }) => {
                assert_eq!(found, &hex::encode(&env.report_data[..32]));
                assert_eq!(expected, &hex::encode(payload_digest(&swapped.payload)));
                assert_ne!(found, expected);
            }
            other => panic!("expected a binding refusal, got {other:?}"),
        }
        assert!(!refusal.checks.report_data);

        // Same for a completely different payload.
        let mut unrelated = env.clone();
        unrelated.payload =
            serde_json::to_vec(&json!({ "unrelated": true })).expect("json encodes");
        assert!(matches!(
            verifier.verify(&unrelated, nonce, NOW).reason(),
            Some(UnverifiedReason::ReportDataNotBound(_))
        ));
    }

    #[test]
    fn a_non_canonical_payload_is_refused_rather_than_hashed_optimistically() {
        let id = identity();
        let nonce = [1u8; 32];
        let verifier = Verifier::new(roots_for(AttestationFormat::Opaque, &id), 300);
        let mut env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");

        // Whitespace and key order: same JSON value, different bytes. Accepting it
        // would mean two byte strings could claim one digest.
        env.payload = b"{ \"value\": 1, \"kind\": \"result\", \"task\": \"t-1\" }".to_vec();
        env.report_data[..32].copy_from_slice(&sha256_digest(&env.payload));
        assert!(matches!(
            verifier.verify(&env, nonce, NOW).reason(),
            Some(UnverifiedReason::PayloadInvalid(_))
        ));

        // Not JSON at all.
        let mut garbage = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        garbage.payload = b"not json at all".to_vec();
        garbage.report_data[..32].copy_from_slice(&sha256_digest(&garbage.payload));
        assert!(matches!(
            verifier.verify(&garbage, nonce, NOW).reason(),
            Some(UnverifiedReason::PayloadInvalid(_))
        ));

        // Root is an array, not an object.
        let mut array = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        array.payload = b"[1,2,3]".to_vec();
        array.report_data[..32].copy_from_slice(&sha256_digest(&array.payload));
        assert!(matches!(
            verifier.verify(&array, nonce, NOW).reason(),
            Some(UnverifiedReason::PayloadInvalid(_))
        ));
    }

    #[test]
    fn a_blob_whose_report_data_differs_from_the_envelope_is_refused() {
        // Guards the "sign one value, present another" substitution: a blob whose
        // report_data is neither the envelope's value nor a valid self-binding is
        // refused, rather than the envelope's field being taken on faith.
        let id = identity();
        let nonce = [1u8; 32];
        // Empty-field arrangement: the quote was assembled without an embedded
        // binding, and the envelope's `report_data` commits to the payload on its
        // own — which is what an honest carrier does when it holds a quote it did
        // not bind itself.
        let blob = synthetic_sgx_quote(&[0u8; 64]);
        let env = signed_blob(AttestationFormat::SgxQuoteV3, blob, false, &id, nonce, NOW);
        assert_eq!(
            &env.payload[SGX_QUOTE_V3_REPORT_DATA_OFFSET..SGX_QUOTE_V3_REPORT_DATA_OFFSET + 64],
            &[0u8; 64],
            "the quote's own field is left empty"
        );
        assert_eq!(
            env.report_data[..REPORT_DATA_BINDING_LEN],
            sha256_digest(&env.payload)[..],
            "the envelope commits to the payload it carries"
        );
        let verifier = Verifier::new(roots_for(AttestationFormat::SgxQuoteV3, &id), 300);
        // Baseline: the envelope and its blob agree, so only the chain refuses.
        let baseline = verifier.verify(&env, nonce, NOW);
        assert_eq!(
            baseline.reason(),
            Some(&UnverifiedReason::ChainNotImplemented {
                format: AttestationFormat::SgxQuoteV3
            }),
            "baseline must be the chain refusal, not {baseline:?}"
        );

        // Now change the envelope's report_data field only. The envelope no longer
        // commits to its payload, and the blob's own field still disagrees, so the
        // envelope is refused rather than either value being taken on faith. Which
        // of the two typed errors comes first is an implementation detail; that a
        // typed error comes *at all* is the property under test.
        let mut lying = env.clone();
        lying.report_data = [9u8; 64];
        let verdict = verifier.verify(&lying, nonce, NOW);
        assert!(
            matches!(
                verdict.reason(),
                Some(UnverifiedReason::ReportDataNotBound(_))
                    | Some(UnverifiedReason::StructurallyInvalid { .. })
            ),
            "expected a binding or blob-consistency refusal, got {verdict:?}"
        );
        assert!(!verdict.is_verified());
        assert_eq!(verdict.grade(), EvidenceGrade::Unverified);
    }

    #[test]
    fn a_self_bound_blob_whose_field_disagrees_with_the_envelope_is_refused() {
        // Both halves of the consistency rule, isolated. Here the envelope's
        // `report_data` is a perfectly valid self-binding digest, so the binding
        // check passes and the *blob's* field is what exposes the substitution: it
        // carries a third value, so the quote was assembled for a different
        // commitment.
        let id = identity();
        let nonce = [3u8; 32];
        let offset = SGX_QUOTE_V3_REPORT_DATA_OFFSET;
        let blob = synthetic_sgx_quote(&[0u8; 64]);
        let env = signed_blob(AttestationFormat::SgxQuoteV3, blob, true, &id, nonce, NOW);
        let verifier = Verifier::new(roots_for(AttestationFormat::SgxQuoteV3, &id), 300);
        assert_eq!(
            verifier.verify(&env, nonce, NOW).reason(),
            Some(&UnverifiedReason::ChainNotImplemented {
                format: AttestationFormat::SgxQuoteV3
            }),
            "the honest envelope gets as far as the chain refusal"
        );

        let mut swapped = env.clone();
        swapped.payload[offset..offset + 32].copy_from_slice(&[0xEEu8; 32]);
        match verifier.verify(&swapped, nonce, NOW).reason() {
            Some(UnverifiedReason::StructurallyInvalid { failures }) => {
                assert!(matches!(
                    failures.as_slice(),
                    [AttestationError::ReportDataMismatch { .. }]
                ));
            }
            other => panic!("expected a blob/envelope report_data mismatch, got {other:?}"),
        }
    }

    #[test]
    fn the_documented_quote_offsets_are_self_consistent() {
        // The declared numbers are pinned at compile time by the `const _: ()`
        // block beside their definitions, so a drift is a build failure. This test
        // adds the two claims a const block cannot make on its own: that the
        // formats are distinguishable, and that each field fits inside its blob.
        //
        // The offsets themselves are checked *behaviourally* — the parser must
        // return the bytes that are actually at that position — by
        // `the_parser_reads_report_data_from_the_documented_offset` below, which is
        // the check that cannot be satisfied by a self-consistent mistake.
        let sgx = SGX_QUOTE_V3_REPORT_DATA_OFFSET;
        let tdx = TDX_QUOTE_REPORT_DATA_OFFSET;
        // A TDX quote body is longer than an SGX report body, so one blob cannot be
        // both, and the offsets must not have collapsed onto each other.
        assert_ne!(sgx, tdx);
        assert_ne!(SGX_QUOTE_V3_MIN_LEN, TDX_QUOTE_MIN_LEN);
        // The 64-byte report_data field must fit inside the minimum blob for each.
        assert!(sgx + 64 <= SGX_QUOTE_V3_MIN_LEN);
        assert!(tdx + 64 <= TDX_QUOTE_MIN_LEN);
        // SEV-SNP is exact-length with no offset field: the parser reads its 64
        // report-data bytes from the end of the fixed-size structure.
        let sev_len = SEV_SNP_REPORT_LEN;
        assert!(sev_len >= 64 && sev_len - 64 < sev_len);
    }

    #[test]
    fn the_parser_reads_report_data_from_the_documented_offset() {
        // Behavioural version of the offset claim: mark the documented window and
        // only that window, and check the parser returns it byte for byte while a
        // byte immediately outside it changes nothing.
        let wanted = [0x5Au8; 64];
        let blob = synthetic_sgx_quote(&wanted);
        let parsed = envelope_raw(AttestationFormat::SgxQuoteV3, blob.clone())
            .parse_structural()
            .expect("synthetic quote parses");
        assert_eq!(parsed.report_data, wanted);
        assert_eq!(
            parsed.report_data_offset,
            Some(SGX_QUOTE_V3_REPORT_DATA_OFFSET)
        );

        let mut outside = blob.clone();
        outside[SGX_QUOTE_V3_REPORT_DATA_OFFSET - 1] = 0xFF;
        outside[SGX_QUOTE_V3_REPORT_DATA_OFFSET + 64] = 0xFF;
        let parsed_outside = envelope_raw(AttestationFormat::SgxQuoteV3, outside)
            .parse_structural()
            .expect("still parses");
        assert_eq!(
            parsed_outside.report_data, wanted,
            "only the documented window is read"
        );

        // The same for TDX, at its own offset.
        let parsed_tdx = envelope_raw(AttestationFormat::TdxQuote, synthetic_tdx_quote(&wanted))
            .parse_structural()
            .expect("synthetic TDX quote parses");
        assert_eq!(parsed_tdx.report_data, wanted);
        assert_eq!(
            parsed_tdx.report_data_offset,
            Some(TDX_QUOTE_REPORT_DATA_OFFSET)
        );

        // And SEV-SNP: the last 64 bytes of the fixed-size structure.
        let parsed_sev = envelope_raw(
            AttestationFormat::SevSnpReport,
            synthetic_sev_report(&wanted),
        )
        .parse_structural()
        .expect("synthetic SEV-SNP report parses");
        assert_eq!(parsed_sev.report_data, wanted);
        assert_eq!(parsed_sev.report_data_offset, Some(SEV_SNP_REPORT_LEN - 64));
    }

    #[test]
    fn a_blob_may_bind_itself_only_in_the_one_checked_form() {
        // The payload *is* the blob here, so the blob carries the self-binding
        // digest. The verifier recomputes it — it is not trusted just because it is
        // present.
        let id = identity();
        let nonce = [2u8; 32];
        let offset = SGX_QUOTE_V3_REPORT_DATA_OFFSET;
        let blob = synthetic_sgx_quote(&[0xAAu8; 64]);
        let env = signed_blob(AttestationFormat::SgxQuoteV3, blob, true, &id, nonce, NOW);
        assert_eq!(
            env.report_data[..REPORT_DATA_BINDING_LEN],
            blob_binding_digest(&env.payload, offset)[..]
        );
        let verifier = Verifier::new(roots_for(AttestationFormat::SgxQuoteV3, &id), 300);
        let refusal = verifier
            .verify(&env, nonce, NOW)
            .refusal()
            .cloned()
            .expect("chain still not implemented");
        assert_eq!(
            refusal.reason,
            UnverifiedReason::ChainNotImplemented {
                format: AttestationFormat::SgxQuoteV3
            },
            "everything else agrees, so the chain is the only objection"
        );
        assert!(refusal.checks.all_implemented());

        // Corrupt the blob's embedded report_data to an arbitrary value: neither
        // the plain digest nor the self-binding digest, so the binding is refused.
        // (The signature covers the old blob, so it fails too; the binding check is
        // what runs first.)
        let mut forged = env.clone();
        forged.payload[offset..offset + 32].copy_from_slice(&[0x55u8; 32]);
        let verdict = verifier.verify(&forged, nonce, NOW);
        assert!(
            matches!(
                verdict.reason(),
                Some(UnverifiedReason::ReportDataNotBound(_))
                    | Some(UnverifiedReason::StructurallyInvalid { .. })
                    | Some(UnverifiedReason::SignatureInvalid(_))
            ),
            "a blob whose report_data is neither form must be refused, got {verdict:?}"
        );
        assert!(!verdict.is_verified());

        // A self-binding digest lifted from a *different* blob is refused too: the
        // digest is recomputed from the payload, never trusted.
        let elsewhere = blob_binding_digest(b"a different blob entirely", offset);
        let mut cross = env.clone();
        cross.report_data[..32].copy_from_slice(&elsewhere);
        assert!(matches!(
            verifier.verify(&cross, nonce, NOW).reason(),
            Some(UnverifiedReason::ReportDataNotBound(_))
        ));
    }

    #[test]
    fn the_self_binding_form_differs_from_the_plain_digest_and_is_deterministic() {
        // The self-binding form must not be a plain SHA-256 a producer could have
        // chosen for a different payload, and it must not cover the field it lives
        // in (that field is covered by the signature instead).
        let offset = SGX_QUOTE_V3_REPORT_DATA_OFFSET;
        let blob = synthetic_sgx_quote(&[0u8; 64]);
        assert_ne!(blob_binding_digest(&blob, offset), payload_digest(&blob));
        assert_eq!(
            blob_binding_digest(&blob, offset),
            blob_binding_digest(&blob, offset),
            "deterministic"
        );

        // Any change outside the bound field moves it...
        let mut changed = blob.clone();
        changed[offset + 40] ^= 0x01;
        assert_ne!(
            blob_binding_digest(&blob, offset),
            blob_binding_digest(&changed, offset)
        );
        // ...while the bound field itself is exactly what the digest leaves out,
        // because it is the value being computed.
        let mut rebound = blob.clone();
        rebound[offset..offset + 32].copy_from_slice(&[0x77u8; 32]);
        assert_eq!(
            blob_binding_digest(&blob, offset),
            blob_binding_digest(&rebound, offset),
            "the self-binding digest excludes the field it populates; the signature \
             over the payload is what covers that field"
        );
        // The other 32 bytes of report_data are *not* zeroed and are covered.
        let mut tail_changed = blob.clone();
        tail_changed[offset + 32] ^= 0xFF;
        assert_ne!(
            blob_binding_digest(&blob, offset),
            blob_binding_digest(&tail_changed, offset)
        );
    }

    // -----------------------------------------------------------------------
    // Constructor errors
    // -----------------------------------------------------------------------

    #[test]
    fn the_constructor_refuses_payloads_that_cannot_be_canonicalized() {
        let id = identity();
        let nonce = [0u8; 32];

        // Not an object at the root.
        let err = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            b"[1,2,3]",
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect_err("arrays have no canonical signing form");
        assert_eq!(err, AttestationError::PayloadNotObject { found: "array" });

        // A float, which canonical JSON refuses so that 100 and 100.0 cannot
        // diverge between languages.
        let err = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            br#"{"amount":100.0}"#,
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect_err("floats are not canonicalizable");
        assert!(matches!(err, AttestationError::PayloadNotCanonical(_)));

        // Not UTF-8.
        let err = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &[0xFF, 0xFE, 0xFD],
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect_err("non-UTF-8 is not JSON");
        assert!(matches!(err, AttestationError::PayloadNotCanonical(_)));

        // Oversize.
        let mut huge = Vec::from(&b"{\"k\":\""[..]);
        huge.resize(MAX_PAYLOAD_LEN + 1, b'x');
        let err =
            AttestationEnvelope::new(AttestationFormat::Opaque, &huge, &id, nonce, || NOW, None)
                .expect_err("oversize payloads are refused before hashing");
        assert_eq!(
            err,
            AttestationError::PayloadTooLarge {
                max: MAX_PAYLOAD_LEN,
                actual: MAX_PAYLOAD_LEN + 1,
            }
        );
    }

    #[test]
    fn the_constructor_stores_the_canonical_bytes_and_binds_them() {
        // The producer's serializer must not be able to smuggle in a different
        // byte spelling of the same value.
        let id = identity();
        let nonce = [1u8; 32];
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            br#"{ "z": 1, "a": [ 2, 3 ] }"#,
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");
        assert_eq!(env.payload, br#"{"a":[2,3],"z":1}"#);
        assert_eq!(env.report_data[..32], env.payload_hash()[..]);
        assert_eq!(env.report_data[32..], [0u8; 32]);
        assert_eq!(env.nonce, nonce);
        assert_eq!(env.issued_at, NOW);
        assert_eq!(env.signer, id.public_key());

        // A caller-supplied report_data tail is preserved verbatim.
        let tail = [0x5Au8; 32];
        let with_tail = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            Some(tail),
        )
        .expect("envelope builds");
        assert_eq!(with_tail.report_data[32..], tail);
    }

    #[test]
    fn carries_unverified_quote_bytes_flags_what_it_says() {
        let id = identity();
        let opaque = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            [0u8; 32],
            || NOW,
            None,
        )
        .expect("envelope builds");
        assert!(!opaque.carries_unverified_quote_bytes());

        let quote = AttestationEnvelope::new(
            AttestationFormat::SgxQuoteV3,
            &payload(1),
            &id,
            [0u8; 32],
            || NOW,
            None,
        )
        .expect("envelope builds");
        assert!(quote.carries_unverified_quote_bytes());
    }

    // -----------------------------------------------------------------------
    // Verifier configuration and small helpers
    // -----------------------------------------------------------------------

    #[test]
    fn a_zero_max_age_is_a_configuration_error_not_a_silent_deny_all() {
        assert!(Verifier::try_new(TrustedRoots::new(), 0).is_err());
        assert!(Verifier::try_new(TrustedRoots::new(), 1).is_ok());
        let verifier = Verifier::new(TrustedRoots::new(), 60);
        assert_eq!(verifier.max_age_secs(), 60);
        assert!(verifier.roots().is_empty());
    }

    #[test]
    #[should_panic(expected = "max_age_secs must be positive")]
    fn new_rejects_a_zero_max_age_loudly() {
        let _ = Verifier::new(TrustedRoots::new(), 0);
    }

    #[test]
    fn trusted_roots_are_per_format_and_do_not_duplicate() {
        let id = identity();
        let mut roots = TrustedRoots::new();
        assert!(roots.is_empty());
        roots.pin(AttestationFormat::Opaque, id.public_key());
        roots.pin(AttestationFormat::Opaque, id.public_key()); // idempotent
        roots.pin(AttestationFormat::TdxQuote, other_identity().public_key());

        assert_eq!(roots.len(), 2);
        assert_eq!(roots.len_for(AttestationFormat::Opaque), 1);
        assert_eq!(roots.len_for(AttestationFormat::SgxQuoteV3), 0);
        assert!(roots.is_trusted(AttestationFormat::Opaque, &id.public_key()));
        assert!(!roots.is_trusted(AttestationFormat::TdxQuote, &id.public_key()));
        let formats: Vec<_> = roots.formats().collect();
        assert_eq!(
            formats,
            vec![AttestationFormat::Opaque, AttestationFormat::TdxQuote]
        );
    }

    #[test]
    fn formats_round_trip_through_serde_with_stable_names() {
        for (format, name) in [
            (AttestationFormat::Opaque, "opaque"),
            (AttestationFormat::SevSnpReport, "sev_snp_report"),
            (AttestationFormat::TdxQuote, "tdx_quote"),
            (AttestationFormat::SgxQuoteV3, "sgx_quote_v3"),
        ] {
            assert_eq!(format.wire_name(), name);
            let encoded = serde_json::to_value(format).expect("serializes");
            assert_eq!(encoded, json!(name));
            let decoded: AttestationFormat = serde_json::from_value(encoded).expect("deserializes");
            assert_eq!(decoded, format);
            assert!(!format.chain_implemented());
        }
        assert_eq!(AttestationFormat::SevSnpReport.min_quote_len(), Some(1184));
        assert_eq!(AttestationFormat::Opaque.min_quote_len(), None);
    }

    #[test]
    fn the_attestation_digest_is_deterministic_and_covers_every_field() {
        let base = attestation_digest(
            AttestationFormat::Opaque,
            &[1u8; 32],
            &[2u8; 64],
            &[3u8; 32],
            NOW,
        )
        .expect("digest builds");
        assert_eq!(
            base,
            attestation_digest(
                AttestationFormat::Opaque,
                &[1u8; 32],
                &[2u8; 64],
                &[3u8; 32],
                NOW
            )
            .expect("digest builds")
        );

        // Every argument is covered: change one at a time and the digest moves.
        let changes = [
            attestation_digest(
                AttestationFormat::TdxQuote,
                &[1u8; 32],
                &[2u8; 64],
                &[3u8; 32],
                NOW,
            ),
            attestation_digest(
                AttestationFormat::Opaque,
                &[9u8; 32],
                &[2u8; 64],
                &[3u8; 32],
                NOW,
            ),
            attestation_digest(
                AttestationFormat::Opaque,
                &[1u8; 32],
                &[9u8; 64],
                &[3u8; 32],
                NOW,
            ),
            attestation_digest(
                AttestationFormat::Opaque,
                &[1u8; 32],
                &[2u8; 64],
                &[9u8; 32],
                NOW,
            ),
            attestation_digest(
                AttestationFormat::Opaque,
                &[1u8; 32],
                &[2u8; 64],
                &[3u8; 32],
                NOW + 1,
            ),
        ];
        for (i, changed) in changes.iter().enumerate() {
            let changed = changed.as_ref().expect("digest builds");
            assert_ne!(&base, changed, "argument {i} is not covered by the digest");
        }
    }

    #[test]
    fn verdict_helpers_behave_as_documented() {
        let id = identity();
        let nonce = [1u8; 32];
        let verifier = Verifier::new(roots_for(AttestationFormat::Opaque, &id), 300);
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            nonce,
            || NOW,
            None,
        )
        .expect("envelope builds");

        let verdict = verifier.verify(&env, nonce, NOW);
        assert!(!verdict.is_verified());
        assert!(verdict.refusal().is_some());
        assert_eq!(verdict.grade(), EvidenceGrade::Unverified);
        let mapped = verdict.clone().map(|s| s.issued_at);
        assert_eq!(mapped.grade(), EvidenceGrade::Unverified);
        assert!(mapped.refusal().is_some());
        assert_eq!(
            verdict.refusal().expect("refused").failures(),
            &[],
            "a chain refusal is not a structural failure"
        );

        // A structural refusal exposes its full failure list.
        let broken = envelope_raw(AttestationFormat::SevSnpReport, vec![0u8; 10]);
        let verdict = verifier.verify(&broken, nonce, NOW);
        let refusal = verdict.refusal().expect("refused");
        assert!(!refusal.failures().is_empty());
        assert_eq!(refusal.grade(), EvidenceGrade::Unverified);
        assert!(!refusal.checks.structural);
    }

    #[test]
    fn structural_failures_are_reported_all_at_once() {
        // A blob that is both the wrong version and the wrong length should say
        // so once, not require two round trips to discover.
        let mut blob = synthetic_sgx_quote(&[0u8; 64]);
        blob[0..2].copy_from_slice(&2u16.to_le_bytes());
        blob.truncate(SGX_QUOTE_V3_MIN_LEN - 8);
        let failures = envelope_raw(AttestationFormat::SgxQuoteV3, blob)
            .parse_structural()
            .expect_err("two problems");
        assert!(
            failures.len() >= 2,
            "expected several failures: {failures:?}"
        );
        let text = UnverifiedReason::StructurallyInvalid {
            failures: failures.clone(),
        }
        .to_string();
        assert!(text.contains("version"), "{text}");
        assert!(text.contains("wrong blob length"), "{text}");
    }

    #[test]
    fn an_envelope_round_trips_through_serde() {
        let id = identity();
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(1),
            &id,
            [7u8; 32],
            || NOW,
            Some([8u8; 32]),
        )
        .expect("envelope builds");
        let json = serde_json::to_string(&env).expect("serializes");
        let back: AttestationEnvelope = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, env);

        // `payload` is bytes, so it must survive as bytes, not as a re-encoded
        // string.
        assert_eq!(back.payload, env.payload);
        assert_eq!(back.report_data, env.report_data);
        assert_eq!(back.nonce, env.nonce);
    }

    #[test]
    fn signed_attestation_reports_its_own_limitations() {
        let id = identity();
        let signed = SignedAttestation {
            format: AttestationFormat::SgxQuoteV3,
            payload_digest: [1u8; 32],
            report_data: [2u8; 64],
            nonce: [3u8; 32],
            issued_at: NOW,
            signer: id.public_key(),
            checks: ChecksPerformed {
                structural: true,
                signature: true,
                nonce: true,
                freshness: true,
                report_data: true,
                hardware_chain: false,
            },
            payload: &[],
        };
        assert_eq!(signed.grade(), EvidenceGrade::SignatureVerified);
        assert!(!signed.hardware_attested());
        assert!(!signed.checks().hardware_chain);
        assert!(signed.checks().all_implemented());
        assert!(signed.payload().is_empty());
        assert_eq!(signed.format, AttestationFormat::SgxQuoteV3);
    }

    #[test]
    fn a_refusal_with_no_failures_still_renders_readable_text() {
        // `summarise` on an empty list must not produce an empty message.
        let text = UnverifiedReason::StructurallyInvalid { failures: vec![] }.to_string();
        assert!(text.contains("no failures recorded"), "{text}");
    }

    /// An envelope with raw bytes and no meaningful signature. Used for the
    /// structural tests, which must not depend on signing at all.
    fn envelope_raw(format: AttestationFormat, payload: Vec<u8>) -> AttestationEnvelope {
        AttestationEnvelope {
            format,
            payload,
            report_data: [0u8; 64],
            signer: identity().public_key(),
            signature: Signature64::from_bytes([0u8; 64]),
            nonce: [0u8; 32],
            issued_at: NOW,
        }
    }
}
