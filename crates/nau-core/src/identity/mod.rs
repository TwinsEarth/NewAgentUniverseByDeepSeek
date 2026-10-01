//! Identity: Ed25519 key material, `did:nau:` derivation, and canonical signing.
//!
//! ## DID derivation
//!
//! ```text
//! did:nau:<first 8 bytes of SHA-256(raw 32-byte Ed25519 public key), lowercase hex>
//! ```
//!
//! That is 16 hex characters, the same construction upstream v2.5.6 uses with
//! the prefix `did:aip:` (`gsn-core/src/identity/did.rs`,
//! `aip-sdk-py/aip/crypto.py:41-44`). [`DID_PREFIX_LEGACY`] is accepted on
//! **parse** so that identities minted by upstream can still be read after
//! migration, but the system only ever mints `did:nau:`.
//!
//! The DID is a *fingerprint*, and SHA-256 is not invertible, so a DID alone can
//! never verify a signature: the verifier needs the public key, transported
//! separately, and must check that the key actually hashes to the DID. That
//! binding check is [`Did::matches_public_key`], and
//! [`verify_payload_bound`] performs it as part of verification. Upstream checks
//! the DID by convention only.

pub mod canonical;

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::{NauError, Result};

pub use canonical::{
    canonical_object, canonical_payload, canonical_payload_string, canonical_string,
    payload_digest_hex, CanonicalError, SIGNATURE_FIELD,
};

/// Prefix minted for new identities.
pub const DID_PREFIX: &str = "did:nau:";
/// Prefix minted by upstream `agent-universe`; accepted when parsing.
pub const DID_PREFIX_LEGACY: &str = "did:aip:";

/// Number of SHA-256 bytes retained for the DID fingerprint.
const DID_FINGERPRINT_BYTES: usize = 8;

/// A raw Ed25519 public key (32 bytes), serialized as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse from 64 hex characters. Rejects wrong length and bad hex, and
    /// rejects byte strings that are not valid, non-degenerate Ed25519 points.
    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s).map_err(|e| NauError::InvalidPublicKey(e.to_string()))?;
        let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            NauError::InvalidPublicKey(format!("expected 32 bytes, got {}", raw.len()))
        })?;
        // Reject non-canonical / off-curve encodings up front so that a malformed
        // key fails at parse time rather than at verification time.
        let vk = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| NauError::InvalidPublicKey(e.to_string()))?;
        // Hardening beyond upstream: a small-order ("weak") key — most notably the
        // all-zero encoding of the identity point — makes signatures forgeable for
        // certain messages. Refuse such keys instead of accepting them.
        if vk.is_weak() {
            return Err(NauError::InvalidPublicKey(
                "public key is a small-order (weak) point and is not usable".into(),
            ));
        }
        Ok(Self(bytes))
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Verify a detached Ed25519 signature over `message`.
    ///
    /// Returns a `Result` rather than a `bool`, so a caller cannot accidentally
    /// ignore a failed check by dropping a boolean.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.0)
            .map_err(|e| NauError::InvalidPublicKey(e.to_string()))?;
        let sig = Signature::from_bytes(signature);
        vk.verify(message, &sig)
            .map_err(|_| NauError::InvalidSignature)
    }

    /// The DID this key fingerprints, with the current prefix.
    pub fn did(&self) -> Did {
        Did::from_public_key(self)
    }

    /// The upstream-compatible DID (`did:aip:`) for this key, for migration.
    pub fn legacy_did(&self) -> Did {
        Did::from_public_key_with_prefix(self, DID_PREFIX_LEGACY)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PublicKey::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A 64-byte Ed25519 signature, serialized as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature64([u8; 64]);

impl Signature64 {
    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Parse 128 hex characters.
    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s).map_err(|e| NauError::InvalidSignatureEncoding(e.to_string()))?;
        let bytes: [u8; 64] = raw.as_slice().try_into().map_err(|_| {
            NauError::InvalidSignatureEncoding(format!("expected 64 bytes, got {}", raw.len()))
        })?;
        Ok(Self(bytes))
    }

    /// The raw 64 bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Lowercase hex encoding (128 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Signature64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Signatures are public data, but truncate for readable logs.
        let hex = self.to_hex();
        write!(f, "Signature64({}…)", &hex[..16])
    }
}

impl fmt::Display for Signature64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Signature64 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Signature64::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A decentralized identifier, e.g. `did:nau:34750f98bd59fcfc`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// Derive a `did:nau:` identifier from a public key.
    pub fn from_public_key(pk: &PublicKey) -> Self {
        Self::from_public_key_with_prefix(pk, DID_PREFIX)
    }

    /// Derive an identifier with an explicit method prefix.
    pub fn from_public_key_with_prefix(pk: &PublicKey, prefix: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pk.as_bytes());
        let digest = hasher.finalize();
        let fingerprint = hex::encode(&digest[..DID_FINGERPRINT_BYTES]);
        Self(format!("{prefix}{fingerprint}"))
    }

    /// Parse and validate a DID string.
    ///
    /// Accepts both [`DID_PREFIX`] and [`DID_PREFIX_LEGACY`]. Rejects anything
    /// whose fingerprint is not exactly 16 lowercase hex characters, so that a
    /// typo cannot silently become a distinct identity.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix(DID_PREFIX)
            .or_else(|| s.strip_prefix(DID_PREFIX_LEGACY))
            .ok_or_else(|| NauError::InvalidDid(s.to_string()))?;
        if rest.len() != DID_FINGERPRINT_BYTES * 2
            || !rest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(NauError::InvalidDid(s.to_string()));
        }
        Ok(Self(s.to_string()))
    }

    /// Build a DID from an already-validated fingerprint and a prefix.
    pub fn from_fingerprint_hex(prefix: &str, fingerprint_hex: &str) -> Result<Self> {
        Self::parse(&format!("{prefix}{fingerprint_hex}"))
    }

    /// The DID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The method prefix (`did:nau:` or `did:aip:`).
    pub fn prefix(&self) -> &str {
        if self.0.starts_with(DID_PREFIX_LEGACY) {
            DID_PREFIX_LEGACY
        } else {
            DID_PREFIX
        }
    }

    /// The 16-character fingerprint.
    pub fn fingerprint(&self) -> &str {
        self.0
            .strip_prefix(DID_PREFIX)
            .or_else(|| self.0.strip_prefix(DID_PREFIX_LEGACY))
            .unwrap_or(&self.0)
    }

    /// True when this DID is the fingerprint of `pk`.
    ///
    /// This is the binding check that makes "verify with this DID" meaningful.
    pub fn matches_public_key(&self, pk: &PublicKey) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(pk.as_bytes());
        let digest = hasher.finalize();
        let expected = hex::encode(&digest[..DID_FINGERPRINT_BYTES]);
        // Fingerprint comparison only; prefix is intentionally irrelevant here so
        // that a migrated `did:aip:` identity still binds to its key.
        self.fingerprint() == expected
    }
}

impl fmt::Debug for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Did({})", self.0)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Did {
    type Err = NauError;
    fn from_str(s: &str) -> Result<Self> {
        Did::parse(s)
    }
}

/// An Ed25519 keypair.
///
/// `SigningKey` zeroizes on drop, so the secret is not left in freed memory.
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Generate a keypair from OS entropy.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Deterministically derive a keypair from a 32-byte seed.
    ///
    /// This is the constructor the cross-language conformance vectors use.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Derive a keypair from a 64-character hex seed.
    pub fn from_seed_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s).map_err(|e| NauError::InvalidPublicKey(e.to_string()))?;
        let seed: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| NauError::Validation("seed must be exactly 32 bytes".into()))?;
        Ok(Self::from_seed(&seed))
    }

    /// The 32-byte secret seed. Handle with care; needed for persistence.
    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// The 64-character hex secret seed.
    pub fn seed_hex(&self) -> String {
        hex::encode(self.seed())
    }

    /// The public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing.verifying_key().to_bytes())
    }

    /// The self-certifying DID for this keypair.
    pub fn did(&self) -> Did {
        self.public_key().did()
    }

    /// Sign raw bytes, returning a detached signature.
    ///
    /// Ed25519 (RFC 8032) is deterministic: the same key and message always
    /// produce the same 64 bytes, which is what makes byte-identical
    /// cross-language signatures possible.
    pub fn sign(&self, message: &[u8]) -> Signature64 {
        Signature64(self.signing.sign(message).to_bytes())
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret.
        write!(f, "Keypair({})", self.did())
    }
}

/// A keypair together with the signing helpers built on canonical payloads.
pub struct Identity {
    keypair: Keypair,
}

impl Identity {
    /// Wrap an existing keypair.
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Generate a fresh identity.
    pub fn generate() -> Self {
        Self::new(Keypair::generate())
    }

    /// Deterministic identity from a seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::new(Keypair::from_seed(seed))
    }

    /// The DID.
    pub fn did(&self) -> Did {
        self.keypair.did()
    }

    /// The public key.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Borrow the keypair.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Sign the canonical payload of `obj`, returning hex.
    pub fn sign_payload<T: Serialize>(&self, obj: &T) -> Result<String> {
        let payload = canonical_payload(obj)?;
        Ok(self.keypair.sign(&payload).to_hex())
    }

    /// Verify a hex signature over the canonical payload of `obj`.
    ///
    /// `obj` must still contain its `signature` field; canonicalization removes
    /// it. The DID↔key binding is checked too.
    pub fn verify_payload<T: Serialize>(&self, obj: &T, signature_hex: &str) -> Result<()> {
        verify_payload_bound(obj, signature_hex, &self.public_key(), &self.did())
    }

    /// Sign raw bytes (no canonicalization), returning hex.
    pub fn sign_raw(&self, message: &[u8]) -> String {
        self.keypair.sign(message).to_hex()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.did())
    }
}

/// Verify a hex signature over the canonical payload of `obj` using `pk`.
pub fn verify_payload<T: Serialize>(obj: &T, signature_hex: &str, pk: &PublicKey) -> Result<()> {
    if signature_hex.is_empty() {
        return Err(NauError::InvalidSignature);
    }
    let sig = Signature64::from_hex(signature_hex)?;
    let payload = canonical_payload(obj)?;
    pk.verify(&payload, sig.as_bytes())
}

/// Verify a signature **and** that `did` is the fingerprint of `pk`.
///
/// This is the check that should be used when an identity arrives from the
/// network: verifying against an attacker-supplied key while trusting a
/// different DID is the classic impersonation bug.
pub fn verify_payload_bound<T: Serialize>(
    obj: &T,
    signature_hex: &str,
    pk: &PublicKey,
    did: &Did,
) -> Result<()> {
    if !did.matches_public_key(pk) {
        return Err(NauError::DidKeyMismatch {
            did: did.to_string(),
        });
    }
    verify_payload(obj, signature_hex, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The fixed seed used by every conformance vector in every language.
    const CONFORMANCE_SEED: [u8; 32] = [1u8; 32];

    #[test]
    fn did_derivation_matches_upstream_v2_5_6() {
        // These exact values are asserted by upstream's own
        // gsn-core/tests/cross_lang_signature.rs, so reproducing them proves the
        // DID construction survived the rewrite.
        let kp = Keypair::from_seed(&CONFORMANCE_SEED);
        assert_eq!(
            kp.public_key().to_hex(),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        assert_eq!(kp.did().as_str(), "did:nau:34750f98bd59fcfc");
        assert_eq!(
            kp.public_key().legacy_did().as_str(),
            "did:aip:34750f98bd59fcfc"
        );
    }

    #[test]
    fn upstream_identity_verifies_after_migration() {
        // A DID minted by upstream must still bind to its key.
        let kp = Keypair::from_seed(&CONFORMANCE_SEED);
        let legacy = Did::parse("did:aip:34750f98bd59fcfc").expect("legacy DID parses");
        assert!(legacy.matches_public_key(&kp.public_key()));
        assert_eq!(legacy.to_string(), "did:aip:34750f98bd59fcfc");
    }

    #[test]
    fn signatures_are_deterministic_and_round_trip() {
        let id = Identity::from_seed(&CONFORMANCE_SEED);
        let card = json!({
            "did": id.did().as_str(),
            "name": "CrossLang",
            "capabilities": ["text-generation", "mcp"],
            "stake": 100,
            "signature": ""
        });
        let sig1 = id.sign_payload(&card).unwrap();
        let sig2 = id.sign_payload(&card).unwrap();
        assert_eq!(sig1, sig2, "Ed25519 must be deterministic");

        let signed = json!({
            "did": id.did().as_str(),
            "name": "CrossLang",
            "capabilities": ["text-generation", "mcp"],
            "stake": 100,
            "signature": sig1
        });
        assert!(id.verify_payload(&signed, &sig1).is_ok());
    }

    #[test]
    fn tampering_is_rejected() {
        let id = Identity::from_seed(&CONFORMANCE_SEED);
        let signed = json!({
            "did": id.did().as_str(),
            "name": "Tampered",
            "capabilities": ["text-generation", "mcp"],
            "stake": 100,
            "signature": "00"
        });
        let err = id.verify_payload(&signed, "00").unwrap_err();
        // "00" is not a valid 64-byte signature, so encoding is rejected.
        assert!(matches!(err, NauError::InvalidSignatureEncoding(_)));
    }

    #[test]
    fn a_signature_from_one_key_cannot_be_attributed_to_another_identity() {
        // Signing as someone else is refused at the domain level.
        let id = Identity::from_seed(&CONFORMANCE_SEED);
        let other = Identity::from_seed(&[2u8; 32]);
        let card = json!({ "did": other.did().as_str(), "n": 1, "signature": "" });
        let sig = id.sign_payload(&card).unwrap();
        let signed = json!({ "did": other.did().as_str(), "n": 1, "signature": sig });

        // `Identity::verify_payload` asks "did *I* sign this?" — and the answer is
        // yes, because `id` did. The binding check is about a (DID, key) pair, so
        // the interesting assertion is that pairing `id`'s key with `other`'s DID
        // is refused outright.
        assert!(id.verify_payload(&signed, &sig).is_ok());
        let err = verify_payload_bound(&signed, &sig, &id.public_key(), &other.did()).unwrap_err();
        assert!(
            matches!(err, NauError::DidKeyMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn did_parser_rejects_malformed_input() {
        assert!(Did::parse("did:nau:short").is_err());
        assert!(
            Did::parse("did:nau:34750F98BD59FCFC").is_err(),
            "uppercase hex rejected"
        );
        assert!(Did::parse("did:key:34750f98bd59fcfc").is_err());
        assert!(Did::parse("34750f98bd59fcfc").is_err());
        assert!(Did::parse("did:nau:34750f98bd59fcfg").is_err());
        assert!(Did::parse("did:nau:34750f98bd59fcfc").is_ok());
    }

    #[test]
    fn malformed_public_keys_are_rejected_at_parse_time() {
        assert!(PublicKey::from_hex("zz").is_err());
        assert!(PublicKey::from_hex(&"00".repeat(31)).is_err());
        // 32 zero bytes decompresses to the small-order identity point, which is
        // refused as a weak key.
        let zero = PublicKey::from_hex(&"00".repeat(32));
        assert!(zero.is_err(), "the all-zero (identity) key must be refused");
        assert!(matches!(zero.unwrap_err(), NauError::InvalidPublicKey(_)));
        // A genuine key still parses.
        assert!(
            PublicKey::from_hex(&Keypair::from_seed(&CONFORMANCE_SEED).public_key().to_hex())
                .is_ok()
        );
    }

    #[test]
    fn keypair_debug_never_leaks_the_seed() {
        let kp = Keypair::from_seed(&CONFORMANCE_SEED);
        let rendered = format!("{kp:?}");
        assert!(!rendered.contains(&kp.seed_hex()));
        assert!(rendered.contains("did:nau:"));
    }
}
