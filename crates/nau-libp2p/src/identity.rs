//! The seam between this project's identity and a libp2p `PeerId`.
//!
//! ## Why this module exists
//!
//! `nau-core` mints identities as
//! `did:nau:<first 8 bytes of SHA-256(raw 32-byte Ed25519 public key), lowercase hex>`.
//! A libp2p `PeerId` for the same key is
//! `base58btc(0x00 0x24 || protobuf(Ed25519 public key))` — a *different*
//! fingerprint over the *same* key material. The `0x00 0x24` prefix is the
//! *identity* multihash: an Ed25519 key's protobuf encoding is 36 bytes, which is
//! at most libp2p's inline limit of 42, so the key is embedded rather than hashed.
//! (A key too long to inline would be `0x12 0x20 || SHA-256(encoding)` instead, and
//! that branch is not what this module produces — see
//! [`PeerId::from_ed25519_public_key`].)
//!
//! A DID is a truncated hash and cannot be inverted, so a DID alone can never
//! yield a `PeerId`. [`NauIdentity::peer_id`] therefore takes the public key and
//! every constructor that accepts a DID alongside a key **verifies** that the two
//! agree ([`NauIdentity::from_did_and_public_key`]) instead of trusting the
//! caller's pairing. That is the same binding check
//! `nau_core::verify_payload_bound` performs for signatures: two views of one
//! key, or an error.
//!
//! ## What is implemented here, and what that costs
//!
//! The entire encoding — base58btc, the `0x12 0x20` multihash prefix, and the
//! protobuf wrapper around the 32 key bytes — is implemented here in ordinary
//! arithmetic tested with no libp2p dependency at all. That is deliberate: it
//! keeps the map between the two stacks testable on a machine that cannot compile
//! libp2p, so `cargo test -p nau-libp2p` with no features still exercises the
//! real derivation rather than a stub.
//!
//! The cost is stated plainly: this module's encoding is *cross-checked* against
//! libp2p's own constructor only when the `libp2p` feature is on (see
//! `crates/nau-libp2p/tests/libp2p_identity_agreement.rs`). With the feature off,
//! an error in the encoding here would not be caught by this crate's test suite.
//!
//! ## Upstream defect this closes
//!
//! agent-universe v2.5.6 has both a DID (`gsn-core/src/identity/did.rs`) and a
//! libp2p `Keypair`, generated independently in different places, with nothing
//! tying them together. Two nodes could present the same DID over HTTP and
//! different `PeerId`s on the wire and no code anywhere would notice.
//! `// upstream v2.5.6 fix: one key, two derived identifiers, with the pairing
//! checked instead of assumed.`

use std::fmt;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use nau_core::{Did, Result as NauResult};

/// Length of a raw Ed25519 public key, in bytes.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// Multihash code for SHA-256 (`sha2-256`).
const MULTIHASH_SHA2_256: u8 = 0x12;

/// Multihash code for the *identity* hash, which is what libp2p uses for a public
/// key whose protobuf encoding is short enough to inline.
const MULTIHASH_IDENTITY: u8 = 0x00;

/// Length of the protobuf encoding of an Ed25519 public key, in bytes
/// (`0x08 0x01 0x12 0x20` plus the 32 key bytes).
const ED25519_PROTOBUF_BYTES: usize = 4 + ED25519_PUBLIC_KEY_BYTES;

/// `libp2p_identity::peer_id::MAX_INLINE_KEY_LENGTH`: a key whose protobuf encoding
/// is at most this many bytes is used **directly** as the peer id, wrapped in an
/// identity multihash, instead of being hashed.
///
/// This is the fact an earlier version of this module got wrong. It assumed the
/// SHA-256 branch unconditionally, which produced a `Qm…` peer id where libp2p
/// produces `12D3KooW…`. The two are both valid {@link Multihash} values, so nothing
/// rejected it locally — only
/// `the_did_and_the_libp2p_keypair_are_the_same_key` caught it, by comparing
/// against libp2p's own constructor.
///
/// `// upstream v2.5.6 fix:` this is exactly the kind of near-miss the crate's
/// cross-check test exists for: a plausible-looking identifier that no other
/// libp2p node would accept.
const MAX_INLINE_KEY_LENGTH: usize = 42;

/// Digest length byte for the 36-byte identity digest of an Ed25519 public key.
const IDENTITY_32_PLUS_4: u8 = (ED25519_PROTOBUF_BYTES) as u8;

/// Total length of an Ed25519 `PeerId` multihash, in bytes: the 2-byte identity
/// prefix (`0x00 0x24`) plus the 36-byte protobuf encoding of the key.
///
/// Note that this is **not** `2 + 32`: an Ed25519 key is short enough to inline, so
/// the digest is the protobuf encoding, not the raw key and not a hash of it.
pub const ED25519_PEER_ID_BYTES: usize = 2 + ED25519_PROTOBUF_BYTES;

/// Multicodec value for an Ed25519 public key, as a protobuf varint (`0x08 0x01`).
const MULTICODEC_ED25519_VARINT: [u8; 2] = [0x08, 0x01];

/// Protobuf field tag for `PublicKey.Data` (field 2, length-delimited).
const PROTOBUF_DATA_TAG: u8 = 0x12;

/// The base58btc alphabet (Bitcoin), as used by libp2p's textual `PeerId` form.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// What can go wrong when mapping between the two identifier spaces.
///
/// Every variant rejects something a caller supplied. None of them can be
/// produced by a value this crate derived itself.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The bytes offered as an Ed25519 public key were not 32 bytes long.
    #[error("public key must be {ED25519_PUBLIC_KEY_BYTES} bytes, got {got}")]
    PublicKeyLength {
        /// The length that was supplied.
        got: usize,
    },
    /// The DID does not parse as a `did:nau:` (or legacy `did:aip:`) identifier.
    #[error("`{did}` is not a valid DID: {reason}")]
    InvalidDid {
        /// The rejected DID.
        did: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The DID is a valid identifier but is the fingerprint of a *different* key.
    #[error("`{did}` does not fingerprint the supplied public key (that key is `{expected}`)")]
    DidKeyMismatch {
        /// The DID the caller claimed.
        did: String,
        /// The DID the key actually fingerprints.
        expected: String,
    },
    /// A textual peer id was not valid base58btc.
    #[error("`{peer_id}` is not base58btc: {reason}")]
    Base58 {
        /// The rejected string.
        peer_id: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A peer id decoded, but is not an inline-Ed25519 identity multihash.
    ///
    /// The message names both multihash codes on purpose: the failure this reports
    /// is almost always "a SHA-256 id was supplied where an inline identity id was
    /// needed" — a `Qm…` id instead of a `12D3KooW…` one — and a caller who can see
    /// `0x00` next to `0x12` can tell which one they have.
    #[error(
        "`{peer_id}` is not an Ed25519 peer id: expected a {ED25519_PEER_ID_BYTES}-byte identity \
         multihash (`{MULTIHASH_IDENTITY:#04x} {IDENTITY_32_PLUS_4:#04x}` prefix, i.e. the \
         36-byte protobuf encoding of the key, at most {MAX_INLINE_KEY_LENGTH} bytes so it is \
         inlined), got {got} bytes; a `{MULTIHASH_SHA2_256:#04x}`-prefixed SHA-256 id is a \
         different construction"
    )]
    NotEd25519PeerId {
        /// The rejected string.
        peer_id: String,
        /// How many bytes it decoded to.
        got: usize,
    },
    /// The peer id is well-formed, but its digest is not SHA-256 of the supplied
    /// Ed25519 public key — the id and the key are unrelated.
    #[error("`{peer_id}` is not the SHA-256 of the supplied Ed25519 public key")]
    PeerIdKeyMismatch {
        /// The rejected peer id.
        peer_id: String,
    },
}

impl From<IdentityError> for nau_core::NauError {
    fn from(err: IdentityError) -> Self {
        nau_core::NauError::Validation(err.to_string())
    }
}

/// A libp2p peer identifier in the encoding libp2p itself uses.
///
/// Stored as the 36 raw multihash bytes, not as a string: two spellings that
/// decode to the same multihash must compare equal, and equality on bytes is the
/// only way to guarantee that. The textual form is derived on demand and is
/// always canonical.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; ED25519_PEER_ID_BYTES]);

impl PeerId {
    /// Build from the raw multihash bytes.
    ///
    /// Rejects a prefix other than `0x00 0x24` (identity, 36 bytes), so a
    /// truncated or differently hashed identifier cannot be smuggled in as an
    /// Ed25519 id.
    pub fn from_multihash_bytes(bytes: [u8; ED25519_PEER_ID_BYTES]) -> Result<Self, IdentityError> {
        if bytes[0] != MULTIHASH_IDENTITY || bytes[1] != IDENTITY_32_PLUS_4 {
            return Err(IdentityError::NotEd25519PeerId {
                peer_id: base58_encode(&bytes),
                got: ED25519_PEER_ID_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// Derive the id for a raw 32-byte Ed25519 public key.
    ///
    /// This is exactly the construction libp2p performs
    /// (`libp2p_identity::PeerId::from_public_key`):
    ///
    /// ```text
    /// key_enc = 0x08 0x01 0x12 0x20 || raw_public_key        // protobuf PublicKey
    /// peer    = 0x00 0x24 || key_enc                          // identity multihash
    /// ```
    ///
    /// `key_enc` is 36 bytes, which is at most libp2p's
    /// `MAX_INLINE_KEY_LENGTH` of 42, so the key is **inlined** rather than hashed.
    /// That is why an Ed25519 peer id begins `12D3KooW`. A key longer than 42 bytes
    /// (RSA, or a protobuf with extra fields) would instead be
    /// `0x12 0x20 || SHA-256(key_enc)`, which is *not* what this function returns
    /// and is not what any Ed25519 node uses.
    pub fn from_ed25519_public_key(public_key: &[u8; ED25519_PUBLIC_KEY_BYTES]) -> Self {
        let protobuf = encode_ed25519_public_key(public_key);
        let mut bytes = [0u8; ED25519_PEER_ID_BYTES];
        bytes[0] = MULTIHASH_IDENTITY;
        bytes[1] = IDENTITY_32_PLUS_4;
        bytes[2..].copy_from_slice(&protobuf);
        Self(bytes)
    }

    /// Verify that `self` is the id `public_key` derives, returning `Ok` if so.
    ///
    /// Used when a peer id arrives from the network alongside a public key:
    /// trusting that pair without this check is how a peer claims someone else's
    /// id.
    pub fn verify_public_key(
        &self,
        public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<(), IdentityError> {
        if *self != Self::from_ed25519_public_key(public_key) {
            return Err(IdentityError::PeerIdKeyMismatch {
                peer_id: self.to_string(),
            });
        }
        Ok(())
    }

    /// Parse the canonical base58btc textual form.
    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        let bytes = base58_decode(s)?;
        if bytes.len() != ED25519_PEER_ID_BYTES {
            return Err(IdentityError::NotEd25519PeerId {
                peer_id: s.to_string(),
                got: bytes.len(),
            });
        }
        let mut fixed = [0u8; ED25519_PEER_ID_BYTES];
        fixed.copy_from_slice(&bytes);
        Self::from_multihash_bytes(fixed)
    }

    /// The raw 36 multihash bytes.
    pub fn as_bytes(&self) -> &[u8; ED25519_PEER_ID_BYTES] {
        &self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base58_encode(&self.0))
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({self})")
    }
}

impl std::str::FromStr for PeerId {
    type Err = IdentityError;
    fn from_str(s: &str) -> Result<Self, IdentityError> {
        Self::parse(s)
    }
}

/// One Ed25519 key viewed as both a `did:nau:` identifier and a libp2p `PeerId`.
///
/// Construct one with [`NauIdentity::from_public_key`] when the key is what you
/// already trust, or with [`NauIdentity::from_did_and_public_key`] when a DID
/// arrived from elsewhere and the pairing should be checked rather than assumed.
///
/// `Clone` but not `Copy`: the public key is four words, but the cached `Did`
/// contains a `String`, so a `Copy` impl is not available without either leaking
/// or duplicating state on every copy.
#[derive(Clone)]
pub struct NauIdentity {
    public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    did: Option<Did>,
}

impl PartialEq for NauIdentity {
    /// Two identities are equal when their **keys** are equal.
    ///
    /// Implemented by hand rather than derived, because the derived version also
    /// compared the cached `Did`. That made
    /// `NauIdentity::from_public_key(k)` unequal to
    /// `NauIdentity::from_did_and_public_key(did, k)` for the *same* key and the
    /// same DID — they render identically and behaved identically, but one had a
    /// populated cache and the other did not. Equality on a derived cache is
    /// equality on an implementation detail.
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl Eq for NauIdentity {}

impl NauIdentity {
    /// Wrap a raw Ed25519 public key, deriving its `did:nau:` identifier.
    pub fn from_public_key(public_key: [u8; ED25519_PUBLIC_KEY_BYTES]) -> Self {
        Self {
            public_key,
            did: None,
        }
    }

    /// Derive an identity from the same 32-byte seed `nau_core::Keypair` uses.
    ///
    /// Keyed on the seed rather than on a `Keypair` because the seed is exactly
    /// what `nau-core` persists (`Keypair::seed_hex`), so a node can reconstruct
    /// both views of its identity from its stored secret without this crate
    /// holding signing state.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_public_key(ed25519_public_key_from_seed(seed))
    }

    /// Wrap a key while asserting that `did` is its fingerprint.
    ///
    /// Returns [`IdentityError::DidKeyMismatch`] when the two disagree, so a
    /// caller cannot pair an attacker-supplied DID with their own key.
    pub fn from_did_and_public_key(
        did: &str,
        public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    ) -> Result<Self, IdentityError> {
        let parsed = Did::parse(did).map_err(|e| IdentityError::InvalidDid {
            did: did.to_string(),
            reason: e.to_string(),
        })?;
        let expected = did_for_public_key(&public_key);
        if parsed.fingerprint() != expected.fingerprint() {
            return Err(IdentityError::DidKeyMismatch {
                did: parsed.to_string(),
                expected: expected.to_string(),
            });
        }
        Ok(Self {
            public_key,
            did: Some(parsed),
        })
    }

    /// The raw Ed25519 public key.
    pub fn public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    /// The `did:nau:` identifier for this key.
    pub fn did(&self) -> Did {
        match &self.did {
            Some(did) => did.clone(),
            None => did_for_public_key(&self.public_key),
        }
    }

    /// The 16-character fingerprint both identifiers are derived from.
    pub fn fingerprint(&self) -> String {
        self.did().fingerprint().to_string()
    }

    /// The libp2p `PeerId` for this key.
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_ed25519_public_key(&self.public_key)
    }

    /// Check that `peer_id` really is the id of this identity's key.
    pub fn verify_peer_id(&self, peer_id: &PeerId) -> Result<(), IdentityError> {
        peer_id.verify_public_key(&self.public_key)
    }
}

impl fmt::Debug for NauIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // There is no secret here; print both public views and nothing else.
        write!(f, "NauIdentity({}, {})", self.did(), self.peer_id())
    }
}

/// The protobuf encoding of an Ed25519 public key, as libp2p serializes it.
///
/// ```text
/// 0x08 0x01   field 1 (Type), varint 1 (Ed25519)
/// 0x12 0x20   field 2 (Data), length-delimited, 32 bytes
/// <32 bytes>  the key
/// ```
///
/// Written out here rather than delegated, because it is the input to the peer id
/// and a mismatch would produce an id that looks right and is accepted by nobody.
pub fn encode_ed25519_public_key(
    public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
) -> [u8; ED25519_PROTOBUF_BYTES] {
    let mut out = [0u8; ED25519_PROTOBUF_BYTES];
    // `MULTICODEC_ED25519_VARINT` is `[0x08, 0x01]`: protobuf field tag 1, varint,
    // value 1 (`KeyType::Ed25519`).
    out[0] = MULTICODEC_ED25519_VARINT[0];
    out[1] = MULTICODEC_ED25519_VARINT[1];
    out[2] = PROTOBUF_DATA_TAG;
    out[3] = ED25519_PUBLIC_KEY_BYTES as u8;
    out[4..].copy_from_slice(public_key);
    out
}

/// The `did:nau:` identifier for a raw Ed25519 public key.
///
/// `nau_core::Did::from_public_key` produces the same string, and this module's
/// `this_matches_nau_core` test asserts it. It is recomputed here so that the
/// mapping between the two stacks is readable in one place.
///
/// This function deliberately does **not** fall back to
/// `nau_core::Did::from_public_key`: an earlier version of it did, and because
/// `nau_core`'s own implementation calls back into the same fingerprint rule, the
/// two formed a cycle that overflowed the stack on the failure path. The fallback
/// was unreachable *and* fatal, which is the worst combination.
///
/// The only failure mode of `Did::from_fingerprint_hex` here is a fingerprint that
/// is not exactly 16 lowercase hex characters, and `hex::encode(&digest[..8])`
/// produces exactly that for every input. The `match` therefore has no reachable
/// error arm; it exists so that this function has no unwind path rather than
/// becoming an `expect` in a library.
pub fn did_for_public_key(public_key: &[u8; ED25519_PUBLIC_KEY_BYTES]) -> Did {
    let digest = Sha256::digest(public_key);
    let fingerprint = hex::encode(&digest[..DID_FINGERPRINT_BYTES]);
    match Did::from_fingerprint_hex(nau_core::identity::DID_PREFIX, &fingerprint) {
        Ok(did) => did,
        // Unreachable: the fingerprint above is 16 lowercase hex characters,
        // which is exactly what `Did::parse` accepts. Returning an all-zero
        // fingerprint rather than recursing keeps the function total without
        // depending on `nau_core`'s own constructor, which is what made a
        // fallback here a cycle.
        Err(_) => Did::from_fingerprint_hex(nau_core::identity::DID_PREFIX, &"0".repeat(16))
            .unwrap_or_else(|_| unreachable_did()),
    }
}

/// A `Did` that cannot fail to construct.
///
/// `"0".repeat(16)` is 16 lowercase hex characters, so `Did::from_fingerprint_hex`
/// accepts it; the external invariant `did_for_public_key_is_total` asserts that
/// both paths above succeed. This exists only so that no function in this module
/// has a panic path.
fn unreachable_did() -> Did {
    match Did::from_fingerprint_hex(nau_core::identity::DID_PREFIX, "0000000000000000") {
        Ok(did) => did,
        Err(_) => std::process::abort(),
    }
}

/// Number of SHA-256 bytes retained for the DID fingerprint, matching `nau-core`.
const DID_FINGERPRINT_BYTES: usize = 8;

/// The public key for a 32-byte Ed25519 seed.
///
/// Delegated to `ed25519-dalek` — the same build `nau-core` links — so the
/// workspace holds exactly one Ed25519 implementation. Implementing the scalar
/// multiplication here would be a second one.
fn ed25519_public_key_from_seed(seed: &[u8; 32]) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// The libp2p peer id string for a raw Ed25519 public key.
pub fn peer_id_string(public_key: &[u8; ED25519_PUBLIC_KEY_BYTES]) -> String {
    PeerId::from_ed25519_public_key(public_key).to_string()
}

/// The libp2p `PeerId` for a `did:nau:` address and the key it must fingerprint.
///
/// The `Result` in `NauError` form is what makes this usable from the callers
/// that already speak `nau_core::Result`.
pub fn peer_id_for_did(did: &str, public_key: &[u8]) -> NauResult<PeerId> {
    let key: [u8; ED25519_PUBLIC_KEY_BYTES] =
        public_key
            .try_into()
            .map_err(|_| IdentityError::PublicKeyLength {
                got: public_key.len(),
            })?;
    Ok(NauIdentity::from_did_and_public_key(did, key)?.peer_id())
}

/// Human-readable `did = peer (fingerprint …)` rendering, for logs and errors.
pub fn describe_identity(identity: &NauIdentity) -> String {
    format!(
        "{} = {} (fingerprint {})",
        identity.did(),
        identity.peer_id(),
        identity.fingerprint()
    )
}

/// Encode bytes as base58btc (Bitcoin alphabet).
///
/// Leading zero bytes become leading `1` characters; the remainder is a
/// repeated-division base conversion, which is O(n²) in the input length and
/// perfectly adequate for 36 bytes.
pub fn base58_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let zeros = input.iter().take_while(|b| **b == 0).count();
    // Worst case is log(256)/log(58) ≈ 1.365 digits per byte, plus one.
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &digit in digits.iter().rev() {
        // `digit` is always < 58 and the alphabet has 58 entries; `min` makes the
        // indexing provably in range without an `expect` or an index panic.
        out.push(char::from(
            BASE58_ALPHABET[usize::from(digit).min(BASE58_ALPHABET.len() - 1)],
        ));
    }
    out
}

/// Decode a base58btc string (Bitcoin alphabet).
///
/// Returns an error only for a character outside the alphabet. The empty string
/// decodes to no bytes, matching Bitcoin Core's `base58_decode("") == []` vector —
/// an earlier version of this function rejected it as "not a peer id", which
/// conflated a *codec* with a *policy*. The peer-id policy is enforced by
/// [`PeerId::parse`], which requires the decoded length to be
/// [`ED25519_PEER_ID_BYTES`], so an empty string is still refused there.
pub fn base58_decode(input: &str) -> Result<Vec<u8>, IdentityError> {
    let reject = |reason: &str| IdentityError::Base58 {
        peer_id: input.to_string(),
        reason: reason.to_string(),
    };
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if !input.is_ascii() {
        return Err(reject("base58btc is ASCII-only"));
    }
    let zeros = input.bytes().take_while(|b| *b == b'1').count();
    let mut bytes: Vec<u8> = Vec::with_capacity(input.len());
    for ch in input.as_bytes()[zeros..].iter().copied() {
        let value = match BASE58_ALPHABET.iter().position(|c| *c == ch) {
            Some(index) => index as u32,
            None => return Err(reject("character is not in the base58btc alphabet")),
        };
        let mut carry = value;
        for byte in bytes.iter_mut() {
            let total = u32::from(*byte) * 58 + carry;
            *byte = (total & 0xff) as u8;
            carry = total >> 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev().copied());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::identity::Keypair;

    /// The fixed seed every conformance vector in every language uses.
    const CONFORMANCE_SEED: [u8; 32] = [1u8; 32];

    #[test]
    fn this_matches_nau_core() {
        // If this crate's DID derivation drifts from nau-core's, the DID a node
        // advertises and the DID it signs with stop describing the same identity.
        let seed = CONFORMANCE_SEED;
        let keypair = Keypair::from_seed(&seed);
        let mine = NauIdentity::from_seed(&seed);
        assert_eq!(mine.public_key(), keypair.public_key().as_bytes());
        assert_eq!(mine.did(), keypair.did());
        assert_eq!(mine.did().as_str(), "did:nau:34750f98bd59fcfc");
        assert_eq!(
            did_for_public_key(keypair.public_key().as_bytes()),
            keypair.did(),
            "the local derivation must agree with nau-core's"
        );
        // And the seed path must agree with the public-key path.
        assert_eq!(
            NauIdentity::from_public_key(*keypair.public_key().as_bytes()),
            mine
        );
    }

    #[test]
    fn peer_id_derivation_is_deterministic_and_round_trips() {
        let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);
        let first = identity.peer_id();
        let second = NauIdentity::from_seed(&CONFORMANCE_SEED).peer_id();
        assert_eq!(first, second, "one key must give one peer id");

        // Round trip through the textual form, which is also canonical.
        let text = first.to_string();
        let parsed = PeerId::parse(&text).unwrap_or_else(|e| panic!("own rendering failed: {e}"));
        assert_eq!(parsed, first);
        assert_eq!(parsed.to_string(), text);
        assert_eq!(
            text.parse::<PeerId>().unwrap_or_else(|e| panic!("{e}")),
            first
        );

        // The id really is this key's id, and is not another key's.
        assert!(identity.verify_peer_id(&first).is_ok());
        let other = NauIdentity::from_seed(&[2u8; 32]);
        assert_ne!(other.peer_id(), first);
        assert!(other.verify_peer_id(&first).is_err());
        assert!(first.verify_public_key(other.public_key()).is_err());
    }

    #[test]
    fn the_derived_peer_id_has_the_expected_shape() {
        let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);
        let peer_id = identity.peer_id();
        let bytes = peer_id.as_bytes();
        assert_eq!(bytes.len(), ED25519_PEER_ID_BYTES);
        assert_eq!(
            ED25519_PEER_ID_BYTES, 38,
            "2-byte prefix + 36-byte protobuf key"
        );
        assert_eq!(
            bytes[0], MULTIHASH_IDENTITY,
            "identity multihash, not sha2-256"
        );
        assert_eq!(bytes[1], IDENTITY_32_PLUS_4, "36-byte inline key");
        assert_ne!(
            bytes[0], MULTIHASH_SHA2_256,
            "hashing the key is the classic near-miss: it yields `Qm…` where libp2p yields `12D3KooW…`"
        );

        // The digest is the protobuf encoding of the key, embedded verbatim.
        let protobuf = encode_ed25519_public_key(identity.public_key());
        assert_eq!(&bytes[2..], &protobuf[..]);
        assert_eq!(protobuf.len(), 36);
        assert_eq!(&protobuf[..4], &[0x08, 0x01, 0x12, 0x20]);
        assert_eq!(&protobuf[4..], &identity.public_key()[..]);

        // 38 bytes of base58 render as 52 characters and begin with the
        // `12D3KooW` prefix that inline-Ed25519 libp2p nodes display.
        let text = peer_id.to_string();
        assert_eq!(text.len(), 52, "got {text}");
        assert!(
            text.starts_with("12D3KooW"),
            "an inline Ed25519 key renders with this prefix; got {text}"
        );
        // The inline limit is 42 and this key's protobuf encoding is 36, so the
        // identity branch really is the one taken. Compared numerically, because
        // `assert!(a <= b)` on two constants is what the optimiser removes — and the
        // failure message is the point of the assertion.
        let inline_margin = MAX_INLINE_KEY_LENGTH - ED25519_PROTOBUF_BYTES;
        assert_eq!(
            inline_margin, 6,
            "an Ed25519 protobuf encoding is {ED25519_PROTOBUF_BYTES} bytes and libp2p's inline \
             limit is {MAX_INLINE_KEY_LENGTH}; if the margin changes, the identity branch may no \
             longer be the one taken"
        );
        // Debug output must be bounded and must name the id.
        let debug = format!("{peer_id:?}");
        assert!(debug.starts_with("PeerId("));
        assert!(debug.len() < 64);
    }

    #[test]
    fn a_did_and_a_key_must_agree() {
        let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);
        let other = NauIdentity::from_seed(&[7u8; 32]);

        let paired =
            NauIdentity::from_did_and_public_key(identity.did().as_str(), *identity.public_key())
                .expect("a genuine pairing must be accepted");
        assert_eq!(paired, identity);

        let err =
            NauIdentity::from_did_and_public_key(other.did().as_str(), *identity.public_key())
                .expect_err("a mismatched pairing must be refused");
        match &err {
            IdentityError::DidKeyMismatch { did, expected } => {
                assert_eq!(did, other.did().as_str());
                assert_eq!(expected, identity.did().as_str());
            }
            unexpected => panic!("expected a mismatch, got {unexpected:?}"),
        }
        // The message names both sides, so a log line is diagnosable.
        assert!(err.to_string().contains(other.did().as_str()));
        assert!(err.to_string().contains(identity.did().as_str()));
        // And it converts into the workspace error type.
        let nau: nau_core::NauError = err.into();
        assert!(matches!(nau, nau_core::NauError::Validation(_)));
    }

    #[test]
    fn legacy_did_prefix_still_binds_to_the_same_key() {
        // A DID minted by upstream agent-universe (`did:aip:`) must map onto the
        // same PeerId, or a migrated node loses its identity on the wire.
        let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);
        let legacy = "did:aip:34750f98bd59fcfc";
        let mapped = NauIdentity::from_did_and_public_key(legacy, *identity.public_key())
            .expect("the legacy prefix binds to the same fingerprint");
        assert_eq!(mapped.peer_id(), identity.peer_id());
        assert_eq!(mapped.did().prefix(), nau_core::identity::DID_PREFIX_LEGACY);
        assert_eq!(
            peer_id_string(identity.public_key()),
            identity.peer_id().to_string()
        );
    }

    #[test]
    fn malformed_dids_and_keys_are_refused_without_panicking() {
        let key = *NauIdentity::from_seed(&CONFORMANCE_SEED).public_key();
        for bad in [
            "",
            "did:nau:",
            "did:nau:short",
            "did:nau:34750F98BD59FCFC",
            "did:key:34750f98bd59fcfc",
            "34750f98bd59fcfc",
            "did:nau:34750f98bd59fcfcg",
            "did:nau:34750f98bd59fcfc\n",
        ] {
            let err = NauIdentity::from_did_and_public_key(bad, key)
                .expect_err("a malformed DID must be refused");
            assert!(
                matches!(err, IdentityError::InvalidDid { .. }),
                "{bad:?} gave {err:?}"
            );
        }
        // Wrong-length keys are refused by the helper, not by a slice panic.
        assert!(matches!(
            peer_id_for_did("did:nau:34750f98bd59fcfc", &[0u8; 31]).unwrap_err(),
            nau_core::NauError::Validation(_)
        ));
        assert!(peer_id_for_did("did:nau:34750f98bd59fcfc", &[0u8; 33]).is_err());
        assert!(peer_id_for_did("did:nau:34750f98bd59fcfc", &[]).is_err());
    }

    #[test]
    fn malformed_peer_ids_are_refused_without_panicking() {
        for bad in [
            "",
            "!!!",
            "0",
            "O0Il",      // characters outside the base58btc alphabet
            "1111",      // decodes to leading zeroes: the wrong length
            "1",         // a single leading zero: the wrong length
            "\u{1f600}", // non-ASCII must not index the alphabet
            // A real, well-formed libp2p id that is *not* an inline Ed25519 key:
            // this is a sha2-256 id (the `Qm…` shape), which is what this module
            // used to produce by mistake. It must be refused as a sender.
            "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
        ] {
            assert!(PeerId::parse(bad).is_err(), "{bad:?} must be refused");
            let err = PeerId::parse(bad).unwrap_err();
            assert!(!err.to_string().is_empty());
        }
        // The right length with the wrong multihash code is refused.
        let mut wrong_code = [0u8; ED25519_PEER_ID_BYTES];
        wrong_code[0] = MULTIHASH_SHA2_256;
        wrong_code[1] = 0x20;
        assert!(matches!(
            PeerId::from_multihash_bytes(wrong_code).unwrap_err(),
            IdentityError::NotEd25519PeerId { got, .. } if got == ED25519_PEER_ID_BYTES
        ));
        // An identity multihash of the wrong digest length is refused too.
        let mut wrong_len = [0u8; ED25519_PEER_ID_BYTES];
        wrong_len[0] = MULTIHASH_IDENTITY;
        wrong_len[1] = 0x20;
        assert!(PeerId::from_multihash_bytes(wrong_len).is_err());
    }

    #[test]
    fn base58_matches_the_bitcoin_test_vectors() {
        // From Bitcoin Core's `base58_encode_decode.json`, the reference every
        // base58btc implementation is checked against.
        let cases: &[(&[u8], &str)] = &[
            (&[], ""),
            (&[0x61], "2g"),
            (&[0x62, 0x62, 0x62], "a3gV"),
            (&[0x63, 0x63, 0x63], "aPEr"),
            (&[0x00], "1"),
            (&[0x00, 0x00], "11"),
            (&[0x00, 0x61], "12g"),
            (&[0xff], "5Q"),
            (&[0xff, 0xff], "LUv"),
            (&[0x00, 0xff, 0xff], "1LUv"),
            (&[0x01, 0x02, 0x03], "Ldp"),
        ];
        for (bytes, text) in cases {
            assert_eq!(&base58_encode(bytes), text, "encode {bytes:?}");
            assert_eq!(
                base58_decode(text).expect("decode must succeed"),
                bytes.to_vec(),
                "decode {text:?}"
            );
        }
        // The 32-byte value 0x01 encodes to 31 leading `1`s plus `2`.
        let mut thirty_two_then_one = [0u8; 33];
        thirty_two_then_one[0] = 0x00;
        thirty_two_then_one[32] = 0x01;
        assert_eq!(
            base58_encode(&thirty_two_then_one[1..]),
            format!("{}2", "1".repeat(31)),
            "31 leading zero bytes then 0x01"
        );
        // Round trip every single-byte input, so no byte value is untested.
        for byte in 0u16..=255 {
            let input = [byte as u8];
            let encoded = base58_encode(&input);
            assert_eq!(base58_decode(&encoded).expect("round trip"), input.to_vec());
        }
        // Round trip a 36-byte multihash-shaped input, the shape actually used.
        for seed_byte in [0u8, 1, 0x12, 0xff] {
            let input = [seed_byte; ED25519_PEER_ID_BYTES];
            assert_eq!(
                base58_decode(&base58_encode(&input)).expect("round trip"),
                input.to_vec()
            );
        }
    }

    #[test]
    fn describe_identity_names_both_views() {
        let identity = NauIdentity::from_seed(&CONFORMANCE_SEED);
        let text = describe_identity(&identity);
        assert!(text.contains("did:nau:34750f98bd59fcfc"));
        assert!(text.contains(&identity.peer_id().to_string()));
        assert!(text.contains(&identity.fingerprint()));
        assert_eq!(identity.fingerprint().len(), 16);
        // Debug must not be a wall of bytes and must never look like a secret.
        assert!(format!("{identity:?}").len() < 128);
    }
}
