//! Chunk attestation: a publisher's Ed25519 signature over a chunk's address.
//!
//! # What is signed, and why it is the address rather than the bytes
//!
//! A signature covers [`message_for`], which is a domain-separation prefix followed by the
//! chunk's content address — **not** the chunk's bytes.
//!
//! * **The bytes are already committed to.** A content address *is* the hash of the bytes,
//!   and the reader checks the bytes against the address before it does anything else. A
//!   signature over the address therefore transitively covers the bytes.
//! * **It is fixed-size.** Signing a gigabyte chunk to say "I published this" would make
//!   attestation cost proportional to the thing attested, which is the wrong shape for a
//!   record that travels alongside the data.
//! * **Domain separation is not decoration.** Without the prefix, a signature over these
//!   bytes in *any other* context in this workspace would verify here. The prefix makes a
//!   chunk signature usable only as a chunk signature, which is what stops a signature
//!   harvested from, say, a task result from being replayed as an image attestation.
//!
//! # What verifying an attestation does and does not establish
//!
//! It establishes that **the holder of the signer's key asserted this content address**.
//! It does not establish that the content is *good* — a publisher can sign anything,
//! including something malicious. Whether a publisher's key is one the node should accept is
//! a trust decision, and trust decisions in this workspace belong to the `Tier` vocabulary,
//! not here. This module answers "did they sign it", and the caller answers "do I care who
//! they are".

use crate::error::{NauError, Result};
use crate::identity::{Did, Keypair, PublicKey, Signature64};
use crate::image::ChunkDigest;

/// The domain-separation prefix for chunk signatures.
///
/// Versioned, because the prefix is part of the signed preimage: changing the scheme without
/// changing the prefix would make old signatures verify under new rules.
pub const CHUNK_SIGNATURE_DOMAIN: &str = "nau-image-chunk:v1";

/// The exact bytes a chunk attestation signs.
///
/// Exposed rather than kept private because the conformance vectors and any second
/// implementation need to reproduce it byte for byte, and a preimage that can only be
/// produced by the code that verifies it is not a specification.
#[must_use]
pub fn message_for(digest: &ChunkDigest) -> Vec<u8> {
    let mut message = Vec::with_capacity(CHUNK_SIGNATURE_DOMAIN.len() + 1 + 64);
    message.extend_from_slice(CHUNK_SIGNATURE_DOMAIN.as_bytes());
    // A separator that cannot appear in the prefix or in lowercase hex, so that no pair of
    // (domain, digest) can produce the same preimage as another pair.
    message.push(b':');
    message.extend_from_slice(digest.as_str().as_bytes());
    message
}

/// A publisher's assertion about a chunk.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChunkAttestation {
    /// The content address being attested.
    pub digest: ChunkDigest,
    /// The DID that claims authorship.
    pub signer: Did,
    /// The public key that must fingerprint [`ChunkAttestation::signer`].
    pub signer_key: PublicKey,
    /// The detached signature over [`message_for`].
    pub signature: Signature64,
}

impl ChunkAttestation {
    /// Sign a chunk address.
    #[must_use]
    pub fn sign(keypair: &Keypair, digest: &ChunkDigest) -> Self {
        let message = message_for(digest);
        Self {
            digest: digest.clone(),
            signer: keypair.did(),
            signer_key: keypair.public_key(),
            signature: keypair.sign(&message),
        }
    }

    /// Check the attestation against a digest.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the signer DID does not fingerprint the carried key, or
    /// when the attestation is about a different digest than the one being checked;
    /// [`NauError::InvalidSignature`] when the signature does not verify.
    ///
    /// The digest check is not redundant with the signature: a valid attestation for chunk
    /// *A* presented while chunk *B* is being loaded must be refused, and without this it
    /// would verify — the signature is over whatever the attestation names, so the caller
    /// has to check that it names the right thing.
    pub fn verify_for(&self, digest: &ChunkDigest) -> Result<()> {
        if &self.digest != digest {
            return Err(NauError::Validation(format!(
                "this attestation is for {} but {} is being loaded",
                self.digest, digest
            )));
        }
        self.verify()
    }

    /// Check the attestation against the digest it names.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the signer DID does not fingerprint the carried key;
    /// [`NauError::InvalidSignature`] when the signature does not verify.
    pub fn verify(&self) -> Result<()> {
        // The DID is self-certifying, so a mismatched pair means either a bug in the
        // producer or an attempt to attribute a signature to someone else's identity. Both
        // are refused; the distinction is not worth making at this layer.
        if !self.signer.matches_public_key(&self.signer_key) {
            return Err(NauError::Validation(format!(
                "attestation claims signer {} but carries a key that fingerprints to {}",
                self.signer,
                self.signer_key.did()
            )));
        }
        self.signer_key
            .verify(&message_for(&self.digest), self.signature.as_bytes())
    }
}

/// Whether chunks must be attested.
///
/// The default is [`SignaturePolicy::Require`], and the other variant exists so that a
/// deliberate downgrade is a thing a caller **writes down** rather than a thing that happens
/// when an attestation is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignaturePolicy {
    /// A chunk with no valid attestation is refused.
    #[default]
    Require,
    /// An unsigned chunk is accepted, with the reason recorded.
    ///
    /// For development against an image that has not been published yet. A deployment that
    /// sets this is choosing to load bytes nobody has vouched for, and the loader says so in
    /// its report rather than staying quiet.
    AllowUnsigned,
}

impl SignaturePolicy {
    /// A label for reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SignaturePolicy::Require => "require",
            SignaturePolicy::AllowUnsigned => "allow-unsigned",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Keypair {
        // A fixed seed, so the test is deterministic rather than depending on OS entropy.
        Keypair::from_seed(&[7_u8; 32])
    }

    #[test]
    fn a_signed_chunk_address_verifies() {
        let digest = ChunkDigest::of(b"chunk bytes");
        let attestation = ChunkAttestation::sign(&signer(), &digest);
        attestation.verify().expect("verifies");
        attestation
            .verify_for(&digest)
            .expect("verifies for its digest");
    }

    #[test]
    fn an_attestation_for_another_chunk_is_refused() {
        // The check that is not redundant with the signature: the signature is over
        // whatever the attestation names, so a caller has to check that it names the right
        // thing. Without this, a valid attestation for chunk A would authorise chunk B.
        let attested = ChunkDigest::of(b"the chunk that was signed");
        let other = ChunkDigest::of(b"a different chunk");
        let attestation = ChunkAttestation::sign(&signer(), &attested);

        attestation.verify().expect("its own digest is fine");
        let err = attestation.verify_for(&other).expect_err("must refuse");
        assert!(
            format!("{err}").contains("being loaded"),
            "the refusal must say which chunk it is about, got: {err}"
        );
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let digest = ChunkDigest::of(b"chunk");
        let mut attestation = ChunkAttestation::sign(&signer(), &digest);
        let mut bytes = *attestation.signature.as_bytes();
        bytes[0] ^= 0xff;
        attestation.signature = Signature64::from_bytes(bytes);
        assert!(
            attestation.verify().is_err(),
            "a flipped bit must not verify"
        );
    }

    #[test]
    fn a_tampered_digest_is_refused() {
        // Changing the digest changes the signed preimage, so the signature stops verifying
        // -- which is what makes the address part of the attestation rather than a label on
        // it.
        let mut attestation = ChunkAttestation::sign(&signer(), &ChunkDigest::of(b"original"));
        attestation.digest = ChunkDigest::of(b"substituted");
        assert!(attestation.verify().is_err());
    }

    #[test]
    fn a_signature_attributed_to_the_wrong_identity_is_refused() {
        // The DID is self-certifying. A record claiming someone else's identity while
        // carrying your own key is refused before the signature is even checked, so a
        // signature cannot be made to appear to come from a party that did not produce it.
        let digest = ChunkDigest::of(b"chunk");
        let mut attestation = ChunkAttestation::sign(&signer(), &digest);
        attestation.signer = Keypair::from_seed(&[9_u8; 32]).did();
        let err = attestation.verify().expect_err("must refuse");
        assert!(
            format!("{err}").contains("fingerprints to"),
            "the refusal must name the mismatch, got: {err}"
        );
    }

    #[test]
    fn the_signed_preimage_is_domain_separated() {
        // Without the prefix, a signature over these bytes produced anywhere else in the
        // workspace would verify here. The test asserts the prefix is present and that two
        // different digests give two different preimages.
        let a = message_for(&ChunkDigest::of(b"a"));
        assert!(a.starts_with(CHUNK_SIGNATURE_DOMAIN.as_bytes()));
        assert_eq!(a[CHUNK_SIGNATURE_DOMAIN.len()], b':');

        let b = message_for(&ChunkDigest::of(b"b"));
        assert_ne!(a, b);

        // And the preimage is exactly the prefix, a separator, and the 64-hex address --
        // nothing else, so a second implementation can reproduce it.
        assert_eq!(a.len(), CHUNK_SIGNATURE_DOMAIN.len() + 1 + 64);
    }

    #[test]
    fn the_policy_default_is_the_strict_one() {
        // fail-closed by default: a caller who has not thought about it gets the policy that
        // refuses unattested chunks.
        assert_eq!(SignaturePolicy::default(), SignaturePolicy::Require);
        assert_eq!(SignaturePolicy::Require.label(), "require");
        assert_eq!(SignaturePolicy::AllowUnsigned.label(), "allow-unsigned");
    }

    #[test]
    fn an_attestation_survives_a_round_trip_through_json() {
        // It travels alongside the chunk, so the serialised form has to come back as the
        // same value and still verify.
        let digest = ChunkDigest::of(b"travelling chunk");
        let attestation = ChunkAttestation::sign(&signer(), &digest);
        let text = serde_json::to_string(&attestation).expect("serialise");
        let back: ChunkAttestation = serde_json::from_str(&text).expect("deserialise");
        assert_eq!(attestation, back);
        back.verify_for(&digest).expect("still verifies");
    }
}
