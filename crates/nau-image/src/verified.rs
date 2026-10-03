//! A source that will not hand out a chunk nobody vouched for.
//!
//! # Fail-closed, and what that means here
//!
//! [`VerifiedSource`] wraps another source and checks every chunk against a
//! [`ChunkAttestation`] before letting it through. Under the default
//! [`SignaturePolicy::Require`], a chunk with **no** attestation is refused exactly like one
//! with a **bad** attestation: the absence of evidence is treated as evidence against,
//! which is the same rule the evidence gates in this workspace follow.
//!
//! The alternative — accept what is unsigned and complain later — is the failure mode this
//! exists to prevent, because "later" is after the bytes are in a sandbox.
//!
//! # Where verification happens, and why here rather than in the reader
//!
//! The reader already re-hashes every chunk, so it could carry this too. It is a decorator
//! instead because the two checks answer different questions and a caller may legitimately
//! want one without the other: **the hash says the bytes are what the address names; the
//! attestation says who said so.** A node loading a locally-built image has a use for the
//! first and none for the second, and a node pulling from a peer has a use for both.
//!
//! # The deliberate downgrade
//!
//! [`SignaturePolicy::AllowUnsigned`] exists so that loading an unpublished image during
//! development is a thing a caller **writes down**. Every chunk admitted that way is
//! counted, and [`VerifiedSource::stats`] reports it, so a deployment that has quietly
//! turned verification off can be seen to have done so rather than inferred.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use nau_core::image::{ChunkAttestation, ChunkDigest, SignaturePolicy};

use crate::source::{ChunkSource, SourceError};

/// What a verified source has admitted, and on what basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerificationStats {
    /// Chunks whose attestation verified.
    pub verified: usize,
    /// Chunks admitted without an attestation, under
    /// [`SignaturePolicy::AllowUnsigned`].
    pub admitted_unsigned: usize,
    /// Chunks refused for a missing or invalid attestation.
    pub refused: usize,
}

/// A source guarded by attestations.
#[derive(Debug)]
pub struct VerifiedSource<S: ChunkSource> {
    inner: S,
    attestations: BTreeMap<String, ChunkAttestation>,
    policy: SignaturePolicy,
    verified: AtomicUsize,
    admitted_unsigned: AtomicUsize,
    refused: AtomicUsize,
}

impl<S: ChunkSource> VerifiedSource<S> {
    /// Guard `inner` under `policy`.
    pub fn new(inner: S, policy: SignaturePolicy) -> Self {
        Self {
            inner,
            attestations: BTreeMap::new(),
            policy,
            verified: AtomicUsize::new(0),
            admitted_unsigned: AtomicUsize::new(0),
            refused: AtomicUsize::new(0),
        }
    }

    /// Add an attestation.
    ///
    /// Not validated here. An attestation that does not verify is refused when the chunk it
    /// names is fetched, and checking at insertion would only move the failure earlier
    /// without making it more informative — the refusal that matters is the one that stops a
    /// chunk being used, and it names the chunk.
    pub fn attest(&mut self, attestation: ChunkAttestation) {
        self.attestations
            .insert(attestation.digest.as_str().to_string(), attestation);
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> SignaturePolicy {
        self.policy
    }

    /// How many attestations are held.
    #[must_use]
    pub fn attested_count(&self) -> usize {
        self.attestations.len()
    }

    /// What this source has admitted.
    #[must_use]
    pub fn stats(&self) -> VerificationStats {
        VerificationStats {
            verified: self.verified.load(Ordering::SeqCst),
            admitted_unsigned: self.admitted_unsigned.load(Ordering::SeqCst),
            refused: self.refused.load(Ordering::SeqCst),
        }
    }

    /// The source underneath, for asserting what it was asked for.
    #[must_use]
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: ChunkSource> ChunkSource for VerifiedSource<S> {
    fn fetch(&self, digest: &ChunkDigest) -> Result<Vec<u8>, SourceError> {
        // The bytes are fetched first and the attestation checked second. The other order
        // would avoid a wasted fetch for an unattested chunk, and it would also mean that a
        // chunk which *is* attested but whose source is down reports the fetch failure --
        // which it should, because that is the failure the caller can act on.
        let bytes = self.inner.fetch(digest)?;

        match self.attestations.get(digest.as_str()) {
            Some(attestation) => match attestation.verify_for(digest) {
                Ok(()) => {
                    self.verified.fetch_add(1, Ordering::SeqCst);
                    Ok(bytes)
                }
                Err(e) => {
                    self.refused.fetch_add(1, Ordering::SeqCst);
                    Err(SourceError::Unattested(format!(
                        "{digest} arrived with an attestation that does not verify: {e}"
                    )))
                }
            },
            None => match self.policy {
                SignaturePolicy::Require => {
                    self.refused.fetch_add(1, Ordering::SeqCst);
                    Err(SourceError::Unattested(format!(
                        "{digest} has no attestation and the policy is `require`; an unsigned \
                         chunk is refused exactly like a badly signed one"
                    )))
                }
                SignaturePolicy::AllowUnsigned => {
                    self.admitted_unsigned.fetch_add(1, Ordering::SeqCst);
                    Ok(bytes)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;
    use nau_core::identity::Keypair;

    fn signer() -> Keypair {
        Keypair::from_seed(&[11_u8; 32])
    }

    /// A store holding two chunks, with an attestation for the first only.
    fn fixture() -> (VerifiedSource<MemorySource>, ChunkDigest, ChunkDigest) {
        let mut store = MemorySource::new();
        let attested = store.insert(b"the attested chunk");
        let unattested = store.insert(b"the unattested chunk");

        let mut source = VerifiedSource::new(store, SignaturePolicy::Require);
        source.attest(ChunkAttestation::sign(&signer(), &attested));
        (source, attested, unattested)
    }

    #[test]
    fn an_attested_chunk_is_admitted() {
        let (source, attested, _) = fixture();
        assert_eq!(
            source.fetch(&attested).expect("attested"),
            b"the attested chunk".to_vec()
        );
        assert_eq!(source.stats().verified, 1);
        assert_eq!(source.stats().refused, 0);
    }

    #[test]
    fn an_unattested_chunk_is_refused_under_the_default_policy() {
        // fail-closed: the absence of evidence is treated as evidence against, exactly like
        // a bad attestation. Accepting it and complaining later would be complaining after
        // the bytes are in a sandbox.
        let (source, _, unattested) = fixture();
        let err = source.fetch(&unattested).expect_err("must refuse");
        match err {
            SourceError::Unattested(why) => {
                assert!(why.contains("no attestation"), "got: {why}");
                assert!(why.contains("refused exactly like"), "got: {why}");
            }
            other => panic!("expected Unattested, got {other:?}"),
        }
        assert_eq!(source.stats().refused, 1);
        assert_eq!(source.stats().admitted_unsigned, 0);
    }

    #[test]
    fn an_attestation_that_does_not_verify_is_refused() {
        let mut store = MemorySource::new();
        let digest = store.insert(b"chunk");
        let other = ChunkDigest::of(b"a different chunk");

        let mut source = VerifiedSource::new(store, SignaturePolicy::Require);
        // Validly signed, but for something else. Stored under the digest being fetched, so
        // the lookup finds it and the digest check inside `verify_for` is what refuses it.
        let mut attestation = ChunkAttestation::sign(&signer(), &other);
        attestation.digest = digest.clone();
        source.attest(attestation);

        let err = source.fetch(&digest).expect_err("must refuse");
        assert!(format!("{err}").contains("does not verify"), "got: {err}");
        assert_eq!(source.stats().refused, 1);
        assert_eq!(source.stats().verified, 0);
    }

    #[test]
    fn an_unsigned_chunk_is_admitted_only_under_the_downgrade_and_is_counted() {
        // The deliberate downgrade has to be visible. A deployment that has quietly turned
        // verification off should be seen to have done so, not inferred.
        let mut store = MemorySource::new();
        let digest = store.insert(b"unsigned but wanted");
        let source = VerifiedSource::new(store, SignaturePolicy::AllowUnsigned);

        assert_eq!(
            source.fetch(&digest).expect("admitted"),
            b"unsigned but wanted".to_vec()
        );
        let stats = source.stats();
        assert_eq!(stats.admitted_unsigned, 1);
        assert_eq!(stats.verified, 0, "admitted is not the same as verified");
        assert_eq!(source.policy().label(), "allow-unsigned");
    }

    #[test]
    fn a_missing_chunk_is_still_reported_as_missing_not_as_unattested() {
        // The decorator must not swallow the inner source's answer. A chunk the source does
        // not have is a reason to ask elsewhere; an unattested chunk is not, because asking
        // elsewhere would produce another unattested chunk.
        let (source, _, _) = fixture();
        let err = source
            .fetch(&ChunkDigest::of(b"never stored"))
            .expect_err("absent");
        assert!(matches!(err, SourceError::Missing(_)), "got {err:?}");
        assert_eq!(
            source.stats().refused,
            0,
            "a miss is not a refusal, and counting it as one would make a sparse cache look \
             like a verification failure"
        );
    }

    #[test]
    fn the_attested_count_is_the_number_of_attestations_held() {
        let (mut source, attested, unattested) = fixture();
        assert_eq!(source.attested_count(), 1);
        source.attest(ChunkAttestation::sign(&signer(), &unattested));
        assert_eq!(source.attested_count(), 2);
        source.fetch(&attested).expect("now attested");
        source.fetch(&unattested).expect("now attested");
        assert_eq!(source.stats().verified, 2);
        assert_eq!(source.stats().refused, 0);
    }
}
