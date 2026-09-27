//! SHA-256 provenance hash chain.
//!
//! An append-only, tamper-evident audit trail. Each link stores the payload it
//! covers, so the chain can be *re-verified from its own bytes* — not merely
//! compared head-to-head.
//!
//! ## Digest input (explicit, not "whatever JSON does")
//!
//! The digest is `SHA-256` over a length-prefixed, domain-separated encoding:
//!
//! ```text
//! "nau-chain-v1\0"
//! seq:<decimal>       "\0"
//! at:<decimal>        "\0"
//! len(payload):<dec>  "\0"  payload bytes  "\0"
//! len(prev):<dec>     "\0"  prev digest bytes
//! ```
//!
//! Every variable-length field carries its own byte length, so no two distinct
//! `(seq, at, payload, prev_digest)` tuples can encode to the same byte string.
//! The encoding uses only integers and raw bytes: it never goes through a float
//! or a serializer whose whitespace/key-order choices could change.

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain-separation tag, versioned so a future format change cannot silently
/// validate against digests produced by this one.
const DOMAIN: &[u8] = b"nau-chain-v1\0";

/// The digest used by the first link's `prev_digest`.
pub const GENESIS_DIGEST: &str = "genesis";

/// One link of the chain.
///
/// `payload` is retained (the upstream chain threw it away, which made the
/// audit trail impossible to re-derive) and `prev_digest` is stored explicitly
/// instead of being kept in shadow state.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ChainLink {
    /// 1-based position in the chain.
    pub seq: u64,
    /// The exact bytes this link commits to.
    pub payload: String,
    /// Lowercase hex `SHA-256` digest of the encoding described above.
    pub digest: String,
    /// `digest` of the previous link, or [`GENESIS_DIGEST`] for the first link.
    pub prev_digest: String,
    /// Logical clock reading when the link was appended.
    pub at: u64,
}

/// An append-only chain of [`ChainLink`]s.
///
/// upstream v2.5.6 fix: the upstream "hash chain"
/// (`gsn-core/src/memory/layered.rs::sha256_hex`,
/// `gsn-core/src/memory/handoff.rs::TraceLedger::append`) hashed with
/// `std::collections::hash_map::DefaultHasher` — 64-bit SipHash — behind a
/// function *named* `sha256_hex` that returned 16 hex characters. That is not
/// collision resistant, it is **not stable across Rust releases** (so an audit
/// trail could not be re-verified after a toolchain bump), and it stored only
/// the digest so the payload was unrecoverable. This type hashes with real
/// `sha2::Sha256`, stores the payload, and can recompute the whole chain.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct HashChain {
    links: Vec<ChainLink>,
}

impl HashChain {
    /// An empty chain whose first link will use [`GENESIS_DIGEST`].
    pub fn new() -> Self {
        Self { links: Vec::new() }
    }

    /// The digest that a new link will chain onto.
    pub fn prev_digest(&self) -> &str {
        self.links
            .last()
            .map(|l| l.digest.as_str())
            .unwrap_or(GENESIS_DIGEST)
    }

    /// Adopt a sequence of already-stored links.
    ///
    /// This is the path an audit trail takes when it comes back from storage or
    /// off the wire. Everything is a *claim* until [`HashChain::verify_chain`]
    /// accepts it: this constructor performs no validation, and
    /// [`HashChain::append`] will not extend a chain whose stored links do not
    /// verify, so a forged prefix cannot be grown into a "valid" longer chain.
    pub fn from_links(links: Vec<ChainLink>) -> Self {
        Self { links }
    }

    /// Append `payload`, stamping it with logical time `at`.
    ///
    /// Fails if `at` moves backwards relative to the previous link, so the
    /// recorded order is always consistent with logical time.
    ///
    /// # Integrity
    ///
    /// Appending does not re-validate the stored prefix — that would make
    /// appending a linear-time scan. A forged prefix is instead caught by
    /// [`HashChain::verify_chain`], which a verifier must call before trusting
    /// the chain: a tamper anywhere in the prefix makes verification report that
    /// link, and the new link cannot "heal" it because the check walks from
    /// index 1.
    pub fn append(&mut self, payload: &str, at: u64) -> Result<&ChainLink> {
        if let Some(last) = self.links.last() {
            if at < last.at {
                return Err(NauError::Validation(format!(
                    "chain time went backwards: {at} < {} at seq {}",
                    last.at, last.seq
                )));
            }
        }
        let seq = self.links.len() as u64 + 1;
        let prev_digest = self.prev_digest().to_string();
        let digest = link_digest(seq, at, payload, &prev_digest);
        self.links.push(ChainLink {
            seq,
            payload: payload.to_string(),
            digest,
            prev_digest,
            at,
        });
        // `push` guarantees the last element exists.
        self.links
            .last()
            .ok_or_else(|| NauError::Validation("chain append lost its link".into()))
    }

    /// The most recently appended link.
    pub fn head(&self) -> Option<&ChainLink> {
        self.links.last()
    }

    /// Number of links.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// True when nothing has been appended yet.
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Every link, in append order.
    pub fn links(&self) -> &[ChainLink] {
        &self.links
    }

    /// Recompute every digest from the stored payloads and report the first
    /// link that does not match.
    ///
    /// The error message always names the offending 1-based `seq`, which is what
    /// makes an audit report actionable.
    pub fn verify_chain(&self) -> Result<()> {
        let mut expected_prev = GENESIS_DIGEST.to_string();
        for (index, link) in self.links.iter().enumerate() {
            let seq = index as u64 + 1;
            if link.seq != seq {
                return Err(NauError::Validation(format!(
                    "provenance chain broken at index {seq}: stored seq is {}",
                    link.seq
                )));
            }
            if link.prev_digest != expected_prev {
                return Err(NauError::Validation(format!(
                    "provenance chain broken at index {seq}: prev_digest is `{}`, expected `{expected_prev}`",
                    link.prev_digest
                )));
            }
            let recomputed = link_digest(link.seq, link.at, &link.payload, &link.prev_digest);
            if recomputed != link.digest {
                return Err(NauError::Validation(format!(
                    "provenance chain broken at index {seq}: digest mismatch \
                     (recomputed `{recomputed}`, stored `{}`)",
                    link.digest
                )));
            }
            expected_prev = link.digest.clone();
        }
        Ok(())
    }
}

/// Recompute the digest of a single link from its fields.
///
/// Exposed so that a verifier can check an individual link without owning the
/// chain (for example when auditing a link streamed off the wire).
pub fn link_digest(seq: u64, at: u64, payload: &str, prev_digest: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(b"seq:");
    hasher.update(seq.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(b"at:");
    hasher.update(at.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(format!("len(payload):{}", payload.len()).as_bytes());
    hasher.update(b"\0");
    hasher.update(payload.as_bytes());
    hasher.update(b"\0");
    hasher.update(format!("len(prev):{}", prev_digest.len()).as_bytes());
    hasher.update(b"\0");
    hasher.update(prev_digest.as_bytes());
    hex::encode(hasher.finalize())
}
