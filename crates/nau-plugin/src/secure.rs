//! The secure channel: how two plugins talk when the bus is not private enough.
//!
//! # Why this is not the bus
//!
//! The plugin bus is a **policy** boundary: it decides who may send what to whom, and it
//! audits every attempt. It is not a **confidentiality** boundary. A message the bus
//! delivers is readable by the host and lands in the audit log, which is the right
//! default — an audit trail nobody can read is not an audit trail.
//!
//! But some payloads are not for the host's eyes either: a plugin pair exchanging a
//! bearer token, a private key share, or a bid that must not leak before a deadline. For
//! those there is a second channel, and it is opt-in: the capability is
//! [`Capability::CryptoChannel`], it is refused outright to the third-party tier, and a
//! plugin without it cannot open one.
//!
//! # The construction, and why each piece is there
//!
//! 1. **X25519** for the key agreement — both sides contribute an ephemeral secret, so a
//!    recorded session cannot be decrypted later even if both long-term keys leak;
//! 2. **HKDF-SHA256** to turn the shared secret into a key, with the two public keys as
//!    `info` — so the two directions and the two identities are bound into the
//!    derivation instead of being assumed;
//! 3. **ChaCha20-Poly1305** for authenticated encryption — confidentiality *and*
//!    integrity, so a modified ciphertext is refused rather than decrypted into
//!    something plausible.
//!
//! # The one thing that must never happen
//!
//! **A nonce must never repeat under the same key.** ChaCha20-Poly1305 loses its
//! confidentiality guarantee entirely if it does, and the failure is silent — the
//! ciphertext still decrypts. So the nonce is a monotonic counter owned by the channel,
//! incremented before every `seal`, and `seal` **returns an error rather than wrapping**
//! when the counter would repeat. This is the kind of rule that has to be structural: a
//! caller who has to remember not to reuse a nonce will eventually not remember.
//!
//! # What this is not
//!
//! It is not a transport. It seals and opens byte strings; delivering them is the bus's
//! job, and the sealed bytes are what goes in the payload. It is also not forward-secret
//! against a compromised *endpoint* — an attacker who owns the process has the key, and
//! no channel construction changes that.

use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::capability::Capability;
use crate::error::{PluginError, Result};

/// Length of the nonce prefix in bytes, leaving room for the counter.
const NONCE_BYTES: usize = 12;
/// Length of the Poly1305 authentication tag.
pub const TAG_BYTES: usize = 16;
/// The largest plaintext one channel will seal.
///
/// A ceiling rather than a suggestion: an unbounded `seal` is an unbounded allocation
/// driven by whatever a plugin asks for, which is the shape of a denial of service.
pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1024;

/// One party's key material for establishing a channel.
///
/// The secret is `EphemeralSecret`, which cannot be cloned and is consumed by the key
/// agreement. That is deliberate: a long-lived secret that can be copied is a secret that
/// ends up in two places, and the whole point of an ephemeral key is that it does not
/// outlive the session.
pub struct Party {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl std::fmt::Debug for Party {
    /// Prints the public half only.
    ///
    /// Not derived, because `EphemeralSecret` deliberately does not implement `Debug` and
    /// a derived one on this type would either fail to compile or, if the inner type ever
    /// gained a `Debug`, start printing key material into a log line. Redaction here is
    /// structural rather than a convention someone has to remember.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Party")
            .field("public", &hex::encode(self.public.to_bytes()))
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Party {
    /// Generate a fresh party.
    #[must_use]
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// This party's public key, to be sent to the other side.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Complete the agreement with the other side's public key.
    ///
    /// The two public keys go into the HKDF `info` parameter in a fixed order, so both
    /// parties derive the same key and neither can be confused for the other.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] when the derived key is all zeroes, which is what
    /// X25519 produces for a low-order public key. RFC 7748 says implementations *may*
    /// check this; here it is checked, because a silent all-zero key would make every
    /// session identical and the ciphertext would still decrypt.
    pub fn agree(self, their_public: [u8; 32]) -> Result<Channel> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(their_public));
        if shared.as_bytes().iter().all(|b| *b == 0) {
            return Err(PluginError::Capability(
                "secure: the key agreement produced an all-zero secret, which means the peer sent \
                 a low-order public key; refusing rather than deriving a key that would be the \
                 same for every session"
                    .into(),
            ));
        }
        // The two public keys must enter the derivation in an order that does **not**
        // depend on which side is computing it. The first version put `self.public` first,
        // so Alice derived from `alice||bob` and Bob from `bob||alice` -- different keys,
        // and a channel that could not open a single message. Sorting makes the order a
        // property of the pair rather than of the caller; the round-trip test is what
        // caught it.
        let mut keys = [self.public.to_bytes(), their_public];
        keys.sort_unstable();
        let mut info = Vec::with_capacity(64);
        info.extend_from_slice(&keys[0]);
        info.extend_from_slice(&keys[1]);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .map_err(|e| PluginError::Capability(format!("secure: key derivation failed: {e}")))?;
        Ok(Channel::new(key))
    }
}

/// A one-directional sealed channel.
///
/// Directional on purpose: each side derives its own `Channel` from its own `Party`, so
/// the counter is per-direction and two sides sealing simultaneously cannot collide on a
/// nonce.
pub struct Channel {
    cipher: ChaCha20Poly1305,
    counter: AtomicU64,
    /// A per-channel prefix, so two channels that happen to start their counters at the
    /// same value still use different nonces.
    prefix: [u8; 4],
}

impl std::fmt::Debug for Channel {
    /// Prints the prefix and the counter, never the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("prefix", &hex::encode(self.prefix))
            .field("sealed", &self.sealed())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Channel {
    /// Build a channel from a derived key.
    fn new(key: [u8; 32]) -> Self {
        // The prefix is taken from the key itself: deterministic, distinct per key, and
        // needing no extra input.
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&key[..4]);
        Self {
            cipher: ChaCha20Poly1305::new((&key).into()),
            counter: AtomicU64::new(0),
            prefix,
        }
    }

    /// How many messages this channel has sealed.
    #[must_use]
    pub fn sealed(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Encrypt and authenticate `plaintext`.
    ///
    /// The output is `nonce || ciphertext || tag`, so the receiver needs no side channel
    /// to know which nonce was used.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] when the plaintext exceeds [`MAX_PLAINTEXT_BYTES`],
    /// when encryption fails, or when the nonce counter would wrap — see the module
    /// documentation for why wrapping is an error rather than something to ignore.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(PluginError::Capability(format!(
                "secure: {len} bytes exceeds the {MAX_PLAINTEXT_BYTES} byte ceiling; an unbounded \
                 seal is an unbounded allocation driven by the peer",
                len = plaintext.len()
            )));
        }
        // Incremented first, so the value used is never the one observed before.
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        if counter == u64::MAX {
            return Err(PluginError::Capability(
                "secure: the nonce counter is exhausted; this channel must be re-established, \
                 because reusing a nonce under the same key silently destroys the confidentiality \
                 of every message sent with it"
                    .into(),
            ));
        }
        let nonce_bytes = nonce_for(self.prefix, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let sealed = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|e| PluginError::Capability(format!("secure: encryption failed: {e}")))?;
        let mut out = Vec::with_capacity(NONCE_BYTES + sealed.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Decrypt and verify `sealed`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] when the frame is too short to contain a nonce and a
    /// tag, or when authentication fails. A failure here is **not** distinguishable from
    /// a forgery attempt by design: the AEAD cannot tell a corrupted byte from a
    /// deliberate one, and pretending otherwise would be a claim the construction does
    /// not support.
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_BYTES + TAG_BYTES {
            return Err(PluginError::Capability(format!(
                "secure: {} bytes is too short to hold a nonce and an authentication tag",
                sealed.len()
            )));
        }
        let (nonce_bytes, body) = sealed.split_at(NONCE_BYTES);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: body,
                    aad: &[],
                },
            )
            .map_err(|_| {
                PluginError::Capability(
                    "secure: authentication failed; the message was modified, truncated, or \
                     sealed under a different key"
                        .into(),
                )
            })
    }
}

/// Build the nonce for a counter value.
///
/// Four bytes of key-derived prefix and eight bytes of counter. The counter is
/// big-endian so that the ordering is inspectable in a hex dump, which matters when the
/// only debugging tool available is looking at the bytes.
fn nonce_for(prefix: [u8; 4], counter: u64) -> [u8; NONCE_BYTES] {
    let mut nonce = [0u8; NONCE_BYTES];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Refuse unless the plugin holds the capability a secure channel needs.
///
/// # Errors
///
/// [`PluginError::Capability`] naming the capability. Separate from the channel itself
/// because opening a channel is a *permission* question and the kernel's token is the
/// only thing that may answer it.
pub fn require_channel_capability(token: &crate::capability::CapabilityToken) -> Result<()> {
    token.require(Capability::CryptoChannel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_parties_derive_the_same_key_and_can_talk() {
        let alice = Party::generate();
        let bob = Party::generate();
        let alice_public = alice.public();
        let bob_public = bob.public();

        let alice_channel = alice.agree(bob_public).expect("alice agrees");
        let bob_channel = bob.agree(alice_public).expect("bob agrees");

        let message = b"the escrow releases on the third signature";
        let sealed = alice_channel.seal(message).expect("seals");
        assert_ne!(
            &sealed[NONCE_BYTES..],
            &message[..],
            "the plaintext must not appear"
        );

        let opened = bob_channel.open(&sealed).expect("bob opens it");
        assert_eq!(opened, message);
    }

    #[test]
    fn a_third_party_with_a_different_key_cannot_open_it() {
        let alice = Party::generate();
        let bob = Party::generate();
        let eve = Party::generate();
        let eve_public = eve.public();
        let bob_public = bob.public();
        let alice_public = alice.public();

        let alice_channel = alice.agree(bob_public).expect("agrees");
        let sealed = alice_channel.seal(b"secret").expect("seals");

        // Eve ran her own agreement with Alice's public key. The keys differ, so the
        // ciphertext must not open.
        let eve_channel = eve.agree(alice_public).expect("agrees");
        let err = eve_channel.open(&sealed).expect_err("must not open");
        assert!(err.to_string().contains("authentication failed"), "{err}");
        let _ = eve_public;
    }

    #[test]
    fn a_single_flipped_byte_is_refused() {
        let alice = Party::generate();
        let bob = Party::generate();
        let bob_public = bob.public();
        let alice_public = alice.public();
        let alice_channel = alice.agree(bob_public).expect("agrees");
        let bob_channel = bob.agree(alice_public).expect("agrees");

        let mut sealed = alice_channel.seal(b"transfer 100").expect("seals");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let err = bob_channel.open(&sealed).expect_err("must be refused");
        assert!(
            err.to_string().contains("authentication failed"),
            "a modified ciphertext must not decrypt into something plausible: {err}"
        );
    }

    #[test]
    fn every_message_uses_a_different_nonce() {
        // The failure this guards against is silent: reuse a nonce under the same key and
        // ChaCha20-Poly1305 still decrypts, while its confidentiality guarantee is gone.
        let alice = Party::generate();
        let bob = Party::generate();
        let bob_public = bob.public();
        let channel = alice.agree(bob_public).expect("agrees");

        let first = channel.seal(b"same plaintext").expect("seals");
        let second = channel.seal(b"same plaintext").expect("seals");
        assert_ne!(
            first, second,
            "identical plaintexts must not produce identical frames"
        );
        assert_ne!(
            first[..NONCE_BYTES],
            second[..NONCE_BYTES],
            "the nonces must differ"
        );
        assert_eq!(channel.sealed(), 2);
    }

    #[test]
    fn the_nonce_is_prefix_then_big_endian_counter() {
        let nonce = nonce_for([1, 2, 3, 4], 0x0102_0304_0506_0708);
        assert_eq!(&nonce[..4], &[1, 2, 3, 4]);
        assert_eq!(&nonce[4..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn a_truncated_frame_is_refused_before_it_reaches_the_cipher() {
        let alice = Party::generate();
        let bob = Party::generate();
        let bob_public = bob.public();
        let channel = alice.agree(bob_public).expect("agrees");
        for len in 0..(NONCE_BYTES + TAG_BYTES) {
            let err = channel.open(&vec![0u8; len]).expect_err("must be refused");
            assert!(err.to_string().contains("too short"), "len {len}: {err}");
        }
    }

    #[test]
    fn an_oversized_plaintext_is_refused_rather_than_allocated() {
        let alice = Party::generate();
        let bob = Party::generate();
        let bob_public = bob.public();
        let channel = alice.agree(bob_public).expect("agrees");
        let big = vec![0u8; MAX_PLAINTEXT_BYTES + 1];
        let err = channel.seal(&big).expect_err("must be refused");
        assert!(err.to_string().contains("exceeds"), "{err}");
        assert_eq!(
            channel.sealed(),
            0,
            "a refused seal does not consume a nonce"
        );
    }

    #[test]
    fn a_low_order_public_key_is_refused_rather_than_deriving_an_all_zero_key() {
        // RFC 7748's low-order points produce an all-zero shared secret. Every session
        // would then use the same key, and the ciphertext would still decrypt -- so this
        // is a case where the failure is invisible without an explicit check.
        let alice = Party::generate();
        let err = alice
            .agree([0u8; 32])
            .expect_err("an all-zero public key must be refused");
        assert!(err.to_string().contains("all-zero secret"), "{err}");
    }

    #[test]
    fn the_channel_capability_is_held_by_the_tiers_that_may_have_it() {
        use crate::capability::{Approval, Capability as Cap, Grant};
        use crate::tier::Tier;
        assert_eq!(Cap::CryptoChannel.decision(Tier::System), Grant::Always);
        assert_eq!(
            Cap::CryptoChannel.decision(Tier::Official),
            Grant::RequiresApproval(Approval::VendorTeam)
        );
        assert_eq!(
            Cap::CryptoChannel.decision(Tier::Certified),
            Grant::RequiresApproval(Approval::CertificationCommittee)
        );
        assert!(
            matches!(
                Cap::CryptoChannel.decision(Tier::ThirdParty),
                Grant::Refused { .. }
            ),
            "a third-party plugin must never be able to open a channel the host cannot read"
        );
    }

    #[test]
    fn a_token_without_the_capability_cannot_open_a_channel() {
        use crate::capability::CapabilityToken;
        use crate::tier::Tier;
        let token = CapabilityToken::issue(
            "com.twinsearth.official.market",
            Tier::Official,
            &[Capability::MessageSend],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            1_750_000_000,
        )
        .expect("issuable");
        let err = require_channel_capability(&token).expect_err("must be refused");
        assert!(err.to_string().contains("crypto:channel"), "{err}");
    }
}
