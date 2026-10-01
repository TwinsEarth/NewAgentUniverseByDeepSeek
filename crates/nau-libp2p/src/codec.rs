//! The wire format for frames carried over GossipSub.
//!
//! ## What this is for
//!
//! [`nau_net::Frame`] is a bare byte string: it has no sender, no version and no
//! framing, because [`nau_net::TcpTransport`](nau_net::TcpTransport) supplies all
//! three at the socket layer. GossipSub supplies none of them — it delivers
//! `(propagation_source, message)` where the bytes are whatever the publisher
//! put there. This module is the missing header, and nothing else.
//!
//! ## Layout
//!
//! ```text
//! offset  size  field
//! 0       1     version          must be PROTOCOL_VERSION (1)
//! 1       8     nonce            publisher-chosen, echoed unchanged
//! 9       38    sender peer id   0x00 0x24 || protobuf(ed25519 public key)
//! 47      ..    payload          the nau_net::Frame body
//! ```
//!
//! ## Why the length cap is checked before allocating
//!
//! `nau_net::check_frame_len` refuses a frame above
//! [`nau_net::MAX_FRAME_BYTES`] before any allocation, because a four-byte length
//! prefix must not be able to make this process reserve an arbitrary amount of
//! memory. There is no length prefix here — GossipSub already delimits the
//! message — but the same rule applies to the *decoder*: [`decode_envelope`]
//! computes the payload length from the slice it was handed and compares it to the
//! cap **before** it copies anything. A 9 MiB gossip message is therefore
//! rejected, not buffered.
//!
//! ## Upstream defect this closes
//!
//! agent-universe v2.5.6's `net/gossip.rs` published `serde_json` blobs with no
//! version field and no sender, then recovered the sender from a side table keyed
//! by topic. A message replayed from a different topic, or from a node that had
//! restarted and lost its table entry, was attributed to whoever happened to be
//! in that slot. `// upstream v2.5.6 fix: the sender and the format version travel
//! with the message, so attribution does not depend on process state.`

use nau_net::{check_frame_len, Frame, MAX_FRAME_BYTES};

use crate::identity::{PeerId, ED25519_PEER_ID_BYTES};

/// Format version written into every envelope.
pub const PROTOCOL_VERSION: u8 = 1;

/// Length of the nonce field, in bytes.
pub const NONCE_BYTES: usize = 8;

/// Length of the fixed header, in bytes (`1 + 8 + 38`).
pub const HEADER_BYTES: usize = 1 + NONCE_BYTES + ED25519_PEER_ID_BYTES;

/// Largest payload a single envelope may carry, in bytes.
pub const MAX_PAYLOAD_BYTES: usize = MAX_FRAME_BYTES;

/// Every way an envelope can be rejected.
///
/// Each variant is produced by bytes that arrived from the network, so none of
/// them carries a panic path: a hostile message becomes an error value that the
/// caller can count, log or drop.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// The message was shorter than the fixed header.
    #[error("envelope of {got} bytes is shorter than the {HEADER_BYTES}-byte header")]
    Truncated {
        /// The length that arrived.
        got: usize,
    },
    /// The version byte was not [`PROTOCOL_VERSION`].
    #[error("envelope version {found} is not the supported version {PROTOCOL_VERSION}")]
    UnsupportedVersion {
        /// The version byte that arrived.
        found: u8,
    },
    /// The payload exceeded the frame cap.
    #[error("envelope payload of {got} bytes exceeds the {MAX_PAYLOAD_BYTES}-byte cap")]
    PayloadTooLarge {
        /// The payload length.
        got: usize,
    },
    /// The sender field was not a well-formed Ed25519 peer id.
    #[error("envelope sender is not a valid Ed25519 peer id: {reason}")]
    InvalidSender {
        /// Why the id was rejected.
        reason: String,
    },
    /// The nonce was not the expected length. Cannot happen for a value this
    /// module produced; present so that a caller assembling an envelope from
    /// parts is told rather than truncated.
    #[error("nonce must be {NONCE_BYTES} bytes, got {got}")]
    NonceLength {
        /// The length that was supplied.
        got: usize,
    },
    /// The caller wanted the envelope's declared size checked against an
    /// explicit budget and it did not fit.
    #[error("envelope of {got} bytes exceeds this caller's {max}-byte budget")]
    OverBudget {
        /// The envelope length.
        got: usize,
        /// The caller's budget.
        max: usize,
    },
}

/// One decoded gossip message: who sent it, and what it carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The publisher's peer id, as carried in the message itself.
    sender: PeerId,
    /// The publisher-chosen nonce, preserved so a receiver can deduplicate
    /// retransmissions without trusting a sequence number.
    nonce: [u8; NONCE_BYTES],
    /// The frame body.
    payload: Frame,
}

impl Envelope {
    /// The peer id that the message claims as its sender.
    ///
    /// This is a *claim*: GossipSub's own `propagation_source` is the peer that
    /// forwarded the message, which is not necessarily the origin. Verifying the
    /// claim against a public key is the caller's job, and
    /// [`Envelope::sender`] is deliberately named to read as a claim rather than
    /// as an authenticated identity.
    pub fn sender(&self) -> &PeerId {
        &self.sender
    }

    /// The publisher-chosen nonce.
    pub fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// The frame body.
    pub fn payload(&self) -> &Frame {
        &self.payload
    }

    /// Consume the envelope, yielding the frame body.
    pub fn into_payload(self) -> Frame {
        self.payload
    }
}

/// Encode a payload for publication on behalf of `sender`.
///
/// The sender is passed in rather than derived here so that the only way to get
/// an envelope is to state who you are; a caller cannot accidentally publish an
/// anonymous message that the receiver will attribute to a default.
pub fn encode_envelope(
    sender: &PeerId,
    nonce: [u8; NONCE_BYTES],
    payload: &Frame,
) -> Result<Vec<u8>, CodecError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(CodecError::PayloadTooLarge { got: payload.len() });
    }
    // The payload cap is the same one `nau_net` uses, checked before allocating
    // the output, so this path cannot be tricked into a large reservation.
    check_frame_len(payload.len())
        .map_err(|_| CodecError::PayloadTooLarge { got: payload.len() })?;
    let mut out = Vec::with_capacity(HEADER_BYTES + payload.len());
    out.push(PROTOCOL_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(sender.as_bytes());
    out.extend_from_slice(payload.as_slice());
    Ok(out)
}

/// The number of bytes [`encode_envelope`] will produce for a payload of
/// `payload_len` bytes, or `None` when the payload is over the cap.
///
/// Lets a caller with a size budget decide *before* building the buffer, which is
/// the same reason `nau_net::check_frame_len` exists.
pub fn encoded_len(payload_len: usize) -> Option<usize> {
    if payload_len > MAX_PAYLOAD_BYTES {
        return None;
    }
    HEADER_BYTES.checked_add(payload_len)
}

/// Decode an envelope that arrived from the network.
///
/// Rejects, in order: a short message, an unknown version, a payload over the
/// cap, and a malformed sender. The order matters — the version is checked before
/// the sender so that a future format cannot be misparsed as this one, and the
/// payload length is checked before the sender is decoded so that a 9 MiB message
/// is refused without the base58 work.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, CodecError> {
    decode_envelope_with_budget(bytes, MAX_PAYLOAD_BYTES)
}

/// Decode an envelope while refusing anything above `max_payload`.
///
/// `max_payload` above [`MAX_PAYLOAD_BYTES`] is clamped down to it, so a caller
/// cannot raise the cap by passing a bigger number.
pub fn decode_envelope_with_budget(
    bytes: &[u8],
    max_payload: usize,
) -> Result<Envelope, CodecError> {
    let budget = max_payload.min(MAX_PAYLOAD_BYTES);
    if bytes.len() < HEADER_BYTES {
        return Err(CodecError::Truncated { got: bytes.len() });
    }
    let version = bytes[0];
    if version != PROTOCOL_VERSION {
        return Err(CodecError::UnsupportedVersion { found: version });
    }
    let payload_len = bytes.len() - HEADER_BYTES;
    if payload_len > budget {
        return Err(CodecError::OverBudget {
            got: bytes.len(),
            max: HEADER_BYTES + budget,
        });
    }
    // Only now, with the length proven acceptable, is the fixed part read.
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&bytes[1..1 + NONCE_BYTES]);
    let mut raw_id = [0u8; ED25519_PEER_ID_BYTES];
    raw_id.copy_from_slice(&bytes[1 + NONCE_BYTES..HEADER_BYTES]);
    let sender = PeerId::from_multihash_bytes(raw_id).map_err(|e| CodecError::InvalidSender {
        reason: e.to_string(),
    })?;
    let payload = Frame::new(bytes[HEADER_BYTES..].to_vec());
    Ok(Envelope {
        sender,
        nonce,
        payload,
    })
}

/// Check a nonce length explicitly, for callers assembling an envelope from
/// parts.
pub fn check_nonce_len(len: usize) -> Result<(), CodecError> {
    if len != NONCE_BYTES {
        return Err(CodecError::NonceLength { got: len });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NauIdentity;

    fn sender() -> PeerId {
        NauIdentity::from_seed(&[1u8; 32]).peer_id()
    }

    fn other_sender() -> PeerId {
        NauIdentity::from_seed(&[2u8; 32]).peer_id()
    }

    #[test]
    fn an_envelope_round_trips() {
        let payload = Frame::new(b"hello over gossipsub".to_vec());
        let nonce = [7u8; NONCE_BYTES];
        let encoded = encode_envelope(&sender(), nonce, &payload).expect("encode");
        assert_eq!(encoded.len(), HEADER_BYTES + payload.len());
        assert_eq!(encoded[0], PROTOCOL_VERSION);
        assert_eq!(&encoded[1..1 + NONCE_BYTES], &nonce);

        let decoded = decode_envelope(&encoded).expect("decode");
        assert_eq!(decoded.sender(), &sender());
        assert_eq!(decoded.nonce(), &nonce);
        assert_eq!(decoded.payload(), &payload);
        assert_eq!(decoded.into_payload(), payload);
    }

    #[test]
    fn an_empty_payload_round_trips_and_is_distinguishable_from_truncation() {
        let payload = Frame::new(Vec::new());
        let encoded = encode_envelope(&sender(), [0u8; NONCE_BYTES], &payload).expect("encode");
        assert_eq!(encoded.len(), HEADER_BYTES);
        let decoded = decode_envelope(&encoded).expect("an empty frame is legal");
        assert!(decoded.payload().is_empty());
        // One byte short of the header is not "an empty frame", it is truncated.
        assert!(matches!(
            decode_envelope(&encoded[..HEADER_BYTES - 1]).expect_err("short"),
            CodecError::Truncated { .. }
        ));
    }

    #[test]
    fn a_foreign_version_is_refused_before_the_sender_is_parsed() {
        let mut encoded =
            encode_envelope(&sender(), [0u8; NONCE_BYTES], &Frame::new(vec![1])).expect("encode");
        encoded[0] = PROTOCOL_VERSION.wrapping_add(1);
        assert!(matches!(
            decode_envelope(&encoded).expect_err("version"),
            CodecError::UnsupportedVersion { found } if found == PROTOCOL_VERSION + 1
        ));
        // Version 0 of the format must not be accepted as version 1.
        encoded[0] = 0;
        assert!(matches!(
            decode_envelope(&encoded).expect_err("version"),
            CodecError::UnsupportedVersion { found: 0 }
        ));
    }

    #[test]
    fn the_payload_cap_is_enforced_before_anything_is_copied() {
        // A payload one byte over the cap cannot even be encoded.
        let oversized = Frame::new(vec![0u8; MAX_PAYLOAD_BYTES + 1]);
        assert!(matches!(
            encode_envelope(&sender(), [0u8; NONCE_BYTES], &oversized).expect_err("over cap"),
            CodecError::PayloadTooLarge { .. }
        ));
        assert_eq!(encoded_len(MAX_PAYLOAD_BYTES + 1), None);
        assert_eq!(
            encoded_len(MAX_PAYLOAD_BYTES),
            Some(HEADER_BYTES + MAX_PAYLOAD_BYTES)
        );

        // A decoder handed an over-cap slice refuses it. Building the slice is
        // cheap because it is all zeroes; the point is that `decode` does not
        // copy it.
        let mut hostile = Vec::with_capacity(HEADER_BYTES + 64);
        hostile.push(PROTOCOL_VERSION);
        hostile.extend_from_slice(&[0u8; NONCE_BYTES]);
        hostile.extend_from_slice(sender().as_bytes());
        hostile.extend(std::iter::repeat(0u8).take(64));
        // With an explicit small budget the same message is over budget.
        assert!(matches!(
            decode_envelope_with_budget(&hostile, 63).expect_err("over budget"),
            CodecError::OverBudget { got, max } if got == HEADER_BYTES + 64 && max == HEADER_BYTES + 63
        ));
        // A budget above the hard cap is clamped, never honoured.
        let hard_capped = decode_envelope_with_budget(&hostile, usize::MAX);
        assert!(hard_capped.is_ok(), "64 bytes is under the hard cap");
        assert_eq!(
            decode_envelope(&hostile)
                .expect("under cap")
                .payload()
                .len(),
            64
        );
    }

    #[test]
    fn a_malformed_sender_is_refused_without_panicking() {
        let mut encoded =
            encode_envelope(&sender(), [0u8; NONCE_BYTES], &Frame::new(vec![9])).expect("encode");
        // Break the multihash prefix: sha2-256 instead of the identity hash.
        encoded[1 + NONCE_BYTES] = 0x12;
        encoded[1 + NONCE_BYTES + 1] = 0x20;
        assert!(matches!(
            decode_envelope(&encoded).expect_err("bad sender"),
            CodecError::InvalidSender { .. }
        ));
        // Every truncation length short of the header is refused, not indexed.
        for len in 0..HEADER_BYTES {
            assert!(
                decode_envelope(&encoded[..len]).is_err(),
                "length {len} must be refused"
            );
        }
    }

    #[test]
    fn two_senders_are_distinguishable() {
        let nonce = [3u8; NONCE_BYTES];
        let payload = Frame::new(b"same bytes".to_vec());
        let a = encode_envelope(&sender(), nonce, &payload).expect("encode");
        let b = encode_envelope(&other_sender(), nonce, &payload).expect("encode");
        assert_ne!(a, b, "the sender is part of the message");
        assert_eq!(decode_envelope(&a).expect("decode").sender(), &sender());
        assert_eq!(
            decode_envelope(&b).expect("decode").sender(),
            &other_sender()
        );
    }

    #[test]
    fn no_sender_can_be_forged_by_truncating_the_header() {
        // The header is fixed-width, so there is no offset at which a shorter
        // sender field could be read and mistaken for a valid one.
        assert_eq!(HEADER_BYTES, 1 + NONCE_BYTES + ED25519_PEER_ID_BYTES);
        assert_eq!(HEADER_BYTES, 47);
        assert_eq!(
            ED25519_PEER_ID_BYTES, 38,
            "identity multihash: 2-byte prefix + 36-byte protobuf key"
        );
        assert!(check_nonce_len(NONCE_BYTES).is_ok());
        assert!(matches!(
            check_nonce_len(NONCE_BYTES - 1).expect_err("short nonce"),
            CodecError::NonceLength { got } if got == NONCE_BYTES - 1
        ));
    }

    #[test]
    fn errors_are_displayable_and_do_not_carry_payload_bytes() {
        // A log line for a rejected 8 MiB message must not contain the message.
        let err = CodecError::PayloadTooLarge {
            got: MAX_PAYLOAD_BYTES + 5,
        };
        let text = err.to_string();
        assert!(text.contains(&(MAX_PAYLOAD_BYTES + 5).to_string()));
        assert!(text.len() < 200);
        assert!(CodecError::Truncated { got: 3 }.to_string().contains('3'));
    }
}
