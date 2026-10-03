//! The chunk-exchange protocol: what a peer asks for, and what it may be told.
//!
//! # Why this is a value type and not a libp2p codec
//!
//! A-06 refused a P2P source because the protocol was undefined. A-07 defines it — and it
//! is defined **here**, as plain data, rather than directly as a codec, for two reasons.
//!
//! First, the protocol is the thing worth reviewing: *may a peer request an arbitrary
//! digest, what does a refusal look like, is a miss distinguishable from a refusal* are
//! questions about the exchange, not about the carriage. Answering them inside a codec
//! couples them to libp2p's types and makes them testable only with a network.
//!
//! Second, `nau-libp2p` carries **GossipSub frames**: pub/sub, no request/response. There is
//! no request/response behaviour in this workspace to hang a chunk exchange on, so the
//! carriage is a real, separate piece of work rather than a parameter.
//!
//! So: the protocol is defined and implemented here, both ends, exercised over a transport
//! port with two in-memory peers; the libp2p carriage is **not** done, and
//! [`crate::peer`] says so where a caller can read it.
//!
//! # The response is three-valued on purpose
//!
//! [`ChunkResponse::NotFound`] and [`ChunkResponse::Refused`] are different answers.
//! "I do not have this chunk" is a reason to ask someone else; "I will not serve you" is a
//! reason to stop. A protocol with a single failure response would make the client either
//! give up on a peer that simply lacks a chunk, or keep asking a peer that has refused —
//! and both are the kind of behaviour that looks like a flaky network rather than a
//! protocol defect.

use nau_core::image::ChunkDigest;

/// What a peer asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkRequest {
    /// Ask for the chunk with this content address.
    ///
    /// By digest and not by index: a peer that is asked for an index has to be trusted to
    /// resolve it against the same manifest, and a peer that is asked for a digest can only
    /// answer with bytes that hash to it or refuse.
    Get {
        /// The chunk's content address.
        digest: ChunkDigest,
    },
}

impl ChunkRequest {
    /// Ask for one chunk.
    #[must_use]
    pub fn get(digest: ChunkDigest) -> Self {
        Self::Get { digest }
    }

    /// The digest being asked for.
    #[must_use]
    pub fn digest(&self) -> &ChunkDigest {
        match self {
            ChunkRequest::Get { digest } => digest,
        }
    }
}

/// What a peer answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkResponse {
    /// Here are the bytes.
    ///
    /// The responder does not have to verify them — it is answering from its own store —
    /// and the requester must anyway: a response is exactly the thing this project does not
    /// trust, so [`crate::PeerSource`] re-hashes before returning.
    Data(Vec<u8>),
    /// I do not have this chunk. Ask elsewhere.
    NotFound,
    /// I will not serve this request, with the reason.
    ///
    /// Refusing is a first-class answer rather than an error, because a peer that has the
    /// chunk and declines to serve it is behaving correctly — it is a scheduling or policy
    /// decision, not a fault.
    Refused(String),
}

impl ChunkResponse {
    /// Whether this response means the peer lacks the chunk.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, ChunkResponse::NotFound)
    }

    /// The refusal reason, if this is a refusal.
    #[must_use]
    pub fn refusal_reason(&self) -> Option<&str> {
        match self {
            ChunkResponse::Refused(why) => Some(why.as_str()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_names_one_digest() {
        let digest = ChunkDigest::of(b"chunk");
        let request = ChunkRequest::get(digest.clone());
        assert_eq!(request.digest(), &digest);
    }

    #[test]
    fn not_found_and_refused_are_different_answers() {
        // The distinction the client's retry behaviour depends on. If these collapsed into
        // one failure response, a client would either give up on a peer that merely lacks a
        // chunk, or keep asking a peer that has refused.
        assert!(ChunkResponse::NotFound.is_not_found());
        assert!(ChunkResponse::NotFound.refusal_reason().is_none());

        let refused = ChunkResponse::Refused("over quota".to_string());
        assert!(!refused.is_not_found());
        assert_eq!(refused.refusal_reason(), Some("over quota"));

        let data = ChunkResponse::Data(vec![1, 2, 3]);
        assert!(!data.is_not_found());
        assert!(data.refusal_reason().is_none());
    }

    #[test]
    fn a_refusal_must_carry_a_reason() {
        // An empty reason is a refusal the requester cannot act on, and it is the shape a
        // stub would produce. Constructed by hand here because the type does not enforce it
        // -- what enforces it is `PeerSource`, which treats an empty reason as a protocol
        // violation rather than as a refusal.
        let empty = ChunkResponse::Refused(String::new());
        assert_eq!(empty.refusal_reason(), Some(""));
    }
}
