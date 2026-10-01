//! Peer identifiers and transport frames.

use std::fmt;
use std::str::FromStr;

use nau_core::{NauError, Result};

/// Longest accepted peer id, in bytes.
pub const MAX_PEER_ID_LEN: usize = 255;

/// An opaque, non-empty identifier for a remote endpoint.
///
/// The id is a *label*, not a cryptographic identity: this layer carries no
/// handshake, so [`TcpTransport`](crate::TcpTransport) labels a connection with
/// the observed socket address (`tcp://127.0.0.1:54321`) while
/// [`MemoryTransport`](crate::MemoryTransport) labels it with whatever the test
/// chooses. Binding a socket address to a DID is the job of a higher layer.
///
/// Accepted characters are ASCII letters, digits, and `- _ . : /`, so both opaque
/// tokens and `tcp://host:port` forms are valid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(String);

impl PeerId {
    /// Validate and wrap an identifier.
    ///
    /// Rejects the empty string, anything longer than [`MAX_PEER_ID_LEN`], and
    /// anything containing whitespace or non-ASCII characters — a peer id ends
    /// up in log lines and in map keys, and an unvalidated one is how a
    /// "peer" becomes a log-injection or a path-traversal.
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(NauError::Validation("peer id must not be empty".into()));
        }
        if s.len() > MAX_PEER_ID_LEN {
            return Err(NauError::Validation(format!(
                "peer id of {} bytes exceeds the {MAX_PEER_ID_LEN}-byte limit",
                s.len()
            )));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/'))
        {
            return Err(NauError::Validation(format!(
                "peer id `{s}` may only contain ASCII letters, digits and `-_.:/`"
            )));
        }
        Ok(Self(s.to_string()))
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for PeerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for PeerId {
    type Err = NauError;
    fn from_str(s: &str) -> Result<Self> {
        PeerId::parse(s)
    }
}

/// One transport payload.
///
/// Frames are byte strings, not values: framing must not depend on the
/// serialization format of the layer above. A frame may not exceed
/// [`MAX_FRAME_BYTES`](crate::MAX_FRAME_BYTES); every send path checks that
/// before touching the network, and every receive path checks the declared
/// length before allocating.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame(pub Vec<u8>);

impl Frame {
    /// Wrap bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the frame carries no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Take the bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Frames can be megabytes and may contain secrets; never dump them whole.
        let preview = &self.0[..self.0.len().min(16)];
        write!(f, "Frame({} bytes: {:02x?})", self.0.len(), preview)
    }
}

impl From<Vec<u8>> for Frame {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Frame {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_ids_are_validated() {
        assert!(PeerId::parse("tcp://127.0.0.1:5555").is_ok());
        assert!(PeerId::parse("node-7").is_ok());
        assert!(PeerId::parse("did:nau:34750f98bd59fcfc").is_ok());
        assert!(PeerId::parse("").is_err());
        assert!(PeerId::parse("has space").is_err());
        assert!(PeerId::parse("new\nline").is_err());
        assert!(PeerId::parse("emoji-🦀").is_err());
        assert!(PeerId::parse(&"x".repeat(MAX_PEER_ID_LEN + 1)).is_err());
        assert_eq!(
            PeerId::parse("node-7").expect("valid").to_string(),
            "node-7"
        );
        assert!("node-7".parse::<PeerId>().is_ok());
    }

    #[test]
    fn frame_debug_does_not_dump_the_whole_payload() {
        let frame = Frame(vec![0xab; 4096]);
        let rendered = format!("{frame:?}");
        assert!(rendered.contains("4096 bytes"));
        assert!(rendered.len() < 256, "debug output must be bounded");
    }
}
