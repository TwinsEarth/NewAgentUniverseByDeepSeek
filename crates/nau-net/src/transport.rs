//! The transport port: what a node needs from the network, and nothing more.

use std::time::Duration;

use async_trait::async_trait;
use nau_core::{NauError, Result};

use crate::peer::{Frame, PeerId};

/// Hard cap on one frame, in bytes (8 MiB).
///
/// Matches `nau_store::MAX_RECORD_BYTES` so that anything storable is
/// transmittable. The cap exists so that a peer cannot make this process
/// allocate an arbitrary amount of memory by sending a four-byte header:
/// [`check_frame_len`] is called *before* any allocation on both the send and
/// the receive path.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Width of the length prefix, in bytes (big-endian `u32`).
pub const FRAME_PREFIX_BYTES: usize = 4;

/// Refuse a frame length that exceeds [`MAX_FRAME_BYTES`].
///
/// Pure arithmetic: no allocation, no I/O, so it is safe to call on a value that
/// arrived from the network.
pub fn check_frame_len(len: usize) -> Result<()> {
    if len > MAX_FRAME_BYTES {
        return Err(NauError::Validation(format!(
            "frame of {len} bytes exceeds the {MAX_FRAME_BYTES}-byte cap"
        )));
    }
    Ok(())
}

/// Encode a frame as its 4-byte big-endian length prefix followed by its body.
///
/// Provided for tests and for callers that want one contiguous buffer; the TCP
/// writer emits the prefix and the body separately to avoid copying a payload
/// that may be megabytes.
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>> {
    check_frame_len(frame.len())?;
    let len = u32::try_from(frame.len())
        .map_err(|_| NauError::Validation("frame length does not fit in u32".into()))?;
    let mut out = Vec::with_capacity(FRAME_PREFIX_BYTES + frame.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&frame.0);
    Ok(out)
}

/// A message transport between peers.
///
/// Implementations must be usable from several tasks at once (`Send + Sync`),
/// must never panic, and must treat a timeout as "no frame", not as an error.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send `frame` to `to`.
    ///
    /// Fails if `to` is not a connected peer, if the frame exceeds
    /// [`MAX_FRAME_BYTES`], or if the connection breaks.
    async fn send(&self, to: &PeerId, frame: Frame) -> Result<()>;

    /// Receive the next frame, waiting at most `timeout`.
    ///
    /// Returns `Ok(None)` when nothing arrived in time — a timeout is normal
    /// operation, not a failure. Frames from different peers may interleave, so
    /// the sending peer is returned alongside every frame.
    async fn recv(&self, timeout: Duration) -> Result<Option<(PeerId, Frame)>>;

    /// This endpoint's own id.
    fn local_id(&self) -> PeerId;

    /// The peers this endpoint can currently send to, in ascending id order.
    async fn connected(&self) -> Vec<PeerId>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_cap_is_enforced_without_allocating() {
        assert!(check_frame_len(0).is_ok());
        assert!(check_frame_len(MAX_FRAME_BYTES).is_ok());
        let err = check_frame_len(MAX_FRAME_BYTES + 1).expect_err("over the cap");
        assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
        // The exact value that a hostile 4-byte header can produce.
        let err = check_frame_len(u32::MAX as usize).expect_err("absurd header");
        assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    }

    #[test]
    fn encoding_round_trips_through_the_prefix() {
        let frame = Frame(b"payload".to_vec());
        let encoded = encode_frame(&frame).expect("encode");
        assert_eq!(&encoded[..FRAME_PREFIX_BYTES], &[0, 0, 0, 7]);
        let declared = u32::from_be_bytes(
            encoded[..FRAME_PREFIX_BYTES]
                .try_into()
                .expect("four bytes"),
        ) as usize;
        assert_eq!(declared, frame.len());
        assert_eq!(&encoded[FRAME_PREFIX_BYTES..], frame.as_slice());
    }
}
