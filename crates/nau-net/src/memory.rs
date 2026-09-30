//! An in-memory [`Transport`] for tests — and it says so in its name.
//!
//! Upstream v2.5.6 shipped `net/dht.rs::KademliaClient`,
//! `net/gossip.rs::GossipSub` and `net/libp2p_node.rs::GsnNode` as `HashMap`
//! stand-ins carrying the *same names as the real services*, so nothing in an
//! integration test revealed that no socket was ever opened. A substitute must be
//! recognisable at the call site; hence `MemoryTransport`, and hence the real
//! implementation lives in a differently-named module ([`crate::tcp`]).
//!
//! Delivery is through bounded `tokio` channels: [`MEMORY_QUEUE_CAP`] frames per
//! endpoint. A bounded queue is deliberate — an unbounded one turns a slow
//! consumer into a memory leak.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use nau_core::{NauError, Result};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::lock;
use crate::peer::{Frame, PeerId};
use crate::transport::{check_frame_len, Transport};

/// Frames that may be queued towards one endpoint before `send` applies
/// back-pressure.
pub const MEMORY_QUEUE_CAP: usize = 1024;

/// A [`Transport`] that delivers frames through in-process channels.
///
/// Two endpoints must be created together with [`MemoryTransport::pair`]; an
/// endpoint from [`MemoryTransport::new`] has no route and rejects every send
/// with [`NauError::NotFound`].
pub struct MemoryTransport {
    local: PeerId,
    peers: Mutex<BTreeSet<PeerId>>,
    outbox: mpsc::Sender<(PeerId, Frame)>,
    inbox: AsyncMutex<mpsc::Receiver<(PeerId, Frame)>>,
}

impl MemoryTransport {
    /// A standalone endpoint with no route to anything.
    ///
    /// Useful to assert the "unknown peer" error path; use
    /// [`MemoryTransport::pair`] for an endpoint that can actually deliver.
    pub fn new(id: PeerId) -> Self {
        let (outbox, unreachable) = mpsc::channel(MEMORY_QUEUE_CAP);
        // Dropping the receiver immediately makes every write to it fail, which
        // is exactly the semantics of "this endpoint has no route".
        drop(unreachable);
        let (_never_used, inbox) = mpsc::channel(MEMORY_QUEUE_CAP);
        Self {
            local: id,
            peers: Mutex::new(BTreeSet::new()),
            outbox,
            inbox: AsyncMutex::new(inbox),
        }
    }

    /// Two endpoints wired to each other.
    ///
    /// `a` and `b` should differ; identical ids still work but make the
    /// `connected()` lists indistinguishable.
    pub fn pair(a: &PeerId, b: &PeerId) -> (Self, Self) {
        let (to_b, for_b) = mpsc::channel(MEMORY_QUEUE_CAP);
        let (to_a, for_a) = mpsc::channel(MEMORY_QUEUE_CAP);
        let endpoint_a = Self {
            local: a.clone(),
            peers: Mutex::new(BTreeSet::from([b.clone()])),
            outbox: to_b,
            inbox: AsyncMutex::new(for_a),
        };
        let endpoint_b = Self {
            local: b.clone(),
            peers: Mutex::new(BTreeSet::from([a.clone()])),
            outbox: to_a,
            inbox: AsyncMutex::new(for_b),
        };
        (endpoint_a, endpoint_b)
    }
}

#[async_trait]
impl Transport for MemoryTransport {
    async fn send(&self, to: &PeerId, frame: Frame) -> Result<()> {
        check_frame_len(frame.len())?;
        // Take the guard in its own statement so it is not held across an await.
        let known = lock::lock(&self.peers).contains(to);
        if !known {
            return Err(NauError::NotFound(format!(
                "peer `{to}` is not connected to `{}`",
                self.local
            )));
        }
        self.outbox
            .send((self.local.clone(), frame))
            .await
            .map_err(|_| NauError::NotFound(format!("the link to peer `{to}` has been closed")))
    }

    async fn recv(&self, timeout: Duration) -> Result<Option<(PeerId, Frame)>> {
        let mut inbox = self.inbox.lock().await;
        match tokio::time::timeout(timeout, inbox.recv()).await {
            // A timeout means "no frame right now", which is not an error.
            Err(_elapsed) => Ok(None),
            Ok(None) => Ok(None),
            Ok(Some(item)) => Ok(Some(item)),
        }
    }

    fn local_id(&self) -> PeerId {
        self.local.clone()
    }

    async fn connected(&self) -> Vec<PeerId> {
        lock::lock(&self.peers).iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_standalone_endpoint_has_no_route() {
        let lonely = MemoryTransport::new(PeerId::parse("solo").expect("id"));
        assert!(lonely.connected().await.is_empty());
        let err = lonely
            .send(
                &PeerId::parse("solo").expect("id"),
                Frame::new(b"x".to_vec()),
            )
            .await
            .expect_err("no route");
        assert!(matches!(err, NauError::NotFound(_)), "got {err:?}");
    }
}
