//! A real TCP transport with length-prefixed frames, a hard size cap and read
//! timeouts.
//!
//! Wire format, per frame:
//!
//! ```text
//! +----------------+---------------------------+
//! | u32 big-endian | that many bytes of payload |
//! +----------------+---------------------------+
//! ```
//!
//! This is the piece upstream v2.5.6 never had: its "network" was three
//! same-named `HashMap` mocks, so no test ever opened a socket. Here, a bound
//! [`TcpTransport`] accepts connections, spawns a reader and a writer task per
//! connection, and exchanges frames with another bound instance over
//! `127.0.0.1`.
//!
//! ## Limits, deliberately chosen
//!
//! * **Frame cap.** The declared length is checked against
//!   [`MAX_FRAME_BYTES`] *before* the buffer is allocated, so a four-byte header
//!   claiming 4 GiB costs nothing and closes the connection instead.
//! * **Read timeout.** A connection that produces no complete frame within
//!   [`DEFAULT_READ_TIMEOUT`] is closed; a peer that connects and then goes
//!   silent cannot pin a task forever.
//! * **Bounded queues.** At most [`OUTBOUND_QUEUE_CAP`] frames may be queued
//!   towards one peer and [`INBOUND_QUEUE_CAP`] frames may wait for `recv`;
//!   beyond that, senders block rather than grow the heap.
//! * **Peer identity.** A peer id is the observed socket address
//!   (`tcp://127.0.0.1:54321`). There is no handshake at this layer, so an
//!   endpoint's own `local_id` (its listening address) differs from the id its
//!   peer sees (the ephemeral source port). Binding an address to a DID belongs
//!   to a higher layer, and pretending otherwise here would be the same mistake
//!   the mocks made.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use nau_core::{NauError, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::lock;
use crate::peer::{Frame, PeerId};
use crate::transport::{check_frame_len, Transport, FRAME_PREFIX_BYTES};

/// Default read timeout: how long a connection may produce nothing before it is
/// closed.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Frames that may be queued towards one peer before `send` waits.
pub const OUTBOUND_QUEUE_CAP: usize = 256;

/// Frames that may wait for `recv` before the socket reader waits.
pub const INBOUND_QUEUE_CAP: usize = 1024;

/// Scheme prefix used to build a peer id from a socket address.
const TCP_SCHEME: &str = "tcp://";

/// Consecutive `accept` failures tolerated before the accept loop gives up.
///
/// An explicit bound: without it, a listener error would spin forever.
const MAX_ACCEPT_ERRORS: u32 = 64;

/// Pause after a failed `accept`, so an error cannot become a hot loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(10);

/// Shared state of a bound TCP endpoint.
struct Inner {
    local_id: PeerId,
    local_addr: String,
    read_timeout: Duration,
    peers: RwLock<BTreeMap<PeerId, mpsc::Sender<Frame>>>,
    inbound_tx: mpsc::Sender<(PeerId, Frame)>,
    inbound_rx: tokio::sync::Mutex<mpsc::Receiver<(PeerId, Frame)>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Inner {
    /// Register a freshly established connection and start its tasks.
    fn register(self: &Arc<Self>, stream: TcpStream, peer: PeerId) {
        let (read_half, write_half) = stream.into_split();
        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_CAP);
        lock::write(&self.peers).insert(peer.clone(), outbound);
        let writer = tokio::spawn(writer_loop(
            self.clone(),
            peer.clone(),
            write_half,
            outbound_rx,
        ));
        let reader = tokio::spawn(reader_loop(
            self.clone(),
            peer,
            read_half,
            self.inbound_tx.clone(),
            self.read_timeout,
        ));
        let mut tasks = lock::lock(&self.tasks);
        tasks.push(writer);
        tasks.push(reader);
    }

    /// Forget a peer whose connection ended.
    fn unregister(&self, peer: &PeerId) {
        lock::write(&self.peers).remove(peer);
    }
}

/// A [`Transport`] that speaks length-prefixed frames over TCP.
pub struct TcpTransport {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTransport")
            .field("local_id", &self.inner.local_id)
            .field("local_addr", &self.inner.local_addr)
            .finish_non_exhaustive()
    }
}

impl TcpTransport {
    /// Bind `addr` (e.g. `"127.0.0.1:0"` to let the OS pick a port) and start
    /// accepting connections.
    pub async fn bind(addr: &str) -> Result<Self> {
        Self::bind_with_read_timeout(addr, DEFAULT_READ_TIMEOUT).await
    }

    /// [`TcpTransport::bind`] with an explicit read timeout.
    ///
    /// Mainly useful in tests, where waiting [`DEFAULT_READ_TIMEOUT`] for the
    /// "silent peer is dropped" behaviour would be absurd.
    pub async fn bind_with_read_timeout(addr: &str, read_timeout: Duration) -> Result<Self> {
        if read_timeout.is_zero() {
            return Err(NauError::Validation(
                "read timeout must be greater than zero".into(),
            ));
        }
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?.to_string();
        let local_id = PeerId::parse(&format!("{TCP_SCHEME}{local_addr}"))?;
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_CAP);
        let inner = Arc::new(Inner {
            local_id,
            local_addr,
            read_timeout,
            peers: RwLock::new(BTreeMap::new()),
            inbound_tx,
            inbound_rx: tokio::sync::Mutex::new(inbound_rx),
            tasks: Mutex::new(Vec::new()),
        });

        let accepting = inner.clone();
        let accept_task = tokio::spawn(async move {
            let mut consecutive_errors: u32 = 0;
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        consecutive_errors = 0;
                        match PeerId::parse(&format!("{TCP_SCHEME}{addr}")) {
                            Ok(peer) => accepting.register(stream, peer),
                            Err(err) => {
                                tracing::warn!(addr = %addr, error = %err, "refusing a peer id")
                            }
                        }
                    }
                    Err(err) => {
                        consecutive_errors += 1;
                        tracing::warn!(
                            addr = %accepting.local_addr,
                            error = %err,
                            consecutive_errors,
                            "tcp accept failed"
                        );
                        if consecutive_errors >= MAX_ACCEPT_ERRORS {
                            break;
                        }
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    }
                }
            }
        });
        lock::lock(&inner.tasks).push(accept_task);
        Ok(Self { inner })
    }

    /// The address this endpoint listens on.
    pub fn local_addr(&self) -> Result<String> {
        Ok(self.inner.local_addr.clone())
    }

    /// The read timeout this endpoint applies to every connection.
    pub fn read_timeout(&self) -> Duration {
        self.inner.read_timeout
    }

    /// Connect to `addr` and return the peer id under which the connection is
    /// registered.
    ///
    /// The returned id is the *observed* remote address; it is what must be
    /// passed to [`Transport::send`].
    pub async fn connect(&self, addr: &str) -> Result<PeerId> {
        let stream = TcpStream::connect(addr).await?;
        let remote = stream.peer_addr()?;
        let peer = PeerId::parse(&format!("{TCP_SCHEME}{remote}"))?;
        self.inner.register(stream, peer.clone());
        tracing::debug!(peer = %peer, "outbound connection established");
        Ok(peer)
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn send(&self, to: &PeerId, frame: Frame) -> Result<()> {
        check_frame_len(frame.len())?;
        let sender = lock::read(&self.inner.peers).get(to).cloned();
        let Some(sender) = sender else {
            return Err(NauError::NotFound(format!(
                "peer `{to}` is not connected to `{}`",
                self.inner.local_id
            )));
        };
        sender.send(frame).await.map_err(|_| {
            NauError::NotFound(format!("the connection to peer `{to}` has been closed"))
        })
    }

    async fn recv(&self, wait: Duration) -> Result<Option<(PeerId, Frame)>> {
        let mut inbox = self.inner.inbound_rx.lock().await;
        match timeout(wait, inbox.recv()).await {
            Err(_elapsed) => Ok(None),
            Ok(None) => Ok(None),
            Ok(Some(item)) => Ok(Some(item)),
        }
    }

    fn local_id(&self) -> PeerId {
        self.inner.local_id.clone()
    }

    async fn connected(&self) -> Vec<PeerId> {
        lock::read(&self.inner.peers).keys().cloned().collect()
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        // Stop the accept loop and every per-connection task this endpoint
        // started; otherwise a dropped endpoint would keep its sockets alive.
        for handle in lock::lock(&self.inner.tasks).drain(..) {
            handle.abort();
        }
    }
}

/// Read frames from one connection until it ends, then forget the peer.
async fn reader_loop(
    inner: Arc<Inner>,
    peer: PeerId,
    mut read_half: OwnedReadHalf,
    inbound: mpsc::Sender<(PeerId, Frame)>,
    read_timeout: Duration,
) {
    loop {
        match read_frame(&mut read_half, read_timeout).await {
            Ok(Some(frame)) => {
                if inbound.send((peer.clone(), frame)).await.is_err() {
                    // The endpoint is gone; the connection is useless.
                    break;
                }
            }
            Ok(None) => break,
            Err(err) => {
                tracing::warn!(peer = %peer, error = %err, "closing connection after a read error");
                break;
            }
        }
    }
    inner.unregister(&peer);
}

/// Write queued frames to one connection until it ends, then forget the peer.
async fn writer_loop(
    inner: Arc<Inner>,
    peer: PeerId,
    mut write_half: OwnedWriteHalf,
    mut outbound: mpsc::Receiver<Frame>,
) {
    while let Some(frame) = outbound.recv().await {
        if let Err(err) = write_frame(&mut write_half, &frame).await {
            tracing::warn!(peer = %peer, error = %err, "closing connection after a write error");
            break;
        }
    }
    let _ = write_half.shutdown().await;
    inner.unregister(&peer);
}

/// Read one frame, or `Ok(None)` at a clean end of stream.
///
/// The declared length is validated before the body buffer is allocated.
async fn read_frame<R>(reader: &mut R, read_timeout: Duration) -> Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_PREFIX_BYTES];
    match timeout(read_timeout, reader.read_exact(&mut header)).await {
        Err(_elapsed) => {
            return Err(NauError::Stale(format!(
                "no frame header within {read_timeout:?}"
            )))
        }
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Ok(Err(err)) => return Err(NauError::Io(err)),
        Ok(Ok(_)) => {}
    }
    let declared = u32::from_be_bytes(header) as usize;
    // upstream v2.5.6 fix: nothing here ever validated a length, because there
    // was no real transport. Reject before allocating.
    check_frame_len(declared)?;
    let mut body = vec![0u8; declared];
    match timeout(read_timeout, reader.read_exact(&mut body)).await {
        Err(_elapsed) => Err(NauError::Stale(format!(
            "frame body of {declared} bytes did not arrive within {read_timeout:?}"
        ))),
        Ok(Err(err)) => Err(NauError::Io(err)),
        Ok(Ok(_)) => Ok(Some(Frame(body))),
    }
}

/// Write one frame: 4-byte big-endian length, then the body.
async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    check_frame_len(frame.len())?;
    let declared = u32::try_from(frame.len())
        .map_err(|_| NauError::Validation("frame length does not fit in u32".into()))?;
    writer.write_all(&declared.to_be_bytes()).await?;
    writer.write_all(&frame.0).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_over_cap_length_is_refused_before_allocating() {
        // A four-byte header claiming 4 GiB, and nothing else.
        let mut hostile: &[u8] = &[0xff, 0xff, 0xff, 0xff];
        let err = read_frame(&mut hostile, Duration::from_millis(50))
            .await
            .expect_err("must refuse the declared length");
        assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_clean_end_of_stream_is_not_an_error() {
        let mut empty: &[u8] = &[];
        assert_eq!(
            read_frame(&mut empty, Duration::from_millis(50))
                .await
                .expect("clean eof"),
            None
        );
    }
}
