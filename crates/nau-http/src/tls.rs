//! Real TLS for `https://`, behind the default-off `tls` feature.
//!
//! # Status in this checkout: implemented, **compiled but not executed**
//!
//! Everything below is a real `rustls` handshake and a real
//! `AsyncRead`/`AsyncWrite` stream wrapper, driven directly by
//! `rustls::ClientConnection`. It is deliberately *not* reachable in a default
//! build: without `--features tls`, an `https://` URL fails with
//! [`crate::HttpError::TlsDisabled`] **before any socket is opened**. There is no
//! "fall back to plain TCP" path, because quietly sending an API key in clear
//! text is strictly worse than failing.
//!
//! What is *not* claimed here: this path has never been run against a TLS server
//! from this machine, because the environment has no working outbound TLS (the
//! shell cannot complete an HTTPS request to `static.crates.io`), so there is
//! nothing to hand-shake with. It compiles under `--features tls` and is
//! exercised by no test. "Verified" in this crate covers the plain HTTP path
//! only.
//!
//! ## Why there is no `tokio-rustls` here
//!
//! `tokio-rustls` is not in this workspace's dependency set or local cache, and
//! the brief for this crate is `rustls` + `webpki-roots` only. The async I/O
//! plumbing below is the direct consequence: it drives
//! `read_tls`/`write_tls`/`process_new_packets` in the order rustls documents.
//!
//! ## Trust anchors
//!
//! `webpki-roots 0.25.4` is the release available in this environment. Its
//! `TrustAnchor` predates `rustls-pki-types`, so [`root_store`] maps its public
//! fields onto `rustls_pki_types::TrustAnchor` one for one — the same
//! subject / SPKI / name-constraints triple, with no invented or re-derived
//! data. If a future `webpki-roots` is pinned, delete that mapping and use
//! `RootCertStore::extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())`.

use std::io::{self, BufRead, Read, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::error::{HttpError, Result};

/// Cached client configuration; `None` until a first successful build.
static CLIENT_CONFIG: OnceLock<Mutex<Option<Arc<ClientConfig>>>> = OnceLock::new();

/// Install the process-wide crypto provider.
///
/// A failure means another library installed its own provider first, which is
/// not an error — it is exactly what `install_default` is built to tolerate.
fn ensure_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The client configuration, built on first use and reused afterwards.
///
/// # Errors
///
/// Returns [`HttpError::TlsUnavailable`] when no trust anchors can be assembled.
/// A client with no roots cannot verify anything, and must not silently accept
/// every certificate instead.
fn client_config() -> Result<Arc<ClientConfig>> {
    ensure_provider();
    let cell = CLIENT_CONFIG.get_or_init(|| Mutex::new(None));
    let mut guard = match cell.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(config) = guard.as_ref() {
        return Ok(Arc::clone(config));
    }
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store()?)
            .with_no_client_auth(),
    );
    *guard = Some(Arc::clone(&config));
    Ok(config)
}

/// Assemble the trust anchors from `webpki-roots`.
///
/// # Errors
///
/// Returns [`HttpError::TlsUnavailable`] when the anchor list is empty, because
/// an empty store verifies nothing and every handshake would then fail in a way
/// that looks like a network fault.
fn root_store() -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for anchor in webpki_roots::TLS_SERVER_ROOTS {
        store.roots.push(rustls::pki_types::TrustAnchor {
            subject: anchor.subject.into(),
            subject_public_key_info: anchor.spki.into(),
            name_constraints: anchor.name_constraints.map(Into::into),
        });
    }
    if store.roots.is_empty() {
        return Err(HttpError::TlsUnavailable(
            "webpki-roots provided no trust anchors".to_string(),
        ));
    }
    Ok(store)
}

/// Adapts the non-blocking async socket to the synchronous `std::io::Write` that
/// `rustls`'s `write_tls` requires.
///
/// `WouldBlock` is passed straight through, which is where rustls stops and waits
/// for the caller to try again — it never loses unwritten records.
struct SocketWriter<'s, 'c, 'd> {
    socket: &'s mut TcpStream,
    cx: &'c mut Context<'d>,
}

impl Write for SocketWriter<'_, '_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.socket).poll_write(self.cx, buf) {
            Poll::Ready(Ok(written)) => Ok(written),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.socket).poll_flush(self.cx) {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

/// A TLS-wrapped TCP stream that implements tokio's async I/O traits.
///
/// Reads decrypt out of rustls's plaintext buffer, writes encrypt into its TLS
/// buffer and flush it to the socket. The handshake is completed before the
/// value reaches the framing code, so the framing code never has to know TLS
/// exists.
#[derive(Debug)]
pub struct TlsStream {
    socket: TcpStream,
    connection: ClientConnection,
    /// Set once the socket has signalled EOF.
    saw_eof: bool,
}

impl TlsStream {
    /// Start a TLS session over `socket`, verifying `host`.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::TlsUnavailable`] when no configuration is available
    /// or the handshake fails, [`HttpError::MalformedHead`] when `host` is not a
    /// valid TLS server name, and [`HttpError::Io`] when the socket itself does.
    pub async fn connect(socket: TcpStream, host: &str) -> Result<Self> {
        let config = client_config()?;
        let server_name = ServerName::try_from(host.to_string()).map_err(|_| {
            HttpError::MalformedHead(format!("`{host}` is not a valid TLS server name"))
        })?;
        let connection = ClientConnection::new(config, server_name)
            .map_err(|error| HttpError::TlsUnavailable(error.to_string()))?;
        let mut stream = Self {
            socket,
            connection,
            saw_eof: false,
        };
        // One empty read is exactly "drive the handshake to completion": the
        // read path flushes pending records, consumes ciphertext and processes
        // it, and only returns once it has plaintext, EOF or a real error.
        let mut nothing = [0u8; 0];
        std::future::poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut nothing);
            Pin::new(&mut stream).poll_read(cx, &mut buf)
        })
        .await?;
        if stream.connection.is_handshaking() {
            return Err(HttpError::TlsUnavailable(
                "the peer closed the connection during the TLS handshake".to_string(),
            ));
        }
        Ok(stream)
    }

    /// Whether the underlying socket has reached EOF.
    pub fn saw_eof(&self) -> bool {
        self.saw_eof
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut scratch = [0u8; 16 * 1024];
        loop {
            // 1. Push anything rustls wants to send, so a peer waiting on us is
            //    never deadlocked.
            if this.connection.wants_write() {
                let written = {
                    let mut writer = SocketWriter {
                        socket: &mut this.socket,
                        cx: &mut *cx,
                    };
                    this.connection.write_tls(&mut writer)
                };
                match written {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        // The socket is full; rustls keeps the records.
                        return Poll::Pending;
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }

            // 2. Hand over plaintext rustls has already decrypted. `fill_buf`
            //    reports `Ok(&[])` or `WouldBlock` when there is none, so there
            //    is no need to guess.
            let plaintext = {
                let mut reader = this.connection.reader();
                match reader.fill_buf() {
                    Ok(chunk) => chunk.len(),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
                    // An unclean close without `close_notify`. The body framing
                    // above still checks `Content-Length`, so the connection is
                    // finished rather than silently truncated.
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        this.saw_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            };
            if plaintext > 0 {
                let read = {
                    let destination = buf.initialize_unfilled();
                    match this.connection.reader().read(&mut *destination) {
                        Ok(read) => read,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                };
                buf.advance(read);
                return Poll::Ready(Ok(()));
            }
            if this.saw_eof {
                // Peer is gone and no plaintext is left: a legitimate end.
                return Poll::Ready(Ok(()));
            }

            // 3. Read more ciphertext, if the socket will give us any.
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.socket).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if read_buf.filled().is_empty() {
                        this.saw_eof = true;
                        // One more turn through the loop so any plaintext rustls
                        // can still produce from buffered records is delivered.
                        continue;
                    }
                }
            }
            if let Err(error) = this.connection.process_new_packets() {
                return Poll::Ready(Err(io_error(HttpError::TlsUnavailable(error.to_string()))));
            }
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // rustls buffers plaintext in memory and refuses more once its own send
        // buffer is full, so `WouldBlock` is a real answer here.
        match this.connection.writer().write(buf) {
            Ok(written) => Poll::Ready(Ok(written)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.connection.wants_write() {
            let written = {
                let mut writer = SocketWriter {
                    socket: &mut this.socket,
                    cx: &mut *cx,
                };
                this.connection.write_tls(&mut writer)
            };
            match written {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        Pin::new(&mut this.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        this.connection.send_close_notify();
        let _ = Pin::new(&mut *this).poll_flush(cx);
        let this = self.get_mut();
        Pin::new(&mut this.socket).poll_shutdown(cx)
    }
}

/// Turn an [`HttpError`] into an `io::Error` for the `AsyncRead` signature.
fn io_error(error: HttpError) -> io::Error {
    match error {
        HttpError::Io(source) => source,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

/// Complete a TLS handshake over `socket` for `host`.
///
/// # Errors
///
/// Propagates [`TlsStream::connect`]'s errors.
pub async fn negotiate(socket: TcpStream, host: &str) -> Result<TlsStream> {
    TlsStream::connect(socket, host).await
}
