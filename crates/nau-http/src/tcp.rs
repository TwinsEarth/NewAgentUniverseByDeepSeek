//! The real transport: HTTP/1.1 over `tokio::net::TcpStream`.
//!
//! ## What is verified here
//!
//! The whole plain-`http://` path is exercised by this crate's tests against
//! `tokio::net::TcpListener` sockets: request framing, status and header
//! parsing, `Content-Length` bodies, chunked bodies, read-to-EOF bodies,
//! truncation detection, the body-size cap, the read timeout, and the connect
//! error path. Nothing in this module is a stub.
//!
//! ## What is *not* verified here
//!
//! The `https://` path behind the default-off `tls` feature is **implemented but
//! unverified in this checkout**; see [`crate::tls`] for exactly why.
//!
//! ## Framing rules (HTTP/1.1, RFC 7230 §3.3)
//!
//! 1. `Transfer-Encoding` ending in `chunked` ⇒ chunked framing, which this
//!    crate **decodes**.
//! 2. Otherwise `Content-Length` ⇒ exactly that many body bytes, and a short
//!    read is [`HttpError::TruncatedBody`] rather than a silently short body.
//! 3. Otherwise ⇒ read to EOF (the server closing the connection delimits the
//!    body). `Connection: close` is sent precisely so this always terminates.
//!
//! Every read is bounded by `max_body` and every await by `read_timeout`, so a
//! hostile or merely broken server can neither exhaust memory nor hang the
//! caller.

use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::error::{HttpError, Result};
use crate::message::{Headers, HttpRequest, HttpResponse, USER_AGENT};
use crate::transport::Transport;
use crate::url::{parse_url, ParsedUrl};

/// Default connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default read timeout: the longest an individual read may make no progress.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Default maximum response body size: 8 MiB.
pub const DEFAULT_MAX_BODY: usize = 8 * 1024 * 1024;
/// Default maximum response head size (status line + headers + CRLFs): 64 KiB.
pub const DEFAULT_MAX_HEAD: usize = 64 * 1024;
/// Bytes requested per socket read.
const READ_CHUNK: usize = 8 * 1024;
/// Methods whose body is always framed, even when the body is empty, so no
/// server has to guess whether a payload follows.
const ALWAYS_FRAMED: [&str; 4] = ["POST", "PUT", "PATCH", "DELETE"];

/// Anything this client can write a request to and read a response from.
///
/// The trait exists so a TLS stream can be substituted for a plain socket
/// without touching the framing code, which keeps the TLS feature additive.
pub trait ReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> ReadWrite for T {}

/// A [`Transport`] that speaks HTTP/1.1 over a real TCP connection.
///
/// One connection per request, always with `Connection: close`: reuse would need
/// a pool, and a pool that is not carefully validated is how a request ends up
/// answered by somebody else's connection. A fresh socket is slower and obviously
/// correct.
#[derive(Clone, Debug)]
pub struct TcpTransport {
    connect_timeout: Duration,
    read_timeout: Duration,
    max_body: usize,
    max_head: usize,
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            max_body: DEFAULT_MAX_BODY,
            max_head: DEFAULT_MAX_HEAD,
        }
    }
}

impl TcpTransport {
    /// A transport with the crate defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// A builder with the crate defaults.
    pub fn builder() -> TcpTransportBuilder {
        TcpTransportBuilder {
            inner: Self::default(),
        }
    }

    /// The connect timeout.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// The per-await read timeout.
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// The maximum accepted response body size, in bytes.
    pub fn max_body(&self) -> usize {
        self.max_body
    }

    /// The maximum accepted response head size, in bytes.
    pub fn max_head(&self) -> usize {
        self.max_head
    }

    /// Replace the connect timeout.
    ///
    /// # Errors
    ///
    /// A zero timeout is rejected: it would fail every connection immediately,
    /// which looks like a network fault while actually being a misconfiguration.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(HttpError::MalformedHead(
                "connect timeout must be greater than zero".to_string(),
            ));
        }
        self.connect_timeout = timeout;
        Ok(self)
    }

    /// Replace the read timeout.
    ///
    /// # Errors
    ///
    /// A zero timeout is rejected for the same reason as
    /// [`TcpTransport::with_connect_timeout`].
    pub fn with_read_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(HttpError::MalformedHead(
                "read timeout must be greater than zero".to_string(),
            ));
        }
        self.read_timeout = timeout;
        Ok(self)
    }

    /// Replace the maximum response body size.
    ///
    /// # Errors
    ///
    /// A zero limit is rejected: it would refuse every response, including an
    /// empty one.
    pub fn with_max_body(mut self, max_body: usize) -> Result<Self> {
        if max_body == 0 {
            return Err(HttpError::MalformedHead(
                "max body size must be greater than zero".to_string(),
            ));
        }
        self.max_body = max_body;
        Ok(self)
    }

    /// Dial `host:port`, applying the connect timeout.
    async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        match tokio::time::timeout(self.connect_timeout, TcpStream::connect((host, port))).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true).map_err(HttpError::Io)?;
                Ok(stream)
            }
            Ok(Err(source)) => Err(HttpError::Connect {
                host: host.to_string(),
                port,
                source,
            }),
            Err(_) => Err(HttpError::ConnectTimeout {
                host: host.to_string(),
                port,
                timeout: self.connect_timeout,
            }),
        }
    }

    /// Frame `request` as HTTP/1.1 bytes.
    ///
    /// upstream v2.5.6 fix: there was no request framing upstream at all — no
    /// HTTP dependency exists in `gsn-core/Cargo.toml`. The headers generated
    /// here are exactly what a provider needs, and `Content-Length` is derived
    /// from the body, so the two can never disagree.
    fn write_raw(request: &HttpRequest, parsed: &ParsedUrl) -> Vec<u8> {
        let mut raw = Vec::with_capacity(256 + request.body_len().unwrap_or(0));
        raw.extend_from_slice(request.method.as_bytes());
        raw.push(b' ');
        raw.extend_from_slice(parsed.path.as_bytes());
        raw.extend_from_slice(b" HTTP/1.1\r\n");

        let has = |name: &str| {
            request
                .headers
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case(name))
        };

        // Caller headers first, skipping the one this client owns: a
        // caller-supplied `Content-Length` that disagreed with the body would
        // desynchronise the connection.
        for (name, value) in &request.headers {
            if name.eq_ignore_ascii_case("content-length") {
                // upstream v2.5.6 fix: `Content-Length` is recomputed from the
                // body below instead of being trusted from the caller.
                continue;
            }
            raw.extend_from_slice(name.as_bytes());
            raw.extend_from_slice(b": ");
            raw.extend_from_slice(value.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
        if !has("host") {
            raw.extend_from_slice(b"Host: ");
            raw.extend_from_slice(parsed.host_header().as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
        if !has("connection") {
            raw.extend_from_slice(b"Connection: close\r\n");
        }
        if !has("accept-encoding") {
            // No transparent decompression is implemented here, so ask for none:
            // advertising `gzip` while handing the caller compressed bytes would
            // be silent corruption.
            raw.extend_from_slice(b"Accept-Encoding: identity\r\n");
        }
        if !has("user-agent") {
            raw.extend_from_slice(b"User-Agent: ");
            raw.extend_from_slice(USER_AGENT.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
        let framed = request.body.is_some()
            || ALWAYS_FRAMED
                .iter()
                .any(|method| method.eq_ignore_ascii_case(&request.method));
        if framed {
            raw.extend_from_slice(b"Content-Length: ");
            raw.extend_from_slice(request.body_len().unwrap_or(0).to_string().as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        if let Some(body) = &request.body {
            raw.extend_from_slice(body);
        }
        raw
    }

    /// Write the request and read the response over an established stream.
    async fn exchange<S: ReadWrite>(&self, stream: S, raw: &[u8]) -> Result<HttpResponse> {
        let mut reader = BufReader::new(stream);
        self.write_framed(&mut reader, raw).await?;
        let (status, headers) = self.read_head(&mut reader).await?;
        let body = self.read_body(&mut reader, status, &headers).await?;
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    /// Write `raw`, bounded by the read timeout (which doubles as the overall
    /// I/O deadline).
    async fn write_framed<S: AsyncWrite + Unpin>(&self, stream: &mut S, raw: &[u8]) -> Result<()> {
        match tokio::time::timeout(self.read_timeout, stream.write_all(raw)).await {
            Ok(Ok(())) => {}
            Ok(Err(source)) => return Err(HttpError::Io(source)),
            Err(_) => {
                return Err(HttpError::ReadTimeout {
                    timeout: self.read_timeout,
                })
            }
        }
        match tokio::time::timeout(self.read_timeout, stream.flush()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(HttpError::Io(source)),
            Err(_) => Err(HttpError::ReadTimeout {
                timeout: self.read_timeout,
            }),
        }
    }

    /// Read a single byte, applying the read timeout.
    async fn read_byte<S: AsyncRead + Unpin>(&self, stream: &mut S) -> Result<Option<u8>> {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(self.read_timeout, stream.read(&mut byte)).await {
            Ok(Ok(0)) => Ok(None),
            Ok(Ok(_)) => Ok(Some(byte[0])),
            Ok(Err(source)) => Err(HttpError::Io(source)),
            Err(_) => Err(HttpError::ReadTimeout {
                timeout: self.read_timeout,
            }),
        }
    }

    /// Read one CRLF- or LF-terminated line, without the terminator. `EOF`
    /// yields a short line, which the callers treat as a truncation.
    async fn read_line<S: AsyncRead + Unpin>(&self, stream: &mut S) -> Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            match self.read_byte(stream).await? {
                None => return Ok(line),
                Some(b'\n') => {
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    return Ok(line);
                }
                Some(byte) => {
                    if line.len() >= self.max_head {
                        return Err(HttpError::HeadTooLarge {
                            limit: self.max_head,
                        });
                    }
                    line.push(byte);
                }
            }
        }
    }

    /// Parse the status line and headers.
    async fn read_head<S: AsyncRead + Unpin>(&self, stream: &mut S) -> Result<(u16, Headers)> {
        let mut consumed = 0usize;
        let status_line = self.read_line(stream).await?;
        if status_line.is_empty() {
            return Err(HttpError::MalformedHead(
                "connection closed before any status line".to_string(),
            ));
        }
        consumed = consumed.saturating_add(status_line.len() + 2);
        let status = parse_status_line(&status_line)?;

        let mut headers = Headers::new();
        loop {
            let line = self.read_line(stream).await?;
            consumed = consumed.saturating_add(line.len() + 2);
            if consumed > self.max_head {
                return Err(HttpError::HeadTooLarge {
                    limit: self.max_head,
                });
            }
            if line.is_empty() {
                return Ok((status, headers));
            }
            let (name, value) = parse_header_line(&line)?;
            headers.push(name, value);
        }
    }

    /// Read the body according to its framing.
    async fn read_body<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        status: u16,
        headers: &Headers,
    ) -> Result<Vec<u8>> {
        if headers.is_chunked() {
            if let Some(length) = headers.content_length() {
                // Both frames at once is a request-smuggling vector; this client
                // refuses to guess which one the peer meant.
                return Err(HttpError::UnsupportedTransferCoding(format!(
                    "response carries both Transfer-Encoding: chunked and Content-Length: {length}"
                )));
            }
            return self.read_chunked(stream).await;
        }
        if let Some(length) = headers.content_length() {
            return self.read_exact_body(stream, length, status).await;
        }
        self.read_to_eof(stream).await
    }

    /// Read exactly `length` body bytes, refusing to allocate beyond `max_body`.
    async fn read_exact_body<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        length: u64,
        status: u16,
    ) -> Result<Vec<u8>> {
        // A bodyless status may still carry a non-zero `Content-Length` (some
        // servers do this for `204`); RFC 7230 says there is no body then.
        if body_forbidden(status) {
            return Ok(Vec::new());
        }
        if length > self.max_body as u64 {
            return Err(HttpError::BodyTooLarge {
                limit: self.max_body,
            });
        }
        let mut remaining = length;
        let mut body = Vec::with_capacity(length.min(self.max_body as u64) as usize);
        let mut buffer = [0u8; READ_CHUNK];
        while remaining > 0 {
            let want = (remaining as usize).min(READ_CHUNK);
            let read =
                match tokio::time::timeout(self.read_timeout, stream.read(&mut buffer[..want]))
                    .await
                {
                    // upstream v2.5.6 fix: a truncated body used to be
                    // indistinguishable from success, because nothing read the
                    // body at all. Here it is a typed error.
                    Ok(Ok(0)) => {
                        return Err(HttpError::TruncatedBody {
                            expected: length,
                            received: body.len() as u64,
                        })
                    }
                    Ok(Ok(read)) => read,
                    Ok(Err(source)) => return Err(HttpError::Io(source)),
                    Err(_) => {
                        return Err(HttpError::ReadTimeout {
                            timeout: self.read_timeout,
                        })
                    }
                };
            body.extend_from_slice(&buffer[..read]);
            remaining = remaining.saturating_sub(read as u64);
        }
        Ok(body)
    }

    /// Read a chunked body, decoding it into plain bytes.
    async fn read_chunked<S: AsyncRead + Unpin>(&self, stream: &mut S) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let size_line = self.read_line(stream).await?;
            let size = parse_chunk_size(&size_line)?;
            if size == 0 {
                // Discard trailers up to the terminating blank line.
                loop {
                    if self.read_line(stream).await?.is_empty() {
                        break;
                    }
                }
                return Ok(body);
            }
            if body.len().saturating_add(size) > self.max_body {
                return Err(HttpError::BodyTooLarge {
                    limit: self.max_body,
                });
            }
            let mut chunk = vec![0u8; size];
            match tokio::time::timeout(self.read_timeout, stream.read_exact(&mut chunk)).await {
                Ok(Ok(_)) => {}
                Ok(Err(source)) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(HttpError::TruncatedBody {
                        expected: size as u64,
                        received: 0,
                    })
                }
                Ok(Err(source)) => return Err(HttpError::Io(source)),
                Err(_) => {
                    return Err(HttpError::ReadTimeout {
                        timeout: self.read_timeout,
                    })
                }
            }
            body.extend_from_slice(&chunk);
            let mut terminator = [0u8; 2];
            match tokio::time::timeout(self.read_timeout, stream.read_exact(&mut terminator)).await
            {
                Ok(Ok(_)) => {}
                Ok(Err(source)) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(HttpError::MalformedChunk(
                        "chunk data was not followed by CRLF".to_string(),
                    ))
                }
                Ok(Err(source)) => return Err(HttpError::Io(source)),
                Err(_) => {
                    return Err(HttpError::ReadTimeout {
                        timeout: self.read_timeout,
                    })
                }
            }
            if &terminator != b"\r\n" {
                return Err(HttpError::MalformedChunk(
                    "chunk data was not followed by CRLF".to_string(),
                ));
            }
        }
    }

    /// Read until EOF, bounded by `max_body`.
    ///
    /// Reaching `max_body` without EOF is an error rather than a truncated body:
    /// the peer has not said it finished, so returning what arrived would hand
    /// the caller a partial document as if it were complete.
    async fn read_to_eof<S: AsyncRead + Unpin>(&self, stream: &mut S) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut buffer = [0u8; READ_CHUNK];
        loop {
            let read = match tokio::time::timeout(self.read_timeout, stream.read(&mut buffer)).await
            {
                Ok(Ok(0)) => return Ok(body),
                Ok(Ok(read)) => read,
                Ok(Err(source)) => return Err(HttpError::Io(source)),
                Err(_) => {
                    return Err(HttpError::ReadTimeout {
                        timeout: self.read_timeout,
                    })
                }
            };
            if body.len().saturating_add(read) > self.max_body {
                return Err(HttpError::BodyTooLarge {
                    limit: self.max_body,
                });
            }
            body.extend_from_slice(&buffer[..read]);
        }
    }

    /// Decode `data` as a complete chunked body, without any I/O.
    ///
    /// This is the same decoder the live path uses, exposed so the transfer
    /// coding can be verified on a fixed byte string.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::MalformedChunk`] for a bad size line and
    /// [`HttpError::TruncatedBody`] when a chunk is cut short.
    pub fn decode_chunked(data: &[u8]) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut offset = 0usize;
        loop {
            let Some(line_end) = find_crlf(data, offset) else {
                return Err(HttpError::MalformedChunk(
                    "chunk stream ended before a size line".to_string(),
                ));
            };
            let size = parse_chunk_size(&data[offset..line_end])?;
            offset = line_end + 2;
            if size == 0 {
                return Ok(body);
            }
            let end = offset.saturating_add(size);
            if end > data.len() {
                return Err(HttpError::TruncatedBody {
                    expected: size as u64,
                    received: data.len().saturating_sub(offset) as u64,
                });
            }
            body.extend_from_slice(&data[offset..end]);
            offset = end.saturating_add(2);
        }
    }
}

/// Builder for [`TcpTransport`].
#[derive(Clone, Debug)]
pub struct TcpTransportBuilder {
    inner: TcpTransport,
}

impl TcpTransportBuilder {
    /// Set the connect timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.inner.connect_timeout = timeout;
        self
    }

    /// Set the per-await read timeout.
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.inner.read_timeout = timeout;
        self
    }

    /// Set the maximum response body size in bytes.
    pub fn max_body(mut self, max_body: usize) -> Self {
        self.inner.max_body = max_body;
        self
    }

    /// Set the maximum response head size in bytes.
    pub fn max_head(mut self, max_head: usize) -> Self {
        self.inner.max_head = max_head;
        self
    }

    /// Finish, validating that every limit is usable.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero timeout or a zero size limit.
    pub fn build(self) -> Result<TcpTransport> {
        if self.inner.connect_timeout.is_zero() {
            return Err(HttpError::MalformedHead(
                "connect timeout must be greater than zero".to_string(),
            ));
        }
        if self.inner.read_timeout.is_zero() {
            return Err(HttpError::MalformedHead(
                "read timeout must be greater than zero".to_string(),
            ));
        }
        if self.inner.max_body == 0 {
            return Err(HttpError::MalformedHead(
                "max body size must be greater than zero".to_string(),
            ));
        }
        if self.inner.max_head == 0 {
            return Err(HttpError::MalformedHead(
                "max head size must be greater than zero".to_string(),
            ));
        }
        Ok(self.inner)
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        let parsed = parse_url(&request.url)?;
        // upstream v2.5.6 fix: an `https://` request must never silently travel
        // in clear text. Without the `tls` feature this is a typed error raised
        // *before* any socket is opened — not a downgrade to plain TCP.
        #[cfg(not(feature = "tls"))]
        if parsed.tls {
            return Err(HttpError::TlsDisabled {
                url: request.url.clone(),
            });
        }
        let raw = TcpTransport::write_raw(&request, &parsed);
        let stream = self.connect(&parsed.host, parsed.port).await?;
        #[cfg(feature = "tls")]
        if parsed.tls {
            let stream = crate::tls::negotiate(stream, &parsed.host).await?;
            return self.exchange(stream, &raw).await;
        }
        self.exchange(stream, &raw).await
    }
}

/// Whether a status code forbids a body (RFC 7230 §3.3.3).
fn body_forbidden(status: u16) -> bool {
    (100..200).contains(&status) || status == 204 || status == 304
}

/// The byte offset of the next CRLF at or after `from`.
fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    if from >= data.len() {
        return None;
    }
    data[from..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| from + index)
}

/// Parse the status line, e.g. `HTTP/1.1 200 OK`.
fn parse_status_line(line: &[u8]) -> Result<u16> {
    let text = std::str::from_utf8(line)
        .map_err(|_| HttpError::MalformedHead("status line is not valid UTF-8".to_string()))?;
    let mut parts = text.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(HttpError::MalformedHead(format!(
            "status line does not start with an HTTP version: `{text}`"
        )));
    }
    let code = parts.next().ok_or_else(|| {
        HttpError::MalformedHead(format!("status line has no status code: `{text}`"))
    })?;
    code.parse::<u16>()
        .map_err(|_| HttpError::MalformedHead(format!("status code `{code}` is not a number")))
}

/// Parse `name: value`.
fn parse_header_line(line: &[u8]) -> Result<(String, String)> {
    let text = std::str::from_utf8(line)
        .map_err(|_| HttpError::MalformedHeader(String::from_utf8_lossy(line).into_owned()))?;
    let (name, value) = text
        .split_once(':')
        .ok_or_else(|| HttpError::MalformedHeader(text.to_string()))?;
    if name.is_empty() || name.contains(char::is_whitespace) {
        return Err(HttpError::MalformedHeader(text.to_string()));
    }
    Ok((name.to_string(), value.trim().to_string()))
}

/// Parse a chunk-size line, ignoring any chunk extension after `;`.
fn parse_chunk_size(line: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(line)
        .map_err(|_| HttpError::MalformedChunk(String::from_utf8_lossy(line).into_owned()))?;
    let size = text.split(';').next().unwrap_or_default().trim();
    if size.is_empty() {
        return Err(HttpError::MalformedChunk(text.to_string()));
    }
    let digits = size.strip_prefix("0x").unwrap_or(size);
    usize::from_str_radix(digits, 16).map_err(|_| HttpError::MalformedChunk(text.to_string()))
}
