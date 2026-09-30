//! Typed errors for the HTTP client.
//!
//! upstream v2.5.6 fix: upstream had **no HTTP client and no HTTP error type**
//! (`gsn-core/Cargo.toml` declares no HTTP dependency at all), so every provider
//! adapter had nothing to report but a panic. Every failure mode of this crate
//! is a named variant here, and none of them is reachable through `unwrap()`.

use std::time::Duration;

/// Everything that can go wrong while building or executing a request.
///
/// The split matters to callers: [`HttpError::Status`] deliberately does **not**
/// exist — a non-2xx response is a successful HTTP exchange and is returned as
/// `Ok(HttpResponse)`, because mapping a status onto a provider-specific error is
/// the provider layer's job.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The URL is structurally unparseable (no `scheme://`, empty host, ...).
    #[error("malformed URL `{url}`: {reason}")]
    MalformedUrl {
        /// The offending URL, verbatim.
        url: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The URL has a scheme this crate cannot speak.
    #[error("unsupported URL scheme `{scheme}` (expected http or https)")]
    UnsupportedScheme {
        /// The scheme as written, lowercased.
        scheme: String,
    },

    /// An `https://` URL was used but the crate was built without `--features tls`.
    #[error(
        "TLS is required for `{url}` but this build of nau-http has the `tls` feature disabled"
    )]
    TlsDisabled {
        /// The `https://` URL that was requested.
        url: String,
    },

    /// TLS was requested and the `tls` feature is enabled, but the TLS stack
    /// could not be set up (no trust anchors, a failed handshake, ...).
    #[error("TLS unavailable: {0}")]
    TlsUnavailable(String),

    /// The TCP connection could not be established.
    #[error("could not connect to {host}:{port}: {source}")]
    Connect {
        /// Host that was dialled.
        host: String,
        /// Port that was dialled.
        port: u16,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// A plain-socket I/O operation failed.
    #[error("transport I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Connecting took longer than the configured timeout.
    #[error("connection to {host}:{port} timed out after {timeout:?}")]
    ConnectTimeout {
        /// Host that was dialled.
        host: String,
        /// Port that was dialled.
        port: u16,
        /// The timeout that expired.
        timeout: Duration,
    },

    /// A read or write stalled for longer than the configured timeout.
    #[error("read timed out after {timeout:?}")]
    ReadTimeout {
        /// The timeout that expired.
        timeout: Duration,
    },

    /// The response head (status line + headers) was not valid HTTP/1.x.
    #[error("malformed response head: {0}")]
    MalformedHead(String),

    /// A header line could not be parsed.
    #[error("malformed header line `{0}`")]
    MalformedHeader(String),

    /// The connection closed before the declared body was fully delivered.
    ///
    /// This is a *typed error, not a panic*: a truncated response is exactly the
    /// case that must not be silently treated as a short body.
    #[error("truncated response body: expected {expected} bytes, received {received}")]
    TruncatedBody {
        /// `Content-Length` from the response head.
        expected: u64,
        /// How many body bytes actually arrived before EOF.
        received: u64,
    },

    /// The body exceeded the transport's `max_body` limit.
    #[error("response body exceeds the {limit}-byte limit")]
    BodyTooLarge {
        /// The configured limit.
        limit: usize,
    },

    /// The response head exceeded the transport's `max_head` limit.
    #[error("response head exceeds the {limit}-byte limit")]
    HeadTooLarge {
        /// The configured limit.
        limit: usize,
    },

    /// Chunked transfer-coding was detected but cannot be decoded.
    ///
    /// Chunked **is** decoded by this crate; this variant exists for the frame
    /// combinations that are not (a chunked frame nested inside a
    /// `Content-Length` frame, which HTTP/1.1 forbids as a request smuggling
    /// vector).
    #[error("unsupported transfer-coding: {0}")]
    UnsupportedTransferCoding(String),

    /// A chunk-size line was not valid hexadecimal.
    #[error("malformed chunk size line `{0}`")]
    MalformedChunk(String),

    /// The body is not valid UTF-8 where text was required.
    #[error("response body is not valid UTF-8: {0}")]
    NotUtf8(#[from] std::str::Utf8Error),

    /// The body is not valid JSON, or not the JSON shape that was requested.
    #[error("response body is not the expected JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, HttpError>;
