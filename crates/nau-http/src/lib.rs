//! # nau-http — a real HTTP/1.1 client
//!
//! Minimal, honest, and complete over `tokio::net::TcpStream`. It exists because
//! upstream `agent-universe` v2.5.6 had **no HTTP client at all**.
//!
//! ## What upstream v2.5.6 did instead
//!
//! `gsn-core/Cargo.toml` declares no HTTP dependency, and all six LLM providers
//! were `Mock*Client`s returning a fixed string. `LlmBackend` / `LlmResult` had
//! no live path, every adapter `.unwrap()`ed a successful-looking result inside a
//! function that could not report failure, and no code anywhere could set an
//! `Authorization`, `x-api-key` or `anthropic-version` header. This crate is the
//! missing layer: a typed request, a typed response, a transport port, and a
//! transport that really opens a socket.
//!
//! ## What is verified here, and what is not
//!
//! **Verified**: the whole plain `http://` path, against real
//! `tokio::net::TcpListener` sockets — request framing and generated headers,
//! status/header parsing, `Content-Length` bodies, chunked bodies, read-to-EOF
//! bodies, truncation detection, the body-size cap, the read timeout, connect
//! failures, and malformed/unsupported URLs.
//!
//! **Not verified**: the `https://` path. It is a real `rustls` implementation
//! behind the default-off `tls` feature, and it is **not executed by any test in
//! this checkout** because this environment cannot complete an outbound TLS
//! connection. See [`tls`] for the details. It is never silently replaced by a
//! plain TCP connection: without the feature, `https://` is a typed
//! [`HttpError::TlsDisabled`].
//!
//! ## Design rules
//!
//! 1. **No `unsafe`.** `#![forbid(unsafe_code)]` is enforced crate-wide.
//! 2. **No panics.** No `unwrap()`, `expect()` or `panic!()` outside
//!    `#[cfg(test)]`; a poisoned mutex is recovered, and every failure is a
//!    typed [`HttpError`].
//! 3. **Non-2xx is `Ok`.** The exchange succeeded; the status is the caller's
//!    business. Only transport and protocol faults are `Err`.
//! 4. **Bounded.** A response body and a response head both have a configured
//!    maximum, and reaching the body cap is an error rather than a truncated
//!    body.
//! 5. **No silent degradation.** No TLS downgrade, no transparent
//!    decompression, no retry, no `Content-Length` guessing.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod error;
pub mod message;
pub mod tcp;
#[cfg(feature = "tls")]
pub mod tls;
pub mod transport;
pub mod url;

pub use error::{HttpError, Result};
pub use message::{Headers, HttpRequest, HttpResponse, USER_AGENT};
pub use tcp::{
    ReadWrite, TcpTransport, TcpTransportBuilder, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_BODY,
    DEFAULT_MAX_HEAD, DEFAULT_READ_TIMEOUT,
};
pub use transport::{CannedTransport, RecordingTransport, Transport};
pub use url::{parse_url, ParsedUrl};
