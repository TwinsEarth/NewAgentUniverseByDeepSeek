//! Requests, responses, and the case-insensitive header list they share.

use std::fmt;

use serde::de::DeserializeOwned;

use crate::error::Result;

/// An ordered, case-insensitive header list.
///
/// Order is preserved exactly as it appeared on the wire, and duplicates are
/// kept (a server may legitimately send `Set-Cookie` more than once). Lookups
/// are case-insensitive, which is what RFC 7230 requires and what the upstream
/// mock adapters never had to worry about because they had no wire at all.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    /// An empty list.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append a header. The name is stored as given; matching is
    /// case-insensitive.
    pub fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push((name.into(), value.into()));
    }

    /// The **first** value for `name`, case-insensitively.
    ///
    /// `None` means the header was absent. First-value-wins matches what a
    /// caller wants for `Content-Length`; use [`Headers::values`] when every
    /// occurrence matters.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value for `name`, in wire order.
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// Whether `name` is present, case-insensitively.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// The number of header lines.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no header lines.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over `(name, value)` pairs in wire order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Parse `Content-Length`, treating an unparseable value as absent so the
    /// caller can fall back to another frame instead of trusting a bogus length.
    pub fn content_length(&self) -> Option<u64> {
        self.get("content-length")
            .and_then(|value| value.trim().parse::<u64>().ok())
    }

    /// Whether `Transfer-Encoding` ends in `chunked`, which is the only
    /// transfer-coding an HTTP/1.1 message may end with.
    pub fn is_chunked(&self) -> bool {
        self.get("transfer-encoding").is_some_and(|value| {
            value
                .split(',')
                .next_back()
                .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
        })
    }
}

impl fmt::Debug for Headers {
    /// Renders like a map but keeps duplicates visible. Header *values* are
    /// printed verbatim, so callers that might have put a credential in a header
    /// should not log a whole response.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.entries.iter()).finish()
    }
}

impl FromIterator<(String, String)> for Headers {
    fn from_iter<T: IntoIterator<Item = (String, String)>>(iter: T) -> Self {
        Self {
            entries: iter.into_iter().collect(),
        }
    }
}

/// An outgoing HTTP/1.1 request.
///
/// `url` is absolute; the transport resolves it with
/// [`crate::parse_url`] and derives the request target, `Host`, and TLS
/// requirement from it, so a request can never be sent to a different host than
/// the one its URL names.
///
/// `Debug` redacts credential-shaped header values — see the manual `Debug`
/// impl — so a request that carries an API key can still be logged.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// HTTP method, e.g. `GET` or `POST`.
    pub method: String,
    /// Absolute URL, including scheme.
    pub url: String,
    /// Caller-supplied headers, in order.
    pub headers: Vec<(String, String)>,
    /// Request body, if any.
    pub body: Option<Vec<u8>>,
}

/// Header names whose values are redacted by [`HttpRequest`]'s `Debug` impl.
///
/// upstream v2.5.6 fix: upstream stored an `api_key` in its config and never
/// used it, so it never had to think about a request that carries one. A
/// credential that can reach a log line is a credential that has leaked.
const SECRET_HEADERS: [&str; 3] = ["authorization", "x-api-key", "api-key"];

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                if SECRET_HEADERS
                    .iter()
                    .any(|secret| name.eq_ignore_ascii_case(secret))
                {
                    (name.as_str(), "<redacted>")
                } else {
                    (name.as_str(), value.as_str())
                }
            })
            .collect();
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &redacted)
            .field("body", &self.body)
            .finish()
    }
}

/// The default `User-Agent`, naming the crate so a server log says where the
/// request came from.
pub const USER_AGENT: &str = concat!("nau-http/", env!("CARGO_PKG_VERSION"));

impl HttpRequest {
    /// A `GET` with no body.
    pub fn get(url: &str) -> Self {
        Self {
            method: "GET".to_string(),
            url: url.to_string(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// A `POST` whose body is `json`, with `Content-Type: application/json`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::HttpError::Json`] if `json` cannot be serialized. The
    /// body is serialized here, once, so `Content-Length` and the bytes on the
    /// wire cannot disagree.
    pub fn post_json(url: &str, json: &serde_json::Value) -> Result<Self> {
        let body = serde_json::to_vec(json)?;
        Ok(Self {
            method: "POST".to_string(),
            url: url.to_string(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: Some(body),
        })
    }

    /// Add a header, replacing any existing header with the same name
    /// (case-insensitively) so a request cannot carry two conflicting copies of
    /// a credential or a content type.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .retain(|(key, _)| !key.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// The body length that will be sent, or `None` when there is no body.
    pub fn body_len(&self) -> Option<usize> {
        self.body.as_ref().map(|body| body.len())
    }
}

/// A received HTTP/1.1 response.
///
/// A non-2xx status is still a **successful exchange**: it is returned inside
/// `Ok`, with `status` set, and the provider layer decides what it means. Only
/// transport and protocol faults are `Err`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpResponse {
    /// Status code, e.g. `200` or `404`.
    pub status: u16,
    /// Response headers, in wire order.
    pub headers: Headers,
    /// Response body bytes, after any chunked framing has been removed.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The body as text.
    ///
    /// # Errors
    ///
    /// Returns [`crate::HttpError::NotUtf8`] when the body is not valid UTF-8,
    /// instead of lossily replacing bytes.
    pub fn text(&self) -> Result<&str> {
        Ok(std::str::from_utf8(&self.body)?)
    }

    /// Deserialize the body as JSON.
    ///
    /// # Errors
    ///
    /// Returns [`crate::HttpError::Json`] when the body is not JSON or does not
    /// match `T`. A successful status with a body of the wrong shape is a real
    /// failure mode — some providers answer `200` with an error document — so it
    /// is reported, never guessed around.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    /// A short, single-line excerpt of the body for error messages.
    ///
    /// Bounded on purpose: an error must not be able to copy a multi-megabyte
    /// error page into a log line. Non-UTF-8 bytes are replaced, which is safe
    /// here precisely because this is only ever used for diagnostics.
    pub fn body_snippet(&self, limit: usize) -> String {
        let end = self.body.len().min(limit);
        String::from_utf8_lossy(&self.body[..end]).replace(['\n', '\r'], " ")
    }
}
