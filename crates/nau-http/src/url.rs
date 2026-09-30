//! URL parsing for the HTTP client.
//!
//! Deliberately small: this parses exactly the subset an HTTP/1.1 request line
//! needs (scheme, host, port, path+query) and rejects everything else with a
//! typed error rather than guessing.

use crate::error::{HttpError, Result};

/// Default port for `http://`.
const HTTP_PORT: u16 = 80;
/// Default port for `https://`.
const HTTPS_PORT: u16 = 443;

/// A URL split into the pieces a request needs.
///
/// upstream v2.5.6 fix: upstream had no URL type at all, because it had no HTTP
/// client; endpoints were opaque strings handed to `Mock*Client`s. Here the
/// pieces are typed, the port is resolved, and `tls` states plainly whether the
/// connection must be encrypted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ParsedUrl {
    /// Lowercased scheme, always `http` or `https`.
    pub scheme: String,
    /// Host without brackets and without the port; never empty.
    pub host: String,
    /// Explicit port, or the scheme default.
    pub port: u16,
    /// Request target: path plus query, always starting with `/`.
    pub path: String,
    /// Whether the connection must be wrapped in TLS.
    pub tls: bool,
}

impl ParsedUrl {
    /// The value for the `Host` request header.
    ///
    /// The port is included only when it is not the scheme default, and an IPv6
    /// literal is re-bracketed, which is what RFC 7230 requires.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { HTTPS_PORT } else { HTTP_PORT };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Split a URL into scheme, host, port, path and a TLS flag.
///
/// # Errors
///
/// * [`HttpError::MalformedUrl`] — no `scheme://`, an empty host, a non-numeric
///   port, a port outside `1..=65535`, or user-info (`user@host`), which this
///   crate does not implement.
/// * [`HttpError::UnsupportedScheme`] — any scheme other than `http` or `https`,
///   including a missing scheme, which is reported as the empty scheme.
pub fn parse_url(url: &str) -> Result<ParsedUrl> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(HttpError::MalformedUrl {
            url: url.to_string(),
            reason: "URL is empty".to_string(),
        });
    }

    // upstream v2.5.6 fix: a missing scheme is a typed error, not a guess that
    // silently turns `api.example.com/v1` into a relative path.
    let (scheme_raw, rest) = match trimmed.find("://") {
        Some(index) => (&trimmed[..index], &trimmed[index + 3..]),
        None => {
            return Err(HttpError::UnsupportedScheme {
                scheme: String::new(),
            })
        }
    };
    let scheme = scheme_raw.to_ascii_lowercase();
    let tls = match scheme.as_str() {
        "http" => false,
        "https" => true,
        _ => return Err(HttpError::UnsupportedScheme { scheme }),
    };

    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(index) => (&rest[..index], rest[index..].to_string()),
        None => (rest, String::new()),
    };

    if authority.is_empty() {
        return Err(HttpError::MalformedUrl {
            url: url.to_string(),
            reason: "host is empty".to_string(),
        });
    }
    if authority.contains('@') {
        return Err(HttpError::MalformedUrl {
            url: url.to_string(),
            reason: "user-info (`user@host`) is not supported".to_string(),
        });
    }

    let (host, port) = split_authority(url, authority, tls)?;

    // A fragment is never sent on the wire, so it is dropped here.
    let path = match path.find('#') {
        Some(index) => path[..index].to_string(),
        None => path,
    };
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path
    };

    Ok(ParsedUrl {
        scheme,
        host,
        port,
        path,
        tls,
    })
}

/// Split `host[:port]`, honouring IPv6 bracket literals.
fn split_authority(url: &str, authority: &str, tls: bool) -> Result<(String, u16)> {
    let malformed = |reason: &str| HttpError::MalformedUrl {
        url: url.to_string(),
        reason: reason.to_string(),
    };

    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:8080`.
        let Some(close) = rest.find(']') else {
            return Err(malformed("IPv6 host literal is missing its closing `]`"));
        };
        let host = &rest[..close];
        let after = &rest[close + 1..];
        if host.is_empty() {
            return Err(malformed("IPv6 host literal is empty"));
        }
        if after.is_empty() {
            return Ok((host.to_string(), default_port(tls)));
        }
        let Some(port) = after.strip_prefix(':') else {
            return Err(malformed(
                "unexpected characters after the IPv6 host literal",
            ));
        };
        return Ok((host.to_string(), parse_port(url, port)?));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err(malformed("host is empty"));
    }
    match port {
        Some(port) => Ok((host.to_string(), parse_port(url, port)?)),
        None => Ok((host.to_string(), default_port(tls))),
    }
}

/// Validate an explicit port.
fn parse_port(url: &str, port: &str) -> Result<u16> {
    let value = port.parse::<u32>().map_err(|_| HttpError::MalformedUrl {
        url: url.to_string(),
        reason: format!("port `{port}` is not a number"),
    })?;
    if value == 0 || value > u32::from(u16::MAX) {
        return Err(HttpError::MalformedUrl {
            url: url.to_string(),
            reason: format!("port `{port}` is outside 1..=65535"),
        });
    }
    // `value` is provably in `1..=65535`.
    Ok(value as u16)
}

/// The default port for a scheme.
fn default_port(tls: bool) -> u16 {
    if tls {
        HTTPS_PORT
    } else {
        HTTP_PORT
    }
}
