//! The desktop shell's library.
//!
//! # What makes this different from upstream's shell
//!
//! Upstream agent-universe v2.5.6's two Rust sides totalled **36 lines** and
//! exposed exactly two commands — `get_platform()` and `get_sdk_version()`, the
//! latter returning a hardcoded string — and `docs/GAP-ANALYSIS.md` §9.5 records
//! that **neither frontend ever called them** (`grep invoke` found nothing).
//! A command that returns a constant and is never invoked is decoration.
//!
//! Every command here performs a real HTTP request against a running
//! `nau-daemon` and returns the daemon's own JSON body, or an error that carries
//! the HTTP status. There is no fallback that invents an answer.
//!
//! # Status
//!
//! **This crate has never been compiled.** The Tauri dependency tree is large
//! and the authoring machine has already failed a comparable build with
//! `rustc-LLVM ERROR: out of memory / Allocation failed`, so `cargo build` and
//! `tauri build` were deliberately not run. `client/README.md` §7 says so
//! plainly, and `client/platforms/` documents how to build it locally. Treat this
//! file as source under review, not as a working binary.

#![deny(missing_docs)]

use std::time::Duration;

use serde_json::Value;
use tauri::{Manager, State};
use url::Url;

/// Environment variable that overrides the daemon base URL.
pub const DAEMON_ENV: &str = "NAU_DAEMON_URL";

/// The daemon URL assumed when [`DAEMON_ENV`] is unset.
pub const DEFAULT_DAEMON: &str = "http://127.0.0.1:4002";

/// Seconds allowed for one request to the daemon.
///
/// A hung daemon must surface as an error the UI can print, not as a window that
/// stops responding.
pub const REQUEST_TIMEOUT_SECS: u64 = 15;

/// The shell's state: which daemon it talks to.
///
/// `#[derive(Default)]` is what `Builder::default()` needs; the URL itself is
/// resolved per request by [`Daemon::base_url`], so changing the environment
/// variable does not require restarting the app with a stale cached value.
#[derive(Debug, Default)]
pub struct Daemon;

impl Daemon {
    /// The base URL of the daemon, with any trailing slash removed.
    pub fn base_url(&self) -> String {
        let raw = std::env::var(DAEMON_ENV).unwrap_or_else(|_| DEFAULT_DAEMON.to_string());
        raw.trim_end_matches('/').to_string()
    }

    /// Join `path` onto the base URL, rejecting a path that escapes it.
    pub fn endpoint(&self, path: &str) -> Result<Url, String> {
        let base = self.base_url();
        let url = Url::parse(&format!("{base}{path}"))
            .map_err(|e| format!("`{base}{path}` is not a valid URL: {e}"))?;
        let origin = Url::parse(&base).map_err(|e| format!("`{base}` is not a valid URL: {e}"))?;
        // Scheme, host *and* port, so a caller cannot smuggle in another origin.
        if url.scheme() != origin.scheme()
            || url.host_str() != origin.host_str()
            || url.port_or_known_default() != origin.port_or_known_default()
        {
            return Err(format!("`{path}` points outside the daemon at {base}"));
        }
        Ok(url)
    }
}

/// A failure the UI can show: an HTTP status where there was one, plus a message.
#[derive(Debug, serde::Serialize)]
pub struct CommandError {
    /// `unauthorized_signature`, `bad_gateway`, `invalid_argument`, …
    pub error: String,
    /// Human-readable explanation, including the status when there was one.
    pub message: String,
    /// The HTTP status, when the failure came from a response.
    pub status: Option<u16>,
}

impl CommandError {
    /// Build an error with no HTTP status (a transport or input failure).
    pub fn local(error: &str, message: impl Into<String>) -> Self {
        Self {
            error: error.to_string(),
            message: message.into(),
            status: None,
        }
    }

    /// Build an error carrying the status the daemon returned.
    pub fn http(status: u16, message: impl Into<String>) -> Self {
        Self {
            error: format!("http_{status}"),
            message: message.into(),
            status: Some(status),
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(status) => write!(f, "HTTP {status} {}: {}", self.error, self.message),
            None => write!(f, "{}: {}", self.error, self.message),
        }
    }
}

/// Turn a `serde_json` body into a `CommandError`, preferring the daemon's own
/// `error` and `message` fields.
fn error_from_body(status: u16, body: Option<&Value>) -> CommandError {
    let code = body
        .and_then(|b| b.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("http_error");
    let message = body
        .and_then(|b| b.get("message"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("the daemon answered HTTP {status} with no message"));
    let mut error = CommandError::http(status, message);
    error.error = code.to_string();
    error
}

/// Perform one JSON request against the daemon.
///
/// `body` is serialized as JSON exactly as supplied — an amount stays the string
/// `"12.5"`, never a float, because the daemon refuses floats with `422` on
/// purpose and the shell must not paper over that rule.
async fn request_json(
    daemon: &Daemon,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, CommandError> {
    let url = daemon.endpoint(path).map_err(|m| CommandError::local("invalid_url", m))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .map_err(|e| CommandError::local("client_error", e.to_string()))?;

    let mut request = client.request(method, url).header("accept", "application/json");
    if let Some(body) = body {
        request = request.json(&body);
    }

    let response = request.send().await.map_err(|e| {
        CommandError::local(
            "unreachable",
            format!("could not reach the daemon at {}: {e}", daemon.base_url()),
        )
    })?;
    let status = response.status().as_u16();

    if !response.status().is_success() {
        // The daemon explains itself; surface its words, not a generic message.
        let body = response.json::<Value>().await.ok();
        return Err(error_from_body(status, body.as_ref()));
    }

    // A route that answers with an empty body is still a success, and `null` is
    // the honest representation of "no body".
    Ok(response.json::<Value>().await.unwrap_or(Value::Null))
}

// ------------------------------------------------------------------- commands

/// `GET /health` — version, protocol, upstream and market counters.
#[tauri::command]
pub async fn daemon_health(daemon: State<'_, Daemon>) -> Result<Value, CommandError> {
    request_json(&daemon, reqwest::Method::GET, "/health", None).await
}

/// `GET /stats` — market counters only.
#[tauri::command]
pub async fn market_stats(daemon: State<'_, Daemon>) -> Result<Value, CommandError> {
    request_json(&daemon, reqwest::Method::GET, "/stats", None).await
}

/// `GET /conservation` — the O(1) invariant counters.
#[tauri::command]
pub async fn conservation(daemon: State<'_, Daemon>) -> Result<Value, CommandError> {
    request_json(&daemon, reqwest::Method::GET, "/conservation", None).await
}

/// `POST /accounts/{account}/deposit` with `{"amount": "<decimal string>"}`.
///
/// `amount` is a **`&str` on purpose**. Taking an `f64` here would be the exact
/// bug the API's `422` exists to prevent: a float cannot be reproduced
/// byte-for-byte in a signed payload. The parameter type makes an invalid call
/// impossible to write, rather than merely refused at run time.
#[tauri::command]
pub async fn deposit(
    daemon: State<'_, Daemon>,
    account: String,
    amount: String,
) -> Result<Value, CommandError> {
    if !amount
        .bytes()
        .all(|b| b.is_ascii_digit() || b == b'.' || b == b'-')
        || amount.is_empty()
    {
        return Err(CommandError::local(
            "invalid_amount",
            format!("`{amount}` is not a decimal amount string such as \"12.5\""),
        ));
    }
    let path = format!("/accounts/{}/deposit", encode_segment(&account));
    request_json(
        &daemon,
        reqwest::Method::POST,
        &path,
        Some(serde_json::json!({ "amount": amount })),
    )
    .await
}

/// `POST /agents` with an already-signed `AgentCard`.
///
/// The card must carry a real Ed25519 signature: the daemon verifies it, checks
/// that `owner_key` fingerprints `owner`, and checks the nonce. A shell cannot
/// mint one on the user's behalf without holding the private key, and it must not
/// pretend to.
#[tauri::command]
pub async fn register_agent(
    daemon: State<'_, Daemon>,
    card: Value,
) -> Result<Value, CommandError> {
    if card.get("signature").and_then(Value::as_str).unwrap_or("").is_empty() {
        return Err(CommandError::local(
            "unsigned_card",
            "the card has no `signature`; the daemon verifies every card and will refuse an unsigned one",
        ));
    }
    request_json(&daemon, reqwest::Method::POST, "/agents", Some(card)).await
}

/// Percent-encode the characters that cannot appear in one request-path segment.
///
/// The daemon refuses a percent-encoded DID — `did%3Anau%3A…` is not a DID — so
/// this only rewrites the characters that genuinely cannot be sent raw, leaving
/// `:`, `.`, `-` and `_` alone.
fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b':' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// -------------------------------------------------------------------- builder

/// Build the Tauri application.
///
/// Kept separate from `main` so a test could construct the app without running
/// it — although, as the module docs say, nothing here has been compiled yet.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .setup(|app| {
            app.manage(Daemon);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            daemon_health,
            market_stats,
            conservation,
            deposit,
            register_agent
        ])
        .run(tauri::generate_context!())
        .expect("error while running the nau client shell");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_daemon_is_the_local_one() {
        // `std::env` is process-wide, so this only asserts the constant; the
        // override path is exercised through `base_url` below.
        assert_eq!(DEFAULT_DAEMON, "http://127.0.0.1:4002");
        std::env::remove_var(DAEMON_ENV);
        assert_eq!(Daemon.base_url(), DEFAULT_DAEMON);
    }

    #[test]
    fn a_trailing_slash_is_removed_so_paths_do_not_double_up() {
        std::env::set_var(DAEMON_ENV, "http://127.0.0.1:4100/");
        assert_eq!(Daemon.base_url(), "http://127.0.0.1:4100");
        assert_eq!(
            Daemon.endpoint("/health").expect("valid").as_str(),
            "http://127.0.0.1:4100/health"
        );
        std::env::remove_var(DAEMON_ENV);
    }

    #[test]
    fn a_path_cannot_escape_the_daemon_origin() {
        std::env::set_var(DAEMON_ENV, "http://127.0.0.1:4100");
        // `Url::parse` resolves an absolute path in `path` against the origin, so
        // a caller cannot smuggle in another host.
        assert!(Daemon.endpoint("/health").is_ok());
        std::env::remove_var(DAEMON_ENV);
    }

    #[test]
    fn a_did_survives_percent_encoding_untouched() {
        assert_eq!(encode_segment("did:nau:34750f98bd59fcfc"), "did:nau:34750f98bd59fcfc");
        assert_eq!(encode_segment("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn an_error_from_the_daemon_keeps_its_code_and_status() {
        let body = serde_json::json!({
            "error": "unprocessable",
            "message": "`amount` must be a decimal string"
        });
        let error = error_from_body(422, Some(&body));
        assert_eq!(error.status, Some(422));
        assert_eq!(error.error, "unprocessable");
        assert!(error.to_string().contains("decimal string"));
    }
}
