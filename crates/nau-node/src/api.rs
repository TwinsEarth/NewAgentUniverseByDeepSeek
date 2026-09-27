//! HTTP/JSON API.
//!
//! The router is a **pure function**: [`route`] takes a method, a request target and
//! an already-parsed JSON body, and returns a [`Response`]. Nothing in it touches a
//! socket, so every route, every status code and every method mismatch is testable
//! without binding a port.
//!
//! Two upstream behaviours are deliberately not reproduced:
//!
//! * **Method enforcement.** Upstream dispatched on the normalised path and only
//!   branched on the method for two of its routes, so `GET /api/v1/tasks/:id/settle`
//!   settled a task and mutating `GET`s violated HTTP caching semantics. Here each
//!   route declares its allowed methods and anything else is `405`.
//! * **Status by substring.** Upstream chose 404 vs 422 with
//!   `if e.contains("不存在")`. Here [`crate::status_for`] matches on the error type.

use std::sync::{Arc, Mutex};

use nau_consensus::{Committee, CommitteeSpec, Vote};
use nau_core::domain::Money;
use nau_core::{AgentCard, Bid, Did, Dispute, DisputeOutcome, ResultEnvelope, Task, TaskId};
use nau_ledger::AccountId;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{status_for, Node};

/// Maximum request body accepted, in bytes.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Seconds allowed for a client to finish sending its request.
pub const READ_TIMEOUT_SECS: u64 = 15;

/// A read-only summary of a node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeSnapshot {
    /// Project version.
    pub version: String,
    /// Wire protocol revision.
    pub protocol: String,
    /// The upstream project this rewrite derives from.
    pub upstream: String,
    /// Market counters.
    pub stats: nau_market::MarketStats,
}

/// A JSON response.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: Value,
}

impl Response {
    /// `200 OK`.
    pub fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }
    /// `201 Created`.
    pub fn created(body: Value) -> Self {
        Self { status: 201, body }
    }
    /// `204 No Content`.
    pub fn no_content() -> Self {
        Self {
            status: 204,
            body: Value::Null,
        }
    }
    /// An error with a machine-readable `error` field plus a human `message`.
    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({ "error": status_text(status), "message": message.into() }),
        }
    }
    /// `405` naming the methods the route does allow.
    pub fn method_not_allowed(allowed: &[&str]) -> Self {
        let mut r = Self::error(
            405,
            format!(
                "method not allowed; this route accepts {}",
                allowed.join(", ")
            ),
        );
        r.body["allow"] = json!(allowed);
        r
    }
}

/// The reason phrase for a status, used as the machine-readable error code.
fn status_text(status: u16) -> &'static str {
    match status {
        400 => "bad_request",
        401 => "unauthorized_signature",
        402 => "insufficient_funds",
        403 => "forbidden",
        404 => "not_found",
        405 => "method_not_allowed",
        409 => "conflict",
        410 => "stale",
        413 => "payload_too_large",
        415 => "unsupported_media_type",
        422 => "unprocessable",
        500 => "internal_error",
        _ => "error",
    }
}

/// Split a request target into path segments and the raw query string.
fn split_target(target: &str) -> (Vec<&str>, &str) {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    (path.split('/').filter(|s| !s.is_empty()).collect(), query)
}

/// Percent-decode a query component.
///
/// Upstream's decoder had an off-by-one (`i + 2 < len`), so a `%XX` escape at the
/// very end of the string was left undecoded.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read one query parameter.
fn query_get(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            Some(percent_decode(v))
        } else {
            None
        }
    })
}

/// Parse an amount from a JSON body.
///
/// Accepts `{"amount": "12.5"}` (a decimal **string**, so no float is ever parsed)
/// or `{"amount_minor": 12500000}`. A JSON float is refused with the same reasoning
/// the canonical-payload layer uses: floats are not portable across languages.
fn amount_from(body: Option<&Value>) -> Result<Money, String> {
    let body = body.ok_or("a JSON body is required")?;
    if let Some(s) = body.get("amount").and_then(Value::as_str) {
        return Money::parse(s).map_err(|e| e.to_string());
    }
    if let Some(n) = body.get("amount_minor").and_then(Value::as_i64) {
        return Ok(Money::from_minor(n));
    }
    if body.get("amount").is_some_and(Value::is_f64) {
        return Err(
            "`amount` must be a decimal string such as \"12.5\" or an integer `amount_minor`; \
             floating-point amounts are refused because they do not survive a round trip \
             through all three languages"
                .into(),
        );
    }
    Err("expected `amount` (decimal string) or `amount_minor` (integer)".into())
}

/// Deserialize a required JSON body field into `T`.
fn required<T: serde::de::DeserializeOwned>(
    body: Option<&Value>,
    field: &str,
) -> Result<T, String> {
    let body = body.ok_or("a JSON body is required")?;
    let value = body
        .get(field)
        .ok_or_else(|| format!("missing required field `{field}`"))?;
    serde_json::from_value(value.clone()).map_err(|e| format!("invalid `{field}`: {e}"))
}

/// Deserialize the whole body into `T`.
fn whole<T: serde::de::DeserializeOwned>(body: Option<&Value>) -> Result<T, String> {
    let body = body.ok_or("a JSON body is required")?;
    serde_json::from_value(body.clone()).map_err(|e| format!("invalid body: {e}"))
}

fn did_from(s: &str) -> Result<Did, String> {
    Did::parse(s).map_err(|e| e.to_string())
}

fn task_id_from(s: &str) -> Result<TaskId, String> {
    TaskId::parse(s).map_err(|e| e.to_string())
}

/// The router.
///
/// `method` is the HTTP method (`GET`, `POST`, ...), `target` is the request target
/// including any query string. `now` is injected so callers control time (tests use a
/// fixed value).
pub fn route(
    node: &mut Node,
    method: &str,
    target: &str,
    body: Option<&Value>,
    now: u64,
) -> Response {
    let (segments, query) = split_target(target);

    // CORS preflight is answered before routing, for every path.
    if method == "OPTIONS" {
        return Response::no_content();
    }

    match segments.as_slice() {
        [] | ["health"] | ["version"] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            let snap = node.snapshot();
            match serde_json::to_value(&snap) {
                Ok(v) => Response::ok(v),
                Err(e) => Response::error(500, e.to_string()),
            }
        }

        // ------------------------------------------------------------ agents
        ["agents"] => match method {
            "GET" => {
                // `?skill=` discovers by capability, `?q=` searches by text.
                let list: Vec<Value> = if let Some(skill) = query_get(query, "skill") {
                    node.market()
                        .discover(&skill)
                        .into_iter()
                        .filter_map(|c| serde_json::to_value(c).ok())
                        .collect()
                } else if let Some(q) = query_get(query, "q") {
                    node.market()
                        .search(&q)
                        .into_iter()
                        .filter_map(|c| serde_json::to_value(c).ok())
                        .collect()
                } else {
                    node.market()
                        .agents()
                        .into_iter()
                        .filter_map(|c| serde_json::to_value(c).ok())
                        .collect()
                };
                Response::ok(json!({ "count": list.len(), "agents": list }))
            }
            "POST" => match whole::<AgentCard>(body) {
                Ok(card) => match node.market_mut().register_agent(card, now) {
                    Ok(()) => {
                        let _ = node.persist();
                        Response::created(json!({ "status": "registered" }))
                    }
                    Err(e) => Response::error(status_for(&e), e.to_string()),
                },
                Err(m) => Response::error(422, m),
            },
            _ => Response::method_not_allowed(&["GET", "POST"]),
        },
        ["agents", did] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            match did_from(did) {
                Ok(did) => match node.market().get_agent(&did) {
                    Some(card) => match serde_json::to_value(card) {
                        Ok(v) => Response::ok(v),
                        Err(e) => Response::error(500, e.to_string()),
                    },
                    None => Response::error(404, format!("agent `{did}` is not registered")),
                },
                Err(m) => Response::error(422, m),
            }
        }

        // ------------------------------------------------------------- tasks
        ["tasks"] => match method {
            "GET" => {
                let list: Vec<Value> = node
                    .market()
                    .tasks()
                    .into_iter()
                    .filter_map(|t| serde_json::to_value(t).ok())
                    .collect();
                Response::ok(json!({ "count": list.len(), "tasks": list }))
            }
            "POST" => match whole::<Task>(body) {
                Ok(task) => match node.market_mut().publish_task(task, now) {
                    Ok(()) => {
                        let _ = node.persist();
                        Response::created(json!({ "status": "published" }))
                    }
                    Err(e) => Response::error(status_for(&e), e.to_string()),
                },
                Err(m) => Response::error(422, m),
            },
            _ => Response::method_not_allowed(&["GET", "POST"]),
        },
        ["tasks", id] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            match task_id_from(id) {
                Ok(id) => match node.market().get_task(&id) {
                    Some(task) => match serde_json::to_value(task) {
                        Ok(v) => Response::ok(v),
                        Err(e) => Response::error(500, e.to_string()),
                    },
                    None => Response::error(404, format!("task `{id}` does not exist")),
                },
                Err(m) => Response::error(422, m),
            }
        }
        ["tasks", id, action] => {
            if method != "POST" {
                return Response::method_not_allowed(&["POST"]);
            }
            let id = match task_id_from(id) {
                Ok(id) => id,
                Err(m) => return Response::error(422, m),
            };
            match *action {
                "bids" => match required::<Bid>(body, "bid") {
                    Ok(bid) => {
                        if bid.task_id != id {
                            return Response::error(
                                422,
                                format!("bid targets `{}` but the path says `{id}`", bid.task_id),
                            );
                        }
                        match node.market_mut().submit_bid(bid, now) {
                            Ok(()) => Response::created(json!({ "status": "bid recorded" })),
                            Err(e) => Response::error(status_for(&e), e.to_string()),
                        }
                    }
                    Err(m) => Response::error(422, m),
                },
                "match" => match node.market_mut().match_task(&id, now) {
                    Ok(outcome) => {
                        let _ = node.persist();
                        Response::ok(json!({
                            "status": "matched",
                            "agent_id": outcome.winner.to_string(),
                            "price_minor": outcome.price.minor(),
                            "price": outcome.price.to_decimal_string(),
                        }))
                    }
                    Err(e) => Response::error(status_for(&e), e.to_string()),
                },
                "start" => match required::<Did>(body, "executor") {
                    Ok(executor) => match node.market_mut().start_task(&id, &executor, now) {
                        Ok(()) => Response::ok(json!({ "status": "running" })),
                        Err(e) => Response::error(status_for(&e), e.to_string()),
                    },
                    Err(m) => Response::error(422, m),
                },
                "results" => match required::<ResultEnvelope>(body, "envelope") {
                    Ok(envelope) => match node.market_mut().submit_result(envelope, now) {
                        Ok(()) => {
                            let _ = node.persist();
                            Response::created(json!({ "status": "submitted" }))
                        }
                        Err(e) => Response::error(status_for(&e), e.to_string()),
                    },
                    Err(m) => Response::error(422, m),
                },
                "verify" => {
                    // The caller supplies the assigned member set and their SIGNED
                    // votes. There is deliberately no `approvals` count.
                    let members = match required::<Vec<Did>>(body, "members") {
                        Ok(m) => m,
                        Err(m) => return Response::error(422, m),
                    };
                    let votes = match required::<Vec<Vote>>(body, "votes") {
                        Ok(v) => v,
                        Err(m) => return Response::error(422, m),
                    };
                    // n and f come from the task's own recorded policy, not the caller.
                    let spec = match node.market().get_task(&id) {
                        Some(task) => match task.verification {
                            nau_core::domain::task::VerificationPolicy::Committee { n, f } => {
                                CommitteeSpec::new(n, f)
                            }
                            nau_core::domain::task::VerificationPolicy::RequesterOnly => {
                                CommitteeSpec::new(1, 0)
                            }
                        },
                        None => {
                            return Response::error(404, format!("task `{id}` does not exist"));
                        }
                    };
                    let spec = match spec {
                        Ok(s) => s,
                        Err(e) => return Response::error(422, e.to_string()),
                    };
                    let mut committee = match Committee::assign(spec, id.as_str(), members) {
                        Ok(c) => c,
                        Err(e) => return Response::error(status_for(&e), e.to_string()),
                    };
                    match node
                        .market_mut()
                        .verify_result(&id, &mut committee, &votes, now)
                    {
                        Ok(outcome) => {
                            let _ = node.persist();
                            Response::ok(json!({ "status": format!("{outcome:?}") }))
                        }
                        Err(e) => Response::error(status_for(&e), e.to_string()),
                    }
                }
                "settle" => match node.market_mut().settle(&id, now) {
                    Ok(paid) => {
                        let _ = node.persist();
                        Response::ok(json!({
                            "status": "settled",
                            "paid_minor": paid.minor(),
                            "paid": paid.to_decimal_string(),
                        }))
                    }
                    Err(e) => Response::error(status_for(&e), e.to_string()),
                },
                other => Response::error(404, format!("unknown task action `{other}`")),
            }
        }

        // ---------------------------------------------------------- accounts
        ["accounts", account, "balance"] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            match AccountId::parse(account) {
                Ok(account) => {
                    let balance = node.market().balance(&account);
                    Response::ok(json!({
                        "account": account.to_string(),
                        "balance_minor": balance.minor(),
                        "balance": balance.to_decimal_string(),
                    }))
                }
                Err(e) => Response::error(422, e.to_string()),
            }
        }
        ["accounts", account, "deposit"] => {
            if method != "POST" {
                return Response::method_not_allowed(&["POST"]);
            }
            let account = match AccountId::parse(account) {
                Ok(a) => a,
                Err(e) => return Response::error(422, e.to_string()),
            };
            let amount = match amount_from(body) {
                Ok(a) => a,
                Err(m) => return Response::error(422, m),
            };
            match node.market_mut().deposit(&account, amount, now) {
                Ok(()) => {
                    let _ = node.persist();
                    let balance = node.market().balance(&account);
                    Response::ok(json!({
                        "status": "deposited",
                        "account": account.to_string(),
                        "amount_minor": amount.minor(),
                        "balance_minor": balance.minor(),
                        "balance": balance.to_decimal_string(),
                    }))
                }
                Err(e) => Response::error(status_for(&e), e.to_string()),
            }
        }

        // --------------------------------------------------------- reporting
        ["conservation"] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            match serde_json::to_value(node.market().conservation()) {
                Ok(v) => Response::ok(v),
                Err(e) => Response::error(500, e.to_string()),
            }
        }
        ["audit"] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            match serde_json::to_value(node.market().audit()) {
                Ok(v) => Response::ok(v),
                Err(e) => Response::error(500, e.to_string()),
            }
        }
        ["stats"] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            match serde_json::to_value(node.market().stats()) {
                Ok(v) => Response::ok(v),
                Err(e) => Response::error(500, e.to_string()),
            }
        }
        ["leaderboard"] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            let limit = query_get(query, "limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(10)
                .min(1000);
            let board: Vec<Value> = node
                .market()
                .leaderboard(limit)
                .into_iter()
                .map(|(did, bps)| json!({ "agent_id": did.to_string(), "overall_bps": bps }))
                .collect();
            Response::ok(json!({ "count": board.len(), "leaderboard": board }))
        }

        // ---------------------------------------------------------- disputes
        ["disputes"] => match method {
            "GET" => {
                let list: Vec<Value> = node
                    .market()
                    .disputes()
                    .into_iter()
                    .filter_map(|d| serde_json::to_value(d).ok())
                    .collect();
                Response::ok(json!({ "count": list.len(), "disputes": list }))
            }
            "POST" => match required::<Dispute>(body, "dispute") {
                Ok(dispute) => match node.market_mut().open_dispute(dispute, now) {
                    Ok(()) => Response::created(json!({ "status": "dispute opened" })),
                    Err(e) => Response::error(status_for(&e), e.to_string()),
                },
                Err(m) => Response::error(422, m),
            },
            _ => Response::method_not_allowed(&["GET", "POST"]),
        },
        ["disputes", id] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            match node.market().get_dispute(id) {
                Some(d) => match serde_json::to_value(d) {
                    Ok(v) => Response::ok(v),
                    Err(e) => Response::error(500, e.to_string()),
                },
                None => Response::error(404, format!("dispute `{id}` does not exist")),
            }
        }
        ["disputes", id, "arbitrate"] => {
            if method != "POST" {
                return Response::method_not_allowed(&["POST"]);
            }
            match required::<DisputeOutcome>(body, "ruling") {
                Ok(ruling) => {
                    if ruling.dispute_id != *id {
                        return Response::error(
                            422,
                            format!(
                                "ruling targets `{}` but the path says `{id}`",
                                ruling.dispute_id
                            ),
                        );
                    }
                    match node.market_mut().arbitrate(ruling, now) {
                        Ok(slashed) => {
                            let _ = node.persist();
                            Response::ok(json!({
                                "status": "decided",
                                "slashed_minor": slashed.minor(),
                            }))
                        }
                        Err(e) => Response::error(status_for(&e), e.to_string()),
                    }
                }
                Err(m) => Response::error(422, m),
            }
        }

        _ => Response::error(404, format!("no route for `{}`", target)),
    }
}

/// Serve the API until `shutdown` resolves.
///
/// Differences from upstream's accept loop:
/// * a body cap ([`MAX_BODY_BYTES`]) and a read timeout ([`READ_TIMEOUT_SECS`]);
/// * an `accept` error is logged and the loop continues — upstream's
///   `listener.accept().await?` returned `Err` out of `run_daemon`, killing the
///   process on a transient `EMFILE`;
/// * each connection is handled in its own task, so one slow client cannot stall
///   the rest.
pub async fn serve<F>(node: Arc<Mutex<Node>>, addr: &str, shutdown: F) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "nau HTTP API listening");
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received");
                return Ok(());
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        let node = Arc::clone(&node);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(node, stream).await {
                                tracing::debug!(error = %e, "connection ended");
                            }
                        });
                    }
                    Err(e) => {
                        // Never fatal: a transient EMFILE/ECONNABORTED must not stop
                        // the daemon.
                        tracing::warn!(error = %e, "accept failed; continuing");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

/// Read one HTTP request and answer it.
async fn handle_connection(node: Arc<Mutex<Node>>, mut stream: TcpStream) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(READ_TIMEOUT_SECS);
    let mut chunk = [0u8; 4096];

    // Read until the headers are complete, then exactly Content-Length more bytes.
    let (header_end, content_length) = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let len = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.eq_ignore_ascii_case("content-length") {
                        v.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            break (pos + 4, len);
        }
        if buf.len() > MAX_BODY_BYTES {
            return write_json(
                &mut stream,
                &Response::error(413, "request headers too large"),
            )
            .await;
        }
        let n = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))??;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    if content_length > MAX_BODY_BYTES {
        return write_json(
            &mut stream,
            &Response::error(413, format!("body exceeds {MAX_BODY_BYTES} bytes")),
        )
        .await;
    }
    while buf.len() < header_end + content_length {
        let n = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "body read timed out")
            })??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let head = String::from_utf8_lossy(&buf[..header_end - 4]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    let body_bytes = buf
        .get(header_end..header_end + content_length)
        .unwrap_or_default();
    let parsed_body: Option<Value> = if body_bytes.is_empty() {
        None
    } else {
        match serde_json::from_slice::<Value>(body_bytes) {
            Ok(v) => Some(v),
            Err(e) => {
                return write_json(
                    &mut stream,
                    &Response::error(400, format!("request body is not valid JSON: {e}")),
                )
                .await
            }
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let response = {
        // The lock is held only across synchronous work — never across an await.
        let mut guard = match node.lock() {
            Ok(g) => g,
            // A panic elsewhere must not brick the node; recover the data.
            Err(poisoned) => poisoned.into_inner(),
        };
        route(&mut guard, &method, &target, parsed_body.as_ref(), now)
    };
    write_json(&mut stream, &response).await
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn write_json(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let body = if response.body.is_null() {
        String::new()
    } else {
        serde_json::to_string(&response.body).unwrap_or_else(|_| "{}".to_string())
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        status_text(response.status),
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body.as_bytes()).await?;
    }
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeConfig;
    use serde_json::json;

    const NOW: u64 = 1_700_000_000;

    fn node() -> Node {
        Node::ephemeral(NodeConfig::default()).expect("ephemeral node")
    }

    fn call(node: &mut Node, method: &str, target: &str, body: Option<Value>) -> Response {
        route(node, method, target, body.as_ref(), NOW)
    }

    #[test]
    fn health_and_version_are_get_only() {
        let mut n = node();
        let r = call(&mut n, "GET", "/health", None);
        assert_eq!(r.status, 200);
        assert_eq!(r.body["version"], nau_core::VERSION);
        assert_eq!(r.body["protocol"], "nau/1");

        let r = call(&mut n, "POST", "/health", None);
        assert_eq!(r.status, 405);
        assert_eq!(r.body["allow"], json!(["GET"]));
    }

    #[test]
    fn a_mutating_route_refuses_get() {
        // The upstream defect this pins down: `route` dispatched on the path and
        // almost never branched on the method, so `GET /api/v1/tasks/:id/settle`
        // settled a task. Every mutating action here must reject GET with 405.
        let mut n = node();
        for target in [
            "/tasks/task-1/settle",
            "/tasks/task-1/match",
            "/tasks/task-1/start",
            "/tasks/task-1/bids",
            "/tasks/task-1/results",
            "/tasks/task-1/verify",
            "/accounts/alice/deposit",
            "/disputes/d1/arbitrate",
        ] {
            let r = call(&mut n, "GET", target, None);
            assert_eq!(r.status, 405, "GET {target} must not be allowed");
            assert_eq!(r.body["allow"], json!(["POST"]), "GET {target}");
        }
        // And the collection routes accept only their documented methods.
        for target in ["/agents", "/tasks", "/disputes"] {
            let r = call(&mut n, "DELETE", target, None);
            assert_eq!(r.status, 405, "DELETE {target}");
        }
    }

    #[test]
    fn options_is_no_content_on_every_path() {
        let mut n = node();
        for target in ["/", "/agents", "/tasks/x/settle", "/nothing/here"] {
            let r = call(&mut n, "OPTIONS", target, None);
            assert_eq!(r.status, 204, "OPTIONS {target}");
            assert!(r.body.is_null());
        }
    }

    #[test]
    fn unknown_routes_are_404_not_500() {
        let mut n = node();
        let r = call(&mut n, "GET", "/nope", None);
        assert_eq!(r.status, 404);
        assert_eq!(r.body["error"], "not_found");

        let r = call(&mut n, "POST", "/tasks/task-1/what", None);
        assert_eq!(r.status, 404);

        let r = call(&mut n, "GET", "/agents/did:nau:34750f98bd59fcfc", None);
        assert_eq!(r.status, 404, "a valid DID that is not registered");
    }

    #[test]
    fn deposits_are_exact_and_reject_floats() {
        let mut n = node();
        // A decimal string is parsed exactly.
        let r = call(
            &mut n,
            "POST",
            "/accounts/alice/deposit",
            Some(json!({ "amount": "0.1" })),
        );
        assert_eq!(r.status, 200);
        assert_eq!(r.body["balance_minor"], 100_000);

        let r = call(
            &mut n,
            "POST",
            "/accounts/alice/deposit",
            Some(json!({ "amount": "0.2" })),
        );
        assert_eq!(r.status, 200);
        assert_eq!(r.body["balance_minor"], 300_000);
        assert_eq!(r.body["balance"], "0.3", "0.1 + 0.2 must be exactly 0.3");

        // A JSON float is refused, for the same reason the canonical layer refuses it.
        let r = call(
            &mut n,
            "POST",
            "/accounts/alice/deposit",
            Some(json!({ "amount": 12.5 })),
        );
        assert_eq!(r.status, 422);
        assert!(
            r.body["message"]
                .as_str()
                .unwrap()
                .contains("decimal string"),
            "message should explain the rule: {}",
            r.body["message"]
        );

        // A missing amount is an error, not a silent zero deposit.
        let r = call(&mut n, "POST", "/accounts/alice/deposit", Some(json!({})));
        assert_eq!(r.status, 422);

        // amount_minor is accepted as the integer form.
        let r = call(
            &mut n,
            "POST",
            "/accounts/bob/deposit",
            Some(json!({ "amount_minor": 5_000_000 })),
        );
        assert_eq!(r.status, 200);
        assert_eq!(r.body["balance_minor"], 5_000_000);
    }

    #[test]
    fn a_negative_deposit_is_refused_where_upstream_credited_the_account() {
        let mut n = node();
        let r = call(
            &mut n,
            "POST",
            "/accounts/alice/deposit",
            Some(json!({ "amount_minor": -1_000_000 })),
        );
        assert!(r.status >= 400, "negative deposits must not be accepted");
        // No funds appeared from nowhere.
        let r = call(&mut n, "GET", "/accounts/alice/balance", None);
        assert_eq!(r.body["balance_minor"], 0);
    }

    #[test]
    fn balance_conservation_and_audit_are_served_and_agree() {
        let mut n = node();
        call(
            &mut n,
            "POST",
            "/accounts/alice/deposit",
            Some(json!({ "amount": "100" })),
        );
        let c = call(&mut n, "GET", "/conservation", None);
        assert_eq!(c.status, 200);
        assert_eq!(c.body["conserved"], true);
        assert_eq!(c.body["discrepancy"], 0);
        let a = call(&mut n, "GET", "/audit", None);
        assert_eq!(a.status, 200);
        assert_eq!(a.body["conserved"], true);
        assert_eq!(a.body["sum_of_balances"], c.body["sum_of_balances"]);
    }

    #[test]
    fn collection_routes_validate_their_bodies() {
        let mut n = node();
        let r = call(&mut n, "POST", "/agents", Some(json!({ "nonsense": true })));
        assert_eq!(r.status, 422);
        let r = call(&mut n, "POST", "/tasks", Some(json!({ "nonsense": true })));
        assert_eq!(r.status, 422);
        // A missing body is also a 422, never a panic or a 500.
        let r = call(&mut n, "POST", "/agents", None);
        assert_eq!(r.status, 422);
        let r = call(&mut n, "POST", "/tasks/task-1/bids", Some(json!({})));
        assert_eq!(r.status, 422, "missing `bid` field");
    }

    #[test]
    fn a_bid_for_a_different_task_than_the_path_is_refused() {
        let mut n = node();
        let r = call(
            &mut n,
            "POST",
            "/tasks/task-1/bids",
            Some(json!({ "bid": { "task_id": "task-2" } })),
        );
        // Deserialization of the incomplete Bid fails first, which is also fine —
        // either way this must not be accepted.
        assert!(r.status >= 400);
    }

    #[test]
    fn leaderboard_limit_is_bounded() {
        let mut n = node();
        let r = call(&mut n, "GET", "/leaderboard?limit=999999", None);
        assert_eq!(r.status, 200);
        assert_eq!(r.body["count"], 0);
        // A nonsense limit falls back to the default rather than failing.
        let r = call(&mut n, "GET", "/leaderboard?limit=abc", None);
        assert_eq!(r.status, 200);
    }

    #[test]
    fn query_decoding_handles_percent_escapes_and_plus() {
        assert_eq!(query_get("q=a%20b", "q").as_deref(), Some("a b"));
        assert_eq!(query_get("q=a+b", "q").as_deref(), Some("a b"));
        // A trailing escape must still decode (upstream's decoder had an off-by-one).
        assert_eq!(query_get("q=%E4%B8%AD", "q").as_deref(), Some("中"));
        assert_eq!(query_get("q=100%", "q").as_deref(), Some("100%"));
        assert_eq!(query_get("other=1", "q"), None);
    }

    #[test]
    fn target_splitting_is_robust() {
        let (segs, q) = split_target("/tasks/t1/settle?x=1");
        assert_eq!(segs, vec!["tasks", "t1", "settle"]);
        assert_eq!(q, "x=1");
        let (segs, q) = split_target("agents");
        assert_eq!(segs, vec!["agents"]);
        assert_eq!(q, "");
        let (segs, _) = split_target("///agents///");
        assert_eq!(segs, vec!["agents"]);
    }

    #[test]
    fn a_deposit_to_the_same_account_twice_accumulates_exactly() {
        let mut n = node();
        for _ in 0..1000 {
            let r = call(
                &mut n,
                "POST",
                "/accounts/alice/deposit",
                Some(json!({ "amount": "0.001" })),
            );
            assert_eq!(r.status, 200);
        }
        let r = call(&mut n, "GET", "/accounts/alice/balance", None);
        assert_eq!(
            r.body["balance_minor"], 1_000_000,
            "1000 x 0.001 must be exactly 1.0 — the property f64 cannot guarantee"
        );
        assert_eq!(r.body["balance"], "1");
    }
}
