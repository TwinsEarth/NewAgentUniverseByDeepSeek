//! HTTP/JSON API.
//!
//! The router is a **pure function**: [`route`] takes a [`Request`] (method,
//! target, already-parsed JSON body, and the `Origin`/`Host`/`Authorization`
//! headers) plus the [`ApiPolicy`] and a `&mut Node`, and returns a [`Response`].
//! Nothing in it touches a socket, so every route, every status code, every
//! method mismatch and every authorization decision is testable without binding a
//! port.
//!
//! ## Upstream behaviours deliberately not reproduced
//!
//! * **Method enforcement.** Upstream dispatched on the normalised path and only
//!   branched on the method for two of its routes, so `GET /api/v1/tasks/:id/settle`
//!   settled a task and mutating `GET`s violated HTTP caching semantics. Here each
//!   route declares its allowed methods and anything else is `405`.
//! * **Status by substring.** Upstream chose 404 vs 422 with
//!   `if e.contains("不存在")`. Here [`crate::status_for`] matches on the error type.
//!
//! ## upstream v2.8.2 fixes
//!
//! upstream v2.8.2 fix (finding 6): upstream calls this router with **no
//! authentication at all** (`node.rs:1107-1152`) for the REST twins of its
//! mutating tools. Here [`route`] begins with a single gate: [`required_scope`]
//! (one table) says what the route needs, [`ApiPolicy::authorize`] decides whether
//! this caller has it, and every handler lives in the private [`dispatch`] below
//! the gate. A route that needs `write` or `admin` cannot be reached without an
//! authenticated principal, and [`ApiPolicy::deny_all`] — no callers configured —
//! refuses rather than allows. A principal bound to a DID may only act as that
//! DID: see [`require_actor`].
//!
//! upstream v2.8.2 fix (finding 7): upstream answers `Access-Control-Allow-Origin:
//! *` with no `Origin`/`Host` validation (`node.rs:741-746`), so any page the
//! operator visits can drive the daemon. Here the transport-level check runs
//! *before* routing: an `Origin` that is not explicitly allow-listed is refused
//! with 403 and is never echoed back, there is no wildcard to configure
//! (`allow_origin("*")` is ignored), an allowed origin is echoed exactly once with
//! `Vary: Origin`, and `Host` is checked too so a DNS-rebinding hostname cannot
//! reach the loopback daemon.
//!
//! upstream v2.8.2 fix (finding 8): upstream grows the body buffer until
//! `Content-Length` is satisfied, with no size cap and no read timeout
//! (`node.rs:984-1007`). Here the head is parsed by the pure
//! [`parse_request_head`], which refuses a duplicated or non-numeric
//! `Content-Length` and any `Transfer-Encoding` (this server does not decode
//! chunked requests, and pretending the body was empty would be a smuggling
//! vector); the body is capped by [`RequestLimits::max_body_bytes`] with a typed
//! `413`, and both the head and the body read are bounded by a total deadline that
//! produces a typed `408`. Memory is bounded by construction: the read buffer can
//! never exceed the cap plus one chunk.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nau_consensus::{Committee, CommitteeSpec, Vote};
use nau_core::domain::Money;
use nau_core::{AgentCard, Bid, Did, Dispute, DisputeOutcome, ResultEnvelope, Task, TaskId};
use nau_ledger::AccountId;
// `open_dispute` and `arbitrate` take an explicit actor (a DID plus the authority
// it claims) rather than treating any reachable caller as the arbitrator.
use nau_market::Actor;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::auth::{ApiPolicy, Principal, Refusal, Scope};
use crate::{status_for, Node};

// The sandbox routes, in their own module so that the daemon's end of the Agent
// Sandbox is reviewable in one place. Declared here (rather than in `lib.rs`)
// because `api.rs` is the module that owns routing; the file lives at
// `src/api/sandbox_routes.rs`.
mod sandbox_routes;

/// Maximum request body accepted, in bytes.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Seconds allowed for a client to finish sending its whole request.
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
    /// Extra response headers, in order.
    ///
    /// Exists so the CORS decision can be expressed as data on the response
    /// rather than as a second decision inside the socket loop. There is no
    /// wildcard here: an origin is echoed only when [`ApiPolicy`] allowed it.
    pub headers: Vec<(String, String)>,
}

impl Response {
    /// `200 OK`.
    pub fn ok(body: Value) -> Self {
        Self {
            status: 200,
            body,
            headers: Vec::new(),
        }
    }
    /// `201 Created`.
    pub fn created(body: Value) -> Self {
        Self {
            status: 201,
            body,
            headers: Vec::new(),
        }
    }
    /// `204 No Content`.
    pub fn no_content() -> Self {
        Self {
            status: 204,
            body: Value::Null,
            headers: Vec::new(),
        }
    }
    /// An error with a machine-readable `error` field plus a human `message`.
    pub fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({ "error": status_text(status), "message": message.into() }),
            headers: Vec::new(),
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
    /// An error built from a typed [`Refusal`].
    ///
    /// The refusal's own machine-readable code is used, so a client can branch on
    /// `credential_required` / `insufficient_scope` / `wrong_actor` /
    /// `forbidden_origin` instead of parsing prose.
    pub fn refused(refusal: &Refusal) -> Self {
        Self {
            status: refusal.status(),
            body: json!({ "error": refusal.code(), "message": refusal.message() }),
            headers: Vec::new(),
        }
    }
    /// Add a response header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
    /// The first value of a response header, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
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
        408 => "request_timeout",
        409 => "conflict",
        410 => "stale",
        413 => "payload_too_large",
        415 => "unsupported_media_type",
        422 => "unprocessable",
        500 => "internal_error",
        501 => "not_implemented",
        // The sandbox routes are the only ones that can answer these: a manager
        // that is shutting down, and a run that was killed at its own deadline.
        503 => "unavailable",
        504 => "timeout",
        _ => "error",
    }
}

/// One request, as the router sees it.
///
/// Time is injected here so a test controls it, and so the router stays a pure
/// function. The header fields are the ones the policy needs: `Origin` and `Host`
/// for the transport check, `Authorization` for authentication.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// The HTTP method, e.g. `GET` or `POST`.
    pub method: String,
    /// The request target, including any query string.
    pub target: String,
    /// The parsed JSON body, when there was one.
    pub body: Option<Value>,
    /// The `Origin` header, when present.
    pub origin: Option<String>,
    /// The `Host` header, when present.
    pub host: Option<String>,
    /// The `Authorization` header, when present.
    pub authorization: Option<String>,
    /// The injected current time, in Unix seconds.
    pub now: u64,
}

impl Request {
    /// A request with a method, a target and a time.
    pub fn new(method: impl Into<String>, target: impl Into<String>, now: u64) -> Self {
        Self {
            method: method.into(),
            target: target.into(),
            body: None,
            origin: None,
            host: None,
            authorization: None,
            now,
        }
    }

    /// Attach a parsed JSON body.
    pub fn with_body(mut self, body: Option<Value>) -> Self {
        self.body = body;
        self
    }

    /// Attach the `Origin` header.
    pub fn with_origin(mut self, origin: Option<impl Into<String>>) -> Self {
        self.origin = origin.map(Into::into);
        self
    }

    /// Attach the `Host` header.
    pub fn with_host(mut self, host: Option<impl Into<String>>) -> Self {
        self.host = host.map(Into::into);
        self
    }

    /// Attach the `Authorization` header.
    pub fn with_authorization(mut self, authorization: Option<impl Into<String>>) -> Self {
        self.authorization = authorization.map(Into::into);
        self
    }
}

/// Limits enforced while reading a request off the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    /// Largest accepted request body, in bytes.
    pub max_body_bytes: usize,
    /// Total time a client has to finish sending its request.
    pub read_timeout: Duration,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_BODY_BYTES,
            read_timeout: Duration::from_secs(READ_TIMEOUT_SECS),
        }
    }
}

impl RequestLimits {
    /// Limits with a different body cap and timeout, for tests and embedding.
    ///
    /// A zero cap is raised to one byte and a zero timeout to one millisecond:
    /// both would otherwise refuse every request, which looks like a network
    /// fault while actually being a misconfiguration.
    pub fn new(max_body_bytes: usize, read_timeout: Duration) -> Self {
        Self {
            max_body_bytes: max_body_bytes.max(1),
            read_timeout: if read_timeout.is_zero() {
                Duration::from_millis(1)
            } else {
                read_timeout
            },
        }
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

/// The part of a target after `sandboxes`, for either published path shape.
///
/// **upstream v2.8.2 fix: defect 1.** Upstream dispatched `/api/v1/sandboxes*`
/// before its router, which is also why nothing authenticated it. The shape is
/// preserved here — `/api/v1/sandboxes…` — and this daemon's own unprefixed shape
/// (`/sandboxes…`, the convention every other route here uses) reaches exactly the
/// same table and the same handlers, so the sandbox API cannot become a second,
/// differently-guarded surface.
fn sandbox_tail<'a>(segments: &'a [&'a str]) -> Option<&'a [&'a str]> {
    segments
        .strip_prefix(&["sandboxes"][..])
        .or_else(|| segments.strip_prefix(&["api", "v1", "sandboxes"][..]))
}

/// The scope a **sandbox** route requires.
///
/// This is consulted twice — by the gate in [`route`] and by the sandbox module
/// when it re-checks that a configured token was presented — and it is the only
/// place either answer comes from.
fn sandbox_scope(method: &str, tail: &[&str]) -> Scope {
    match (method, tail) {
        ("POST", [])
        | ("POST", [_, "exec" | "commands" | "run" | "pause" | "resume"])
        | ("DELETE", [_]) => Scope::Write,
        // The reads, and every method or sub-path these routes do not serve: a
        // wrong method gets a `405` from the handler, but it must not be reachable
        // without a credential either.
        _ => Scope::Read,
    }
}

/// The scope a route requires.
///
/// **One table.** The gate at the top of [`route`] consults it before the match,
/// so an arm cannot forget to declare that it mutates: the decision is made
/// before the arm runs. Tests assert that every mutating target in
/// [`MUTATING_TARGETS`] maps to `write` or `admin` *and* that the same target is
/// refused without a credential. Sandbox targets are listed in
/// `sandbox_routes::tests::SANDBOX_ROUTES` and asserted against
/// [`required_scope_for`] there, because their refusal without a credential is a
/// `403 sandbox_disabled` rather than the gate's `401`: with no caller configured
/// there is no principal that could own a sandbox, and that answer does not depend
/// on the method.
/// Persist, or answer with the one thing the caller has to know.
///
/// # The defect this replaces
///
/// Eight handlers did `let _ = node.persist();` and then answered `200`/`201`. A caller was
/// told the mutation succeeded while the write to disk had failed — and the mutation **had**
/// happened, in memory, so the only two answers available were "it worked" and "nothing
/// happened". Neither is true: the change exists and is not durable, and that is a third
/// outcome a caller must be able to see.
///
/// This is the defect `agent-universe`'s v3.4.2 audit named in **its own** tree — "about eight
/// `let _ = node.persist()` sites dropping persistence errors". Their v3.4.5 reports it as no
/// longer applicable there, because their `gsn-core` has no `persist` at all. Checking that
/// claim against **this** tree rather than believing it is what found it live here, at exactly
/// eight sites.
///
/// Returns `None` when the write succeeded, so a handler reads as "do the work, then persist
/// or report".
/// Ask `sys.ledger` whether it holds the escrow a settlement is about to release.
///
/// # What makes this a gate rather than a report
///
/// The ledger's answer decides. A settlement it has never escrowed is refused **before**
/// anything moves, and the refusal names the plugin — because the operator's next question is
/// which of the two records is wrong, and a refusal that does not say who disagreed sends them
/// to the wrong one.
///
/// # Why the plugin is asked rather than the market's own books
///
/// The market's books are the thing being checked. Asking them whether they are right is the
/// shape of check this project keeps finding: a control that consults the same record it is
/// supposed to be testing. `sys.ledger` reads through a separate interface, and since the
/// previous round it reads the **same** ledger — which is what makes disagreement meaningful
/// rather than a second, emptier opinion.
///
/// # Errors
///
/// A response, when the settlement must not proceed.
fn ledger_gate(node: &mut crate::Node, task: &str, now: u64) -> Result<(), Response> {
    let answer = match node.plugins_mut().call(
        "com.twinsearth.sys.ledger",
        "plugin:message:send",
        json!({ "op": "escrow", "task": task }),
        now,
    ) {
        Ok(answer) => answer,
        Err(e) => {
            return Err(Response::error(
                503,
                format!(
                    "cannot settle: `com.twinsearth.sys.ledger` could not be asked whether it \
                     holds this escrow ({e}), and releasing funds without that answer is the one \
                     thing this route will not do"
                ),
            ))
        }
    };
    if answer.get("open").and_then(Value::as_bool) != Some(true) {
        return Err(Response::error(
            409,
            format!(
                "cannot settle `{task}`: `com.twinsearth.sys.ledger` holds no escrow for it, so \
                 there is nothing to release. Either the task was never matched -- matching is \
                 what locks the budget -- or its escrow was already released. The ledger is asked \
                 first because it is the record the release would move money out of."
            ),
        ));
    }
    Ok(())
}

fn persist_or_report(node: &mut crate::Node) -> Option<Response> {
    match node.persist() {
        Ok(()) => None,
        Err(e) => Some(Response::error(
            500,
            format!(
                "the change was applied in memory but could not be written to disk, so it will \
                 not survive a restart: {e}"
            ),
        )),
    }
}

fn required_scope(method: &str, segments: &[&str]) -> Scope {
    if let Some(tail) = sandbox_tail(segments) {
        return sandbox_scope(method, tail);
    }
    match (method, segments) {
        ("POST", ["agents"]) | ("POST", ["tasks"]) | ("POST", ["disputes"]) => Scope::Write,
        ("POST", ["tasks", _, "bids"])
        | ("POST", ["tasks", _, "match"])
        | ("POST", ["tasks", _, "start"])
        | ("POST", ["tasks", _, "results"])
        | ("POST", ["tasks", _, "verify"])
        | ("POST", ["tasks", _, "settle"])
        | ("POST", ["accounts", _, "deposit"]) => Scope::Write,
        // Deciding a dispute can slash another account's stake.
        ("POST", ["disputes", _, "arbitrate"]) => Scope::Admin,
        // Calling a system plugin is admin, not write. The plugins behind this route are the
        // node's own machinery: `sys.policy` writes the policy table, `sys.blacklist` reads
        // the quarantine, `sys.orchestrator` speaks for the load order. A route that lets a
        // write-scoped caller reach them is a route that lets a caller reach the node's
        // internals through a plugin id.
        ("POST", ["plugins", _, "call"]) => Scope::Admin,
        _ => Scope::Read,
    }
}

/// The scope [`route`] requires of `method target`, for tests and clients.
///
/// Exposed so a test (or an operator's script) can ask what a route demands
/// without guessing from the prose.
pub fn required_scope_for(method: &str, target: &str) -> Scope {
    let (segments, _) = split_target(target);
    required_scope(method, &segments)
}

/// Every mutating route, as `(method, target)` pairs, for the gate tests.
///
/// The router's arms and this list are the two hand-maintained views of the same
/// table; `every_mutating_route_refuses_without_a_credential` asserts that they
/// agree with [`required_scope`] and that the live gate refuses each one.
pub const MUTATING_TARGETS: &[(&str, &str)] = &[
    ("POST", "/agents"),
    ("POST", "/tasks"),
    ("POST", "/tasks/task-1/bids"),
    ("POST", "/tasks/task-1/match"),
    ("POST", "/tasks/task-1/start"),
    ("POST", "/tasks/task-1/results"),
    ("POST", "/tasks/task-1/verify"),
    ("POST", "/tasks/task-1/settle"),
    ("POST", "/accounts/alice/deposit"),
    ("POST", "/disputes"),
    ("POST", "/disputes/d1/arbitrate"),
    // Calling a system plugin. Admin scope, and on the list because it is the one route
    // that reaches the node's own machinery: the plugins behind it include the policy
    // writer and the blacklist reader.
    ("POST", "/plugins/com.twinsearth.sys.policy/call"),
];

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
///
/// upstream v2.8.2 fix (finding 4): this is the only place an externally supplied
/// number enters the money path, and every float — finite or not — is refused
/// before it can be ordered or converted. A JSON body can only carry a finite
/// number in the first place, so a `NaN` cannot even be expressed.
fn amount_from(body: Option<&Value>) -> Result<Money, String> {
    let body = body.ok_or("a JSON body is required")?;
    if let Some(s) = body.get("amount").and_then(Value::as_str) {
        return Money::parse(s).map_err(|e| e.to_string());
    }
    if let Some(n) = body.get("amount_minor").and_then(Value::as_i64) {
        return Ok(Money::from_minor(n));
    }
    if body.get("amount").is_some_and(Value::is_f64)
        || body.get("amount_minor").is_some_and(Value::is_f64)
    {
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

/// Require that a DID-bound caller acts only as itself.
///
/// upstream v2.8.2 fix (finding 6): a shared secret authenticates a *request*,
/// never a *caller*, so upstream cannot express "this token may only touch this
/// account". A [`Principal`] bound to a DID must name that DID wherever the body
/// names an actor; a principal configured without a DID is a service credential
/// and is not identity-bound, which is a deliberate and documented privilege.
///
/// # Errors
///
/// [`Refusal::WrongActor`] as a `403` response.
pub fn require_actor(principal: &Principal, claimed: &str) -> Result<(), Response> {
    let Some(did) = principal.did() else {
        return Ok(());
    };
    if did.as_str() == claimed {
        return Ok(());
    }
    Err(Response::refused(&Refusal::WrongActor {
        caller: principal.id().to_string(),
        did: did.to_string(),
        claimed: claimed.to_string(),
    }))
}

/// The router.
///
/// `request.method` is the HTTP method, `request.target` the request target
/// including any query string, and `request.now` the injected time. `policy` is
/// the authentication and cross-origin policy; see [`ApiPolicy::deny_all`] for the
/// default that refuses every mutation.
pub fn route(node: &mut Node, request: &Request, policy: &ApiPolicy) -> Response {
    let (segments, query) = split_target(&request.target);

    // 1. Transport-level policy for *every* request, before any routing: a
    //    cross-origin caller or a rebinding `Host` is refused here, and the
    //    refusal carries no CORS header, so a hostile origin is never echoed.
    if let Err(refusal) = policy.check_transport(request.origin.as_deref(), request.host.as_deref())
    {
        return Response::refused(&refusal);
    }

    // 2. CORS preflight, answered before routing but only for an origin the
    //    policy allows.
    if request.method == "OPTIONS" {
        return preflight(request, policy);
    }

    // 3. Sandbox routes are closed entirely while no caller is configured.
    //
    //    upstream v2.8.2 fix: defect 1 — upstream's sandbox routes were reachable
    //    with *nothing* configured, because nothing was ever checked. This check
    //    runs before the scope gate so that every method gets the same answer: a
    //    `POST` would otherwise be a `401` from the gate and a `GET` a `403` from
    //    the sandbox module, and "which status means closed?" would depend on the
    //    method. The sandbox module repeats the check for its own callers; this is
    //    the one that decides the answer.
    if sandbox_tail(&segments).is_some() && policy.authenticator().configured_callers() == 0 {
        return sandbox_routes::disabled_response();
    }

    // 4. The single authorization gate. `required_scope` is the one table.
    let requirement = required_scope(&request.method, &segments);
    let principal = match policy.authorize(request.authorization.as_deref(), requirement) {
        Ok(principal) => principal,
        Err(refusal) => {
            let mut response = Response::refused(&refusal);
            // A caller that authenticated may still be told which origin it was
            // allowed from; a refusal never *grants* an origin.
            if let Some(origin) = allowed_origin(request, policy) {
                response = response.with_header("Access-Control-Allow-Origin", &origin);
                response = response.with_header("Vary", "Origin");
            }
            return response;
        }
    };

    // 5. Everything below the gate. `dispatch` is private and is the only place
    //    this module mutates the node. The policy travels with the request
    //    because sandbox routes consult it a second time: the gate above admits an
    //    anonymous *read*, and a sandbox is owned by a principal, so those routes
    //    additionally require a presented, configured token.
    let mut response = dispatch(node, request, &segments, query, &principal, policy);

    // 6. Echo an allowed origin so a browser can read the answer. The value is
    //    the exact origin that was allow-listed, never `*`.
    if let Some(origin) = allowed_origin(request, policy) {
        response = response.with_header("Access-Control-Allow-Origin", &origin);
        response = response.with_header("Vary", "Origin");
    }
    response
}

/// The exact origin to echo, when the policy allows it.
fn allowed_origin(request: &Request, policy: &ApiPolicy) -> Option<String> {
    let origin = request.origin.as_deref()?.trim();
    if origin.is_empty() {
        return None;
    }
    policy.origin_allowed(origin).then(|| origin.to_string())
}

/// Answer a CORS preflight.
///
/// A hostile origin never reaches this function: [`ApiPolicy::check_transport`]
/// refused it before routing. The response therefore never carries
/// `Access-Control-Allow-Origin` for an origin that was not allow-listed, and
/// there is no wildcard branch to reach.
fn preflight(request: &Request, policy: &ApiPolicy) -> Response {
    let mut response = Response::no_content();
    match allowed_origin(request, policy) {
        Some(origin) => {
            response = response
                .with_header("Access-Control-Allow-Origin", &origin)
                .with_header("Vary", "Origin")
                .with_header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
                .with_header(
                    "Access-Control-Allow-Headers",
                    "authorization, content-type",
                )
                .with_header("Access-Control-Max-Age", "600");
        }
        None => {
            // No `Origin` at all: not a browser preflight. Answer it, but grant
            // nothing.
            response = response.with_header("Vary", "Origin");
        }
    }
    response
}

/// Route one request, below the authorization gate.
///
/// Private on purpose: it is the only place in this module that mutates the node,
/// and it is called only from [`route`] after the gate.
fn dispatch(
    node: &mut Node,
    request: &Request,
    segments: &[&str],
    query: &str,
    principal: &Principal,
    policy: &ApiPolicy,
) -> Response {
    let method = request.method.as_str();
    let body = request.body.as_ref();
    let now = request.now;

    // upstream v2.8.2 fix: defect 1 — upstream dispatched `/api/v1/sandboxes*`
    // here, before its router and with no authentication at all. These routes go
    // through this one gate and then through their own module, which requires a
    // presented, configured token *in addition* to the scope above and binds the
    // sandbox to that principal.
    if let Some(tail) = sandbox_tail(segments) {
        return sandbox_routes::dispatch(node, request, tail, principal, policy);
    }

    match segments {
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

        // ------------------------------------------------------------ plugins
        //
        // The node's own functionality is plugins, so "which of them are running" is a
        // health question about the node rather than a detail about a subsystem. Read scope,
        // because this exposes names and states and no capability material.
        //
        // A route exists at all because a plugin host nobody can observe is
        // indistinguishable from one that is not running: before this the daemon booted the
        // plugins and the only way to find out was to read a log line.
        ["plugins"] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            let boot = node.plugins();
            let plugins: Vec<Value> = boot
                .names
                .iter()
                .map(|name| {
                    json!({
                        "id": name,
                        "state": boot
                            .state(name)
                            .map(nau_plugin::lifecycle::PluginState::label)
                            .unwrap_or("unknown"),
                        // Messages the plugin queued for the bus that nobody has carried.
                        //
                        // Nothing in the running node drains an outbox -- the daemon holds no
                        // Bus and the host holds no Registry for `Bus::send` to resolve
                        // recipients against -- so this number is the only evidence that a
                        // plugin tried to talk to another one. A queue nobody reads and a
                        // queue that is always empty are indistinguishable without it.
                        "outbox_pending": boot.outbox_len(name).unwrap_or(0),
                    })
                })
                .collect();
            Response::ok(json!({
                "count": boot.len(),
                // The ephemeral key the host generated at boot. Reported rather than
                // hidden, because it is what the manifests were signed with and an operator
                // comparing two boot reports needs to see it change across a restart.
                "host_key": boot.vendor_key_hex,
                "plugins": plugins,
            }))
        }

        // `POST /plugins/<id>/call` — the node *using* its plugins rather than only booting
        // them.
        //
        // # Why this route is the point of the whole plugin host
        //
        // Booting seventeen plugins and reporting their state makes them observable; it does
        // not make them do anything. Until this arm existed the daemon started its own
        // functionality and never invoked it -- the same "written but not wired" shape one
        // level further in, and the reason `plugins_mut` sat in `Node` as dead code.
        //
        // The caller names the capability it wants the plugin to act under, and the
        // **plugin's own** `require_declared` decides whether that is acceptable. The route
        // does not keep a second list of which capability each plugin takes, because such a
        // list is a second source of truth for the capability model and would be the thing
        // that goes stale.
        ["plugins", plugin, "call"] => {
            if method != "POST" {
                return Response::method_not_allowed(&["POST"]);
            }
            let Some(body) = body else {
                return Response::error(400, "a plugin call needs a JSON body");
            };
            let Some(capability) = body.get("capability").and_then(Value::as_str) else {
                return Response::error(
                    400,
                    "a plugin call must name the `capability` it acts under; the plugin's own \
                     `require_declared` is what decides whether that capability is acceptable, \
                     so the caller has to state it",
                );
            };
            // Everything except `capability` is the plugin's own payload, passed through
            // untouched: reshaping it here would put a second, disagreeing view of each
            // plugin's protocol in the router.
            let mut payload = body.clone();
            if let Some(object) = payload.as_object_mut() {
                object.remove("capability");
            }
            match node.plugins_mut().call(plugin, capability, payload, now) {
                Ok(answer) => {
                    // A plugin that queued bus messages during the call has them carried now.
                    //
                    // `flush_outbox` takes the host mutably and the bus mutably, which is two
                    // borrows of this node and therefore has to happen here rather than inside
                    // the host. Without this the daemon had **no bus at all**: a system plugin
                    // could queue a message and nothing would ever carry it, so the internal
                    // messaging protocol existed as a kernel component with tests and no
                    // runtime. The drain is reported alongside the answer because a refusal
                    // there is a fact the caller has to see, not a log line.
                    let carried = node
                        .drain_plugin_outbox(plugin, now)
                        .map(|outcomes| {
                            outcomes
                                .iter()
                                .map(|outcome| {
                                    json!({
                                        "message_id": outcome.message_id,
                                        "target": outcome.target,
                                        "delivered_to": outcome.delivered_to,
                                        "refusal": outcome.refusal,
                                    })
                                })
                                .collect::<Vec<Value>>()
                        })
                        .unwrap_or_default();
                    let mut answer = answer;
                    if let Some(object) = answer.as_object_mut() {
                        object.insert("bus".to_string(), Value::Array(carried));
                    }
                    Response::ok(answer)
                }
                // The host's and the plugin's refusals are values here, not errors: an
                // unknown target, a plugin that is not running, a capability it does not
                // declare -- each is an answer a caller has to read.
                Err(refusal) => Response::error(400, refusal),
            }
        }

        // `POST /plugins/com.twinsearth.sys.security.police/report` — C-03's enforcement point.
        //
        // # Why this route is two calls and one answer
        //
        // C-03 splits the act in two, deliberately: the **police decides** whether a report is
        // well-formed and against whom, and the **host enforces**, because the lifecycles are the
        // host's. A route that only called the plugin would return a verdict nothing acted on --
        // the "written but not wired" shape -- and a route that only called `record_violation`
        // would be an unguarded way to quarantine any plugin, with the police body reduced to
        // decoration.
        //
        // So one request does both, in that order, and the second half runs **only if the first
        // accepted**. A refused report changes nothing.
        ["plugins", "com.twinsearth.sys.security.police", "report"] => {
            if method != "POST" {
                return Response::method_not_allowed(&["POST"]);
            }
            let Some(body) = body else {
                return Response::error(400, "a violation report needs a JSON body");
            };
            for field in ["subject", "what"] {
                if body.get(field).and_then(Value::as_str).is_none() {
                    return Response::error(
                        400,
                        format!(
                            "a violation report must name `{field}`; a report that does not say \
                             who and what is one the host cannot act on"
                        ),
                    );
                }
            }

            // 1. the police decides.
            //
            // The op is set **here**, not taken from the body. This is the report route, and a
            // caller that could name the operation would be able to make it call any of the
            // police's operations — including ones that do not report anything, whose answers this
            // route would then hand to `record_violation` as though they were verdicts.
            let mut payload = body.clone();
            if let Some(object) = payload.as_object_mut() {
                let _ = object.remove("capability");
                let _ = object.insert("op".to_string(), Value::String("report".to_string()));
            }
            let verdict = node.plugins_mut().call(
                "com.twinsearth.sys.security.police",
                // The police's own authority, because deciding that a plugin has violated is
                // acting on that plugin. Sending a weaker capability would be refused by the
                // plugin -- correctly, and that refusal is what this line responds to rather than
                // works around.
                "kernel:plugin:manage",
                payload,
                now,
            );
            let verdict = match verdict {
                Ok(v) => v,
                Err(refusal) => return Response::error(400, refusal),
            };

            // 2. and the host enforces, through `Lifecycle::violation` and the one transition
            //    table. The violation body is read from the **verdict** rather than from the
            //    request: the plugin has by now validated it, and re-reading the caller's copy
            //    would be a second parse that could disagree with the first.
            let subject = verdict
                .get("subject")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let what = verdict
                .get("what")
                .and_then(Value::as_str)
                .unwrap_or_default();
            match node.plugins_mut().record_violation(subject, what, now) {
                Ok(state) => Response::ok(json!({
                    "subject": subject,
                    "what": what,
                    "accepted_by": "com.twinsearth.sys.security.police",
                    "state": state.label(),
                    "violations": node.plugins().violations(subject),
                    "threshold": nau_plugin::lifecycle::VIOLATION_THRESHOLD,
                })),
                Err(refusal) => Response::error(400, refusal.to_string()),
            }
        }

        // ------------------------------------------------------ the bus (PMB)
        //
        // The internal messaging protocol's **external** interface. Until this route existed
        // the bus was invisible from outside the kernel: `Bus::audit()` and `Bus::limits()` had
        // no caller anywhere in `nau-node`, so an operator could not see what plugins had sent,
        // to whom, or whether it was delivered.
        //
        // There is deliberately **no** `POST /bus/send`. A PMB send has to present the caller's
        // capability token, and an operator arriving over HTTP has none -- a token is minted for
        // a plugin at load time. Minting one so that a route could send would create an
        // authority the host does not have, which is exactly the kind of quiet widening this
        // build refuses. The payload says so, rather than leaving the missing route to be read
        // as an oversight.
        ["bus"] => match method {
            "GET" => {
                let bus = node.bus();
                let limits = bus.limits();
                let audit = bus.audit();
                // Newest first, capped: the audit is bounded by the bus's own limit, and an
                // endpoint that returned all 4096 records would be a way to make the daemon
                // produce a large response on demand.
                let recent: Vec<&nau_plugin::bus::AuditRecord> =
                    audit.iter().rev().take(50).collect();
                Response::ok(json!({
                    "limits": {
                        "max_message_bytes": limits.max_message_bytes,
                        "max_messages_per_minute": limits.max_messages_per_minute,
                        "max_audit_records": limits.max_audit_records,
                    },
                    "records": audit.len(),
                    "carried": audit.iter().filter(|r| r.delivered).count(),
                    "refused": audit.iter().filter(|r| !r.delivered).count(),
                    "audit": recent,
                    "send_via_http": false,
                    "why_not": "a PMB send must present a plugin's capability token, and an HTTP \
                                 caller has none; minting one here would grant an authority this \
                                 host does not have",
                }))
            }
            _ => Response::method_not_allowed(&["GET"]),
        },

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
                Ok(card) => {
                    if let Err(response) = require_actor(principal, card.owner.as_str()) {
                        return response;
                    }
                    match node.market_mut().register_agent(card, now) {
                        Ok(()) => {
                            // Persist, or say plainly that the change is in memory and not on disk.
                            if let Some(refusal) = persist_or_report(node) {
                                return refusal;
                            }
                            Response::created(json!({ "status": "registered" }))
                        }
                        Err(e) => Response::error(status_for(&e), e.to_string()),
                    }
                }
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

        // ---------------------------------------------------------------- p2p
        // Read-only views of what peers have told us. Nothing here mutates the
        // market: a card that arrived over the wire is shown but never enters the
        // staked registry, so an unauthenticated GET cannot change local state.
        ["p2p", "peers"] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            let directory = node.directory().snapshot();
            Response::ok(json!({
                "local_peer_id": directory.local_peer_id,
                "local_did": directory.local_did,
                "count": directory.peers.len(),
                "peers": directory.peers.values().collect::<Vec<_>>(),
                "frames_published": directory.frames_published,
                "frames_received": directory.frames_received,
                "frames_rejected": directory.frames_rejected,
            }))
        }
        ["p2p", "agents"] => {
            if method != "GET" && method != "HEAD" {
                return Response::method_not_allowed(&["GET"]);
            }
            let directory = node.directory().snapshot();
            Response::ok(json!({
                "local_did": directory.local_did,
                "count": directory.agents.len(),
                "agents": directory.agents.values().collect::<Vec<_>>(),
            }))
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
                Ok(task) => {
                    if let Err(response) = require_actor(principal, task.spec.owner.as_str()) {
                        return response;
                    }
                    match node.market_mut().publish_task(task, now) {
                        Ok(()) => {
                            // Persist, or say plainly that the change is in memory and not on disk.
                            if let Some(refusal) = persist_or_report(node) {
                                return refusal;
                            }
                            Response::created(json!({ "status": "published" }))
                        }
                        Err(e) => Response::error(status_for(&e), e.to_string()),
                    }
                }
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
                        if let Err(response) = require_actor(principal, bid.bidder.as_str()) {
                            return response;
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
                        // Persist, or say plainly that the change is in memory and not on disk.
                        if let Some(refusal) = persist_or_report(node) {
                            return refusal;
                        }
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
                    Ok(executor) => {
                        if let Err(response) = require_actor(principal, executor.as_str()) {
                            return response;
                        }
                        match node.market_mut().start_task(&id, &executor, now) {
                            Ok(()) => Response::ok(json!({ "status": "running" })),
                            Err(e) => Response::error(status_for(&e), e.to_string()),
                        }
                    }
                    Err(m) => Response::error(422, m),
                },
                "results" => match required::<ResultEnvelope>(body, "envelope") {
                    Ok(envelope) => {
                        if let Err(response) = require_actor(principal, envelope.agent.as_str()) {
                            return response;
                        }
                        match node.market_mut().submit_result(envelope, now) {
                            Ok(()) => {
                                // Persist, or say plainly that the change is in memory and not on disk.
                                if let Some(refusal) = persist_or_report(node) {
                                    return refusal;
                                }
                                Response::created(json!({ "status": "submitted" }))
                            }
                            Err(e) => Response::error(status_for(&e), e.to_string()),
                        }
                    }
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
                    // Every vote must be cast by the identity that signed it, and a
                    // DID-bound caller may only contribute its own vote.
                    if let Some(did) = principal.did() {
                        if let Some(foreign) = votes
                            .iter()
                            .find(|vote| vote.voter.as_str() != did.as_str())
                        {
                            return Response::refused(&Refusal::WrongActor {
                                caller: principal.id().to_string(),
                                did: did.to_string(),
                                claimed: foreign.voter.to_string(),
                            });
                        }
                    }
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
                            // Persist, or say plainly that the change is in memory and not on disk.
                            if let Some(refusal) = persist_or_report(node) {
                                return refusal;
                            }
                            Response::ok(json!({ "status": format!("{outcome:?}") }))
                        }
                        Err(e) => Response::error(status_for(&e), e.to_string()),
                    }
                }
                // **B1: the plugin's answer decides whether the market may act.**
                //
                // Upstream calls this "the orchestrator takes over the data plane", and this is
                // the shape of it: the route asks a plugin first and moves money only if the
                // answer permits. Ours asks `sys.ledger` whether it holds an escrow for this
                // task, because the market and the ledger are two records of the same money and
                // nothing until now made them agree before a release.
                //
                // This gate was impossible to build honestly until the previous round: the
                // plugin was constructed over an **empty** ledger of its own, so it answered
                // `open: false` to every task and the gate would have refused every settlement
                // while looking like a control.
                "settle" => match ledger_gate(node, id.as_str(), now) {
                    Err(refusal) => refusal,
                    Ok(()) => match node.market_mut().settle(&id, now) {
                        Ok(paid) => {
                            // Persist, or say plainly that the change is in memory and not on disk.
                            if let Some(refusal) = persist_or_report(node) {
                                return refusal;
                            }
                            Response::ok(json!({
                                "status": "settled",
                                "paid_minor": paid.minor(),
                                "paid": paid.to_decimal_string(),
                            }))
                        }
                        Err(e) => Response::error(status_for(&e), e.to_string()),
                    },
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
            if let Err(response) = require_actor(principal, account.as_str()) {
                return response;
            }
            let amount = match amount_from(body) {
                Ok(a) => a,
                Err(m) => return Response::error(422, m),
            };
            match node.market_mut().deposit(&account, amount, now) {
                Ok(()) => {
                    // Persist, or say plainly that the change is in memory and not on disk.
                    if let Some(refusal) = persist_or_report(node) {
                        return refusal;
                    }
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
                Ok(dispute) => {
                    if let Err(response) = require_actor(principal, dispute.complainant.as_str()) {
                        return response;
                    }
                    // The actor is the DID that signed the dispute, acting as a
                    // party; the market checks it against the task. `require_actor`
                    // above already bound a DID-carrying caller to exactly this
                    // identity.
                    match node.market_mut().open_dispute(
                        Actor::party(dispute.complainant.clone()),
                        dispute,
                        now,
                    ) {
                        Ok(()) => Response::created(json!({ "status": "dispute opened" })),
                        Err(e) => Response::error(status_for(&e), e.to_string()),
                    }
                }
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
                    if let Err(response) = require_actor(principal, ruling.arbitrator.as_str()) {
                        return response;
                    }
                    // The actor is the DID that signed the ruling, claiming the
                    // arbitrator authority; the market checks that it is not a
                    // party to the dispute. `require_actor` above already bound a
                    // DID-carrying caller to exactly this identity, and the route
                    // itself requires the `admin` scope.
                    match node.market_mut().arbitrate(
                        Actor::arbitrator(ruling.arbitrator.clone()),
                        ruling,
                        now,
                    ) {
                        Ok(slashed) => {
                            // Persist, or say plainly that the change is in memory and not on disk.
                            if let Some(refusal) = persist_or_report(node) {
                                return refusal;
                            }
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

        _ => Response::error(404, format!("no route for `{}`", request.target)),
    }
}

// ---------------------------------------------------------------------------
// The socket loop
// ---------------------------------------------------------------------------

/// The head of one request, as parsed from the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    /// The HTTP method.
    pub method: String,
    /// The request target.
    pub target: String,
    /// The declared body length, when the request declared one.
    pub content_length: Option<usize>,
    /// The `Origin` header.
    pub origin: Option<String>,
    /// The `Host` header.
    pub host: Option<String>,
    /// The `Authorization` header.
    pub authorization: Option<String>,
}

/// Parse a request head.
///
/// upstream v2.8.2 fix (finding 8): a duplicated `Content-Length`, a
/// non-numeric one, a negative one and any `Transfer-Encoding` are **refused**
/// rather than treated as "no body". Upstream read the first match and fell back
/// to a zero length, so a request that declared a body it did not need to deliver
/// — or two conflicting lengths — could be answered as though the body did not
/// exist. This server does not decode a chunked request body, and answering a
/// chunked request as if it were empty is a request-smuggling shape, so the
/// transfer coding is refused explicitly instead.
///
/// # Errors
///
/// A human-readable reason, which the caller turns into a `400`.
pub fn parse_request_head(head: &str) -> Result<RequestHead, String> {
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .filter(|method| !method.is_empty())
        .ok_or_else(|| "the request line has no method".to_string())?
        .to_string();
    if !method.chars().all(|c| c.is_ascii_uppercase() || c == '-') {
        return Err(format!("`{method}` is not an HTTP method"));
    }
    let target = parts
        .next()
        .ok_or_else(|| "the request line has no request target".to_string())?
        .to_string();

    let mut content_lengths: Vec<&str> = Vec::new();
    let mut origin = None;
    let mut host = None;
    let mut authorization = None;
    let mut transfer_encoding: Option<&str> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_lengths.push(value);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding = Some(value);
        } else if name.eq_ignore_ascii_case("origin") {
            origin = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("host") {
            host = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_string());
        }
    }

    if let Some(encoding) = transfer_encoding {
        return Err(format!(
            "`Transfer-Encoding: {encoding}` is not supported; send a `Content-Length` body"
        ));
    }
    let content_length = match content_lengths.as_slice() {
        [] => None,
        [single] => {
            let value = single.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!(
                    "`Content-Length: {value}` is not a non-negative integer"
                ));
            }
            Some(
                value
                    .parse::<usize>()
                    .map_err(|_| format!("`Content-Length: {value}` does not fit in memory"))?,
            )
        }
        many => {
            return Err(format!(
                "the request declares {n} conflicting `Content-Length` values",
                n = many.len()
            ))
        }
    };

    Ok(RequestHead {
        method,
        target,
        content_length,
        origin,
        host,
        authorization,
    })
}

/// Serve the API until `shutdown` resolves.
///
/// Differences from upstream's accept loop:
/// * a body cap ([`MAX_BODY_BYTES`]) and a read timeout ([`READ_TIMEOUT_SECS`]),
///   both typed (`413`/`408`);
/// * an `accept` error is logged and the loop continues — upstream's
///   `listener.accept().await?` returned `Err` out of `run_daemon`, killing the
///   process on a transient `EMFILE`;
/// * each connection is handled in its own task, so one slow client cannot stall
///   the rest.
///
/// The policy comes from the environment (see [`crate::auth`]). A **non-loopback**
/// bind address with no configured caller is refused before the socket is bound:
/// serving a privileged, unauthenticated API to the network is not a configuration
/// this daemon will accept.
pub async fn serve<F>(node: Arc<Mutex<Node>>, addr: &str, shutdown: F) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let policy = ApiPolicy::from_env().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the API policy is misconfigured: {error}"),
        )
    })?;
    if !is_loopback_addr(addr) && policy.authenticator().configured_callers() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing to serve a privileged API on {addr} with no configured caller; configure \
                 `{}` (id:token[:did][:scope,scope]) or bind a loopback address",
                crate::auth::TOKENS_ENV
            ),
        ));
    }
    if !is_loopback_addr(addr) && policy.authenticator().anonymous_writes_allowed() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "`{}` is set but {addr} is not a loopback address; anonymous writes are a \
                 loopback-only development escape hatch",
                crate::auth::ANONYMOUS_WRITES_ENV
            ),
        ));
    }
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        %addr,
        callers = policy.authenticator().configured_callers(),
        anonymous_writes = policy.authenticator().anonymous_writes_allowed(),
        "nau HTTP API listening"
    );
    serve_on(listener, node, policy, RequestLimits::default(), shutdown).await
}

/// Serve on an already-bound listener with an explicit policy and limits.
///
/// Split out so a test can bind `127.0.0.1:0`, learn the port, and drive the real
/// socket path — including the `413`, `408` and cross-origin refusals — without
/// waiting out the production timeout.
pub async fn serve_on<F>(
    listener: TcpListener,
    node: Arc<Mutex<Node>>,
    policy: ApiPolicy,
    limits: RequestLimits,
    shutdown: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let policy = Arc::new(policy);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received");
                // No orphans: a daemon that stops kills and removes the sandboxes
                // it still holds. What it cannot reach (an `exec` in flight holds
                // the node lock) is reclaimed by the next run's startup sweep,
                // which is the mechanism that also makes a crash recoverable.
                sandbox_routes::shutdown_node(&node);
                return Ok(());
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        let node = Arc::clone(&node);
                        let policy = Arc::clone(&policy);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(node, policy, limits, stream).await {
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

/// Whether an `addr` names a loopback interface.
fn is_loopback_addr(addr: &str) -> bool {
    let host = addr
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(addr)
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    matches!(host, "127.0.0.1" | "localhost" | "::1") || host.starts_with("127.")
}

/// Read one HTTP request and answer it.
async fn handle_connection(
    node: Arc<Mutex<Node>>,
    policy: Arc<ApiPolicy>,
    limits: RequestLimits,
    mut stream: TcpStream,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(4096);
    let deadline = tokio::time::Instant::now() + limits.read_timeout;
    let mut chunk = [0u8; 4096];

    // Read until the headers are complete. The buffer is bounded by the body cap
    // plus one chunk: a client that never sends the terminator is refused rather
    // than allowed to grow memory.
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > limits.max_body_bytes {
            return refuse_and_drain(
                &mut stream,
                &Response::error(413, "request headers exceed the request size limit"),
                limits,
            )
            .await;
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(error)) => return Err(error),
            // upstream v2.8.2 fix (finding 8): a slow or stalled client gets a
            // typed `408` instead of a silently dropped connection.
            Err(_) => {
                return write_response(
                    &mut stream,
                    &Response::error(
                        408,
                        format!(
                            "the request head was not completed within {:?}",
                            limits.read_timeout
                        ),
                    ),
                )
                .await
            }
        }
    };

    let head_text = String::from_utf8_lossy(&buf[..header_end - 4]).into_owned();
    let head = match parse_request_head(&head_text) {
        Ok(head) => head,
        Err(reason) => {
            return refuse_and_drain(&mut stream, &Response::error(400, reason), limits).await;
        }
    };

    let content_length = head.content_length.unwrap_or(0);
    if content_length > limits.max_body_bytes {
        return refuse_and_drain(
            &mut stream,
            &Response::error(
                413,
                format!(
                    "the declared body of {content_length} bytes exceeds the {}-byte limit",
                    limits.max_body_bytes
                ),
            ),
            limits,
        )
        .await;
    }

    while buf.len() < header_end + content_length {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return write_response(
                    &mut stream,
                    &Response::error(
                        408,
                        format!(
                            "the request body was not completed within {:?}",
                            limits.read_timeout
                        ),
                    ),
                )
                .await
            }
        }
    }

    let body_bytes = buf
        .get(header_end..header_end + content_length)
        .unwrap_or_default();
    let parsed_body: Option<Value> = if body_bytes.is_empty() {
        None
    } else {
        match serde_json::from_slice::<Value>(body_bytes) {
            Ok(v) => Some(v),
            Err(e) => {
                return write_response(
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

    let request = Request {
        method: head.method,
        target: head.target,
        body: parsed_body,
        origin: head.origin,
        host: head.host,
        authorization: head.authorization,
        now,
    };

    let response = {
        // The lock is held only across synchronous work — never across an await.
        let mut guard = match node.lock() {
            Ok(g) => g,
            // A panic elsewhere must not brick the node; recover the data.
            Err(poisoned) => poisoned.into_inner(),
        };
        route(&mut guard, &request, &policy)
    };
    write_response(&mut stream, &response).await
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read and discard whatever the client has already sent, then close.
///
/// A server that answers a refusal and closes **while the client is still
/// sending** leaves unread bytes in its receive buffer, which makes the stack emit
/// a reset; on Windows that reset discards the answer the client had not read yet,
/// so the client sees a connection error instead of the typed `413`/`400` this
/// server produced. Draining first (bounded by the request cap, with a short
/// timeout, ignoring errors) makes the refusal reachable. This is a correctness
/// property of the refusal path, not a courtesy: a typed status that cannot be
/// observed is not a typed status.
async fn refuse_and_drain(
    stream: &mut TcpStream,
    response: &Response,
    limits: RequestLimits,
) -> std::io::Result<()> {
    let written = write_response(stream, response).await;
    let mut remaining = limits.max_body_bytes;
    let mut scratch = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
    while remaining > 0 {
        let want = remaining.min(scratch.len());
        match tokio::time::timeout_at(deadline, stream.read(&mut scratch[..want])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(read)) => remaining = remaining.saturating_sub(read),
        }
    }
    written
}

/// Write a response, including any headers the policy attached.
async fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let body = if response.body.is_null() {
        String::new()
    } else {
        serde_json::to_string(&response.body).unwrap_or_else(|_| "{}".to_string())
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        status_text(response.status),
        body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body.as_bytes()).await?;
    }
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Authenticator, Credential};
    use crate::NodeConfig;
    use serde_json::json;

    const NOW: u64 = 1_700_000_000;
    /// A credential with every scope and no DID: a service token, so the
    /// behaviour tests are not entangled with the ownership rules.
    const SERVICE_TOKEN: &str = "service-token-for-tests";
    /// A DID another test's principal is *not*: used to prove cross-principal
    /// refusal.
    const ALICE_DID: &str = "did:nau:1111111111111111";
    const BOB_DID: &str = "did:nau:2222222222222222";

    fn node() -> Node {
        Node::ephemeral(NodeConfig::default()).expect("ephemeral node")
    }

    /// A policy with one unbound service caller that holds every scope.
    fn service_policy() -> ApiPolicy {
        ApiPolicy::deny_all().with_authenticator(
            Authenticator::deny_all()
                .with_token(
                    SERVICE_TOKEN,
                    "tester",
                    None,
                    &[Scope::Read, Scope::Write, Scope::Admin],
                )
                .expect("configures"),
        )
    }

    /// Drive the router as the service caller.
    fn call(node: &mut Node, method: &str, target: &str, body: Option<Value>) -> Response {
        route(
            node,
            &Request::new(method, target, NOW)
                .with_body(body)
                .with_authorization(Some(format!("Bearer {SERVICE_TOKEN}"))),
            &service_policy(),
        )
    }

    /// Drive the router with no credential at all.
    fn call_anonymous(
        node: &mut Node,
        method: &str,
        target: &str,
        body: Option<Value>,
    ) -> Response {
        route(
            node,
            &Request::new(method, target, NOW).with_body(body),
            &ApiPolicy::deny_all(),
        )
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
        for (_, target) in MUTATING_TARGETS {
            let r = call(&mut n, "GET", target, None);
            if matches!(*target, "/agents" | "/tasks" | "/disputes") {
                // A collection route legitimately answers GET; only its POST side
                // mutates.
                assert_eq!(r.status, 200, "GET {target} is a read");
                continue;
            }
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

        // `amount_minor` as a float is refused too: the money path never sees a
        // non-integer (upstream v2.8.2 finding 4).
        let r = call(
            &mut n,
            "POST",
            "/accounts/alice/deposit",
            Some(json!({ "amount_minor": 1.5 })),
        );
        assert_eq!(r.status, 422);
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

    // -----------------------------------------------------------------------
    // upstream v2.8.2 finding 6: authentication, identity and the default
    // -----------------------------------------------------------------------

    #[test]
    fn every_mutating_route_refuses_without_a_credential() {
        // The strongest test of the gate: an **unconfigured** deployment (the
        // default) must refuse every mutating target, and the one table that
        // decides the requirement must agree with the list of mutating targets.
        let mut n = node();
        for (method, target) in MUTATING_TARGETS {
            assert_ne!(
                required_scope_for(method, target),
                Scope::Read,
                "{method} {target} must declare a write or admin requirement"
            );
            let r = call_anonymous(&mut n, method, target, Some(json!({})));
            assert_eq!(
                r.status, 401,
                "{method} {target} must demand a credential, got {} {}",
                r.status, r.body
            );
            assert_eq!(r.body["error"], "credential_required", "{target}");
            assert!(
                r.body["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("refuses mutating requests by default"),
                "the refusal must say a default is in force: {}",
                r.body
            );
        }
        // Nothing happened: no deposit was credited, no task was published.
        let r = call_anonymous(&mut n, "GET", "/health", None);
        assert_eq!(r.status, 200, "reads are still served");
        let r = call_anonymous(&mut n, "GET", "/accounts/alice/balance", None);
        assert_eq!(r.body["balance_minor"], 0);
    }

    #[test]
    fn a_credential_that_authenticates_nobody_is_refused_not_downgraded() {
        let mut n = node();
        let policy = service_policy();
        for header in [
            "Bearer not-a-configured-token",
            "Basic service-token-for-tests",
            "Bearer ",
            "service-token-for-tests",
        ] {
            let r = route(
                &mut n,
                &Request::new("POST", "/accounts/alice/deposit", NOW)
                    .with_body(Some(json!({"amount": "1"})))
                    .with_authorization(Some(header)),
                &policy,
            );
            assert_eq!(r.status, 401, "for `{header}`");
            assert!(
                matches!(
                    r.body["error"].as_str(),
                    Some("unknown_credential" | "malformed_credential" | "credential_required")
                ),
                "for `{header}`: {}",
                r.body
            );
        }
        // And the balance is untouched.
        let r = call(&mut n, "GET", "/accounts/alice/balance", None);
        assert_eq!(r.body["balance_minor"], 0);
    }

    #[test]
    fn a_caller_without_the_write_scope_cannot_mutate() {
        let mut n = node();
        let read_only = ApiPolicy::deny_all().with_authenticator(
            Authenticator::deny_all()
                .with_token("reader", "reader", None, &[Scope::Read])
                .expect("configures"),
        );
        let r = route(
            &mut n,
            &Request::new("POST", "/accounts/alice/deposit", NOW)
                .with_body(Some(json!({"amount": "1"})))
                .with_authorization(Some("Bearer reader")),
            &read_only,
        );
        assert_eq!(r.status, 403);
        assert_eq!(r.body["error"], "insufficient_scope");
        assert!(r.body["message"].as_str().unwrap().contains("reader"));

        // The same caller can still read.
        let r = route(
            &mut n,
            &Request::new("GET", "/accounts/alice/balance", NOW)
                .with_authorization(Some("Bearer reader")),
            &read_only,
        );
        assert_eq!(r.status, 200);
    }

    #[test]
    fn only_an_admin_caller_can_arbitrate() {
        let mut n = node();
        let writer = ApiPolicy::deny_all().with_authenticator(
            Authenticator::deny_all()
                .with_token("writer", "writer", None, &[Scope::Read, Scope::Write])
                .expect("configures"),
        );
        let r = route(
            &mut n,
            &Request::new("POST", "/disputes/d1/arbitrate", NOW)
                .with_body(Some(json!({"ruling": {}})))
                .with_authorization(Some("Bearer writer")),
            &writer,
        );
        assert_eq!(r.status, 403, "{}", r.body);
        assert_eq!(r.body["error"], "insufficient_scope");
        assert_eq!(
            required_scope_for("POST", "/disputes/d1/arbitrate"),
            Scope::Admin
        );
    }

    #[test]
    fn a_did_bound_caller_can_only_act_as_itself() {
        // Cross-principal refusal on the mutating routes: Alice's credential may
        // not deposit into Bob's account, bid as Bob, or claim to be Bob.
        let mut n = node();
        let policy = ApiPolicy::deny_all().with_authenticator(
            Authenticator::deny_all()
                .with_token(
                    "alice-token",
                    "alice",
                    Some(ALICE_DID),
                    &[Scope::Read, Scope::Write],
                )
                .expect("configures"),
        );
        let as_alice = |target: String, body: Value| {
            Request::new("POST", target, NOW)
                .with_body(Some(body))
                .with_authorization(Some("Bearer alice-token"))
        };

        // Another identity's account.
        let r = route(
            &mut n,
            &as_alice(
                format!("/accounts/{BOB_DID}/deposit"),
                json!({"amount": "1"}),
            ),
            &policy,
        );
        assert_eq!(r.status, 403, "{}", r.body);
        assert_eq!(r.body["error"], "wrong_actor");
        assert!(r.body["message"].as_str().unwrap().contains(ALICE_DID));

        // Naming another identity as the executor of a task.
        let r = route(
            &mut n,
            &as_alice(
                "/tasks/task-1/start".to_string(),
                json!({"executor": BOB_DID}),
            ),
            &policy,
        );
        assert_eq!(r.status, 403, "{}", r.body);
        assert_eq!(r.body["error"], "wrong_actor");
        assert!(r.body["message"].as_str().unwrap().contains(BOB_DID));

        // Her own account is allowed, and the deposit really lands.
        let r = route(
            &mut n,
            &as_alice(
                format!("/accounts/{ALICE_DID}/deposit"),
                json!({"amount": "2.5"}),
            ),
            &policy,
        );
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.body["balance_minor"], 2_500_000);

        // A principal with no DID is a service credential: not identity-bound, so
        // the same cross-principal request is allowed. That is the documented
        // privilege of a service token, and it is why tokens should carry a DID
        // wherever ownership matters.
        let service = service_policy();
        let r = route(
            &mut n,
            &Request::new("POST", format!("/accounts/{BOB_DID}/deposit"), NOW)
                .with_body(Some(json!({"amount": "1"})))
                .with_authorization(Some(format!("Bearer {SERVICE_TOKEN}"))),
            &service,
        );
        assert_eq!(r.status, 200, "{}", r.body);
    }

    // -----------------------------------------------------------------------
    // upstream v2.8.2 finding 7: no wildcard CORS, no echoed hostile origin
    // -----------------------------------------------------------------------

    #[test]
    fn a_hostile_origin_is_refused_and_never_echoed() {
        let mut n = node();
        let policy = service_policy();
        for origin in [
            "http://evil.example",
            "https://evil.example",
            "null",
            "http://127.0.0.1:1420.evil.example",
        ] {
            let r = route(
                &mut n,
                &Request::new("POST", "/accounts/alice/deposit", NOW)
                    .with_body(Some(json!({"amount": "1"})))
                    .with_origin(Some(origin))
                    .with_authorization(Some(format!("Bearer {SERVICE_TOKEN}"))),
                &policy,
            );
            assert_eq!(r.status, 403, "for origin `{origin}`");
            assert_eq!(r.body["error"], "forbidden_origin");
            assert_eq!(
                r.header("access-control-allow-origin"),
                None,
                "a refused origin must never be echoed, for `{origin}`"
            );
        }

        // The preflight for a hostile origin is refused too, and carries no
        // `Access-Control-Allow-Origin`.
        let r = route(
            &mut n,
            &Request::new("OPTIONS", "/accounts/alice/deposit", NOW)
                .with_origin(Some("http://evil.example")),
            &policy,
        );
        assert_eq!(r.status, 403);
        assert_eq!(r.header("access-control-allow-origin"), None);
        assert_eq!(r.header("vary"), None);
    }

    #[test]
    fn an_allow_listed_origin_is_echoed_exactly_once_and_never_as_a_wildcard() {
        let mut n = node();
        let policy = service_policy().allow_origin("http://127.0.0.1:1420");
        let r = route(
            &mut n,
            &Request::new("POST", "/accounts/alice/deposit", NOW)
                .with_body(Some(json!({"amount": "1"})))
                .with_origin(Some("http://127.0.0.1:1420"))
                .with_authorization(Some(format!("Bearer {SERVICE_TOKEN}"))),
            &policy,
        );
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(
            r.header("access-control-allow-origin"),
            Some("http://127.0.0.1:1420")
        );
        assert_eq!(r.header("vary"), Some("Origin"));

        // A preflight answers with the same exact origin and the allowed methods.
        let r = route(
            &mut n,
            &Request::new("OPTIONS", "/accounts/alice/deposit", NOW)
                .with_origin(Some("http://127.0.0.1:1420")),
            &policy,
        );
        assert_eq!(r.status, 204);
        assert_eq!(
            r.header("access-control-allow-origin"),
            Some("http://127.0.0.1:1420")
        );
        assert!(r
            .header("access-control-allow-methods")
            .unwrap_or_default()
            .contains("POST"));

        // There is no configuration that produces a wildcard.
        let wildcard = service_policy().allow_origin("*");
        assert!(wildcard.allowed_origins().is_empty());
        let r = route(
            &mut n,
            &Request::new("OPTIONS", "/agents", NOW).with_origin(Some("http://evil.example")),
            &wildcard,
        );
        assert_eq!(r.status, 403);
        assert_eq!(r.header("access-control-allow-origin"), None);
    }

    #[test]
    fn a_rebinding_host_is_refused_even_without_an_origin() {
        let mut n = node();
        let policy = service_policy();
        let r = route(
            &mut n,
            &Request::new("GET", "/health", NOW).with_host(Some("evil.example")),
            &policy,
        );
        assert_eq!(r.status, 403);
        assert_eq!(r.body["error"], "forbidden_host");

        // A loopback name, and no `Host` at all, are both served.
        for host in ["127.0.0.1:4002", "localhost:4002", "[::1]:4002"] {
            let r = route(
                &mut n,
                &Request::new("GET", "/health", NOW).with_host(Some(host)),
                &policy,
            );
            assert_eq!(r.status, 200, "for host `{host}`");
        }
        let r = route(&mut n, &Request::new("GET", "/health", NOW), &policy);
        assert_eq!(r.status, 200);
    }

    // -----------------------------------------------------------------------
    // upstream v2.8.2 finding 8: bounded request reads
    // -----------------------------------------------------------------------

    #[test]
    fn a_request_head_is_parsed_strictly() {
        let head = "POST /accounts/alice/deposit HTTP/1.1\r\nHost: 127.0.0.1:4002\r\n\
                    Content-Length: 12\r\nOrigin: http://127.0.0.1:1420\r\n\
                    Authorization: Bearer abc\r\n";
        let parsed = parse_request_head(head).expect("parses");
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/accounts/alice/deposit");
        assert_eq!(parsed.content_length, Some(12));
        assert_eq!(parsed.origin.as_deref(), Some("http://127.0.0.1:1420"));
        assert_eq!(parsed.host.as_deref(), Some("127.0.0.1:4002"));
        assert_eq!(parsed.authorization.as_deref(), Some("Bearer abc"));

        // No body declared is legitimate.
        let parsed = parse_request_head("GET /health HTTP/1.1\r\nHost: x\r\n").expect("parses");
        assert_eq!(parsed.content_length, None);

        // Everything below is refused rather than guessed at: upstream read the
        // first `Content-Length` it found and fell back to zero.
        for head in [
            "POST / HTTP/1.1\r\nContent-Length: abc\r\n",
            "POST / HTTP/1.1\r\nContent-Length: -1\r\n",
            "POST / HTTP/1.1\r\nContent-Length: \r\n",
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n",
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n",
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n",
            "POST\r\n",
        ] {
            assert!(
                parse_request_head(head).is_err(),
                "`{head}` must be refused"
            );
        }
        // A method that is not a token is refused rather than routed.
        assert!(parse_request_head("get / HTTP/1.1\r\n").is_err());
    }

    #[test]
    fn request_limits_cannot_be_zero() {
        let limits = RequestLimits::new(0, Duration::ZERO);
        assert_eq!(limits.max_body_bytes, 1);
        assert_eq!(limits.read_timeout, Duration::from_millis(1));
        let limits = RequestLimits::default();
        assert_eq!(limits.max_body_bytes, MAX_BODY_BYTES);
        assert_eq!(limits.read_timeout, Duration::from_secs(READ_TIMEOUT_SECS));
    }

    #[test]
    fn a_non_loopback_bind_is_refused_without_a_configured_caller() {
        assert!(is_loopback_addr("127.0.0.1:4002"));
        assert!(is_loopback_addr("localhost:4002"));
        assert!(is_loopback_addr("[::1]:4002"));
        assert!(is_loopback_addr("127.0.0.53:4002"));
        assert!(!is_loopback_addr("0.0.0.0:4002"));
        assert!(!is_loopback_addr("192.168.1.10:4002"));
        // The refusal itself is exercised in `tests/api_security.rs`, which can
        // call `serve` (it is async and binds a socket).
    }

    #[test]
    fn the_service_credential_is_never_printed() {
        let credential = Credential::new(SERVICE_TOKEN).expect("ok");
        assert_eq!(format!("{credential:?}"), "<redacted credential>");
        let policy = service_policy();
        let rendered = format!("{policy:?}");
        assert!(
            !rendered.contains(SERVICE_TOKEN),
            "a policy print must not leak a token: {rendered}"
        );
    }
}
