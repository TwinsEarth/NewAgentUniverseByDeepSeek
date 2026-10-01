//! Sandbox routes: the daemon's end of the `nau-sandbox` crate.
//!
//! Upstream `agent-universe` v2.8.2 shipped an Agent Sandbox whose security
//! boundaries existed only in documentation. The four defects this module closes
//! at the routing layer, one per numbered finding in the audit:
//!
//! * **defect 1 — unauthenticated remote code execution by default.**
//!   `node.rs:1069-1105` dispatched `/api/v1/sandboxes*` *before* the normal
//!   router and with no auth check at all, on `0.0.0.0:4002`, while
//!   `sandbox/api.rs:68-73` performed no authentication either. `POST
//!   /api/v1/sandboxes` followed by `POST /{id}/exec` ran attacker-chosen Python
//!   or JavaScript as the daemon's user. Here the sandbox routes are reached
//!   through the daemon's one gate, and on top of it: (a) every sandbox route is
//!   refused with **403 `sandbox_disabled`** unless at least one caller is
//!   configured — there is no "nothing configured, so allow" branch; (b) every
//!   sandbox route is refused with **401 `credential_required`** unless the
//!   request presents a configured token, *including* the reads, because a
//!   sandbox is owned by a named principal and the anonymous fallback is not one;
//!   (c) `POST`/`DELETE` demand the `write` scope and `GET` the `read` scope
//!   through the daemon's existing [`Scope`] table.
//! * **defect 2 — no ownership model.** Any reachable client could exec, pause or
//!   destroy any sandbox, and ids were a per-process counter (`sb-N`,
//!   `manager.rs:67-70`) whose directories lived in the persistent data dir, so a
//!   restart reissued `sb-1` on top of the previous `sb-1`'s files. Here the owner
//!   is the authenticated [`Principal`]'s id and every route reaches the sandbox
//!   only through a manager call that checks it; a different principal gets the
//!   **same 404 as an id that never existed**, so none of these routes is an
//!   existence oracle. Ids come from the crate (v4 UUIDs through its one path
//!   component validator).
//! * **defect 3 — the request body was parsed and discarded** (`sandbox/api.rs`
//!   parsed at `:85-89` and called `acquire(None)` at `:94`), so neither caller nor
//!   operator could set any policy: everything ran on hardcoded defaults. Here the
//!   `POST /sandboxes` body **is** the [`SandboxSpec`]: every limit, the network
//!   policy, the filesystem policy and the env allowlist. `SandboxSpec` has no
//!   `Default` and no `Option` field, so a body that omits one is a `422` rather
//!   than a silent default, and a body that asks for a boundary the selected
//!   backend cannot enforce is a `422 policy_not_enforceable` naming the boundary
//!   — never a silently unconfined run.
//! * **defect 4 — one global mutex across every sandbox** (`node.rs:1075`,
//!   `sandbox_tools.rs:91`), taken with `.lock().unwrap()`, so any panic poisoned
//!   it and disabled the whole subsystem. Here the daemon keeps no lock across
//!   execution at all: [`SandboxManager`] methods take `&self` and do their own
//!   per-sandbox locking, the registry lock exists only to look a manager up (and
//!   to open it once per root), and a *poisoned* lock is recovered explicitly
//!   rather than `unwrap`ped — one panic elsewhere must not disable the routes.
//!
//! # Routes
//!
//! The shape upstream published is preserved (`/api/v1/sandboxes…`), and the same
//! handlers answer this daemon's own unprefixed shape (`/sandboxes…`) so that the
//! sandbox API is not a second, differently-guarded surface:
//!
//! | Method | Target | Scope | Answer |
//! |---|---|---|---|
//! | `POST` | `/api/v1/sandboxes` | write | `201` with the new `id` |
//! | `GET` | `/api/v1/sandboxes` | read | `200` with this caller's sandboxes and the backend's capability declaration |
//! | `GET` | `/api/v1/sandboxes/{id}` | read | `200` with one description, or `404` |
//! | `DELETE` | `/api/v1/sandboxes/{id}` | write | `200`, or `404` |
//! | `POST` | `/api/v1/sandboxes/{id}/exec` | write | `200` with the run's outcome, or `404` |
//! | `POST` | `/api/v1/sandboxes/{id}/commands` | write | alias of `exec` |
//! | `POST` | `/api/v1/sandboxes/{id}/run` | write | alias of `exec` |
//! | `POST` | `/api/v1/sandboxes/{id}/pause` | write | `200`, or `404` |
//! | `POST` | `/api/v1/sandboxes/{id}/resume` | write | `200`, or `404` |
//!
//! # Execution backend
//!
//! The backend is a property of the *deployment*, never of a request (a caller
//! must not be able to choose the thing that confines it). [`BACKEND_ENV`] selects
//! it: unset — the default — is `NullExecutor`, which **executes nothing** and
//! says so with `501 execution_disabled`; `process` selects
//! `RealProcessExecutor`, whose declaration is published by `GET /sandboxes` and
//! enforced at every `create`. Both are the crate's, unchanged.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use nau_sandbox::{
    shared, ExecOutcome, ExecRequest, NullExecutor, SandboxError, SandboxExecutor, SandboxManager,
    SandboxSpec,
};
// Reached only through the `#[cfg(windows)]` arm of `executor_for` and the Windows-only
// execution tests, so an unconditional import is an `unused import` warning on Linux and
// macOS -- which `clippy --all-targets -- -D warnings` turns into a CI failure.
#[cfg(windows)]
use nau_sandbox::RealProcessExecutor;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{Request, Response};
use crate::auth::{ApiPolicy, Credential, Principal, Refusal, Scope};
use crate::Node;

/// The environment variable that selects the execution backend.
///
/// `none` (the default; the crate's [`NullExecutor`], which runs nothing) or
/// `process` (the platform process backend). Anything else refuses to open a
/// manager rather than falling back to a default: a typo in a security setting
/// must not select a weaker one.
pub const BACKEND_ENV: &str = "NAU_SANDBOX_BACKEND";

/// The directory under the node's data directory that holds sandbox work
/// directories.
const SANDBOX_DIR: &str = "sandboxes";

/// The open managers, keyed by canonical sandbox root.
type Managers = BTreeMap<PathBuf, Arc<SandboxManager>>;

/// The process-wide manager registry.
///
/// One daemon serves one node, and a node has one sandbox root, so this is a
/// table with a single live entry in production. It exists because the router's
/// signature is `route(node, request, policy)` and the [`Node`] type is another
/// agent's file; the important property is that it is **not** a lock over
/// execution: it is held only to look a manager up, and each request then works
/// through [`SandboxManager`], which locks per sandbox.
fn registry() -> &'static Mutex<Managers> {
    static REGISTRY: OnceLock<Mutex<Managers>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Take the registry lock, recovering from poisoning.
///
/// upstream v2.8.2 fix: defect 4 — upstream's `mgr.lock().unwrap()` turned one
/// panic anywhere into a panic on *every* later sandbox call. The map here holds
/// `Arc`s and cannot be left half-mutated by a panic, so the honest recovery is to
/// use it; refusing every route because an unrelated thread panicked is exactly
/// the failure mode this crate removes.
fn registry_lock() -> MutexGuard<'static, Managers> {
    match registry().lock() {
        Ok(managers) => managers,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Build the backend named by `selection`.
///
/// # Errors
///
/// A message naming [`BACKEND_ENV`] and the accepted values, so a typo is a loud
/// refusal rather than a silent downgrade to a different backend.
fn executor_for(selection: &str) -> Result<Arc<dyn SandboxExecutor>, String> {
    match selection.trim().to_ascii_lowercase().as_str() {
        "" | "none" | "null" | "null-executor" | "off" => Ok(shared(NullExecutor::new())),
        "process" | "real" | "real-process" => {
            // The process backend is verified on Windows only, and CI has shown the Unix
            // path does not behave: on Ubuntu the wall-clock timeout was NOT enforced, and
            // on macOS four execute-through-the-router tests failed while passing on
            // Ubuntu. A backend that compiles everywhere but cannot demonstrate its own
            // enforced set is precisely the "documented but unenforced" boundary this
            // crate exists to refuse, so the selection is refused rather than
            // half-honoured. The default (`none` -> `NullExecutor`) executes nothing and
            // is unaffected, on every platform.
            #[cfg(windows)]
            {
                Ok(shared(RealProcessExecutor::new()))
            }
            #[cfg(not(windows))]
            {
                Err(format!(
                    "`{BACKEND_ENV}=process` is refused on this platform. The process backend's \
                     enforcement is verified on Windows only, and on Unix it has not been shown to \
                     honour its own capability declaration: CI observed the timeout not being \
                     enforced on Ubuntu, and execution through the router failing on macOS while \
                     passing on Ubuntu. Use `none` (the default), which executes nothing, or run on \
                     Windows. See docs/VERIFICATION.md."
                ))
            }
        }
        other => Err(format!(
            "`{BACKEND_ENV}={other}` is not a backend; use `none` (execute nothing, the default) \
             or `process` (the platform process backend, whose capability declaration is enforced \
             at every create)"
        )),
    }
}

/// The backend this deployment selected.
fn executor_from_env() -> Result<Arc<dyn SandboxExecutor>, String> {
    match std::env::var(BACKEND_ENV) {
        Ok(selection) => executor_for(&selection),
        Err(_) => executor_for(""),
    }
}

/// The canonical sandbox root for `node`, created if it does not exist.
///
/// The root is a directory of its own under the node's data directory, so a
/// sandbox can never be created *in* the store's directory.
fn sandbox_root(node: &Node) -> Result<PathBuf, String> {
    let root = node.config().data_dir.join(SANDBOX_DIR);
    std::fs::create_dir_all(&root)
        .map_err(|e| format!("cannot create the sandbox root {}: {e}", root.display()))?;
    std::fs::canonicalize(&root)
        .map_err(|e| format!("cannot resolve the sandbox root {}: {e}", root.display()))
}

/// The canonical sandbox root for `node`, when it already exists.
fn existing_root(node: &Node) -> Option<PathBuf> {
    std::fs::canonicalize(node.config().data_dir.join(SANDBOX_DIR)).ok()
}

/// The manager for `node`'s sandbox root, sweeping it the first time it is opened.
///
/// upstream v2.8.2 fix: defect 2 (no orphans) and defect 4 (a lock over
/// execution). [`SandboxManager::open`] is what runs the startup sweep, so wiring
/// this call is what makes "a restarted daemon does not inherit the previous run's
/// sandbox directories" true; the registry lock is held across that open *once per
/// root* so two concurrent first requests cannot both sweep and then have one of
/// the two managers' `Drop` remove the other's work directories.
///
/// # Errors
///
/// A `500` response: a root that cannot be created, a backend selection that is
/// not a backend, or a sweep that could not finish. The last one fails closed —
/// the manager refuses to open rather than letting new sandboxes be created on top
/// of unaccounted state — and the caller is told which directories were involved.
fn manager_for(node: &Node, now: u64) -> Result<Arc<SandboxManager>, Response> {
    let root = sandbox_root(node).map_err(|message| Response::error(500, message))?;
    let mut managers = registry_lock();
    if let Some(existing) = managers.get(&root) {
        return Ok(Arc::clone(existing));
    }
    let executor = executor_from_env().map_err(|message| Response::error(500, message))?;
    match SandboxManager::open(&root, executor, now) {
        Ok(manager) => {
            let manager = Arc::new(manager);
            managers.insert(root, Arc::clone(&manager));
            Ok(manager)
        }
        Err(error) => Err(error_response(&error)),
    }
}

/// Handle one sandbox request, below the daemon's authorization gate.
///
/// `tail` is the part of the target after `sandboxes` (see
/// [`super::sandbox_tail`]); `principal` is the caller the gate authenticated.
///
/// # Errors
///
/// Never: every failure is a [`Response`] with a typed status.
pub(super) fn dispatch(
    node: &Node,
    request: &Request,
    tail: &[&str],
    principal: &Principal,
    policy: &ApiPolicy,
) -> Response {
    let method = request.method.as_str();

    // (a) Requirement 1: closed unless a token is configured. The check that
    //     produces the *same* answer for every method lives in `route`, before the
    //     scope gate; this one is the module's own belt-and-braces so a future
    //     caller that reached `dispatch` another way still cannot pass.
    if policy.authenticator().configured_callers() == 0 {
        return disabled_response();
    }

    // (b) Requirement 2: every request presents a configured token, reusing the
    //     daemon's own credential machinery. The anonymous fallback is not a
    //     principal that can own a sandbox, so it is refused here — including for
    //     a read.
    if let Err(refusal) = presented_token(request, policy, super::sandbox_scope(method, tail)) {
        return Response::refused(&refusal);
    }

    // (c) The route shape, before any state is touched: a wrong method or an
    //     unknown action must not create a manager, a directory or a sweep.
    let Some(allowed) = allowed_methods(tail) else {
        return Response::error(404, format!("no route for `{}`", request.target));
    };
    let effective = if method == "HEAD" { "GET" } else { method };
    if !allowed.contains(&effective) {
        return Response::method_not_allowed(allowed);
    }

    // (d) The manager, opened (and swept) once per root.
    let manager = match manager_for(node, request.now) {
        Ok(manager) => manager,
        Err(response) => return response,
    };
    // `&SandboxManager`, not a guard: the daemon adds no lock over execution.
    let manager: &SandboxManager = manager.as_ref();
    // upstream v2.8.2 fix: defect 2 — the owner is the authenticated principal,
    // and every handler below passes it to the manager, which answers "not found"
    // for an id that belongs to somebody else.
    let owner = principal.id();
    let body = request.body.as_ref();

    match (effective, tail) {
        ("GET", []) => list(manager, owner),
        ("POST", []) => create(manager, owner, body),
        ("GET", [id]) => describe(manager, owner, id),
        ("DELETE", [id]) => destroy(manager, owner, id),
        ("POST", [id, action]) => match *action {
            "exec" | "commands" | "run" => exec(manager, owner, id, body),
            "pause" => set_paused(manager, owner, id, true),
            "resume" => set_paused(manager, owner, id, false),
            // Unreachable through `allowed_methods`, which refused every other
            // action above; answered rather than assumed.
            other => Response::error(404, format!("unknown sandbox action `{other}`")),
        },
        _ => Response::error(404, format!("no route for `{}`", request.target)),
    }
}

/// The refusal for a deployment with no configured caller.
///
/// **403, not 404.** The route exists; hiding it would buy nothing (the daemon
/// already refuses to bind a non-loopback address with no configured caller, see
/// [`super::serve`]) and would present a misconfiguration as a missing feature. A
/// 404 would also make this indistinguishable from "another principal's sandbox",
/// which is the one thing the sandbox routes deliberately keep indistinguishable.
pub(super) fn disabled_response() -> Response {
    coded_response(
        403,
        "sandbox_disabled",
        format!(
            "the sandbox API is closed on this deployment: no caller is configured, so no \
             principal could own a sandbox; configure `{}` (id:token[:did][:scope,scope]) to \
             enable it",
            crate::auth::TOKENS_ENV
        ),
    )
}

/// Require the request to present a configured token holding `scope`.
///
/// upstream v2.8.2 fix: defect 1 — this is the rule upstream did not have. It uses
/// the daemon's existing machinery (the header parser, the token table and the
/// scope check) rather than a second authentication path, and it answers with the
/// existing [`Refusal`] taxonomy.
///
/// # Errors
///
/// [`Refusal::MissingCredential`] when no usable header was presented (a blank one
/// counts as none), [`Refusal::MalformedCredential`] when the header is not
/// `Bearer <token>`, [`Refusal::UnknownCredential`] when the token matches no
/// configured caller — a presented credential is never downgraded to anonymous —
/// and whatever [`ApiPolicy::authorize`] says about the scope.
fn presented_token(request: &Request, policy: &ApiPolicy, scope: Scope) -> Result<(), Refusal> {
    let Some(header) = request
        .authorization
        .as_deref()
        .map(str::trim)
        .filter(|header| !header.is_empty())
    else {
        return Err(Refusal::MissingCredential { scope });
    };
    let Some(credential) = Credential::from_authorization_header(header) else {
        return Err(Refusal::MalformedCredential);
    };
    if !policy.authenticator().authenticates(&credential) {
        return Err(Refusal::UnknownCredential);
    }
    policy.authorize(Some(header), scope)?;
    Ok(())
}

/// The methods a sandbox route accepts, or `None` when the path is not one.
fn allowed_methods(tail: &[&str]) -> Option<&'static [&'static str]> {
    match tail {
        [] => Some(&["GET", "POST"]),
        [_] => Some(&["GET", "DELETE"]),
        [_, "exec" | "commands" | "run" | "pause" | "resume"] => Some(&["POST"]),
        _ => None,
    }
}

/// `GET /sandboxes` — this caller's sandboxes, plus what the backend enforces.
///
/// The capability declaration is included because "which limits does this
/// deployment actually have?" should be answerable from the running binary rather
/// than from a document.
fn list(manager: &SandboxManager, owner: &str) -> Response {
    let ids = match manager.list(owner) {
        Ok(ids) => ids,
        Err(error) => return error_response(&error),
    };
    let mut sandboxes: Vec<Value> = Vec::with_capacity(ids.len());
    for id in &ids {
        match manager.describe(owner, id) {
            Ok(description) => match serde_json::to_value(&description) {
                Ok(value) => sandboxes.push(value),
                Err(error) => return Response::error(500, error.to_string()),
            },
            Err(error) => return error_response(&error),
        }
    }
    let capabilities = match serde_json::to_value(manager.capabilities()) {
        Ok(value) => value,
        // A capability declaration that cannot be rendered is a server fault.
        Err(error) => return Response::error(500, error.to_string()),
    };
    Response::ok(json!({
        "count": sandboxes.len(),
        "sandboxes": sandboxes,
        "backend": manager.capabilities().backend(),
        "capabilities": capabilities,
    }))
}

/// `POST /sandboxes` — create one, owned by `owner`, from the request body.
///
/// upstream v2.8.2 fix: defect 3 — the body is the policy, not decoration.
fn create(manager: &SandboxManager, owner: &str, body: Option<&Value>) -> Response {
    let Some(body) = body else {
        return Response::error(
            422,
            "a sandbox spec is required: the body must state every limit, the network policy, \
             the filesystem policy and the env allowlist (there are no defaults, by design)",
        );
    };
    // `SandboxSpec` refuses unknown fields, so a typo is a refusal rather than a
    // silently ignored policy field.
    let spec: SandboxSpec = match serde_json::from_value(body.clone()) {
        Ok(spec) => spec,
        Err(error) => {
            return Response::error(422, format!("the body is not a sandbox spec: {error}"))
        }
    };
    match manager.create(owner, &spec) {
        Ok(id) => Response::created(json!({
            "status": "created",
            "id": id.as_str(),
            "owner": owner,
            "backend": manager.capabilities().backend(),
        })),
        Err(error) => error_response(&error),
    }
}

/// `GET /sandboxes/{id}`.
fn describe(manager: &SandboxManager, owner: &str, id: &str) -> Response {
    match manager.describe(owner, id) {
        Ok(description) => match serde_json::to_value(&description) {
            Ok(value) => Response::ok(value),
            Err(error) => Response::error(500, error.to_string()),
        },
        Err(error) => error_response(&error),
    }
}

/// `DELETE /sandboxes/{id}`.
fn destroy(manager: &SandboxManager, owner: &str, id: &str) -> Response {
    match manager.destroy(owner, id) {
        Ok(()) => Response::ok(json!({ "status": "destroyed", "id": id })),
        Err(error) => error_response(&error),
    }
}

/// `POST /sandboxes/{id}/{pause,resume}`.
fn set_paused(manager: &SandboxManager, owner: &str, id: &str, paused: bool) -> Response {
    let outcome = if paused {
        manager.pause(owner, id)
    } else {
        manager.resume(owner, id)
    };
    match outcome {
        Ok(()) => Response::ok(json!({
            "status": if paused { "paused" } else { "ready" },
            "id": id,
        })),
        Err(error) => error_response(&error),
    }
}

/// What an `exec` body may say.
///
/// There is deliberately no `code`/`language` pair: the program is fixed at
/// creation, and a script body travels on stdin (see
/// [`nau_sandbox::Interpreter`]). Unknown fields are refused, so upstream's
/// `{"code": …}` body is a clear `422` and not a silently ignored policy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecBody {
    /// Bytes handed to the program on stdin. For an interpreter that reads its
    /// program from stdin, this *is* the program.
    stdin: Option<String>,
    /// An override spec, which may only tighten what the sandbox was created
    /// with; widening any limit is refused by the crate.
    spec: Option<SandboxSpec>,
}

/// `POST /sandboxes/{id}/{exec,commands,run}` — run one program in the sandbox.
fn exec(manager: &SandboxManager, owner: &str, id: &str, body: Option<&Value>) -> Response {
    let parsed: ExecBody = match body {
        None => ExecBody {
            stdin: None,
            spec: None,
        },
        Some(value) => match serde_json::from_value(value.clone()) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Response::error(
                    422,
                    format!("the body must be `{{ \"stdin\": \"…\", \"spec\": {{…}} }}`: {error}"),
                )
            }
        },
    };
    let request = match parsed.stdin {
        Some(stdin) => ExecRequest::with_stdin(stdin.into_bytes()),
        None => ExecRequest::new(),
    };
    // upstream v2.8.2 fix: defect 3 — upstream called `acquire(None)` here, so the
    // body could not tighten anything; the override reaches the manager, which
    // refuses anything that would widen the recorded policy.
    match manager.exec(owner, id, parsed.spec.as_ref(), &request) {
        Ok(outcome) => Response::ok(outcome_json(&outcome)),
        Err(error) => error_response(&error),
    }
}

/// One run's outcome, as JSON.
///
/// `stdout`/`stderr` are lossy UTF-8: arbitrary bytes become replacement
/// characters. The alternative — base64 — would hide a script's own output from
/// the operator reading the response, and the truncation flags say plainly when
/// what is shown is not all of it.
fn outcome_json(outcome: &ExecOutcome) -> Value {
    json!({
        "exit_code": outcome.exit_code,
        "stdout": outcome.stdout_lossy(),
        "stderr": outcome.stderr_lossy(),
        "stdout_truncated": outcome.stdout_truncated,
        "stderr_truncated": outcome.stderr_truncated,
        "timed_out": outcome.timed_out,
        "terminated": outcome.terminated,
        "elapsed_ms": outcome.elapsed_ms,
    })
}

/// An error response with a machine-readable `error` code.
fn coded_response(status: u16, code: &str, message: impl Into<String>) -> Response {
    let mut response = Response::error(status, message);
    response.body["error"] = json!(code);
    response
}

/// A typed [`SandboxError`] as a response.
///
/// The refusal that matters most here is
/// [`SandboxError::PolicyNotEnforceable`], which arrives with the boundary, the
/// backend and the backend's reason; they are put in the body so a caller sees
/// *which* boundary could not be enforced instead of a generic failure.
fn error_response(error: &SandboxError) -> Response {
    let mut response = coded_response(
        status_for_sandbox(error),
        code_for_sandbox(error),
        error.to_string(),
    );
    match error {
        SandboxError::PolicyNotEnforceable {
            boundary,
            backend,
            detail,
        } => {
            response.body["boundary"] = json!(boundary.as_str());
            response.body["backend"] = json!(backend);
            response.body["detail"] = json!(detail);
        }
        SandboxError::NotFound(id) => response.body["id"] = json!(id),
        _ => {}
    }
    response
}

/// The HTTP status for a sandbox error.
///
/// `NotFound` is the one that carries the ownership rule: the crate returns it
/// both for an id that does not exist **and** for an id owned by another
/// principal, so this route cannot confirm that somebody else's sandbox exists.
/// An unsafe path component is folded into the same `404` for the same reason —
/// a malformed id is not a sandbox, and saying anything else about it would make
/// the two cases distinguishable.
fn status_for_sandbox(error: &SandboxError) -> u16 {
    match error {
        SandboxError::NotFound(_) | SandboxError::Destroyed(_) | SandboxError::Component(_) => 404,
        SandboxError::ExecutionDisabled(_) => 501,
        SandboxError::PolicyNotEnforceable { .. }
        | SandboxError::Limit { .. }
        | SandboxError::Start(_) => 422,
        SandboxError::Busy(..) => 409,
        SandboxError::Timeout { .. } => 504,
        SandboxError::ManagerGone => 503,
        _ => 500,
    }
}

/// The machine-readable code for a sandbox error.
fn code_for_sandbox(error: &SandboxError) -> &'static str {
    match error {
        SandboxError::Component(_) | SandboxError::NotFound(_) | SandboxError::Destroyed(_) => {
            "not_found"
        }
        SandboxError::ExecutionDisabled(_) => "execution_disabled",
        SandboxError::PolicyNotEnforceable { .. } => "policy_not_enforceable",
        SandboxError::Busy(..) => "conflict",
        SandboxError::Limit { .. } => "limit_refused",
        SandboxError::Timeout { .. } => "timeout",
        SandboxError::Start(_) => "start_failed",
        SandboxError::ManagerGone => "unavailable",
        SandboxError::OrphanReclaim { .. } => "orphan_reclaim",
        _ => "internal_error",
    }
}

/// Kill and remove the sandboxes this node owns, on shutdown.
///
/// Best effort and **non-blocking**: the node lock is taken only if it is free,
/// because a sandbox `exec` holds it for the length of one run and waiting for it
/// here would stall the shutdown path. A directory that survives this is reclaimed
/// by the next run's startup sweep, which is the mechanism that also makes a crash
/// recoverable.
pub(super) fn shutdown_node(node: &Arc<Mutex<Node>>) {
    let root = match node.try_lock() {
        Ok(guard) => existing_root(&guard),
        Err(_) => None,
    };
    if let Some(root) = root {
        // Dropping the last `Arc` runs the manager's `Drop`, which kills every job
        // and removes every work directory it owns.
        let removed = registry_lock().remove(&root);
        drop(removed);
    }
}

// ---------------------------------------------------------------------------
// Test hooks
//
// These come after every production item: `scripts/check-no-panics.mjs` scans a
// file up to its first `#[cfg(test)]`, and code hidden behind that marker would
// be code the gate does not check.
// ---------------------------------------------------------------------------

/// Install a manager with an explicit backend for `node`'s root.
///
/// Production never calls this: it exists so a test can drive the routes with the
/// real backend, or with the null one, without depending on the process
/// environment (which every parallel test in the binary shares).
#[cfg(test)]
fn install_for_test(
    node: &Node,
    executor: Arc<dyn SandboxExecutor>,
    now: u64,
) -> Result<(), String> {
    let root = sandbox_root(node)?;
    let manager = SandboxManager::open(&root, executor, now).map_err(|error| error.to_string())?;
    registry_lock().insert(root, Arc::new(manager));
    Ok(())
}

/// Forget the manager for `node`'s root, shutting it down.
#[cfg(test)]
fn remove_for_test(node: &Node) {
    if let Some(root) = existing_root(node) {
        let removed = registry_lock().remove(&root);
        drop(removed);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use nau_sandbox::{shared, NullExecutor, RealProcessExecutor, SandboxExecutor};
    use serde_json::{json, Value};

    // Explicit imports rather than `use super::*`, so that a name this module and
    // its parent both use cannot be bound twice.
    use super::{
        code_for_sandbox, executor_for, install_for_test, registry, remove_for_test, sandbox_root,
        status_for_sandbox, BACKEND_ENV,
    };
    use crate::api::{route, Request, Response};
    use crate::auth::{ApiPolicy, Authenticator, Scope};
    use crate::{Node, NodeConfig};

    const NOW: u64 = 1_700_000_000;
    /// A credential for `alice`, who owns the sandboxes in these tests.
    const ALICE_TOKEN: &str = "alice-token-for-sandbox-tests";
    /// A credential for `bob`, a different principal with the same scopes.
    const BOB_TOKEN: &str = "bob-token-for-sandbox-tests";

    /// Every sandbox route, in the shape upstream published and in this daemon's
    /// unprefixed shape.
    const SANDBOX_ROUTES: &[(&str, &str)] = &[
        ("POST", "/api/v1/sandboxes"),
        ("GET", "/api/v1/sandboxes"),
        ("GET", "/api/v1/sandboxes/11111111111111111111111111111111"),
        (
            "DELETE",
            "/api/v1/sandboxes/11111111111111111111111111111111",
        ),
        (
            "POST",
            "/api/v1/sandboxes/11111111111111111111111111111111/exec",
        ),
        (
            "POST",
            "/api/v1/sandboxes/11111111111111111111111111111111/commands",
        ),
        (
            "POST",
            "/api/v1/sandboxes/11111111111111111111111111111111/run",
        ),
        (
            "POST",
            "/api/v1/sandboxes/11111111111111111111111111111111/pause",
        ),
        (
            "POST",
            "/api/v1/sandboxes/11111111111111111111111111111111/resume",
        ),
        ("POST", "/sandboxes"),
        ("GET", "/sandboxes"),
        ("GET", "/sandboxes/11111111111111111111111111111111"),
    ];

    /// A policy with two configured principals, each holding every scope.
    fn policy() -> ApiPolicy {
        ApiPolicy::deny_all().with_authenticator(
            Authenticator::deny_all()
                .with_token(
                    ALICE_TOKEN,
                    "alice",
                    None,
                    &[Scope::Read, Scope::Write, Scope::Admin],
                )
                .expect("configures alice")
                .with_token(
                    BOB_TOKEN,
                    "bob",
                    None,
                    &[Scope::Read, Scope::Write, Scope::Admin],
                )
                .expect("configures bob"),
        )
    }

    /// A node whose data directory belongs to exactly one test.
    fn node_for(name: &str) -> Node {
        let data_dir = std::env::temp_dir().join(format!(
            "nau-node-sandbox-routes/{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        Node::ephemeral(NodeConfig {
            data_dir,
            ..NodeConfig::default()
        })
        .expect("an ephemeral node")
    }

    /// Drive the router with `policy()` and an optional bearer token.
    fn call_with(
        node: &mut Node,
        policy: &ApiPolicy,
        token: Option<&str>,
        method: &str,
        target: &str,
        body: Option<Value>,
    ) -> Response {
        let request = Request::new(method, target, NOW)
            .with_body(body)
            .with_authorization(token.map(|token| format!("Bearer {token}")));
        route(node, &request, policy)
    }

    /// Drive the router as a configured caller (or anonymously, with `None`).
    fn call(
        node: &mut Node,
        token: &str,
        method: &str,
        target: &str,
        body: Option<Value>,
    ) -> Response {
        call_with(node, &policy(), Some(token), method, target, body)
    }

    /// Drop the manager (killing and removing its sandboxes) and the data dir.
    fn cleanup(node: &Node) {
        remove_for_test(node);
        let _ = std::fs::remove_dir_all(&node.config().data_dir);
    }

    /// Install an explicit backend for `node`, so a test does not depend on the
    /// process environment.
    fn install(node: &Node, executor: Arc<dyn SandboxExecutor>) {
        install_for_test(node, executor, NOW).expect("installs the test backend");
    }

    /// The libtest name of one of the worker tests below.
    fn worker_test_name(name: &str) -> String {
        // `module_path!()` here is `nau_node::api::sandbox_routes::tests`; libtest
        // names a library test without the crate prefix.
        let path = module_path!();
        let trimmed = path.strip_prefix("nau_node::").unwrap_or(path);
        format!("{trimmed}::{name}")
    }

    /// An interpreter that runs one worker **in this test binary**.
    ///
    /// Running this binary means no interpreter has to exist on the host and no
    /// external program's output format is depended on — the same trick
    /// `nau-sandbox/tests/common/mod.rs` uses.
    fn worker_interpreter(name: &str) -> Value {
        let bin = std::env::current_exe()
            .expect("the test binary path")
            .to_string_lossy()
            .into_owned();
        json!({
            "argv": {
                "bin": bin,
                "args": ["--exact", worker_test_name(name), "--nocapture"],
            },
        })
    }

    /// A spec the real backend can actually serve on this platform.
    ///
    /// Every boundary the platform backend declares unenforced is waived *with a
    /// reason*, which is the crate's only honest way to run: a waiver is audited,
    /// and a boundary that is neither waived nor enforceable is a refusal. The
    /// value is JSON on purpose — these tests go through the HTTP body parser.
    fn creatable_spec() -> Value {
        json!({
            "interpreter": worker_interpreter("sandbox_worker_echoes"),
            "limits": {
                "timeout_ms": 20_000,
                "memory_bytes": 512 * 1024 * 1024,
                "cpu_ms": 20_000,
                "disk_bytes": 32 * 1024 * 1024,
                "max_processes": 4,
                "max_open_files": 256,
                "max_output_bytes": 256 * 1024,
            },
            "network": {
                "unrestricted": {
                    "justification": "test: this host offers no egress filter to a plain child",
                },
            },
            "filesystem": {
                "confinement": "whole_host",
                "extra_readable": [],
                "writable": [],
            },
            "env": {
                "inherit": "nothing",
                "vars": [["NAU_SANDBOX_TEST_READ_STDIN", "1"]],
            },
            "waivers": {
                "filesystem_confinement": "test: no confinement primitive in this backend",
                "disk_bytes": "test: no quota primitive in this backend",
                "cpu_ms": "test: no enforced CPU-time cap in this backend",
                "max_open_files": "test: no handle cap in this backend",
            },
        })
    }

    /// Create a sandbox through the router and return its id.
    fn create_sandbox(node: &mut Node, token: &str, spec: Value) -> String {
        let response = call(node, token, "POST", "/api/v1/sandboxes", Some(spec));
        assert_eq!(response.status, 201, "{}", response.body);
        response.body["id"]
            .as_str()
            .expect("a created sandbox answers with an id")
            .to_string()
    }

    /// The sandbox root of `node`, as the routes compute it.
    fn root_of(node: &Node) -> PathBuf {
        sandbox_root(node).expect("the sandbox root")
    }

    /// A worker that echoes its stdin, so a test can prove that the `exec` body's
    /// `stdin` reached the child.
    ///
    /// It reads stdin only when the *spec's* env allowlist says so: under a plain
    /// `cargo test` this test's stdin is the terminal, and a blocking read would
    /// hang the suite.
    #[test]
    fn sandbox_worker_echoes() {
        if std::env::var("NAU_SANDBOX_TEST_READ_STDIN").is_err() {
            println!("STDIN:<not asked to read>");
            return;
        }
        use std::io::Read;
        let mut input = String::new();
        let _ = std::io::stdin().read_to_string(&mut input);
        println!("STDIN:{input}");
    }

    /// A worker that marks that it started, waits, and then reports.
    ///
    /// The wait is driven by `NAU_SANDBOX_TEST_SLEEP_MS`, which only the *spec's*
    /// env allowlist passes in; the in-suite run of this test therefore returns
    /// immediately, while the sandboxed run sleeps long enough for another thread
    /// to observe that the sandbox is executing.
    #[test]
    fn sandbox_worker_slow() {
        let Ok(delay) = std::env::var("NAU_SANDBOX_TEST_SLEEP_MS") else {
            return;
        };
        let delay = delay.parse::<u64>().unwrap_or(3_000);
        std::fs::write("started.txt", "started").expect("mark the work directory");
        std::thread::sleep(std::time::Duration::from_millis(delay));
        println!("SLOW_DONE");
    }

    /// Requirement 1: with no token configured, **every** sandbox route is refused
    /// with 403 `sandbox_disabled` — including with the anonymous-write escape
    /// hatch enabled, which is the "allow by default" branch this must not have.
    #[test]
    fn every_sandbox_route_is_closed_with_no_caller_configured() {
        let mut node = node_for("closed");
        let no_callers = ApiPolicy::deny_all();
        let anonymous_writes = ApiPolicy::deny_all()
            .with_authenticator(Authenticator::deny_all().with_anonymous_writes(true));
        for (method, target) in SANDBOX_ROUTES {
            for policy in [&no_callers, &anonymous_writes] {
                let response = call_with(&mut node, policy, None, method, target, None);
                assert_eq!(
                    response.status, 403,
                    "{method} {target} must be closed: {}",
                    response.body
                );
                assert_eq!(
                    response.body["error"], "sandbox_disabled",
                    "{method} {target}"
                );
            }
        }
        // Nothing was created on disk by any of those refusals.
        assert!(
            !node.config().data_dir.exists(),
            "a closed sandbox API must not even touch its root"
        );
        cleanup(&node);
    }

    /// Requirement 2: every sandbox route demands a presented, configured token —
    /// a missing one and a wrong one are refused, and the refusal is the daemon's
    /// own (`credential_required` / `unknown_credential`), not a second taxonomy.
    #[test]
    fn every_sandbox_route_demands_a_presented_configured_token() {
        let mut node = node_for("token");
        let policy = policy();
        for (method, target) in SANDBOX_ROUTES {
            let response = call_with(&mut node, &policy, None, method, target, None);
            assert_eq!(
                response.status, 401,
                "{method} {target} must demand a credential: {}",
                response.body
            );
            assert_eq!(
                response.body["error"], "credential_required",
                "{method} {target}"
            );

            let response = call_with(
                &mut node,
                &policy,
                Some("not-a-configured-token"),
                method,
                target,
                None,
            );
            assert_eq!(
                response.status, 401,
                "a wrong token for {method} {target}: {}",
                response.body
            );
            assert_eq!(
                response.body["error"], "unknown_credential",
                "{method} {target}"
            );
        }

        // A malformed header is never treated as "no credential, therefore
        // anonymous": it is a 401 of its own.
        let request = Request::new("GET", "/api/v1/sandboxes", NOW)
            .with_authorization(Some("Basic alice-token-for-sandbox-tests"));
        let response = route(&mut node, &request, &policy);
        assert_eq!(response.status, 401, "{}", response.body);
        assert_eq!(response.body["error"], "malformed_credential");
        cleanup(&node);
    }

    /// The scope table applies to sandbox routes: a read-only caller may list its
    /// (empty) set but may not create, exec, pause, resume or destroy.
    #[test]
    fn a_read_only_caller_may_list_but_may_not_mutate() {
        let mut node = node_for("scope");
        install(&node, shared(NullExecutor::new()));
        let reader = ApiPolicy::deny_all().with_authenticator(
            Authenticator::deny_all()
                .with_token("reader-token", "reader", None, &[Scope::Read])
                .expect("configures a reader"),
        );
        let listed = call_with(
            &mut node,
            &reader,
            Some("reader-token"),
            "GET",
            "/sandboxes",
            None,
        );
        assert_eq!(listed.status, 200, "{}", listed.body);

        for (method, target) in [
            ("POST", "/sandboxes"),
            ("DELETE", "/sandboxes/11111111111111111111111111111111"),
            ("POST", "/sandboxes/11111111111111111111111111111111/exec"),
            ("POST", "/sandboxes/11111111111111111111111111111111/pause"),
            ("POST", "/sandboxes/11111111111111111111111111111111/resume"),
        ] {
            let response = call_with(
                &mut node,
                &reader,
                Some("reader-token"),
                method,
                target,
                Some(json!({})),
            );
            assert_eq!(
                response.status, 403,
                "{method} {target} needs write: {}",
                response.body
            );
            assert_eq!(response.body["error"], "insufficient_scope", "{target}");
        }
        cleanup(&node);
    }

    /// The one scope table agrees with the published route shape.
    #[test]
    fn the_scope_table_declares_the_sandbox_routes() {
        for (method, target) in SANDBOX_ROUTES {
            let scope = crate::api::required_scope_for(method, target);
            let expected = if *method == "GET" {
                Scope::Read
            } else {
                Scope::Write
            };
            assert_eq!(scope, expected, "{method} {target}");
        }
        // Both path shapes land on the same table.
        assert_eq!(
            crate::api::required_scope_for("POST", "/api/v1/sandboxes"),
            crate::api::required_scope_for("POST", "/sandboxes")
        );
    }

    /// Requirement 3: another principal's sandbox is answered exactly like an id
    /// that never existed — 404 — on every route, and the sandbox survives the
    /// attempt.
    #[test]
    fn another_principals_sandbox_is_not_found_on_every_route() {
        let mut node = node_for("ownership");
        install(&node, shared(RealProcessExecutor::new()));
        let id = create_sandbox(&mut node, ALICE_TOKEN, creatable_spec());

        for (method, suffix) in [
            ("GET", ""),
            ("DELETE", ""),
            ("POST", "/exec"),
            ("POST", "/commands"),
            ("POST", "/run"),
            ("POST", "/pause"),
            ("POST", "/resume"),
        ] {
            let target = format!("/api/v1/sandboxes/{id}{suffix}");
            let response = call(&mut node, BOB_TOKEN, method, &target, Some(json!({})));
            assert_eq!(
                response.status, 404,
                "bob must not learn that `{id}` exists: {method} {target} → {}",
                response.body
            );
            assert_eq!(response.body["error"], "not_found", "{method} {target}");
            assert!(
                !response.body.to_string().contains("forbidden"),
                "another principal's id is not a 403: {}",
                response.body
            );
        }

        // Bob's destroy attempt destroyed nothing, and his list is empty and
        // mentions no id of alice's.
        let mine = call(
            &mut node,
            ALICE_TOKEN,
            "GET",
            &format!("/api/v1/sandboxes/{id}"),
            None,
        );
        assert_eq!(mine.status, 200, "{}", mine.body);
        let bob_list = call(&mut node, BOB_TOKEN, "GET", "/api/v1/sandboxes", None);
        assert_eq!(bob_list.status, 200);
        assert_eq!(bob_list.body["count"], 0);
        assert!(!bob_list.body.to_string().contains(&id));

        let alice_list = call(&mut node, ALICE_TOKEN, "GET", "/api/v1/sandboxes", None);
        assert_eq!(alice_list.body["count"], 1);
        cleanup(&node);
    }

    /// Requirement 4: the body configures the sandbox. The recorded limits are the
    /// ones the body asked for, and two different bodies are two different
    /// sandboxes — nothing here is a hardcoded template.
    #[test]
    fn the_create_body_configures_the_sandbox() {
        let mut node = node_for("configured");
        install(&node, shared(RealProcessExecutor::new()));

        let mut first = creatable_spec();
        first["limits"]["timeout_ms"] = json!(4_321);
        first["limits"]["memory_bytes"] = json!(96 * 1024 * 1024);
        first["limits"]["max_processes"] = json!(3);
        first["limits"]["max_output_bytes"] = json!(1_024);
        let created = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            "/api/v1/sandboxes",
            Some(first),
        );
        assert_eq!(created.status, 201, "{}", created.body);
        let id = created.body["id"].as_str().expect("an id").to_string();
        assert_eq!(id.len(), 32, "a v4 UUID, not an `sb-N` counter: {id}");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{id}");

        let described = call(
            &mut node,
            ALICE_TOKEN,
            "GET",
            &format!("/api/v1/sandboxes/{id}"),
            None,
        );
        assert_eq!(described.status, 200, "{}", described.body);
        assert_eq!(described.body["timeout_ms"], 4_321);
        assert_eq!(described.body["memory_bytes"], 96 * 1024 * 1024);
        assert_eq!(described.body["max_processes"], 3);
        assert_eq!(described.body["max_output_bytes"], 1_024);
        assert_eq!(described.body["network"], "unrestricted");
        assert_eq!(described.body["owner"], "alice");

        let mut second = creatable_spec();
        second["limits"]["max_output_bytes"] = json!(2_048);
        let other = create_sandbox(&mut node, ALICE_TOKEN, second);
        assert_ne!(other, id);
        let other_described = call(
            &mut node,
            ALICE_TOKEN,
            "GET",
            &format!("/api/v1/sandboxes/{other}"),
            None,
        );
        assert_eq!(other_described.body["max_output_bytes"], 2_048);
        assert_ne!(other_described.body["max_output_bytes"], 1_024);

        // A body that is not a spec at all, and one with a field nobody defined,
        // are refusals rather than defaults.
        let empty = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            "/api/v1/sandboxes",
            Some(json!({})),
        );
        assert_eq!(empty.status, 422, "{}", empty.body);
        let mut typo = creatable_spec();
        typo["limits"]["timeout_millis"] = json!(1_000);
        let typo = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            "/api/v1/sandboxes",
            Some(typo),
        );
        assert_eq!(
            typo.status, 422,
            "a typo must not be ignored: {}",
            typo.body
        );

        // The capability declaration travels with the list, so "what does this
        // deployment actually enforce?" is answerable from the API.
        let list = call(&mut node, ALICE_TOKEN, "GET", "/api/v1/sandboxes", None);
        assert_eq!(list.body["backend"], nau_sandbox::PLATFORM_BACKEND);
        assert!(list.body["capabilities"]["enforced"].is_array());
        assert!(list.body["capabilities"]["unenforced"].is_array());
        cleanup(&node);
    }

    /// Requirement 4, second half: a body that asks for a boundary the backend
    /// cannot enforce fails with the crate's typed refusal, **naming the
    /// boundary**, and creates nothing — never a silently unconfined run.
    #[test]
    fn an_unenforceable_boundary_is_refused_by_name_and_creates_nothing() {
        let mut node = node_for("refusal");
        install(&node, shared(RealProcessExecutor::new()));

        // Every boundary below is declared unenforced by the platform backend on
        // every platform this crate supports.
        let mut deny_egress = creatable_spec();
        deny_egress["network"] = json!("deny_all");
        let mut narrow_egress = creatable_spec();
        narrow_egress["network"] = json!({ "allow_list": { "hosts": ["example.com:443"] } });
        let mut confine = creatable_spec();
        confine["filesystem"] = json!({
            "confinement": "required",
            "extra_readable": [],
            "writable": [],
        });
        let mut quota = creatable_spec();
        quota["waivers"]["disk_bytes"] = json!(null);

        for (boundary, spec) in [
            ("network_deny_all", deny_egress),
            ("network_allow_list", narrow_egress),
            ("filesystem_confinement", confine),
            ("disk_quota", quota),
        ] {
            let response = call(
                &mut node,
                ALICE_TOKEN,
                "POST",
                "/api/v1/sandboxes",
                Some(spec),
            );
            assert_eq!(
                response.status, 422,
                "a boundary the backend cannot enforce must fail: {boundary} → {}",
                response.body
            );
            assert_eq!(response.body["error"], "policy_not_enforceable");
            assert_eq!(
                response.body["boundary"], boundary,
                "the refusal must name the boundary: {}",
                response.body
            );
            assert_eq!(response.body["backend"], nau_sandbox::PLATFORM_BACKEND);
        }

        // Nothing was created, and nothing is on disk.
        let list = call(&mut node, ALICE_TOKEN, "GET", "/api/v1/sandboxes", None);
        assert_eq!(list.body["count"], 0);
        let entries: Vec<_> = std::fs::read_dir(root_of(&node))
            .expect("the sandbox root exists")
            .filter_map(|entry| entry.ok())
            .collect();
        assert!(
            entries.is_empty(),
            "a refused create must leave no directory behind"
        );
        cleanup(&node);
    }

    /// The crate's stated default: the null backend enforces **nothing**, so a
    /// create is refused by name before anything can run. The default really is
    /// "nothing executes", not "no policy is applied" — and the refusal names the
    /// first boundary the backend cannot deliver.
    #[test]
    fn the_default_backend_refuses_every_boundary_by_name() {
        let mut node = node_for("null-backend");
        install(&node, shared(NullExecutor::new()));
        let response = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            "/api/v1/sandboxes",
            Some(creatable_spec()),
        );
        assert_eq!(response.status, 422, "{}", response.body);
        assert_eq!(response.body["error"], "policy_not_enforceable");
        assert_eq!(response.body["backend"], "null-executor");
        assert_eq!(response.body["boundary"], "env_allowlist");
        cleanup(&node);
    }

    /// The error mapping is typed, and `NotFound` is the one that carries the
    /// ownership rule: an id that does not exist and an id owned by somebody else
    /// are the same answer.
    #[test]
    fn sandbox_errors_map_to_typed_statuses_and_codes() {
        use nau_sandbox::{Capability, SandboxError};
        let refused = SandboxError::PolicyNotEnforceable {
            boundary: Capability::NetworkDenyAll,
            backend: "test-backend".to_string(),
            detail: "no egress filter".to_string(),
        };
        assert_eq!(status_for_sandbox(&refused), 422);
        assert_eq!(code_for_sandbox(&refused), "policy_not_enforceable");
        assert_eq!(status_for_sandbox(&SandboxError::NotFound("x".into())), 404);
        assert_eq!(
            status_for_sandbox(&SandboxError::Destroyed("x".into())),
            404
        );
        assert_eq!(
            status_for_sandbox(&SandboxError::Busy("x".into(), "paused".into())),
            409
        );
        assert_eq!(
            status_for_sandbox(&SandboxError::ExecutionDisabled("none".into())),
            501
        );
        assert_eq!(status_for_sandbox(&SandboxError::ManagerGone), 503);
        assert_eq!(status_for_sandbox(&SandboxError::Internal("x".into())), 500);
        assert_eq!(
            status_for_sandbox(&SandboxError::OrphanReclaim {
                count: 1,
                detail: "x".into(),
            }),
            500
        );
    }

    /// The backend selection refuses a value it does not know rather than falling
    /// back to a default — a typo in a security setting must not pick a backend.
    #[test]
    fn an_unknown_backend_selection_is_refused() {
        assert!(executor_for("").is_ok(), "the default executes nothing");
        assert_eq!(
            executor_for("").expect("the null backend").name(),
            "null-executor"
        );
        #[cfg(windows)]
        assert!(executor_for("process").is_ok());
        #[cfg(not(windows))]
        {
            let e = executor_for("process")
                .err()
                .expect("the process backend is refused on this platform");
            assert!(e.contains("verified on Windows only"), "{e}");
        }
        #[cfg(windows)]
        assert!(executor_for(" REAL ").is_ok());
        #[cfg(not(windows))]
        assert!(
            executor_for(" REAL ").is_err(),
            "the process backend is refused on this platform however it is spelled"
        );
        let error = match executor_for("python") {
            Ok(_) => panic!("`python` is not a backend"),
            Err(error) => error,
        };
        assert!(error.contains(BACKEND_ENV), "{error}");
        assert!(error.contains("process"), "{error}");
    }

    /// Requirement 4 at exec time: the limits the body configured are the limits
    /// that run, and the body's `stdin` reaches the child.
    // Windows only, for the same reason the daemon refuses `NAU_SANDBOX_BACKEND=process`
    // off Windows: these tests install a real process executor DIRECTLY, bypassing the
    // selection, and on Unix that backend has not been shown to honour its declaration
    // (CI: the timeout was not enforced on Ubuntu; execution through the router failed
    // on macOS while passing on Ubuntu). They are evidence for Windows, and
    // `tests/platform_support.rs` in nau-sandbox states the gap for everyone else.
    #[cfg(windows)]
    #[test]
    fn exec_runs_with_the_limits_the_body_configured() {
        let mut node = node_for("exec-limits");
        install(&node, shared(RealProcessExecutor::new()));

        let mut tight = creatable_spec();
        tight["limits"]["max_output_bytes"] = json!(8);
        let tight_id = create_sandbox(&mut node, ALICE_TOKEN, tight);

        let mut loose = creatable_spec();
        loose["limits"]["max_output_bytes"] = json!(256 * 1024);
        let loose_id = create_sandbox(&mut node, ALICE_TOKEN, loose);

        let tight_run = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            &format!("/api/v1/sandboxes/{tight_id}/exec"),
            Some(json!({ "stdin": "nau" })),
        );
        assert_eq!(tight_run.status, 200, "{}", tight_run.body);
        assert_eq!(
            tight_run.body["stdout"].as_str().map(str::len),
            Some(8),
            "the body's output cap is what runs: {}",
            tight_run.body
        );
        assert_eq!(tight_run.body["stdout_truncated"], true);
        assert_eq!(tight_run.body["exit_code"], 0, "{}", tight_run.body);

        // The `run` alias, a generous cap and real stdin: the whole stream is
        // retained and the script body arrived.
        let loose_run = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            &format!("/api/v1/sandboxes/{loose_id}/run"),
            Some(json!({ "stdin": "nau" })),
        );
        assert_eq!(loose_run.status, 200, "{}", loose_run.body);
        assert_eq!(loose_run.body["stdout_truncated"], false);
        assert!(
            loose_run.body["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("STDIN:nau"),
            "the exec body's stdin must reach the child: {}",
            loose_run.body
        );
        cleanup(&node);
    }

    /// An exec override may only tighten: a widened limit is refused, a tightened
    /// one is honoured and used.
    #[cfg(windows)]
    #[test]
    fn an_exec_override_may_only_tighten() {
        let mut node = node_for("exec-override");
        install(&node, shared(RealProcessExecutor::new()));
        let id = create_sandbox(&mut node, ALICE_TOKEN, creatable_spec());

        let mut widened = creatable_spec();
        widened["limits"]["timeout_ms"] = json!(60_000);
        let response = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            &format!("/api/v1/sandboxes/{id}/exec"),
            Some(json!({ "spec": widened })),
        );
        assert_eq!(response.status, 422, "{}", response.body);
        assert_eq!(response.body["error"], "policy_not_enforceable");
        assert_eq!(response.body["boundary"], "timeout");

        let mut tighter = creatable_spec();
        tighter["limits"]["timeout_ms"] = json!(15_000);
        tighter["limits"]["max_output_bytes"] = json!(4);
        let response = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            &format!("/api/v1/sandboxes/{id}/exec"),
            Some(json!({ "spec": tighter })),
        );
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(response.body["stdout"].as_str().map(str::len), Some(4));
        cleanup(&node);
    }

    /// A paused sandbox refuses to exec until it is resumed.
    #[cfg(windows)]
    #[test]
    fn a_paused_sandbox_refuses_to_exec_until_it_is_resumed() {
        let mut node = node_for("pause");
        install(&node, shared(RealProcessExecutor::new()));
        let id = create_sandbox(&mut node, ALICE_TOKEN, creatable_spec());

        let paused = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            &format!("/api/v1/sandboxes/{id}/pause"),
            None,
        );
        assert_eq!(paused.status, 200, "{}", paused.body);
        assert_eq!(paused.body["status"], "paused");

        let refused = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            &format!("/api/v1/sandboxes/{id}/exec"),
            None,
        );
        assert_eq!(refused.status, 409, "{}", refused.body);
        assert_eq!(refused.body["error"], "conflict");

        let resumed = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            &format!("/api/v1/sandboxes/{id}/resume"),
            None,
        );
        assert_eq!(resumed.status, 200, "{}", resumed.body);
        assert_eq!(resumed.body["status"], "ready");

        let ran = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            &format!("/api/v1/sandboxes/{id}/exec"),
            None,
        );
        assert_eq!(ran.status, 200, "{}", ran.body);
        cleanup(&node);
    }

    /// Destroy removes the work directory, the id is terminal, and a new sandbox
    /// never lands in the old directory.
    #[test]
    fn destroying_removes_the_work_directory_and_the_id_is_never_reissued() {
        let mut node = node_for("destroy");
        install(&node, shared(RealProcessExecutor::new()));
        let root = root_of(&node);
        let first = create_sandbox(&mut node, ALICE_TOKEN, creatable_spec());
        assert!(root.join(&first).is_dir(), "the work directory must exist");

        let destroyed = call(
            &mut node,
            ALICE_TOKEN,
            "DELETE",
            &format!("/api/v1/sandboxes/{first}"),
            None,
        );
        assert_eq!(destroyed.status, 200, "{}", destroyed.body);
        assert_eq!(destroyed.body["status"], "destroyed");
        assert!(
            !root.join(&first).exists(),
            "destroy must remove the work directory"
        );

        let again = call(
            &mut node,
            ALICE_TOKEN,
            "GET",
            &format!("/api/v1/sandboxes/{first}"),
            None,
        );
        assert_eq!(
            again.status, 404,
            "a destroyed id is terminal: {}",
            again.body
        );

        let second = create_sandbox(&mut node, ALICE_TOKEN, creatable_spec());
        assert_ne!(second, first, "an id is never reissued");
        assert!(!root.join(&first).exists());
        assert!(root.join(&second).is_dir());
        cleanup(&node);
    }

    /// Requirement 6: a directory no live sandbox owns, from a run that is gone,
    /// is reclaimed when the manager opens — before any new sandbox could be
    /// created on top of it.
    #[test]
    fn a_startup_sweep_reclaims_an_orphan_directory_from_a_dead_run() {
        let node = node_for("sweep");
        let root = root_of(&node);
        let orphan = root.join("11111111111111111111111111111111");
        std::fs::create_dir_all(&orphan).expect("an orphan directory");
        std::fs::write(
            orphan.join(".nau-sandbox-run.json"),
            json!({
                "run_id": "a-run-that-is-gone",
                // A pid that cannot exist, so the sweep does not mistake the
                // directory for a concurrently starting daemon's.
                "pid": u32::MAX,
                "created_at": 0,
            })
            .to_string(),
        )
        .expect("the run marker");
        assert!(orphan.is_dir());

        // The first sandbox request opens the manager, which is what sweeps.
        let mut node = node;
        let response = call(&mut node, ALICE_TOKEN, "GET", "/api/v1/sandboxes", None);
        assert_eq!(response.status, 200, "{}", response.body);
        assert!(
            !orphan.exists(),
            "the startup sweep must reclaim a directory no live sandbox owns"
        );

        // And a new sandbox does not inherit the reclaimed id's directory.
        install(&node, shared(RealProcessExecutor::new()));
        let id = create_sandbox(&mut node, ALICE_TOKEN, creatable_spec());
        assert_ne!(id, "11111111111111111111111111111111");
        assert!(!root.join("11111111111111111111111111111111").exists());
        assert!(root.join(&id).is_dir());
        cleanup(&node);
    }

    /// A hostile `Origin` is refused before routing and is never echoed — on the
    /// sandbox routes too, where upstream answered `Access-Control-Allow-Origin: *`.
    #[test]
    fn a_hostile_origin_is_refused_and_never_echoed_on_a_sandbox_route() {
        let mut node = node_for("origin");

        let hostile = Request::new("GET", "/api/v1/sandboxes", NOW)
            .with_origin(Some("http://evil.example"))
            .with_authorization(Some(format!("Bearer {ALICE_TOKEN}")));
        let response = route(&mut node, &hostile, &policy());
        assert_eq!(response.status, 403, "{}", response.body);
        assert_eq!(response.body["error"], "forbidden_origin");
        assert_eq!(
            response.header("Access-Control-Allow-Origin"),
            None,
            "a hostile origin must never be echoed"
        );

        // An allow-listed origin is echoed exactly, once, with `Vary: Origin`.
        install(&node, shared(NullExecutor::new()));
        let allowed = policy().allow_origin("http://127.0.0.1:1420");
        let ok = Request::new("GET", "/api/v1/sandboxes", NOW)
            .with_origin(Some("http://127.0.0.1:1420"))
            .with_authorization(Some(format!("Bearer {ALICE_TOKEN}")));
        let response = route(&mut node, &ok, &allowed);
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(
            response.header("Access-Control-Allow-Origin"),
            Some("http://127.0.0.1:1420")
        );
        assert_eq!(response.header("Vary"), Some("Origin"));
        cleanup(&node);
    }

    /// Requirement 5, second half: a poisoned lock is recovered, not `unwrap`ped.
    /// The upstream defect was `mgr.lock().unwrap()`, where one panic anywhere
    /// disabled every later sandbox call.
    #[test]
    fn a_poisoned_registry_lock_does_not_disable_the_routes() {
        let mut node = node_for("poison");
        install(&node, shared(NullExecutor::new()));
        let before = call(&mut node, ALICE_TOKEN, "GET", "/sandboxes", None);
        assert_eq!(before.status, 200, "{}", before.body);

        // Poison the registry exactly as a panic elsewhere in the daemon would.
        let poisoned = std::panic::catch_unwind(|| {
            let _guard = registry().lock();
            panic!("poison the registry from a test");
        });
        assert!(poisoned.is_err(), "the closure must have panicked");
        assert!(registry().lock().is_err(), "the lock must be poisoned now");

        let after = call(&mut node, ALICE_TOKEN, "GET", "/sandboxes", None);
        assert_eq!(
            after.status, 200,
            "a poisoned registry must not disable the route: {}",
            after.body
        );
        cleanup(&node);
    }

    /// Requirement 5, first half: no daemon-level lock is held across execution.
    /// While one sandbox is running, the registry — the only lock this module adds
    /// — is free.
    #[cfg(windows)]
    #[test]
    fn the_registry_lock_is_not_held_while_a_sandbox_executes() {
        let mut node = node_for("no-global-lock");
        install(&node, shared(RealProcessExecutor::new()));

        let mut spec = creatable_spec();
        spec["interpreter"] = worker_interpreter("sandbox_worker_slow");
        spec["env"]["vars"] = json!([["NAU_SANDBOX_TEST_SLEEP_MS", "3000"]]);
        let id = create_sandbox(&mut node, ALICE_TOKEN, spec);
        let started = root_of(&node).join(&id).join("started.txt");

        let target = format!("/api/v1/sandboxes/{id}/exec");
        let runner = std::thread::spawn(move || {
            let mut node = node;
            let response = call(&mut node, ALICE_TOKEN, "POST", &target, None);
            (node, response)
        });

        // Wait until the sandboxed program is provably running.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !started.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the sandboxed program never started"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        match registry().try_lock() {
            Ok(_) => {}
            // A poisoned registry is another test's doing; it is still *free*.
            Err(std::sync::TryLockError::Poisoned(_)) => {}
            Err(std::sync::TryLockError::WouldBlock) => {
                panic!("the registry must not be held across an execution")
            }
        }
        let (node, response) = runner.join().expect("the exec thread must finish");
        assert_eq!(response.status, 200, "{}", response.body);
        assert!(
            response.body["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("SLOW_DONE"),
            "{}",
            response.body
        );
        cleanup(&node);
    }

    /// Route shape: a wrong method is a 405 naming what the route accepts, and an
    /// unknown action is a 404 — neither is answered by running anything.
    #[test]
    fn a_wrong_method_is_405_and_an_unknown_action_is_404() {
        let mut node = node_for("shape");
        install(&node, shared(NullExecutor::new()));

        let put = call(&mut node, ALICE_TOKEN, "PUT", "/sandboxes", None);
        assert_eq!(put.status, 405, "{}", put.body);
        assert_eq!(put.body["allow"], json!(["GET", "POST"]));

        let get_action = call(
            &mut node,
            ALICE_TOKEN,
            "GET",
            "/sandboxes/some-id/exec",
            None,
        );
        assert_eq!(get_action.status, 405, "{}", get_action.body);
        assert_eq!(get_action.body["allow"], json!(["POST"]));

        let unknown = call(
            &mut node,
            ALICE_TOKEN,
            "POST",
            "/sandboxes/some-id/runn",
            None,
        );
        assert_eq!(unknown.status, 404, "{}", unknown.body);

        let too_deep = call(
            &mut node,
            ALICE_TOKEN,
            "GET",
            "/sandboxes/some-id/exec/more",
            None,
        );
        assert_eq!(too_deep.status, 404, "{}", too_deep.body);
        cleanup(&node);
    }
}
