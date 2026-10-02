//! The MCP server: one tool registry, one dispatch path, correct wire shapes.
//!
//! ## What changed from upstream v2.5.6
//!
//! | defect | fix |
//! |---|---|
//! | the schema and dispatch were two hand-maintained lists, and arguments were read with `.unwrap_or(..)` so a wrong type silently became a default | a [`ToolDefinition`] carries its parameters *and* its handler; [`McpServer::handle`] validates before dispatch |
//! | an unknown tool returned protocol error `-32001` | it returns a normal `tools/call` result with `isError: true` |
//! | `initialize` ignored its params and always answered a hardcoded version | [`McpServer::initialize_result`] negotiates, and a request before `initialize` is refused with `-32002` |
//! | every read path needed `&mut self`, forcing a mutex | [`McpServer::handle`] takes `&self` |
//!
//! ## What changed from upstream v2.8.2
//!
//! upstream v2.8.2 fix (finding 5): upstream validates arguments in a function
//! that one transport calls and the other two bypass
//! (`tool.rs:165-201` is reached only from `server.rs:202`, and `McpServer` has
//! no production call site at all). Here there is **one** dispatch function,
//! [`McpServer::dispatch`], and every transport goes through
//! [`crate::server::handle_line`] to reach it. There is no second entry: the
//! per-tool handler is private to [`crate::tool`]
//! (`ToolDefinition::call` is the only caller), so "call the bridge directly" —
//! what upstream's `sse.rs:130-147` and `stdio.rs:85-93` do — is not expressible
//! against this API.
//!
//! upstream v2.8.2 fix (finding 6): every path into a tool now takes a
//! [`Principal`], and [`McpServer::dispatch`] refuses a mutating tool for a
//! principal without [`Scope::Write`] *before* validation or the handler. A
//! principal can only carry the write scope if it came from
//! [`crate::auth::Authenticator::authenticate`], so an unauthenticated transport
//! cannot mutate anything, and per-caller ownership is enforced where the tool
//! declares an [`OwnershipSpec`].

use std::collections::HashMap;

use nau_core::{NauError, Result};
use serde_json::{json, Value};

use crate::auth::{Principal, Scope};
use crate::capability::InitializeResult;
use crate::protocol::{is_supported, InitializeParams, SUPPORTED_PROTOCOL_VERSIONS};
use crate::rpc::{error_code, parse_request, RequestId, RpcError, RpcRequest, RpcResponse};
use crate::tool::{ToolDefinition, ToolEffect, ToolOutcome};

/// MCP method names this server implements.
pub mod method {
    /// The handshake.
    pub const INITIALIZE: &str = "initialize";
    /// The client's "handshake complete" notification.
    pub const INITIALIZED: &str = "notifications/initialized";
    /// Liveness check.
    pub const PING: &str = "ping";
    /// List the registered tools.
    pub const TOOLS_LIST: &str = "tools/list";
    /// Invoke a tool.
    pub const TOOLS_CALL: &str = "tools/call";
}

/// How far the session has got.
///
/// The state is owned by the caller and passed to [`McpServer::handle`], so the
/// server itself needs no interior mutability: one `&McpServer` can serve many
/// sessions concurrently.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum SessionState {
    /// `initialize` has not been seen: only `initialize` is accepted.
    #[default]
    Uninitialized,
    /// `initialize` succeeded.
    Initialized {
        /// The version the server answered with.
        negotiated: &'static str,
        /// The version the client asked for, remembered for diagnostics.
        requested: Option<String>,
    },
}

impl SessionState {
    /// True once `initialize` has succeeded.
    pub fn is_initialized(&self) -> bool {
        matches!(self, SessionState::Initialized { .. })
    }

    /// The negotiated version, if the session is initialized.
    pub fn negotiated_version(&self) -> Option<&'static str> {
        match self {
            SessionState::Initialized { negotiated, .. } => Some(negotiated),
            SessionState::Uninitialized => None,
        }
    }

    /// The version the client asked for, if it asked for one.
    pub fn requested_version(&self) -> Option<&str> {
        match self {
            SessionState::Initialized { requested, .. } => requested.as_deref(),
            SessionState::Uninitialized => None,
        }
    }
}

/// An MCP server over a registry of [`ToolDefinition`]s.
pub struct McpServer {
    server_name: &'static str,
    server_version: &'static str,
    tools: HashMap<&'static str, ToolDefinition>,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServer")
            .field("server_name", &self.server_name)
            .field("server_version", &self.server_version)
            .field("tool_count", &self.tools.len())
            .finish_non_exhaustive()
    }
}

impl McpServer {
    /// A server with no tools yet.
    pub fn new(server_name: &'static str, server_version: &'static str) -> Self {
        Self {
            server_name,
            server_version,
            tools: HashMap::new(),
        }
    }

    /// The server's declared name.
    pub fn server_name(&self) -> &'static str {
        self.server_name
    }

    /// The server's declared version.
    pub fn server_version(&self) -> &'static str {
        self.server_version
    }

    /// Register a tool.
    ///
    /// # Errors
    ///
    /// [`NauError::Conflict`] if a tool with the same name is already
    /// registered, or if the definition declares the same parameter twice.
    /// Upstream's `register_tool` used `HashMap::insert` and silently replaced
    /// the previous definition -?and its handler, if any.
    pub fn register(&mut self, tool: ToolDefinition) -> Result<()> {
        if tool.name.trim().is_empty() {
            return Err(NauError::Validation("tool name must not be empty".into()));
        }
        if self.tools.contains_key(tool.name) {
            return Err(NauError::Conflict(format!(
                "a tool named `{}` is already registered",
                tool.name
            )));
        }
        let mut seen = Vec::with_capacity(tool.params.len());
        for param in &tool.params {
            if param.name.trim().is_empty() {
                return Err(NauError::Validation(format!(
                    "tool `{}` declares a parameter with an empty name",
                    tool.name
                )));
            }
            if seen.contains(&param.name) {
                return Err(NauError::Conflict(format!(
                    "tool `{}` declares parameter `{}` twice",
                    tool.name, param.name
                )));
            }
            seen.push(param.name);
        }
        self.tools.insert(tool.name, tool);
        Ok(())
    }

    /// The registered tools, sorted by name.
    ///
    /// Sorted rather than hash order, so `tools/list` is byte-identical across
    /// processes and platforms.
    pub fn tools(&self) -> Vec<&ToolDefinition> {
        let mut tools: Vec<&ToolDefinition> = self.tools.values().collect();
        tools.sort_by_key(|tool| tool.name);
        tools
    }

    /// How many tools are registered.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Look up one tool by name.
    pub fn tool(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools.get(name)
    }

    /// Handle one request, advancing `state`, as `principal`.
    ///
    /// Takes `&self`: upstream required `&mut self` even for pure reads such as
    /// `tools/list`, which forced every caller to wrap the server in a mutex.
    ///
    /// Takes a [`Principal`] because every path into a tool must be an
    /// authenticated one: a transport that cannot name its caller cannot call a
    /// mutating tool. Use [`Principal::anonymous`] for a caller that presented no
    /// credential; that caller can still read.
    pub fn handle(
        &self,
        principal: &Principal,
        state: &mut SessionState,
        req: &RpcRequest,
    ) -> RpcResponse {
        let id = req.id.clone();

        if !req.has_valid_version() {
            return RpcResponse::err(
                id,
                error_code::INVALID_REQUEST,
                format!(
                    "`jsonrpc` must be `{}`, got `{}`",
                    crate::rpc::JSONRPC_VERSION,
                    req.jsonrpc
                ),
            );
        }

        if req.method == method::INITIALIZE {
            return self.initialize_result(state, &id, &req.params);
        }

        if !state.is_initialized() {
            // upstream v2.5.6 fix: upstream answered every method regardless of
            // whether `initialize` had happened, so a client could skip version
            // negotiation entirely.
            return RpcResponse::err(
                id,
                error_code::NOT_INITIALIZED,
                format!(
                    "`{}` arrived before `initialize`; negotiate a protocol version first \
                     (supported: {})",
                    req.method,
                    SUPPORTED_PROTOCOL_VERSIONS.join(", ")
                ),
            );
        }

        match req.method.as_str() {
            method::INITIALIZED => RpcResponse::ok(id, json!({})),
            method::PING => RpcResponse::ok(id, json!({})),
            method::TOOLS_LIST => self.tools_list_result(&id),
            method::TOOLS_CALL => self.tool_result(principal, &id, &req.params),
            other => RpcResponse::err(
                id,
                error_code::METHOD_NOT_FOUND,
                format!("unknown method `{other}`"),
            ),
        }
    }

    /// The `initialize` result, or an error for an unsupported version.
    pub fn initialize_result(
        &self,
        state: &mut SessionState,
        id: &RequestId,
        params: &Value,
    ) -> RpcResponse {
        let parsed = InitializeParams::from_params(params);
        let requested = parsed.requested_version();
        if let Some(version) = requested {
            if !is_supported(version) {
                return RpcResponse::err(
                    id.clone(),
                    error_code::INVALID_PARAMS,
                    format!(
                        "unsupported protocol version `{version}`; supported: {}",
                        SUPPORTED_PROTOCOL_VERSIONS.join(", ")
                    ),
                );
            }
        }
        let negotiated = parsed.negotiated_version();
        *state = SessionState::Initialized {
            negotiated,
            requested: requested.map(str::to_string),
        };
        let result = InitializeResult::new(self.server_name, self.server_version, negotiated);
        match serde_json::to_value(&result) {
            Ok(value) => RpcResponse::ok(id.clone(), value),
            Err(error) => RpcResponse::err(
                id.clone(),
                error_code::INTERNAL_ERROR,
                format!("could not serialize the initialize result: {error}"),
            ),
        }
    }

    /// The `tools/list` result, tools sorted by name.
    ///
    /// Each entry carries the `annotations` MCP uses to describe a tool's effect,
    /// so a client (and a model) can see that a tool mutates state *before*
    /// calling it. The annotation is derived from [`ToolDefinition::effect`], the
    /// same field the dispatch gate enforces, so the published claim and the
    /// enforced rule cannot disagree.
    pub fn tools_list_result(&self, id: &RequestId) -> RpcResponse {
        let tools: Vec<Value> = self
            .tools()
            .iter()
            .map(|tool| {
                let mut entry = json!({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema(),
                    "annotations": {
                        "readOnlyHint": tool.effect() == ToolEffect::ReadOnly,
                        "destructiveHint": tool.effect() == ToolEffect::Mutating,
                    },
                });
                if let (Some(ownership), Some(object)) = (tool.ownership(), entry.as_object_mut()) {
                    // The ownership binding is data, not prose: a client can see
                    // which argument must name the caller's own DID.
                    let mut binding = json!({ "argument": ownership.param });
                    if !ownership.path.is_empty() {
                        binding["path"] = json!(ownership.path);
                    }
                    object.insert("x-nau-ownership".to_string(), binding);
                }
                entry
            })
            .collect();
        RpcResponse::ok(id.clone(), json!({ "tools": tools }))
    }

    /// Map a raw `tools/call` params object onto an MCP result, echoing `id`.
    ///
    /// Structural problems (no `name`, wrong `arguments` type) are protocol
    /// `-32602` errors. Everything else — an unknown tool, a validation failure,
    /// an authorization refusal, a handler error — is a **normal result** with
    /// `isError: true`, because that is what MCP expects and what lets a model
    /// read the message and correct itself.
    pub fn tool_result(
        &self,
        principal: &Principal,
        id: &RequestId,
        params: &Value,
    ) -> RpcResponse {
        let name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => {
                return RpcResponse::err(
                    id.clone(),
                    error_code::INVALID_PARAMS,
                    "`tools/call` requires a string `name`",
                )
            }
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
        if !arguments.is_object() && !arguments.is_null() {
            return RpcResponse::err(
                id.clone(),
                error_code::INVALID_PARAMS,
                "`tools/call` `arguments` must be an object",
            );
        }
        RpcResponse::ok(id.clone(), self.dispatch(principal, name, &arguments))
    }

    /// [`McpServer::tool_result`] with a `null` id, for callers that have no
    /// request id to echo.
    pub fn tools_call_result(&self, principal: &Principal, params: &Value) -> RpcResponse {
        self.tool_result(principal, &RequestId::Null, params)
    }

    /// Invoke a tool as `principal`, returning the MCP result object.
    ///
    /// **This is the single dispatch point.** Every transport reaches a tool
    /// through it, and it is the only function that decides both authorization
    /// and argument validity:
    ///
    /// 1. the tool must be registered (an unknown name is a normal `isError`
    ///    result, not a protocol error);
    /// 2. the principal must hold the scope the tool's [`ToolEffect`] requires —
    ///    `write` for a mutating tool — checked **before** validation and before
    ///    the handler;
    /// 3. when the principal is bound to a DID and the tool declares an
    ///    [`crate::tool::OwnershipSpec`], the argument that names the acting DID
    ///    must equal the caller's own; a DID-bound caller therefore cannot act on
    ///    another's account, task or bid;
    /// 4. only then is the argument object validated and the (private) handler
    ///    invoked, via [`ToolDefinition::call`].
    pub fn dispatch(&self, principal: &Principal, name: &str, arguments: &Value) -> Value {
        let Some(tool) = self.tools.get(name) else {
            return ToolOutcome::error(format!(
                "unknown tool `{name}`; this server exposes: {}",
                self.tool_names().join(", ")
            ))
            .to_mcp_result();
        };
        if let Err(error) = self.authorize(principal, tool, arguments) {
            return ToolOutcome::error(error.to_string()).to_mcp_result();
        }
        tool.call(arguments).to_mcp_result()
    }

    /// The authorization decision for one call, before any validation or handler.
    fn authorize(
        &self,
        principal: &Principal,
        tool: &ToolDefinition,
        arguments: &Value,
    ) -> Result<()> {
        principal.require(if tool.effect().requires_write_scope() {
            Scope::Write
        } else {
            Scope::Read
        })?;
        let (Some(ownership), Some(did)) = (tool.ownership(), principal.did()) else {
            // Either the tool has no ownership binding, or the caller is a
            // service credential that is not bound to an identity. The market's
            // own authorization still applies to the mutation itself.
            return Ok(());
        };
        match ownership.owner(arguments) {
            Some(owner) if owner == did => Ok(()),
            Some(owner) => Err(NauError::Unauthorized(format!(
                "caller `{}` acts as `{did}` and may not invoke `{}` for `{owner}`",
                principal.id(),
                tool.name
            ))),
            None => Err(NauError::Unauthorized(format!(
                "tool `{}` acts on `{}`, which must name the calling DID, and caller `{}` is bound \
                 to `{did}`, so the argument may not be omitted",
                tool.name,
                ownership.param,
                principal.id()
            ))),
        }
    }

    /// The registered tool names, sorted.
    pub fn tool_names(&self) -> Vec<&'static str> {
        self.tools().iter().map(|tool| tool.name).collect()
    }
}

/// Parse one line of JSON-RPC and answer it as `principal`.
///
/// A line that is not JSON yields a `-32700` parse-error response with
/// `id: null`, as JSON-RPC requires; a line that is JSON but not a valid request
/// yields `-32600`. A notification (no `id`) yields `None`.
///
/// upstream v2.8.2 fix (finding 5): the principal is a **required argument**, so
/// there is no way to answer a line without saying who is asking. That is the
/// difference between a validator a transport can bypass and one it cannot.
pub fn handle_line(
    server: &McpServer,
    principal: &Principal,
    state: &mut SessionState,
    line: &str,
) -> Option<RpcResponse> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let value: Value = match serde_json::from_str(trimmed) {
        Ok(value) => value,
        Err(error) => {
            // upstream v2.5.6 fix: upstream answered `id: 0` here, because its
            // `RequestId` had no `Null` variant. JSON-RPC requires `null`.
            return Some(RpcResponse::err(
                RequestId::Null,
                error_code::PARSE_ERROR,
                format!("invalid JSON: {error}"),
            ));
        }
    };
    match parse_request(value) {
        Ok(request) => {
            if request.is_notification() {
                return None;
            }
            Some(server.handle(principal, state, &request))
        }
        Err((id, error)) => Some(RpcResponse::err(id, error.code, error.message)),
    }
}

/// Format a JSON-RPC response as one line.
pub fn encode_response(response: &RpcResponse) -> Result<String> {
    Ok(serde_json::to_string(response)?)
}

/// Build the MCP error body for a protocol-level failure. Exposed so a transport
/// can produce the same shape as [`handle_line`].
pub fn protocol_error(id: RequestId, error: RpcError) -> RpcResponse {
    RpcResponse::err(id, error.code, error.message)
}
