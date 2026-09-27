//! # nau-mcp — an MCP server with one source of truth per tool
//!
//! This crate replaces upstream `agent-universe` v2.5.6's
//! `gsn-core/src/mcp/*`. The organising idea is that a tool is declared
//! **once**: [`ToolDefinition`] carries its name, description, typed parameter
//! list and handler, and everything else — the published JSON Schema, the
//! argument validation, the dispatch — is derived from that single record. The
//! upstream schema and its dispatch were two hand-written lists, and the schema
//! was never enforced.
//!
//! ## What is fixed here
//!
//! 1. **Schemas are derived, and arguments are validated.** `market_deposit`
//!    with `amount: "lots"` used to deposit 0 because every argument was read
//!    with `.unwrap_or(..)`. A missing or wrongly typed parameter is now a
//!    `-32602 InvalidParams` error naming the offending parameters, before any
//!    handler runs.
//! 2. **No caller-supplied quorum thresholds.** `approvals` and
//!    `committee_size` do not exist in this tool surface. The vote tools take a
//!    task id and an array of signed votes, and the observed count is decided
//!    here ([`validated_votes`]).
//! 3. **[`RequestId::Null`] exists**, so a parse-error response carries `id:
//!    null` as JSON-RPC requires instead of the upstream `id: 0`.
//! 4. **Tool-level failures are results, not protocol errors.** An unknown tool,
//!    a validation failure or a handler error all return
//!    `{"content":[{"type":"text","text":...}],"isError":true}`.
//! 5. **Version negotiation is real.** `initialize` parses `protocolVersion`,
//!    echoes a supported version, records what the client asked for, and refuses
//!    a request that arrives before `initialize` with `-32002`.
//! 6. **Reads take `&self`.** [`McpServer::handle`] no longer needs `&mut self`,
//!    so no mutex is required to serve concurrent sessions.
//! 7. **Capability structs use correct wire naming** (`listChanged`,
//!    `inputSchema`, `protocolVersion`, `serverInfo`), asserted by a test.
//!
//! ## Design rules
//!
//! * `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`, every public item
//!   documented.
//! * No `unwrap()`/`expect()`/`panic!()` outside `#[cfg(test)]`, and no error
//!   path can abort a session: a panicking handler is contained by
//!   [`ToolDefinition::call`].
//! * Deterministic ordering: tools are always listed sorted by name.
//! * Every upstream fix is marked with a `// upstream v2.5.6 fix:` comment.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod capability;
pub mod market;
pub mod protocol;
pub mod rpc;
pub mod server;
pub mod tool;
pub mod transport;

pub use capability::{
    InitializeResult, PromptsCapability, ResourcesCapability, ServerCapabilities, ServerInfo,
    ToolsCapability,
};
pub use market::{validated_votes, Dispatcher, MarketToolBridge};
pub use protocol::{
    is_supported, negotiate, InitializeParams, DEFAULT_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};
pub use rpc::{
    error_code, parse_request, RequestId, RpcError, RpcRequest, RpcResponse, JSONRPC_VERSION,
};
pub use server::{encode_response, handle_line, protocol_error, McpServer, SessionState};
pub use tool::{ParamSpec, ParamType, ToolDefinition, ToolHandler, ToolOutcome};
pub use transport::{serve_stdio, sse_frame};
