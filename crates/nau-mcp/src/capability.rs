//! `initialize` result and capability declarations.
//!
//! ## What changed from upstream v2.5.6
//!
//! Upstream's capability structs
//! (`gsn-core/src/mcp/protocol.rs` — `ToolsCapability { list_changed: bool }`,
//! `ResourcesCapability`, `PromptsCapability`) had **no** rename attribute, so
//! they serialized `list_changed` / `subscribe` while the surrounding
//! `InitializeResult` correctly used camelCase. The result was a capability
//! object that no MCP client could parse. Every field here is pinned by the
//! `wire_shapes_are_exactly_right` test.
//!
//! Upstream also ignored its own `initialize` params and always answered
//! `MCP_PROTOCOL_VERSION`; [`InitializeResult`] carries whichever supported
//! version the server negotiated.

use serde::{Deserialize, Serialize};

use crate::protocol::DEFAULT_PROTOCOL_VERSION;

/// Declares the `tools` capability. Wire key: `listChanged`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ToolsCapability {
    /// Always `false`: this server's tool set is fixed at construction.
    ///
    /// upstream v2.5.6 fix: the field is pinned to the wire name `listChanged`.
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

impl ToolsCapability {
    /// The capability as this server reports it: registered handlers only, and
    /// the tool list never changes after construction.
    pub const fn fixed() -> Self {
        Self {
            list_changed: false,
        }
    }
}

/// Declares the `resources` capability. Wire keys: `subscribe`, `listChanged`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ResourcesCapability {
    /// Always `false`: this server pushes no resource updates.
    #[serde(rename = "subscribe")]
    pub subscribe: bool,
    /// Always `false`.
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

/// Declares the `prompts` capability. Wire key: `listChanged`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct PromptsCapability {
    /// Always `false`.
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

/// The server's capability declaration.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Present when the server exposes tools.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    /// Present when the server exposes resources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    /// Present when the server exposes prompts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
}

impl ServerCapabilities {
    /// Tools only — the shape this crate's server always reports.
    pub const fn tools_only() -> Self {
        Self {
            tools: Some(ToolsCapability::fixed()),
            resources: None,
            prompts: None,
        }
    }
}

/// Server identity. Wire key: `serverInfo`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server name.
    pub name: String,
    /// Server version.
    pub version: String,
}

/// The `initialize` result. Wire keys: `protocolVersion`, `serverInfo`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    /// The negotiated protocol version, always one of
    /// [`SUPPORTED_PROTOCOL_VERSIONS`].
    pub protocol_version: String,
    /// What the server can do.
    pub capabilities: ServerCapabilities,
    /// Who the server is.
    pub server_info: ServerInfo,
    /// Optional usage instructions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

impl InitializeResult {
    /// The result for a negotiated version.
    pub fn new(server_name: &str, server_version: &str, protocol_version: &str) -> Self {
        Self {
            protocol_version: protocol_version.to_string(),
            capabilities: ServerCapabilities::tools_only(),
            server_info: ServerInfo {
                name: server_name.to_string(),
                version: server_version.to_string(),
            },
            instructions: None,
        }
    }

    /// Attach usage instructions.
    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// The default-version result.
    pub fn with_default_version(server_name: &str, server_version: &str) -> Self {
        Self::new(server_name, server_version, DEFAULT_PROTOCOL_VERSION)
    }
}
