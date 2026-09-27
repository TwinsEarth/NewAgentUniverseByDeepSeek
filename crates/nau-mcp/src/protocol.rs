//! Protocol version negotiation.
//!
//! ## What changed from upstream v2.5.6
//!
//! Upstream's `handle_initialize` took no parameters
//! (`gsn-core/src/mcp/server.rs::handle_initialize(&self, id)`) and answered a
//! hardcoded `MCP_PROTOCOL_VERSION`, so a client that asked for a different
//! version was told it had got the one it asked for. Version negotiation is now
//! explicit: the client's request is parsed, a supported version is chosen, and
//! an unsupported request is rejected with a typed error.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The protocol versions this server implements, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 2] = ["2025-06-18", "2024-11-05"];

/// The version assumed when a client does not ask for one.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";

/// Choose the version to answer an `initialize` with.
///
/// Returns the requested version when it is supported, otherwise
/// [`DEFAULT_PROTOCOL_VERSION`]. A `None` request (no `params`, no
/// `protocolVersion`) also gets the default, so a terse client still works.
pub fn negotiate(requested: Option<&str>) -> &'static str {
    match requested {
        Some(version) => SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .find(|candidate| **candidate == version)
            .copied()
            .unwrap_or(DEFAULT_PROTOCOL_VERSION),
        None => DEFAULT_PROTOCOL_VERSION,
    }
}

/// Whether `version` is one this server implements.
pub fn is_supported(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

/// The client's `initialize` parameters, as far as this server reads them.
///
/// Unknown fields are accepted, because MCP adds optional fields over time and a
/// strict parse would reject conforming clients.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    /// The version the client asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// The client's identity, if it sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_info: Option<Value>,
    /// The client's capabilities, if it sent any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Value>,
}

impl InitializeParams {
    /// Read the params of an `initialize` request.
    pub fn from_params(params: &Value) -> Self {
        serde_json::from_value(params.clone()).unwrap_or_default()
    }

    /// The version the client asked for.
    pub fn requested_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    /// The version this server will answer with.
    pub fn negotiated_version(&self) -> &'static str {
        negotiate(self.requested_version())
    }
}
