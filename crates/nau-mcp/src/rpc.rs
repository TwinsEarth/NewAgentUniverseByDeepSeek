//! JSON-RPC 2.0 wire types, error codes and their MCP wire shapes.
//!
//! ## What changed from upstream v2.5.6
//!
//! * **`id: null` was unrepresentable.** Upstream's `RequestId` had only
//!   `Number` and `String` variants, so a parse-error response — which JSON-RPC
//!   requires to carry `id: null` — could not be expressed, and upstream sent
//!   `id: 0` instead, which collides with the legitimate request id `0`.
//!   [`RequestId::Null`] fixes that, and it is the *default* for a request that
//!   omits `id`.
//! * **A request could not be parsed without an `id`.** Upstream's `McpRequest`
//!   required `id`, so a JSON-RPC notification failed to deserialize and was
//!   reported as an invalid request. [`RpcRequest`] defaults `id` to
//!   [`RequestId::Null`], which is how a notification is recognised.
//! * **Capability structs serialized `list_changed`.** See [`crate::capability`].

use std::fmt;

use serde::de::{self, Unexpected};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// The JSON-RPC version literal every message must carry.
pub const JSONRPC_VERSION: &str = "2.0";

/// The JSON-RPC 2.0 error codes, plus the MCP extension this crate uses.
pub mod error_code {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: i32 = -32700;
    /// The JSON was valid but was not a valid Request object.
    pub const INVALID_REQUEST: i32 = -32600;
    /// The method does not exist or is not available.
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// The method's parameters are wrong.
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i32 = -32603;
    /// MCP: a request other than `initialize` arrived before `initialize`.
    pub const NOT_INITIALIZED: i32 = -32002;
}

/// A JSON-RPC request id.
///
/// JSON-RPC 2.0 allows a string, a number, or `null`; `null` is required on the
/// response to a request that could not be parsed.
///
/// The default is `Null`: a request without an `id` is a notification, which is
/// exactly what `null` means here. Expressed with `#[default]` on the variant
/// rather than a hand-written `Default` impl.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum RequestId {
    /// The `null` id: used for unparseable requests and for notifications.
    #[default]
    Null,
    /// A numeric id.
    Number(u64),
    /// A string id.
    String(String),
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestId::Null => f.write_str("null"),
            RequestId::Number(value) => write!(f, "{value}"),
            RequestId::String(value) => write!(f, "\"{value}\""),
        }
    }
}

impl RequestId {
    /// True for [`RequestId::Null`], i.e. a notification or an unparseable
    /// request.
    pub fn is_null(&self) -> bool {
        matches!(self, RequestId::Null)
    }
}

impl Serialize for RequestId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RequestId::Null => serializer.serialize_unit(),
            RequestId::Number(value) => serializer.serialize_u64(*value),
            RequestId::String(value) => serializer.serialize_str(value),
        }
    }
}

/// Deserialize a JSON-RPC `id`, where `null` is a real value rather than a
/// missing field.
///
/// A derived `#[serde(untagged)]` implementation cannot do this: `Value::Null`
/// fails every variant except a unit variant, and the derive does not fall back
/// to one. So the deserializer is written out explicitly.
impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The `id` may legitimately be `null`, so the value is read through
        // `serde_json::Value`: this is the only way to see a bare `null` as a
        // value rather than as an absent field.
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Null => Ok(RequestId::Null),
            Value::Number(number) => match number.as_u64() {
                Some(value) => Ok(RequestId::Number(value)),
                None => Err(de::Error::invalid_value(
                    Unexpected::Other("non-integer or negative number"),
                    &"a string, a non-negative integer, or null",
                )),
            },
            Value::String(value) => Ok(RequestId::String(value)),
            other => Err(de::Error::invalid_type(
                Unexpected::Other(describe(&other)),
                &"a string, a non-negative integer, or null",
            )),
        }
    }
}

fn describe(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// A JSON-RPC request (or notification).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The request id; [`RequestId::Null`] means "notification".
    #[serde(default)]
    pub id: RequestId,
    /// The method name.
    pub method: String,
    /// Method parameters.
    #[serde(default)]
    pub params: Value,
}

impl RpcRequest {
    /// A request with the standard `jsonrpc` literal.
    pub fn new(id: RequestId, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: method.into(),
            params,
        }
    }

    /// True when this is a notification: no `id`, so no response is expected.
    pub fn is_notification(&self) -> bool {
        self.id.is_null()
    }

    /// True when the `jsonrpc` field is exactly `"2.0"`.
    pub fn has_valid_version(&self) -> bool {
        self.jsonrpc == JSONRPC_VERSION
    }
}

/// A JSON-RPC error object.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RpcError {
    /// One of [`error_code`].
    pub code: i32,
    /// Human-readable message.
    pub message: String,
    /// Optional structured detail (e.g. the list of offending parameters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC response: exactly one of `result` or `error`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Echoes the request id, or `null` if it could not be read.
    pub id: RequestId,
    /// Present on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Present on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    /// A success response.
    pub fn ok(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// An error response without structured detail.
    pub fn err(id: RequestId, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// An error response carrying structured detail.
    pub fn err_with_data(
        id: RequestId,
        code: i32,
        message: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
        }
    }

    /// True when this response carries a result rather than an error.
    pub fn is_success(&self) -> bool {
        self.result.is_some() && self.error.is_none()
    }
}

/// Parse a single JSON-RPC request from a JSON value.
///
/// Returns [`RequestId::Null`] alongside the error when the id could not be
/// read, so the caller can still answer with a correctly-shaped response.
pub fn parse_request(value: Value) -> Result<RpcRequest, (RequestId, RpcError)> {
    let id = value
        .get("id")
        .map(|raw| serde_json::from_value::<RequestId>(raw.clone()))
        .transpose()
        .ok()
        .flatten()
        .unwrap_or(RequestId::Null);

    if !value.is_object() {
        return Err((
            id,
            RpcError {
                code: error_code::INVALID_REQUEST,
                message: format!(
                    "a JSON-RPC request must be an object, got {}",
                    describe(&value)
                ),
                data: None,
            },
        ));
    }

    serde_json::from_value::<RpcRequest>(value).map_err(|error| {
        (
            id,
            RpcError {
                code: error_code::INVALID_REQUEST,
                message: error.to_string(),
                data: None,
            },
        )
    })
}
