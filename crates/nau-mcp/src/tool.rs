//! Tool definitions: **one** declaration drives the JSON Schema, the argument
//! validation and the dispatch.
//!
//! ## What changed from upstream v2.5.6
//!
//! Upstream kept the schema and the dispatch as two hand-maintained lists
//! (`gsn-core/src/mcp/market_tools.rs`: `tool_definitions()` built the schema,
//! and a separate `call()` matched on the name and read every argument with
//! `.unwrap_or(0.0)` / `.unwrap_or("")` / `.unwrap_or(false)`). The result was
//! that the schema was decorative: `market_deposit` with `amount: "lots"`
//! silently deposited **0**, and a missing required argument silently became its
//! default. Here a tool is a [`ToolDefinition`] carrying its parameter list *and*
//! its handler, the schema is derived from that list, and arguments are
//! validated against it before the handler runs.

use std::sync::Arc;

use nau_core::{NauError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// The declared type of a tool parameter.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamType {
    /// A JSON string.
    String,
    /// A JSON integer: a number with no fractional part.
    Integer,
    /// A JSON number, fractional part allowed.
    ///
    /// Accepting a JSON number here is not the same as computing with `f64`: a
    /// handler that needs exact arithmetic must take [`ParamType::String`] and
    /// parse a decimal, the way `nau_core::Money` does.
    Number,
    /// A JSON boolean.
    Boolean,
    /// A JSON array.
    Array,
    /// A JSON object.
    Object,
}

impl ParamType {
    /// The JSON Schema `type` keyword for this parameter type.
    pub const fn schema_type(self) -> &'static str {
        match self {
            ParamType::String => "string",
            ParamType::Integer => "integer",
            ParamType::Number => "number",
            ParamType::Boolean => "boolean",
            ParamType::Array => "array",
            ParamType::Object => "object",
        }
    }

    /// A short human-readable name, used in validation messages.
    pub const fn label(self) -> &'static str {
        self.schema_type()
    }

    /// Whether `value` satisfies this type.
    pub fn accepts(self, value: &Value) -> bool {
        match self {
            ParamType::String => value.is_string(),
            ParamType::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
            ParamType::Number => value.is_number(),
            ParamType::Boolean => value.is_boolean(),
            ParamType::Array => value.is_array(),
            ParamType::Object => value.is_object(),
        }
    }

    /// Describe what `value` actually is, for an error message.
    pub fn describe(value: &Value) -> &'static str {
        match value {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(number) => {
                if number.is_f64() {
                    "a fractional number"
                } else {
                    "an integer"
                }
            }
            Value::String(_) => "a string",
            Value::Array(_) => "an array",
            Value::Object(_) => "an object",
        }
    }
}

/// One declared parameter of a tool.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ParamSpec {
    /// Parameter name, as it appears in `arguments`.
    pub name: &'static str,
    /// Declared type.
    pub ty: ParamType,
    /// Whether the parameter must be present.
    pub required: bool,
    /// Human-readable description, published in the schema.
    pub description: &'static str,
}

impl ParamSpec {
    /// A required parameter.
    pub const fn required(name: &'static str, ty: ParamType, description: &'static str) -> Self {
        Self {
            name,
            ty,
            required: true,
            description,
        }
    }

    /// An optional parameter.
    pub const fn optional(name: &'static str, ty: ParamType, description: &'static str) -> Self {
        Self {
            name,
            ty,
            required: false,
            description,
        }
    }
}

/// The result of a successful handler invocation.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ToolOutcome {
    /// Text content returned to the model.
    pub text: String,
    /// Whether this outcome reports a tool-level failure.
    pub is_error: bool,
    /// Optional machine-readable payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
}

impl ToolOutcome {
    /// A successful outcome.
    pub fn ok(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
            structured: None,
        }
    }

    /// A failed outcome, reported inside a normal `tools/call` result.
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
            structured: None,
        }
    }

    /// Attach a structured payload.
    pub fn with_structured(mut self, value: Value) -> Self {
        self.structured = Some(value);
        self
    }

    /// The MCP result object: `{ "content": [...], "isError": bool }`.
    ///
    /// upstream v2.5.6 fix: upstream's `ToolResult` serialized `is_error`, not
    /// the MCP `isError`, so a conforming client saw every tool failure as a
    /// success with a text block.
    pub fn to_mcp_result(&self) -> Value {
        let mut result = json!({
            "content": [{ "type": "text", "text": self.text }],
            "isError": self.is_error,
        });
        if let (Some(structured), Some(object)) = (&self.structured, result.as_object_mut()) {
            object.insert("structuredContent".to_string(), structured.clone());
        }
        result
    }
}

/// A synchronous, fallible tool handler. It must not panic.
pub type ToolHandler = Arc<dyn Fn(&Value) -> Result<ToolOutcome> + Send + Sync>;

/// The single definition of a tool.
///
/// `name`, `description`, `params` and `handler` are one record, so the schema
/// cannot describe a tool that dispatch does not implement, and dispatch cannot
/// accept an argument the schema does not declare.
#[derive(Clone)]
pub struct ToolDefinition {
    /// Tool name, as used by `tools/call`.
    pub name: &'static str,
    /// Description published in `tools/list`.
    pub description: &'static str,
    /// Declared parameters.
    pub params: Vec<ParamSpec>,
    /// The handler.
    pub handler: ToolHandler,
}

impl std::fmt::Debug for ToolDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolDefinition")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl ToolDefinition {
    /// Define a tool from its declared parameters and its handler.
    pub fn new(
        name: &'static str,
        description: &'static str,
        params: Vec<ParamSpec>,
        handler: ToolHandler,
    ) -> Self {
        Self {
            name,
            description,
            params,
            handler,
        }
    }

    /// Define a tool with no parameters.
    pub fn no_params(name: &'static str, description: &'static str, handler: ToolHandler) -> Self {
        Self::new(name, description, Vec::new(), handler)
    }

    /// The JSON Schema, **derived** from `params`.
    pub fn input_schema(&self) -> Value {
        let mut properties = Map::new();
        let mut required: Vec<Value> = Vec::new();
        for param in &self.params {
            properties.insert(
                param.name.to_string(),
                json!({
                    "type": param.ty.schema_type(),
                    "description": param.description,
                }),
            );
            if param.required {
                required.push(Value::String(param.name.to_string()));
            }
        }
        json!({
            "type": "object",
            "properties": Value::Object(properties),
            "required": Value::Array(required),
            "additionalProperties": false,
        })
    }

    /// Validate `arguments` against the declared parameters.
    ///
    /// Every problem is collected, so one call reports all of them. Errors are
    /// [`NauError::Validation`], and the message lists the offending parameter
    /// names, which is what the server turns into `-32602` and what a model needs
    /// in order to correct itself.
    pub fn validate_arguments(&self, arguments: &Value) -> Result<()> {
        let mut problems: Vec<String> = Vec::new();

        let object = match arguments {
            Value::Object(object) => Some(object),
            // `null` means "no arguments supplied". A tool that declares required
            // parameters must therefore fail, so the loop below still runs and
            // reports each of them as missing; a tool with none stays callable
            // with no arguments at all.
            Value::Null => None,
            other => {
                problems.push(format!(
                    "arguments must be an object, got {}",
                    ParamType::describe(other)
                ));
                None
            }
        };

        for param in &self.params {
            match object.and_then(|object| object.get(param.name)) {
                None => {
                    if param.required {
                        problems.push(format!("missing required parameter `{}`", param.name));
                    }
                }
                Some(Value::Null) => {
                    if param.required {
                        problems.push(format!(
                            "parameter `{}` is null, but it is required",
                            param.name
                        ));
                    }
                }
                Some(value) => {
                    if !param.ty.accepts(value) {
                        problems.push(format!(
                            "parameter `{}` must be {}, got {}",
                            param.name,
                            param.ty.label(),
                            ParamType::describe(value)
                        ));
                    }
                }
            }
        }
        // Unknown arguments are refused rather than ignored: silently
        // dropping an argument is how a caller ends up believing it passed
        // `amount` when the server never looked at it.
        if let Some(object) = object {
            for key in object.keys() {
                if !self.params.iter().any(|param| param.name == key) {
                    problems.push(format!("unknown parameter `{key}`"));
                }
            }
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(NauError::Validation(format!(
                "invalid arguments for tool `{}`: {}",
                self.name,
                problems.join("; ")
            )))
        }
    }

    /// Validate `arguments`, then invoke the handler.
    ///
    /// A handler that fails or panics is caught here: `Err` becomes
    /// [`ToolOutcome::error`], so the server can answer `isError: true` instead
    /// of aborting the session.
    pub fn call(&self, arguments: &Value) -> ToolOutcome {
        match self.validate_arguments(arguments) {
            Ok(()) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                (self.handler)(arguments)
            })) {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(error)) => ToolOutcome::error(error.to_string()),
                Err(_) => ToolOutcome::error(format!(
                    "tool `{}` failed internally; the session is unaffected",
                    self.name
                )),
            },
            Err(error) => ToolOutcome::error(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_handler(arguments: &Value) -> Result<ToolOutcome> {
        Ok(ToolOutcome::ok(arguments.to_string()))
    }

    fn tool() -> ToolDefinition {
        ToolDefinition::new(
            "demo",
            "a demo tool",
            vec![
                ParamSpec::required("account", ParamType::String, "the account"),
                ParamSpec::required("amount", ParamType::Integer, "the amount"),
                ParamSpec::optional("note", ParamType::String, "an optional note"),
            ],
            Arc::new(echo_handler),
        )
    }

    #[test]
    fn a_missing_required_parameter_is_named_in_the_error() {
        let err = tool()
            .validate_arguments(&json!({ "account": "did:nau:34750f98bd59fcfc" }))
            .unwrap_err();
        assert!(err.to_string().contains("amount"), "got {err}");
    }

    #[test]
    fn a_wrong_typed_parameter_is_named_in_the_error() {
        let err = tool()
            .validate_arguments(&json!({
                "account": "did:nau:34750f98bd59fcfc",
                "amount": "lots"
            }))
            .unwrap_err();
        assert!(err.to_string().contains("amount"), "got {err}");
        assert!(err.to_string().contains("integer"), "got {err}");
    }

    #[test]
    fn an_unknown_parameter_is_refused() {
        let err = tool()
            .validate_arguments(&json!({
                "account": "a",
                "amount": 1,
                "approvals": 3
            }))
            .unwrap_err();
        assert!(err.to_string().contains("approvals"), "got {err}");
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let err = tool()
            .validate_arguments(&json!({ "amount": "lots" }))
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("account"), "got {message}");
        assert!(message.contains("amount"), "got {message}");
    }

    #[test]
    fn a_valid_call_reaches_the_handler() {
        let outcome = tool().call(&json!({ "account": "a", "amount": 5 }));
        assert!(!outcome.is_error);
        assert!(outcome.text.contains("\"amount\":5"));
    }

    #[test]
    fn a_missing_arguments_object_is_refused_for_a_tool_that_needs_one() {
        assert!(tool().validate_arguments(&Value::Null).is_err());
        assert!(tool().validate_arguments(&json!([])).is_err());
    }

    #[test]
    fn a_failing_handler_becomes_a_tool_error_not_a_panic() {
        let failing = ToolDefinition::new(
            "boom",
            "always fails",
            Vec::new(),
            Arc::new(|_| Err(NauError::Validation("nope".into()))),
        );
        let outcome = failing.call(&json!({}));
        assert!(outcome.is_error);
        assert!(outcome.text.contains("nope"));
    }

    #[test]
    fn a_panicking_handler_is_contained() {
        let panicking = ToolDefinition::new(
            "panics",
            "panics inside",
            Vec::new(),
            Arc::new(|_| panic!("handler exploded")),
        );
        let outcome = panicking.call(&json!({}));
        assert!(outcome.is_error);
        assert!(outcome.text.contains("panics"));
    }

    #[test]
    fn the_schema_is_derived_from_the_declared_parameters() {
        let schema = tool().input_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["account"]["type"], "string");
        assert_eq!(schema["properties"]["amount"]["type"], "integer");
        assert_eq!(schema["required"], json!(["account", "amount"]));
        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["properties"]["note"].is_object());
    }

    #[test]
    fn the_mcp_result_uses_the_camel_case_key() {
        let value = ToolOutcome::ok("fine").to_mcp_result();
        assert_eq!(value["isError"], Value::Bool(false));
        assert_eq!(value["content"][0]["type"], "text");
        assert_eq!(value["content"][0]["text"], "fine");
        let value = ToolOutcome::error("bad").to_mcp_result();
        assert_eq!(value["isError"], Value::Bool(true));
    }

    #[test]
    fn param_types_accept_exactly_what_they_declare() {
        assert!(ParamType::String.accepts(&json!("x")));
        assert!(!ParamType::String.accepts(&json!(1)));
        assert!(ParamType::Integer.accepts(&json!(1)));
        assert!(!ParamType::Integer.accepts(&json!(1.5)));
        assert!(ParamType::Number.accepts(&json!(1.5)));
        assert!(ParamType::Number.accepts(&json!(1)));
        assert!(ParamType::Boolean.accepts(&json!(true)));
        assert!(ParamType::Array.accepts(&json!([])));
        assert!(ParamType::Object.accepts(&json!({})));
        assert!(!ParamType::Object.accepts(&json!([])));
        assert_eq!(ParamType::describe(&json!(1.5)), "a fractional number");
    }
}
