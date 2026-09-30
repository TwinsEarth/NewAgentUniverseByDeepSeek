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
//!
//! ## What changed from upstream v2.8.2
//!
//! upstream v2.8.2 fix (finding 5): upstream *has* a `validate_arguments`, it is
//! unit-tested, and it is **not on the live path** — `tool.rs:165-201` is called
//! only by `server.rs:202`, and `McpServer` has zero production call sites, while
//! both live transports call the tool bridges directly. Validation was therefore
//! a check a future caller could forget, and did.
//!
//! Three doors are closed here, and each is a *type*, not a check:
//!
//! 1. [`ToolDefinition::handler`] is **private**. The only way to run a handler is
//!    [`ToolDefinition::call`], which validates first. A transport cannot reach
//!    past the gate even by accident, because the gate is the only public entry.
//! 2. A handler receives [`Args`], not `&Value`. [`Args`] has **no public
//!    constructor** and can only be produced by [`ToolDefinition::call`] after
//!    validation succeeded, so `args.required_i64("amount_minor")` cannot observe
//!    a missing or mistyped amount: it is a `Result`, and `?` propagates a
//!    refusal. There is no `unwrap_or_zero` to reach for.
//! 3. Every tool declares its [`ToolEffect`], so the single dispatch point can
//!    refuse a mutating tool for a caller without the `write` scope before any
//!    handler runs (see [`crate::auth`] and [`crate::server::McpServer::dispatch`]).

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
    /// parse a decimal, the way `nau_core::Money` does. A **non-finite** number
    /// is refused (see [`ParamType::accepts`]), so nothing downstream can order
    /// or compare a `NaN`.
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
    ///
    /// upstream v2.8.2 fix (finding 4): a [`ParamType::Number`] accepts only a
    /// **finite** number. Upstream orders caller-supplied `f64` weights with
    /// `partial_cmp(..).unwrap()` (`hetero_llm.rs:68,100`), so a `NaN` anywhere
    /// upstream is a panic; the same discipline this project already applies to
    /// the money path is applied here to every externally supplied float. (In
    /// practice `serde_json` cannot represent a non-finite number at all — see the
    /// domain test in `tests/transports.rs` — so this is the second lock on the
    /// same door, and it is the one a future encoder cannot bypass.)
    pub fn accepts(self, value: &Value) -> bool {
        match self {
            ParamType::String => value.is_string(),
            ParamType::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
            ParamType::Number => value.as_f64().is_some_and(f64::is_finite),
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
                if !number.is_f64() {
                    "an integer"
                } else if number.as_f64().is_some_and(f64::is_finite) {
                    "a fractional number"
                } else {
                    "a non-finite number, which is refused"
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
    /// Smallest accepted value, for an integer parameter.
    ///
    /// upstream v2.8.2 fix (finding 5): an amount was read with a numeric
    /// fallback, so a malformed amount became *zero* and the call reported
    /// success. A declared minimum is published in the JSON Schema **and**
    /// enforced by [`ToolDefinition::validate_arguments`], so
    /// `{"amount_minor": 0}` or a negative amount is refused before any handler
    /// runs instead of being quietly credited.
    pub minimum: Option<i64>,
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
            minimum: None,
            description,
        }
    }

    /// An optional parameter.
    pub const fn optional(name: &'static str, ty: ParamType, description: &'static str) -> Self {
        Self {
            name,
            ty,
            required: false,
            minimum: None,
            description,
        }
    }

    /// A required integer parameter with a minimum.
    ///
    /// The type is fixed to [`ParamType::Integer`] on purpose: a minimum is only
    /// meaningful for an ordered scalar, and an amount that could be a float is
    /// the defect this exists to remove.
    pub const fn required_integer_at_least(
        name: &'static str,
        minimum: i64,
        description: &'static str,
    ) -> Self {
        Self {
            name,
            ty: ParamType::Integer,
            required: true,
            minimum: Some(minimum),
            description,
        }
    }

    /// An optional integer parameter that, when present, must be at least
    /// `minimum`.
    ///
    /// Absent stays legitimate — an optional stake or price is a default the
    /// market owns — but a *present* value outside the bound is refused rather
    /// than clamped or silently dropped.
    pub const fn optional_integer_at_least(
        name: &'static str,
        minimum: i64,
        description: &'static str,
    ) -> Self {
        Self {
            name,
            ty: ParamType::Integer,
            required: false,
            minimum: Some(minimum),
            description,
        }
    }
}

/// What a tool does to the world.
///
/// Declared once, at the definition, and used by the single dispatch point to
/// decide whether a caller must be authenticated. A tool that mutates but
/// declares [`ToolEffect::ReadOnly`] is a bug the tests can catch
/// (`tests/transports.rs` asserts the effect of every market tool by name).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolEffect {
    /// Reads state; safe for any caller and for a model to retry freely.
    ReadOnly,
    /// Mutates state; requires a caller with the `write` scope.
    Mutating,
}

impl ToolEffect {
    /// Whether this effect requires an authenticated caller with the write scope.
    pub const fn requires_write_scope(self) -> bool {
        matches!(self, ToolEffect::Mutating)
    }
}

/// Which argument names the DID a call acts on, so per-caller ownership is
/// expressible instead of implied by a shared secret.
///
/// upstream v2.8.2 fix (finding 6): upstream's MCP surface authenticates 15
/// mutating tools with one shared secret and knows nothing about *who* is
/// calling, so no rule of the form "you may only act on your own account" can be
/// written. A spec is part of the tool's one declaration — deliberately not a
/// second table keyed by name, which is the upstream anti-pattern this crate
/// exists to remove.
///
/// When the caller's principal declares a DID, the argument named here must equal
/// it (see [`crate::server::McpServer::dispatch`]); a principal with no DID is a
/// service credential and is not bound.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnershipSpec {
    /// The top-level argument that holds the acting object.
    pub param: &'static str,
    /// The path inside that argument to the DID, empty when it *is* the DID.
    pub path: &'static [&'static str],
}

impl OwnershipSpec {
    /// The argument *is* the acting DID, e.g. `market_deposit`'s `account`.
    pub const fn top_level(param: &'static str) -> Self {
        Self { param, path: &[] }
    }

    /// The acting DID lives inside an object argument, e.g. `bid.bidder`.
    pub const fn nested(param: &'static str, path: &'static [&'static str]) -> Self {
        Self { param, path }
    }

    /// The DID this call claims to act as, when the argument chain resolves to a
    /// string.
    pub fn owner<'a>(&self, arguments: &'a Value) -> Option<&'a str> {
        let mut value = arguments.get(self.param)?;
        for step in self.path {
            value = value.get(*step)?;
        }
        value.as_str()
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

/// The arguments of a call that has **already** passed validation.
///
/// upstream v2.8.2 fix (finding 5): this type is the structural half of the fix
/// for the bypassed validator. It has no public constructor, so a transport
/// cannot manufacture one, and every accessor is fallible, so a handler cannot
/// read a missing argument as a default. The upstream shape — a handler that
/// receives the raw [`Value`] and calls `.unwrap_or(0.0)` on it — is not
/// expressible against this type.
#[derive(Clone, Debug)]
pub struct Args {
    arguments: Value,
}

impl Args {
    /// Wrap validated arguments.
    ///
    /// Private to this module on purpose: [`ToolDefinition::call`] is the only
    /// caller, and it calls this **after** `validate_arguments` has succeeded.
    fn validated(arguments: Value) -> Self {
        Self { arguments }
    }

    /// The raw argument object, for a handler that must forward it wholesale.
    ///
    /// Reading through the accessors below is preferred; this exists for the
    /// market bridge, which forwards a sub-object to a dispatcher that validates
    /// it again.
    pub fn raw(&self) -> &Value {
        &self.arguments
    }

    /// A required value, whatever its type.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] naming the parameter. It cannot be absent on a
    /// validated [`Args`], so this is unreachable in practice — which is exactly
    /// the point: the signature tells a handler author that reading an argument
    /// can fail, so there is no reason to invent a default.
    pub fn required(&self, name: &str) -> Result<&Value> {
        self.arguments
            .get(name)
            .filter(|value| !value.is_null())
            .ok_or_else(|| NauError::Validation(format!("required argument `{name}` is absent")))
    }

    /// An optional value, if it is present and not `null`.
    pub fn optional(&self, name: &str) -> Option<&Value> {
        self.arguments.get(name).filter(|value| !value.is_null())
    }

    /// A required string argument.
    pub fn required_str(&self, name: &str) -> Result<&str> {
        self.required(name)?
            .as_str()
            .ok_or_else(|| NauError::Validation(format!("argument `{name}` is not a string")))
    }

    /// A required integer argument.
    pub fn required_i64(&self, name: &str) -> Result<i64> {
        let value = self.required(name)?;
        value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
            .ok_or_else(|| NauError::Validation(format!("argument `{name}` is not an integer")))
    }

    /// A required array argument.
    pub fn required_array(&self, name: &str) -> Result<&Vec<Value>> {
        self.required(name)?
            .as_array()
            .ok_or_else(|| NauError::Validation(format!("argument `{name}` is not an array")))
    }

    /// A required object argument.
    pub fn required_object(&self, name: &str) -> Result<&Map<String, Value>> {
        self.required(name)?
            .as_object()
            .ok_or_else(|| NauError::Validation(format!("argument `{name}` is not an object")))
    }
}

/// A synchronous, fallible tool handler. It receives **validated** arguments and
/// must not panic.
pub type ToolHandler = Arc<dyn Fn(&Args) -> Result<ToolOutcome> + Send + Sync>;

/// The single definition of a tool.
///
/// `name`, `description`, `params`, `effect` and `handler` are one record, so the
/// schema cannot describe a tool that dispatch does not implement, and dispatch
/// cannot accept an argument the schema does not declare. `handler` is private:
/// see the module documentation.
#[derive(Clone)]
pub struct ToolDefinition {
    /// Tool name, as used by `tools/call`.
    pub name: &'static str,
    /// Description published in `tools/list`.
    pub description: &'static str,
    /// Declared parameters.
    pub params: Vec<ParamSpec>,
    /// Whether the tool mutates state.
    pub effect: ToolEffect,
    /// The argument that names the DID this tool acts on, if any.
    ///
    /// See [`OwnershipSpec`]: declaration, not a separate table, so it cannot
    /// drift away from the tool it belongs to.
    pub ownership: Option<OwnershipSpec>,
    /// The handler.
    ///
    /// Private on purpose: [`ToolDefinition::call`] is the only way to reach it,
    /// and it validates and authorizes first.
    handler: ToolHandler,
}

impl std::fmt::Debug for ToolDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolDefinition")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("params", &self.params)
            .field("effect", &self.effect)
            .field("ownership", &self.ownership)
            .finish_non_exhaustive()
    }
}

impl ToolDefinition {
    /// Define a read-only tool from its declared parameters and its handler.
    pub fn read_only(
        name: &'static str,
        description: &'static str,
        params: Vec<ParamSpec>,
        handler: ToolHandler,
    ) -> Self {
        Self::new(name, description, ToolEffect::ReadOnly, params, handler)
    }

    /// Define a mutating tool from its declared parameters and its handler.
    pub fn mutating(
        name: &'static str,
        description: &'static str,
        params: Vec<ParamSpec>,
        handler: ToolHandler,
    ) -> Self {
        Self::new(name, description, ToolEffect::Mutating, params, handler)
    }

    /// Define a tool from its name, effect, declared parameters and handler.
    pub fn new(
        name: &'static str,
        description: &'static str,
        effect: ToolEffect,
        params: Vec<ParamSpec>,
        handler: ToolHandler,
    ) -> Self {
        Self {
            name,
            description,
            params,
            effect,
            ownership: None,
            handler,
        }
    }

    /// Declare which argument names the DID this tool acts on.
    pub fn with_ownership(mut self, ownership: OwnershipSpec) -> Self {
        self.ownership = Some(ownership);
        self
    }

    /// The ownership binding, if the tool has one.
    pub fn ownership(&self) -> Option<OwnershipSpec> {
        self.ownership
    }

    /// Whether the tool mutates state.
    pub fn effect(&self) -> ToolEffect {
        self.effect
    }

    /// The JSON Schema, **derived** from `params`.
    pub fn input_schema(&self) -> Value {
        let mut properties = Map::new();
        let mut required: Vec<Value> = Vec::new();
        for param in &self.params {
            let mut property = json!({
                "type": param.ty.schema_type(),
                "description": param.description,
            });
            if let (Some(minimum), Some(object)) = (param.minimum, property.as_object_mut()) {
                // The bound travels with the schema, so a model that reads
                // `tools/list` can see the rule the server will enforce.
                object.insert("minimum".to_string(), json!(minimum));
            }
            properties.insert(param.name.to_string(), property);
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
    /// names, which is what the server turns into a refusal the model can read
    /// and correct.
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
                    } else if let Some(minimum) = param.minimum {
                        // upstream v2.8.2 fix (finding 5): the amount bounds are
                        // enforced here, on the live path, before any handler can
                        // turn a malformed or zero amount into a successful call.
                        match value.as_i64() {
                            Some(actual) if actual < minimum => problems.push(format!(
                                "parameter `{}` must be at least {minimum}, got {actual}",
                                param.name
                            )),
                            _ => {}
                        }
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

    /// Validate `arguments`, then invoke the handler with the validated
    /// [`Args`].
    ///
    /// A handler that fails or panics is caught here: `Err` becomes
    /// [`ToolOutcome::error`], so the server can answer `isError: true` instead
    /// of aborting the session.
    ///
    /// This is the **only** way to run the handler: the field is private and this
    /// method validates first, so no transport can reach past validation.
    pub fn call(&self, arguments: &Value) -> ToolOutcome {
        match self.validate_arguments(arguments) {
            Ok(()) => {
                let validated = Args::validated(arguments.clone());
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    (self.handler)(&validated)
                })) {
                    Ok(Ok(outcome)) => outcome,
                    Ok(Err(error)) => ToolOutcome::error(error.to_string()),
                    Err(_) => ToolOutcome::error(format!(
                        "tool `{}` failed internally; the session is unaffected",
                        self.name
                    )),
                }
            }
            Err(error) => ToolOutcome::error(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_handler(arguments: &Args) -> Result<ToolOutcome> {
        Ok(ToolOutcome::ok(arguments.raw().to_string()))
    }

    fn tool() -> ToolDefinition {
        ToolDefinition::read_only(
            "demo",
            "a demo tool",
            vec![
                ParamSpec::required("account", ParamType::String, "the account"),
                ParamSpec::required_integer_at_least("amount", 1, "the amount, at least 1"),
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
    fn a_declared_minimum_is_enforced_before_the_handler_runs() {
        // upstream v2.8.2 fix (finding 5): `{"amount": 0}` used to be a
        // successful no-op deposit. It is now refused by name, and the handler is
        // never reached.
        for bad in [json!(0), json!(-1), json!(-1_000_000)] {
            let outcome = tool().call(&json!({ "account": "a", "amount": bad }));
            assert!(outcome.is_error, "amount {bad} must be refused");
            assert!(outcome.text.contains("at least 1"), "{}", outcome.text);
        }
        let outcome = tool().call(&json!({ "account": "a", "amount": 1 }));
        assert!(!outcome.is_error);
    }

    #[test]
    fn a_failing_handler_becomes_a_tool_error_not_a_panic() {
        let failing = ToolDefinition::read_only(
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
        let panicking = ToolDefinition::read_only(
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
    fn a_handler_that_requires_an_absent_argument_fails_instead_of_defaulting() {
        // The structural half of finding 5: `Args` accessors are fallible, so a
        // handler cannot inherit upstream's `.unwrap_or(0.0)`. This handler is
        // declared with no parameters, so its `required_i64` must fail.
        let greedy = ToolDefinition::read_only(
            "greedy",
            "reads an argument it did not declare",
            Vec::new(),
            Arc::new(|args: &Args| {
                let amount = args.required_i64("amount_minor")?;
                Ok(ToolOutcome::ok(format!("{amount}")))
            }),
        );
        let outcome = greedy.call(&json!({}));
        assert!(outcome.is_error);
        assert!(
            outcome.text.contains("amount_minor"),
            "the refusal must name the argument: {}",
            outcome.text
        );
    }

    #[test]
    fn the_schema_is_derived_from_the_declared_parameters() {
        let schema = tool().input_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["account"]["type"], "string");
        assert_eq!(schema["properties"]["amount"]["type"], "integer");
        assert_eq!(schema["properties"]["amount"]["minimum"], json!(1));
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
        // Non-finite floats are refused by the type itself (finding 4).
        assert!(!ParamType::Number.accepts(&Value::Null));
        assert_eq!(
            ParamType::describe(&json!("NaN")),
            "a string",
            "the JSON literal `NaN` is not a number, it is a string"
        );
    }

    #[test]
    fn a_mutating_tool_says_so() {
        assert!(!tool().effect().requires_write_scope());
        let writer = ToolDefinition::mutating("w", "writes", Vec::new(), Arc::new(echo_handler));
        assert!(writer.effect().requires_write_scope());
    }
}
