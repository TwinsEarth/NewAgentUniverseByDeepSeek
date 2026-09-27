//! The market tool bridge: the standard market tool surface, wired to a
//! caller-supplied dispatcher.
//!
//! This crate has **no dependency on the market crate**. The market crate owns
//! the async dispatch; it hands this module an opaque
//! `Fn(String, Value) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>>`
//! and gets a registered tool set back.
//!
//! ## What changed from upstream v2.5.6
//!
//! * **Quorum thresholds were caller-supplied.**
//!   `market_verify_result` took `approvals` and `committee_size`, defaulting to
//!   the quorum-satisfying `3` and `4`
//!   (`gsn-core/src/mcp/market_tools.rs`:
//!   `unwrap_or(3)` / `unwrap_or(4)`), so a model that simply omitted both
//!   parameters declared a *successful* BFT verification out of thin air. Those
//!   parameters do not exist here: the tool takes the task id and a JSON array of
//!   signed votes, and the server-side policy decides the quorum from the votes
//!   it can actually validate.
//! * **Every argument was read with a fallback.** `get_f64("amount")` with
//!   `.unwrap_or(0.0)` meant `{"amount": "lots"}` deposited 0. The parameters are
//!   declared once and validated before dispatch, so a wrong type is `-32602`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use nau_core::{NauError, Result};
use serde_json::{json, Map, Value};

use crate::server::McpServer;
use crate::tool::{ParamSpec, ParamType, ToolDefinition, ToolHandler, ToolOutcome};

/// The async dispatcher a bridge is built against.
///
/// The future must be `'static` because it is boxed and polled by the bridge
/// rather than awaited by this crate.
pub type Dispatcher =
    Arc<dyn Fn(String, Value) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>> + Send + Sync>;

/// The standard market tool set.
pub struct MarketToolBridge {
    dispatch: Dispatcher,
}

impl std::fmt::Debug for MarketToolBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarketToolBridge")
            .field("tools", &Self::TOOL_NAMES.len())
            .finish_non_exhaustive()
    }
}

impl MarketToolBridge {
    /// The names of the 16 tools this bridge registers, sorted.
    pub const TOOL_NAMES: [&'static str; 16] = [
        "market_balance",
        "market_deposit",
        "market_discover_agents",
        "market_get_agent",
        "market_get_task",
        "market_open_dispute",
        "market_publish_task",
        "market_record_votes",
        "market_register_agent",
        "market_search_agents",
        "market_settle_task",
        "market_submit_bid",
        "market_submit_result",
        "market_task_vote_quorum",
        "market_validate_votes",
        "market_withdraw",
    ];

    /// Build a bridge against `dispatch`, which receives `(tool name, arguments)`
    /// and returns the market's JSON reply.
    pub fn new(dispatch: Dispatcher) -> Self {
        Self { dispatch }
    }

    /// Register the standard tool set into `server`.
    pub fn register_into(&self, server: &mut McpServer) -> Result<()> {
        for tool in self.tools()? {
            server.register(tool)?;
        }
        Ok(())
    }

    /// The standard tool set, with names sorted.
    ///
    /// `TOOL_NAMES` and the definitions are produced by the same macro
    /// invocation, so the advertised list and the registered tools cannot drift.
    fn tools(&self) -> Result<Vec<ToolDefinition>> {
        let mut tools = vec![
            agent_register(self.dispatch.clone()),
            agent_get(self.dispatch.clone()),
            agent_discover(self.dispatch.clone()),
            agent_search(self.dispatch.clone()),
            task_publish(self.dispatch.clone()),
            task_get(self.dispatch.clone()),
            bid_submit(self.dispatch.clone()),
            task_submit_result(self.dispatch.clone()),
            task_settle(self.dispatch.clone()),
            dispute_open(self.dispatch.clone()),
            account_deposit(self.dispatch.clone()),
            account_withdraw(self.dispatch.clone()),
            account_balance(self.dispatch.clone()),
            // The two server-side-decided tools, which do NOT accept a caller
            // supplied threshold.
            task_fetch_votes(self.dispatch.clone()),
            task_record_votes(self.dispatch.clone()),
            validate_votes_tool(self.dispatch.clone()),
        ];
        tools.sort_by_key(|tool| tool.name);
        debug_assert_eq!(tools.len(), Self::TOOL_NAMES.len());
        Ok(tools)
    }

    /// Register the tool set into a new server of `name`/`version`.
    pub fn register_into_new(
        &self,
        server_name: &'static str,
        server_version: &'static str,
    ) -> Result<McpServer> {
        let mut server = McpServer::new(server_name, server_version);
        self.register_into(&mut server)?;
        Ok(server)
    }
}

/// Wrap a dispatcher call in a [`ToolHandler`].
///
/// The dispatcher is async but tool handlers are synchronous, so the boxed future
/// is driven to completion here with a no-op waker. The dispatcher is expected to
/// do non-blocking work (an in-process market actor); a network client should be
/// driven by its own runtime and registered through a different bridge.
fn handler(
    dispatch: Dispatcher,
    call: impl Fn(&Value) -> (String, Value) + Send + Sync + 'static,
) -> ToolHandler {
    Arc::new(move |arguments: &Value| {
        let (method, payload) = call(arguments);
        let future = dispatch(method.clone(), payload);
        match block_on(future) {
            Ok(value) => Ok(ToolOutcome::ok(render(&value)).with_structured(value)),
            Err(error) => Err(NauError::Validation(format!(
                "market dispatcher rejected `{method}`: {error}"
            ))),
        }
    })
}

/// Render a dispatcher reply as text: compact JSON, or the raw string.
fn render(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<unrenderable>".to_string()),
    }
}

/// A waker that does nothing, for driving a future that never yields.
struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

/// Drive a dispatcher future to completion on the current thread.
///
/// # Errors
///
/// [`NauError::Validation`] if the future is still pending after being polled:
/// a dispatcher used from a synchronous tool handler must complete immediately,
/// because there is no reactor here to wake it. Failing the tool call is the
/// honest response; blocking forever would hang the session.
fn block_on(mut future: Pin<Box<dyn Future<Output = Result<Value>> + Send>>) -> Result<Value> {
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut context = Context::from_waker(&waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => Err(NauError::Validation(
            "the market dispatcher returned a pending future; a synchronous tool handler requires \
             a dispatcher that completes immediately"
                .into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// The tool definitions.
// ---------------------------------------------------------------------------

fn agent_register(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_register_agent",
        "Register an agent with the market. The market validates the DID, stake and price.",
        vec![
            ParamSpec::required("agent_id", ParamType::String, "the agent's DID"),
            ParamSpec::required("name", ParamType::String, "human-facing name"),
            ParamSpec::optional(
                "skills",
                ParamType::Array,
                "skill ids, e.g. [\"translation\"]",
            ),
            ParamSpec::optional(
                "stake_minor",
                ParamType::Integer,
                "stake in integer minor units",
            ),
            ParamSpec::optional(
                "price_minor",
                ParamType::Integer,
                "unit price in integer minor units",
            ),
            ParamSpec::optional("description", ParamType::String, "capability description"),
        ],
        handler(dispatch, |args| {
            ("register_agent".to_string(), args.clone())
        }),
    )
}

fn agent_get(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_get_agent",
        "Fetch one agent card by DID.",
        vec![ParamSpec::required(
            "agent_id",
            ParamType::String,
            "the agent's DID",
        )],
        handler(dispatch, |args| {
            (
                "get_agent".to_string(),
                json!({ "agent_id": string_arg(args, "agent_id") }),
            )
        }),
    )
}

fn agent_discover(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_discover_agents",
        "Discover agents that advertise a skill.",
        vec![ParamSpec::required(
            "skill",
            ParamType::String,
            "skill id, e.g. translation",
        )],
        handler(dispatch, |args| {
            (
                "discover_agents".to_string(),
                json!({ "skill": string_arg(args, "skill") }),
            )
        }),
    )
}

fn agent_search(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_search_agents",
        "Search agents by keyword.",
        vec![ParamSpec::required(
            "query",
            ParamType::String,
            "search keyword",
        )],
        handler(dispatch, |args| {
            (
                "search_agents".to_string(),
                json!({ "query": string_arg(args, "query") }),
            )
        }),
    )
}

fn task_publish(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_publish_task",
        "Publish a task. `task` is the full TaskSpec object, validated by the market.",
        vec![ParamSpec::required(
            "task",
            ParamType::Object,
            "the six-field TaskSpec object plus budget, in integer minor units",
        )],
        handler(dispatch, |args| {
            (
                "publish_task".to_string(),
                json!({ "task": args.get("task").cloned().unwrap_or(Value::Null) }),
            )
        }),
    )
}

fn task_get(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_get_task",
        "Fetch one task by id.",
        vec![ParamSpec::required(
            "task_id",
            ParamType::String,
            "the task id",
        )],
        handler(dispatch, |args| {
            (
                "get_task".to_string(),
                json!({ "task_id": string_arg(args, "task_id") }),
            )
        }),
    )
}

fn bid_submit(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_submit_bid",
        "Submit a signed bid for a task.",
        vec![ParamSpec::required(
            "bid",
            ParamType::Object,
            "the signed Bid object: task_id, bidder, price in integer minor units, eta_secs, nonce, signed_at, signature",
        )],
        handler(dispatch, |args| {
            (
                "submit_bid".to_string(),
                json!({ "bid": args.get("bid").cloned().unwrap_or(Value::Null) }),
            )
        }),
    )
}

fn task_submit_result(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_submit_result",
        "Submit a signed result envelope for a task.",
        vec![ParamSpec::required(
            "envelope",
            ParamType::Object,
            "the signed ResultEnvelope: task_id, agent, output_digest, evidence, nonce, signed_at, signature",
        )],
        handler(dispatch, |args| {
            (
                "submit_result".to_string(),
                json!({ "envelope": args.get("envelope").cloned().unwrap_or(Value::Null) }),
            )
        }),
    )
}

fn task_settle(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_settle_task",
        "Settle an accepted task. The market checks the evidence grade and the deadline itself.",
        vec![ParamSpec::required(
            "task_id",
            ParamType::String,
            "the task id",
        )],
        handler(dispatch, |args| {
            (
                "settle_task".to_string(),
                json!({ "task_id": string_arg(args, "task_id") }),
            )
        }),
    )
}

fn dispute_open(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_open_dispute",
        "Open a dispute. `dispute` is the signed Dispute object.",
        vec![ParamSpec::required(
            "dispute",
            ParamType::Object,
            "the signed Dispute: task_id, complainant, respondent, reason, nonce, signed_at, signature",
        )],
        handler(dispatch, |args| {
            (
                "open_dispute".to_string(),
                json!({ "dispute": args.get("dispute").cloned().unwrap_or(Value::Null) }),
            )
        }),
    )
}

fn account_deposit(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_deposit",
        "Deposit into an account. `amount_minor` is an integer number of minor units.",
        vec![
            ParamSpec::required("account", ParamType::String, "the account DID"),
            ParamSpec::required(
                "amount_minor",
                ParamType::Integer,
                "amount in integer minor units, greater than zero",
            ),
        ],
        handler(dispatch, |args| {
            (
                "deposit".to_string(),
                json!({
                    "account": string_arg(args, "account"),
                    "amount_minor": args.get("amount_minor").cloned().unwrap_or(Value::Null),
                }),
            )
        }),
    )
}

fn account_withdraw(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_withdraw",
        "Withdraw from an account. `amount_minor` is an integer number of minor units.",
        vec![
            ParamSpec::required("account", ParamType::String, "the account DID"),
            ParamSpec::required(
                "amount_minor",
                ParamType::Integer,
                "amount in integer minor units, greater than zero",
            ),
        ],
        handler(dispatch, |args| {
            (
                "withdraw".to_string(),
                json!({
                    "account": string_arg(args, "account"),
                    "amount_minor": args.get("amount_minor").cloned().unwrap_or(Value::Null),
                }),
            )
        }),
    )
}

fn account_balance(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_balance",
        "Read an account balance.",
        vec![ParamSpec::required(
            "account",
            ParamType::String,
            "the account DID",
        )],
        handler(dispatch, |args| {
            (
                "balance".to_string(),
                json!({ "account": string_arg(args, "account") }),
            )
        }),
    )
}

fn task_fetch_votes(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_task_vote_quorum",
        "Read the server-side vote tally for a task: how many valid signed votes have arrived and \
         what quorum the task's own verification policy requires. Takes no caller-supplied counts.",
        vec![ParamSpec::required(
            "task_id",
            ParamType::String,
            "the task id",
        )],
        handler(dispatch, |args| {
            (
                "task_vote_quorum".to_string(),
                json!({ "task_id": string_arg(args, "task_id") }),
            )
        }),
    )
}

fn task_record_votes(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_record_votes",
        "Record signed committee votes for a task. The server validates each vote's shape and \
         decides, from the task's own policy, whether quorum is met. There is intentionally no \
         `approvals` or `committee_size` parameter.",
        vec![
            ParamSpec::required(
                "task_id",
                ParamType::String,
                "the task id the votes are for",
            ),
            ParamSpec::required(
                "votes",
                ParamType::Array,
                "signed votes: [{voter, task_id, approve, nonce, signed_at, signature}, ...]",
            ),
        ],
        handler(dispatch, |args| {
            let task_id = string_arg(args, "task_id");
            let votes = args.get("votes").cloned().unwrap_or(Value::Null);
            // Bind every vote to the task being voted on, and refuse the whole
            // call if any vote is malformed. The count is *observed*, never
            // supplied.
            match validated_votes(&votes, Some(&task_id)) {
                Ok(entries) => (
                    "record_votes".to_string(),
                    json!({ "task_id": task_id, "votes": entries }),
                ),
                Err(error) => (
                    "record_votes".to_string(),
                    json!({ "task_id": task_id, "invalid_votes": error.to_string() }),
                ),
            }
        }),
    )
}

fn validate_votes_tool(dispatch: Dispatcher) -> ToolDefinition {
    ToolDefinition::new(
        "market_validate_votes",
        "Validate the shape of a signed-vote array without recording it. Returns the observed \
         approve/reject counts; it does not accept a caller-supplied threshold.",
        vec![ParamSpec::required(
            "votes",
            ParamType::Array,
            "signed votes: [{voter, task_id, approve, nonce, signed_at, signature}, ...]",
        )],
        handler(dispatch, |args| {
            let votes = args.get("votes").cloned().unwrap_or(Value::Null);
            ("validate_votes".to_string(), json!({ "votes": votes }))
        }),
    )
}

/// Read a declared string parameter. The value is validated before the handler
/// runs, so this is total; a missing value yields an empty string rather than a
/// silent default that looks like real data.
fn string_arg(arguments: &Value, name: &str) -> String {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Validate a JSON array of signed votes and return the observed counts.
///
/// Each entry must be an object carrying `voter` (a string), `task_id` (a
/// string), `approve` (a boolean), `nonce` (an integer), `signed_at` (an
/// integer) and `signature` (a hex string). When `expected_task` is given, every
/// vote must name that task: a vote for a different task is not a vote.
///
/// The *count* of valid votes is what it returns; no threshold is accepted from
/// the caller, which is the point. This is shape validation only — it does not
/// verify the signatures, which the market crate does with the real keys.
pub fn validated_votes(votes: &Value, expected_task: Option<&str>) -> Result<Value> {
    let array = votes
        .as_array()
        .ok_or_else(|| NauError::Validation("`votes` must be an array of vote objects".into()))?;
    if array.is_empty() {
        return Err(NauError::Validation(
            "`votes` must contain at least one signed vote".into(),
        ));
    }
    let mut entries: Vec<Value> = Vec::with_capacity(array.len());
    let mut approve = 0u32;
    let mut reject = 0u32;
    let mut problems: Vec<String> = Vec::new();

    for (index, vote) in array.iter().enumerate() {
        let object: &Map<String, Value> = match vote.as_object() {
            Some(object) => object,
            None => {
                problems.push(format!(
                    "votes[{index}] must be an object, got {}",
                    describe(vote)
                ));
                continue;
            }
        };
        let mut missing: Vec<&str> = Vec::new();
        for field in ["voter", "signature"] {
            if object.get(field).and_then(Value::as_str).is_none() {
                missing.push(field);
            }
        }
        if object.get("approve").and_then(Value::as_bool).is_none() {
            missing.push("approve");
        }
        for field in ["nonce", "signed_at"] {
            if object.get(field).and_then(Value::as_u64).is_none() {
                missing.push(field);
            }
        }
        let vote_task = object.get("task_id").and_then(Value::as_str);
        if vote_task.is_none() {
            missing.push("task_id");
        }
        if !missing.is_empty() {
            problems.push(format!(
                "votes[{index}] is missing or mistyped: {}",
                missing.join(", ")
            ));
            continue;
        }
        if let (Some(expected), Some(actual)) = (expected_task, vote_task) {
            if expected != actual {
                problems.push(format!(
                    "votes[{index}] targets task `{actual}`, not `{expected}`"
                ));
                continue;
            }
        }
        let signature = object
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if signature.trim().is_empty() {
            problems.push(format!("votes[{index}] has an empty `signature`"));
            continue;
        }
        match object.get("approve").and_then(Value::as_bool) {
            Some(true) => approve = approve.saturating_add(1),
            Some(false) => reject = reject.saturating_add(1),
            None => {
                problems.push(format!("votes[{index}] has no boolean `approve`"));
                continue;
            }
        }
        entries.push(Value::Object(object.clone()));
    }

    if !problems.is_empty() {
        return Err(NauError::Validation(problems.join("; ")));
    }

    Ok(json!({
        "valid": entries.len(),
        "approve": approve,
        "reject": reject,
        "votes": entries,
    }))
}

fn describe(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}
