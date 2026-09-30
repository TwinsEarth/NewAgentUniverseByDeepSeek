//! Transport-level integration tests: the surface a client actually talks to.
//!
//! These are the tests that answer the question upstream v2.8.2 got wrong. It
//! *had* a `validate_arguments`, and *had* unit tests for it — and its two live
//! transports called the tool bridges directly (`sse.rs:130-147` for HTTP,
//! `stdio.rs:85-93` for stdio), so validation never ran on the path a client
//! uses. `market_deposit {"amount":"lots"}` therefore reached `get_money`'s
//! `unwrap_or(Money::ZERO)`, **deposited 0**, and answered
//! `{"status":"deposited"}`.
//!
//! Every test here drives a **transport**, not a validator, and the dispatcher
//! records how many times it was reached: the assertion is not only "the call was
//! refused" but "the money path was never entered".

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use nau_core::domain::Money;
use nau_mcp::market::{Dispatcher, MarketToolBridge};
use nau_mcp::{
    handle_http_message, serve_stdio, serve_stdio_as, Authenticator, McpServer, Principal, Scope,
    SessionState, ToolEffect, DEFAULT_TOKEN_ENV, TOKENS_ENV,
};
use serde_json::{json, Value};
use tokio::io::BufReader;

/// The credential of the write-capable caller.
const ALICE_TOKEN: &str = "alice-token-0123456789";
/// The credential of the read-only caller.
const BOB_TOKEN: &str = "bob-token-0123456789";
/// Alice's DID, as her credential is bound to it.
const ALICE_DID: &str = "did:nau:1111111111111111";
/// Bob's DID.
const BOB_DID: &str = "did:nau:2222222222222222";

/// A dispatcher that records how often the market was reached and answers with a
/// success document.
///
/// The canned reply says `"status": "deposited"` on purpose: that is exactly what
/// upstream answered for a zero-value deposit, so a test that sees this reply has
/// seen the defect.
fn recording_dispatch() -> (Dispatcher, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let dispatch: Dispatcher = Arc::new(move |method: String, payload: Value| {
        counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(json!({
                "status": "deposited",
                "method": method,
                "echo": payload,
            }))
        })
    });
    (dispatch, calls)
}

fn server(dispatch: Dispatcher) -> McpServer {
    MarketToolBridge::new(dispatch)
        // The crate's own version, not a literal: a second copy of the release
        // number is a second thing that goes stale at the next bump.
        .register_into_new("nau-market", env!("CARGO_PKG_VERSION"))
        .expect("the standard tool set registers")
}

/// Alice: write scope, bound to a DID.
fn write_principal() -> Principal {
    Authenticator::deny_all()
        .with_token(
            ALICE_TOKEN,
            "alice",
            Some(ALICE_DID),
            &[Scope::Read, Scope::Write],
        )
        .expect("configures")
        .authenticate(Some(&nau_mcp::Credential::new(ALICE_TOKEN).expect("ok")))
        .expect("alice authenticates")
}

/// The handshake line every session must send first.
const INITIALIZE: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;

fn tools_call(id: u64, name: &str, arguments: Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    .to_string()
}

/// Run `messages` through the stdio transport as `principal` and return every
/// response line.
async fn stdio_session(
    server: &McpServer,
    principal: &Principal,
    messages: &[String],
) -> Vec<Value> {
    let input = messages.join("\n");
    let mut output: Vec<u8> = Vec::new();
    let mut state = SessionState::default();
    serve_stdio_as(
        server,
        principal,
        &mut state,
        BufReader::new(input.as_bytes()),
        &mut output,
    )
    .await
    .expect("the stdio session ends at EOF");
    String::from_utf8(output)
        .expect("responses are utf-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("every line is a JSON-RPC response"))
        .collect()
}

// ---------------------------------------------------------------------------
// Transport 1: newline-delimited stdio
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_stdio_transport_refuses_a_malformed_amount_without_reaching_the_market() {
    let (dispatch, calls) = recording_dispatch();
    let server = server(dispatch);
    let principal = write_principal();

    let responses = stdio_session(
        &server,
        &principal,
        &[
            INITIALIZE.to_string(),
            // `amount` is not a declared parameter at all.
            tools_call(
                2,
                "market_deposit",
                json!({"amount": "lots", "account": ALICE_DID}),
            ),
            // String in an integer slot.
            tools_call(
                3,
                "market_deposit",
                json!({"account": ALICE_DID, "amount_minor": "lots"}),
            ),
            // Absent amount.
            tools_call(4, "market_deposit", json!({"account": ALICE_DID})),
            // Zero and negative are refused by the declared minimum.
            tools_call(
                5,
                "market_deposit",
                json!({"account": ALICE_DID, "amount_minor": 0}),
            ),
            tools_call(
                6,
                "market_deposit",
                json!({"account": ALICE_DID, "amount_minor": -1_000}),
            ),
        ],
    )
    .await;

    assert_eq!(responses.len(), 6, "one response per request");
    for response in &responses[1..] {
        let result = &response["result"];
        assert_eq!(
            result["isError"], true,
            "a malformed amount must be refused: {response}"
        );
        assert!(
            !result["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("deposited"),
            "the market's success text must not appear: {response}"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the money path must never be entered for a malformed amount"
    );

    // The control: the same transport with a well-formed amount does reach the
    // market, so the test above is not passing because nothing works.
    let responses = stdio_session(
        &server,
        &principal,
        &[
            INITIALIZE.to_string(),
            tools_call(
                7,
                "market_deposit",
                json!({"account": ALICE_DID, "amount_minor": 12_500_000}),
            ),
        ],
    )
    .await;
    assert_eq!(responses[1]["result"]["isError"], false, "{}", responses[1]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_stdio_transport_requires_a_write_scope_for_every_mutating_tool() {
    let (dispatch, calls) = recording_dispatch();
    let server = server(dispatch);
    let anonymous = Principal::anonymous();

    let responses = stdio_session(
        &server,
        &anonymous,
        &[
            INITIALIZE.to_string(),
            tools_call(
                2,
                "market_deposit",
                json!({"account": ALICE_DID, "amount_minor": 5}),
            ),
            tools_call(3, "market_settle_task", json!({"task_id": "t-1"})),
            tools_call(
                4,
                "market_record_votes",
                json!({"task_id": "t-1", "votes": []}),
            ),
            // A read is still served: an unauthenticated discovery client is a
            // legitimate caller, it just cannot mutate.
            tools_call(5, "market_balance", json!({"account": ALICE_DID})),
        ],
    )
    .await;

    for response in &responses[1..4] {
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(
            text.contains("`write` scope"),
            "the refusal must name the missing scope: {response}"
        );
    }
    assert_eq!(responses[4]["result"]["isError"], false, "{}", responses[4]);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "only the read reached the market"
    );
}

#[tokio::test]
async fn a_did_bound_caller_cannot_act_for_another_identity_over_stdio() {
    let (dispatch, calls) = recording_dispatch();
    let server = server(dispatch);
    let alice = write_principal();

    let responses = stdio_session(
        &server,
        &alice,
        &[
            INITIALIZE.to_string(),
            // Alice's credential may only act as Alice.
            tools_call(
                2,
                "market_deposit",
                json!({"account": BOB_DID, "amount_minor": 5}),
            ),
            tools_call(
                3,
                "market_submit_bid",
                json!({"bid": {"bidder": BOB_DID, "task_id": "t", "price_minor": 1}}),
            ),
            tools_call(
                4,
                "market_publish_task",
                json!({"task": {"requester": BOB_DID}}),
            ),
            // Her own account is fine.
            tools_call(
                5,
                "market_deposit",
                json!({"account": ALICE_DID, "amount_minor": 5}),
            ),
        ],
    )
    .await;

    for response in &responses[1..4] {
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(
            text.contains("may not invoke"),
            "cross-principal use must be refused by name: {response}"
        );
        assert_eq!(response["result"]["isError"], true, "{response}");
    }
    assert_eq!(responses[4]["result"]["isError"], false, "{}", responses[4]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_env_driven_stdio_path_serves_reads_and_refuses_writes_when_nothing_is_configured() {
    // upstream v2.8.2 fix (finding 6): "nothing configured" must mean *refuse*,
    // not *allow*. This drives `serve_stdio` itself — the function a real process
    // uses — with an authenticator that has no callers.
    std::env::remove_var(DEFAULT_TOKEN_ENV);
    std::env::remove_var(TOKENS_ENV);
    let (dispatch, calls) = recording_dispatch();
    let server = server(dispatch);
    let authenticator = Authenticator::from_env().expect("an unset variable is not an error");
    assert_eq!(authenticator.configured_callers(), 0);

    let input = [
        INITIALIZE.to_string(),
        tools_call(
            2,
            "market_deposit",
            json!({"account": ALICE_DID, "amount_minor": 1}),
        ),
        tools_call(3, "market_balance", json!({"account": ALICE_DID})),
    ]
    .join("\n");
    let mut output: Vec<u8> = Vec::new();
    let mut state = SessionState::default();
    serve_stdio(
        &server,
        &authenticator,
        &mut state,
        BufReader::new(input.as_bytes()),
        &mut output,
    )
    .await
    .expect("serves to EOF");

    let responses: Vec<Value> = String::from_utf8(output)
        .expect("utf-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("a response"))
        .collect();
    assert_eq!(responses[1]["result"]["isError"], true, "{}", responses[1]);
    assert_eq!(responses[2]["result"]["isError"], false, "{}", responses[2]);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "only the read ran");
}

// ---------------------------------------------------------------------------
// Transport 2: MCP over HTTP (the SSE frame path)
// ---------------------------------------------------------------------------

/// Split an SSE frame into its `event:`/`data:` fields.
fn sse_fields(frame: &str) -> (String, String) {
    let mut event = String::new();
    let mut data = String::new();
    for line in frame.lines() {
        if let Some(rest) = line.strip_prefix("event: ") {
            event = rest.to_string();
        }
        if let Some(rest) = line.strip_prefix("data: ") {
            data.push_str(rest);
        }
    }
    (event, data)
}

#[tokio::test]
async fn the_http_transport_refuses_an_anonymous_mutation_and_accepts_an_authenticated_one() {
    let (dispatch, calls) = recording_dispatch();
    let server = server(dispatch);
    let authenticator = Authenticator::deny_all()
        .with_token(
            ALICE_TOKEN,
            "alice",
            Some(ALICE_DID),
            &[Scope::Read, Scope::Write],
        )
        .expect("configures")
        .with_token(BOB_TOKEN, "bob", Some(BOB_DID), &[Scope::Read])
        .expect("configures");
    let mut state = SessionState::default();

    let init = handle_http_message(&server, &authenticator, None, &mut state, INITIALIZE)
        .expect("frames")
        .expect("initialize is answered");
    assert_eq!(sse_fields(&init).0, "message");

    // No credential at all: the mutating call is refused, the read is served.
    let refused = handle_http_message(
        &server,
        &authenticator,
        None,
        &mut state,
        &tools_call(
            2,
            "market_deposit",
            json!({"account": ALICE_DID, "amount_minor": 1}),
        ),
    )
    .expect("frames")
    .expect("answered");
    let (_, data) = sse_fields(&refused);
    let response: Value = serde_json::from_str(&data).expect("the frame carries JSON");
    assert_eq!(response["result"]["isError"], true, "{response}");

    // A credential that authenticates nobody is refused at the boundary, not
    // silently downgraded.
    let unknown = handle_http_message(
        &server,
        &authenticator,
        Some("Bearer not-a-configured-token"),
        &mut state,
        &tools_call(3, "market_balance", json!({"account": ALICE_DID})),
    )
    .expect("frames")
    .expect("answered");
    let (_, data) = sse_fields(&unknown);
    let response: Value = serde_json::from_str(&data).expect("JSON");
    assert_eq!(response["error"]["code"], -32003, "{response}");

    // A malformed header is refused too.
    let malformed = handle_http_message(
        &server,
        &authenticator,
        Some("Basic abc"),
        &mut state,
        &tools_call(4, "market_balance", json!({"account": ALICE_DID})),
    )
    .expect("frames")
    .expect("answered");
    let (_, data) = sse_fields(&malformed);
    let response: Value = serde_json::from_str(&data).expect("JSON");
    assert_eq!(response["error"]["code"], -32003, "{response}");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "nothing reached the market yet: the boundary refusals happened first"
    );

    // A caller that authenticates but lacks the write scope is refused by the
    // dispatch gate — and can still read, so the two halves are distinguished.
    let bob_reads = handle_http_message(
        &server,
        &authenticator,
        Some(&format!("Bearer {BOB_TOKEN}")),
        &mut state,
        &tools_call(6, "market_balance", json!({"account": BOB_DID})),
    )
    .expect("frames")
    .expect("answered");
    let (_, data) = sse_fields(&bob_reads);
    let response: Value = serde_json::from_str(&data).expect("JSON");
    assert_eq!(response["result"]["isError"], false, "{response}");

    let bob_writes = handle_http_message(
        &server,
        &authenticator,
        Some(&format!("Bearer {BOB_TOKEN}")),
        &mut state,
        &tools_call(
            7,
            "market_deposit",
            json!({"account": BOB_DID, "amount_minor": 1}),
        ),
    )
    .expect("frames")
    .expect("answered");
    let (_, data) = sse_fields(&bob_writes);
    let response: Value = serde_json::from_str(&data).expect("JSON");
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert!(
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("`write` scope"),
        "{response}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "only bob's read reached the market"
    );

    // The authenticated writer gets through, and the frame is one SSE line.
    let accepted = handle_http_message(
        &server,
        &authenticator,
        Some(&format!("Bearer {ALICE_TOKEN}")),
        &mut state,
        &tools_call(
            5,
            "market_deposit",
            json!({"account": ALICE_DID, "amount_minor": 1}),
        ),
    )
    .expect("frames")
    .expect("answered");
    assert_eq!(
        accepted
            .lines()
            .filter(|line| line.starts_with("data: "))
            .count(),
        1,
        "an SSE frame must carry exactly one data line: {accepted:?}"
    );
    assert_eq!(
        accepted.lines().count(),
        3,
        "an SSE frame is `event:`, one `data:` and a blank terminator: {accepted:?}"
    );
    assert!(
        accepted.starts_with("event: message\ndata: "),
        "{accepted:?}"
    );
    assert!(accepted.ends_with("\n\n"), "{accepted:?}");
    let (_, data) = sse_fields(&accepted);
    let response: Value = serde_json::from_str(&data).expect("JSON");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_http_transport_refuses_a_malformed_amount_before_the_market() {
    let (dispatch, calls) = recording_dispatch();
    let server = server(dispatch);
    let authenticator = Authenticator::deny_all()
        .with_token(ALICE_TOKEN, "alice", Some(ALICE_DID), &[Scope::Write])
        .expect("configures");
    let mut state = SessionState::default();
    handle_http_message(&server, &authenticator, None, &mut state, INITIALIZE).expect("frames");

    for arguments in [
        json!({"amount": "lots", "account": ALICE_DID}),
        json!({"account": ALICE_DID, "amount_minor": "lots"}),
        json!({"account": ALICE_DID, "amount_minor": 0}),
        json!({"account": ALICE_DID}),
    ] {
        let frame = handle_http_message(
            &server,
            &authenticator,
            Some(&format!("Bearer {ALICE_TOKEN}")),
            &mut state,
            &tools_call(9, "market_deposit", arguments.clone()),
        )
        .expect("frames")
        .expect("answered");
        let (_, data) = sse_fields(&frame);
        let response: Value = serde_json::from_str(&data).expect("JSON");
        assert_eq!(
            response["result"]["isError"], true,
            "`{arguments}` must be refused: {response}"
        );
        assert!(
            !response["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("deposited"),
            "no success text for a malformed amount: {response}"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// The declaration itself: effects, schema bounds and the number domain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_mutating_tools_are_exactly_the_ones_that_need_a_write_scope() {
    // A hardcoded list, so a future tool that forgets `.mutating()` fails here
    // rather than silently becoming callable by an anonymous client.
    const EXPECTED_MUTATING: [&str; 9] = [
        "market_deposit",
        "market_open_dispute",
        "market_publish_task",
        "market_record_votes",
        "market_register_agent",
        "market_settle_task",
        "market_submit_bid",
        "market_submit_result",
        "market_withdraw",
    ];
    let (dispatch, _calls) = recording_dispatch();
    let server = server(dispatch);

    let mut mutating: Vec<&str> = server
        .tools()
        .iter()
        .filter(|tool| tool.effect() == ToolEffect::Mutating)
        .map(|tool| tool.name)
        .collect();
    mutating.sort_unstable();
    let mut expected = EXPECTED_MUTATING;
    expected.sort_unstable();
    assert_eq!(
        mutating, expected,
        "the mutating set is the security boundary; it must be exactly this"
    );

    // Every read-only tool still refuses a *bad call*, so "read-only" is not a
    // synonym for "unvalidated".
    assert!(server
        .dispatch(&Principal::anonymous(), "market_balance", &json!({}))
        .get("isError")
        .is_some_and(|flag| flag == &Value::Bool(true)));

    // And every mutating tool refuses an anonymous caller by name before
    // validation runs, whatever its arguments are.
    for name in EXPECTED_MUTATING {
        let outcome = server.dispatch(&Principal::anonymous(), name, &json!({}));
        assert_eq!(outcome["isError"], true, "{name}");
        assert!(
            outcome["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("`write` scope"),
            "`{name}` must be refused for the missing scope: {outcome}"
        );
    }
}

#[tokio::test]
async fn the_deposit_schema_publishes_the_bound_the_server_enforces() {
    let (dispatch, _calls) = recording_dispatch();
    let server = server(dispatch);
    let tool = server.tool("market_deposit").expect("registered");
    let schema = tool.input_schema();
    assert_eq!(schema["properties"]["amount_minor"]["type"], "integer");
    assert_eq!(
        schema["properties"]["amount_minor"]["minimum"], 1,
        "the published schema and the enforced rule must agree: {schema}"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["account", "amount_minor"]));
    assert_eq!(
        tool.ownership().map(|spec| spec.param),
        Some("account"),
        "the ownership binding is part of the same declaration"
    );
    // And the listing says which tools mutate, from the same field.
    let listing = server.tools_list_result(&nau_mcp::RequestId::Number(1));
    let listed = listing.result.expect("a result")["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|entry| entry["name"] == "market_deposit")
        .expect("listed")
        .clone();
    assert_eq!(listed["annotations"]["readOnlyHint"], false);
    assert_eq!(listed["annotations"]["destructiveHint"], true);
    assert_eq!(listed["x-nau-ownership"]["argument"], "account");
}

#[tokio::test]
async fn a_non_finite_number_cannot_reach_a_tool_through_any_transport() {
    // upstream v2.8.2 fix (finding 4): upstream orders caller-supplied `f64`
    // weights with `partial_cmp(..).unwrap()`, which panics on `NaN`. The lock
    // here is the JSON-RPC layer plus the number type: neither `NaN`, `Infinity`
    // nor an overflowing literal is a JSON value, so the message cannot even be
    // parsed, and `serde_json` cannot construct a non-finite number.
    assert!(serde_json::Number::from_f64(f64::NAN).is_none());
    assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());
    for hostile in ["NaN", "Infinity", "-Infinity", "1e999"] {
        assert!(
            serde_json::from_str::<Value>(hostile).is_err(),
            "`{hostile}` must not parse as JSON"
        );
    }

    let (dispatch, calls) = recording_dispatch();
    let server = server(dispatch);
    let authenticator = Authenticator::deny_all()
        .with_token(ALICE_TOKEN, "alice", Some(ALICE_DID), &[Scope::Write])
        .expect("configures");
    let mut state = SessionState::default();
    handle_http_message(&server, &authenticator, None, &mut state, INITIALIZE).expect("frames");

    // A hostile body cannot be framed as a request at all: the transport answers
    // a parse error instead of delivering a `NaN` to a handler.
    let hostile = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\
         \"market_deposit\",\"arguments\":{{\"account\":\"{ALICE_DID}\",\"amount_minor\":1e999}}}}}}"
    );
    let frame = handle_http_message(
        &server,
        &authenticator,
        Some(&format!("Bearer {ALICE_TOKEN}")),
        &mut state,
        &hostile,
    )
    .expect("frames")
    .expect("answered");
    let (_, data) = sse_fields(&frame);
    let response: Value = serde_json::from_str(&data).expect("JSON");
    assert_eq!(response["error"]["code"], -32700, "{response}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // A `Number` parameter accepts only a finite value, as a second lock.
    assert!(!nau_mcp::ParamType::Number.accepts(&Value::Null));
    assert!(nau_mcp::ParamType::Number.accepts(&json!(1.5)));
    assert!(nau_mcp::ParamType::Number.accepts(&json!(-0.0)));
}

#[tokio::test]
async fn the_amount_helper_used_by_the_money_tests_is_exact_in_minor_units() {
    // A guard against the tests themselves drifting: the fixture amounts are
    // integers of minor units, which is what the tool surface declares.
    assert_eq!(Money::from_minor(12_500_000).to_decimal_string(), "12.5");
    assert!(Money::from_minor(0).minor() == 0);
}
