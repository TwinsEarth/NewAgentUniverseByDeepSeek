//! `nau-plugin-mcp` — the official (T1) plugin for the MCP / ACA compatible tool surface.
//!
//! `docs/PLUGIN-ARCHITECTURE.md` lists eleven official plugins and `nau_plugins::official`
//! catalogues all eleven; before this file only `nau-plugin-market` was genuinely runnable.
//! This binary is the second, and what makes it count is narrow and checkable:
//!
//! * it is a real file a host can start, and it speaks the host ABI frame from
//!   [`nau_plugins::frame`] — the same codec `nau-plugin-echo`, `nau-plugin-market`,
//!   `nau-plugin-swarm` and `nau-plugin-reputation` speak, not a second implementation;
//! * its `initialize` op delegates to [`nau_mcp::protocol::negotiate`] and
//!   [`nau_mcp::protocol::is_supported`] and returns a
//!   [`nau_mcp::capability::InitializeResult`] built by the crate's own constructor, so the
//!   wire shape a host receives is the crate's, not a re-spelling of it;
//! * its `rpc` op delegates to [`nau_mcp::rpc::parse_request`] and reports the crate's own
//!   `Result<RpcRequest, (RequestId, RpcError)>` verbatim;
//! * its `capabilities` op reports what the official catalogue declares next to what this
//!   binary implements, and derives the tier's approval requirements from
//!   [`Capability::decision`] at runtime rather than restating them.
//!
//! # Protocol
//!
//! ```text
//! stdin:  u32_be(len) || {"abi":"3.2","id":"req-1","op":"initialize","payload":{…}}
//! stdout: u32_be(len) || {"abi":"3.2","id":"req-1",
//!                         "plugin":"com.twinsearth.official.mcp",
//!                         "version":"1.0.0","ok":true,"payload":{…}}
//! ```
//!
//! One frame in, one frame out, then exit. stdout carries **only** frames; every
//! diagnostic goes to stderr, because a stray `println!` is a protocol corruption and this
//! binary has no other way to talk to its host.
//!
//! ## `initialize`
//!
//! The payload is the argument [`negotiate`] actually takes, not an MCP envelope:
//!
//! ```json
//! { "requested_version": "2025-06-18", "server_name": "…", "server_version": "…",
//!   "instructions": "…" }
//! ```
//!
//! Every key is optional, and a `null` payload is the handshake with no request at all.
//! `server_name` and `server_version` default to this plugin's own name and version, so
//! the server identity is a fact rather than a caller-supplied claim unless the caller
//! deliberately overrides it. The answer:
//!
//! ```json
//! {
//!   "requested_version": "2025-06-18",
//!   "requested_version_supported": true,
//!   "negotiated_version": "2025-06-18",
//!   "initialize_result": { "protocolVersion": "2025-06-18", "capabilities": { … },
//!                          "serverInfo": { "name": "…", "version": "…" } }
//! }
//! ```
//!
//! **`requested_version_supported` is the honest half.** [`negotiate`] answers an
//! unsupported request with [`DEFAULT_PROTOCOL_VERSION`] rather than refusing it, so a
//! client that asked for a version this server does not implement is told it got *a*
//! version, not *its* version — which is the upstream defect the crate's own module docs
//! describe. A host that read only `negotiated_version` would see a plausible number and
//! never learn that the request was downgraded; `requested_version_supported: false` is
//! where that is visible. It is `null` when the client asked for no version at all, since
//! there is then nothing to support or refuse.
//!
//! ## `rpc`
//!
//! ```json
//! { "request": { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} } }
//! ```
//!
//! `request` is required and may be any JSON value — including `null`, which is a value
//! [`parse_request`] can refuse rather than a missing key. The answer carries the crate's
//! verdict, and **a parse failure is an answer rather than a refusal**:
//!
//! ```json
//! { "parsed": true, "id": 1, "method": "tools/list", "is_notification": false,
//!   "has_valid_version": true, "params_kind": "an object", "request": { … }, "error": null }
//! ```
//!
//! ```json
//! { "parsed": false, "id": null, "method": null, "is_notification": null,
//!   "has_valid_version": null, "params_kind": null, "request": null,
//!   "error": { "code": -32600, "message": "…", "data": … } }
//! ```
//!
//! The `(RequestId, RpcError)` pair `parse_request` returned is reported through `id` and
//! `error` using the crate's own `Serialize`, so nothing is stringified or reshaped. The
//! call is refused only when the *payload itself* is not the shape this op documents
//! (`mcp_rpc_payload_invalid`); whether the caller's JSON-RPC request is valid is the
//! question the op was asked, and answering it is not a failure.
//!
//! **`parse_request` does not check the `jsonrpc` literal.** A request carrying
//! `"jsonrpc": "1.0"` parses successfully; [`RpcRequest::has_valid_version`] is a separate
//! call, and this op makes it so the answer cannot be mistaken for a validated request.
//!
//! ## `capabilities`
//!
//! Takes no arguments. Returns the plugin's identity and version, the tier derived from its
//! name, the catalogue's capability set, this binary's declaration, whether the two agree,
//! the approvals the official tier needs for what is declared (derived from
//! [`Capability::decision`]), the authorities that tier names for non-basic capabilities,
//! the ops this binary implements, which op (if any) exercises each declared capability,
//! and which crate function each op delegates to.
//!
//! # Exit codes
//!
//! `0` answered, `1` answered with `ok: false`, `2` the frame itself could not be read or
//! written — the convention of the four plugins before this one, unchanged. `2` means the
//! binary is not speaking this ABI at all, which is a different repair from "the plugin
//! refused the call".
//!
//! # Fail-closed choices
//!
//! * an unknown op, an incompatible `abi` and a payload of the wrong shape are each a typed
//!   refusal, never an empty success;
//! * unknown *keys* inside a payload are tolerated (the frame envelope's
//!   additive-within-a-major rule); an unknown op is not;
//! * a diagnostic echoed back to the host is bounded, because an error string built from
//!   caller-supplied JSON is how a log becomes an attack surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_mcp::capability::InitializeResult;
use nau_mcp::protocol::{is_supported, negotiate};
use nau_mcp::rpc::parse_request;
use nau_plugin::capability::{Capability, Grant};
use nau_plugin::tier::Tier;
use nau_plugins::frame::{self, Response};
use nau_plugins::official::Official;
use nau_plugins::payload;
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// The catalogue name this binary implements, from
/// [`nau_plugins::official::OFFICIALS`]. The tier is derived from this name, so the
/// spelling is not cosmetic.
const PLUGIN_NAME: &str = "com.twinsearth.official.mcp";

/// The version this binary reports, which is the catalogue entry's version rather than the
/// workspace's. A test asserts the two are equal, so a catalogue bump that forgets this
/// constant fails instead of shipping a plugin that lies about its own version.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named in [`OP_DELEGATION`]
/// is listed here, so this table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 3] = ["capabilities", "initialize", "rpc"];

/// The capability set this binary's manifest declares.
///
/// `plugin:message:send` is what the catalogue entry for this plugin names
/// ([`nau_plugins::official::OFFICIALS`]), and it is one of the three capabilities every
/// loadable tier holds by construction — so the official tier's approval machinery is not
/// triggered by this declaration at all. That is the accurate state, and the answer says
/// so with an empty `required_approvals` rather than by inventing a capability this plugin
/// does not need.
const DECLARED_CAPABILITIES: [&str; 1] = ["plugin:message:send"];

/// Which implemented op exercises each declared capability.
///
/// Empty, and that is the honest state rather than a placeholder: neither `initialize` nor
/// `rpc` sends anything on the plugin bus. Reporting an op here would be a claim that this
/// binary does that capability's work, which it does not.
const CAPABILITY_BACKING: [(&str, &[&str]); 1] = [("plugin:message:send", &[])];

/// Which crate function each implemented op delegates to, as `(op, target)`.
///
/// Reported in the `capabilities` answer so a host can see the delegation rather than
/// having to trust a description of it.
const OP_DELEGATION: [(&str, &str); 3] = [
    ("capabilities", "nau_plugins::official::OFFICIALS"),
    (
        "initialize",
        "nau_mcp::protocol::{negotiate, is_supported} + \
         nau_mcp::capability::InitializeResult::new",
    ),
    ("rpc", "nau_mcp::rpc::parse_request"),
];

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "`initialize` and `rpc` delegate to nau_mcp (protocol negotiation, the \
                     capability structs, and the JSON-RPC parser); neither sends a message on \
                     the plugin bus, so the one declared capability is declared but not \
                     exercised and declared_capabilities_backed_by_ops is false. The declared \
                     set is the catalogue's, and `plugin:message:send` is a basic capability, \
                     so the official tier requires no approval for it: required_approvals is \
                     empty because the matrix grants it unconditionally, not because the \
                     derivation was skipped. A JSON-RPC parse failure is reported as the \
                     crate's own (RequestId, RpcError) with parsed: false, not as a plugin \
                     refusal. This op surface negotiates a handshake and parses requests; it \
                     dispatches no tool and authenticates no caller.";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: a payload is neither a JSON object nor the `null` an empty call uses.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: an `initialize` payload is an object but not the shape this op documents.
const CODE_INITIALIZE_PAYLOAD: &str = "mcp_initialize_payload_invalid";
/// Error code: an `rpc` payload is an object but does not carry `request`.
const CODE_RPC_PAYLOAD: &str = "mcp_rpc_payload_invalid";
/// Error code: this binary and the official catalogue disagree about its own identity.
const CODE_CAPABILITIES: &str = "mcp_capabilities_unavailable";

/// Longest diagnostic quoted back to the host, in characters.
///
/// The message is written into a frame the host logs, and a `serde_json` diagnostic for a
/// wrong enum variant quotes the offending string — which the caller chose. Bounding it
/// keeps a caller from deciding how much text this plugin writes.
const MAX_DIAGNOSTIC_CHARS: usize = 512;

/// A refusal: a machine-readable code and a bounded explanation.
#[derive(Debug)]
struct Refusal {
    /// The code the host branches on.
    code: &'static str,
    /// The explanation, already bounded.
    message: String,
}

/// One op's answer, or the typed refusal that replaces it.
type Answer = std::result::Result<Value, Refusal>;

/// The `initialize` payload, as [`negotiate`] and [`InitializeResult::new`] consume it.
///
/// Deliberately not `deny_unknown_fields`: the frame envelope is additive within a major,
/// and a payload that refused new keys would break that promise one layer down.
#[derive(Debug, Default, Deserialize)]
struct InitializeRequest {
    /// The protocol version the client asked for, or `None` for a client that asked for
    /// none. This is the argument [`negotiate`] takes directly.
    #[serde(default)]
    requested_version: Option<String>,
    /// The server name to report. Defaults to this plugin's own name.
    #[serde(default)]
    server_name: Option<String>,
    /// The server version to report. Defaults to this plugin's own version.
    #[serde(default)]
    server_version: Option<String>,
    /// Optional usage instructions for the client.
    #[serde(default)]
    instructions: Option<String>,
}

/// The `rpc` payload: one JSON-RPC request, as a value for [`parse_request`].
#[derive(Debug, Deserialize)]
struct RpcPayload {
    /// The JSON-RPC request. Required, and any JSON value: `null` is a value the parser can
    /// refuse, which is different from a missing key.
    request: Value,
}

fn main() -> ExitCode {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    ExitCode::from(run(&mut input, &mut output))
}

/// Read one request, answer it, and report the exit code.
fn run<R: Read, W: Write>(input: &mut R, output: &mut W) -> u8 {
    let payload = match frame::read_frame(input) {
        Ok(Some(payload)) => payload,
        Ok(None) => {
            // A clean EOF before any frame: nothing was asked, so nothing is refused.
            eprintln!("{PLUGIN_NAME}: no request on stdin");
            return EXIT_IO;
        }
        Err(err) => {
            eprintln!("{PLUGIN_NAME}: {err}");
            return EXIT_IO;
        }
    };

    let request = match frame::decode_request(&payload) {
        Ok(request) => request,
        Err(err) => {
            // The frame was readable but not a request: answer with the refusal, so a host
            // sees a typed code rather than a dead process.
            let response = Response::refused(
                "",
                PLUGIN_NAME,
                PLUGIN_VERSION,
                frame::CODE_NOT_JSON,
                &err.to_string(),
            );
            return report(output, &response, EXIT_REFUSED);
        }
    };

    if !request.abi_is_compatible() {
        let response = Response::refused(
            &request.id,
            PLUGIN_NAME,
            PLUGIN_VERSION,
            frame::CODE_ABI_MISMATCH,
            &format!(
                "this plugin speaks {} and was asked for {}",
                frame::abi_version(),
                request.abi
            ),
        );
        return report(output, &response, EXIT_REFUSED);
    }

    let response = match request.op.as_str() {
        "initialize" => match initialize(&request.payload) {
            Ok(answer) => Response::ok(&request, PLUGIN_NAME, PLUGIN_VERSION, answer),
            Err(refusal) => refusal_from(refusal, &request),
        },
        "rpc" => match rpc(&request.payload) {
            Ok(answer) => Response::ok(&request, PLUGIN_NAME, PLUGIN_VERSION, answer),
            Err(refusal) => refusal_from(refusal, &request),
        },
        "capabilities" => match capabilities() {
            Ok(answer) => Response::ok(&request, PLUGIN_NAME, PLUGIN_VERSION, answer),
            Err(refusal) => refusal_from(refusal, &request),
        },
        other => Response::refused(
            &request.id,
            PLUGIN_NAME,
            PLUGIN_VERSION,
            payload::CODE_UNKNOWN_OPERATION,
            &format!(
                "`{PLUGIN_NAME}` implements {}, not `{other}`",
                IMPLEMENTED_OPS.join(", ")
            ),
        ),
    };
    let code = if response.ok { EXIT_OK } else { EXIT_REFUSED };
    report(output, &response, code)
}

/// The refusal response for one [`Refusal`].
fn refusal_from(refusal: Refusal, request: &frame::Request) -> Response {
    Response::refused(
        &request.id,
        PLUGIN_NAME,
        PLUGIN_VERSION,
        refusal.code,
        &refusal.message,
    )
}

/// Write the response frame and return `fallback` unless the write failed.
fn report<W: Write>(output: &mut W, response: &Response, fallback: u8) -> u8 {
    let encoded = match serde_json::to_vec(response) {
        Ok(encoded) => encoded,
        Err(err) => {
            eprintln!("{PLUGIN_NAME}: cannot encode the response: {err}");
            return EXIT_IO;
        }
    };
    match frame::write_frame(output, &encoded) {
        Ok(()) => fallback,
        Err(err) => {
            eprintln!("{PLUGIN_NAME}: cannot write the response frame: {err}");
            EXIT_IO
        }
    }
}

/// Negotiate the MCP handshake with the crate's own protocol and capability code.
fn initialize(payload: &Value) -> Answer {
    // A handshake with no arguments is an empty call, not a malformed one: `null` payload
    // means "the client asked for no version", which `negotiate(None)` answers.
    let request: InitializeRequest = match payload {
        Value::Null => InitializeRequest::default(),
        Value::Object(_) => serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_INITIALIZE_PAYLOAD,
            message: bounded(&err.to_string()),
        })?,
        other => {
            return Err(Refusal {
                code: CODE_NOT_OBJECT,
                message: format!(
                    "an `initialize` payload must be a JSON object or null, found {}",
                    payload::kind_of(other)
                ),
            })
        }
    };

    let requested = request.requested_version.as_deref();

    // The two delegations the brief names, called the way the crate defines them:
    // `is_supported` answers "was the client's request implemented here?" and `negotiate`
    // answers "which version will the server use?". They are separate questions, and the
    // whole point of the first is that the second can silently answer with the default.
    let supported = requested.map(is_supported);
    let negotiated = negotiate(requested);

    // The crate's own constructor and builder, so the wire shape (camelCase keys,
    // `listChanged`, `serverInfo`) is the crate's rather than a re-spelling.
    let server_name = request
        .server_name
        .unwrap_or_else(|| PLUGIN_NAME.to_string());
    let server_version = request
        .server_version
        .unwrap_or_else(|| PLUGIN_VERSION.to_string());
    let mut result = InitializeResult::new(&server_name, &server_version, negotiated);
    if let Some(instructions) = request.instructions {
        result = result.with_instructions(instructions);
    }
    let result_value = serde_json::to_value(&result).map_err(|err| Refusal {
        code: CODE_INITIALIZE_PAYLOAD,
        message: bounded(&err.to_string()),
    })?;

    Ok(json!({
        "requested_version": request.requested_version,
        "requested_version_supported": supported,
        "negotiated_version": negotiated,
        "initialize_result": result_value,
    }))
}

/// Validate one JSON-RPC request with the crate's own parser and report its verdict.
fn rpc(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "an `rpc` payload must be a JSON object carrying `request`, found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let parsed: RpcPayload = serde_json::from_value(payload.clone()).map_err(|err| Refusal {
        code: CODE_RPC_PAYLOAD,
        message: bounded(&err.to_string()),
    })?;

    // The delegation: the crate's parser, on the caller's value. Its `(RequestId, RpcError)`
    // failure pair is reported through `id` and `error` with the crate's own `Serialize`,
    // so a host sees exactly what the parser produced.
    match parse_request(parsed.request) {
        Ok(request) => {
            let shape = serde_json::to_value(&request).map_err(|err| Refusal {
                code: CODE_RPC_PAYLOAD,
                message: bounded(&err.to_string()),
            })?;
            Ok(json!({
                "parsed": true,
                "id": request.id,
                "method": request.method,
                "is_notification": request.is_notification(),
                "has_valid_version": request.has_valid_version(),
                "params_kind": payload::kind_of(&request.params),
                "request": shape,
                "error": Value::Null,
            }))
        }
        Err((id, error)) => {
            let error_value = serde_json::to_value(&error).map_err(|err| Refusal {
                code: CODE_RPC_PAYLOAD,
                message: bounded(&err.to_string()),
            })?;
            Ok(json!({
                "parsed": false,
                "id": id,
                "method": Value::Null,
                "is_notification": Value::Null,
                "has_valid_version": Value::Null,
                "params_kind": Value::Null,
                "request": Value::Null,
                "error": error_value,
            }))
        }
    }
}

/// The authorities this tier names for capabilities above the basic set, derived from the
/// matrix rather than written down.
///
/// For the official tier this is `["vendor-team"]`: every non-basic, non-kernel capability
/// resolves to `RequiresApproval(VendorTeam)`. It is reported even though this declaration
/// triggers none of it, because "what would this tier need approval for?" is a question a
/// host can answer from the answer rather than from this crate's source.
fn non_basic_capability_authorities(tier: Tier) -> Vec<&'static str> {
    let mut authorities: Vec<&'static str> = Vec::new();
    for capability in Capability::ALL {
        if capability.is_basic() {
            continue;
        }
        // Kernel authority and the blacklist resolve to `Refused`, which names no
        // authority: nothing can approve them, so nothing is listed.
        if let Grant::RequiresApproval(authority) = capability.decision(tier) {
            let label = authority.label();
            if !authorities.contains(&label) {
                authorities.push(label);
            }
        }
    }
    authorities.sort_unstable();
    authorities
}

/// What this binary declares, what the catalogue declares, and what it implements.
fn capabilities() -> Answer {
    let entry = Official::find(PLUGIN_NAME).ok_or_else(|| Refusal {
        code: CODE_CAPABILITIES,
        message: format!(
            "`{PLUGIN_NAME}` is not in `nau_plugins::official::OFFICIALS`; this binary and the \
             catalogue disagree about its identity, so nothing about it can be reported"
        ),
    })?;

    let tier = entry.tier().map_err(|err| Refusal {
        code: CODE_CAPABILITIES,
        message: bounded(&err.to_string()),
    })?;

    let mut catalogue_capabilities = Vec::new();
    for capability in entry.capabilities {
        catalogue_capabilities.push(capability.as_str());
    }

    // The approvals the declared set needs, derived from the kernel's matrix at runtime.
    // `Grant::Always` needs nobody's approval; `RequiresApproval` names the authority;
    // `Refused` is a declaration this tier may not hold at all, which is a refusal here
    // rather than a line item, because the manifest would not load anyway.
    let mut required_approvals = Vec::new();
    for capability in DECLARED_CAPABILITIES {
        let parsed = Capability::parse(capability).map_err(|err| Refusal {
            code: CODE_CAPABILITIES,
            message: bounded(&err.to_string()),
        })?;
        match parsed.decision(tier) {
            Grant::Always => {}
            Grant::RequiresApproval(authority) => required_approvals.push(json!({
                "capability": parsed.as_str(),
                "authority": authority.label(),
            })),
            Grant::Refused { reason } => {
                return Err(Refusal {
                    code: CODE_CAPABILITIES,
                    message: format!(
                        "`{}` is declared by this binary but the {tier} tier refuses it: {reason}",
                        parsed.as_str()
                    ),
                })
            }
        }
    }

    // Which op exercises each declared capability. An empty list means "declared but not
    // exercised", which is a fact a host must be able to read without interpreting prose.
    let mut backing = Map::new();
    let mut all_backed = true;
    let mut unbacked = Vec::new();
    for capability in DECLARED_CAPABILITIES {
        let ops = capability_backing(capability);
        if ops.is_empty() {
            all_backed = false;
            unbacked.push(capability);
        }
        backing.insert(capability.to_string(), json!(ops));
    }

    let covered: BTreeSet<&str> = CAPABILITY_BACKING
        .iter()
        .flat_map(|(_, ops)| ops.iter().copied())
        .collect();
    let uncovered: Vec<&str> = IMPLEMENTED_OPS
        .iter()
        .copied()
        .filter(|op| !covered.contains(op))
        .collect();

    let mut delegation = Map::new();
    for (op, target) in OP_DELEGATION {
        delegation.insert(op.to_string(), Value::String(target.to_string()));
    }

    let mut declared_sorted = DECLARED_CAPABILITIES.to_vec();
    declared_sorted.sort_unstable();
    let mut catalogue_sorted = catalogue_capabilities.clone();
    catalogue_sorted.sort_unstable();

    Ok(json!({
        "plugin": PLUGIN_NAME,
        "version": PLUGIN_VERSION,
        "tier": tier.label(),
        "summary": entry.summary,
        "from": entry.from,
        "catalogue_capabilities": catalogue_capabilities,
        "declared_capabilities": DECLARED_CAPABILITIES,
        "declared_matches_catalogue": declared_sorted == catalogue_sorted,
        "required_approvals": required_approvals,
        "non_basic_capability_authorities": non_basic_capability_authorities(tier),
        "implemented_ops": IMPLEMENTED_OPS,
        "capability_backing": Value::Object(backing),
        "declared_capabilities_backed_by_ops": all_backed,
        "unbacked_declared_capabilities": unbacked,
        "ops_not_named_by_a_declared_capability": uncovered,
        "op_delegation": Value::Object(delegation),
        "notes": NOTES,
    }))
}

/// The ops that exercise `capability`, or an empty slice when none does.
fn capability_backing(capability: &str) -> &'static [&'static str] {
    for (name, ops) in CAPABILITY_BACKING {
        if name == capability {
            return ops;
        }
    }
    &[]
}

/// Truncate `text` to [`MAX_DIAGNOSTIC_CHARS`] characters, marking the cut.
fn bounded(text: &str) -> String {
    let mut out = String::new();
    for (index, character) in text.chars().enumerate() {
        if index >= MAX_DIAGNOSTIC_CHARS {
            out.push('…');
            break;
        }
        out.push(character);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_plugins::frame::{decode_response, Request};

    /// Run one request through `run` and decode exactly one response frame.
    fn call_request(request: &Request) -> (u8, Response) {
        let mut wire = Vec::new();
        frame::write_frame(&mut wire, &serde_json::to_vec(request).expect("encodes"))
            .expect("writes");
        let mut output = Vec::new();
        let code = run(&mut wire.as_slice(), &mut output);
        // One reader over the whole stream: the second read must be a clean EOF, which is
        // what "stdout carried exactly one frame and nothing else" means.
        let mut reader = output.as_slice();
        let payload = frame::read_frame(&mut reader)
            .expect("reads")
            .expect("one frame");
        assert!(
            frame::read_frame(&mut reader).expect("clean eof").is_none(),
            "stdout carried more than one frame"
        );
        (code, decode_response(&payload).expect("decodes"))
    }

    /// Run one call with the host's own ABI.
    fn call(op: &str, payload: Value) -> (u8, Response) {
        call_request(&Request {
            abi: frame::abi_version(),
            id: "req-1".into(),
            op: op.to_string(),
            payload,
        })
    }

    #[test]
    fn initialize_answers_with_the_crates_own_negotiation_and_result() {
        // A supported request must be honoured, and the result must be the crate's own
        // serialization of the crate's own constructor.
        let (code, response) = call("initialize", json!({ "requested_version": "2025-06-18" }));
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(response.ok);
        assert_eq!(response.plugin, PLUGIN_NAME);
        assert_eq!(response.version, PLUGIN_VERSION);

        let answer = response.payload.expect("a payload");
        assert_eq!(answer["requested_version"], json!("2025-06-18"));
        assert_eq!(answer["requested_version_supported"], json!(true));
        assert_eq!(answer["negotiated_version"], json!("2025-06-18"));

        // Compare against a direct call to the crate, which is the only check that can
        // distinguish a delegation from a canned answer.
        let expected =
            InitializeResult::new(PLUGIN_NAME, PLUGIN_VERSION, negotiate(Some("2025-06-18")));
        assert_eq!(
            answer["initialize_result"],
            serde_json::to_value(&expected).expect("serialises")
        );

        // And the wire keys are the crate's, not this plugin's spelling.
        let result = &answer["initialize_result"];
        assert_eq!(result["protocolVersion"], json!("2025-06-18"));
        assert_eq!(result["serverInfo"]["name"], json!(PLUGIN_NAME));
        assert_eq!(result["serverInfo"]["version"], json!(PLUGIN_VERSION));
        assert_eq!(result["capabilities"]["tools"]["listChanged"], json!(false));
        assert!(result["capabilities"]["resources"].is_null());
    }

    #[test]
    fn an_unsupported_version_is_answered_with_the_default_and_the_downgrade_is_reported() {
        // The crate's documented behaviour: an unsupported request gets *a* version, not
        // the one it asked for. `requested_version_supported` is the only field that says so.
        let (code, response) = call("initialize", json!({ "requested_version": "1999-01-01" }));
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["requested_version"], json!("1999-01-01"));
        assert_eq!(
            answer["requested_version_supported"],
            json!(false),
            "the client must be able to see that its request was not honoured"
        );
        assert_eq!(
            answer["negotiated_version"],
            json!(nau_mcp::protocol::DEFAULT_PROTOCOL_VERSION)
        );
        assert_ne!(
            answer["negotiated_version"], answer["requested_version"],
            "the negotiation must not echo an unsupported request"
        );
        assert_eq!(
            answer["initialize_result"]["protocolVersion"], answer["negotiated_version"],
            "the result carries the version that was negotiated"
        );

        // No request at all: nothing to support, and the default version.
        let (code, response) = call("initialize", Value::Null);
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["requested_version"], Value::Null);
        assert_eq!(answer["requested_version_supported"], Value::Null);
        assert_eq!(
            answer["negotiated_version"],
            json!(nau_mcp::protocol::DEFAULT_PROTOCOL_VERSION)
        );
    }

    #[test]
    fn initialize_reports_the_server_identity_it_used_and_accepts_instructions() {
        let (code, response) = call(
            "initialize",
            json!({
                "requested_version": "2024-11-05",
                "server_name": "example-mcp",
                "server_version": "9.9.9",
                "instructions": "read the tool list first",
            }),
        );
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        let result = &answer["initialize_result"];
        assert_eq!(result["serverInfo"]["name"], json!("example-mcp"));
        assert_eq!(result["serverInfo"]["version"], json!("9.9.9"));
        assert_eq!(result["instructions"], json!("read the tool list first"));
    }

    #[test]
    fn rpc_reports_a_valid_request_exactly_as_the_crate_parsed_it() {
        let value = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {} });
        let expected = parse_request(value.clone()).expect("the fixture is a valid request");

        let (code, response) = call("rpc", json!({ "request": value }));
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["parsed"], json!(true));
        assert_eq!(answer["id"], json!(7));
        assert_eq!(answer["method"], json!("tools/list"));
        assert_eq!(answer["is_notification"], json!(false));
        assert_eq!(answer["has_valid_version"], json!(true));
        assert_eq!(answer["params_kind"], json!("an object"));
        assert_eq!(answer["error"], Value::Null);
        assert_eq!(
            answer["request"],
            serde_json::to_value(&expected).expect("serialises"),
            "the reported request must be the crate's own serialization"
        );
    }

    #[test]
    fn rpc_reports_a_parse_failure_as_the_crates_own_id_and_error_pair() {
        // A parse failure is the verdict the op was asked for, so it is an answer -- and
        // the crate's whole `(RequestId, RpcError)` pair must survive the frame.
        let value = json!(5);
        let (expected_id, expected_error) =
            parse_request(value.clone()).expect_err("a bare number is not a request");
        assert_eq!(
            expected_error.code,
            nau_mcp::rpc::error_code::INVALID_REQUEST
        );

        let (code, response) = call("rpc", json!({ "request": value }));
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(
            response.ok,
            "answering 'this request is invalid' is not a plugin failure"
        );
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["parsed"], json!(false));
        assert_eq!(
            answer["id"],
            serde_json::to_value(&expected_id).expect("serialises"),
            "the id the parser reported must reach the host verbatim"
        );
        assert_eq!(
            answer["error"],
            serde_json::to_value(&expected_error).expect("serialises"),
            "the crate's RpcError must reach the host verbatim, including its code"
        );
        assert_eq!(answer["error"]["code"], json!(-32600));
        assert!(answer["method"].is_null());
        assert!(answer["request"].is_null());
    }

    #[test]
    fn a_request_with_the_wrong_jsonrpc_literal_still_parses_and_says_so() {
        // `parse_request` deserializes; it does not check the version literal. That is a
        // separate call, and the answer must not let a host mistake one for the other.
        let (code, response) = call(
            "rpc",
            json!({ "request": { "jsonrpc": "1.0", "id": "a", "method": "x" } }),
        );
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(
            answer["parsed"],
            json!(true),
            "the crate parses this; the version check is a different function"
        );
        assert_eq!(answer["has_valid_version"], json!(false));
        assert_eq!(answer["id"], json!("a"));

        // A notification has no id, which deserializes to `RequestId::Null`.
        let (code, response) = call(
            "rpc",
            json!({ "request": { "jsonrpc": "2.0", "method": "notifications/ready" } }),
        );
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["parsed"], json!(true));
        assert_eq!(answer["is_notification"], json!(true));
        assert_eq!(answer["id"], Value::Null);
    }

    #[test]
    fn rpc_refuses_a_payload_that_is_not_the_shape_this_op_documents() {
        // The payload's shape is refused; the *request's* validity is answered.
        let (code, response) = call("rpc", json!([1, 2, 3]));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_NOT_OBJECT));

        let (code, response) = call("rpc", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_RPC_PAYLOAD));
        assert!(
            response.message.expect("a message").contains("request"),
            "the refusal must name the missing field"
        );
    }

    #[test]
    fn capabilities_reports_the_catalogue_the_tier_and_no_false_green() {
        let (code, response) = call("capabilities", Value::Null);
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");

        assert_eq!(answer["plugin"], json!(PLUGIN_NAME));
        assert_eq!(answer["version"], json!(PLUGIN_VERSION));
        assert_eq!(answer["tier"], json!("official"));
        assert_eq!(
            answer["declared_capabilities"],
            json!(DECLARED_CAPABILITIES)
        );
        assert_eq!(
            answer["catalogue_capabilities"],
            json!(DECLARED_CAPABILITIES)
        );
        assert_eq!(answer["declared_matches_catalogue"], json!(true));
        assert_eq!(answer["implemented_ops"], json!(IMPLEMENTED_OPS));

        // Point 1 of the brief: the approvals come from the matrix, and the authority the
        // tier names for anything above the basic set is the vendor team. The declared
        // capability is basic, so it needs none -- and the answer says both things.
        assert_eq!(
            answer["required_approvals"],
            json!([]),
            "`plugin:message:send` is basic, so the matrix grants it unconditionally"
        );
        assert_eq!(
            answer["non_basic_capability_authorities"],
            json!(["vendor-team"]),
            "the official tier's authority above the basic set is the vendor team"
        );

        // The honest half: one capability declared, none exercised.
        assert_eq!(
            answer["declared_capabilities_backed_by_ops"],
            json!(false),
            "neither `initialize` nor `rpc` sends a bus message"
        );
        assert_eq!(
            answer["capability_backing"]["plugin:message:send"],
            json!([])
        );
        assert_eq!(
            answer["unbacked_declared_capabilities"],
            json!(DECLARED_CAPABILITIES)
        );
        assert_eq!(
            answer["ops_not_named_by_a_declared_capability"],
            json!(IMPLEMENTED_OPS)
        );
        assert_eq!(
            answer["op_delegation"]["rpc"],
            json!("nau_mcp::rpc::parse_request")
        );
    }

    #[test]
    fn the_binary_and_the_catalogue_agree_and_the_tier_rule_is_the_matrixs() {
        let entry = Official::find(PLUGIN_NAME).expect("the catalogue lists the mcp plugin");
        assert_eq!(entry.tier().expect("classifies"), Tier::Official);
        assert_eq!(entry.version, PLUGIN_VERSION);
        assert_eq!(entry.name, PLUGIN_NAME);
        assert_eq!(
            Tier::from_name(PLUGIN_NAME).expect("classifies"),
            Tier::Official
        );
        assert!(Tier::Official.requires_counter_signature());

        // `Official::approvals()` derives the same thing this binary derives, by asking the
        // same matrix. If either derivation changes, this fails.
        let catalogue_approvals: Vec<(String, String)> = entry
            .approvals()
            .expect("the catalogue entry is holdable at its tier")
            .into_iter()
            .map(|(capability, authority)| {
                (
                    capability.as_str().to_string(),
                    authority.label().to_string(),
                )
            })
            .collect();
        assert_eq!(
            catalogue_approvals,
            Vec::<(String, String)>::new(),
            "nothing this entry declares needs an approval"
        );

        // The tier rule itself, pinned directly against the matrix: a non-basic official
        // capability is approval-gated by the vendor team, and a kernel capability is
        // refused outright with no approval path.
        assert_eq!(
            Capability::EconomySettle.decision(Tier::Official),
            Grant::RequiresApproval(nau_plugin::capability::Approval::VendorTeam)
        );
        assert!(matches!(
            Capability::KernelPolicyWrite.decision(Tier::Official),
            Grant::Refused { .. }
        ));
    }

    #[test]
    fn every_declared_capability_has_a_backing_row_and_every_row_names_a_real_capability() {
        for capability in DECLARED_CAPABILITIES {
            assert!(
                CAPABILITY_BACKING
                    .iter()
                    .any(|(name, _)| *name == capability),
                "`{capability}` is declared with no backing row"
            );
        }
        for (name, ops) in CAPABILITY_BACKING {
            let parsed =
                Capability::parse(name).expect("the row names a capability the matrix knows");
            assert_eq!(parsed.as_str(), name);
            assert_eq!(parsed.decision(Tier::Official), Grant::Always);
            for op in ops {
                assert!(IMPLEMENTED_OPS.contains(op), "`{op}` is not implemented");
            }
            assert_eq!(capability_backing(name), ops);
        }
        for (op, _) in OP_DELEGATION {
            assert!(
                IMPLEMENTED_OPS.iter().any(|known| *known == op),
                "`{op}` has a delegation entry but is not implemented"
            );
        }
        assert_eq!(CAPABILITY_BACKING.len(), DECLARED_CAPABILITIES.len());
    }

    #[test]
    fn every_implemented_op_is_dispatched_and_every_other_op_is_refused_by_name() {
        for op in IMPLEMENTED_OPS {
            let (_, response) = call(op, json!({}));
            assert_ne!(
                response.code.as_deref(),
                Some(payload::CODE_UNKNOWN_OPERATION),
                "`{op}` is listed as implemented but was refused as unknown"
            );
        }
        let (code, response) = call("rank", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(
            response.code.as_deref(),
            Some(payload::CODE_UNKNOWN_OPERATION)
        );
        let message = response.message.expect("a message");
        assert!(
            message.contains("initialize") && message.contains("rpc"),
            "the known ops must be listed: {message}"
        );
    }

    #[test]
    fn no_diagnostic_quoted_back_to_the_host_can_exceed_the_bound() {
        // Every refusal this op can produce is bounded, whether or not serde chosen to echo
        // the caller's value into it.
        let long = "m".repeat(MAX_DIAGNOSTIC_CHARS * 4);
        for payload in [
            json!([1, 2, 3]),
            json!({ "requested_version": 5 }),
            json!({ "server_name": true }),
            json!({ "instructions": 7 }),
            json!({ "request": { "jsonrpc": 5 } }),
            json!({ "request": { "id": [] } }),
            json!({ "op": long }),
        ] {
            let (_, response) = call("initialize", payload.clone());
            if let Some(message) = response.message {
                assert!(
                    message.chars().count() <= MAX_DIAGNOSTIC_CHARS + 1,
                    "{} characters is not bounded: {message}",
                    message.chars().count()
                );
            }
            let (_, response) = call("rpc", payload);
            if let Some(message) = response.message {
                assert!(
                    message.chars().count() <= MAX_DIAGNOSTIC_CHARS + 1,
                    "{} characters is not bounded: {message}",
                    message.chars().count()
                );
            }
        }
    }

    #[test]
    fn an_abi_from_the_future_is_refused_rather_than_guessed() {
        let (code, response) = call_request(&Request {
            abi: "9.0".into(),
            id: "req-1".into(),
            op: "capabilities".into(),
            payload: Value::Null,
        });
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(frame::CODE_ABI_MISMATCH));
        assert!(response.message.expect("a message").contains("9.0"));
    }

    #[test]
    fn an_unreadable_frame_is_not_a_refusal_and_a_request_that_is_not_json_is() {
        let mut wire = Vec::new();
        frame::write_frame(&mut wire, b"not json at all").expect("writes");
        let mut output = Vec::new();
        let code = run(&mut wire.as_slice(), &mut output);
        assert_eq!(code, EXIT_REFUSED);
        let payload = frame::read_frame(&mut output.as_slice())
            .expect("reads")
            .expect("one frame");
        assert_eq!(
            decode_response(&payload).expect("decodes").code.as_deref(),
            Some(frame::CODE_NOT_JSON)
        );

        // An oversized frame is refused from its prefix, before anything is answered.
        let mut output = Vec::new();
        assert_eq!(
            run(&mut &[0x00, 0xA0, 0x00, 0x00][..], &mut output),
            EXIT_IO
        );
        assert!(output.is_empty());

        // A truncated frame is not a refusal either.
        let mut output = Vec::new();
        assert_eq!(run(&mut &[0u8, 0, 0, 8, b'{'][..], &mut output), EXIT_IO);
        assert!(output.is_empty());

        // A clean EOF before any frame: nothing asked, nothing answered.
        let mut output = Vec::new();
        assert_eq!(run(&mut &[][..], &mut output), EXIT_IO);
        assert!(output.is_empty());
    }
}
