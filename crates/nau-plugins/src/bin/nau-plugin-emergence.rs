//! `nau-plugin-emergence` — the official (T1) plugin for `com.twinsearth.official.swarm`.
//!
//! # What this plugin is, and what it deliberately is not
//!
//! Upstream `TwinsEarth/agent-universe` **v3.5.0** ships `com.twinsearth.official.swarm-emergence`
//! as a **Python entry module** run in a sandbox
//! (`gsn-core/src/plugin/official/mod.rs`, `EMERGENCE_ENTRY`, a port of
//! `swarm/emergence.rs::EmergenceDetector::detect`). Its `detect` op takes
//! `history` (rows of `[timestamp, throughput, latency]`), a caller-supplied `threshold`
//! (default `0.5`) and a `window_size` (default `3`), and reports two signals when the
//! **mean** throughput or latency of the most recent window differs from the preceding
//! window by more than the threshold:
//!
//! | upstream signal | criterion |
//! |---|---|
//! | `collaboration` | `(recent_throughput - older_throughput) / older_throughput > threshold` |
//! | `load_balancing` | `(older_latency - recent_latency) / older_latency > threshold` |
//!
//! **This binary does not implement that criterion, and it therefore returns no
//! verdict.** That is the whole design, and the reason is not laziness:
//!
//! * No crate in this workspace computes the statistic that criterion is defined over.
//!   `nau-consensus` decides *votes*, `nau-market` ranks *bids* and smooths *reputation*,
//!   `nau-agent` holds layered memory — none of them detects a change between two windows of
//!   a metric series, and there is no emergence detector anywhere in `crates/`.
//!   Re-implementing upstream's arithmetic here would be exactly the "second set of rules"
//!   this project exists to refuse;
//! * the criterion's decisive parameter is **caller-supplied**. A plugin that took
//!   `threshold` from its caller and answered "emergence detected" would be reporting the
//!   caller's own number back with a verdict attached — the same defect this workspace
//!   removed from shared memory, where a publisher-supplied weight used to decide its own
//!   ranking (`nau_agent::experience`). Borrowing it for emergence would be a regression
//!   dressed as a port.
//!
//! So `detect` narrows to what it can say honestly and completely: **the input was
//! understood, and the judgement was not made.** It validates the shape upstream documents,
//! echoes the parameters it read, records the upstream criterion it did *not* apply, and
//! answers `detected: null` with `available: false`.
//!
//! # The empty list that must not be returned
//!
//! Upstream answers "no emergence" with `signals: []`. An op that returned `signals: []`
//! here would be indistinguishable from a real negative judgement, which is the one thing
//! this plugin has not earned. The answer therefore **omits** `signals` entirely and lists
//! it in `not_reported`, so a host cannot read "no signals" where "no judgement" is meant.
//! `judgement: "not_made"` is explicit, and a test feeds a history that *would* satisfy
//! upstream's criterion and asserts that the verdict is still absent.
//!
//! # Protocol
//!
//! ```text
//! stdin:  u32_be(len) || {"abi":"3.2","id":"req-1","op":"detect","payload":{…}}
//! stdout: u32_be(len) || {"abi":"3.2","id":"req-1",
//!                         "plugin":"com.twinsearth.official.swarm",
//!                         "version":"1.0.0","ok":true,"payload":{…}}
//! ```
//!
//! One frame in, one frame out, then exit. stdout carries **only** frames; every diagnostic
//! goes to stderr, because a stray `println!` is a protocol corruption and this binary has
//! no other way to talk to its host.
//!
//! ## `detect`
//!
//! ```json
//! { "history": [ [1700000000, 100.0, 220.0], [1700000001, 101.0, 219.0] ],
//!   "threshold": 0.5, "window_size": 3 }
//! ```
//!
//! `history` is required and must be rows of exactly three numbers (upstream's positional
//! shape). `threshold` and `window_size` default to `0.5` and `3` like upstream's, and are
//! echoed back — read, never used to judge.
//!
//! ```json
//! {
//!   "available": false, "judgement": "not_made", "detected": null,
//!   "reason": "no_emergence_detector_in_this_workspace",
//!   "input": { "history_len": 2, "window_size": 3, "threshold": 0.5, "row_width": 3 },
//!   "upstream": { "implementation": "…", "port_of": "…", "signals": [...],
//!                 "threshold_source": "caller-supplied" },
//!   "not_reported": ["signals"]
//! }
//! ```
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
//! The catalogue declares `swarm:consensus` for this entry, and at the official tier that
//! capability is `RequiresApproval(VendorTeam)` — so `required_approvals` is non-empty here,
//! unlike the plugins whose declared capability is basic. `detect` runs **no** consensus and
//! **no** emergence judgement, so `capability_backing` is empty for it and
//! `declared_capabilities_backed_by_ops` is `false`: the declaration is the catalogue's, and
//! this binary does not exercise it. Saying otherwise would be the false green this project
//! built the field to catch.
//!
//! # Exit codes
//!
//! `0` answered, `1` answered with `ok: false`, `2` the frame itself could not be read or
//! written — the convention of the seven plugins before this one, unchanged.
//!
//! # Fail-closed choices
//!
//! * an unknown op, an incompatible `abi` and a payload of the wrong shape are each a typed
//!   refusal, never an empty success;
//! * a malformed history is refused rather than silently ignored, because "the plugin
//!   understood your input" is the one thing this op does claim;
//! * a diagnostic echoed back to the host is bounded, because an error string built from
//!   caller-supplied JSON is how a log becomes an attack surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process::ExitCode;

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
const PLUGIN_NAME: &str = "com.twinsearth.official.swarm";

/// The version this binary reports, which is the catalogue entry's version rather than the
/// workspace's. A test asserts the two are equal, so a catalogue bump that forgets this
/// constant fails instead of shipping a plugin that lies about its own version.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named in [`OP_DELEGATION`]
/// is listed here, so this table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 2] = ["capabilities", "detect"];

/// The capability set this binary's manifest declares.
///
/// `swarm:consensus` is what the catalogue entry for this plugin names
/// ([`nau_plugins::official::OFFICIALS`]). At the official tier the matrix resolves it to
/// `RequiresApproval(VendorTeam)`, which the answer reports — and which this binary does
/// **not** exercise, because it runs no consensus.
const DECLARED_CAPABILITIES: [&str; 1] = ["swarm:consensus"];

/// Which implemented op exercises each declared capability.
///
/// Empty, and that is the honest state rather than a placeholder: `detect` makes no
/// judgement and touches no committee, so nothing here exercises `swarm:consensus`.
/// Reporting an op would be a claim that this binary does that capability's work.
const CAPABILITY_BACKING: [(&str, &[&str]); 1] = [("swarm:consensus", &[])];

/// Which crate function each implemented op delegates to, as `(op, target)`.
///
/// `detect` delegates to **nothing**: it is the op this plugin refuses to fake. The entry
/// says so rather than naming a function it does not call.
const OP_DELEGATION: [(&str, &str); 2] = [
    (
        "capabilities",
        "nau_plugin::capability::Capability::decision",
    ),
    (
        "detect",
        "(nothing: no emergence detector exists in this workspace)",
    ),
];

/// The upstream criterion this binary does not apply, as a machine-readable record.
///
/// Read from `gsn-core/src/plugin/official/mod.rs` at tag `v3.5.0` (`EMERGENCE_ENTRY`),
/// which is a port of `swarm/emergence.rs::EmergenceDetector::detect`. Recording it is the
/// point: a host that wants the judgement can see exactly what it would have to implement,
/// and can see that this plugin did not invent a substitute.
const UPSTREAM_IMPLEMENTATION: &str = "gsn-core/src/plugin/official/mod.rs @ v3.5.0, \
                                       EMERGENCE_ENTRY (Python entry module)";

/// The module upstream ported its criterion from.
const UPSTREAM_PORT_OF: &str = "swarm/emergence.rs::EmergenceDetector::detect";

/// The signal names upstream reports.
const UPSTREAM_SIGNALS: [&str; 2] = ["collaboration", "load_balancing"];

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "`detect` performs no emergence judgement: this workspace has no \
                     emergence detector, and the upstream criterion takes its decisive \
                     threshold from the caller, so copying it would be a second rule book \
                     rather than a delegation. The op validates upstream's input shape and \
                     answers available: false with judgement: not_made, and it omits the \
                     `signals` field entirely because an empty list would read as a real \
                     negative verdict. The catalogue declares `swarm:consensus` for this \
                     entry, which the official tier holds only with vendor-team approval; \
                     this binary runs no consensus and so does not exercise it, and \
                     declared_capabilities_backed_by_ops is false for that reason.";

/// The reason code carried when no judgement was made.
const REASON_NO_DETECTOR: &str = "no_emergence_detector_in_this_workspace";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: a payload is not a JSON object.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: a `detect` payload is an object but not the shape upstream documents.
const CODE_DETECT_PAYLOAD: &str = "emergence_detect_payload_invalid";
/// Error code: this binary and the official catalogue disagree about its own identity.
const CODE_CAPABILITIES: &str = "emergence_capabilities_unavailable";

/// Longest diagnostic quoted back to the host, in characters.
///
/// The message is written into a frame the host logs, and a `serde_json` diagnostic for a
/// wrong type quotes the offending value — which the caller chose. Bounding it keeps a
/// caller from deciding how much text this plugin writes.
const MAX_DIAGNOSTIC_CHARS: usize = 512;

/// Upstream's default for `threshold`.
fn default_threshold() -> f64 {
    0.5
}

/// Upstream's default for `window_size`.
fn default_window_size() -> usize {
    3
}

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

/// The `detect` payload, in the shape upstream documents.
///
/// The row is a positional triple, exactly as upstream reads it, so a caller that has an
/// upstream payload can send it unchanged. Deliberately not `deny_unknown_fields`: the frame
/// envelope is additive within a major.
#[derive(Debug, Deserialize)]
struct DetectRequest {
    /// Rows of `[timestamp, throughput, latency]`.
    history: Vec<[f64; 3]>,
    /// Upstream's `threshold`. Defaults to upstream's default, and is never used to judge.
    #[serde(default = "default_threshold")]
    threshold: f64,
    /// Upstream's `window_size`. Defaults to upstream's default, and is never used to judge.
    #[serde(default = "default_window_size")]
    window_size: usize,
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
        "detect" => match detect(&request.payload) {
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

/// Read upstream's input shape, and report that no emergence judgement was made.
///
/// No statistic is computed over `history` and `threshold` is never compared to anything.
/// The function validates the shape (so a caller learns whether the plugin understood the
/// input at all) and returns a verdict-free answer.
fn detect(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `detect` payload must be a JSON object carrying `history` (and optionally \
                 `threshold` and `window_size`), found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: DetectRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_DETECT_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;

    // No aggregation, no comparison, no signal list. The two upstream signal names are
    // reported as the criterion that was *not* applied, never as results.
    Ok(json!({
        "available": false,
        "judgement": "not_made",
        "detected": Value::Null,
        "reason": REASON_NO_DETECTOR,
        "input": {
            "history_len": request.history.len(),
            "window_size": request.window_size,
            "threshold": request.threshold,
            "row_width": 3,
        },
        "upstream": {
            "implementation": UPSTREAM_IMPLEMENTATION,
            "port_of": UPSTREAM_PORT_OF,
            "signals": UPSTREAM_SIGNALS,
            "criterion": "mean throughput growth (collaboration) or mean latency improvement \
                          (load_balancing) between the last window and the preceding window, \
                          compared against a caller-supplied threshold",
            "threshold_source": "caller-supplied",
        },
        "not_reported": ["signals"],
    }))
}

/// The authorities this tier names for capabilities above the basic set, derived from the
/// matrix rather than written down.
///
/// For the official tier this is `["vendor-team"]`. It is reported even though this binary
/// exercises none of it: "what would this tier need approval for?" is a question a host can
/// answer from the answer rather than from this crate's source.
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
    // For this declaration the matrix requires the vendor team, so the list is not empty --
    // and it is derived rather than restated, so a matrix change shows up here.
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
    // exercised", which here is the substantive fact: this plugin runs no consensus.
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
    fn detect_reports_no_judgement_rather_than_an_empty_signal_list() {
        let (code, response) = call(
            "detect",
            json!({
                "history": [
                    [1_700_000_000, 100.0, 220.0],
                    [1_700_000_001, 101.0, 219.0],
                    [1_700_000_002, 99.0, 221.0],
                ],
            }),
        );
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(response.ok);
        assert_eq!(response.plugin, PLUGIN_NAME);
        assert_eq!(response.version, PLUGIN_VERSION);

        let answer = response.payload.expect("a payload");
        assert_eq!(answer["available"], json!(false));
        assert_eq!(answer["judgement"], json!("not_made"));
        assert_eq!(answer["detected"], Value::Null);
        assert_eq!(answer["reason"], json!(REASON_NO_DETECTOR));

        // The critical shape: no `signals` key at all. An empty list would be
        // indistinguishable from a real negative verdict.
        assert!(
            answer.get("signals").is_none(),
            "the answer must not carry a signals field: {answer}"
        );
        assert_eq!(answer["not_reported"], json!(["signals"]));

        // The input was read and echoed, so "understood" is a claim with evidence.
        assert_eq!(answer["input"]["history_len"], json!(3));
        assert_eq!(answer["input"]["row_width"], json!(3));
        // Upstream's defaults, reported as read.
        assert_eq!(answer["input"]["window_size"], json!(3));
        assert_eq!(answer["input"]["threshold"], json!(0.5));
    }

    #[test]
    fn a_history_that_would_satisfy_the_upstream_criterion_still_gets_no_verdict() {
        // Throughput doubles between the two windows: upstream's `collaboration` signal
        // would fire with threshold 0.5. This plugin must still refuse to say so -- if it
        // ever started computing the statistic, this test would fail loudly.
        let history = json!([
            [1_700_000_000, 10.0, 400.0],
            [1_700_000_001, 10.0, 400.0],
            [1_700_000_002, 30.0, 100.0],
            [1_700_000_003, 30.0, 100.0],
        ]);
        let (code, response) = call(
            "detect",
            json!({ "history": history, "threshold": 0.5, "window_size": 2 }),
        );
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");

        assert_eq!(answer["detected"], Value::Null);
        assert_eq!(answer["judgement"], json!("not_made"));
        assert!(
            answer.get("signals").is_none(),
            "a satisfiable input must not make this plugin produce signals: {answer}"
        );
        // The parameters were read, which is all they are used for.
        assert_eq!(answer["input"]["window_size"], json!(2));
        assert_eq!(answer["input"]["threshold"], json!(0.5));

        // And the criterion it did not apply is recorded, so a host knows what is missing.
        assert_eq!(
            answer["upstream"]["signals"],
            json!(["collaboration", "load_balancing"])
        );
        assert_eq!(
            answer["upstream"]["threshold_source"],
            json!("caller-supplied")
        );
        assert!(
            answer["upstream"]["implementation"]
                .as_str()
                .expect("a string")
                .contains("v3.5.0"),
            "the upstream revision must be named: {answer}"
        );
    }

    #[test]
    fn detect_refuses_an_input_shape_it_cannot_claim_to_have_understood() {
        // A row that is not a triple.
        let (code, response) = call("detect", json!({ "history": [[1, 2]] }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_DETECT_PAYLOAD));

        // A row whose third element is not a number.
        let (code, response) = call("detect", json!({ "history": [[1, 2, "fast"]] }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_DETECT_PAYLOAD));

        // `history` is required: a missing key is a refusal naming the field, not an
        // empty history that would answer as if it had been supplied.
        let (code, response) = call("detect", json!({ "threshold": 0.5 }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_DETECT_PAYLOAD));
        assert!(
            response.message.expect("a message").contains("history"),
            "the refusal must name the missing field"
        );

        // A non-object payload is a different refusal.
        let (code, response) = call("detect", json!([1, 2, 3]));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_NOT_OBJECT));

        // An empty history is a valid shape: this op does not need samples to say that it
        // made no judgement, and inventing a minimum would be inventing a criterion.
        let (code, response) = call("detect", json!({ "history": [] }));
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["input"]["history_len"], json!(0));
        assert_eq!(answer["detected"], Value::Null);
    }

    #[test]
    fn capabilities_reports_the_approval_the_catalogue_requires_and_no_false_green() {
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

        // `swarm:consensus` is not a basic capability, so the official tier holds it only
        // with the vendor team's approval -- derived from the matrix here, not restated.
        let approvals = answer["required_approvals"].as_array().expect("an array");
        assert_eq!(approvals.len(), 1, "{approvals:?}");
        assert_eq!(approvals[0]["capability"], json!("swarm:consensus"));
        assert_eq!(approvals[0]["authority"], json!("vendor-team"));
        assert_eq!(
            answer["non_basic_capability_authorities"],
            json!(["vendor-team"])
        );

        // The honest half: the declared capability is not exercised by anything here.
        assert_eq!(
            answer["declared_capabilities_backed_by_ops"],
            json!(false),
            "`detect` runs no consensus, so it cannot back `swarm:consensus`"
        );
        assert_eq!(answer["capability_backing"]["swarm:consensus"], json!([]));
        assert_eq!(
            answer["unbacked_declared_capabilities"],
            json!(DECLARED_CAPABILITIES)
        );
        assert_eq!(
            answer["ops_not_named_by_a_declared_capability"],
            json!(IMPLEMENTED_OPS)
        );
    }

    #[test]
    fn the_binary_and_the_catalogue_agree_and_the_tier_rule_is_the_matrixs() {
        let entry = Official::find(PLUGIN_NAME).expect("the catalogue lists the swarm entry");
        assert_eq!(entry.tier().expect("classifies"), Tier::Official);
        assert_eq!(entry.version, PLUGIN_VERSION);
        assert_eq!(entry.name, PLUGIN_NAME);
        assert_eq!(
            entry.approvals().expect("holdable at its tier"),
            vec![(
                Capability::SwarmConsensus,
                nau_plugin::capability::Approval::VendorTeam
            )],
            "the catalogue's own derivation must be the vendor team"
        );
        assert_eq!(
            Capability::SwarmConsensus.decision(Tier::Official),
            Grant::RequiresApproval(nau_plugin::capability::Approval::VendorTeam)
        );
        assert!(matches!(
            Capability::SwarmConsensus.decision(Tier::ThirdParty),
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
            assert!(ops.is_empty(), "this plugin backs nothing yet");
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
        let (code, response) = call("tally", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(
            response.code.as_deref(),
            Some(payload::CODE_UNKNOWN_OPERATION)
        );
        let message = response.message.expect("a message");
        assert!(
            message.contains("detect"),
            "the known ops must be listed: {message}"
        );
    }

    #[test]
    fn a_diagnostic_built_from_caller_json_stays_bounded() {
        // A long string where a number is expected: serde quotes it, and the caller chose it.
        let long = "x".repeat(MAX_DIAGNOSTIC_CHARS * 4);
        let (code, response) = call("detect", json!({ "history": [[1, 2, long]] }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_DETECT_PAYLOAD));
        let message = response.message.expect("a message");
        assert!(
            message.chars().count() <= MAX_DIAGNOSTIC_CHARS + 1,
            "{} characters is not bounded",
            message.chars().count()
        );
        assert!(message.ends_with('…'), "{message}");
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
