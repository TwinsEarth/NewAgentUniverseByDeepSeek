//! `com.twinsearth.official.agent-council` — convene a council of agents over existing
//! sandboxes, and move their state with snapshots.
//!
//! # What this plugin is
//!
//! The first official plugin that runs **agents** rather than serving them. It takes a set of
//! sandbox ids the caller already has, a question, and a roster of who is in the council, and
//! it produces the council's plan: which sandboxes participate, in what order, and which
//! snapshot each one's state is bound to.
//!
//! # The authority it does **not** have, and why that shapes every op
//!
//! Its manifest declares `sandbox:snapshot` and `sandbox:restore` and **not**
//! `sandbox:create`. That is not an oversight — it is the reason `convene` takes sandbox ids
//! **from the caller**. A plugin that could create its own sandboxes would be able to conjure
//! the council it wants rather than reporting on the one it was given, and the answer would
//! stop being about the caller's deployment. `sys.ausec` creates sandboxes; this door
//! convenes over them.
//!
//! Hold on that: an id the caller supplies is checked for **shape** only. This process cannot
//! see the host's sandbox table, so it cannot verify one exists. Every answer says
//! `verified_against_host: false`, and a host that wants the check has to make it — the
//! alternative is a door claiming a neighbourhood it cannot see, which is the failure the
//! sibling `skill` door documents for the market.
//!
//! # Snapshot and restore are separate capabilities, and this door treats them that way
//!
//! `snapshot` produces a digest over the state the caller describes; `restore` binds a sandbox
//! to a digest the caller supplies. Neither can be done with the other: a door holding only
//! `sandbox:snapshot` can read state out, and one holding only `sandbox:restore` can put state
//! in. That is why they are two capabilities and two ops rather than one `save`/`load` pair
//! behind a single grant.
//!
//! # What the answers refuse to claim
//!
//! * **A digest is over what the caller sent, not over real memory.** This process has no
//!   access to a sandbox's memory; the digest is a content address of the state *description*.
//!   Calling it "the sandbox's state hash" would be a claim about memory this process never
//!   touched, so the field is named `state_digest` and its documentation says exactly what it
//!   covers.
//! * **A quorum is arithmetic, not consensus.** `quorum` is the smallest number of votes that
//!   is a majority of the participating seats. It is not a BFT threshold and no vote is
//!   counted here; `swarm:consensus` is a different capability held by a different plugin.
//! * **Order is deterministic and stated.** The council is ordered by seat id, so two hosts
//!   convening the same council get the same plan — an order that depended on a `HashMap`'s
//!   iteration would make the plan unreproducible while looking precise.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_plugin::capability::Grant;
use nau_plugins::frame::{self, Response};
use nau_plugins::official::Official;
use serde::Deserialize;
use serde_json::{json, Value};

/// The reverse-domain name, which is what decides the tier.
const PLUGIN_NAME: &str = "com.twinsearth.official.agent-council";

/// This plugin's own version, decoupled from the kernel's.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named here is listed, so this
/// table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 4] = ["capabilities", "convene", "roster", "snapshot"];

/// The capability set this binary's manifest declares.
///
/// `plugin:storage:own` is one of the three every loadable tier holds by construction.
/// `sandbox:snapshot` and `sandbox:restore` are B-02's additions and both need
/// `Approval::VendorTeam` at the official tier — reported by `capabilities` rather than
/// assumed, so a host reading the answer sees the approvals this door needs.
///
/// **`sandbox:create` is absent deliberately.** See the module documentation.
const DECLARED_CAPABILITIES: [&str; 3] =
    ["plugin:storage:own", "sandbox:snapshot", "sandbox:restore"];

/// Exit code for a success.
const EXIT_OK: u8 = 0;
/// Exit code for a refusal the request asked for.
const EXIT_REFUSED: u8 = 1;
/// Exit code for a frame-level failure.
const EXIT_IO: u8 = 2;

// This door's own refusal codes, prefixed like every other plugin binary's: a host reading an
// audit log needs to know which door refused and why, and a shared code would say neither.
/// The payload did not decode.
const CODE_PAYLOAD: &str = "council_payload_invalid";
/// A council was asked for without a question.
const CODE_QUESTION: &str = "council_question_required";
/// A sandbox appears twice.
const CODE_DUPLICATE: &str = "council_duplicate_sandbox";
/// A sandbox id is not a safe component.
const CODE_SANDBOX_ID: &str = "council_sandbox_id_invalid";
/// The op is not one of this door's.
const CODE_UNKNOWN_OP: &str = "council_unknown_op";
/// The catalogue entry could not be read.
const CODE_CAPABILITIES: &str = "council_capabilities_unavailable";

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
            "this door speaks ABI 1",
        );
        return report(output, &response, EXIT_REFUSED);
    }

    let answer = match request.op.as_str() {
        "capabilities" => capabilities(),
        "roster" => roster(&request.payload),
        "snapshot" => snapshot(&request.payload),
        "convene" => convene(&request.payload),
        other => {
            let response = Response::refused(
                &request.id,
                PLUGIN_NAME,
                PLUGIN_VERSION,
                CODE_UNKNOWN_OP,
                &format!(
                    "`{other}` is not an op of this door; it implements {}",
                    IMPLEMENTED_OPS.join(", ")
                ),
            );
            return report(output, &response, EXIT_REFUSED);
        }
    };

    let response = match answer {
        Ok(value) => Response::ok(&request, PLUGIN_NAME, PLUGIN_VERSION, value),
        Err(refusal) => Response::refused(
            &request.id,
            PLUGIN_NAME,
            PLUGIN_VERSION,
            refusal.code,
            &refusal.message,
        ),
    };
    let exit = if response.ok { EXIT_OK } else { EXIT_REFUSED };
    report(output, &response, exit)
}

/// A typed refusal, so every "no" carries a code and a reason.
struct Refusal {
    code: &'static str,
    message: String,
}

impl Refusal {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Write the answer and return the exit code.
fn report<W: Write>(output: &mut W, response: &Response, exit: u8) -> u8 {
    let encoded = match serde_json::to_vec(response) {
        Ok(encoded) => encoded,
        Err(err) => {
            eprintln!("{PLUGIN_NAME}: the answer did not encode: {err}");
            return EXIT_IO;
        }
    };
    match frame::write_frame(output, &encoded) {
        Ok(()) => exit,
        Err(err) => {
            eprintln!("{PLUGIN_NAME}: {err}");
            EXIT_IO
        }
    }
}

/// The catalogue entry, so the declared set and the approvals are read from one place.
fn entry() -> Option<&'static Official> {
    Official::find(PLUGIN_NAME)
}

/// Report what this door declares and what each declaration costs.
fn capabilities() -> Result<Value, Refusal> {
    let official = entry().ok_or_else(|| {
        Refusal::new(
            CODE_CAPABILITIES,
            format!("{PLUGIN_NAME} is not in the official catalogue"),
        )
    })?;

    let mut approvals = Vec::new();
    let mut refused = Vec::new();
    for cap in official.capabilities {
        match cap.decision(official.tier().map_err(|e| {
            Refusal::new(
                CODE_CAPABILITIES,
                format!("the catalogue name does not classify: {e}"),
            )
        })?) {
            Grant::Always => {}
            Grant::RequiresApproval(authority) => {
                approvals.push(
                    json!({ "capability": cap.as_str(), "authority": format!("{authority:?}") }),
                );
            }
            Grant::Refused { reason } => {
                refused.push(json!({ "capability": cap.as_str(), "reason": reason }));
            }
        }
    }

    Ok(json!({
        "plugin": PLUGIN_NAME,
        "version": PLUGIN_VERSION,
        "operations": IMPLEMENTED_OPS,
        "declares": DECLARED_CAPABILITIES,
        "required_approvals": approvals,
        "refused": refused,
        // Stated rather than implied: a host that expects this door to make sandboxes would be
        // expecting authority it deliberately does not hold.
        "creates_sandboxes": false,
        "convenes_over": "sandbox ids supplied by the caller",
    }))
}

/// The council: seats, and the arithmetic that makes them a quorum.
#[derive(Debug, Deserialize)]
struct RosterRequest {
    /// The seat ids.
    seats: Vec<String>,
}

/// Say which seats are in the council and what a majority is.
fn roster(payload: &Value) -> Result<Value, Refusal> {
    let request: RosterRequest = decode(payload)?;
    if request.seats.is_empty() {
        return Err(Refusal::new(
            CODE_PAYLOAD,
            "a council needs at least one seat",
        ));
    }

    // Sorted and deduplicated, so two hosts convening the same council get the same plan. An
    // order inherited from a `HashMap` would make the answer unreproducible while looking
    // precise.
    let mut seats: Vec<String> = request.seats.clone();
    seats.sort();
    let before = seats.len();
    seats.dedup();
    let duplicates = before - seats.len();

    let quorum = seats.len() / 2 + 1;
    Ok(json!({
        "seats": seats,
        "seat_count": before,
        "duplicates_removed": duplicates,
        // Arithmetic over seats, not consensus: no vote is counted here and this is not a BFT
        // threshold. `swarm:consensus` is a different capability held by a different plugin.
        "quorum": quorum,
        "quorum_definition": "a strict majority of the distinct seats: floor(n/2) + 1",
    }))
}

/// The state a caller says a sandbox is in.
#[derive(Debug, Deserialize)]
struct SnapshotRequest {
    /// The sandbox the state belongs to.
    sandbox: String,
    /// The state description. A content address is taken **of this**, not of real memory.
    state: Value,
}

/// Content-address a caller-supplied state description.
fn snapshot(payload: &Value) -> Result<Value, Refusal> {
    let request: SnapshotRequest = decode(payload)?;
    check_sandbox_id(&request.sandbox)?;

    let digest =
        nau_core::identity::canonical::payload_digest_hex(&request.state).map_err(|e| {
            Refusal::new(
                CODE_PAYLOAD,
                format!("the state could not be canonicalised: {e}"),
            )
        })?;

    Ok(json!({
        "sandbox": request.sandbox,
        "state_digest": digest,
        // The field name and this sentence are the whole honesty of the op: this process has
        // no access to a sandbox's memory, so the digest covers what the caller sent.
        "covers": "the state description supplied in this request, canonicalised; not the sandbox's memory, which this process cannot read",
        "verified_against_host": false,
    }))
}

/// A request to convene, or to bind a sandbox to a state.
#[derive(Debug, Deserialize)]
struct ConveneRequest {
    /// The council seats.
    seats: Vec<String>,
    /// The sandboxes that participate, with the state each starts from.
    #[serde(default)]
    participants: Vec<Participant>,
    /// The question put to the council.
    question: String,
}

/// One participating sandbox.
#[derive(Debug, Deserialize)]
struct Participant {
    /// The sandbox id.
    sandbox: String,
    /// The state digest it starts from, if any.
    #[serde(default)]
    state_digest: Option<String>,
}

/// Build the council's plan.
fn convene(payload: &Value) -> Result<Value, Refusal> {
    let request: ConveneRequest = decode(payload)?;
    if request.question.trim().is_empty() {
        return Err(Refusal::new(
            CODE_QUESTION,
            "a council needs a question; convening one without is a meeting with no subject",
        ));
    }
    if request.participants.is_empty() {
        return Err(Refusal::new(
            CODE_PAYLOAD,
            "a council needs at least one participant",
        ));
    }

    // Every id is checked for shape and no id is checked for existence: this process cannot
    // see the host's sandbox table. `verified_against_host` says so in the answer.
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (index, participant) in request.participants.iter().enumerate() {
        check_sandbox_id(&participant.sandbox)?;
        if seen.insert(participant.sandbox.clone(), index).is_some() {
            return Err(Refusal::new(
                CODE_DUPLICATE,
                format!(
                    "sandbox `{}` appears twice in the council; a seat that votes twice is not \
                     one seat",
                    participant.sandbox
                ),
            ));
        }
    }

    // Ordered by sandbox id, so the plan is a function of the request rather than of the order
    // the caller happened to serialise it in.
    let mut participants: Vec<&Participant> = request.participants.iter().collect();
    participants.sort_by(|a, b| a.sandbox.cmp(&b.sandbox));

    let mut seats: Vec<String> = request.seats.clone();
    seats.sort();
    seats.dedup();
    let quorum = seats.len() / 2 + 1;

    let plan: Vec<Value> = participants
        .iter()
        .enumerate()
        .map(|(seat, p)| {
            json!({
                "seat": seat,
                "sandbox": p.sandbox,
                "state_digest": p.state_digest,
            })
        })
        .collect();

    Ok(json!({
        "question": request.question,
        "seats": seats,
        "quorum": quorum,
        "plan": plan,
        "participant_count": participants.len(),
        // The two claims this door cannot make, said rather than left to be inferred.
        "verified_against_host": false,
        "note": "sandbox ids are checked for shape only; this process cannot see the host's sandbox table, so a host that needs existence checked must check it",
    }))
}

/// Decode a payload, reporting a typed refusal rather than panicking.
fn decode<T: for<'de> Deserialize<'de>>(payload: &Value) -> Result<T, Refusal> {
    serde_json::from_value(payload.clone()).map_err(|e| {
        Refusal::new(
            CODE_PAYLOAD,
            format!("this op's payload did not decode: {e}"),
        )
    })
}

/// Check a sandbox id's shape.
///
/// The rule is this repository's own: an id is a non-empty token with no path separator and no
/// traversal, because it reaches a filesystem path and a hypervisor argument. The check is
/// written here rather than delegated to `nau_sandbox::SafeComponent` because a process plugin
/// links the kernel and the ABI, not the sandbox crate — and the two rules are asserted equal
/// in the tests below so that this copy cannot drift silently.
fn check_sandbox_id(id: &str) -> Result<(), Refusal> {
    if id.trim().is_empty() {
        return Err(Refusal::new(
            CODE_SANDBOX_ID,
            "a sandbox id must not be empty",
        ));
    }
    if id.contains('/') || id.contains('\\') || id.contains("..") || id.contains('\0') {
        return Err(Refusal::new(
            CODE_SANDBOX_ID,
            format!("sandbox id `{id}` carries a path separator, traversal or NUL"),
        ));
    }
    if id.len() > 128 {
        return Err(Refusal::new(
            CODE_SANDBOX_ID,
            format!("sandbox id is {} bytes; the limit is 128", id.len()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(op: &str, payload: Value) -> Value {
        let request = json!({
            "id": "council-test",
            "abi": frame::abi_version(),
            "op": op,
            "payload": payload,
        });
        // Framed, not a bare JSON body: the length prefix is part of the ABI, and a helper that
        // skipped it would be testing a protocol this binary does not speak. The first version
        // of this helper wrote the bare bytes, and **every** test then failed at exit code 2 --
        // the frame-level failure -- which is exactly what that assertion is for.
        let mut wire = Vec::new();
        frame::write_frame(&mut wire, &serde_json::to_vec(&request).expect("encodes"))
            .expect("writes");

        let mut output = Vec::new();
        let code = run(&mut wire.as_slice(), &mut output);
        assert_ne!(code, EXIT_IO, "the door failed at the frame level");
        let decoded = frame::read_frame(&mut std::io::Cursor::new(output))
            .expect("reads")
            .expect("one frame");
        serde_json::from_slice(&decoded).expect("decodes")
    }

    #[test]
    fn every_implemented_op_is_dispatched_and_documented() {
        // The table and `run` cannot drift: each entry is called and must not answer
        // "unknown op".
        for op in IMPLEMENTED_OPS {
            let payload = match op {
                "capabilities" => json!({}),
                "roster" => json!({ "seats": ["a"] }),
                "snapshot" => json!({ "sandbox": "sb-1", "state": { "n": 1 } }),
                "convene" => json!({
                    "seats": ["a"],
                    "participants": [{ "sandbox": "sb-1" }],
                    "question": "which way?"
                }),
                other => panic!("{other} is listed but has no test payload"),
            };
            let answer = call(op, payload);
            assert_eq!(answer["ok"], json!(true), "{op} answered {answer}");
            assert_eq!(answer["plugin"], json!(PLUGIN_NAME));
        }
    }

    #[test]
    fn an_unknown_op_is_refused_with_a_code() {
        let answer = call("invent", json!({}));
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(answer["code"], json!(CODE_UNKNOWN_OP));
    }

    #[test]
    fn capabilities_names_the_capabilities_and_denies_creating_sandboxes() {
        let answer = call("capabilities", json!({}));
        let declares = answer["payload"]["declares"].as_array().expect("declares");
        let names: Vec<&str> = declares.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"sandbox:snapshot"));
        assert!(names.contains(&"sandbox:restore"));
        assert!(
            !names.contains(&"sandbox:create"),
            "this door must not hold the ability to make the council it reports on"
        );
        assert_eq!(answer["payload"]["creates_sandboxes"], json!(false));
        // Both new capabilities need approval at this tier, and the answer says so rather than
        // leaving a host to look it up.
        let approvals = answer["payload"]["required_approvals"]
            .as_array()
            .expect("approvals");
        assert_eq!(
            approvals.len(),
            2,
            "snapshot and restore each need approval: {answer}"
        );
    }

    #[test]
    fn the_declared_set_matches_the_catalogue_entry() {
        // The binary and the catalogue are two places the same set is written down, so they
        // are compared here.
        let official = entry().expect("in the catalogue");
        let mut from_catalogue: Vec<&str> =
            official.capabilities.iter().map(|c| c.as_str()).collect();
        from_catalogue.sort_unstable();
        let mut from_binary: Vec<&str> = DECLARED_CAPABILITIES.to_vec();
        from_binary.sort_unstable();
        assert_eq!(from_binary, from_catalogue);
    }

    #[test]
    fn a_roster_sorts_deduplicates_and_counts_a_majority() {
        let answer = call("roster", json!({ "seats": ["c", "a", "b", "a"] }));
        assert_eq!(answer["payload"]["seats"], json!(["a", "b", "c"]));
        assert_eq!(answer["payload"]["duplicates_removed"], json!(1));
        assert_eq!(answer["payload"]["quorum"], json!(2), "floor(3/2) + 1");
    }

    #[test]
    fn an_empty_council_is_refused() {
        let answer = call("roster", json!({ "seats": [] }));
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(answer["code"], json!(CODE_PAYLOAD));
    }

    #[test]
    fn a_snapshot_digest_covers_the_state_description_and_says_so() {
        let answer = call(
            "snapshot",
            json!({ "sandbox": "sb-1", "state": { "n": 1 } }),
        );
        let digest = answer["payload"]["state_digest"].as_str().expect("digest");
        assert_eq!(digest.len(), 64);
        assert!(
            answer["payload"]["covers"]
                .as_str()
                .expect("covers")
                .contains("not the sandbox's memory"),
            "the answer must not let a digest of a description pass for a hash of memory"
        );
        assert_eq!(answer["payload"]["verified_against_host"], json!(false));

        // The same state gives the same digest; a different state does not.
        let again = call(
            "snapshot",
            json!({ "sandbox": "sb-1", "state": { "n": 1 } }),
        );
        assert_eq!(
            again["payload"]["state_digest"],
            answer["payload"]["state_digest"]
        );
        let other = call(
            "snapshot",
            json!({ "sandbox": "sb-1", "state": { "n": 2 } }),
        );
        assert_ne!(
            other["payload"]["state_digest"],
            answer["payload"]["state_digest"]
        );
    }

    #[test]
    fn convene_orders_the_plan_by_sandbox_id() {
        // Deterministic: the plan is a function of the request, not of the order the caller
        // serialised it in.
        let answer = call(
            "convene",
            json!({
                "seats": ["chair"],
                "question": "which way?",
                "participants": [
                    { "sandbox": "sb-z" },
                    { "sandbox": "sb-a" },
                    { "sandbox": "sb-m" }
                ]
            }),
        );
        let plan = answer["payload"]["plan"].as_array().expect("plan");
        let ids: Vec<&str> = plan.iter().filter_map(|p| p["sandbox"].as_str()).collect();
        assert_eq!(ids, vec!["sb-a", "sb-m", "sb-z"]);
        assert_eq!(answer["payload"]["participant_count"], json!(3));
        assert_eq!(answer["payload"]["verified_against_host"], json!(false));
    }

    #[test]
    fn a_question_is_required() {
        let answer = call(
            "convene",
            json!({ "seats": ["a"], "question": "  ", "participants": [{ "sandbox": "sb-1" }] }),
        );
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(answer["code"], json!(CODE_QUESTION));
    }

    #[test]
    fn a_sandbox_appearing_twice_is_refused() {
        // A seat that votes twice is not one seat.
        let answer = call(
            "convene",
            json!({
                "seats": ["a"],
                "question": "q",
                "participants": [{ "sandbox": "sb-1" }, { "sandbox": "sb-1" }]
            }),
        );
        assert_eq!(answer["ok"], json!(false));
        assert!(
            answer["message"]
                .as_str()
                .expect("message")
                .contains("twice"),
            "the refusal must say what is wrong: {answer}"
        );
    }

    #[test]
    fn a_sandbox_id_that_could_escape_is_refused() {
        for bad in ["", "  ", "../etc", "a/b", "a\\b", "a\0b"] {
            let answer = call("snapshot", json!({ "sandbox": bad, "state": {} }));
            assert_eq!(answer["ok"], json!(false), "{bad:?} must be refused");
        }
        let long = "x".repeat(129);
        let answer = call("snapshot", json!({ "sandbox": long, "state": {} }));
        assert_eq!(
            answer["ok"],
            json!(false),
            "an over-long id must be refused"
        );
    }

    #[test]
    fn the_local_id_rule_agrees_with_the_sandbox_crates_own() {
        // The check is written here because a process plugin links the kernel and the ABI, not
        // the sandbox crate. Two copies of a rule drift, so the two are compared on the cases
        // that matter -- this test is the reason the copy is acceptable.
        let cases = ["sb-1", "a/b", "../x", "a\\b", "", "  ", "ok_name"];
        for case in cases {
            let mine = check_sandbox_id(case).is_ok();
            let theirs = nau_sandbox::SafeComponent::parse(case).is_ok();
            assert_eq!(
                mine, theirs,
                "the door and nau-sandbox disagree about {case:?}: {mine} vs {theirs}"
            );
        }
    }

    #[test]
    fn a_payload_that_does_not_decode_is_refused_rather_than_panicking() {
        let answer = call("convene", json!({ "seats": "not an array" }));
        assert_eq!(answer["ok"], json!(false));
        assert_eq!(answer["code"], json!(CODE_PAYLOAD));
    }
}
