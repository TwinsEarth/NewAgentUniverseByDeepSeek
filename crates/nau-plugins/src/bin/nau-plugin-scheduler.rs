//! `nau-plugin-scheduler` — the official (T1) plugin for task scheduling.
//!
//! `nau_plugins::official::OFFICIALS` names this plugin "Task scheduling and load
//! balancing", and the only thing a scheduler may decide without a second rule book is what
//! the **kernel's own domain model** says about a task: whether it is well formed, whether
//! its signature holds, whether it has expired, and whether a lifecycle transition is
//! legal. So this binary delegates every one of those questions to `nau-core` and
//! **re-derives none of them**:
//!
//! * its `validate` op calls [`Task::validate`], [`Task::validate_and_verify`],
//!   [`Task::is_expired`], [`TaskSpec::gaps`], [`VerificationPolicy::quorum`] and
//!   [`TaskId::parse`], and reports each outcome as that call returned it;
//! * its `transition` op calls [`TaskState::can_transition_to`], [`TaskState::transition`]
//!   and [`TaskState::is_terminal`];
//! * its `capabilities` op reports the catalogue's declaration next to what this binary
//!   implements and derives the tier's approvals from [`Capability::decision`].
//!
//! # Protocol
//!
//! ```text
//! stdin:  u32_be(len) || {"abi":"3.2","id":"req-1","op":"validate","payload":{…}}
//! stdout: u32_be(len) || {"abi":"3.2","id":"req-1",
//!                         "plugin":"com.twinsearth.official.scheduler",
//!                         "version":"1.0.0","ok":true,"payload":{…}}
//! ```
//!
//! One frame in, one frame out, then exit. stdout carries **only** frames; every
//! diagnostic goes to stderr, because a stray `println!` is a protocol corruption and this
//! binary has no other way to talk to its host.
//!
//! ## `validate`
//!
//! ```json
//! { "task": { …a serialized `nau_core::Task`… }, "now": 1700000000, "verify_signature": true }
//! ```
//!
//! `task` is required; `now` and `verify_signature` are optional and each gates exactly one
//! question. The answer reports the model's verdicts side by side, never merged:
//!
//! ```json
//! {
//!   "id": "task-1", "id_valid": true, "id_reason": null,
//!   "state": "open",
//!   "spec": { … }, "required_skills": [ … ], "budget_minor": 50000000,
//!   "deadline": null, "verification": { "kind": "committee", "n": 4, "f": 1 },
//!   "quorum": 3, "quorum_reason": null,
//!   "spec_gaps": [],
//!   "valid": true, "reason": null,
//!   "expired": false,
//!   "signature_checked": true, "signature_valid": true, "signature_reason": null
//! }
//! ```
//!
//! **An invalid task is an answer, not a plugin refusal.** The op was asked "is this task
//! valid?", so `ok: true` with `valid: false` and the model's own reason is the answer;
//! refusing would turn the op's purpose into an error. `expired`, `signature_valid` and
//! `quorum` are `null` when the caller did not ask for them.
//!
//! **What `valid` does and does not cover** — this is the part worth reading, because the
//! three verdicts are deliberately not one boolean:
//!
//! * `valid` is [`Task::validate`]: the spec (goal, context, at least one acceptance
//!   criterion and one step, length caps), a non-empty `required_skills` of legal ids, a
//!   positive budget, the verification policy's `n >= 3f+1` relation, the `spec.owner` ↔
//!   `requester_key` binding, and `deadline > signed_at` when a deadline is set.
//! * `valid` does **not** cover the signature. That is [`Task::validate_and_verify`], run
//!   only when `verify_signature` is true, and reported as its own pair.
//! * `valid` does **not** cover `id`: [`Task::validate`] never looks at it. `id_valid` is
//!   [`TaskId::parse`], the kernel's own id validator, called here because `serde` builds a
//!   `TaskId` from any string without consulting it. A task can therefore be `valid: true`
//!   and `id_valid: false`, and the answer says so rather than folding the two together.
//! * `validate_and_verify` covers the signature and the DID↔key binding but **not**
//!   freshness: it calls [`nau_core::domain::Verifiable::verify`], not
//!   [`nau_core::domain::Verifiable::verify_fresh`]. The deadline is a separate question,
//!   answered by `expired` from [`Task::is_expired`] when `now` is supplied. So
//!   `signature_valid: true` and `expired: true` can both hold, and a host that checks only
//!   one of them is checking half of what it thinks it is.
//!
//! ## `transition`
//!
//! ```json
//! { "task_id": "task-1", "from": "matched", "to": "running" }
//! ```
//!
//! ```json
//! { "task_id": "task-1", "from": "matched", "to": "running",
//!   "from_terminal": false, "legal_edge": true, "applied": "running", "reason": null }
//! ```
//!
//! An illegal transition is again an answer: `applied` is `null` and `reason` is the
//! model's own [`NauError::InvalidTransition`] message.
//!
//! **`legal_edge` and `applied` can disagree, and that is the model's design rather than a
//! bug here.** [`TaskState::can_transition_to`] has no self-edges — a state cannot
//! transition to itself — while [`TaskState::transition`] returns `Ok(next)` when
//! `from == to`, treating a repeat as a no-op. Both are called and both are reported, so a
//! host that needs the strict table reads `legal_edge` and a host that needs the applied
//! state reads `applied`.
//!
//! ## `capabilities`
//!
//! Takes no arguments. Returns the plugin's identity and version, the tier derived from its
//! name, the catalogue's capability set, this binary's declaration, whether the two agree,
//! the approvals the official tier needs for what is declared, the authorities that tier
//! names for non-basic capabilities, the ops this binary implements, which op (if any)
//! exercises each declared capability, and which crate function each op delegates to.
//!
//! # Exit codes
//!
//! `0` answered, `1` answered with `ok: false`, `2` the frame itself could not be read or
//! written — the convention of the four plugins before this one, unchanged.
//!
//! # Fail-closed choices
//!
//! * an unknown op, an incompatible `abi` and a payload of the wrong shape are each a typed
//!   refusal, never an empty success;
//! * an invalid `task_id` is refused using the kernel's own [`TaskId::parse`] message,
//!   rather than echoed back as if it were an identifier the kernel would accept;
//! * unknown *keys* inside a payload are tolerated (the frame envelope's
//!   additive-within-a-major rule); an unknown state name is not, because it would silently
//!   become a different lifecycle question;
//! * a diagnostic echoed back to the host is bounded, because an error string built from
//!   caller-supplied JSON is how a log becomes an attack surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_core::{Task, TaskId, TaskState};
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
const PLUGIN_NAME: &str = "com.twinsearth.official.scheduler";

/// The version this binary reports, which is the catalogue entry's version rather than the
/// workspace's. A test asserts the two are equal, so a catalogue bump that forgets this
/// constant fails instead of shipping a plugin that lies about its own version.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named in [`OP_DELEGATION`]
/// is listed here, so this table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 3] = ["capabilities", "transition", "validate"];

/// The capability set this binary's manifest declares.
///
/// `plugin:message:send` is what the catalogue entry for this plugin names
/// ([`nau_plugins::official::OFFICIALS`]), and it is one of the three capabilities every
/// loadable tier holds by construction — so the official tier's approval machinery is not
/// triggered by this declaration at all. That is the accurate state, and the answer says so
/// with an empty `required_approvals` rather than by inventing a capability this plugin
/// does not need.
const DECLARED_CAPABILITIES: [&str; 1] = ["plugin:message:send"];

/// Which implemented op exercises each declared capability.
///
/// Empty, and that is the honest state rather than a placeholder: validation and lifecycle
/// transitions are computations over a caller-supplied task, and neither sends anything on
/// the plugin bus. Reporting an op here would be a claim that this binary does that
/// capability's work, which it does not.
const CAPABILITY_BACKING: [(&str, &[&str]); 1] = [("plugin:message:send", &[])];

/// Which crate function each implemented op delegates to, as `(op, target)`.
///
/// Reported in the `capabilities` answer so a host can see the delegation rather than
/// having to trust a description of it.
const OP_DELEGATION: [(&str, &str); 3] = [
    ("capabilities", "nau_plugins::official::OFFICIALS"),
    (
        "transition",
        "nau_core::domain::task::TaskState::{can_transition_to, transition, is_terminal}",
    ),
    (
        "validate",
        "nau_core::domain::task::{Task::validate, Task::validate_and_verify, Task::is_expired, \
         TaskSpec::gaps, VerificationPolicy::quorum, TaskId::parse}",
    ),
];

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "`validate` and `transition` delegate to nau_core's own domain validation \
                     and lifecycle code; neither sends a message on the plugin bus, so the one \
                     declared capability is declared but not exercised and \
                     declared_capabilities_backed_by_ops is false. The declared set is the \
                     catalogue's, and `plugin:message:send` is a basic capability, so the \
                     official tier requires no approval for it: required_approvals is empty \
                     because the matrix grants it unconditionally, not because the derivation \
                     was skipped. An invalid task or an illegal transition is reported as an \
                     answer with the model's own reason, not as a plugin refusal. `valid` is \
                     Task::validate only: it does not cover the id, the signature or freshness, \
                     which are reported separately as id_valid, signature_valid and expired.";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: a payload is not a JSON object.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: a `validate` payload is an object but not the shape this op documents.
const CODE_VALIDATE_PAYLOAD: &str = "scheduler_validate_payload_invalid";
/// Error code: a `transition` payload is an object but not the shape this op documents.
const CODE_TRANSITION_PAYLOAD: &str = "scheduler_transition_payload_invalid";
/// Error code: the supplied task id is one the kernel's own parser refuses.
const CODE_TASK_ID: &str = "scheduler_task_id_invalid";
/// Error code: this binary and the official catalogue disagree about its own identity.
const CODE_CAPABILITIES: &str = "scheduler_capabilities_unavailable";

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

/// The `validate` payload, as the kernel's validators consume it.
///
/// Deliberately not `deny_unknown_fields`: the frame envelope is additive within a major,
/// and a payload that refused new keys would break that promise one layer down.
#[derive(Debug, Deserialize)]
struct ValidateRequest {
    /// The task to validate.
    task: Task,
    /// The clock, when the caller wants the deadline question answered.
    #[serde(default)]
    now: Option<u64>,
    /// Whether to also verify the requester's signature.
    #[serde(default)]
    verify_signature: bool,
}

/// The `transition` payload: one lifecycle edge, named by the task it belongs to.
#[derive(Debug, Deserialize)]
struct TransitionRequest {
    /// The task the transition belongs to. Used in the model's refusal message, and
    /// re-validated with the kernel's own parser because `serde` does not.
    task_id: TaskId,
    /// The state the task is in.
    from: TaskState,
    /// The state the caller wants to move it to.
    to: TaskState,
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
        "validate" => match validate(&request.payload) {
            Ok(answer) => Response::ok(&request, PLUGIN_NAME, PLUGIN_VERSION, answer),
            Err(refusal) => refusal_from(refusal, &request),
        },
        "transition" => match transition(&request.payload) {
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

/// Report what the kernel's own validators say about one task.
fn validate(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `validate` payload must be a JSON object carrying `task` (and optionally \
                 `now` and `verify_signature`), found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: ValidateRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_VALIDATE_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;
    let task = request.task;

    // The delegation, call by call: each question goes to the kernel's own function and
    // each answer is reported as that function returned it. Nothing is folded together.
    let (valid, reason) = match task.validate() {
        Ok(()) => (true, None),
        Err(err) => (false, Some(bounded(&err.to_string()))),
    };

    // `Task::validate` never looks at the id, so the kernel's id validator is called
    // separately. `serde` builds a `TaskId` from any string without consulting it.
    let (id_valid, id_reason) = match TaskId::parse(task.id.as_str()) {
        Ok(_) => (true, None),
        Err(err) => (false, Some(bounded(&err.to_string()))),
    };

    let (quorum, quorum_reason) = match task.verification.quorum() {
        Ok(value) => (Some(value), None),
        Err(err) => (None, Some(bounded(&err.to_string()))),
    };

    // Only asked for when the caller asked: a signature verdict that was not requested must
    // not be reported as if it had been checked.
    let (signature_valid, signature_reason) = if request.verify_signature {
        match task.validate_and_verify() {
            Ok(()) => (Some(true), None),
            Err(err) => (Some(false), Some(bounded(&err.to_string()))),
        }
    } else {
        (None, None)
    };

    let expired = request.now.map(|now| task.is_expired(now));

    Ok(json!({
        "id": task.id.as_str(),
        "id_valid": id_valid,
        "id_reason": id_reason,
        "state": task.state,
        "spec": task.spec,
        "required_skills": task.required_skills,
        "budget_minor": task.budget.minor(),
        "deadline": task.deadline,
        "verification": task.verification,
        "quorum": quorum,
        "quorum_reason": quorum_reason,
        "spec_gaps": task.spec.gaps(),
        "valid": valid,
        "reason": reason,
        "expired": expired,
        "signature_checked": request.verify_signature,
        "signature_valid": signature_valid,
        "signature_reason": signature_reason,
    }))
}

/// Report what the kernel's own lifecycle table says about one transition.
fn transition(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `transition` payload must be a JSON object carrying `task_id`, `from` and \
                 `to`, found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: TransitionRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_TRANSITION_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;

    // The kernel's own id parser, because `serde`'s is not one: `TaskId` is transparent
    // over a `String`, so a payload could otherwise name a task the model would refuse.
    let task_id = TaskId::parse(request.task_id.as_str()).map_err(|err| Refusal {
        code: CODE_TASK_ID,
        message: bounded(&err.to_string()),
    })?;

    let from = request.from;
    let to = request.to;

    // Two real calls, reported side by side. They disagree on a repeat (`from == to`):
    // `can_transition_to` has no self-edges, while `transition` treats a repeat as a no-op.
    let legal_edge = from.can_transition_to(to);
    let (applied, reason) = match from.transition(to, &task_id) {
        Ok(next) => (Some(next), None),
        Err(err) => (None, Some(bounded(&err.to_string()))),
    };

    Ok(json!({
        "task_id": task_id.as_str(),
        "from": from,
        "to": to,
        "from_terminal": from.is_terminal(),
        "legal_edge": legal_edge,
        "applied": applied,
        "reason": reason,
    }))
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
    use nau_core::domain::Verifiable;
    use nau_core::{Identity, Money, TaskSpec, VerificationPolicy};
    use nau_plugins::frame::{decode_response, Request};

    const SIGNED_AT: u64 = 1_700_000_000;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed(&[seed; 32])
    }

    /// A real, signed task: the only fixture that can distinguish delegation from a re-run.
    fn signed_task(requester: &Identity) -> Task {
        signed_task_with(requester, None)
    }

    /// A signed task with a deadline. The deadline is part of what the signature covers, so
    /// it has to be set before signing rather than patched in afterwards.
    fn signed_task_with(requester: &Identity, deadline: Option<u64>) -> Task {
        let mut task = Task::draft(
            TaskId::parse("task-1").expect("a valid id"),
            TaskSpec {
                goal: "translate".into(),
                context: "en->zh".into(),
                done: vec!["all sections".into()],
                todo: vec!["translate".into()],
                trace: None,
                owner: requester.did(),
            },
            vec!["translation".into()],
            Money::from_minor(50_000_000),
            deadline,
            VerificationPolicy::Committee { n: 4, f: 1 },
            requester.public_key(),
            SIGNED_AT,
            1,
        );
        task.sign(requester).expect("the test task signs");
        task
    }

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
    fn validate_reports_exactly_what_the_kernels_validators_said() {
        let requester = identity(1);
        let task = signed_task(&requester);

        let (code, response) = call(
            "validate",
            json!({ "task": &task, "now": SIGNED_AT + 10, "verify_signature": true }),
        );
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(response.ok);
        assert_eq!(response.plugin, PLUGIN_NAME);
        assert_eq!(response.version, PLUGIN_VERSION);

        let answer = response.payload.expect("a payload");

        // Every verdict compared against a direct call to the same kernel function.
        assert_eq!(answer["valid"], json!(task.validate().is_ok()));
        assert_eq!(
            answer["signature_valid"],
            json!(task.validate_and_verify().is_ok())
        );
        assert_eq!(answer["expired"], json!(task.is_expired(SIGNED_AT + 10)));
        assert_eq!(
            answer["spec_gaps"],
            serde_json::to_value(task.spec.gaps()).expect("serialises")
        );
        assert_eq!(
            answer["quorum"],
            serde_json::to_value(task.verification.quorum().expect("in range"))
                .expect("serialises")
        );
        assert_eq!(answer["valid"], json!(true));
        assert_eq!(answer["reason"], Value::Null);
        assert_eq!(answer["signature_checked"], json!(true));
        assert_eq!(answer["spec_gaps"], json!([]));

        // The field projection, from the task's own fields.
        assert_eq!(answer["id"], json!("task-1"));
        assert_eq!(answer["id_valid"], json!(true));
        assert_eq!(answer["state"], json!("open"));
        assert_eq!(answer["budget_minor"], json!(50_000_000));
        assert_eq!(answer["required_skills"], json!(["translation"]));
        assert_eq!(answer["deadline"], Value::Null);
        assert_eq!(answer["verification"]["kind"], json!("committee"));
        assert_eq!(answer["quorum"], json!(3));
        assert_eq!(
            answer["spec"],
            serde_json::to_value(&task.spec).expect("serialises")
        );
    }

    #[test]
    fn an_invalid_task_is_answered_with_the_models_reason_rather_than_refused() {
        // The op exists to answer "is this valid?", so "no" is a success with a verdict.
        let requester = identity(1);
        let mut task = signed_task(&requester);
        task.spec.goal = "   ".into();

        let (code, response) = call("validate", json!({ "task": task }));
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(
            response.ok,
            "an invalid task must not become a plugin failure"
        );
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["valid"], json!(false));
        let reason = answer["reason"].as_str().expect("a reason");
        assert!(
            reason.contains("goal must not be empty"),
            "the model's own reason must reach the host: {reason}"
        );
        let gaps = answer["spec_gaps"].as_array().expect("an array");
        assert!(
            gaps.iter()
                .any(|gap| gap.as_str().is_some_and(|g| g.contains("goal"))),
            "the gap list is the model's own: {gaps:?}"
        );

        // And a task whose budget is zero is refused by the model, not by this plugin.
        let mut broke = signed_task(&requester);
        broke.budget = Money::from_minor(0);
        let (code, response) = call("validate", json!({ "task": broke }));
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["valid"], json!(false));
        assert!(
            answer["reason"]
                .as_str()
                .expect("a reason")
                .contains("budget"),
            "{answer}"
        );
    }

    #[test]
    fn the_three_verdicts_are_separate_and_a_task_can_pass_one_and_fail_another() {
        let requester = identity(1);

        // (1) A signature is not checked unless it is asked for.
        let task = signed_task(&requester);
        let (code, response) = call("validate", json!({ "task": task }));
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["signature_checked"], json!(false));
        assert_eq!(
            answer["signature_valid"],
            Value::Null,
            "an unchecked signature must not be reported as verified"
        );

        // (2) A tampered task is structurally valid and fails verification, which is exactly
        // what `validate_and_verify` is for.
        let mut tampered = signed_task(&requester);
        tampered.spec.context = "changed after signing".into();
        let (code, response) = call(
            "validate",
            json!({ "task": &tampered, "verify_signature": true }),
        );
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(
            answer["valid"],
            json!(true),
            "the tampering left every structural rule satisfied"
        );
        assert_eq!(answer["signature_valid"], json!(false));
        assert!(
            answer["signature_reason"]
                .as_str()
                .expect("a reason")
                .contains("signature"),
            "{answer}"
        );

        // (3) The id is not covered by `Task::validate` at all. A task the kernel's own id
        // parser refuses is still structurally valid, and the answer says both.
        let bad_id = signed_task(&requester);
        let mut value = serde_json::to_value(&bad_id).expect("serialises");
        value["id"] = json!("bad id! with spaces");
        let (code, response) = call("validate", json!({ "task": value }));
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["id_valid"], json!(false));
        assert!(
            answer["id_reason"]
                .as_str()
                .expect("a reason")
                .contains("may only contain"),
            "the kernel's own id message must reach the host: {answer}"
        );
        assert_eq!(
            answer["valid"],
            json!(true),
            "`Task::validate` never looks at the id, and this answer must not pretend it does"
        );

        // (4) The deadline is a separate question from the signature: `validate_and_verify`
        // calls `verify`, not `verify_fresh`, so both can be true at once. The deadline is
        // part of the signed payload, so it is set before signing -- patching it afterwards
        // would (correctly) invalidate the signature instead.
        let late = signed_task_with(&requester, Some(SIGNED_AT + 100));
        let (code, response) = call(
            "validate",
            json!({ "task": &late, "now": SIGNED_AT + 200, "verify_signature": true }),
        );
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["expired"], json!(true));
        assert_eq!(
            answer["signature_valid"],
            json!(true),
            "verification does not enforce the deadline; `expired` is where that lives"
        );
        assert_eq!(answer["valid"], json!(true));

        // Without `now`, the deadline question was not asked and is not answered.
        let (code, response) = call("validate", json!({ "task": late }));
        assert_eq!(code, EXIT_OK);
        assert_eq!(response.payload.expect("a payload")["expired"], Value::Null);
    }

    #[test]
    fn transition_reports_the_legal_edge_and_the_applied_state_side_by_side() {
        // A legal edge: both the table and the application agree.
        let (code, response) = call(
            "transition",
            json!({ "task_id": "task-1", "from": "matched", "to": "running" }),
        );
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["legal_edge"], json!(true));
        assert_eq!(answer["applied"], json!("running"));
        assert_eq!(answer["reason"], Value::Null);
        assert_eq!(answer["from_terminal"], json!(false));

        // An illegal edge: the model's own `InvalidTransition` message, as an answer.
        let (code, response) = call(
            "transition",
            json!({ "task_id": "task-1", "from": "settled", "to": "open" }),
        );
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["legal_edge"], json!(false));
        assert_eq!(answer["applied"], Value::Null);
        assert_eq!(answer["from_terminal"], json!(true));
        let reason = answer["reason"].as_str().expect("a reason");
        assert!(
            reason.contains("invalid state transition") && reason.contains("task-1"),
            "the model's own message must reach the host: {reason}"
        );

        // The repeat case: the table has no self-edge, while `transition` treats `from == to`
        // as a no-op. Both calls are reported so neither reading is hidden.
        let (code, response) = call(
            "transition",
            json!({ "task_id": "task-1", "from": "running", "to": "running" }),
        );
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(
            answer["legal_edge"],
            json!(false),
            "`can_transition_to` has no self-edges"
        );
        assert_eq!(
            answer["applied"],
            json!("running"),
            "`transition` treats a repeat as a no-op, and that disagreement is the model's"
        );
        assert_eq!(answer["reason"], Value::Null);
    }

    #[test]
    fn a_committee_whose_arithmetic_overflows_is_refused_by_the_model_not_wrapped() {
        // The checked-arithmetic fix, reaching a host: `f = u32::MAX` makes `2f+1` and
        // `3f+1` unrepresentable. The model reports both, and this op must not turn either
        // into a wrapped number.
        let requester = identity(1);
        let task = signed_task(&requester);
        let mut value = serde_json::to_value(&task).expect("serialises");
        value["verification"] = json!({ "kind": "committee", "n": u32::MAX, "f": u32::MAX });

        let (code, response) = call("validate", json!({ "task": value }));
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["valid"], json!(false));
        assert!(
            answer["reason"]
                .as_str()
                .expect("a reason")
                .contains("3f+1"),
            "the model's overflow refusal must reach the host: {answer}"
        );
        assert_eq!(
            answer["quorum"],
            Value::Null,
            "an unrepresentable quorum must not be wrapped into a number"
        );
        assert!(
            answer["quorum_reason"]
                .as_str()
                .expect("a reason")
                .contains("overflows"),
            "{answer}"
        );
    }

    #[test]
    fn a_task_id_the_kernel_refuses_is_refused_with_the_kernels_own_message() {
        let (code, response) = call(
            "transition",
            json!({ "task_id": "bad id!", "from": "matched", "to": "running" }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_TASK_ID));
        assert!(
            response
                .message
                .expect("a message")
                .contains("may only contain"),
            "the kernel's own id message must be the refusal"
        );

        // An empty id is refused by the same parser.
        let (code, response) = call(
            "transition",
            json!({ "task_id": "", "from": "matched", "to": "running" }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_TASK_ID));
    }

    #[test]
    fn a_payload_of_the_wrong_shape_is_refused_rather_than_guessed() {
        let (code, response) = call("validate", json!([1, 2, 3]));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_NOT_OBJECT));

        // `task` is required: a missing key is a refusal naming the field.
        let (code, response) = call("validate", json!({ "now": 1 }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_VALIDATE_PAYLOAD));
        assert!(
            response.message.expect("a message").contains("task"),
            "the refusal must name the missing field"
        );

        // A state name the kernel does not have is a refusal, not a different question.
        let (code, response) = call(
            "transition",
            json!({ "task_id": "task-1", "from": "flying", "to": "running" }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_TRANSITION_PAYLOAD));

        let (code, response) = call("transition", json!({ "task_id": "task-1" }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_TRANSITION_PAYLOAD));
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

        // The approvals come from the matrix; the declared capability is basic, so it needs
        // none, and the tier's authority above the basic set is the vendor team.
        assert_eq!(answer["required_approvals"], json!([]));
        assert_eq!(
            answer["non_basic_capability_authorities"],
            json!(["vendor-team"])
        );

        // The honest half: one capability declared, none exercised.
        assert_eq!(
            answer["declared_capabilities_backed_by_ops"],
            json!(false),
            "neither `validate` nor `transition` sends a bus message"
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
            answer["op_delegation"]["validate"],
            json!(
                "nau_core::domain::task::{Task::validate, Task::validate_and_verify, \
                 Task::is_expired, TaskSpec::gaps, VerificationPolicy::quorum, TaskId::parse}"
            )
        );
    }

    #[test]
    fn the_binary_and_the_catalogue_agree_and_the_tier_rule_is_the_matrixs() {
        let entry = Official::find(PLUGIN_NAME).expect("the catalogue lists the scheduler plugin");
        assert_eq!(entry.tier().expect("classifies"), Tier::Official);
        assert_eq!(entry.version, PLUGIN_VERSION);
        assert_eq!(entry.name, PLUGIN_NAME);
        assert_eq!(
            Tier::from_name(PLUGIN_NAME).expect("classifies"),
            Tier::Official
        );

        // The catalogue's own derivation of the approvals, next to this binary's: both ask
        // the same matrix, so a change in either place fails here.
        assert_eq!(
            entry.approvals().expect("holdable at its tier"),
            Vec::new(),
            "nothing this entry declares needs an approval"
        );
        assert_eq!(
            Capability::EconomySettle.decision(Tier::Official),
            Grant::RequiresApproval(nau_plugin::capability::Approval::VendorTeam)
        );
        assert!(matches!(
            Capability::KernelIsolationConfigure.decision(Tier::Official),
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
            message.contains("validate") && message.contains("transition"),
            "the known ops must be listed: {message}"
        );
    }

    #[test]
    fn a_diagnostic_built_from_caller_json_stays_bounded() {
        // An unknown lifecycle state makes serde_json quote the caller's string, which is
        // the caller's, so it must not decide how much this plugin writes.
        let long = "x".repeat(MAX_DIAGNOSTIC_CHARS * 4);
        let (code, response) = call(
            "transition",
            json!({ "task_id": "task-1", "from": long, "to": "running" }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_TRANSITION_PAYLOAD));
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
