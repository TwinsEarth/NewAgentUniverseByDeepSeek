//! `nau-plugin-reputation` — the first **third-party (T3) plugin that is an executable**.
//!
//! The process-plugin path was exercised by `nau-plugin-echo` (T3, no capability at all),
//! `nau-plugin-market` (T1) and `nau-plugin-swarm` (T2). What none of them exercises is the
//! tier the registration-and-review flow was actually built for: an ordinary reverse-domain
//! name that is **not** inside the vendor's reserved namespace, holding **nothing above the
//! basic capability set**, doing real delegated work. This binary is that plugin, and what
//! makes it count is narrow and checkable:
//!
//! * it is a real file a host can start, and it speaks the host ABI frame from
//!   [`nau_plugins::frame`] — the same codec `nau-plugin-echo`, `nau-plugin-market` and
//!   `nau-plugin-swarm` speak, not a second implementation of it;
//! * its name is `com.example.reputation`, which [`Tier::from_name`] classifies as
//!   [`Tier::ThirdParty`] and which is outside `com.twinsearth.`, so it is a name a third
//!   party could actually publish — and one the kernel would refuse if it pretended to the
//!   vendor's namespace;
//! * its `advise` op delegates to [`nau_market::reputation::Reputation`] — `record_settled`,
//!   `record_fault`, `record_clean` — and reports values that come from the model's own
//!   accessors (`overall_bps`, `overall`, `bps`, `is_eligible`), never recomputed here;
//! * its `capabilities` op reports the declared set next to what it implements, and says in
//!   a machine-readable field that **no declared capability is exercised by an op**, because
//!   for this plugin that is the truth rather than a placeholder.
//!
//! # Why the tier matters here
//!
//! T3 holds [`Capability::BASIC`] and nothing else: [`Capability::decision`] refuses every
//! other capability at this tier outright, and no approval can grant it. So the design is
//! narrowed to fit: `advise` neither writes an agent card nor settles an economy movement,
//! reads no lifecycle state, sends no bus message and touches no sandbox directory. It is a
//! pure computation over state the caller supplies, which is exactly what the basic set is
//! enough for. `capabilities` derives each decision from the kernel's own matrix at runtime
//! and reports the approvals the tier requires — which, for this declaration, is none.
//!
//! # Protocol
//!
//! ```text
//! stdin:  u32_be(len) || {"abi":"3.2","id":"req-1","op":"advise","payload":{…}}
//! stdout: u32_be(len) || {"abi":"3.2","id":"req-1",
//!                         "plugin":"com.example.reputation",
//!                         "version":"1.0.0","ok":true,"payload":{…}}
//! ```
//!
//! One frame in, one frame out, then exit. stdout carries **only** frames; every
//! diagnostic goes to stderr, because a stray `println!` is a protocol corruption and this
//! binary has no other way to talk to its host.
//!
//! ## `advise`
//!
//! The payload mirrors the model's **real** shape, because it was designed after reading
//! `reputation.rs` rather than before. A [`Reputation`] is six integers and deserializes
//! from six integers:
//!
//! ```json
//! {
//!   "reputation": { "quality": 5000, "speed": 5000, "honesty": 5000,
//!                   "availability": 5000, "settled": 0, "faults": 0 },
//!   "events": [
//!     { "kind": "settled", "latency_ratio_bps": 9000, "evidence_trustworthy": true },
//!     { "kind": "fault",   "severity_bps": 2500 },
//!     { "kind": "clean" }
//!   ],
//!   "min_overall_bps": 4000
//! }
//! ```
//!
//! `reputation` is required. `events` is optional and absent means "apply nothing", which
//! is the pure read the model is asked for; the list is applied **in the order given**,
//! because the three mutators are a state machine and their composition is not commutative.
//! `min_overall_bps` is optional because it is the parameter of one question: when it is
//! absent, `eligible` is `null` — the plugin does not invent a floor, and it does not answer
//! a question it was not asked.
//!
//! The answer:
//!
//! ```json
//! {
//!   "reputation": { …the mutated `nau_market::Reputation`… },
//!   "quality_bps": 5000, "speed_bps": 5000, "honesty_bps": 5000, "availability_bps": 5000,
//!   "settled": 0, "faults": 0,
//!   "overall_bps": 5000, "overall": 5000,
//!   "min_overall_bps": 4000, "eligible": true,
//!   "events_applied": 3
//! }
//! ```
//!
//! Every score field comes from a real accessor on the mutated value: the four dimensions
//! and the counters from the struct (via [`ReputationScore::bps`]), `overall_bps` from
//! `Reputation::overall_bps`, `overall` from `Reputation::overall`, `eligible` from
//! `Reputation::is_eligible`. Nothing is recomputed, and in particular the weighted sum is
//! never repeated here. `overall` is the [`ReputationScore`] that `overall()` returned,
//! serialized transparently as its integer; the two agree for any in-range state because
//! `overall()` is defined as `clamped(overall_bps() as u16)`, and a test asserts that
//! rather than assuming it.
//!
//! `events_applied` is this plugin's own bookkeeping — how many mutators it called — and is
//! named so that it cannot be mistaken for a field of the model.
//!
//! **Three of those mutators return `()`.** `record_settled`, `record_fault` and
//! `record_clean` mutate in place and return nothing, so "report what they returned" is
//! literally "report the struct they mutated" — which is what every field above does. The
//! one check this plugin adds that the model does not have is on the **incoming** state:
//! `ReputationScore` is `#[serde(transparent)]` over a `u16`, so `serde` builds one without
//! consulting `ReputationScore::from_bps`, and a payload could carry a score above the
//! documented `0..=10_000` that no constructor would produce. `advise` re-runs the model's
//! own `from_bps` over the four dimensions and refuses with `reputation_score_out_of_range`
//! and the model's own message. Event parameters are deliberately **not** pre-checked:
//! `record_fault` documents that it clamps `severity_bps`, and the speed target handles any
//! `latency_ratio_bps`, so a check there would be a rule the model does not have.
//!
//! **This op advises; it does not attest.** The reputation it reports is computed from the
//! state the *caller* supplied, and nothing on this path verifies who the caller is or
//! whether the events happened. A host that needs an authoritative reputation must take it
//! from wherever it is signed, not from this answer. The caveat is a field in the answer
//! (`advisory: true`), not only a sentence here.
//!
//! ## `capabilities`
//!
//! Takes no arguments. Returns the plugin's own name and version, the tier derived from
//! that name, whether that tier requires a vendor counter-signature, the declared
//! capability set, the approvals the matrix requires for it, the ops this binary
//! implements, which op (if any) exercises each declared capability, which crate function
//! each op delegates to, and whether the declaration is backed by the implementation.
//!
//! `declared_matches_catalogue` is `null`: this build has no third-party catalogue, so
//! there is nothing to compare the declaration against, and a `true` there would be a
//! false green.
//!
//! # Exit codes
//!
//! `0` answered, `1` answered with `ok: false`, `2` the frame itself could not be read or
//! written — `nau-plugin-echo`'s convention, unchanged by the three plugins before this
//! one. `2` means the binary is not speaking this ABI at all, which is a different repair
//! from "the plugin refused the call".
//!
//! # Fail-closed choices
//!
//! * an unknown op, an incompatible `abi` and a payload of the wrong shape are each a typed
//!   refusal, never an empty success;
//! * a score outside the model's documented range is refused with the model's own message
//!   rather than used to produce a number the model could not represent;
//! * unknown *keys* inside a payload are tolerated (the additive-within-a-major rule the
//!   frame envelope follows); an unknown event `kind` is not, because it would silently
//!   drop an update the caller believed it had recorded;
//! * a diagnostic echoed back to the host is bounded, because an error string built from
//!   caller-supplied JSON is how a log becomes an attack surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_core::domain::ReputationScore;
use nau_market::reputation::Reputation;
use nau_plugin::capability::{Capability, Grant};
use nau_plugin::tier::Tier;
use nau_plugins::frame::{self, Response};
use nau_plugins::payload;
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// The name this binary implements: an ordinary third-party reverse-domain name.
///
/// Deliberately **not** under `com.twinsearth.`. That prefix is reserved, and the kernel
/// refuses a name inside it that does not match a known tier prefix, so a third-party
/// plugin could not publish under it at all. The tier is derived from this name, so the
/// spelling is not cosmetic.
const PLUGIN_NAME: &str = "com.example.reputation";

/// The version this binary reports.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named in [`OP_DELEGATION`]
/// is listed here, so this table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 2] = ["advise", "capabilities"];

/// Which implemented op exercises each declared capability.
///
/// Every row is empty, and that is the honest current state rather than a placeholder:
/// the capability matrix has no reputation token, this plugin needs none, and `advise`
/// reads no lifecycle state, sends no bus message and touches no sandbox directory.
/// Listing an op here would be a claim that this binary does that capability's work,
/// which it does not.
const CAPABILITY_BACKING: [(&str, &[&str]); 3] = [
    ("plugin:lifecycle:read", &[]),
    ("plugin:message:send", &[]),
    ("plugin:storage:own", &[]),
];

/// Which crate function each implemented op delegates to, as `(op, target)`.
///
/// Reported in the `capabilities` answer so a host can see the delegation rather than
/// having to trust a description of it.
const OP_DELEGATION: [(&str, &str); 2] = [
    (
        "advise",
        "nau_market::reputation::Reputation::{record_settled, record_fault, record_clean, \
         overall_bps, overall, is_eligible}",
    ),
    (
        "capabilities",
        "nau_plugin::capability::Capability::decision",
    ),
];

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "`advise` delegates to nau_market::reputation::Reputation and reports that \
                     model's own accessors; it is a pure computation over caller-supplied \
                     state, so it needs no capability above the basic set and declares none. \
                     No implemented op exercises a declared capability: the capability matrix \
                     has no reputation token, and this binary reads no lifecycle state, sends \
                     no bus message and touches no sandbox directory, so \
                     declared_capabilities_backed_by_ops is false. The answer is advisory, not \
                     an attestation: the reputation is computed from the state the caller \
                     supplied and nothing on this path verifies the caller or the events. There \
                     is no third-party catalogue in this build, so declared_matches_catalogue \
                     is null rather than true.";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: an `advise` payload is not a JSON object.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: an `advise` payload is an object but not the shape the model needs.
const CODE_ADVISE_PAYLOAD: &str = "reputation_advise_payload_invalid";
/// Error code: the supplied reputation carries a score outside `0..=10_000`.
const CODE_SCORE_RANGE: &str = "reputation_score_out_of_range";
/// Error code: this binary cannot report its own capabilities.
const CODE_CAPABILITIES: &str = "reputation_capabilities_unavailable";

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

/// One reputation event, as the model's mutators actually consume it.
///
/// Internally tagged so that the `kind` the caller writes is the one this enum matches:
/// an unknown kind is a typed refusal naming the accepted ones, rather than an event the
/// caller believes was recorded.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Event {
    /// A task settled for this agent — `Reputation::record_settled`.
    Settled {
        /// Observed latency over the agent's own advertised p95, in basis points.
        latency_ratio_bps: u32,
        /// Whether the settlement's evidence was trustworthy.
        evidence_trustworthy: bool,
    },
    /// A dispute found against this agent — `Reputation::record_fault`.
    Fault {
        /// How severe the finding was, in basis points; the model clamps it.
        severity_bps: u16,
    },
    /// An honest outcome without a fault — `Reputation::record_clean`.
    Clean,
}

/// The `advise` payload, as the reputation model consumes it.
///
/// Deliberately not `deny_unknown_fields`: the frame envelope is additive within a major,
/// and a payload that refused new keys would break that promise one layer down.
#[derive(Debug, Deserialize)]
struct AdviseRequest {
    /// The state to advise on, deserialized as a [`Reputation`].
    reputation: Reputation,
    /// The events to apply, in order. Absent means none: a pure read.
    #[serde(default)]
    events: Vec<Event>,
    /// The eligibility floor, when the caller wants the eligibility question answered.
    #[serde(default)]
    min_overall_bps: Option<u32>,
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
        "advise" => match advise(&request.payload) {
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

/// Apply the payload's events to the payload's reputation and report the model's numbers.
fn advise(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "an `advise` payload must be a JSON object carrying `reputation` (and \
                 optionally `events` and `min_overall_bps`), found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: AdviseRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_ADVISE_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;
    let AdviseRequest {
        mut reputation,
        events,
        min_overall_bps,
    } = request;

    // `serde` builds a `ReputationScore` from any `u16` without consulting the model's
    // constructor, so re-run the model's own `from_bps` over the incoming state. This is
    // the only check this plugin adds, and its message is the model's.
    validate_scores(&reputation)?;

    // The delegation: the model's three real mutators, in the caller's order. They return
    // `()`, so their effect is read back off the struct below -- never recomputed from the
    // event list.
    for event in &events {
        match event {
            Event::Settled {
                latency_ratio_bps,
                evidence_trustworthy,
            } => reputation.record_settled(*latency_ratio_bps, *evidence_trustworthy),
            Event::Fault { severity_bps } => reputation.record_fault(*severity_bps),
            Event::Clean => reputation.record_clean(),
        }
    }

    // The model's own accessors, each called once on the mutated value.
    let overall_bps = reputation.overall_bps();
    let overall = reputation.overall();
    // The eligibility question is answered by the model's own rule, and only when the caller
    // asked it: `null` is an answer, while a defaulted floor would be an invented one.
    let eligible = min_overall_bps.map(|floor| reputation.is_eligible(floor));

    // The mutated state itself, serialized by its own `Serialize`, so a host can compare it
    // against a direct call to the model rather than against this plugin's projection.
    let state = serde_json::to_value(&reputation).map_err(|err| Refusal {
        code: CODE_ADVISE_PAYLOAD,
        message: bounded(&err.to_string()),
    })?;

    Ok(json!({
        "reputation": state,
        "quality_bps": reputation.quality.bps(),
        "speed_bps": reputation.speed.bps(),
        "honesty_bps": reputation.honesty.bps(),
        "availability_bps": reputation.availability.bps(),
        "settled": reputation.settled,
        "faults": reputation.faults,
        "overall_bps": overall_bps,
        "overall": overall,
        "min_overall_bps": min_overall_bps,
        "eligible": eligible,
        "events_applied": events.len(),
        "advisory": true,
    }))
}

/// Re-validate the four dimensions with the model's own range check.
///
/// `ReputationScore` is `#[serde(transparent)]`, so deserializing a [`Reputation`] bypasses
/// [`ReputationScore::from_bps`] — the constructor that is the documented way to reach a
/// score in `0..=10_000`. This delegates the check back to that constructor instead of
/// re-implementing the comparison, so the refusal message is the model's and cannot drift
/// from it.
fn validate_scores(reputation: &Reputation) -> std::result::Result<(), Refusal> {
    let dimensions = [
        ("quality", reputation.quality),
        ("speed", reputation.speed),
        ("honesty", reputation.honesty),
        ("availability", reputation.availability),
    ];
    for (name, score) in dimensions {
        if let Err(err) = ReputationScore::from_bps(score.bps()) {
            return Err(Refusal {
                code: CODE_SCORE_RANGE,
                message: format!("`{name}` is outside the model's range: {err}"),
            });
        }
    }
    Ok(())
}

/// The capability set this binary declares: the third-party tier's ceiling, and no more.
///
/// Derived from [`Capability::BASIC`] rather than spelled out as strings, so the declaration
/// cannot drift from the matrix that decides what the tier may hold.
fn declared_capabilities() -> Vec<&'static str> {
    Capability::BASIC.iter().map(|c| c.as_str()).collect()
}

/// What this binary declares, what the matrix says about it, and what it implements.
fn capabilities() -> Answer {
    // The tier is derived from the name, the way the kernel derives it, rather than
    // asserted in prose: `3rd` is a property of the name inside the signed manifest.
    let tier = Tier::from_name(PLUGIN_NAME).map_err(|err| Refusal {
        code: CODE_CAPABILITIES,
        message: bounded(&err.to_string()),
    })?;
    if tier != Tier::ThirdParty {
        return Err(Refusal {
            code: CODE_CAPABILITIES,
            message: format!(
                "`{PLUGIN_NAME}` classifies as {tier}, not third-party; this binary and its own \
                 name disagree, so nothing about the tier can be reported"
            ),
        });
    }

    let declared = declared_capabilities();

    // The declaration the host is asked to trust, audited one capability at a time against
    // the kernel's own matrix. For this tier the honest result is an empty approval list:
    // the basic set is held by construction, and anything above it is refused outright and
    // is therefore not declared at all.
    let mut required_approvals = Vec::new();
    for capability in &declared {
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

    // A machine-readable statement of the design constraint, so a reviewer does not have to
    // take the prose's word for it: this is exactly the tier's ceiling, nothing above it.
    let basic: Vec<&str> = Capability::BASIC.iter().map(|c| c.as_str()).collect();
    let declares_only_the_basic_set = declared == basic;

    // Which op exercises each declared capability. Every list is empty, and that is a fact a
    // host must be able to read without interpreting prose.
    let mut backing = Map::new();
    let mut all_backed = true;
    let mut unbacked = Vec::new();
    for capability in &declared {
        let ops = capability_backing(capability);
        if ops.is_empty() {
            all_backed = false;
            unbacked.push(*capability);
        }
        backing.insert((*capability).to_string(), json!(ops));
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

    Ok(json!({
        "plugin": PLUGIN_NAME,
        "version": PLUGIN_VERSION,
        "tier": tier.label(),
        "requires_counter_signature": tier.requires_counter_signature(),
        "runs_in_process": tier.runs_in_process(),
        "declares_only_the_basic_set": declares_only_the_basic_set,
        "catalogue_capabilities": Value::Null,
        "declared_capabilities": declared,
        "declared_matches_catalogue": Value::Null,
        "required_approvals": required_approvals,
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

    /// A reputation in a state no default construction produces, so "pure read" is visible.
    fn known_state() -> Reputation {
        Reputation {
            quality: ReputationScore::clamped(8_000),
            speed: ReputationScore::clamped(6_000),
            honesty: ReputationScore::clamped(7_000),
            availability: ReputationScore::clamped(9_000),
            // D-09's fifth dimension. Set to a value that is neither the default nor any of the four
            // above, so that a plugin which dropped it would produce a different composite and this
            // fixture would catch that rather than agreeing by coincidence.
            truthfulness: ReputationScore::clamped(5_500),
            settled: 7,
            faults: 2,
            observations: 3,
        }
    }

    /// The same computation the plugin delegates to, run directly on the model.
    fn direct(reputation: &Reputation, events: &[Event]) -> Reputation {
        let mut out = reputation.clone();
        for event in events {
            match event {
                Event::Settled {
                    latency_ratio_bps,
                    evidence_trustworthy,
                } => out.record_settled(*latency_ratio_bps, *evidence_trustworthy),
                Event::Fault { severity_bps } => out.record_fault(*severity_bps),
                Event::Clean => out.record_clean(),
            }
        }
        out
    }

    /// The events as JSON, so the payload is the wire shape rather than the Rust type.
    fn events_json() -> Vec<Value> {
        vec![
            json!({ "kind": "settled", "latency_ratio_bps": 20_000, "evidence_trustworthy": true }),
            json!({ "kind": "fault", "severity_bps": 2_500 }),
            json!({ "kind": "clean" }),
        ]
    }

    fn events_typed() -> Vec<Event> {
        vec![
            Event::Settled {
                latency_ratio_bps: 20_000,
                evidence_trustworthy: true,
            },
            Event::Fault {
                severity_bps: 2_500,
            },
            Event::Clean,
        ]
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
    fn advise_returns_exactly_what_the_reputation_model_computed() {
        // The central claim of this binary, tested the only way that can distinguish a
        // delegation from a canned answer: run both and compare every field.
        let before = known_state();
        let expected = direct(&before, &events_typed());

        let (code, response) = call(
            "advise",
            json!({
                "reputation": &before,
                "events": events_json(),
                "min_overall_bps": 4_000,
            }),
        );
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(response.ok);
        assert_eq!(response.plugin, PLUGIN_NAME);
        assert_eq!(response.version, PLUGIN_VERSION);

        let answer = response.payload.expect("a payload");
        assert_eq!(answer["quality_bps"], json!(expected.quality.bps()));
        assert_eq!(answer["speed_bps"], json!(expected.speed.bps()));
        assert_eq!(answer["honesty_bps"], json!(expected.honesty.bps()));
        assert_eq!(
            answer["availability_bps"],
            json!(expected.availability.bps())
        );
        assert_eq!(answer["settled"], json!(expected.settled));
        assert_eq!(answer["faults"], json!(expected.faults));
        assert_eq!(answer["overall_bps"], json!(expected.overall_bps()));
        assert_eq!(answer["overall"], json!(expected.overall()));
        assert_eq!(
            answer["eligible"],
            json!(expected.is_eligible(4_000)),
            "eligibility is the model's comparison, not this plugin's"
        );
        assert_eq!(answer["min_overall_bps"], json!(4_000));
        assert_eq!(answer["events_applied"], json!(3));
        assert_eq!(answer["advisory"], json!(true));

        // The mutated state is serialized by the model itself, so it must equal a direct
        // `to_value` of the directly-computed value -- no field renamed or dropped.
        assert_eq!(
            answer["reputation"],
            serde_json::to_value(&expected).expect("serialises"),
            "the reported state must be the model's own serialization"
        );

        // The fixture must actually move the model, or this test proves nothing.
        assert_ne!(answer["quality_bps"], json!(before.quality.bps()));
        assert_eq!(answer["settled"], json!(8), "one settled event was applied");
        assert_eq!(answer["faults"], json!(3), "one fault event was applied");

        // `overall()` is defined as `clamped(overall_bps() as u16)`; the two accessors must
        // agree on in-range state, and that is asserted here rather than assumed.
        assert_eq!(
            answer["overall"].as_u64(),
            answer["overall_bps"].as_u64(),
            "both accessors report the same composite score"
        );
    }

    #[test]
    fn a_pure_read_applies_nothing_and_reports_the_state_it_was_given() {
        // "No events" is the pure read: an absent list and an explicitly empty one are the
        // same request, and neither may move the counters.
        let before = known_state();
        let (code, response) = call("advise", json!({ "reputation": &before }));
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");

        assert_eq!(answer["events_applied"], json!(0));
        assert_eq!(answer["settled"], json!(7));
        assert_eq!(answer["faults"], json!(2));
        assert_eq!(answer["quality_bps"], json!(before.quality.bps()));
        assert_eq!(answer["overall_bps"], json!(before.overall_bps()));
        assert_eq!(
            answer["reputation"],
            serde_json::to_value(&before).expect("serialises"),
            "a pure read must return the state it was handed, unchanged"
        );

        // The eligibility question was not asked, so it is not answered.
        assert_eq!(answer["min_overall_bps"], Value::Null);
        assert_eq!(
            answer["eligible"],
            Value::Null,
            "a floor must not be invented for a caller who supplied none"
        );

        // An explicitly empty list is the same request.
        let (code, response) = call("advise", json!({ "reputation": &before, "events": [] }));
        assert_eq!(code, EXIT_OK);
        let empty = response.payload.expect("a payload");
        assert_eq!(empty["reputation"], answer["reputation"]);
        assert_eq!(empty["events_applied"], json!(0));
    }

    #[test]
    fn the_events_are_applied_in_the_order_the_caller_gave_them() {
        // The three mutators are a non-commutative state machine, so the order is part of
        // the request rather than an implementation detail.
        let before = known_state();
        let forward = vec![
            Event::Fault {
                severity_bps: 2_500,
            },
            Event::Clean,
        ];
        let reverse = vec![
            Event::Clean,
            Event::Fault {
                severity_bps: 2_500,
            },
        ];

        let forward_json = json!({
            "reputation": &before,
            "events": [
                { "kind": "fault", "severity_bps": 2_500 },
                { "kind": "clean" },
            ],
        });
        let reverse_json = json!({
            "reputation": &before,
            "events": [
                { "kind": "clean" },
                { "kind": "fault", "severity_bps": 2_500 },
            ],
        });

        let (code, response) = call("advise", forward_json);
        assert_eq!(code, EXIT_OK);
        let got_forward = response.payload.expect("a payload");

        let (code, response) = call("advise", reverse_json);
        assert_eq!(code, EXIT_OK);
        let got_reverse = response.payload.expect("a payload");

        assert_eq!(
            got_forward["reputation"],
            serde_json::to_value(direct(&before, &forward)).expect("serialises")
        );
        assert_eq!(
            got_reverse["reputation"],
            serde_json::to_value(direct(&before, &reverse)).expect("serialises")
        );
        assert_ne!(
            got_forward["reputation"], got_reverse["reputation"],
            "if these were equal the order would not be observable and this test would be vacuous"
        );
    }

    #[test]
    fn a_score_outside_the_models_range_is_refused_with_the_models_own_message() {
        // `ReputationScore` is `#[serde(transparent)]`, so serde will build one above the
        // documented maximum; the model's own constructor is what refuses it.
        let (code, response) = call(
            "advise",
            json!({
                "reputation": {
                    "quality": 60_000, "speed": 5_000, "honesty": 5_000, "availability": 5_000,
                    "settled": 0, "faults": 0
                }
            }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert!(!response.ok);
        assert_eq!(response.code.as_deref(), Some(CODE_SCORE_RANGE));
        let message = response.message.expect("a message");
        assert!(
            message.contains("`quality`"),
            "the refusal must name the dimension: {message}"
        );
        assert!(
            message.contains("10000"),
            "the refusal must be the model's own range message: {message}"
        );
    }

    #[test]
    fn an_unknown_event_kind_is_a_typed_refusal_rather_than_a_dropped_update() {
        let (code, response) = call(
            "advise",
            json!({
                "reputation": known_state(),
                "events": [ { "kind": "bribe", "amount": 1 } ],
            }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_ADVISE_PAYLOAD));
        let message = response.message.expect("a message");
        assert!(
            message.contains("bribe"),
            "the refusal must name the offending kind: {message}"
        );
        assert!(
            message.contains("clean"),
            "the refusal must list the accepted kinds: {message}"
        );
    }

    #[test]
    fn an_advise_payload_of_the_wrong_shape_is_refused_rather_than_guessed() {
        let (code, response) = call("advise", json!([1, 2, 3]));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_NOT_OBJECT));

        // `reputation` is required: a misspelled or absent key is a refusal naming the
        // field, not a defaulted neutral state.
        let (code, response) = call("advise", json!({ "events": [] }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_ADVISE_PAYLOAD));
        assert!(
            response.message.expect("a message").contains("reputation"),
            "the refusal must name the missing field"
        );

        // A fifth dimension is not a dimension: the model's struct has exactly six fields,
        // and a misspelled one is missing rather than extra.
        let (code, response) = call(
            "advise",
            json!({
                "reputation": {
                    "quality": 5_000, "speed": 5_000, "honesty": 5_000, "availabilty": 5_000,
                    "settled": 0, "faults": 0
                }
            }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_ADVISE_PAYLOAD));

        // `events` must be an array, and each event must be an object.
        let (code, response) = call(
            "advise",
            json!({ "reputation": known_state(), "events": "clean" }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_ADVISE_PAYLOAD));

        // The eligibility floor is a non-negative integer or absent; a string is neither.
        let (code, response) = call(
            "advise",
            json!({ "reputation": known_state(), "min_overall_bps": "high" }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_ADVISE_PAYLOAD));
    }

    #[test]
    fn a_settled_event_without_its_two_parameters_is_refused() {
        // A boolean must be supplied rather than defaulted: whether the evidence was
        // trustworthy moves quality and availability in opposite directions.
        for event in [
            json!({ "kind": "settled", "latency_ratio_bps": 9_000 }),
            json!({ "kind": "settled", "evidence_trustworthy": true }),
            json!({ "kind": "fault" }),
        ] {
            let (code, response) = call(
                "advise",
                json!({ "reputation": known_state(), "events": [event] }),
            );
            assert_eq!(code, EXIT_REFUSED, "{event}");
            assert_eq!(response.code.as_deref(), Some(CODE_ADVISE_PAYLOAD));
        }
    }

    #[test]
    fn capabilities_reports_the_third_party_ceiling_without_a_false_green() {
        let (code, response) = call("capabilities", Value::Null);
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");

        assert_eq!(answer["plugin"], json!(PLUGIN_NAME));
        assert_eq!(answer["version"], json!(PLUGIN_VERSION));
        assert_eq!(answer["tier"], json!("3rd"));
        assert_eq!(
            answer["requires_counter_signature"],
            json!(false),
            "the third-party tier has no counter-signature, which is why it holds nothing above \
             the basic set"
        );
        assert_eq!(
            answer["runs_in_process"],
            json!(false),
            "only the system tier runs inside the host"
        );
        assert_eq!(
            answer["declared_capabilities"],
            json!(declared_capabilities())
        );
        assert_eq!(answer["implemented_ops"], json!(IMPLEMENTED_OPS));
        assert_eq!(
            answer["declares_only_the_basic_set"],
            json!(true),
            "the design is narrowed to the tier's ceiling"
        );

        // The basic set needs no approval at any loadable tier, so the list is empty -- and
        // that is derived from the matrix rather than asserted.
        assert_eq!(answer["required_approvals"], json!([]));

        // There is no third-party catalogue in this build, so there is nothing to compare
        // the declaration against -- reported as null, not as agreement.
        assert_eq!(answer["catalogue_capabilities"], Value::Null);
        assert_eq!(answer["declared_matches_catalogue"], Value::Null);

        // The honest part: three capabilities declared, none exercised by any op.
        assert_eq!(
            answer["declared_capabilities_backed_by_ops"],
            json!(false),
            "`advise` reads no lifecycle state, sends no bus message and touches no storage"
        );
        for capability in Capability::BASIC {
            assert_eq!(
                answer["capability_backing"][capability.as_str()],
                json!([]),
                "`{capability}` is declared but must not claim an op"
            );
        }
        assert_eq!(
            answer["unbacked_declared_capabilities"],
            json!(declared_capabilities())
        );
        assert_eq!(
            answer["ops_not_named_by_a_declared_capability"],
            json!(IMPLEMENTED_OPS)
        );
        assert_eq!(
            answer["op_delegation"]["advise"],
            json!(
                "nau_market::reputation::Reputation::{record_settled, record_fault, \
                 record_clean, overall_bps, overall, is_eligible}"
            )
        );
    }

    #[test]
    fn the_binary_is_a_third_party_name_and_cannot_borrow_the_vendor_prefix() {
        assert_eq!(
            Tier::from_name(PLUGIN_NAME).expect("classifies"),
            Tier::ThirdParty
        );
        assert!(!Tier::ThirdParty.requires_counter_signature());
        assert!(Tier::ThirdParty.is_loadable());
        assert!(!PLUGIN_NAME.starts_with("com.twinsearth."));
        assert_eq!(Tier::from_label("3rd").expect("parses"), Tier::ThirdParty);

        // The reserved namespace is the reason the name is `com.example.*`: a third-party
        // plugin that named itself inside `com.twinsearth.` would be refused rather than
        // classified, so it could not be published at all.
        assert!(
            Tier::from_name("com.twinsearth.reputation").is_err(),
            "the vendor namespace is reserved and a squatter must be refused"
        );
        assert_eq!(
            nau_plugin::PluginId::parse(PLUGIN_NAME)
                .expect("a valid plugin id")
                .tier()
                .expect("classifies"),
            Tier::ThirdParty
        );
    }

    #[test]
    fn every_declared_capability_has_a_backing_row_and_every_row_names_a_real_capability() {
        // Drift guards: adding a capability to the declaration without deciding whether an op
        // backs it, or naming a capability the matrix does not know, both fail here.
        for capability in declared_capabilities() {
            assert!(
                CAPABILITY_BACKING
                    .iter()
                    .any(|(name, _)| *name == capability),
                "`{capability}` is declared with no backing row, so `capabilities` would report \
                 it as if it did not exist"
            );
        }
        for (name, ops) in CAPABILITY_BACKING {
            let parsed =
                Capability::parse(name).expect("the row names a capability the matrix knows");
            assert_eq!(parsed.as_str(), name, "the row's key must be the wire name");
            assert!(
                parsed.is_basic(),
                "this plugin must declare only the basic set, and `{name}` is above it"
            );
            for op in ops {
                assert!(
                    IMPLEMENTED_OPS.contains(op),
                    "`{op}` backs `{name}` but is not an implemented op"
                );
            }
            assert_eq!(
                capability_backing(name),
                ops,
                "the lookup must return the row"
            );
        }
        assert_eq!(
            CAPABILITY_BACKING.len(),
            declared_capabilities().len(),
            "a backing row for a capability that is not declared is drift too"
        );
        for (op, _) in OP_DELEGATION {
            assert!(
                IMPLEMENTED_OPS.iter().any(|known| *known == op),
                "`{op}` has a delegation entry but is not implemented"
            );
        }
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
            message.contains("advise") && message.contains("capabilities"),
            "the known ops must be listed: {message}"
        );
    }

    #[test]
    fn a_diagnostic_built_from_caller_json_stays_bounded() {
        // An enum with a long unknown variant makes serde_json quote the caller's string.
        // That string is the caller's, so it must not decide how much this plugin writes.
        let long = "x".repeat(MAX_DIAGNOSTIC_CHARS * 4);
        let (code, response) = call(
            "advise",
            json!({ "reputation": known_state(), "events": [ { "kind": long } ] }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_ADVISE_PAYLOAD));
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
