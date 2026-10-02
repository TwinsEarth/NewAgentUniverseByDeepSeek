//! `nau-plugin-swarm` — the first **certified (T2) plugin that is an executable**.
//!
//! `docs/PLUGIN-ARCHITECTURE.md` names five tiers and `nau_plugin::Tier` implements all
//! five, but only four of them had a running plugin before this file: the process-plugin
//! path was exercised by `nau-plugin-echo` (T3) and `nau-plugin-market` (T1), and the
//! `com.twinsearth.certified.*` name — the name a plugin gets when it has passed review
//! and been counter-signed by the vendor — had no member that runs at all. This binary is
//! the attempt to make that false for one certified name, and what makes it count is
//! narrow and checkable:
//!
//! * it is a real file a host can start, and it speaks the host ABI frame from
//!   [`nau_plugins::frame`] — the same codec `nau-plugin-echo` and `nau-plugin-market`
//!   speak, not a second implementation of it;
//! * its `tally` op delegates to [`nau_consensus::Committee`] — `assign`, `cast` and
//!   `tally` — and returns a projection of the [`nau_consensus::TallyResult`] that
//!   `tally` actually returned, field by field;
//! * its name is `com.twinsearth.certified.swarm`, which
//!   [`Tier::from_name`] classifies as [`Tier::Certified`] and which therefore
//!   [`Tier::requires_counter_signature`] — the two properties that make this a T2
//!   plugin rather than a plugin with a nice filename;
//! * its `capabilities` op reports the declared capability set, the approval the
//!   certified tier needs for the sensitive part of it, the ops this binary actually
//!   implements, and — capability by capability — which op (if any) exercises it.
//!
//! # Why the tier matters here, and what it changes
//!
//! `swarm:consensus` is refused outright to the third-party tier and held by the
//! certified tier **only once the certification committee has approved it**
//! ([`Capability::decision`] returns `RequiresApproval(CertificationCommittee)`).
//! So this plugin is the object the whole review-and-certification machinery exists to
//! produce: `capabilities` derives that approval requirement from the kernel's own
//! matrix at runtime rather than restating it, so a host can see *which* capability is
//! conditional on *whose* approval without trusting this file's prose.
//!
//! # Protocol
//!
//! ```text
//! stdin:  u32_be(len) || {"abi":"3.2","id":"req-1","op":"tally","payload":{…}}
//! stdout: u32_be(len) || {"abi":"3.2","id":"req-1",
//!                         "plugin":"com.twinsearth.certified.swarm",
//!                         "version":"1.0.0","ok":true,"payload":{…}}
//! ```
//!
//! One frame in, one frame out, then exit. stdout carries **only** frames; every
//! diagnostic goes to stderr, because a stray `println!` is a protocol corruption and
//! this binary has no other way to talk to its host.
//!
//! ## `tally`
//!
//! The payload mirrors [`Committee::assign`]'s **real** parameters, because the shape was
//! designed after reading its signature rather than before:
//!
//! ```json
//! {
//!   "spec":     { "n": 4, "f": 1 },
//!   "proposal": "task-1",
//!   "members":  [ "did:nau:…", "did:nau:…", "did:nau:…", "did:nau:…" ],
//!   "votes":    [ { …a serialized `nau_consensus::Vote`… } ],
//!   "now":      1700000000
//! }
//! ```
//!
//! Every input is required, including `votes`: a caller that means "no ballots yet"
//! writes `"votes": []`, and a caller that misspells the key gets a typed refusal rather
//! than a plausible-looking all-silent tally. `now` is the **host's** clock, supplied
//! rather than read here, because [`Committee::cast`] verifies freshness against it and a
//! verdict that depended on the plugin's own clock would depend on where the plugin runs.
//!
//! The answer:
//!
//! ```json
//! {
//!   "proposal": "task-1", "round": 0, "spec": { "n": 4, "f": 1 },
//!   "quorum": 3, "outcome": "accepted", "reason": "quorum_reached",
//!   "accept": 3, "reject": 0, "silent": 1,
//!   "equivocators": [], "safety_violation": false, "decided": true,
//!   "ballots_accepted_by_cast": 3, "ballots_refused_by_cast": 0,
//!   "cast_refusals": []
//! }
//! ```
//!
//! Every verdict field (`outcome`, `reason`, `quorum`, `accept`, `reject`, `silent`,
//! `equivocators`, `safety_violation`, `decided`) comes from the returned
//! `TallyResult`, and nothing is recomputed: a host that calls the same functions
//! directly gets the same numbers. `outcome` and `reason` are this ABI's `snake_case`
//! labels for `nau_consensus::committee::Outcome` and `TallyReason`, whose own `serde`
//! spelling is `NoQuorum`/`RoundVoidedByEquivocation`; the mappings [`outcome_label`] and
//! [`reason_label`] are exhaustive matches, so a variant added upstream fails to compile
//! here instead of being silently unlabelled.
//!
//! `ballots_accepted_by_cast` counts ballots [`Committee::cast`] returned `Ok` for, which
//! is **not** the same as `accept + reject`: a member repeating the same decision with a
//! fresh nonce is an idempotent duplicate announcement (`Ok`, not a second ballot), and
//! `ballots_refused_by_cast` counts the `Err`s, each listed in `cast_refusals` with the
//! reason the committee itself gave. An equivocation is one of those refusals — and it is
//! recorded, not dropped, so the tally it voids says so.
//!
//! If **every** supplied ballot is refused by `cast` (and at least one was supplied) the
//! whole call is refused with `swarm_tally_no_ballot_accepted`, because a tally over zero
//! accepted ballots is not the tally the caller asked for. The refusal quotes the first
//! refusal the committee gave, so a caller that sent ballots for the wrong proposal learns
//! which proposal the committee was deciding.
//!
//! **This op tallies; it does not run a consensus round.** It is stateless: the committee
//! is reconstructed from the ballots in the payload on every call, so the host owns the
//! round state and no ballot is replayed across calls here. It does not cast votes on its
//! own behalf, open a network connection, gossip a proposal or detect emergence.
//!
//! ## `capabilities`
//!
//! Takes no arguments. Returns the plugin's own name and version, the tier derived from
//! that name, whether that tier requires a vendor counter-signature, the declared
//! capability set (the kernel's basic set plus `swarm:consensus`), the approvals the
//! matrix requires for what is declared, the ops this binary implements, which op (if
//! any) exercises each declared capability, which crate function each op delegates to,
//! and whether the declaration is backed by the implementation.
//!
//! `declared_matches_catalogue` is `null`, and that is deliberate rather than unfinished:
//! the only catalogue in this build is [`nau_plugins::official::OFFICIALS`], which is not
//! a certified catalogue, so there is nothing to compare this declaration against. A
//! `true` there would be exactly the false green the field exists to prevent.
//!
//! # Exit codes
//!
//! `0` answered, `1` answered with `ok: false`, `2` the frame itself could not be read
//! or written. The distinction is `nau-plugin-echo`'s and `nau-plugin-market`'s and is
//! deliberately unchanged: `2` means the binary is not speaking this ABI at all, which
//! is a different repair from "the plugin refused the call".
//!
//! # Fail-closed choices
//!
//! * an unknown op, an incompatible `abi` and a payload of the wrong shape are each a
//!   typed refusal, never an empty success;
//! * a ballot the committee refuses does not silently vanish: it is counted and quoted;
//! * unknown *keys* inside a payload are tolerated (the same additive-within-a-major rule
//!   the frame envelope follows), which is safe here because every required key is
//!   required — a missing one is a refusal naming the field rather than a default;
//! * a diagnostic echoed back to the host is bounded, because an error string built from
//!   caller-supplied JSON is how a log becomes an attack surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_consensus::committee::{Outcome, TallyReason, TallyResult};
use nau_consensus::{Committee, CommitteeSpec, Vote};
use nau_core::{Did, NauError};
use nau_plugin::capability::{Capability, Grant};
use nau_plugin::tier::Tier;
use nau_plugins::frame::{self, Response};
use nau_plugins::payload;
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// The name this binary implements. The tier is derived from this name, so the
/// spelling is not cosmetic: `com.twinsearth.official.swarm` is a *different* plugin at
/// a different tier, and `com.twinsearth.certified.swarm` is the name a manifest must
/// carry for the arbiter to require a certification for it.
const PLUGIN_NAME: &str = "com.twinsearth.certified.swarm";

/// The version this binary reports.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named in
/// [`OP_DELEGATION`] is listed here, so this table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 2] = ["capabilities", "tally"];

/// The capability this plugin exists to hold, and the one whose grant is conditional.
///
/// Named once, so the declaration, the approval report and the backing report cannot
/// disagree about which capability is the sensitive one.
const SENSITIVE_CAPABILITY: Capability = Capability::SwarmConsensus;

/// Which implemented op exercises each declared capability.
///
/// `swarm:consensus` is backed by `tally`: that op performs the tallying the capability
/// gates. The three basic capabilities have no op here — this binary reads no lifecycle
/// state, sends no bus message and touches no sandbox directory — and an empty list is
/// how that is reported rather than hidden. Listing an op for them would be a claim that
/// this binary does their work, which it does not.
const CAPABILITY_BACKING: [(&str, &[&str]); 4] = [
    ("plugin:lifecycle:read", &[]),
    ("plugin:message:send", &[]),
    ("plugin:storage:own", &[]),
    ("swarm:consensus", &["tally"]),
];

/// Which crate function each implemented op delegates to, as `(op, target)`.
///
/// Reported in the `capabilities` answer so a host can see the delegation rather than
/// having to trust a description of it.
const OP_DELEGATION: [(&str, &str); 2] = [
    (
        "capabilities",
        "nau_plugin::capability::Capability::decision",
    ),
    ("tally", "nau_consensus::Committee::{assign, cast, tally}"),
];

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "`tally` delegates to nau_consensus::Committee::{assign, cast, tally} \
                     and reports that function's own TallyResult: it is the tallying half of \
                     `swarm:consensus` and it does not cast votes on its own behalf, run a \
                     network round, gossip a proposal or detect emergence. The three basic \
                     capabilities are declared because the matrix grants them unconditionally \
                     to every loadable tier, and no op here reads a lifecycle state, sends a \
                     bus message or touches a sandbox directory, so they are declared but not \
                     exercised — which is why declared_capabilities_backed_by_ops is false \
                     while every_approval_gated_capability_backed_by_ops is true. There is no \
                     certified catalogue in this build, so declared_matches_catalogue is null \
                     rather than true.";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: a `tally` payload is not a JSON object.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: a `tally` payload is an object but not the shape the committee needs.
const CODE_TALLY_PAYLOAD: &str = "swarm_tally_payload_invalid";
/// Error code: `Committee::assign` refused the spec, the proposal or the member list.
const CODE_TALLY_COMMITTEE: &str = "swarm_tally_committee_invalid";
/// Error code: every supplied ballot was refused by `Committee::cast`.
const CODE_TALLY_NO_BALLOT: &str = "swarm_tally_no_ballot_accepted";
/// Error code: this binary cannot report its own capabilities.
const CODE_CAPABILITIES: &str = "swarm_capabilities_unavailable";

/// Longest diagnostic quoted back to the host, in characters.
///
/// The message is written into a frame the host logs, and a `serde_json` diagnostic for
/// a wrong enum variant quotes the offending string — which the caller chose. Bounding
/// it keeps a caller from deciding how much text this plugin writes.
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

/// The `tally` payload, as [`Committee::assign`] and [`Committee::cast`] consume it.
///
/// Deliberately not `deny_unknown_fields`: the frame envelope is additive within a
/// major, and a payload that refused new keys would break that promise one layer down.
/// Every *required* key is required, though, so tolerance of unknown keys never turns a
/// typo into a default.
#[derive(Debug, Deserialize)]
struct TallyRequest {
    /// The committee parameters, validated by [`Committee::assign`].
    spec: CommitteeSpec,
    /// The proposal being decided, validated by [`Committee::assign`].
    proposal: String,
    /// The assigned members; [`Committee::assign`] requires exactly `spec.n()` distinct
    /// ones, so a caller cannot choose how many ballots a verdict needs.
    members: Vec<Did>,
    /// The signed ballots to cast before tallying. Required, so "no ballots" is written
    /// `[]` rather than inferred from a misspelling.
    votes: Vec<Vote>,
    /// The host's clock, in Unix seconds, against which [`Committee::cast`] checks each
    /// ballot's freshness.
    now: u64,
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
            // The frame was readable but not a request: answer with the refusal, so a
            // host sees a typed code rather than a dead process.
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
        "tally" => match tally(&request.payload) {
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

/// Rebuild the round from the payload's ballots and report the committee's own tally.
fn tally(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `tally` payload must be a JSON object carrying `spec`, `proposal`, \
                 `members`, `votes` and `now`, found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: TallyRequest = serde_json::from_value(payload.clone()).map_err(|err| Refusal {
        code: CODE_TALLY_PAYLOAD,
        message: bounded(&err.to_string()),
    })?;
    let TallyRequest {
        spec,
        proposal,
        members,
        votes,
        now,
    } = request;

    // The first delegation: the committee's real constructor, on the caller's real
    // member list. It is what refuses `n != 3f+1`, a duplicate member, a blank proposal
    // and a member list that does not match `n`.
    let mut committee = Committee::assign(spec, &proposal, members).map_err(|err| Refusal {
        code: CODE_TALLY_COMMITTEE,
        message: bounded(&err.to_string()),
    })?;

    let mut refusals = Vec::with_capacity(votes.len());
    let mut first_refusal: Option<(&'static str, String)> = None;
    for (index, vote) in votes.iter().enumerate() {
        // The second delegation: the committee's own authenticated `cast`. A forged
        // ballot, a stranger, a stale nonce, a wrong round/proposal and an equivocation
        // are all refused *here*, by the real verifier, and each refusal is recorded
        // instead of being dropped.
        if let Err(err) = committee.cast(vote, now) {
            let code = cast_code(&err);
            let message = bounded(&err.to_string());
            refusals.push(json!({
                "index": index,
                "voter": vote.voter.as_str(),
                "decision": vote.decision.label(),
                "code": code,
                "message": message,
            }));
            if first_refusal.is_none() {
                first_refusal = Some((code, message));
            }
        }
    }

    if !votes.is_empty() && refusals.len() == votes.len() {
        let first = match first_refusal {
            Some((code, message)) => format!("`{code}`: {message}"),
            None => "unreported".to_string(),
        };
        return Err(Refusal {
            code: CODE_TALLY_NO_BALLOT,
            message: format!(
                "all {} supplied ballot(s) were refused by `Committee::cast`, so none of them \
                 is part of the tally the committee would report; the first refusal was {first}",
                votes.len()
            ),
        });
    }

    // The third delegation, and the reason this binary exists: the committee's own
    // `tally`, whose return value is projected field by field below. `tally` takes no
    // arguments, so there is no caller-supplied count anywhere on this path.
    let result: TallyResult = committee.tally();
    tally_payload(&committee, &result, votes.len(), refusals)
}

/// Project the committee and its [`TallyResult`] into the JSON a host receives.
///
/// Faithful on purpose: every verdict field here comes from the returned struct, and
/// nothing is recomputed. A host can therefore compare this answer against a direct call
/// to `Committee::tally` and get the same numbers. `supplied` is how many ballots the
/// payload carried and `refusals` is what `Committee::cast` returned for the ones it
/// would not take, in the order they were supplied.
fn tally_payload(
    committee: &Committee,
    result: &TallyResult,
    supplied: usize,
    refusals: Vec<Value>,
) -> Answer {
    let equivocators: Vec<&str> = result
        .equivocators
        .iter()
        .map(Did::as_str)
        .collect::<Vec<&str>>();

    let refused = refusals.len();

    Ok(json!({
        "proposal": committee.proposal(),
        "round": committee.round(),
        "spec": { "n": committee.spec().n(), "f": committee.spec().f() },
        "quorum": result.quorum,
        "outcome": outcome_label(result.outcome),
        "reason": reason_label(result.reason),
        "accept": result.accept,
        "reject": result.reject,
        "silent": result.silent,
        "equivocators": equivocators,
        "safety_violation": result.safety_violation,
        "decided": result.is_decided(),
        "ballots_accepted_by_cast": supplied.saturating_sub(refused),
        "ballots_refused_by_cast": refused,
        "cast_refusals": refusals,
    }))
}

/// This ABI's label for the verdict that was reached.
///
/// Exhaustive over [`Outcome`] so a variant added upstream fails to compile here rather
/// than reaching a host unlabelled.
fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Accepted => "accepted",
        Outcome::Rejected => "rejected",
        Outcome::NoQuorum => "no_quorum",
        Outcome::SafetyViolation => "safety_violation",
    }
}

/// This ABI's label for why that verdict was reached.
///
/// Exhaustive over [`TallyReason`], for the same reason.
fn reason_label(reason: TallyReason) -> &'static str {
    match reason {
        TallyReason::QuorumReached => "quorum_reached",
        TallyReason::SilenceExceedsFaults => "silence_exceeds_faults",
        TallyReason::InsufficientVotes => "insufficient_votes",
        TallyReason::ConflictingQuorums => "conflicting_quorums",
        TallyReason::RoundVoidedByEquivocation => "round_voided_by_equivocation",
    }
}

/// A machine-readable code for one ballot refusal.
///
/// The committee's taxonomy is [`NauError`], which is `#[non_exhaustive]`, so the final
/// arm exists because the enum can grow — and it still names the refusal rather than
/// inventing a success. The committee's own prose always reaches the host next to this
/// code, so a code this plugin has no better name for is still legible.
fn cast_code(err: &NauError) -> &'static str {
    match err {
        NauError::Conflict(_) => "ballot_equivocation",
        NauError::Unauthorized(_) => "ballot_not_a_member",
        NauError::Stale(_) => "ballot_stale",
        NauError::InvalidSignature | NauError::DidKeyMismatch { .. } => "ballot_not_authentic",
        NauError::InvalidSignatureEncoding(_)
        | NauError::InvalidPublicKey(_)
        | NauError::Canonical(_) => "ballot_malformed",
        NauError::Validation(_) => "ballot_invalid",
        _ => "ballot_refused",
    }
}

/// The capability set this binary declares: the kernel's basic set, plus the sensitive one.
///
/// Derived from [`Capability::BASIC`] and [`SENSITIVE_CAPABILITY`] rather than spelled
/// out as strings, so the declaration cannot drift from the matrix that decides what the
/// tier may hold. There is no certified catalogue in this build, so this function *is*
/// the declaration.
fn declared_capabilities() -> Vec<&'static str> {
    let mut declared: Vec<&'static str> = Capability::BASIC.iter().map(|c| c.as_str()).collect();
    declared.push(SENSITIVE_CAPABILITY.as_str());
    declared
}

/// What this binary declares, what the matrix says about it, and what it implements.
fn capabilities() -> Answer {
    // The tier is derived from the name, the way the kernel derives it, rather than
    // asserted in prose: `certified` is a property of the name inside the signed manifest.
    let tier = Tier::from_name(PLUGIN_NAME).map_err(|err| Refusal {
        code: CODE_CAPABILITIES,
        message: bounded(&err.to_string()),
    })?;
    if tier != Tier::Certified {
        return Err(Refusal {
            code: CODE_CAPABILITIES,
            message: format!(
                "`{PLUGIN_NAME}` classifies as {tier}, not certified; this binary and its own \
                 name disagree, so nothing about the tier can be reported"
            ),
        });
    }

    let declared = declared_capabilities();

    // The declaration the host is asked to trust, audited one capability at a time
    // against the kernel's own matrix. A capability the certified tier refuses outright
    // is a refusal here, not a line item: the matrix is the authority on what a tier may
    // hold, and a declaration outside it is not a policy, it is a bug.
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

    // Which op exercises each declared capability. An empty list means "declared but not
    // exercised", which is a fact a host must be able to read without interpreting prose.
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

    // The narrower, more useful question for this tier: the capability that needs the
    // certification committee's approval is the one that has to be *actually exercised*,
    // and this says whether it is -- separately, so the basic set's non-exercise cannot
    // hide it.
    let mut approval_gated_backed = true;
    for approval in &required_approvals {
        let name = approval["capability"].as_str().unwrap_or_default();
        if capability_backing(name).is_empty() {
            approval_gated_backed = false;
        }
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
        "catalogue_capabilities": Value::Null,
        "declared_capabilities": declared,
        "declared_matches_catalogue": Value::Null,
        "required_approvals": required_approvals,
        "implemented_ops": IMPLEMENTED_OPS,
        "capability_backing": Value::Object(backing),
        "declared_capabilities_backed_by_ops": all_backed,
        "unbacked_declared_capabilities": unbacked,
        "every_approval_gated_capability_backed_by_ops": approval_gated_backed,
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
    use nau_consensus::Decision;
    use nau_core::Identity;
    use nau_plugins::frame::{decode_response, Request};

    const NOW: u64 = 1_700_000_000;
    const PROPOSAL: &str = "task-1";

    fn identity(seed: u8) -> Identity {
        Identity::from_seed(&[seed; 32])
    }

    /// A committee of `n` distinct members, plus the identities that sign for them.
    fn committee_of(n: u32, f: u32) -> (CommitteeSpec, Vec<Identity>) {
        let spec = CommitteeSpec::new(n, f).expect("the test spec is a legal committee");
        let identities: Vec<Identity> = (1..=n).map(|seed| identity(seed as u8)).collect();
        (spec, identities)
    }

    fn members_of(identities: &[Identity]) -> Vec<Did> {
        identities.iter().map(Identity::did).collect()
    }

    fn ballot(round: u64, who: &Identity, decision: Decision, nonce: u64) -> Vote {
        Vote::signed(round, PROPOSAL, who, decision, nonce, NOW).expect("a test ballot signs")
    }

    /// Run one request through `run` and decode exactly one response frame.
    fn call_request(request: &Request) -> (u8, Response) {
        let mut wire = Vec::new();
        frame::write_frame(&mut wire, &serde_json::to_vec(request).expect("encodes"))
            .expect("writes");
        let mut output = Vec::new();
        let code = run(&mut wire.as_slice(), &mut output);
        // One reader over the whole stream: the second read must be a clean EOF, which
        // is what "stdout carried exactly one frame and nothing else" means.
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

    /// A `tally` payload carrying `votes` for the given committee.
    fn tally_payload(spec: CommitteeSpec, identities: &[Identity], votes: &[Vote]) -> Value {
        json!({
            "spec": spec,
            "proposal": PROPOSAL,
            "members": members_of(identities),
            "votes": votes,
            "now": NOW,
        })
    }

    /// The same computation the plugin delegates to, run directly.
    fn direct_tally(
        spec: CommitteeSpec,
        identities: &[Identity],
        votes: &[Vote],
    ) -> (Committee, TallyResult, Vec<String>) {
        let mut committee = Committee::assign(spec, PROPOSAL, members_of(identities))
            .expect("the test committee assigns");
        let mut refused = Vec::new();
        for vote in votes {
            if let Err(err) = committee.cast(vote, NOW) {
                refused.push(err.to_string());
            }
        }
        let result = committee.tally();
        (committee, result, refused)
    }

    #[test]
    fn tally_answers_with_exactly_what_the_committee_tallied() {
        // The central claim of this binary, tested the only way that can distinguish a
        // delegation from a canned answer: run both and compare every field.
        let (spec, identities) = committee_of(4, 1);
        let votes = vec![
            ballot(0, &identities[0], Decision::Accept, 1),
            ballot(0, &identities[1], Decision::Accept, 1),
            ballot(0, &identities[2], Decision::Accept, 1),
        ];

        let (_, expected, refused) = direct_tally(spec, &identities, &votes);
        assert_eq!(
            expected.outcome,
            Outcome::Accepted,
            "the fixture must produce a real verdict, or this test proves nothing"
        );
        assert!(refused.is_empty());

        let (code, response) = call("tally", tally_payload(spec, &identities, &votes));
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(response.ok);
        assert_eq!(response.plugin, PLUGIN_NAME);
        assert_eq!(response.version, PLUGIN_VERSION);

        let answer = response.payload.expect("a payload");
        assert_eq!(answer["proposal"], json!(PROPOSAL));
        assert_eq!(answer["outcome"], json!(outcome_label(expected.outcome)));
        assert_eq!(answer["reason"], json!(reason_label(expected.reason)));
        assert_eq!(answer["quorum"].as_u64(), Some(u64::from(expected.quorum)));
        assert_eq!(answer["accept"].as_u64(), Some(u64::from(expected.accept)));
        assert_eq!(answer["reject"].as_u64(), Some(u64::from(expected.reject)));
        assert_eq!(answer["silent"].as_u64(), Some(u64::from(expected.silent)));
        assert_eq!(answer["safety_violation"], json!(expected.safety_violation));
        assert_eq!(answer["decided"], json!(expected.is_decided()));
        assert_eq!(answer["equivocators"], json!([]));
        assert_eq!(answer["ballots_accepted_by_cast"], json!(3));
        assert_eq!(answer["ballots_refused_by_cast"], json!(0));
        assert_eq!(answer["cast_refusals"], json!([]));
        // The quorum the tally applied is the one the committee computed, not a restatement.
        assert_eq!(answer["quorum"].as_u64(), Some(3));
    }

    #[test]
    fn a_rejected_proposal_is_reported_as_rejected_with_the_committees_own_reason() {
        let (spec, identities) = committee_of(4, 1);
        let votes = vec![
            ballot(0, &identities[0], Decision::Reject, 1),
            ballot(0, &identities[1], Decision::Reject, 1),
            ballot(0, &identities[2], Decision::Reject, 1),
        ];
        let (_, expected, _) = direct_tally(spec, &identities, &votes);
        assert_eq!(expected.outcome, Outcome::Rejected);

        let (code, response) = call("tally", tally_payload(spec, &identities, &votes));
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["outcome"], json!("rejected"));
        assert_eq!(answer["reason"], json!(reason_label(expected.reason)));
        assert_eq!(answer["reject"].as_u64(), Some(u64::from(expected.reject)));
        assert_eq!(answer["decided"], json!(true));
    }

    #[test]
    fn an_equivocation_voids_the_round_and_the_offender_is_named() {
        // A member that votes Accept and then Reject is refused by `cast` -- and the
        // refusal is recorded, so the tally it voids says so instead of counting a
        // verdict that the double vote makes untrustworthy.
        let (spec, identities) = committee_of(4, 1);
        let first = ballot(0, &identities[0], Decision::Accept, 1);
        let second = ballot(0, &identities[0], Decision::Reject, 2);
        let votes = vec![
            first,
            second,
            ballot(0, &identities[1], Decision::Accept, 1),
            ballot(0, &identities[2], Decision::Accept, 1),
        ];

        let (_, expected, refused) = direct_tally(spec, &identities, &votes);
        assert_eq!(
            refused.len(),
            1,
            "the second ballot of the pair is the conflict"
        );
        assert_eq!(expected.outcome, Outcome::NoQuorum);
        assert_eq!(expected.reason, TallyReason::RoundVoidedByEquivocation);
        assert_eq!(expected.equivocators, vec![identities[0].did()]);

        let (code, response) = call("tally", tally_payload(spec, &identities, &votes));
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["outcome"], json!("no_quorum"));
        assert_eq!(answer["reason"], json!("round_voided_by_equivocation"));
        assert_eq!(answer["decided"], json!(false));
        assert_eq!(
            answer["equivocators"],
            json!([identities[0].did().as_str()])
        );
        assert_eq!(answer["ballots_refused_by_cast"], json!(1));
        let refusals = answer["cast_refusals"].as_array().expect("an array");
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0]["code"], json!("ballot_equivocation"));
        assert_eq!(refusals[0]["voter"], json!(identities[0].did().as_str()));
        assert!(
            refusals[0]["message"]
                .as_str()
                .expect("a message")
                .contains("equivocated"),
            "the committee's own prose must reach the host: {refusals:?}"
        );
    }

    #[test]
    fn a_ballot_that_cast_refuses_is_counted_and_quoted_rather_than_silently_dropped() {
        let (spec, identities) = committee_of(4, 1);
        let stranger = identity(9);
        let votes = vec![
            ballot(0, &stranger, Decision::Accept, 1),
            ballot(0, &identities[0], Decision::Accept, 1),
            ballot(0, &identities[1], Decision::Accept, 1),
            ballot(0, &identities[2], Decision::Accept, 1),
        ];

        let (code, response) = call("tally", tally_payload(spec, &identities, &votes));
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["outcome"], json!("accepted"));
        assert_eq!(
            answer["ballots_accepted_by_cast"],
            json!(3),
            "a refused ballot must not be counted as cast"
        );
        assert_eq!(answer["ballots_refused_by_cast"], json!(1));
        let refusals = answer["cast_refusals"].as_array().expect("an array");
        assert_eq!(refusals[0]["code"], json!("ballot_not_a_member"));
        assert_eq!(refusals[0]["index"], json!(0));
    }

    #[test]
    fn a_committee_whose_only_ballots_were_all_refused_is_not_answered_with_a_tally() {
        // The fail-closed half: a tally over zero accepted ballots is not the tally the
        // caller asked for, so the call is refused and the committee's own reason is
        // quoted rather than a plausible-looking all-silent verdict being returned.
        let (spec, identities) = committee_of(4, 1);
        let stranger = identity(9);
        let votes = vec![ballot(0, &stranger, Decision::Accept, 1)];

        let (code, response) = call("tally", tally_payload(spec, &identities, &votes));
        assert_eq!(code, EXIT_REFUSED);
        assert!(!response.ok);
        assert_eq!(response.code.as_deref(), Some(CODE_TALLY_NO_BALLOT));
        let message = response.message.expect("a message");
        assert!(
            message.contains("not an assigned member"),
            "the committee's own refusal must survive: {message}"
        );
    }

    #[test]
    fn a_forged_ballot_cannot_be_driven_into_a_verdict_through_this_plugin() {
        // The signature is the vote: tampering with a signed ballot after the fact makes
        // `cast` refuse it, and one forged ballot is not zero ballots -- it is a refusal.
        let (spec, identities) = committee_of(4, 1);
        let mut forged = ballot(0, &identities[0], Decision::Accept, 1);
        forged.decision = Decision::Reject;
        let votes = vec![forged];

        let (code, response) = call("tally", tally_payload(spec, &identities, &votes));
        assert_eq!(code, EXIT_REFUSED);
        let message = response.message.expect("a message");
        assert!(
            message.contains("signature"),
            "the refusal must name what failed to verify: {message}"
        );
    }

    #[test]
    fn an_explicitly_empty_round_is_tallied_truthfully_rather_than_refused() {
        // `"votes": []` is how a caller tallies a round nobody has voted in, and the
        // committee's own answer for that is a real answer. Omitting the key entirely is
        // a different thing, and is refused (see the payload-shape test below).
        let (spec, identities) = committee_of(4, 1);
        let (code, response) = call("tally", tally_payload(spec, &identities, &[]));
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["accept"], json!(0));
        assert_eq!(answer["silent"], json!(4));
        assert_eq!(answer["outcome"], json!("no_quorum"));
        assert_eq!(answer["reason"], json!("silence_exceeds_faults"));
        assert_eq!(answer["ballots_accepted_by_cast"], json!(0));
    }

    #[test]
    fn capabilities_reports_the_certified_tier_and_does_not_claim_a_false_green() {
        let (code, response) = call("capabilities", Value::Null);
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");

        assert_eq!(answer["plugin"], json!(PLUGIN_NAME));
        assert_eq!(answer["version"], json!(PLUGIN_VERSION));
        assert_eq!(answer["tier"], json!("certified"));
        assert_eq!(
            answer["requires_counter_signature"],
            json!(true),
            "T2 is the tier that defines itself by the vendor counter-signature"
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

        // There is no certified catalogue in this build, so there is nothing to compare
        // the declaration against -- reported as null, not as agreement.
        assert_eq!(answer["catalogue_capabilities"], Value::Null);
        assert_eq!(answer["declared_matches_catalogue"], Value::Null);

        // The capability this tier exists for is conditional, and on whose approval is
        // derived from the kernel's matrix rather than restated here.
        let approvals = answer["required_approvals"].as_array().expect("an array");
        assert_eq!(approvals.len(), 1, "{approvals:?}");
        assert_eq!(approvals[0]["capability"], json!("swarm:consensus"));
        assert_eq!(approvals[0]["authority"], json!("certification-committee"));

        // The honest part: four capabilities declared, and the basic three are not
        // exercised by any op -- while the approval-gated one is.
        assert_eq!(
            answer["declared_capabilities_backed_by_ops"],
            json!(false),
            "no op here reads a lifecycle state, sends a bus message or touches storage"
        );
        assert_eq!(
            answer["every_approval_gated_capability_backed_by_ops"],
            json!(true),
            "`tally` is the op that exercises `swarm:consensus`"
        );
        assert_eq!(
            answer["capability_backing"]["swarm:consensus"],
            json!(["tally"])
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
            json!(Capability::BASIC
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<&str>>())
        );
        assert_eq!(
            answer["ops_not_named_by_a_declared_capability"],
            json!(["capabilities"]),
            "`capabilities` describes the plugin; no declared capability is about describing one"
        );
        assert_eq!(
            answer["op_delegation"]["tally"],
            json!("nau_consensus::Committee::{assign, cast, tally}")
        );
    }

    #[test]
    fn the_binary_claims_the_certified_tier_and_does_not_borrow_the_official_catalogue() {
        assert_eq!(
            Tier::from_name(PLUGIN_NAME).expect("classifies"),
            Tier::Certified
        );
        assert!(Tier::Certified.requires_counter_signature());
        assert!(Tier::Certified.is_loadable());
        assert_eq!(
            Tier::from_label("certified").expect("parses"),
            Tier::Certified
        );

        // The one catalogue in this build is the *official* one. This binary's name is
        // not in it, and saying so is what keeps `declared_matches_catalogue: null` from
        // being read as a claim about a certified catalogue that does not exist.
        assert!(
            nau_plugins::official::Official::find(PLUGIN_NAME).is_none(),
            "the official catalogue must not be treated as a certified one"
        );
    }

    #[test]
    fn every_declared_capability_has_a_backing_row_and_every_row_names_a_real_capability() {
        // Drift guards: adding a capability to the declaration without deciding whether an
        // op backs it, or naming a capability the matrix does not know, both fail here.
        for capability in declared_capabilities() {
            assert!(
                CAPABILITY_BACKING
                    .iter()
                    .any(|(name, _)| *name == capability),
                "`{capability}` is declared with no backing row, so `capabilities` would \
                 report it as if it did not exist"
            );
        }
        for (name, ops) in CAPABILITY_BACKING {
            let parsed =
                Capability::parse(name).expect("the row names a capability the matrix knows");
            assert_eq!(parsed.as_str(), name, "the row's key must be the wire name");
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
        assert!(declared_capabilities().contains(&SENSITIVE_CAPABILITY.as_str()));
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
        let (code, response) = call("rank", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(
            response.code.as_deref(),
            Some(payload::CODE_UNKNOWN_OPERATION)
        );
        let message = response.message.expect("a message");
        assert!(
            message.contains("tally") && message.contains("capabilities"),
            "the known ops must be listed: {message}"
        );
    }

    #[test]
    fn a_tally_payload_of_the_wrong_shape_is_refused_rather_than_guessed() {
        let (spec, identities) = committee_of(4, 1);

        let (code, response) = call("tally", json!([1, 2, 3]));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_NOT_OBJECT));

        // Every required input is required: a misspelled or absent key is a refusal that
        // names the field, not a default.
        for missing in ["spec", "proposal", "members", "votes", "now"] {
            let mut payload = tally_payload(spec, &identities, &[]);
            if let Value::Object(map) = &mut payload {
                map.remove(missing);
            }
            let (code, response) = call("tally", payload);
            assert_eq!(code, EXIT_REFUSED, "`{missing}` must be required");
            assert_eq!(
                response.code.as_deref(),
                Some(CODE_TALLY_PAYLOAD),
                "`{missing}`: {response:?}"
            );
            assert!(
                response.message.expect("a message").contains(missing),
                "the refusal must name the missing field `{missing}`"
            );
        }

        // A committee that cannot exist is refused by the committee's own validator.
        let impossible = json!({
            "spec": { "n": 3, "f": 1 },
            "proposal": PROPOSAL,
            "members": members_of(&identities)[..3].to_vec(),
            "votes": [],
            "now": NOW,
        });
        let (code, response) = call("tally", impossible);
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_TALLY_COMMITTEE));
        assert!(
            response.message.expect("a message").contains("3f+1"),
            "the BFT relation must be the committee's own refusal"
        );

        // A member list that does not match `n` is refused too.
        let short = json!({
            "spec": { "n": 4, "f": 1 },
            "proposal": PROPOSAL,
            "members": members_of(&identities)[..2].to_vec(),
            "votes": [],
            "now": NOW,
        });
        let (code, response) = call("tally", short);
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_TALLY_COMMITTEE));
        assert!(
            response.message.expect("a message").contains("exactly 4"),
            "the refusal must say how many members `n` requires"
        );
    }

    #[test]
    fn a_diagnostic_built_from_caller_json_stays_bounded() {
        // An enum with a long unknown variant makes serde_json quote the caller's
        // string. That string is the caller's, so it must not decide how much this
        // plugin writes -- and the field is ordered before the ones that would need a
        // real key, so the refusal happens at the caller's own value.
        let (spec, identities) = committee_of(4, 1);
        let long = "x".repeat(MAX_DIAGNOSTIC_CHARS * 4);
        let payload = json!({
            "spec": spec,
            "proposal": PROPOSAL,
            "members": members_of(&identities),
            "now": NOW,
            "votes": [ {
                "round": 0,
                "proposal": PROPOSAL,
                "voter": identities[0].did().as_str(),
                "decision": long,
                "nonce": 1,
                "signed_at": NOW,
                "voter_key": identities[0].public_key().to_hex(),
            } ],
        });
        let (code, response) = call("tally", payload);
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_TALLY_PAYLOAD));
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
