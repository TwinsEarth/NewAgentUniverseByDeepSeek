//! `com.twinsearth.official.skill` — which agents can do a job, decided from a caller-supplied
//! roster.
//!
//! # What this port is, and what it deliberately is not
//!
//! `agent-universe` v3.5.0's `com.twinsearth.official.agent-skill` is the skill door of its
//! four business-enabled official plugins. This is that door's **semantics**, not its code: our
//! process plugins are native binaries speaking the frame ABI, and upstream's are Python run in
//! a sandbox, so nothing here is copied.
//!
//! The op it adds is `match`: given the skills a task requires and a roster of agents, say which
//! agents can take it. The roster is **caller-supplied**, because a process plugin cannot read
//! the market — that is the T0 plugins' job, and a T2 door that pretended otherwise would be
//! reporting a neighbourhood it cannot see.
//!
//! # The one rule, and where it comes from
//!
//! Skill ids match **case-insensitively on the lowercased id**. That is not this plugin's
//! invention: `Market::discover` lowercases its query and looks it up in the skill index built
//! from `AgentCard.skills`, and [`Skill::new`] lowercases on construction. This door applies the
//! same rule and says so in every answer, so a host never has to guess whether two doors agree.
//!
//! Skills are **parsed** through [`Skill`] rather than through a local struct: a second parser
//! would be a second spelling of a skill, and the two would drift.
//!
//! # What the answer refuses to claim
//!
//! * **A version is reported, never inferred.** `min_version` is applied only when the caller
//!   supplies it; a matching agent whose version is lower is `below_floor`, not silently
//!   dropped and not silently accepted.
//! * **A match is not a recommendation.** The answer lists who *can* do the job; it ranks
//!   nobody and consults no reputation, because both of those belong to doors that own that
//!   state.
//! * **An empty roster is an answer, not a refusal.** "Nobody here can do this" is the question
//!   the op exists to answer.
//!
//! # Fail-closed choices
//!
//! * an unknown op, an incompatible `abi` and a payload of the wrong shape are each a typed
//!   refusal, never an empty success;
//! * a roster entry with no `did` is a refusal rather than an unnamed match, because a match
//!   nobody can act on is not an answer;
//! * a duplicate `did` is a refusal: two entries for one agent would make "how many agents can
//!   do this" depend on how the caller spelled the list;
//! * a diagnostic echoed back to the host is bounded, because an error string built from
//!   caller-supplied JSON is how a log becomes an attack surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_core::domain::agent::Skill;
use nau_plugin::capability::{Capability, Grant};
use nau_plugins::frame::{self, Response};
use nau_plugins::official::Official;
use nau_plugins::payload;
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// The catalogue name this binary implements, from [`nau_plugins::official::OFFICIALS`]. The
/// tier is derived from this name, so the spelling is not cosmetic.
const PLUGIN_NAME: &str = "com.twinsearth.official.skill";

/// The version this binary reports, which is the catalogue entry's version rather than the
/// workspace's. A test asserts the two are equal, so a catalogue bump that forgets this
/// constant fails instead of shipping a plugin that lies about its own version.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named in [`OP_DELEGATION`] is
/// listed here, so this table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 2] = ["capabilities", "match"];

/// The capability set this binary's manifest declares.
///
/// `plugin:storage:own` is what the catalogue entry for this plugin names, and it is one of the
/// three capabilities every loadable tier holds by construction — so the official tier's
/// approval machinery is not triggered by this declaration at all. That is the accurate state,
/// and the answer says so with an empty `required_approvals` rather than by inventing a
/// capability this plugin does not need.
const DECLARED_CAPABILITIES: [&str; 1] = ["plugin:storage:own"];

/// Which implemented op exercises each declared capability.
///
/// Empty, and that is the honest state rather than a placeholder: `match` is a computation over
/// a caller-supplied roster, and it reads and writes no sandbox directory. Reporting an op here
/// would be a claim that this binary does that capability's work, which it does not.
const CAPABILITY_BACKING: [(&str, &[&str]); 1] = [("plugin:storage:own", &[])];

/// Which crate function each implemented op delegates to, as `(op, target)`.
///
/// Reported in the `capabilities` answer so a host can see the delegation rather than having to
/// trust a description of it.
const OP_DELEGATION: [(&str, &str); 2] = [
    ("capabilities", "nau_plugins::official::OFFICIALS"),
    (
        "match",
        "nau_core::domain::agent::Skill (parsing) + the lowercased-id rule Market::discover \
         applies",
    ),
];

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "`match` decides from a caller-supplied roster: a process plugin cannot read \
                     the market, and a door that pretended to would be reporting a neighbourhood \
                     it cannot see. Skill ids match case-insensitively on the lowercased id -- \
                     the rule `Market::discover` applies to the index built from \
                     `AgentCard.skills`, and the rule `Skill::new` applies on construction -- and \
                     skills are parsed through `nau_core::domain::agent::Skill` rather than a \
                     local struct, because a second parser is a second spelling of a skill. \
                     `min_version` is applied only when supplied. The answer ranks nobody and \
                     consults no reputation: both belong to doors that own that state.";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: a payload is not a JSON object.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: a `match` payload is an object but not the shape this op documents.
const CODE_MATCH_PAYLOAD: &str = "skill_match_payload_invalid";
/// Error code: the roster names one agent twice.
const CODE_DUPLICATE_AGENT: &str = "skill_match_duplicate_agent";
/// Error code: this binary and the official catalogue disagree about its own identity.
const CODE_CAPABILITIES: &str = "skill_capabilities_unavailable";

/// Longest diagnostic quoted back to the host, in characters.
///
/// The message is written into a frame the host logs, and a `serde_json` diagnostic for a wrong
/// enum variant quotes the offending string — which the caller chose. Bounding it keeps a
/// caller from deciding how much text this plugin writes.
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

/// The `match` payload: what the job needs, and who is available.
///
/// Deliberately not `deny_unknown_fields`: the frame envelope is additive within a major, and a
/// payload that refused new keys would break that promise one layer down.
#[derive(Debug, Deserialize)]
struct MatchRequest {
    /// The skills the task requires. An empty list matches every agent, which is the honest
    /// reading of "this job requires nothing".
    #[serde(default)]
    required: Vec<String>,
    /// The agents to consider.
    #[serde(default)]
    agents: Vec<RosterEntry>,
    /// When supplied, an agent whose version for a required skill is below this is reported
    /// `below_floor` rather than matched. Absent means no floor is applied — and the answer
    /// says which of the two happened.
    #[serde(default)]
    min_version: Option<u32>,
}

/// One agent in the roster.
#[derive(Debug, Deserialize)]
struct RosterEntry {
    /// The agent's DID. Required: a match nobody can act on is not an answer.
    did: String,
    /// The skills the agent claims, parsed by [`Skill`] so the spelling rule is `nau_core`'s.
    #[serde(default)]
    skills: Vec<Skill>,
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
            // The frame was readable but not a request: answer with the refusal, so a host sees
            // a typed code rather than a dead process.
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
        "match" => match matched(&request.payload) {
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

/// Bound a diagnostic before it is written into a frame the host logs.
fn bounded(message: &str) -> String {
    if message.chars().count() <= MAX_DIAGNOSTIC_CHARS {
        return message.to_string();
    }
    let kept: String = message.chars().take(MAX_DIAGNOSTIC_CHARS).collect();
    format!(
        "{kept}... ({} characters truncated)",
        message.chars().count() - MAX_DIAGNOSTIC_CHARS
    )
}

/// Which agents can do the job, and for the rest, what they are missing.
fn matched(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `match` payload must be a JSON object carrying `required` and `agents`, found \
                 {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: MatchRequest = serde_json::from_value(payload.clone()).map_err(|err| Refusal {
        code: CODE_MATCH_PAYLOAD,
        message: bounded(&err.to_string()),
    })?;

    // The rule, applied once: every id on both sides is lowercased before it is compared, the
    // same way `Market::discover` lowercases its query.
    let required: Vec<String> = request
        .required
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    // Two entries for one agent would make the count depend on how the caller spelled the
    // list, so it is a refusal rather than a silent merge.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for entry in &request.agents {
        if entry.did.trim().is_empty() {
            return Err(Refusal {
                code: CODE_MATCH_PAYLOAD,
                message: "every roster entry needs a non-empty `did`: a match nobody can act on \
                          is not an answer"
                    .to_string(),
            });
        }
        if !seen.insert(entry.did.as_str()) {
            return Err(Refusal {
                code: CODE_DUPLICATE_AGENT,
                message: format!(
                    "`{}` appears twice in the roster; one agent must be one entry, or the count \
                     of who can do the job depends on how the list was written",
                    entry.did
                ),
            });
        }
    }

    let mut can: Vec<Value> = Vec::new();
    let mut cannot: Vec<Value> = Vec::new();
    let mut below_floor: Vec<Value> = Vec::new();

    for entry in &request.agents {
        // The best version this agent claims for each required skill. `max` rather than the
        // first: an agent that claims one skill at two versions offers the higher one.
        let mut offered: BTreeMap<String, u32> = BTreeMap::new();
        for skill in &entry.skills {
            let id = skill.id.to_ascii_lowercase();
            let slot = offered.entry(id).or_insert(skill.version);
            *slot = (*slot).max(skill.version);
        }

        let missing: Vec<&String> = required
            .iter()
            .filter(|need| !offered.contains_key(need.as_str()))
            .collect();

        if !missing.is_empty() {
            cannot.push(json!({
                "did": entry.did,
                "missing": missing,
            }));
            continue;
        }

        let matched_skills: Vec<Value> = required
            .iter()
            .map(|need| {
                let version = offered.get(need.as_str()).copied().unwrap_or(0);
                json!({ "skill": need, "version": version })
            })
            .collect();

        // The floor is applied only when the caller supplied one, and a below-floor agent is
        // reported rather than dropped: dropping it would make "no agent can do this" and "the
        // best agent is one version short" the same answer.
        let weakest = required
            .iter()
            .map(|need| offered.get(need.as_str()).copied().unwrap_or(0))
            .min()
            .unwrap_or(0);
        match request.min_version {
            Some(floor) if weakest < floor => below_floor.push(json!({
                "did": entry.did,
                "weakest_version": weakest,
                "floor": floor,
                "matched": matched_skills,
            })),
            _ => can.push(json!({
                "did": entry.did,
                "weakest_version": weakest,
                "matched": matched_skills,
            })),
        }
    }

    Ok(json!({
        "required": required,
        "can": can,
        "cannot": cannot,
        "below_floor": below_floor,
        "can_count": can.len(),
        "roster_count": request.agents.len(),
        "min_version": request.min_version,
        "version_floor_applied": request.min_version.is_some(),
        "match_rule": "case-insensitive on the lowercased skill id -- the rule \
                       `Market::discover` applies to the index built from `AgentCard.skills`",
        "ranks_nobody": true,
        "consults_reputation": false,
        "decided_from": "caller-supplied roster; a process plugin cannot read the market",
    }))
}

/// Which implemented op exercises a declared capability, if any.
fn capability_backing(capability: &str) -> &'static [&'static str] {
    for (name, ops) in CAPABILITY_BACKING {
        if name == capability {
            return ops;
        }
    }
    &[]
}

/// Report this binary's identity, its delegation and what it deliberately does not do.
fn capabilities() -> Answer {
    let entry = Official::find(PLUGIN_NAME).ok_or_else(|| Refusal {
        code: CODE_CAPABILITIES,
        message: format!(
            "`{PLUGIN_NAME}` is not in `nau_plugins::official::OFFICIALS`; this binary and the \
             catalogue disagree about its identity, so nothing about it can be reported"
        ),
    })?;

    // The version, checked rather than assumed: this constant is written down twice, and a
    // catalogue bump that forgets the binary would otherwise ship a plugin that lies about
    // itself in the one op whose whole job is to describe it.
    if entry.version != PLUGIN_VERSION {
        return Err(Refusal {
            code: CODE_CAPABILITIES,
            message: format!(
                "the catalogue says `{PLUGIN_NAME}` is version {} and this binary is \
                 {PLUGIN_VERSION}",
                entry.version
            ),
        });
    }

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
    // `Refused` is a declaration this tier may not hold at all, which is a refusal here rather
    // than a line item, because the manifest would not load anyway.
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
    for capability in DECLARED_CAPABILITIES {
        let ops = capability_backing(capability);
        if ops.is_empty() {
            all_backed = false;
        }
        backing.insert(capability.to_string(), json!(ops));
    }

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
        "declared_capabilities_backed_by_ops": all_backed,
        "capability_backing": Value::Object(backing),
        "implemented_ops": IMPLEMENTED_OPS,
        "delegation": Value::Object(delegation),
        "notes": NOTES,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Imported here rather than at the top: the binary never names Tier -- it reads the label
    // off the value Official::tier returns -- and an import the production code does not use
    // is a claim about the production code that is not true.
    use nau_plugin::tier::Tier;

    /// Encode a request, run one frame through this binary's own `run`, and decode the answer.
    fn call(op: &str, payload: Value) -> (Response, u8) {
        let request = json!({
            "id": "skill-test",
            "abi": frame::abi_version(),
            "op": op,
            "payload": payload,
        });
        // The request goes on the wire **framed**, not as a bare JSON body: the length prefix is
        // part of the ABI, and a helper that skipped it would be testing a protocol this binary
        // does not speak.
        let mut wire = Vec::new();
        frame::write_frame(&mut wire, &serde_json::to_vec(&request).expect("encodes"))
            .expect("writes");
        let mut output = Vec::new();
        let code = run(&mut wire.as_slice(), &mut output);
        let decoded = frame::read_frame(&mut std::io::Cursor::new(output))
            .expect("reads")
            .expect("a frame");
        (frame::decode_response(&decoded).expect("decodes"), code)
    }

    /// The refusal text, for tests that assert on prose.
    fn refusal(response: &Response) -> String {
        response.message.clone().unwrap_or_default()
    }

    /// The refusal code, which is a field of its own rather than a substring of the prose.
    fn code_of(response: &Response) -> String {
        response.code.clone().unwrap_or_default()
    }

    /// The answer, for tests that assert on the payload.
    fn answer(response: &Response) -> Value {
        response.payload.clone().expect("a payload")
    }

    fn roster(entries: &[(&str, &[(&str, u32)])]) -> Value {
        Value::Array(
            entries
                .iter()
                .map(|(did, skills)| {
                    json!({
                        "did": did,
                        "skills": skills
                            .iter()
                            .map(|(id, version)| json!({ "id": id, "version": version }))
                            .collect::<Vec<Value>>(),
                    })
                })
                .collect(),
        )
    }

    #[test]
    fn the_catalogue_entry_exists_and_agrees_with_this_binary() {
        let official = Official::find(PLUGIN_NAME).expect("the catalogue names this plugin");
        assert_eq!(official.version, PLUGIN_VERSION);
        assert_eq!(official.tier().expect("classifies"), Tier::Official);
    }

    #[test]
    fn every_implemented_op_is_dispatched_and_documented() {
        for op in IMPLEMENTED_OPS {
            // `capabilities` needs no payload, and `match` accepts an empty one -- an empty
            // roster matches nobody, which is an answer rather than a refusal.
            let (response, code) = call(op, json!({}));
            assert_eq!(
                code,
                EXIT_OK,
                "`{op}` is listed as implemented but refused an empty payload: {}",
                refusal(&response)
            );
        }
        for (op, _) in OP_DELEGATION {
            assert!(
                IMPLEMENTED_OPS.contains(&op),
                "`{op}` is documented as delegated but is not implemented"
            );
        }
    }

    #[test]
    fn a_skill_matches_case_insensitively_on_the_lowercased_id() {
        let (response, code) = call(
            "match",
            json!({
                "required": ["Text-Generation"],
                "agents": roster(&[("did:nau:aa", &[("TEXT-GENERATION", 3)])]),
            }),
        );
        assert_eq!(code, EXIT_OK, "{}", refusal(&response));
        let a = answer(&response);
        assert_eq!(a["can_count"], 1, "{a}");
        assert_eq!(a["can"][0]["did"], "did:nau:aa", "{a}");
        assert_eq!(
            a["can"][0]["weakest_version"], 3,
            "the version claim must survive normalisation: {a}"
        );
        // What the answer reports is the normalised id, so a host compares it against the index
        // the market built rather than against whatever the caller typed.
        assert_eq!(a["required"][0], "text-generation", "{a}");
    }

    #[test]
    fn an_agent_missing_one_required_skill_is_reported_with_what_it_lacks() {
        let (response, _) = call(
            "match",
            json!({
                "required": ["rust", "solidity"],
                "agents": roster(&[("did:nau:aa", &[("rust", 1)])]),
            }),
        );
        let a = answer(&response);
        assert_eq!(a["can_count"], 0, "{a}");
        assert_eq!(a["cannot"][0]["did"], "did:nau:aa", "{a}");
        assert_eq!(a["cannot"][0]["missing"], json!(["solidity"]), "{a}");
    }

    #[test]
    fn the_version_floor_is_applied_only_when_supplied_and_is_reported_not_dropped() {
        let payload = json!({
            "required": ["rust"],
            "agents": roster(&[("did:nau:aa", &[("rust", 1)])]),
        });

        // No floor: the agent matches, and the answer says no floor was applied.
        let (without, _) = call("match", payload.clone());
        let plain = answer(&without);
        assert_eq!(plain["can_count"], 1, "{plain}");
        assert_eq!(plain["version_floor_applied"], false, "{plain}");
        assert_eq!(plain["min_version"], Value::Null, "{plain}");

        // With a floor it cannot meet it moves to `below_floor` -- neither dropped nor accepted.
        let mut floored = payload;
        floored["min_version"] = json!(5);
        let (with, _) = call("match", floored);
        let gated = answer(&with);
        assert_eq!(gated["can_count"], 0, "{gated}");
        assert_eq!(gated["below_floor"][0]["weakest_version"], 1, "{gated}");
        assert_eq!(gated["below_floor"][0]["floor"], 5, "{gated}");
        assert_eq!(gated["version_floor_applied"], true, "{gated}");
    }

    #[test]
    fn the_best_version_an_agent_claims_is_the_one_used() {
        let (response, _) = call(
            "match",
            json!({
                "required": ["rust"],
                "agents": roster(&[("did:nau:aa", &[("rust", 2), ("rust", 7), ("rust", 4)])]),
            }),
        );
        let a = answer(&response);
        assert_eq!(a["can"][0]["weakest_version"], 7, "{a}");
    }

    #[test]
    fn an_empty_roster_is_an_answer_not_a_refusal() {
        let (response, code) = call("match", json!({ "required": ["rust"], "agents": [] }));
        assert_eq!(code, EXIT_OK, "{}", refusal(&response));
        let a = answer(&response);
        assert_eq!(a["can_count"], 0, "{a}");
        assert_eq!(a["roster_count"], 0, "{a}");
    }

    #[test]
    fn a_roster_entry_without_a_did_is_refused_rather_than_named_empty() {
        let (response, code) = call(
            "match",
            json!({
                "required": ["rust"],
                "agents": [{ "skills": [{ "id": "rust", "version": 1 }] }],
            }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(code_of(&response), CODE_MATCH_PAYLOAD, "{response:?}");
    }

    #[test]
    fn one_agent_twice_is_refused_because_it_would_change_the_count() {
        let (response, code) = call(
            "match",
            json!({
                "required": ["rust"],
                "agents": roster(&[
                    ("did:nau:aa", &[("rust", 1)]),
                    ("did:nau:aa", &[("rust", 2)]),
                ]),
            }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(code_of(&response), CODE_DUPLICATE_AGENT, "{response:?}");
    }

    #[test]
    fn the_answer_states_the_rule_and_what_it_does_not_do() {
        let (response, _) = call("match", json!({ "required": [], "agents": [] }));
        let a = answer(&response);
        assert!(
            a["match_rule"]
                .as_str()
                .unwrap_or("")
                .contains("lowercased"),
            "{a}"
        );
        assert_eq!(a["ranks_nobody"], true, "{a}");
        assert_eq!(a["consults_reputation"], false, "{a}");
    }

    #[test]
    fn an_unknown_op_is_refused_with_the_list_of_implemented_ones() {
        let (response, code) = call("summon", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(
            code_of(&response),
            payload::CODE_UNKNOWN_OPERATION,
            "{response:?}"
        );
        assert!(refusal(&response).contains("match"), "{response:?}");
    }

    #[test]
    fn a_payload_that_is_not_an_object_is_refused_by_shape() {
        let (response, code) = call("match", json!([1, 2, 3]));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(code_of(&response), CODE_NOT_OBJECT, "{response:?}");
    }

    #[test]
    fn capabilities_reports_identity_tier_and_an_empty_approval_set() {
        let (response, code) = call("capabilities", json!({}));
        assert_eq!(code, EXIT_OK, "{}", refusal(&response));
        let a = answer(&response);
        assert_eq!(a["plugin"], PLUGIN_NAME);
        assert_eq!(a["tier"], "official", "the tier label is lower case: {a}");
        assert_eq!(a["declared_matches_catalogue"], true, "{a}");
        assert_eq!(a["required_approvals"], json!([]), "{a}");
        // Declared but not exercised, said in a field rather than in prose.
        assert_eq!(a["declared_capabilities_backed_by_ops"], false, "{a}");
    }
}
