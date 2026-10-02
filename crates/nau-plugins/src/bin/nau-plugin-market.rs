//! `nau-plugin-market` — the first **official (T1) plugin that is an executable**.
//!
//! `docs/PLUGIN-MIGRATION.md` §3 says all eleven official plugins exist as manifests and
//! that **none of them runs**. This binary is the attempt to make that sentence false
//! for one of them, and what makes it count is narrow and checkable:
//!
//! * it is a real file a host can start, and it speaks the host ABI frame from
//!   [`nau_plugins::frame`] — the same codec `nau-plugin-echo` speaks, not a second
//!   implementation of it;
//! * its `rank` op delegates to [`nau_market::matching::rank_bids`], the marketplace's
//!   real ranking function, and returns a projection of the value that function
//!   actually returns;
//! * its `capabilities` op reports what the catalogue *declares* next to what this
//!   binary *implements*, so a host can compare the two instead of trusting either.
//!
//! # What it is not
//!
//! It is **not** registration, task lifecycle or settlement, although the catalogue
//! entry `com.twinsearth.official.market` declares all three
//! ([`nau_plugins::official::OFFICIALS`]). `rank` is a *matching* operation and the
//! kernel's capability matrix has no matching token, so **no declared capability is
//! exercised by an implemented op** — and the `capabilities` answer says so in a
//! machine-readable field (`declared_capabilities_backed_by_ops: false`) rather than
//! leaving a host to infer it. Saying "the market plugin runs" without that caveat
//! would be the "declared but not wired" defect this project exists to stop; the whole
//! point of the second op is that the caveat is an answer, not a comment.
//!
//! # Protocol
//!
//! ```text
//! stdin:  u32_be(len) || {"abi":"3.2","id":"req-1","op":"rank","payload":{…}}
//! stdout: u32_be(len) || {"abi":"3.2","id":"req-1",
//!                         "plugin":"com.twinsearth.official.market",
//!                         "version":"1.0.0","ok":true,"payload":{…}}
//! ```
//!
//! One frame in, one frame out, then exit. stdout carries **only** frames; every
//! diagnostic goes to stderr, because a stray `println!` is a protocol corruption and
//! this binary has no other way to talk to its host.
//!
//! ## `rank`
//!
//! The payload mirrors [`rank_bids`]' **real** parameters, because the shape was
//! designed after reading its signature rather than before:
//!
//! ```json
//! {
//!   "task":        { …a serialized `nau_core::Task`… },
//!   "bids":        [ { …`nau_core::Bid`… } ],
//!   "agents":      { "did:nau:…": { …`nau_core::AgentCard`… } },
//!   "reputations": { "did:nau:…": { …`nau_market::Reputation`… } }
//! }
//! ```
//!
//! `task` is required; the other three default to empty, and an empty `agents` is not a
//! silent success: every bid is then reported in `skipped` and the call is refused with
//! `market_rank_failed`, so a misspelled key fails loudly rather than ranking nothing.
//!
//! ```json
//! {
//!   "winner":      "did:nau:…",
//!   "price_minor": 10000000,
//!   "score":       898710000000,
//!   "ranked":      [ { "did": "did:nau:…", "score": 898710000000 } ],
//!   "skipped":     [ { "did": "did:nau:…", "reason": "bid price is not positive" } ]
//! }
//! ```
//!
//! `price_minor` is minor units (10⁻⁶ of a major unit), which is exactly how
//! `nau_core::Money` serializes; there is no decimal re-formatting here that could
//! disagree with the rest of the workspace.
//!
//! **This op ranks, it does not authenticate.** `rank_bids` does not verify bid
//! signatures — the market's `submit_bid` does that on the way in — so this binary
//! inherits that boundary instead of inventing a second, weaker one. A host that needs
//! authenticated ranking must verify before calling.
//!
//! ## `capabilities`
//!
//! Takes no arguments. Returns the plugin's declared capability set, the catalogue's
//! set, whether the two agree, the approvals the official tier needs for what is
//! declared, the ops this binary actually implements, which op (if any) exercises each
//! declared capability, and which crate function each op delegates to.
//!
//! # Exit codes
//!
//! `0` answered, `1` answered with `ok: false`, `2` the frame itself could not be read
//! or written. The distinction is `nau-plugin-echo`'s and is deliberately unchanged:
//! `2` means the binary is not speaking this ABI at all, which is a different repair
//! from "the plugin refused the call".
//!
//! # Fail-closed choices
//!
//! * an unknown op, an incompatible `abi` and a payload of the wrong shape are each a
//!   typed refusal, never an empty success;
//! * unknown *keys* inside a payload are tolerated (the same additive-within-a-major
//!   rule the frame envelope follows), which is safe here because a key that is missing
//!   produces skipped bids or a typed refusal rather than a plausible-looking answer;
//! * a diagnostic echoed back to the host is bounded, because an error string built
//!   from caller-supplied JSON is how a log becomes an attack surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_core::{AgentCard, Bid, Did, Task};
use nau_market::matching::{rank_bids, MatchOutcome};
use nau_market::Reputation;
use nau_plugins::frame::{self, Response};
use nau_plugins::official::Official;
use nau_plugins::payload;
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// The catalogue name this binary implements, from
/// [`nau_plugins::official::OFFICIALS`]. The tier is derived from this name, so the
/// spelling is not cosmetic: `off.market` would classify as a different tier.
const PLUGIN_NAME: &str = "com.twinsearth.official.market";

/// The version this binary reports, which is the version of the catalogue entry it
/// implements rather than the workspace's. A test asserts the two are equal, so a
/// catalogue bump that forgets this constant fails the build instead of shipping a
/// plugin that lies about its own version.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named in
/// [`OP_DELEGATION`] is listed here, so this table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 2] = ["capabilities", "rank"];

/// The capability set this binary's own manifest declares.
///
/// Held here as well as in the catalogue on purpose: the two are independent inputs, so
/// `capabilities` can compare them **at runtime** instead of deriving one claim from
/// the other and always agreeing with itself.
const DECLARED_CAPABILITIES: [&str; 3] =
    ["agent:card:create", "agent:card:update", "economy:settle"];

/// Which implemented op exercises each declared capability.
///
/// Every row is empty, and that is the honest current state rather than a placeholder:
/// `rank` is matching, not registration or settlement, so **none** of the three
/// declared capabilities is backed by an implemented op. Listing an op here would be a
/// claim that this binary does that capability's work, which it does not.
const CAPABILITY_BACKING: [(&str, &[&str]); 3] = [
    ("agent:card:create", &[]),
    ("agent:card:update", &[]),
    ("economy:settle", &[]),
];

/// Which crate function each implemented op delegates to, as `(op, target)`.
///
/// Reported in the `capabilities` answer so a host can see the delegation rather than
/// having to trust a description of it.
const OP_DELEGATION: [(&str, &str); 2] = [
    ("capabilities", "nau_plugins::official::OFFICIALS"),
    ("rank", "nau_market::matching::rank_bids"),
];

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "`rank` delegates to nau_market::matching::rank_bids, a matching operation; the \
                     capability matrix has no matching token and no declared capability is exercised \
                     by an implemented op. The declaration is the catalogue's, not a claim that \
                     registration, task lifecycle or settlement is implemented.";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: a `rank` payload is not a JSON object.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: a `rank` payload is an object but not the shape `rank_bids` needs.
const CODE_RANK_PAYLOAD: &str = "market_rank_payload_invalid";
/// Error code: the marketplace itself refused to rank (for example, no scoreable bid).
const CODE_RANK_FAILED: &str = "market_rank_failed";
/// Error code: this binary and the official catalogue disagree about its own identity.
const CODE_CAPABILITIES: &str = "market_capabilities_unavailable";

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

/// The `rank` payload, as [`rank_bids`] actually consumes it.
///
/// Deliberately not `deny_unknown_fields`: the frame envelope is additive within a
/// major, and a payload that refused new keys would break that promise one layer down.
/// The tolerance is safe rather than silent, because a missing map produces a refusal
/// that names every skipped bid.
#[derive(Debug, Deserialize)]
struct RankRequest {
    /// The task the bids target. `rank_bids` reads its id and its budget.
    task: Task,
    /// The bids to rank. Defaults to none, which is then a typed refusal.
    #[serde(default)]
    bids: Vec<Bid>,
    /// Registered agent cards, keyed by DID — `rank_bids`' third parameter.
    #[serde(default)]
    agents: BTreeMap<Did, AgentCard>,
    /// Reputations, keyed by DID — `rank_bids`' fourth parameter.
    #[serde(default)]
    reputations: BTreeMap<Did, Reputation>,
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
        "rank" => match rank(&request.payload) {
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

/// Rank the payload's bids with the marketplace's own ranking function.
fn rank(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `rank` payload must be a JSON object carrying `task` (and optionally `bids`, \
                 `agents`, `reputations`), found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: RankRequest = serde_json::from_value(payload.clone()).map_err(|err| Refusal {
        code: CODE_RANK_PAYLOAD,
        message: bounded(&err.to_string()),
    })?;

    // The one line this whole binary exists for: the marketplace's real function, on the
    // caller's real inputs, with its real return value.
    let outcome = rank_bids(
        &request.task,
        &request.bids,
        &request.agents,
        &request.reputations,
    )
    .map_err(|err| Refusal {
        code: CODE_RANK_FAILED,
        message: bounded(&err.to_string()),
    })?;

    outcome_payload(&outcome)
}

/// Project [`MatchOutcome`] into the JSON a host receives.
///
/// Faithful on purpose: every field here comes from the returned struct, and nothing is
/// recomputed. A host can therefore compare this answer against a direct call to
/// `rank_bids` and get the same numbers.
fn outcome_payload(outcome: &MatchOutcome) -> Answer {
    let score = score_to_json(outcome.score)?;

    let mut ranked = Vec::with_capacity(outcome.ranked.len());
    for (did, bid_score) in &outcome.ranked {
        ranked.push(json!({
            "did": did.as_str(),
            "score": score_to_json(*bid_score)?,
        }));
    }

    let mut skipped = Vec::with_capacity(outcome.skipped.len());
    for (did, reason) in &outcome.skipped {
        skipped.push(json!({
            "did": did.as_str(),
            "reason": bounded(reason),
        }));
    }

    Ok(json!({
        "winner": outcome.winner.as_str(),
        "price_minor": outcome.price.minor(),
        "score": score,
        "ranked": ranked,
        "skipped": skipped,
    }))
}

/// Report an `i128` score as a JSON number, refusing rather than truncating.
///
/// `rank_bids` scores in `i128`; every JSON number this ABI can carry without a
/// precision promise is an `i64`. The two currently fit (`reputation_bps ≤ 10⁴`,
/// `price ≥ 1` minor unit, penalty `≤ 10⁴`), and if that ever stops being true the host
/// gets a refusal rather than a number that silently changed.
fn score_to_json(score: i128) -> std::result::Result<i64, Refusal> {
    i64::try_from(score).map_err(|_| Refusal {
        code: CODE_RANK_FAILED,
        message: format!("the score {score} does not fit in the i64 this ABI reports scores as"),
    })
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

    let approvals = entry.approvals().map_err(|err| Refusal {
        code: CODE_CAPABILITIES,
        message: bounded(&err.to_string()),
    })?;
    let mut required_approvals = Vec::new();
    for (capability, authority) in &approvals {
        required_approvals.push(json!({
            "capability": capability.as_str(),
            "authority": authority.label(),
        }));
    }

    // The declaration the host is being asked to trust, audited one capability at a
    // time. An empty list of ops means "declared but not exercised", which is a fact a
    // host must be able to read without interpreting prose.
    let mut backing = Map::new();
    let mut all_backed = true;
    for capability in DECLARED_CAPABILITIES {
        let ops = capability_backing(capability);
        if ops.is_empty() {
            all_backed = false;
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
    let declared_matches_catalogue = declared_sorted == catalogue_sorted;

    Ok(json!({
        "plugin": PLUGIN_NAME,
        "version": PLUGIN_VERSION,
        "tier": tier.label(),
        "summary": entry.summary,
        "from": entry.from,
        "catalogue_capabilities": catalogue_capabilities,
        "declared_capabilities": DECLARED_CAPABILITIES,
        "declared_matches_catalogue": declared_matches_catalogue,
        "required_approvals": required_approvals,
        "implemented_ops": IMPLEMENTED_OPS,
        "capability_backing": Value::Object(backing),
        "declared_capabilities_backed_by_ops": all_backed,
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
    use nau_core::domain::money::major;
    use nau_core::{
        Identity, Money, ReputationScore, Skill, Sla, TaskId, TaskSpec, Verifiable,
        VerificationPolicy,
    };
    use nau_plugins::frame::{decode_response, Request};

    fn identity(seed: u8) -> Identity {
        Identity::from_seed(&[seed; 32])
    }

    fn agent_card(id: &Identity, name: &str, p95_ms: u64) -> AgentCard {
        let mut card = AgentCard::draft(
            id,
            name,
            vec![Skill::new("translation", 1)],
            major(100),
            1_700_000_000,
            1,
        );
        card.sla = Sla {
            latency_p95_ms: p95_ms,
            availability_bps: 9_900,
            max_concurrency: 4,
        };
        card.sign(id).expect("signs");
        card
    }

    fn task_for(requester: &Identity, budget_minor: i64) -> Task {
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
            Money::from_minor(budget_minor),
            None,
            VerificationPolicy::Committee { n: 4, f: 1 },
            requester.public_key(),
            1_700_000_000,
            1,
        );
        task.sign(requester).expect("signs");
        task
    }

    fn bid(task: &Task, bidder: &Identity, price_minor: i64, eta_secs: u64, nonce: u64) -> Bid {
        let mut bid = Bid {
            task_id: task.id.clone(),
            bidder: bidder.did(),
            bidder_key: bidder.public_key(),
            price: Money::from_minor(price_minor),
            eta_secs,
            confidence_bps: 9_000,
            expires_at: None,
            nonce,
            signed_at: 1_700_000_100,
            signature: String::new(),
        };
        bid.sign(bidder).expect("signs");
        bid
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

    #[test]
    fn rank_answers_with_exactly_what_rank_bids_returned() {
        // The central claim of this binary, tested the only way that can distinguish a
        // delegation from a canned answer: run both and compare.
        let requester = identity(1);
        let good = identity(2);
        let cheap = identity(3);
        let task = task_for(&requester, 50_000_000);

        let mut agents = BTreeMap::new();
        agents.insert(good.did(), agent_card(&good, "good", 1_000));
        agents.insert(cheap.did(), agent_card(&cheap, "cheap", 1_000));
        let mut reputations = BTreeMap::new();
        reputations.insert(
            good.did(),
            Reputation {
                quality: ReputationScore::clamped(10_000),
                honesty: ReputationScore::clamped(10_000),
                ..Reputation::default()
            },
        );

        // A zero-priced bid is the upstream defect this ranking function exists to
        // refuse, so the fixture pins that rule as well as the ordering.
        let bids = vec![
            bid(&task, &cheap, 0, 1, 1),
            bid(&task, &good, 10_000_000, 1, 1),
        ];

        let expected = rank_bids(&task, &bids, &agents, &reputations).expect("ranks");
        assert_eq!(expected.winner, good.did());
        assert_eq!(expected.skipped.len(), 1);

        let (code, response) = call(
            "rank",
            json!({
                "task": task,
                "bids": bids,
                "agents": agents,
                "reputations": reputations,
            }),
        );
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(response.ok);
        assert_eq!(response.plugin, PLUGIN_NAME);
        assert_eq!(response.version, PLUGIN_VERSION);

        let answer = response.payload.expect("a payload");
        assert_eq!(answer["winner"], json!(expected.winner.as_str()));
        assert_eq!(
            answer["price_minor"].as_i64(),
            Some(expected.price.minor()),
            "the price is the winner's real bid, not the budget"
        );
        assert_eq!(
            answer["score"].as_i64(),
            i64::try_from(expected.score).ok(),
            "the score is the ranking function's own integer"
        );

        let ranked = answer["ranked"].as_array().expect("an array");
        assert_eq!(ranked.len(), expected.ranked.len());
        for (got, want) in ranked.iter().zip(expected.ranked.iter()) {
            assert_eq!(got["did"], json!(want.0.as_str()));
            assert_eq!(got["score"].as_i64(), i64::try_from(want.1).ok());
        }

        let skipped = answer["skipped"].as_array().expect("an array");
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0]["did"], json!(cheap.did().as_str()));
        assert!(
            skipped[0]["reason"]
                .as_str()
                .expect("a reason")
                .contains("price"),
            "the refusal must name the field: {skipped:?}"
        );
    }

    #[test]
    fn a_bid_from_an_unregistered_agent_is_skipped_rather_than_aborting_the_match() {
        let requester = identity(1);
        let known = identity(2);
        let ghost = identity(3);
        let task = task_for(&requester, 50_000_000);

        let mut agents = BTreeMap::new();
        agents.insert(known.did(), agent_card(&known, "known", 1_000));
        let bids = vec![
            bid(&task, &ghost, 1_000_000, 1, 1),
            bid(&task, &known, 10_000_000, 1, 1),
        ];
        let expected =
            rank_bids(&task, &bids, &agents, &BTreeMap::new()).expect("one bid is scoreable");

        let (code, response) = call(
            "rank",
            json!({ "task": task, "bids": bids, "agents": agents }),
        );
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["winner"], json!(expected.winner.as_str()));
        assert_eq!(answer["skipped"].as_array().expect("an array").len(), 1);
        assert_eq!(answer["skipped"][0]["did"], json!(ghost.did().as_str()));
    }

    #[test]
    fn a_task_with_no_scoreable_bid_is_refused_with_a_code() {
        // The empty payload is a well-formed request with no bids: the marketplace
        // refuses it, and the refusal must survive the frame rather than becoming an
        // empty success.
        let requester = identity(1);
        let task = task_for(&requester, 50_000_000);
        let (code, response) = call("rank", json!({ "task": task }));
        assert_eq!(code, EXIT_REFUSED);
        assert!(!response.ok);
        assert_eq!(response.code.as_deref(), Some(CODE_RANK_FAILED));
        assert!(
            response
                .message
                .expect("a message")
                .contains("no scoreable bid"),
            "the marketplace's own reason must reach the host"
        );
    }

    #[test]
    fn a_rank_payload_of_the_wrong_shape_is_refused_rather_than_guessed() {
        let (code, response) = call("rank", json!([1, 2, 3]));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_NOT_OBJECT));

        let (code, response) = call("rank", json!({ "task": 5 }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_RANK_PAYLOAD));
        let message = response.message.expect("a message");
        assert!(!message.is_empty());
        assert!(message.chars().count() <= MAX_DIAGNOSTIC_CHARS + 1);
    }

    #[test]
    fn a_diagnostic_built_from_caller_json_stays_bounded() {
        // An enum with a long unknown variant makes serde_json quote the caller's
        // string. That string is the caller's, so it must not be able to decide how much
        // this plugin writes.
        let long = "x".repeat(MAX_DIAGNOSTIC_CHARS * 4);
        let (code, response) = call(
            "rank",
            json!({ "task": { "state": long, "verification": { "kind": "requester_only" } } }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_RANK_PAYLOAD));
        let message = response.message.expect("a message");
        assert!(
            message.chars().count() <= MAX_DIAGNOSTIC_CHARS + 1,
            "{} characters is not bounded",
            message.chars().count()
        );
        assert!(message.ends_with('…'), "{message}");
    }

    #[test]
    fn capabilities_reports_declared_against_implemented_without_a_false_green() {
        let (code, response) = call("capabilities", Value::Null);
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");

        assert_eq!(answer["plugin"], json!(PLUGIN_NAME));
        assert_eq!(answer["version"], json!(PLUGIN_VERSION));
        assert_eq!(answer["tier"], json!("official"));
        assert_eq!(
            answer["declared_capabilities"],
            json!(DECLARED_CAPABILITIES)
        );
        assert_eq!(answer["implemented_ops"], json!(IMPLEMENTED_OPS));
        assert_eq!(answer["declared_matches_catalogue"], json!(true));

        // The honest part: three capabilities declared, none exercised by an op.
        assert_eq!(
            answer["declared_capabilities_backed_by_ops"],
            json!(false),
            "no implemented op performs registration or settlement, and the answer must say so"
        );
        for capability in DECLARED_CAPABILITIES {
            assert_eq!(
                answer["capability_backing"][capability],
                json!([]),
                "`{capability}` is declared but must not claim an op"
            );
        }
        assert_eq!(
            answer["ops_not_named_by_a_declared_capability"],
            json!(IMPLEMENTED_OPS)
        );

        // The approvals the official tier needs for the declaration are derived by the
        // catalogue from the real matrix, not restated here.
        let approvals = answer["required_approvals"].as_array().expect("an array");
        assert_eq!(approvals.len(), DECLARED_CAPABILITIES.len());
        for approval in approvals {
            assert_eq!(approval["authority"], json!("vendor-team"));
        }

        assert_eq!(
            answer["op_delegation"]["rank"],
            json!("nau_market::matching::rank_bids")
        );
    }

    #[test]
    fn the_binary_and_the_catalogue_agree_about_the_plugin() {
        let entry = Official::find(PLUGIN_NAME).expect("the catalogue lists the market plugin");
        assert_eq!(
            entry.tier().expect("classifies"),
            nau_plugin::Tier::Official
        );
        assert_eq!(entry.version, PLUGIN_VERSION);
        assert_eq!(entry.name, PLUGIN_NAME);
        assert_eq!(
            nau_plugin::Tier::from_name(PLUGIN_NAME).expect("classifies"),
            nau_plugin::Tier::Official
        );
    }

    #[test]
    fn every_declared_capability_has_a_backing_row_and_every_backed_op_is_implemented() {
        // Drift guards: adding a capability to the catalogue without deciding whether an
        // op backs it, or naming an op that does not exist, both fail here.
        for capability in DECLARED_CAPABILITIES {
            assert!(
                CAPABILITY_BACKING
                    .iter()
                    .any(|(name, _)| *name == capability),
                "`{capability}` is declared with no backing row, so `capabilities` would \
                 report it as if it did not exist"
            );
        }
        for (capability, ops) in CAPABILITY_BACKING {
            for op in ops {
                assert!(
                    IMPLEMENTED_OPS.contains(op),
                    "`{op}` backs `{capability}` but is not an implemented op"
                );
            }
            assert_eq!(
                capability_backing(capability),
                ops,
                "the lookup must return the table's own row"
            );
        }
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
        let (code, response) = call("settle", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(
            response.code.as_deref(),
            Some(payload::CODE_UNKNOWN_OPERATION)
        );
        let message = response.message.expect("a message");
        assert!(
            message.contains("rank"),
            "the known ops must be listed: {message}"
        );
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
    fn a_payload_that_is_not_a_request_is_refused_and_an_unreadable_frame_is_not_a_refusal() {
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
