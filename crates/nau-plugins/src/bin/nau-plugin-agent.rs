//! `nau-plugin-agent` — the official (T1) plugin for the **current** agent identity card.
//!
//! `nau_plugins::official::OFFICIALS` names this plugin "Layered memory: individual, swarm
//! and cross-generation"; what a one-frame process plugin can honestly do with that is the
//! part of the model that is already public in `nau-core`: check a current
//! [`AgentCard`] against the kernel's own structural invariants, and project its fields. So
//! this binary delegates both and re-derives neither:
//!
//! * its `validate` op calls [`AgentCard::validate`], plus the two questions that
//!   `validate` deliberately does not answer — the signature ([`Verifiable::verify`]) and
//!   freshness ([`Verifiable::check_freshness`]) — and reports all three as **separate**
//!   verdicts;
//! * its `project` op reads the card's own fields, calling no rule at all;
//! * its `capabilities` op reports the catalogue's declaration next to what this binary
//!   implements and derives the tier's approvals from [`Capability::decision`].
//!
//! # How this differs from `sys.migrate`, which also talks about an "agent card"
//!
//! They are not duplicates and they share no input format:
//!
//! | | `com.twinsearth.sys.migrate` (T0, in-process) | this binary (`official.agent`, T1) |
//! |---|---|---|
//! | the input | an **upstream v2.5.6 legacy** AgentCard, as verbatim **text** | this repository's **current** [`AgentCard`], as JSON |
//! | what verifies it | `nau_migrate::verify_legacy_record` — the legacy signature over the legacy canonical form | [`Verifiable::verify`] — the current Ed25519 signature over this project's canonical form |
//! | the key | a **`DID → key` registry** the caller supplies, because a legacy card carries no key | nothing out of band: the current card carries `owner_key`, and the key must fingerprint `owner` |
//! | the rule book | `nau-migrate`'s readers and findings; it never constructs `nau_core::AgentCard` | `nau-core`'s `AgentCard::validate` / `Skill::validate` / `Pricing::validate` / `Sla::validate` |
//! | its op | `card` | `validate`, `project` |
//!
//! In one sentence: **`sys.migrate` reads a record of the old world and does not build the
//! new type; this plugin takes the new type and asks the kernel what it thinks of it.** A
//! legacy card handed to this binary is simply a card the current model refuses, and a
//! current card handed to `sys.migrate` is not a legacy record. Neither replaces the other.
//!
//! # Protocol
//!
//! ```text
//! stdin:  u32_be(len) || {"abi":"3.2","id":"req-1","op":"validate","payload":{…}}
//! stdout: u32_be(len) || {"abi":"3.2","id":"req-1",
//!                         "plugin":"com.twinsearth.official.agent",
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
//! { "card": { …a serialized `nau_core::AgentCard`… }, "now": 1700000000,
//!   "verify_signature": true }
//! ```
//!
//! `card` is required; `verify_signature` and `now` are optional, and each asks exactly one
//! of the two questions `AgentCard::validate` does not answer. The answer:
//!
//! ```json
//! {
//!   "valid": false,
//!   "first_failure": "validation failed: agent name must not be empty",
//!   "first_failure_kind": "validation",
//!   "verdict_is_first_failure_only": true,
//!   "later_invariants_not_examined": true,
//!   "invariant_order": [ … ],
//!   "signature_checked": false, "signature_valid": null, "signature_reason": null,
//!   "freshness_checked": false, "fresh": null, "freshness_reason": null
//! }
//! ```
//!
//! ### The verdict is first-failure-only, and that matters
//!
//! [`AgentCard::validate`] **returns the first failure it reaches and stops**. So
//! `valid: false` with one sentence does **not** mean the card has exactly one problem: every
//! invariant after the failing one was never examined. The answer says so three ways rather
//! than turning it into a clean boolean:
//!
//! * `verdict_is_first_failure_only` is always `true` — it is a property of the API;
//! * `later_invariants_not_examined` is `true` exactly when the card was refused, so a host
//!   cannot read a refusal as a complete report;
//! * `invariant_order` lists the checks in the order [`AgentCard::validate`] performs them,
//!   so a host can see which of them the verdict stopped short of.
//!
//! `invariant_order` is the one field in this answer that is a **transcription rather than a
//! call result**: the model exposes no accessor for its own order. It is guarded by tests
//! that provoke each invariant and by fixtures with two problems at once, which pin the
//! relative order of the checks. The authoritative source is
//! `crates/nau-core/src/domain/agent.rs`, and a change there that reorders the checks is a
//! change this list has to follow.
//!
//! ### What `validate` covers, and what it does not
//!
//! In this order, and stopping at the first failure:
//!
//! | # | invariant | fails with |
//! |---|---|---|
//! | 1 | `name` is not blank | `Validation` |
//! | 2 | `name` is at most 128 **bytes** (`String::len`, not characters) | `Validation` |
//! | 3 | `skills` is non-empty | `Validation` |
//! | 4 | every skill id is non-blank, at most 64 bytes, and lowercase | `Validation` |
//! | 5 | no two skills share an id | `Validation` |
//! | 6 | `pricing.unit_price` is not negative | `InvalidAmount` |
//! | 7 | `sla.availability_bps <= 10_000` | `Validation` |
//! | 8 | `sla.max_concurrency >= 1` | `Validation` |
//! | 9 | `stake` is positive | `InvalidAmount` |
//! | 10 | `owner` fingerprints `owner_key` | `DidKeyMismatch` |
//! | 11 | `expires_at`, when set, is after `signed_at` | `Validation` |
//!
//! It does **not** cover, and this answer does not pretend otherwise:
//!
//! * **the signature** — that is [`Verifiable::verify`], reported as `signature_valid`, and
//!   only called when `verify_signature` is true;
//! * **freshness** — [`Verifiable::check_freshness`] against `now`, reported as `fresh`, and
//!   called only when `now` is supplied (supplying a clock *is* asking the question);
//! * `endpoints`, `description`, `skills[].version` and `skills[].description`,
//!   `pricing.model`/`pricing.unit` consistency, the size of `stake` beyond positivity,
//!   `signed_at`, and `nonce` monotonicity (a registry concern, not a card concern);
//! * the shape of `owner` as a DID: `Did` is `#[serde(transparent)]`, so `serde` accepts any
//!   string, and the only thing that catches a malformed one is the `owner` ↔ `owner_key`
//!   binding at step 10 — which reports a **key mismatch**, not an invalid DID. A
//!   `canonical DID` check does not exist on this path.
//!
//! `owner_key`, by contrast, is checked **harder** than `validate` by `serde` itself:
//! `PublicKey` deserialization rejects non-hex, wrong-length and small-order points.
//!
//! The three questions are never merged, and the combined entry points
//! [`AgentCard::validate_and_verify`] and [`AgentCard::validate_verified_fresh`] are
//! deliberately **not** used: each would fuse a structural verdict with a cryptographic one,
//! and a host that read the fused boolean would believe it had checked more than it had.
//!
//! ## `project`
//!
//! ```json
//! { "card": { … } }
//! ```
//!
//! Every field of the answer is read off the struct; no rule is called and nothing is
//! recomputed. Projection is deliberately **not** validation: an invalid card projects
//! exactly as faithfully as a valid one, and a host that wants a verdict must ask
//! `validate`. The signature hex is **not** echoed (there is no use for it here);
//! `signature_present` says only whether the field is non-empty.
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
//! written — the convention of the five plugins before this one, unchanged.
//!
//! # Fail-closed choices
//!
//! * an unknown op, an incompatible `abi` and a payload of the wrong shape are each a typed
//!   refusal, never an empty success;
//! * an invalid card is an **answer** (`valid: false` with the model's own sentence), not a
//!   plugin refusal: "is this card valid?" is the question the op exists to answer;
//! * unknown *keys* inside a payload are tolerated (the frame envelope's
//!   additive-within-a-major rule); an unknown category or pricing model is not, because it
//!   would silently become a different card;
//! * a diagnostic echoed back to the host is bounded, because an error string built from
//!   caller-supplied JSON is how a log becomes an attack surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_core::domain::Verifiable;
use nau_core::{AgentCard, NauError};
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
const PLUGIN_NAME: &str = "com.twinsearth.official.agent";

/// The version this binary reports, which is the catalogue entry's version rather than the
/// workspace's. A test asserts the two are equal, so a catalogue bump that forgets this
/// constant fails instead of shipping a plugin that lies about its own version.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named in [`OP_DELEGATION`]
/// is listed here, so this table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 3] = ["capabilities", "project", "validate"];

/// The capability set this binary's manifest declares.
///
/// `plugin:storage:own` is what the catalogue entry for this plugin names
/// ([`nau_plugins::official::OFFICIALS`]), and it is one of the three capabilities every
/// loadable tier holds by construction — so the official tier's approval machinery is not
/// triggered by this declaration at all. That is the accurate state, and the answer says so
/// with an empty `required_approvals` rather than by inventing a capability this plugin
/// does not need.
const DECLARED_CAPABILITIES: [&str; 1] = ["plugin:storage:own"];

/// Which implemented op exercises each declared capability.
///
/// Empty, and that is the honest state rather than a placeholder: `validate` and `project`
/// are computations over a caller-supplied card, and neither reads or writes a sandbox
/// directory. Reporting an op here would be a claim that this binary does that capability's
/// work, which it does not.
const CAPABILITY_BACKING: [(&str, &[&str]); 1] = [("plugin:storage:own", &[])];

/// Which crate function each implemented op delegates to, as `(op, target)`.
///
/// Reported in the `capabilities` answer so a host can see the delegation rather than
/// having to trust a description of it.
const OP_DELEGATION: [(&str, &str); 3] = [
    ("capabilities", "nau_plugins::official::OFFICIALS"),
    (
        "project",
        "nau_core::domain::agent::AgentCard (field projection only; no rule is called)",
    ),
    (
        "validate",
        "nau_core::domain::agent::AgentCard::validate + nau_core::domain::Verifiable::{verify, \
         check_freshness}",
    ),
];

/// The order in which [`AgentCard::validate`] examines its invariants.
///
/// A **transcription**, not a call result: the model exposes no accessor for its own order,
/// and this list exists so that a host reading `valid: false` can see which of the later
/// checks the verdict stopped short of. The authoritative source is
/// `crates/nau-core/src/domain/agent.rs`; tests provoke every entry and pin the relative
/// order of the ones that matter with two-problem fixtures.
const INVARIANT_ORDER: [&str; 11] = [
    "name_not_blank",
    "name_at_most_128_bytes",
    "skills_not_empty",
    "every_skill_id_valid",
    "skill_ids_unique",
    "pricing_unit_price_not_negative",
    "sla_availability_bps_at_most_10000",
    "sla_max_concurrency_at_least_one",
    "stake_positive",
    "owner_fingerprints_owner_key",
    "expires_at_after_signed_at",
];

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "`validate` and `project` delegate to nau_core's own AgentCard model; \
                     neither reads or writes a sandbox directory, so the one declared \
                     capability is declared but not exercised and \
                     declared_capabilities_backed_by_ops is false. The declared set is the \
                     catalogue's, and `plugin:storage:own` is a basic capability, so the \
                     official tier requires no approval for it: required_approvals is empty \
                     because the matrix grants it unconditionally, not because the derivation \
                     was skipped. AgentCard::validate returns the FIRST failure and stops, so \
                     `valid: false` means 'at least one problem', never 'exactly one': the \
                     answer says that with verdict_is_first_failure_only, \
                     later_invariants_not_examined and invariant_order. The signature and \
                     freshness questions are separate real calls (verify, check_freshness) and \
                     are never merged into the structural verdict. This plugin validates the \
                     CURRENT AgentCard; com.twinsearth.sys.migrate reads an upstream v2.5.6 \
                     legacy card from raw text and does not construct this type.";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: a payload is not a JSON object.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: a `validate` payload is an object but not the shape this op documents.
const CODE_VALIDATE_PAYLOAD: &str = "agent_validate_payload_invalid";
/// Error code: a `project` payload is an object but does not carry `card`.
const CODE_PROJECT_PAYLOAD: &str = "agent_project_payload_invalid";
/// Error code: this binary and the official catalogue disagree about its own identity.
const CODE_CAPABILITIES: &str = "agent_capabilities_unavailable";

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

/// The `validate` payload: one current card, plus the two optional questions about it.
///
/// Deliberately not `deny_unknown_fields`: the frame envelope is additive within a major,
/// and a payload that refused new keys would break that promise one layer down.
#[derive(Debug, Deserialize)]
struct ValidateRequest {
    /// The card to validate.
    card: AgentCard,
    /// The clock. Supplying it is what asks the freshness question; there is no second flag,
    /// because a caller who supplied a clock has already asked.
    #[serde(default)]
    now: Option<u64>,
    /// Whether to also verify the owner's signature. This needs a flag because it needs no
    /// input: the signature is already in the card.
    #[serde(default)]
    verify_signature: bool,
}

/// The `project` payload: one current card to read fields from.
#[derive(Debug, Deserialize)]
struct ProjectRequest {
    /// The card to project. Required.
    card: AgentCard,
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
        "project" => match project(&request.payload) {
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

/// A machine-readable label for the `NauError` variant a refusal came from.
///
/// This classifies the **error**, not the check that produced it: `AgentCard::validate`
/// reports its refusals as prose, and guessing which invariant fired from a substring is
/// exactly the second rule book this plugin refuses to write. `NauError` is
/// `#[non_exhaustive]`, so the final arm exists because the enum can grow.
fn failure_kind(err: &NauError) -> &'static str {
    match err {
        NauError::Validation(_) => "validation",
        NauError::InvalidAmount(_) => "invalid_amount",
        NauError::DidKeyMismatch { .. } => "did_key_mismatch",
        _ => "other",
    }
}

/// Report the kernel's own structural verdict, and the two questions it does not answer.
fn validate(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `validate` payload must be a JSON object carrying `card` (and optionally \
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
    let card = request.card;

    // Question one: is the card shaped correctly? `AgentCard::validate` returns the first
    // failure and stops, so the answer reports the sentence AND says that the verdict is not
    // a complete report.
    let (valid, first_failure, first_failure_kind) = match card.validate() {
        Ok(()) => (true, None, None),
        Err(err) => (
            false,
            Some(bounded(&err.to_string())),
            Some(failure_kind(&err)),
        ),
    };

    // Question two: did its owner sign it? `Verifiable::verify` checks the signature and the
    // DID↔key binding, and touches no structural invariant -- so a malformed card that its
    // owner really did sign reports `valid: false` with `signature_valid: true`, which is
    // the whole point of keeping the questions apart.
    let (signature_valid, signature_reason) = if request.verify_signature {
        match card.verify() {
            Ok(()) => (Some(true), None),
            Err(err) => (Some(false), Some(bounded(&err.to_string()))),
        }
    } else {
        (None, None)
    };

    // Question three: are its timestamps acceptable at `now`? `check_freshness` enforces the
    // expiry and clock-skew rules alone; it does not re-check the signature, so `fresh` and
    // `signature_valid` are independent too. Supplying `now` is what asks the question.
    let (fresh, freshness_reason) = match request.now {
        Some(now) => match card.check_freshness(now) {
            Ok(()) => (Some(true), None),
            Err(err) => (Some(false), Some(bounded(&err.to_string()))),
        },
        None => (None, None),
    };

    Ok(json!({
        "valid": valid,
        "first_failure": first_failure,
        "first_failure_kind": first_failure_kind,
        "verdict_is_first_failure_only": true,
        "later_invariants_not_examined": !valid,
        "invariant_order": INVARIANT_ORDER,
        "signature_checked": request.verify_signature,
        "signature_valid": signature_valid,
        "signature_reason": signature_reason,
        "freshness_checked": fresh.is_some(),
        "fresh": fresh,
        "freshness_reason": freshness_reason,
    }))
}

/// Project the card's fields, calling no rule and recomputing nothing.
fn project(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `project` payload must be a JSON object carrying `card`, found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: ProjectRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_PROJECT_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;
    let card = request.card;

    Ok(json!({
        "owner": card.owner.as_str(),
        "owner_key": card.owner_key.to_hex(),
        "name": card.name,
        "description": card.description,
        "category": card.category,
        "skills": card.skills,
        "pricing": card.pricing,
        "unit_price_minor": card.pricing.unit_price.minor(),
        "sla": card.sla,
        "stake_minor": card.stake.minor(),
        "endpoints": card.endpoints,
        "signed_at": card.signed_at,
        "expires_at": card.expires_at,
        "nonce": card.nonce,
        "signature_present": !card.signature.is_empty(),
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
    use nau_core::domain::money::major;
    use nau_core::{Identity, Money, Skill, Sla};
    use nau_plugins::frame::{decode_response, Request};

    const SIGNED_AT: u64 = 1_700_000_000;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed(&[seed; 32])
    }

    /// A real, signed card: the only fixture that can distinguish delegation from a re-run.
    fn signed_card() -> AgentCard {
        let owner = identity(7);
        let mut card = AgentCard::draft(
            &owner,
            "Translator",
            vec![Skill::new("translation", 1)],
            major(100),
            SIGNED_AT,
            1,
        );
        card.sign(&owner).expect("the test card signs");
        card
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

    /// Send a card through `validate` and return the answer payload.
    fn validate_card(card: &AgentCard, extra: Value) -> Value {
        let mut payload = json!({ "card": card });
        if let (Value::Object(extra), Value::Object(target)) = (extra, &mut payload) {
            for (key, value) in extra {
                target.insert(key, value);
            }
        }
        let (code, response) = call("validate", payload);
        assert_eq!(code, EXIT_OK, "{response:?}");
        response.payload.expect("a payload")
    }

    #[test]
    fn validate_reports_the_kernels_own_verdict_for_a_well_formed_card() {
        let card = signed_card();
        assert!(card.validate().is_ok(), "the fixture must start valid");

        // No clock and no signature question: neither is answered.
        let answer = validate_card(&card, json!({}));
        assert_eq!(
            answer["freshness_checked"],
            json!(false),
            "a caller who supplied no clock did not ask the freshness question"
        );
        assert_eq!(answer["fresh"], Value::Null);

        // The structural verdict, compared against a direct call to the same function.
        assert_eq!(answer["valid"], json!(card.validate().is_ok()));
        assert_eq!(answer["valid"], json!(true));
        assert_eq!(answer["first_failure"], Value::Null);
        assert_eq!(answer["first_failure_kind"], Value::Null);
        assert_eq!(answer["verdict_is_first_failure_only"], json!(true));
        assert_eq!(
            answer["later_invariants_not_examined"],
            json!(false),
            "a card that passed every check has nothing left unexamined"
        );
        assert_eq!(answer["invariant_order"], json!(INVARIANT_ORDER));
        assert_eq!(answer["signature_checked"], json!(false));
        assert_eq!(answer["signature_valid"], Value::Null);

        // And when both are asked, they are the kernel's own verdicts.
        let answer = validate_card(
            &card,
            json!({ "now": SIGNED_AT + 10, "verify_signature": true }),
        );
        assert_eq!(answer["signature_valid"], json!(card.verify().is_ok()));
        assert_eq!(
            answer["fresh"],
            json!(card.check_freshness(SIGNED_AT + 10).is_ok())
        );
        assert_eq!(answer["signature_valid"], json!(true));
        assert_eq!(answer["fresh"], json!(true));
        assert_eq!(answer["freshness_checked"], json!(true));
    }

    #[test]
    fn every_structural_invariant_has_a_counterexample_that_names_it() {
        // One fixture per invariant `AgentCard::validate` checks, each with exactly one
        // problem, so the reported sentence identifies the invariant that fired. This is the
        // covered list the module docs claim, kept honest by execution rather than by prose.
        let cases: Vec<(&str, AgentCard, &str)> = vec![
            (
                "name_not_blank",
                {
                    let mut c = signed_card();
                    c.name = "   ".into();
                    c
                },
                "name must not be empty",
            ),
            (
                "name_at_most_128_bytes",
                {
                    let mut c = signed_card();
                    c.name = "n".repeat(129);
                    c
                },
                "at most 128",
            ),
            (
                "skills_not_empty",
                {
                    let mut c = signed_card();
                    c.skills.clear();
                    c
                },
                "at least one skill",
            ),
            (
                "every_skill_id_valid",
                {
                    let mut c = signed_card();
                    c.skills = vec![Skill {
                        id: "  ".into(),
                        version: 1,
                        description: None,
                    }];
                    c
                },
                "skill id must not be empty",
            ),
            (
                "every_skill_id_valid",
                {
                    let mut c = signed_card();
                    c.skills = vec![Skill {
                        id: "s".repeat(65),
                        version: 1,
                        description: None,
                    }];
                    c
                },
                "longer than 64",
            ),
            (
                "every_skill_id_valid",
                {
                    let mut c = signed_card();
                    c.skills = vec![Skill {
                        id: "Translation".into(),
                        version: 1,
                        description: None,
                    }];
                    c
                },
                "must be lowercase",
            ),
            (
                "skill_ids_unique",
                {
                    let mut c = signed_card();
                    c.skills = vec![Skill::new("translation", 1), Skill::new("translation", 2)];
                    c
                },
                "duplicate skill",
            ),
            (
                "pricing_unit_price_not_negative",
                {
                    let mut c = signed_card();
                    c.pricing.unit_price = Money::from_minor(-5);
                    c
                },
                "must not be negative",
            ),
            (
                "sla_availability_bps_at_most_10000",
                {
                    let mut c = signed_card();
                    c.sla.availability_bps = 10_001;
                    c
                },
                "exceeds 10000",
            ),
            (
                "sla_max_concurrency_at_least_one",
                {
                    let mut c = signed_card();
                    c.sla.max_concurrency = 0;
                    c
                },
                "at least 1",
            ),
            (
                "stake_positive",
                {
                    let mut c = signed_card();
                    c.stake = Money::ZERO;
                    c
                },
                "stake must be greater than zero",
            ),
            (
                "owner_fingerprints_owner_key",
                {
                    let mut c = signed_card();
                    c.owner_key = identity(9).public_key();
                    c
                },
                "does not match the supplied public key",
            ),
            (
                "expires_at_after_signed_at",
                {
                    let mut c = signed_card();
                    c.expires_at = Some(SIGNED_AT);
                    c
                },
                "must be after signed_at",
            ),
        ];

        for (invariant, card, expected) in cases {
            let answer = validate_card(&card, json!({}));
            assert_eq!(
                answer["valid"],
                json!(false),
                "`{invariant}` must make the card invalid"
            );
            let message = answer["first_failure"].as_str().expect("a sentence");
            assert!(
                message.contains(expected),
                "`{invariant}` must be the failure the model reports, got: {message}"
            );
            assert_eq!(
                answer["later_invariants_not_examined"],
                json!(true),
                "a refusal must say that later invariants were not examined"
            );
            assert!(
                INVARIANT_ORDER.contains(&invariant),
                "`{invariant}` is exercised by a test but missing from invariant_order"
            );
            // The kind comes from the error variant, not from a guess at the check.
            let kind = answer["first_failure_kind"].as_str().expect("a kind");
            assert!(
                ["validation", "invalid_amount", "did_key_mismatch", "other"].contains(&kind),
                "unexpected kind `{kind}`"
            );
        }
    }

    #[test]
    fn the_verdict_is_first_failure_only_and_one_message_is_not_one_problem() {
        // Two problems at once: the earlier invariant fires and the later one is never
        // examined. This is the property a host has to be able to read.
        let mut card = signed_card();
        card.name = String::new();
        card.skills.clear();
        card.stake = Money::ZERO;

        let answer = validate_card(&card, json!({}));
        assert_eq!(answer["valid"], json!(false));
        assert_eq!(
            answer["first_failure"],
            json!(card.validate().expect_err("invalid").to_string()),
            "the sentence must be the model's own"
        );
        assert!(
            answer["first_failure"]
                .as_str()
                .expect("a sentence")
                .contains("name must not be empty"),
            "name is checked before skills and stake, so it is the one that fires"
        );
        assert_eq!(
            answer["later_invariants_not_examined"],
            json!(true),
            "the answer must not read as a complete list of problems"
        );
        assert!(
            answer["invariant_order"]
                .as_array()
                .expect("an array")
                .iter()
                .any(|name| name == "stake_positive"),
            "the stake problem exists but is not examined, and the order list says so"
        );

        // The relative order, pinned pair by pair with two-problem fixtures: each fixture
        // would be reported differently if the order were reversed.
        let mut skills_before_stake = signed_card();
        skills_before_stake.skills.clear();
        skills_before_stake.stake = Money::ZERO;
        let answer = validate_card(&skills_before_stake, json!({}));
        assert!(
            answer["first_failure"]
                .as_str()
                .expect("a sentence")
                .contains("at least one skill"),
            "skills are checked before stake: {answer}"
        );

        let mut pricing_before_stake = signed_card();
        pricing_before_stake.pricing.unit_price = Money::from_minor(-5);
        pricing_before_stake.stake = Money::ZERO;
        let answer = validate_card(&pricing_before_stake, json!({}));
        assert!(
            answer["first_failure"]
                .as_str()
                .expect("a sentence")
                .contains("must not be negative"),
            "pricing is checked before stake: {answer}"
        );

        let mut skill_before_pricing = signed_card();
        skill_before_pricing.skills = vec![Skill {
            id: "UPPER".into(),
            version: 1,
            description: None,
        }];
        skill_before_pricing.pricing.unit_price = Money::from_minor(-5);
        let answer = validate_card(&skill_before_pricing, json!({}));
        assert!(
            answer["first_failure"]
                .as_str()
                .expect("a sentence")
                .contains("must be lowercase"),
            "the per-skill checks run before pricing: {answer}"
        );
    }

    #[test]
    fn the_structural_signature_and_freshness_verdicts_are_never_merged() {
        // A card that is structurally invalid but that its owner really did sign: the two
        // questions have opposite answers, and merging them would hide one of them.
        let owner = identity(7);
        let mut malformed = AgentCard::draft(
            &owner,
            String::new(),
            vec![Skill::new("translation", 1)],
            major(100),
            SIGNED_AT,
            1,
        );
        malformed.sign(&owner).expect("signing does not validate");

        let answer = validate_card(
            &malformed,
            json!({ "verify_signature": true, "now": SIGNED_AT + 10 }),
        );
        assert_eq!(answer["valid"], json!(false));
        assert!(answer["first_failure"]
            .as_str()
            .expect("a sentence")
            .contains("name must not be empty"));
        assert_eq!(
            answer["signature_valid"],
            json!(true),
            "the signature covers what was signed, malformed or not"
        );
        assert_eq!(answer["fresh"], json!(true));

        // A tampered card: structurally fine, but the signature no longer covers it.
        let mut tampered = signed_card();
        tampered.sla = Sla {
            latency_p95_ms: 1,
            availability_bps: 9_900,
            max_concurrency: 4,
        };
        let answer = validate_card(
            &tampered,
            json!({ "verify_signature": true, "now": SIGNED_AT }),
        );
        assert_eq!(answer["valid"], json!(true));
        assert_eq!(answer["signature_valid"], json!(false));
        assert!(
            !answer["signature_reason"]
                .as_str()
                .expect("a reason")
                .is_empty(),
            "the kernel's reason must reach the host: {answer}"
        );

        // Freshness is its own call: an expired card verifies but is not fresh.
        let owner = identity(7);
        let mut expiring = AgentCard::draft(
            &owner,
            "Translator",
            vec![Skill::new("translation", 1)],
            major(100),
            SIGNED_AT,
            1,
        );
        expiring.expires_at = Some(SIGNED_AT + 100);
        expiring.sign(&owner).expect("signs");

        let answer = validate_card(
            &expiring,
            json!({ "verify_signature": true, "now": SIGNED_AT + 200 }),
        );
        assert_eq!(answer["valid"], json!(true));
        assert_eq!(answer["signature_valid"], json!(true));
        assert_eq!(answer["fresh"], json!(false));
        assert!(
            answer["freshness_reason"]
                .as_str()
                .expect("a reason")
                .contains("expired"),
            "{answer}"
        );

        // ...and `check_freshness` is not called when no clock was supplied: there is
        // nothing to check against, and a verdict is not invented.
        let answer = validate_card(&expiring, json!({}));
        assert_eq!(answer["freshness_checked"], json!(false));
        assert_eq!(answer["fresh"], Value::Null);
    }

    #[test]
    fn project_reads_every_field_off_the_card_and_calls_no_rule() {
        let card = signed_card();
        let (code, response) = call("project", json!({ "card": &card }));
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(response.ok);
        assert_eq!(response.plugin, PLUGIN_NAME);
        assert_eq!(response.version, PLUGIN_VERSION);

        let answer = response.payload.expect("a payload");
        assert_eq!(answer["owner"], json!(card.owner.as_str()));
        assert_eq!(answer["owner_key"], json!(card.owner_key.to_hex()));
        assert_eq!(answer["name"], json!(card.name));
        assert_eq!(
            answer["description"],
            serde_json::to_value(&card.description).expect("ser")
        );
        assert_eq!(
            answer["category"],
            serde_json::to_value(card.category).expect("ser")
        );
        assert_eq!(
            answer["skills"],
            serde_json::to_value(&card.skills).expect("ser")
        );
        assert_eq!(
            answer["pricing"],
            serde_json::to_value(&card.pricing).expect("ser")
        );
        assert_eq!(
            answer["unit_price_minor"],
            json!(card.pricing.unit_price.minor())
        );
        assert_eq!(answer["sla"], serde_json::to_value(card.sla).expect("ser"));
        assert_eq!(answer["stake_minor"], json!(card.stake.minor()));
        assert_eq!(answer["endpoints"], json!(card.endpoints));
        assert_eq!(answer["signed_at"], json!(card.signed_at));
        assert_eq!(
            answer["expires_at"],
            serde_json::to_value(card.expires_at).expect("ser")
        );
        assert_eq!(answer["nonce"], json!(card.nonce));
        assert_eq!(answer["signature_present"], json!(true));

        // Projection is not validation: an invalid card projects just as faithfully, and
        // that is deliberate rather than an oversight.
        let mut broken = card;
        broken.name = String::new();
        broken.skills.clear();
        let (code, response) = call("project", json!({ "card": broken }));
        assert_eq!(code, EXIT_OK);
        assert!(response.ok);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["name"], json!(""));
        assert_eq!(answer["skills"], json!([]));
        assert_eq!(
            answer["signature_present"],
            json!(true),
            "the signature field is reported as present, never as valid"
        );
    }

    #[test]
    fn a_payload_of_the_wrong_shape_is_refused_rather_than_guessed() {
        let (code, response) = call("validate", json!([1, 2, 3]));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_NOT_OBJECT));

        // `card` is required by both ops; a missing key names the field.
        for op in ["validate", "project"] {
            let (code, response) = call(op, json!({ "now": 1 }));
            assert_eq!(code, EXIT_REFUSED, "{op}");
            assert_eq!(
                response.code.as_deref(),
                Some(if op == "validate" {
                    CODE_VALIDATE_PAYLOAD
                } else {
                    CODE_PROJECT_PAYLOAD
                })
            );
            assert!(
                response.message.expect("a message").contains("card"),
                "`{op}`: the refusal must name the missing field"
            );
        }

        // A category the kernel does not have is a refusal, not a different card.
        let mut value = serde_json::to_value(signed_card()).expect("serialises");
        value["category"] = json!("telepathy");
        let (code, response) = call("validate", json!({ "card": value }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_VALIDATE_PAYLOAD));

        // An empty skill list is a valid *shape* and an invalid *card*, which is the
        // distinction this op exists to keep.
        let mut value = serde_json::to_value(signed_card()).expect("serialises");
        value["skills"] = json!([]);
        let (code, response) = call("validate", json!({ "card": value }));
        assert_eq!(code, EXIT_OK, "a shaped card is answered, not refused");
        assert_eq!(response.payload.expect("a payload")["valid"], json!(false));
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
            "neither `validate` nor `project` touches a sandbox directory"
        );
        assert_eq!(
            answer["capability_backing"]["plugin:storage:own"],
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
                "nau_core::domain::agent::AgentCard::validate + \
                 nau_core::domain::Verifiable::{verify, check_freshness}"
            )
        );
    }

    #[test]
    fn the_binary_and_the_catalogue_agree_and_the_tier_rule_is_the_matrixs() {
        let entry = Official::find(PLUGIN_NAME).expect("the catalogue lists the agent plugin");
        assert_eq!(entry.tier().expect("classifies"), Tier::Official);
        assert_eq!(entry.version, PLUGIN_VERSION);
        assert_eq!(entry.name, PLUGIN_NAME);
        assert_eq!(
            Tier::from_name(PLUGIN_NAME).expect("classifies"),
            Tier::Official
        );
        assert_eq!(
            entry.approvals().expect("holdable at its tier"),
            Vec::new(),
            "nothing this entry declares needs an approval"
        );
        assert_eq!(
            Capability::StorageOwn.decision(Tier::Official),
            Grant::Always
        );
        assert_eq!(
            Capability::EconomySettle.decision(Tier::Official),
            Grant::RequiresApproval(nau_plugin::capability::Approval::VendorTeam)
        );
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
        let (code, response) = call("card", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(
            response.code.as_deref(),
            Some(payload::CODE_UNKNOWN_OPERATION)
        );
        let message = response.message.expect("a message");
        assert!(
            message.contains("validate") && message.contains("project"),
            "the known ops must be listed: {message}"
        );
        assert!(
            !message.contains("card_json"),
            "`sys.migrate`'s op must not be advertised here: {message}"
        );
    }

    #[test]
    fn a_diagnostic_built_from_caller_json_stays_bounded() {
        // An unknown variant makes serde_json quote the caller's string, which is the
        // caller's, so it must not decide how much this plugin writes.
        let long = "x".repeat(MAX_DIAGNOSTIC_CHARS * 4);
        let mut value = serde_json::to_value(signed_card()).expect("serialises");
        value["category"] = json!(long);
        let (code, response) = call("validate", json!({ "card": value }));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_VALIDATE_PAYLOAD));
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
