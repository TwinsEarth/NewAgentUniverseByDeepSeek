//! `com.twinsearth.official.chain-anchor` — the rules of `contracts/src/AgentCardAnchor.sol`,
//! applied offline to a caller-supplied anchor set.
//!
//! # What this port is, and what it deliberately is not
//!
//! Upstream `agent-universe` v3.5.0 lists `com.twinsearth.official.chain-anchor` ("链上锚定",
//! v2.1.0). Our `contracts/` tree carries the same contract as `AgentCardAnchor.sol`, with its
//! own Foundry tests, and **this plugin ports its decisions rather than its chain**: there is no
//! RPC client in this workspace, and a door named "anchor" that quietly reached for one would be
//! the defect this project exists to refuse.
//!
//! So the anchor **set is caller-supplied**, and every answer says `on_chain: false`. What the
//! plugin reproduces exactly is the part that is a *rule* rather than a *ledger*:
//!
//! | Contract rule | Reproduced as |
//! |---|---|
//! | a zero `cidHash` reverts `ZeroCidHash` | a refusal, `chain_anchor_zero_cid` |
//! | a zero `agentDidHash` reverts `ZeroAgentDidHash` | a refusal, `chain_anchor_zero_did` |
//! | **first write wins**; a second reverts `AlreadyAnchored` | a refusal naming the existing anchorer |
//! | `anchorCount >= maxAnchorsPerAgent` reverts `AnchorLimitReached` | a refusal carrying the cap |
//! | `verify` checks the digest **and** the DID hash | both are checked, and a digest bound to another agent is reported as such |
//! | `getAnchor` reverts, `tryGetAnchor` does not | the answer distinguishes *unknown* from *known* rather than returning a zero row |
//! | `anchorsOf` clamps `limit` and reverts `PageOutOfRange` on `offset > total` | the same clamp, the same refusal |
//!
//! The two rules that carry the contract's whole reason for existing are the third and the
//! fifth, and both are upstream v2.5.6 defects that this repository fixes in Solidity: an
//! unauthenticated `anchor()` that overwrote unconditionally, and a `verify()` that ignored the
//! agent so a valid card from A verified as true for B. A port that lost either would be a port
//! of the bug.
//!
//! # What is not reproduced, and why
//!
//! * **Storage.** No mapping, no `msg.sender`, no block number: the caller supplies the set and
//!   the anchored-at values stay whatever the caller wrote. A port that invented block numbers
//!   would be reporting chain facts it cannot observe.
//! * **The `Anchored` event.** There is no log to emit into. The answer carries what the event
//!   would have said, and says it is not an event.
//! * **Immutability of the past.** The plugin cannot prevent a caller from handing it a set in
//!   which a `cid` appears twice; it refuses such a set instead, because "the anchorer of X" is
//!   supposed to be a settled historical fact and a set that disagrees with itself is not one.
//!
//! # Fail-closed choices
//!
//! * an unknown op, an incompatible `abi` and a payload of the wrong shape are each a typed
//!   refusal, never an empty success;
//! * **an already-anchored digest is a refusal**, not an answer with `anchored: false`: the
//!   contract reverts, and a caller that had to read a boolean would treat "did not anchor" and
//!   "someone else already did" as the same outcome;
//! * a hash that is not `0x` + 64 lower-case hex digits, and an address that is not `0x` + 40,
//!   are refused by shape rather than compared as strings;
//! * a set that names one `cid` twice is refused, because the first-write-wins rule is only
//!   meaningful over a set that has one answer per digest.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_plugin::capability::{Capability, Grant};
use nau_plugins::frame::{self, Response};
use nau_plugins::official::Official;
use nau_plugins::payload;
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// The catalogue name this binary implements, from [`nau_plugins::official::OFFICIALS`]. The
/// tier is derived from this name, so the spelling is not cosmetic.
const PLUGIN_NAME: &str = "com.twinsearth.official.chain-anchor";

/// The version this binary reports, which is the catalogue entry's version rather than the
/// workspace's. A test asserts the two are equal, so a catalogue bump that forgets this
/// constant fails instead of shipping a plugin that lies about its own version.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
const IMPLEMENTED_OPS: [&str; 5] = ["anchor", "anchorable", "capabilities", "page", "verify"];

/// The capability set this binary's manifest declares.
///
/// `plugin:storage:own` is what the catalogue entry names, and it is one of the three
/// capabilities every loadable tier holds by construction — so the official tier's approval
/// machinery is not triggered by this declaration at all. That is the accurate state, and the
/// answer says so with an empty `required_approvals` rather than by inventing a capability this
/// plugin does not need.
const DECLARED_CAPABILITIES: [&str; 1] = ["plugin:storage:own"];

/// Which implemented op exercises each declared capability, if any.
const CAPABILITY_BACKING: [(&str, &[&str]); 1] = [("plugin:storage:own", &[])];

/// Which crate or file each implemented op answers for, as `(op, target)`.
///
/// Reported in the `capabilities` answer so a host can see the provenance rather than having to
/// trust a description of it. `contracts/src/AgentCardAnchor.sol` is a file rather than a crate
/// function, and naming it as one would be a false claim about where the rule lives.
const OP_DELEGATION: [(&str, &str); 5] = [
    (
        "anchor",
        "contracts/src/AgentCardAnchor.sol::anchor (rules only; no chain)",
    ),
    (
        "anchorable",
        "contracts/src/AgentCardAnchor.sol::isAnchorable",
    ),
    ("capabilities", "nau_plugins::official::OFFICIALS"),
    ("page", "contracts/src/AgentCardAnchor.sol::anchorsOf"),
    ("verify", "contracts/src/AgentCardAnchor.sol::verify"),
];

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "The rules of `contracts/src/AgentCardAnchor.sol` applied offline to a \
                     caller-supplied anchor set. No RPC client exists in this workspace and this \
                     door opens no socket, so every answer carries `on_chain: false` and the \
                     anchored-at values are whatever the caller supplied rather than observed \
                     block facts. The two rules that carry the contract's reason for existing are \
                     reproduced exactly: anchoring is first-write-wins, and `verify` checks the \
                     card digest AND the agent DID hash. A digest that is anchored to a different \
                     agent is reported as such rather than as a plain false, because that is the \
                     distinction upstream v2.5.6's `verify` destroyed.";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: a payload is not a JSON object.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: a payload is an object but not the shape this op documents.
const CODE_PAYLOAD: &str = "chain_anchor_payload_invalid";
/// Error code: a `cidHash` of all zeroes.
const CODE_ZERO_CID: &str = "chain_anchor_zero_cid";
/// Error code: an `agentDidHash` of all zeroes.
const CODE_ZERO_DID: &str = "chain_anchor_zero_did";
/// Error code: the digest already has an anchor, and anchoring is first-write-wins.
const CODE_ALREADY_ANCHORED: &str = "chain_anchor_already_anchored";
/// Error code: the anchorer has reached the per-address cap.
const CODE_LIMIT_REACHED: &str = "chain_anchor_limit_reached";
/// Error code: the supplied set names one digest twice.
const CODE_SET_INCONSISTENT: &str = "chain_anchor_set_inconsistent";
/// Error code: a `page` offset beyond the anchorer's total.
const CODE_PAGE_OUT_OF_RANGE: &str = "chain_anchor_page_out_of_range";
/// Error code: this binary and the official catalogue disagree about its own identity.
const CODE_CAPABILITIES: &str = "chain_anchor_capabilities_unavailable";

/// Hex digits in a `bytes32`, after `0x`.
const BYTES32_DIGITS: usize = 64;
/// Hex digits in an EVM address, after `0x`.
const ADDRESS_DIGITS: usize = 40;

/// Longest diagnostic quoted back to the host, in characters.
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

/// One anchor in the caller-supplied set: exactly the four fields the contract's `Anchor` struct
/// stores, with the two `uint64`s left as the caller wrote them.
#[derive(Debug, Clone, Deserialize)]
struct AnchorRow {
    /// Digest of the canonical agent card.
    cid: String,
    /// Hash of the owning agent DID, as supplied at anchor time.
    did_hash: String,
    /// Address that submitted the first — and only — anchor.
    anchorer: String,
    /// Block the anchor was written in, as the caller reports it.
    #[serde(default)]
    at_block: u64,
    /// Timestamp the anchor was written at, as the caller reports it.
    #[serde(default)]
    at_time: u64,
}

/// The `anchor` payload.
#[derive(Debug, Deserialize)]
struct AnchorRequest {
    /// The digest to anchor.
    cid: String,
    /// The agent DID hash to bind it to.
    did_hash: String,
    /// The address anchoring it.
    anchorer: String,
    /// The anchors that already exist.
    #[serde(default)]
    existing: Vec<AnchorRow>,
    /// The constructor-set cap, per anchorer. Absent means no cap is applied, and the answer
    /// says which of the two happened.
    #[serde(default)]
    max_per_anchorer: Option<u64>,
    /// The block and timestamp to record, as the caller reports them.
    #[serde(default)]
    at_block: u64,
    #[serde(default)]
    at_time: u64,
}

/// The `verify` payload.
#[derive(Debug, Deserialize)]
struct VerifyRequest {
    /// The digest being presented as evidence.
    cid: String,
    /// The agent DID hash it is being presented *for*.
    did_hash: String,
    /// The anchors that exist.
    #[serde(default)]
    existing: Vec<AnchorRow>,
}

/// The `anchorable` payload.
#[derive(Debug, Deserialize)]
struct AnchorableRequest {
    /// The digest to ask about.
    cid: String,
    /// The anchors that exist.
    #[serde(default)]
    existing: Vec<AnchorRow>,
}

/// The `page` payload.
#[derive(Debug, Deserialize)]
struct PageRequest {
    /// Whose anchors to page over.
    anchorer: String,
    /// The anchors that exist.
    #[serde(default)]
    existing: Vec<AnchorRow>,
    /// First index to return.
    #[serde(default)]
    offset: u64,
    /// Maximum entries to return.
    #[serde(default)]
    limit: u64,
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
        "anchor" => match anchor(&request.payload) {
            Ok(answer) => Response::ok(&request, PLUGIN_NAME, PLUGIN_VERSION, answer),
            Err(refusal) => refusal_from(refusal, &request),
        },
        "verify" => match verify(&request.payload) {
            Ok(answer) => Response::ok(&request, PLUGIN_NAME, PLUGIN_VERSION, answer),
            Err(refusal) => refusal_from(refusal, &request),
        },
        "anchorable" => match anchorable(&request.payload) {
            Ok(answer) => Response::ok(&request, PLUGIN_NAME, PLUGIN_VERSION, answer),
            Err(refusal) => refusal_from(refusal, &request),
        },
        "page" => match page(&request.payload) {
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

/// Whether `value` is `0x` followed by exactly `digits` lower-case hex digits.
///
/// Lower case only, and that is the same decision `sys.chain` documents: the contract's ABI
/// encoding and JSON-RPC's quantity encoding both write `0x`, and accepting a second spelling
/// would make two strings mean one digest without either being canonical.
fn is_hex(value: &str, digits: usize) -> bool {
    let Some(rest) = value.strip_prefix("0x") else {
        return false;
    };
    rest.len() == digits
        && rest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// Whether a `bytes32` is all zeroes.
fn is_zero_bytes32(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|rest| rest.chars().all(|c| c == '0'))
}

/// Require a `bytes32` field by shape, and return it.
fn bytes32_field<'a>(value: &'a str, field: &str, code: &'static str) -> Result<&'a str, Refusal> {
    if !is_hex(value, BYTES32_DIGITS) {
        return Err(Refusal {
            code,
            message: format!(
                "`{field}` must be `0x` followed by {BYTES32_DIGITS} lower-case hex digits, found \
                 {} character(s)",
                value.chars().count()
            ),
        });
    }
    Ok(value)
}

/// Require an address field by shape, and return it.
fn address_field<'a>(value: &'a str, field: &str) -> Result<&'a str, Refusal> {
    if !is_hex(value, ADDRESS_DIGITS) {
        return Err(Refusal {
            code: CODE_PAYLOAD,
            message: format!(
                "`{field}` must be `0x` followed by {ADDRESS_DIGITS} lower-case hex digits, found \
                 {} character(s)",
                value.chars().count()
            ),
        });
    }
    Ok(value)
}

/// Index the set by digest, refusing a set that names one digest twice.
///
/// The first-write-wins rule is only meaningful over a set with one answer per digest: a set
/// that disagrees with itself has no anchorer for that digest, and picking the first row would
/// be this plugin inventing a tie-break the contract never had.
fn index(existing: &[AnchorRow]) -> Result<BTreeMap<&str, &AnchorRow>, Refusal> {
    let mut by_cid: BTreeMap<&str, &AnchorRow> = BTreeMap::new();
    for row in existing {
        bytes32_field(&row.cid, "existing[].cid", CODE_PAYLOAD)?;
        bytes32_field(&row.did_hash, "existing[].did_hash", CODE_PAYLOAD)?;
        address_field(&row.anchorer, "existing[].anchorer")?;
        if by_cid.insert(row.cid.as_str(), row).is_some() {
            return Err(Refusal {
                code: CODE_SET_INCONSISTENT,
                message: format!(
                    "`{}` appears twice in the anchor set; anchoring is first-write-wins, so a set \
                     with two answers for one digest is not a history this door can read",
                    row.cid
                ),
            });
        }
    }
    Ok(by_cid)
}

/// `anchor`: apply the contract's write rules to one proposed anchor.
fn anchor(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "an `anchor` payload must be a JSON object carrying `cid`, `did_hash`, `anchorer` \
                 and `existing`, found {}",
                payload::kind_of(payload)
            ),
        });
    }
    let request: AnchorRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;

    let cid = bytes32_field(&request.cid, "cid", CODE_PAYLOAD)?;
    let did = bytes32_field(&request.did_hash, "did_hash", CODE_PAYLOAD)?;
    let anchorer = address_field(&request.anchorer, "anchorer")?;

    // The two non-zero guards, in the contract's order, because a caller reading a refusal
    // should see the rule that fired.
    if is_zero_bytes32(cid) {
        return Err(Refusal {
            code: CODE_ZERO_CID,
            message: "`cid` is all zeroes; the contract reserves `bytes32(0)` to mean unset, so \
                      anchoring it would create a digest no card can produce"
                .to_string(),
        });
    }
    if is_zero_bytes32(did) {
        return Err(Refusal {
            code: CODE_ZERO_DID,
            message: "`did_hash` is all zeroes; the contract refuses it because an anchor with no \
                      agent binding verifies as evidence for nobody in particular"
                .to_string(),
        });
    }

    let by_cid = index(&request.existing)?;

    // First write wins. This is the contract's `AlreadyAnchored` revert, and it is a refusal
    // rather than an answer with `anchored: false`, because a caller that had to read a boolean
    // would treat "did not anchor" and "somebody else already did" as one outcome.
    if let Some(existing) = by_cid.get(cid) {
        return Err(Refusal {
            code: CODE_ALREADY_ANCHORED,
            message: format!(
                "`{cid}` is already anchored by `{}`; anchoring is first-write-wins and permanent, \
                 with no admin override and no replace path",
                existing.anchorer
            ),
        });
    }

    let count_for_anchorer = request
        .existing
        .iter()
        .filter(|row| row.anchorer == anchorer)
        .count() as u64;

    // The cap is applied only when the caller supplies one, and the answer says which happened:
    // a default would be this door inventing the operator's constructor argument.
    if let Some(cap) = request.max_per_anchorer {
        if count_for_anchorer >= cap {
            return Err(Refusal {
                code: CODE_LIMIT_REACHED,
                message: format!(
                    "`{anchorer}` already holds {count_for_anchorer} anchor(s) and the cap is \
                     {cap}; the contract reverts rather than evicting, so the count for an \
                     address stays a bound rather than a guess"
                ),
            });
        }
    }

    Ok(json!({
        "anchored": true,
        "cid": cid,
        "did_hash": did,
        "anchorer": anchorer,
        "at_block": request.at_block,
        "at_time": request.at_time,
        "count_for_anchorer": count_for_anchorer + 1,
        "max_per_anchorer": request.max_per_anchorer,
        "cap_applied": request.max_per_anchorer.is_some(),
        "first_write_wins": true,
        "replaces_nothing": true,
        // Said in every answer, because the whole risk of a door named `anchor` is a caller
        // reading it as a chain write.
        "on_chain": false,
        "emits_event": false,
        "note": NOTES,
    }))
}

/// `verify`: is this digest anchored, **and** anchored to this agent?
fn verify(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `verify` payload must be a JSON object carrying `cid`, `did_hash` and \
                 `existing`, found {}",
                payload::kind_of(payload)
            ),
        });
    }
    let request: VerifyRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;

    let cid = bytes32_field(&request.cid, "cid", CODE_PAYLOAD)?;
    let did = bytes32_field(&request.did_hash, "did_hash", CODE_PAYLOAD)?;
    let by_cid = index(&request.existing)?;

    let found = by_cid.get(cid);
    let (verified, anchored_to_other, anchorer, bound_did) = match found {
        Some(row) => (
            row.did_hash == did,
            row.did_hash != did,
            Some(row.anchorer.clone()),
            Some(row.did_hash.clone()),
        ),
        None => (false, false, None, None),
    };

    Ok(json!({
        "verified": verified,
        "cid": cid,
        "did_hash": did,
        "known": found.is_some(),
        // The distinction upstream v2.5.6's `verify` destroyed: a real anchor belonging to
        // somebody else is not the same answer as no anchor at all.
        "anchored_to_other_agent": anchored_to_other,
        "anchorer": anchorer,
        "bound_did_hash": bound_did,
        "checks": ["cid_is_anchored", "agent_did_hash_matches"],
        "on_chain": false,
    }))
}

/// `anchorable`: may this digest still be anchored by anyone?
fn anchorable(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "an `anchorable` payload must be a JSON object carrying `cid` and `existing`, \
                 found {}",
                payload::kind_of(payload)
            ),
        });
    }
    let request: AnchorableRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;
    let cid = bytes32_field(&request.cid, "cid", CODE_PAYLOAD)?;
    let by_cid = index(&request.existing)?;
    let existing = by_cid.get(cid);
    Ok(json!({
        "cid": cid,
        "anchorable": existing.is_none(),
        "anchorer": existing.map(|row| row.anchorer.clone()),
        "on_chain": false,
    }))
}

/// `page`: one anchorer's anchors, clamped the way the contract clamps.
fn page(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `page` payload must be a JSON object carrying `anchorer` and `existing`, found \
                 {}",
                payload::kind_of(payload)
            ),
        });
    }
    let request: PageRequest = serde_json::from_value(payload.clone()).map_err(|err| Refusal {
        code: CODE_PAYLOAD,
        message: bounded(&err.to_string()),
    })?;
    let anchorer = address_field(&request.anchorer, "anchorer")?;
    index(&request.existing)?;

    let all: Vec<&AnchorRow> = request
        .existing
        .iter()
        .filter(|row| row.anchorer == anchorer)
        .collect();
    let total = all.len() as u64;
    if request.offset > total {
        return Err(Refusal {
            code: CODE_PAGE_OUT_OF_RANGE,
            message: format!(
                "offset {} is past the {total} anchor(s) `{anchorer}` holds; the contract reverts \
                 rather than returning an empty page, because an empty page and a wrong offset \
                 would otherwise look the same",
                request.offset
            ),
        });
    }

    let remaining = total - request.offset;
    let count = request.limit.min(remaining);
    let start = usize::try_from(request.offset).unwrap_or(usize::MAX);
    let take = usize::try_from(count).unwrap_or(0);
    let slice: Vec<Value> = all
        .iter()
        .skip(start)
        .take(take)
        .map(|row| {
            json!({
                "cid": row.cid,
                "did_hash": row.did_hash,
                "anchorer": row.anchorer,
                "at_block": row.at_block,
                "at_time": row.at_time,
            })
        })
        .collect();

    Ok(json!({
        "anchorer": anchorer,
        "total": total,
        "offset": request.offset,
        "limit": request.limit,
        "returned": slice.len(),
        "page": slice,
        "limit_clamped": count != request.limit,
        "on_chain": false,
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

/// Report this binary's identity, its provenance and what it deliberately does not do.
fn capabilities() -> Answer {
    let entry = Official::find(PLUGIN_NAME).ok_or_else(|| Refusal {
        code: CODE_CAPABILITIES,
        message: format!(
            "`{PLUGIN_NAME}` is not in `nau_plugins::official::OFFICIALS`; this binary and the \
             catalogue disagree about its identity, so nothing about it can be reported"
        ),
    })?;

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
    // Imported here rather than at the top: the binary never names `Tier` -- it reads the label
    // off the value `Official::tier` returns -- and an import the production code does not use
    // is a claim about the production code that is not true.
    use nau_plugin::tier::Tier;

    /// Encode a request, run one frame through this binary's own `run`, and decode the answer.
    fn call(op: &str, payload: Value) -> (Response, u8) {
        let request = json!({
            "id": "anchor-test",
            "abi": frame::abi_version(),
            "op": op,
            "payload": payload,
        });
        // Framed, not a bare JSON body: the length prefix is part of the ABI.
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

    fn refusal(response: &Response) -> String {
        response.message.clone().unwrap_or_default()
    }

    fn code_of(response: &Response) -> String {
        response.code.clone().unwrap_or_default()
    }

    fn answer(response: &Response) -> Value {
        response.payload.clone().expect("a payload")
    }

    /// A `bytes32` that is not zero, distinguishable by its last digit.
    fn cid(n: u8) -> String {
        format!("0x{}{n}", "0".repeat(63))
    }

    /// An address that is not zero.
    fn addr(n: u8) -> String {
        format!("0x{}{n}", "0".repeat(39))
    }

    const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

    fn row(cid_value: &str, did: &str, anchorer: &str) -> Value {
        json!({ "cid": cid_value, "did_hash": did, "anchorer": anchorer, "at_block": 7, "at_time": 8 })
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
            let (response, _code) = call(op, json!({}));
            // Every op either answers or refuses by *shape*; none may be an unknown op. A shape
            // refusal is the correct outcome for an empty payload here, so the assertion is
            // about the code rather than about success.
            assert_ne!(
                code_of(&response),
                payload::CODE_UNKNOWN_OPERATION,
                "`{op}` is listed as implemented but is not dispatched"
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
    fn anchoring_is_first_write_wins() {
        // The contract's whole reason for existing, and upstream v2.5.6's first defect: an
        // `anchor()` that overwrote unconditionally let anyone take over an existing digest.
        let (response, code) = call(
            "anchor",
            json!({
                "cid": cid(1),
                "did_hash": cid(2),
                "anchorer": addr(3),
                "existing": [row(&cid(1), &cid(2), &addr(9))],
            }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(code_of(&response), CODE_ALREADY_ANCHORED, "{response:?}");
        // The refusal names who holds it, because that is what makes an anchor attributable.
        assert!(
            refusal(&response).contains(&addr(9)),
            "{}",
            refusal(&response)
        );
    }

    #[test]
    fn a_digest_nobody_holds_is_anchored_and_the_answer_says_nothing_was_replaced() {
        let (response, code) = call(
            "anchor",
            json!({
                "cid": cid(1),
                "did_hash": cid(2),
                "anchorer": addr(3),
                "existing": [],
                "at_block": 11,
                "at_time": 12,
            }),
        );
        assert_eq!(code, EXIT_OK, "{}", refusal(&response));
        let a = answer(&response);
        assert_eq!(a["anchored"], true, "{a}");
        assert_eq!(a["replaces_nothing"], true, "{a}");
        assert_eq!(a["first_write_wins"], true, "{a}");
        assert_eq!(a["count_for_anchorer"], 1, "{a}");
        assert_eq!(a["cap_applied"], false, "no cap was supplied: {a}");
        assert_eq!(a["on_chain"], false, "{a}");
        assert_eq!(a["emits_event"], false, "{a}");
    }

    #[test]
    fn the_two_non_zero_guards_fire_in_the_contracts_order() {
        let (zero_cid, _) = call(
            "anchor",
            json!({ "cid": ZERO32, "did_hash": cid(2), "anchorer": addr(3) }),
        );
        assert_eq!(code_of(&zero_cid), CODE_ZERO_CID, "{zero_cid:?}");

        let (zero_did, _) = call(
            "anchor",
            json!({ "cid": cid(1), "did_hash": ZERO32, "anchorer": addr(3) }),
        );
        assert_eq!(code_of(&zero_did), CODE_ZERO_DID, "{zero_did:?}");
    }

    #[test]
    fn verify_checks_the_digest_and_the_agent() {
        // Upstream v2.5.6's second defect: `verify(cidHash)` ignored the agent, so a real anchor
        // for agent A verified as true for agent B.
        let existing = vec![row(&cid(1), &cid(2), &addr(3))];

        let (right, _) = call(
            "verify",
            json!({ "cid": cid(1), "did_hash": cid(2), "existing": existing }),
        );
        let a = answer(&right);
        assert_eq!(a["verified"], true, "{a}");
        assert_eq!(a["known"], true, "{a}");
        assert_eq!(a["anchored_to_other_agent"], false, "{a}");

        // The same digest presented for a different agent: verified false, and *said to be*
        // bound to somebody else rather than merely false.
        let (wrong, _) = call(
            "verify",
            json!({ "cid": cid(1), "did_hash": cid(4), "existing": existing }),
        );
        let b = answer(&wrong);
        assert_eq!(b["verified"], false, "{b}");
        assert_eq!(b["known"], true, "the digest IS anchored: {b}");
        assert_eq!(b["anchored_to_other_agent"], true, "{b}");
        assert_eq!(b["bound_did_hash"], cid(2), "{b}");
        assert_eq!(b["anchorer"], addr(3), "{b}");

        // And an unknown digest is not the same answer as a bound-to-somebody-else one.
        let (unknown, _) = call(
            "verify",
            json!({ "cid": cid(5), "did_hash": cid(2), "existing": existing }),
        );
        let c = answer(&unknown);
        assert_eq!(c["verified"], false, "{c}");
        assert_eq!(c["known"], false, "{c}");
        assert_eq!(c["anchored_to_other_agent"], false, "{c}");
    }

    #[test]
    fn the_cap_is_applied_only_when_supplied() {
        let existing = vec![row(&cid(1), &cid(2), &addr(3))];

        // No cap: the second anchor from the same address is fine.
        let (without, code) = call(
            "anchor",
            json!({ "cid": cid(5), "did_hash": cid(2), "anchorer": addr(3), "existing": existing }),
        );
        assert_eq!(code, EXIT_OK, "{}", refusal(&without));
        assert_eq!(answer(&without)["count_for_anchorer"], 2);

        // Cap of one: refused, and the refusal carries the cap.
        let (with, _) = call(
            "anchor",
            json!({
                "cid": cid(5),
                "did_hash": cid(2),
                "anchorer": addr(3),
                "existing": existing,
                "max_per_anchorer": 1,
            }),
        );
        assert_eq!(code_of(&with), CODE_LIMIT_REACHED, "{with:?}");
        assert!(refusal(&with).contains("cap is 1"), "{}", refusal(&with));
    }

    #[test]
    fn a_set_that_names_one_digest_twice_is_refused() {
        let (response, code) = call(
            "verify",
            json!({
                "cid": cid(1),
                "did_hash": cid(2),
                "existing": [row(&cid(1), &cid(2), &addr(3)), row(&cid(1), &cid(4), &addr(5))],
            }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(code_of(&response), CODE_SET_INCONSISTENT, "{response:?}");
    }

    #[test]
    fn a_hash_of_the_wrong_shape_is_refused_by_shape() {
        let (response, _) = call(
            "anchor",
            json!({ "cid": "0xAA", "did_hash": cid(2), "anchorer": addr(3) }),
        );
        assert_eq!(code_of(&response), CODE_PAYLOAD, "{response:?}");
        // Upper case is a different spelling of the same digest, and this door accepts one.
        let (upper, _) = call(
            "anchor",
            json!({ "cid": format!("0x{}", "A".repeat(64)), "did_hash": cid(2), "anchorer": addr(3) }),
        );
        assert_eq!(code_of(&upper), CODE_PAYLOAD, "{upper:?}");
    }

    #[test]
    fn anchorable_distinguishes_free_from_taken() {
        let existing = vec![row(&cid(1), &cid(2), &addr(3))];
        let (free, _) = call("anchorable", json!({ "cid": cid(9), "existing": existing }));
        let a = answer(&free);
        assert_eq!(a["anchorable"], true, "{a}");
        assert_eq!(a["anchorer"], Value::Null, "{a}");

        let (taken, _) = call("anchorable", json!({ "cid": cid(1), "existing": existing }));
        let b = answer(&taken);
        assert_eq!(b["anchorable"], false, "{b}");
        assert_eq!(b["anchorer"], addr(3), "{b}");
    }

    #[test]
    fn page_clamps_the_limit_and_refuses_an_offset_past_the_end() {
        let existing = vec![
            row(&cid(1), &cid(2), &addr(3)),
            row(&cid(4), &cid(2), &addr(3)),
            row(&cid(5), &cid(2), &addr(9)),
        ];

        // The limit clamps to what remains, and the answer says it clamped.
        let (clamped, code) = call(
            "page",
            json!({ "anchorer": addr(3), "existing": existing, "offset": 1, "limit": 50 }),
        );
        assert_eq!(code, EXIT_OK, "{}", refusal(&clamped));
        let a = answer(&clamped);
        assert_eq!(a["total"], 2, "only addr(3)'s anchors are paged: {a}");
        assert_eq!(a["returned"], 1, "{a}");
        assert_eq!(a["limit_clamped"], true, "{a}");
        assert_eq!(a["page"][0]["cid"], cid(4), "{a}");

        // A zero limit is an empty page, not a refusal -- the contract's own choice.
        let (empty, code) = call(
            "page",
            json!({ "anchorer": addr(3), "existing": existing, "offset": 0, "limit": 0 }),
        );
        assert_eq!(code, EXIT_OK, "{}", refusal(&empty));
        assert_eq!(answer(&empty)["returned"], 0);

        // Past the end it reverts rather than answering an empty page.
        let (past, _) = call(
            "page",
            json!({ "anchorer": addr(3), "existing": existing, "offset": 3, "limit": 1 }),
        );
        assert_eq!(code_of(&past), CODE_PAGE_OUT_OF_RANGE, "{past:?}");
    }

    #[test]
    fn an_unknown_op_is_refused_with_the_list_of_implemented_ones() {
        let (response, code) = call("mine", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(code_of(&response), payload::CODE_UNKNOWN_OPERATION);
        assert!(
            refusal(&response).contains("anchor"),
            "{}",
            refusal(&response)
        );
    }

    #[test]
    fn capabilities_reports_identity_tier_and_an_empty_approval_set() {
        let (response, code) = call("capabilities", json!({}));
        assert_eq!(code, EXIT_OK, "{}", refusal(&response));
        let a = answer(&response);
        assert_eq!(a["plugin"], PLUGIN_NAME);
        assert_eq!(a["tier"], "official");
        assert_eq!(a["declared_matches_catalogue"], true, "{a}");
        assert_eq!(a["required_approvals"], json!([]), "{a}");
        assert_eq!(a["declared_capabilities_backed_by_ops"], false, "{a}");
        // Provenance is reported per op, and it names the contract rather than a crate.
        assert!(
            a["delegation"]["anchor"]
                .as_str()
                .unwrap_or("")
                .contains("AgentCardAnchor.sol"),
            "{a}"
        );
    }
}
