//! `nau-plugin-bridge` — the official (T1) plugin for `com.twinsearth.official.bridge`.
//!
//! # Why the migration document's "hard limit" for this plugin is mis-stated
//!
//! `docs/PLUGIN-MIGRATION.md` lists `com.twinsearth.official.bridge` as unimplemented
//! "because there is no Rust chain client", calls that **a hard limit**, and counts bridge
//! and mesh as the only two such limits. The first half of that is true and the conclusion
//! does not follow. Upstream `TwinsEarth/agent-universe` **v3.5.0** ships
//! `com.twinsearth.official.chain-bridge` as an **offline** entry module
//! (`gsn-core/src/plugin/official/mod.rs`, `BRIDGE_ENTRY`) — a port of
//! `contracts/src/ReputationRegistry.sol` written as pure state functions:
//!
//! * **no RPC, no provider, no chain client, no network of any kind.** The registry's state
//!   (`owner`, `verifiers`, `epochs`, `agent_epochs`, `final_snapshots`) travels *inside the
//!   payload*; `add_verifier` / `record` / `finalize` / `get_latest` are functions over that
//!   state and nothing else;
//! * its hashing is a **pure-Python keccak256** inlined in the module — evidence that the
//!   contract's hash is reproduced rather than asked of a node;
//! * the sibling `chain-anchor` entry says the same thing in words: "offline port of
//!   `contracts/src/AgentCardAnchor.sol` (**no RPC; does NOT claim real on-chain**)".
//!
//! So a chain client is required to **write** to a chain, and it was never required for the
//! bridge's semantics, which are computable offline. The missing piece was an offline
//! commitment-and-verification design, not a client. `nau-attest::commit` is that design —
//! a real SHA-256 Merkle commitment with real inclusion proofs — so this plugin exists, and
//! the accurate sentence for the migration document is *"bridge needs an offline port of the
//! registry's aggregation rules, not a chain client"*, not *"bridge needs a chain client"*.
//!
//! # What this plugin does, and how it differs from upstream
//!
//! It bridges off-chain reputation into something a third party can verify later **without a
//! chain**, which is the property the upstream bridge exists to provide:
//!
//! | | upstream `chain-bridge` (v3.5.0) | this binary |
//! |---|---|---|
//! | shape | the `ReputationRegistry` **state machine** in the payload: owner, ≤32 verifiers, epochs, finalised snapshots | the **commitment**: a Merkle root over the snapshots, plus a proof for each |
//! | aggregation | per-dimension **median** of verifier submissions, finalised at quorum `floor(n/2)+1` | none: the snapshots are committed as given |
//! | identity keys | **keccak256** of the agent DID and of epoch keys | the snapshot's **canonical JSON** (`nau_core::canonical`), SHA-256 leaf hashes |
//! | immutability | a finalised epoch cannot be re-finalised or contradicted | the root is a commitment: any change to any snapshot changes the root |
//! | verification | re-run the state machine with the same payload | `verify_inclusion` against the root, offline |
//! | chain client | **none** | **none** |
//!
//! The aggregation half is deliberately **not** implemented: no crate in this workspace
//! computes a median or a quorum over verifier submissions, and reproducing upstream's
//! median-and-quorum would be porting the algorithm this project refuses to port. What is
//! implemented is the half that makes the bridge a bridge in this architecture — a verdict
//! anyone can re-check offline — and the absent half is named in `notes` rather than implied.
//!
//! The snapshot type **is** shared: upstream's registry records four basis-point dimensions,
//! and [`Reputation`] is exactly that (quality, speed, honesty, availability), with
//! [`ReputationScore`] enforcing the same `0..=10_000` range upstream's `record` checks — so
//! the range check is delegated to the model's own constructor rather than restated.
//!
//! **Nothing here claims on-chain compatibility.** Our identity is SHA-256 and canonical
//! JSON, not keccak256, and no chain is contacted: every answer says `"on_chain": false`.
//! A host that needs the Solidity contract's hashes needs a chain client; a host that needs
//! to know whether a reputation snapshot it was shown is in a set it was told about does not.
//!
//! # Protocol
//!
//! ```text
//! stdin:  u32_be(len) || {"abi":"3.2","id":"req-1","op":"commit","payload":{…}}
//! stdout: u32_be(len) || {"abi":"3.2","id":"req-1",
//!                         "plugin":"com.twinsearth.official.bridge",
//!                         "version":"1.0.0","ok":true,"payload":{…}}
//! ```
//!
//! One frame in, one frame out, then exit. stdout carries **only** frames; every diagnostic
//! goes to stderr, because a stray `println!` is a protocol corruption and this binary has
//! no other way to talk to its host.
//!
//! ## `commit`
//!
//! ```json
//! { "snapshots": [ { "agent": "did:nau:…", "epoch": 3,
//!                    "reputation": { "quality": 8000, "speed": 6000, "honesty": 7000,
//!                                    "availability": 9000, "settled": 7, "faults": 2 } } ] }
//! ```
//!
//! ```json
//! { "root": "…64 hex…", "leaf_count": 1,
//!   "leaves": [ { "index": 0, "agent": "did:nau:…", "epoch": 3,
//!                 "leaf_digest": "…64 hex…", "canonical": "{…}", "proof": { … } } ],
//!   "scheme": { "implementation": "nau_attest::commit", "requires_chain_client": false,
//!               "verifiable_offline": true, "upstream_counterpart": "…" },
//!   "on_chain": false }
//! ```
//!
//! The `proof` is the crate's own `MerkleProof`, serialized by the crate: `siblings` is an
//! array of 32-byte arrays, not hex. A caller passes it back to `verify` unchanged.
//!
//! ## `verify`
//!
//! ```json
//! { "root": "…64 hex…", "snapshot": { …same shape as one element of `snapshots`… },
//!   "proof": { …the proof committed for it… } }
//! ```
//!
//! ```json
//! { "included": true, "root": "…", "leaf_index": 0, "leaf_count": 1,
//!   "verification_cost": 0, "reason": null, "on_chain": false }
//! ```
//!
//! "This snapshot is not in that set" is an **answer** (`included: false` with the
//! crate's own reason), not a plugin refusal: it is the question the op exists to answer.
//! The payload's *shape* is refused when it is unusable (a root that is not 32 bytes of hex,
//! a missing proof).
//!
//! ## `capabilities`
//!
//! Takes no arguments. The catalogue declares `chain:evm:read` and `chain:evm:write` for
//! this entry, and at the official tier the matrix resolves **both** to
//! `RequiresApproval(VendorTeam)` — so `required_approvals` carries two rows here.
//!
//! Neither is exercised: `commit` and `verify` touch no chain, which is the entire point of
//! an **offline** bridge. `capability_backing` is therefore empty for both and
//! `declared_capabilities_backed_by_ops` is `false`. That is not a defect to be papered
//! over — it is the honest state of an offline implementation of a catalogue entry whose
//! declaration is about the on-chain half, and the answer says so in `notes`.
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
//! * a score outside the model's documented range is refused with the model's own message,
//!   because `serde` builds a `ReputationScore` without consulting its constructor;
//! * an empty snapshot set is refused by the commitment, not defaulted to a "zero root",
//!   which would make an empty set indistinguishable from a set that hashes to zero;
//! * a diagnostic echoed back to the host is bounded, because an error string built from
//!   caller-supplied JSON is how a log becomes an attack surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process::ExitCode;

use nau_attest::commit::{commit_outputs, verify_inclusion, MerkleProof};
use nau_core::canonical::canonical_object;
use nau_core::domain::ReputationScore;
use nau_market::reputation::Reputation;
use nau_plugin::capability::{Capability, Grant};
use nau_plugin::tier::Tier;
use nau_plugins::frame::{self, Response};
use nau_plugins::official::Official;
use nau_plugins::payload;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// The catalogue name this binary implements, from
/// [`nau_plugins::official::OFFICIALS`]. The tier is derived from this name, so the
/// spelling is not cosmetic.
const PLUGIN_NAME: &str = "com.twinsearth.official.bridge";

/// The version this binary reports, which is the catalogue entry's version rather than the
/// workspace's. A test asserts the two are equal, so a catalogue bump that forgets this
/// constant fails instead of shipping a plugin that lies about its own version.
const PLUGIN_VERSION: &str = "1.0.0";

/// The operations this binary actually implements.
///
/// A test asserts every entry is dispatched and that every op named in [`OP_DELEGATION`]
/// is listed here, so this table cannot drift away from `run`.
const IMPLEMENTED_OPS: [&str; 3] = ["capabilities", "commit", "verify"];

/// The capability set this binary's manifest declares.
///
/// Both are what the catalogue entry for this plugin names
/// ([`nau_plugins::official::OFFICIALS`]). At the official tier the matrix resolves each to
/// `RequiresApproval(VendorTeam)`, and neither is exercised by an offline implementation —
/// which the answer reports rather than hides.
const DECLARED_CAPABILITIES: [&str; 2] = ["chain:evm:read", "chain:evm:write"];

/// Which implemented op exercises each declared capability.
///
/// Every row is empty, and here that is the substantive fact rather than a placeholder:
/// `commit` and `verify` build and check a Merkle commitment offline and touch no chain.
/// The catalogue's declaration is about the on-chain half of a bridge; this binary
/// implements the offline half, and says so.
const CAPABILITY_BACKING: [(&str, &[&str]); 2] =
    [("chain:evm:read", &[]), ("chain:evm:write", &[])];

/// Which crate function each implemented op delegates to, as `(op, target)`.
///
/// Reported in the `capabilities` answer so a host can see the delegation rather than
/// having to trust a description of it.
const OP_DELEGATION: [(&str, &str); 3] = [
    (
        "capabilities",
        "nau_plugin::capability::Capability::decision",
    ),
    (
        "commit",
        "nau_attest::commit::{commit_outputs, MerkleTree::proof} + \
         nau_core::canonical::canonical_object + nau_core::domain::ReputationScore::from_bps",
    ),
    ("verify", "nau_attest::commit::verify_inclusion"),
];

/// The upstream entry this plugin's offline design answers, as a machine-readable record.
const UPSTREAM_IMPLEMENTATION: &str = "gsn-core/src/plugin/official/mod.rs @ v3.5.0, \
                                       BRIDGE_ENTRY (offline port of \
                                       contracts/src/ReputationRegistry.sol)";

/// The scheme this plugin commits under.
const SCHEME: &str = "nau_attest::commit: SHA-256 Merkle tree, leaf/node domain separation, \
                      leaf count folded into the root, empty set refused";

/// The sentence a host should read next to `declared_capabilities_backed_by_ops: false`.
const NOTES: &str = "This is the OFFLINE half of a cross-chain reputation bridge: it commits \
                     canonical reputation snapshots into a SHA-256 Merkle root \
                     (nau_attest::commit) and verifies inclusion proofs against that root, \
                     with no chain client and no network. Upstream's chain-bridge is offline \
                     too, so `docs/PLUGIN-MIGRATION.md`'s 'no Rust chain client' is not the \
                     reason this entry was unimplemented: what was missing is an offline \
                     commitment design, which nau-attest already provides. The catalogue \
                     declares chain:evm:read and chain:evm:write for this entry and the \
                     official tier holds each only with vendor-team approval; neither is \
                     exercised, because nothing here touches a chain -- so \
                     declared_capabilities_backed_by_ops is false. The aggregation half of \
                     upstream's registry (verifier set, per-epoch median, floor(n/2)+1 \
                     quorum, keccak256 identity keys) is NOT implemented: no crate here \
                     provides a median or that quorum, and porting them would be rewriting \
                     the algorithm. Reputation snapshots are committed as given.";

/// Exit code: the call was answered and succeeded.
const EXIT_OK: u8 = 0;
/// Exit code: the call was answered with a refusal.
const EXIT_REFUSED: u8 = 1;
/// Exit code: no frame could be read or written.
const EXIT_IO: u8 = 2;

/// Error code: a payload is not a JSON object.
const CODE_NOT_OBJECT: &str = payload::CODE_NOT_OBJECT;
/// Error code: a `commit` payload is an object but not the shape this op documents.
const CODE_COMMIT_PAYLOAD: &str = "bridge_commit_payload_invalid";
/// Error code: the commitment itself refused the set (empty, or beyond its depth limit).
const CODE_COMMIT_FAILED: &str = "bridge_commit_failed";
/// Error code: a snapshot score is outside the model's documented range.
const CODE_SNAPSHOT_RANGE: &str = "bridge_snapshot_score_out_of_range";
/// Error code: a snapshot could not be canonicalized, so it has no stable leaf bytes.
const CODE_NOT_CANONICAL: &str = "bridge_snapshot_not_canonical";
/// Error code: a `verify` payload is an object but not the shape this op documents.
const CODE_VERIFY_PAYLOAD: &str = "bridge_verify_payload_invalid";
/// Error code: this binary and the official catalogue disagree about its own identity.
const CODE_CAPABILITIES: &str = "bridge_capabilities_unavailable";

/// Longest diagnostic quoted back to the host, in characters.
///
/// The message is written into a frame the host logs, and a `serde_json` diagnostic for a
/// wrong type quotes the offending value — which the caller chose. Bounding it keeps a
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

/// One reputation snapshot, as upstream's registry records one per agent and epoch.
///
/// The reputation is [`Reputation`] — the same four basis-point dimensions upstream's
/// registry stores — and the agent/epoch pair is what upstream keys a registry entry by.
#[derive(Debug, Serialize, Deserialize)]
struct Snapshot {
    /// The agent the snapshot is about. Upstream hashes it; this bridge commits it inside
    /// the canonical record instead, and says so.
    agent: String,
    /// The reputation epoch the snapshot belongs to.
    epoch: u64,
    /// The reputation itself.
    reputation: Reputation,
}

/// The `commit` payload.
#[derive(Debug, Deserialize)]
struct CommitRequest {
    /// The snapshots to commit. Required, and refused when empty by the commitment itself.
    snapshots: Vec<Snapshot>,
}

/// The `verify` payload.
#[derive(Debug, Deserialize)]
struct VerifyRequest {
    /// The commitment root, as 64 hex characters.
    root: String,
    /// The snapshot whose membership is being checked.
    snapshot: Snapshot,
    /// The proof produced by `commit` for that snapshot.
    proof: MerkleProof,
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
        "commit" => match commit(&request.payload) {
            Ok(answer) => Response::ok(&request, PLUGIN_NAME, PLUGIN_VERSION, answer),
            Err(refusal) => refusal_from(refusal, &request),
        },
        "verify" => match verify(&request.payload) {
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

/// Re-validate a snapshot's four dimensions with the model's own range check.
///
/// `ReputationScore` is `#[serde(transparent)]`, so deserializing a [`Reputation`] bypasses
/// [`ReputationScore::from_bps`] — the constructor that is the documented way to reach a
/// score in `0..=10_000`, which is also the range upstream's registry `record` enforces.
/// Delegating to that constructor keeps the refusal message the model's.
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
                code: CODE_SNAPSHOT_RANGE,
                message: format!("`{name}` is outside the model's range: {err}"),
            });
        }
    }
    Ok(())
}

/// The canonical leaf bytes of one snapshot: the exact bytes the commitment hashes.
///
/// Canonical JSON, from `nau-core`, so two hosts that agree on the snapshot agree on its
/// bytes — which is what makes the commitment re-checkable by somebody who never saw this
/// process. The snapshot's range is checked first, because a score outside the model's range
/// is not a reputation this project can commit to.
fn leaf_bytes(snapshot: &Snapshot) -> std::result::Result<Vec<u8>, Refusal> {
    validate_scores(&snapshot.reputation)?;
    let value = serde_json::to_value(snapshot).map_err(|err| Refusal {
        code: CODE_COMMIT_PAYLOAD,
        message: bounded(&err.to_string()),
    })?;
    let canonical = canonical_object(&value).map_err(|err| Refusal {
        code: CODE_NOT_CANONICAL,
        message: bounded(&err.to_string()),
    })?;
    Ok(canonical.into_bytes())
}

/// Commit the payload's snapshots and prove each one's inclusion.
fn commit(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `commit` payload must be a JSON object carrying `snapshots`, found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: CommitRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_COMMIT_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;

    let mut leaves = Vec::with_capacity(request.snapshots.len());
    for snapshot in &request.snapshots {
        leaves.push(leaf_bytes(snapshot)?);
    }

    // The delegation that makes this a bridge rather than a hash: the crate's own
    // commitment, which refuses an empty set, refuses a set beyond its depth limit, and
    // folds the leaf count into the root so a set and a set-plus-a-duplicate cannot collide.
    let tree = commit_outputs(&leaves).map_err(|err| Refusal {
        code: CODE_COMMIT_FAILED,
        message: bounded(&err.to_string()),
    })?;

    let mut committed = Vec::with_capacity(request.snapshots.len());
    for (index, snapshot) in request.snapshots.iter().enumerate() {
        let leaf = match tree.leaves.get(index) {
            Some(leaf) => *leaf,
            None => {
                return Err(Refusal {
                    code: CODE_COMMIT_FAILED,
                    message: format!(
                        "the commitment returned {} leaves but was asked to prove index {index}",
                        tree.len()
                    ),
                })
            }
        };
        let proof = tree.proof(index).map_err(|err| Refusal {
            code: CODE_COMMIT_FAILED,
            message: bounded(&err.to_string()),
        })?;
        let proof_value = serde_json::to_value(&proof).map_err(|err| Refusal {
            code: CODE_COMMIT_FAILED,
            message: bounded(&err.to_string()),
        })?;
        let canonical = leaves
            .get(index)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        committed.push(json!({
            "index": index,
            "agent": snapshot.agent,
            "epoch": snapshot.epoch,
            "leaf_digest": hex::encode(leaf),
            "canonical": canonical,
            "proof": proof_value,
        }));
    }

    Ok(json!({
        "root": hex::encode(tree.root),
        "leaf_count": tree.len(),
        "leaves": committed,
        "scheme": {
            "implementation": SCHEME,
            "requires_chain_client": false,
            "verifiable_offline": true,
            "upstream_counterpart": UPSTREAM_IMPLEMENTATION,
            "aggregation_implemented": false,
            "identity_keying": "canonical JSON (SHA-256 leaves), not keccak256",
        },
        "on_chain": false,
        "notes": NOTES,
    }))
}

/// Check whether a snapshot is in the set a root commits to.
fn verify(payload: &Value) -> Answer {
    if payload::object(payload).is_err() {
        return Err(Refusal {
            code: CODE_NOT_OBJECT,
            message: format!(
                "a `verify` payload must be a JSON object carrying `root`, `snapshot` and \
                 `proof`, found {}",
                payload::kind_of(payload)
            ),
        });
    }

    let request: VerifyRequest =
        serde_json::from_value(payload.clone()).map_err(|err| Refusal {
            code: CODE_VERIFY_PAYLOAD,
            message: bounded(&err.to_string()),
        })?;

    let raw = hex::decode(&request.root).map_err(|err| Refusal {
        code: CODE_VERIFY_PAYLOAD,
        message: format!("`root` must be 64 hex characters: {err}"),
    })?;
    let root: [u8; 32] = raw.as_slice().try_into().map_err(|_| Refusal {
        code: CODE_VERIFY_PAYLOAD,
        message: format!("`root` must be 32 bytes, found {}", raw.len()),
    })?;

    let leaf = leaf_bytes(&request.snapshot)?;

    // The delegation: the crate's own verifier, on the caller's root, leaf and proof. It
    // rejects a wrong leaf, a tampered sibling, a wrong index and an inflated leaf count,
    // and its refusal is reported as the crate wrote it.
    let (included, reason) = match verify_inclusion(root, &leaf, &request.proof) {
        Ok(()) => (true, None),
        Err(err) => (false, Some(bounded(&err.to_string()))),
    };

    Ok(json!({
        "included": included,
        "root": hex::encode(root),
        "leaf_index": request.proof.index(),
        "leaf_count": request.proof.leaf_count(),
        "verification_cost": request.proof.verification_cost(),
        "reason": reason,
        "on_chain": false,
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
    // Both declared capabilities resolve to `RequiresApproval(VendorTeam)` here, so the list
    // carries two rows -- derived, not restated.
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

    // Which op exercises each declared capability. Every list is empty: this bridge is
    // offline, and that is exactly why.
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

    /// A snapshot in the shape upstream's registry records: an agent, an epoch, four scores.
    fn snapshot(agent: &str, epoch: u64, quality: u16) -> Value {
        json!({
            "agent": agent,
            "epoch": epoch,
            "reputation": {
                "quality": quality,
                "speed": 6_000,
                "honesty": 7_000,
                "availability": 9_000,
                "settled": 7,
                "faults": 2,
            },
        })
    }

    fn snapshots() -> Vec<Value> {
        vec![
            snapshot("did:nau:0011223344556677", 1, 8_000),
            snapshot("did:nau:8899aabbccddeeff", 1, 4_000),
            snapshot("did:nau:8899aabbccddeeff", 2, 5_000),
        ]
    }

    /// The canonical leaf bytes of one snapshot, computed directly from `nau-core`.
    fn direct_leaf(snapshot: &Value) -> Vec<u8> {
        canonical_object(snapshot)
            .expect("the fixture is canonicalizable")
            .into_bytes()
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
    fn commit_agrees_with_the_crates_own_commitment_and_proves_every_leaf() {
        let snapshots = snapshots();
        let leaves: Vec<Vec<u8>> = snapshots.iter().map(direct_leaf).collect();
        let expected = commit_outputs(&leaves).expect("a non-empty set commits");

        let (code, response) = call("commit", json!({ "snapshots": snapshots }));
        assert_eq!(code, EXIT_OK, "{response:?}");
        assert!(response.ok);
        assert_eq!(response.plugin, PLUGIN_NAME);
        assert_eq!(response.version, PLUGIN_VERSION);

        let answer = response.payload.expect("a payload");
        assert_eq!(
            answer["root"],
            json!(hex::encode(expected.root)),
            "the root must be the crate's own"
        );
        assert_eq!(answer["leaf_count"], json!(3));
        assert_eq!(answer["on_chain"], json!(false));
        assert_eq!(
            answer["scheme"]["requires_chain_client"],
            json!(false),
            "an offline bridge must say so in the answer, not only in its documentation"
        );

        let committed = answer["leaves"].as_array().expect("an array");
        assert_eq!(committed.len(), 3);
        for (index, entry) in committed.iter().enumerate() {
            assert_eq!(entry["index"], json!(index));
            assert_eq!(
                entry["leaf_digest"],
                json!(hex::encode(expected.leaves[index]))
            );
            // The proof the answer carries must verify, through the crate, against the root
            // and the exact canonical bytes the caller would resend.
            let proof: MerkleProof =
                serde_json::from_value(entry["proof"].clone()).expect("the proof round-trips");
            verify_inclusion(expected.root, &leaves[index], &proof)
                .expect("the proof the answer carries must verify");
            assert_eq!(
                entry["canonical"],
                json!(String::from_utf8_lossy(&leaves[index]))
            );
        }
    }

    #[test]
    fn verify_answers_about_membership_and_round_trips_a_committed_proof() {
        let snapshots = snapshots();
        let (_, response) = call("commit", json!({ "snapshots": &snapshots }));
        let committed = response.payload.expect("a payload");

        // The proof from `commit`, sent back unchanged, must be accepted.
        let payload = json!({
            "root": committed["root"],
            "snapshot": &snapshots[1],
            "proof": committed["leaves"][1]["proof"],
        });
        let (code, response) = call("verify", payload);
        assert_eq!(code, EXIT_OK, "{response:?}");
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["included"], json!(true));
        assert_eq!(answer["reason"], Value::Null);
        assert_eq!(answer["leaf_index"], json!(1));
        assert_eq!(answer["leaf_count"], json!(3));
        assert_eq!(answer["on_chain"], json!(false));

        // A snapshot that differs by one score is not in the set, and that is an answer.
        let tampered = snapshot("did:nau:8899aabbccddeeff", 1, 4_001);
        let (code, response) = call(
            "verify",
            json!({
                "root": committed["root"],
                "snapshot": tampered,
                "proof": committed["leaves"][1]["proof"],
            }),
        );
        assert_eq!(code, EXIT_OK);
        assert!(
            response.ok,
            "a negative membership verdict is not a failure"
        );
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["included"], json!(false));
        assert!(
            answer["reason"]
                .as_str()
                .expect("a reason")
                .contains("root mismatch")
                || answer["reason"]
                    .as_str()
                    .expect("a reason")
                    .contains("does not"),
            "the crate's own reason must reach the host: {answer}"
        );

        // A wrong root is the same kind of answer.
        let (code, response) = call(
            "verify",
            json!({
                "root": "00".repeat(32),
                "snapshot": &snapshots[1],
                "proof": committed["leaves"][1]["proof"],
            }),
        );
        assert_eq!(code, EXIT_OK);
        assert_eq!(
            response.payload.expect("a payload")["included"],
            json!(false)
        );
    }

    #[test]
    fn an_empty_snapshot_set_is_refused_by_the_commitment_rather_than_defaulted() {
        let (code, response) = call("commit", json!({ "snapshots": [] }));
        assert_eq!(code, EXIT_REFUSED);
        assert!(!response.ok);
        assert_eq!(response.code.as_deref(), Some(CODE_COMMIT_FAILED));
        assert!(
            response.message.expect("a message").contains("empty"),
            "the crate refuses an empty set; its reason must reach the host"
        );
    }

    #[test]
    fn a_score_outside_the_models_range_is_refused_with_the_models_own_message() {
        let (code, response) = call(
            "commit",
            json!({ "snapshots": [ snapshot("did:nau:0011223344556677", 1, 60_000) ] }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_SNAPSHOT_RANGE));
        let message = response.message.expect("a message");
        assert!(message.contains("`quality`"), "{message}");
        assert!(message.contains("10000"), "{message}");
    }

    #[test]
    fn a_payload_of_the_wrong_shape_is_refused_rather_than_guessed() {
        let (code, response) = call("commit", json!([1, 2, 3]));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_NOT_OBJECT));

        let (code, response) = call("commit", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_COMMIT_PAYLOAD));
        assert!(
            response.message.expect("a message").contains("snapshots"),
            "the refusal must name the missing field"
        );

        // A root that is not 32 bytes of hex is unusable: refused, not guessed.
        let (code, response) = call(
            "verify",
            json!({
                "root": "not-hex",
                "snapshot": snapshot("did:nau:0011223344556677", 1, 8_000),
                "proof": { "index": 0, "leaf_count": 1, "siblings": [] },
            }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_VERIFY_PAYLOAD));
        assert!(
            response.message.expect("a message").contains("hex"),
            "the refusal must say what is wrong with the root"
        );

        // A missing proof is refused too.
        let (code, response) = call(
            "verify",
            json!({
                "root": "00".repeat(32),
                "snapshot": snapshot("did:nau:0011223344556677", 1, 8_000),
            }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_VERIFY_PAYLOAD));

        // A hand-assembled proof of an impossible shape is the crate's refusal to give, as
        // an answer: the op asked whether the leaf is in the set, and it is not.
        let (code, response) = call(
            "verify",
            json!({
                "root": "00".repeat(32),
                "snapshot": snapshot("did:nau:0011223344556677", 1, 8_000),
                "proof": { "index": 5, "leaf_count": 1, "siblings": [] },
            }),
        );
        assert_eq!(code, EXIT_OK);
        let answer = response.payload.expect("a payload");
        assert_eq!(answer["included"], json!(false));
        assert!(!answer["reason"].as_str().expect("a reason").is_empty());
    }

    #[test]
    fn capabilities_reports_both_gated_capabilities_and_no_false_green() {
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

        // Both catalogue capabilities are chain capabilities, and the official tier holds
        // each only with the vendor team's approval -- two rows, derived from the matrix.
        let approvals = answer["required_approvals"].as_array().expect("an array");
        assert_eq!(approvals.len(), 2, "{approvals:?}");
        for (row, capability) in approvals.iter().zip(DECLARED_CAPABILITIES) {
            assert_eq!(row["capability"], json!(capability));
            assert_eq!(row["authority"], json!("vendor-team"));
        }
        assert_eq!(
            answer["non_basic_capability_authorities"],
            json!(["vendor-team"])
        );

        // The honest half, and here it is the important one: an offline bridge exercises
        // neither chain capability, and the answer says so rather than implying on-chain work.
        assert_eq!(
            answer["declared_capabilities_backed_by_ops"],
            json!(false),
            "nothing here touches a chain"
        );
        for capability in DECLARED_CAPABILITIES {
            assert_eq!(answer["capability_backing"][capability], json!([]));
        }
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
        let entry = Official::find(PLUGIN_NAME).expect("the catalogue lists the bridge entry");
        assert_eq!(entry.tier().expect("classifies"), Tier::Official);
        assert_eq!(entry.version, PLUGIN_VERSION);
        assert_eq!(entry.name, PLUGIN_NAME);
        assert_eq!(
            entry.approvals().expect("holdable at its tier").len(),
            2,
            "both chain capabilities need the vendor team"
        );
        assert_eq!(
            Capability::ChainEvmWrite.decision(Tier::Official),
            Grant::RequiresApproval(nau_plugin::capability::Approval::VendorTeam)
        );
        assert!(matches!(
            Capability::ChainEvmWrite.decision(Tier::ThirdParty),
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
            assert!(
                ops.is_empty(),
                "an offline bridge backs no chain capability"
            );
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
        let (code, response) = call("anchor", json!({}));
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(
            response.code.as_deref(),
            Some(payload::CODE_UNKNOWN_OPERATION)
        );
        let message = response.message.expect("a message");
        assert!(
            message.contains("commit") && message.contains("verify"),
            "the known ops must be listed: {message}"
        );
    }

    #[test]
    fn a_diagnostic_built_from_caller_json_stays_bounded() {
        // A long string where an integer is expected: serde quotes it, and the caller chose it.
        let long = "x".repeat(MAX_DIAGNOSTIC_CHARS * 4);
        let (code, response) = call(
            "commit",
            json!({ "snapshots": [ {
                "agent": "did:nau:0011223344556677",
                "epoch": long,
                "reputation": {
                    "quality": 1, "speed": 1, "honesty": 1, "availability": 1,
                    "settled": 0, "faults": 0
                },
            } ] }),
        );
        assert_eq!(code, EXIT_REFUSED);
        assert_eq!(response.code.as_deref(), Some(CODE_COMMIT_PAYLOAD));
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
