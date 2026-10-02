//! # nau-attest — attestation envelopes and commit-and-challenge receipts
//!
//! This crate exists to **replace an unchecked string with a checked property**,
//! and to be explicit about how small that checked property is.
//!
//! ## The upstream defect this crate answers
//!
//! Upstream `agent-universe` v2.5.6 carries two fields on its task/result path:
//! `tee_quote` and `zk_proof`. Both are opaque strings. They are never parsed,
//! never verified, and nothing consumes them — no code path branches on them, no
//! key is pinned, no digest is compared. They are *trophies*: their presence in a
//! signed JSON document was treated as evidence of hardware attestation and of a
//! zero-knowledge machine-learning proof. A string in a struct is not evidence.
//! Calling that "verified" is worse than having no field at all, because it
//! launders trust: a reviewer sees `tee_quote` and stops looking.
//!
//! This crate does not repeat that. It implements one narrow property properly
//! and refuses to grade anything higher than that property:
//!
//! 1. [`attest`] — the envelope is structurally well-formed for its declared
//!    format, its signature verifies against a key **pinned by the verifier**
//!    (not a key carried in the envelope), it is bound to a **nonce the verifier
//!    chose**, it is **fresh** within `nau_core::MAX_CLOCK_SKEW_SECS`, and its
//!    `report_data` commits to the **exact canonical payload bytes**.
//! 2. [`grade`] — the evidence ladder. [`EvidenceGrade::HardwareAttested`] is
//!    unreachable: no certificate chain is verified here, so the grader provably
//!    never constructs it.
//! 3. [`commit`] — a real Merkle commitment with real inclusion proofs. It
//!    replaces "zkML" with "this output is in this committed set", which is a
//!    true statement, instead of "this computation was proved correct", which
//!    would be a false one.
//!
//! ## Trust boundary, stated once
//!
//! [`attest::VerifiedAttestation`] means exactly: *"signed by a pinned key, over
//! these bytes, for a nonce I chose, recently, with a `report_data` that commits
//! to those same bytes."* It carries **no** claim about hardware, because nothing
//! in this process can check one.
//!
//! ## What this does NOT prove
//!
//! 1. **It does not verify Intel or AMD certificate chains, nor any hardware
//!    root.** No PKI roots are bundled, no signature over a quote is checked
//!    against Intel's root CA or AMD's VCEK/ARK, no CRL or TCB level is
//!    consulted. An envelope declaring [`AttestationFormat::SgxQuoteV3`] or
//!    [`AttestationFormat::SevSnpReport`] is graded
//!    [`UnverifiedReason::ChainNotImplemented`] no matter how well-formed its
//!    bytes are. The bytes are parsed; the chain behind them is not trusted.
//! 2. **It does not prove that a computation was executed correctly.** The
//!    receipt in [`commit`] proves that an output value is a member of a
//!    committed *set*. It says nothing about how that set was produced. The
//!    committed outputs may be garbage and the inclusion proof will still verify —
//!    that limitation has its own test (`inclusion_is_not_correctness`).
//! 3. **It is not zero-knowledge and not succinct.** No proving system is used
//!    (no risc0, no SP1, no halo2, no bellman — none is in this workspace, and
//!    inventing a "zk" label over a hash chain is the upstream defect). An
//!    inclusion proof reveals the leaf value, its index, and the tree height; it
//!    is `O(log n)` hashes to verify, not `O(1)`, and it does not hide anything.
//! 4. **No TEE was contacted and no real hardware quote was ever parsed.** There
//!    is no SGX, TDX or SEV-SNP device in this crate's test environment and none
//!    was used. Every fixture in the test suite is **synthetic**: hand-assembled
//!    bytes with the documented header fields filled in, plus Ed25519 signatures
//!    over them. A synthetic fixture proves the *code path*, never the *format's*
//!    real-world correctness, and the tests say so individually.
//! 5. **`report_data` proves binding, not freshness on the hardware's clock.** A
//!    binding over a payload could have been produced at any time by whoever held
//!    the pinned signing key. Nonce and timestamp only bound it relative to
//!    *this* verifier's request.
//!
//! ## Design rules
//!
//! 1. `#![forbid(unsafe_code)]`.
//! 2. No `unwrap`/`expect`/`panic!` outside `#[cfg(test)]`, and no indexing or
//!    slicing that a caller-supplied length could make panic.
//! 3. Every failure is a distinct typed variant; none is a `bool` a caller can
//!    drop on the floor.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attest;
pub mod commit;
pub mod grade;

pub use attest::{
    attestation_digest, blob_binding_digest, check_freshness, payload_binding, payload_digest,
    report_data_is_empty, AttestationEnvelope, AttestationError, AttestationFormat,
    ChecksPerformed, ParsedQuote, Refusal, SignedAttestation, TrustedRoots, UnverifiedReason,
    Verified, Verifier, BLOB_BINDING_DOMAIN, MAX_PAYLOAD_LEN, NONCE_LEN, REPORT_DATA_BINDING_LEN,
    SEV_SNP_REPORT_LEN, SGX_QUOTE_V3_MIN_LEN, SGX_QUOTE_V3_REPORT_DATA_OFFSET,
    SGX_QUOTE_V3_VERSION, TDX_QUOTE_MIN_LEN, TDX_QUOTE_REPORT_DATA_OFFSET, TDX_QUOTE_VERSION,
};
pub use commit::{
    commit_outputs, committed_output_hash, open_commitment, prove_inclusion, verify_inclusion,
    CommitmentError, ComputationCommitment, MerkleProof, MerkleTree, COMMITMENT_VERSION,
    MAX_TREE_DEPTH,
};
pub use grade::{grade_of, label, EvidenceGrade, MAX_ACHIEVABLE_GRADE};
pub use nau_core::MAX_CLOCK_SKEW_SECS;
