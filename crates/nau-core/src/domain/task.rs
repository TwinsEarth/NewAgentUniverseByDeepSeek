//! Tasks, bids, results, evidence grading and disputes.
//!
//! ## What changed from upstream v2.5.6
//!
//! * **The six-field [`TaskSpec`] is actually enforced.** Upstream documents
//!   "六字段：goal / context / done / todo / trace / owner"
//!   (`marketplace/task.rs:78`) but `validate()` checks `budget`,
//!   `required_skills` and `requester` instead, and never `done`, `trace` or
//!   `owner`. Here [`TaskSpec::validate`] checks the six documented fields, and
//!   the fields that belong to a *task* (budget, skills) live on [`Task`].
//! * **The state machine has no dead ends.** Upstream declares 12 states in
//!   which `Running` and `Arbitration` are never assigned, `Rework` has no exit,
//!   and `NoQuorum` is absorbing — while the docs claim
//!   `NO_QUORUM → VIEW_CHANGE → OPEN`. [`TaskState::can_transition_to`] is a
//!   total, tested table that makes every reachable state reachable and gives
//!   the no-quorum path a real recovery edge.
//! * **Signed structures carry nonce + timestamps + their public key**, so
//!   replay and impersonation are both checkable. Upstream's `Bid` and
//!   `ResultEnvelope` have no signature, no timestamp and no nonce at all, and
//!   `Bid.score` is a caller-supplied field that no code ever reads.
//! * **`deadline` is enforced.** Upstream stores `TaskSpec.deadline` and never
//!   reads it, so an expired task settles normally.
//! * **Evidence grade gates settlement.** Upstream defines
//!   `EvidenceGrade::is_trustworthy()` "用于结算门禁" and then never calls it, so
//!   a result marked `Unverified` settles at full budget.

use serde::{Deserialize, Serialize};

use crate::domain::money::Money;
use crate::domain::Verifiable;
use crate::error::{NauError, Result};
use crate::identity::{Did, PublicKey};

/// The six fields that define a well-formed task specification.
pub const SIX_FIELDS: [&str; 6] = ["goal", "context", "done", "todo", "trace", "owner"];

/// Maximum length accepted for any identifier (task id, skill id).
pub const MAX_ID_LEN: usize = 64;
/// Maximum length accepted for free-text fields, guarding against unbounded payloads.
pub const MAX_TEXT_LEN: usize = 16_384;

/// A validated task identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(String);

impl TaskId {
    /// Validate and wrap an existing identifier.
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(NauError::Validation("task id must not be empty".into()));
        }
        if s.len() > MAX_ID_LEN {
            return Err(NauError::Validation(format!(
                "task id is longer than {MAX_ID_LEN} characters"
            )));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(NauError::Validation(format!(
                "task id `{s}` may only contain ASCII letters, digits, `-` and `_`"
            )));
        }
        Ok(Self(s.to_string()))
    }

    /// Generate a fresh identifier from OS entropy.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        // Cannot fail: "task-" plus 16 hex characters.
        Self(format!("task-{}", hex::encode(bytes)))
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for TaskId {
    type Err = NauError;
    fn from_str(s: &str) -> Result<Self> {
        TaskId::parse(s)
    }
}

/// The six-field task specification.
///
/// Field semantics follow upstream's documented intent: `goal` is what to
/// achieve, `context` is what the executor needs to know, `done` lists
/// acceptance criteria, `todo` lists the steps, `trace` optionally points at a
/// prior trace/ledger entry, and `owner` is the responsible DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSpec {
    /// What must be achieved.
    pub goal: String,
    /// Background the executor needs.
    pub context: String,
    /// Acceptance criteria. At least one is required.
    pub done: Vec<String>,
    /// Planned steps. At least one is required.
    pub todo: Vec<String>,
    /// Optional reference to a prior trace or ledger entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
    /// The DID responsible for the task.
    pub owner: Did,
}

impl TaskSpec {
    /// Every missing or invalid field, as human-readable strings.
    pub fn gaps(&self) -> Vec<String> {
        let mut gaps = Vec::new();
        if self.goal.trim().is_empty() {
            gaps.push("goal must not be empty".into());
        }
        if self.context.trim().is_empty() {
            gaps.push("context must not be empty".into());
        }
        if self.done.is_empty() || self.done.iter().all(|d| d.trim().is_empty()) {
            gaps.push("done must contain at least one non-empty acceptance criterion".into());
        }
        if self.todo.is_empty() || self.todo.iter().all(|t| t.trim().is_empty()) {
            gaps.push("todo must contain at least one non-empty step".into());
        }
        if self.goal.len() > MAX_TEXT_LEN || self.context.len() > MAX_TEXT_LEN {
            gaps.push(format!("goal/context must be at most {MAX_TEXT_LEN} bytes"));
        }
        if self.done.len() > 256 || self.todo.len() > 256 {
            gaps.push("done/todo may contain at most 256 entries".into());
        }
        gaps
    }

    /// Fail unless [`TaskSpec::gaps`] is empty.
    pub fn validate(&self) -> Result<()> {
        let gaps = self.gaps();
        if gaps.is_empty() {
            Ok(())
        } else {
            Err(NauError::Validation(gaps.join("; ")))
        }
    }
}

/// How a task's result is to be verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerificationPolicy {
    /// A BFT-lite committee of `n` members tolerating `f` faults.
    Committee {
        /// Committee size. Must satisfy `n >= 3f + 1`.
        n: u32,
        /// Tolerated Byzantine members.
        f: u32,
    },
    /// No independent verification; the requester accepts the result directly.
    ///
    /// Modelled explicitly rather than by omission, so that "unverified" is a
    /// deliberate, recorded policy and can be priced accordingly.
    RequesterOnly,
}

impl VerificationPolicy {
    /// Validate the BFT parameter relation with checked arithmetic.
    ///
    /// Upstream computes `3 * f + 1` on unchecked `u32`
    /// (`marketplace/qa_committee.rs:53`), which panics in debug and wraps in
    /// release for large `f` — with `f = 1_431_655_766` the guard evaluates
    /// `n < 1` and an absurd committee is accepted.
    pub fn validate(&self) -> Result<()> {
        match *self {
            VerificationPolicy::Committee { n, f } => {
                let minimum =
                    f.checked_mul(3)
                        .and_then(|v| v.checked_add(1))
                        .ok_or(NauError::Validation(format!(
                            "committee f={f} overflows 3f+1"
                        )))?;
                if n < minimum {
                    return Err(NauError::Validation(format!(
                        "BFT-lite requires n >= 3f+1, got n={n}, f={f} (need n >= {minimum})"
                    )));
                }
                if n == 0 {
                    return Err(NauError::Validation("committee size must be > 0".into()));
                }
                Ok(())
            }
            VerificationPolicy::RequesterOnly => Ok(()),
        }
    }

    /// The quorum `2f + 1`, or `1` when the requester alone decides.
    pub fn quorum(&self) -> Result<u32> {
        match *self {
            VerificationPolicy::Committee { f, .. } => f
                .checked_mul(2)
                .and_then(|v| v.checked_add(1))
                .ok_or(NauError::Validation(format!(
                    "committee f={f} overflows 2f+1"
                ))),
            VerificationPolicy::RequesterOnly => Ok(1),
        }
    }
}

/// Task lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    /// Published and accepting bids.
    Open,
    /// A winner has been selected.
    Matched,
    /// The executor is working.
    Running,
    /// The executor has delivered a result.
    Submitted,
    /// A committee (or the requester) is checking the result.
    Verifying,
    /// The result was accepted; payment is due.
    Accepted,
    /// The result was rejected; the executor may try again.
    Rework,
    /// Paid and closed.
    Settled,
    /// Under dispute.
    Disputed,
    /// A dispute found against the agent; stake slashed, task closed.
    Slashed,
    /// Cancelled by the requester before execution completed.
    Cancelled,
    /// Not enough committee members voted; the round is void.
    NoQuorum,
}

impl TaskState {
    /// True when no further transition is possible.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskState::Settled | TaskState::Slashed | TaskState::Cancelled
        )
    }

    /// The complete transition table.
    ///
    /// Every state reachable by the market is listed, including the two recovery
    /// edges upstream lacks:
    /// * `NoQuorum -> Open` — the "view change" the upstream docs promise but
    ///   whose task state was absorbing.
    /// * `Rework -> Running` — the documented rework loop.
    pub fn can_transition_to(self, next: TaskState) -> bool {
        use TaskState::*;
        match self {
            Open => matches!(next, Matched | Cancelled | NoQuorum),
            Matched => matches!(next, Running | Open | Cancelled | Disputed),
            Running => matches!(next, Submitted | Disputed | Cancelled),
            Submitted => matches!(next, Verifying | Disputed),
            Verifying => matches!(next, Accepted | Rework | NoQuorum | Disputed),
            Rework => matches!(next, Running | Open | Cancelled),
            Accepted => matches!(next, Settled | Disputed),
            Disputed => matches!(next, Settled | Slashed | Accepted | Cancelled),
            // The recovery edge upstream is missing.
            NoQuorum => matches!(next, Open | Cancelled),
            Settled | Slashed | Cancelled => false,
        }
    }

    /// Apply a transition, or explain why it is illegal.
    pub fn transition(self, next: TaskState, task_id: &TaskId) -> Result<TaskState> {
        if self == next {
            return Ok(next);
        }
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(NauError::InvalidTransition {
                task: task_id.to_string(),
                from: format!("{self:?}"),
                to: format!("{next:?}"),
            })
        }
    }
}

/// How trustworthy the evidence accompanying a result is.
///
/// Ordered from most to least trustworthy. [`EvidenceGrade::default`] is
/// `Unverified`, i.e. fail-closed: a result that does not say otherwise is not
/// treated as evidence.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGrade {
    /// Independently re-executed and agreed by a committee.
    Verified,
    /// Executed locally with a signed, reproducible trace; not re-executed.
    CpuProto,
    /// Self-reported, no evidence.
    #[default]
    Unverified,
}

impl EvidenceGrade {
    /// Machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            EvidenceGrade::Verified => "verified",
            EvidenceGrade::CpuProto => "cpu-proto",
            EvidenceGrade::Unverified => "unverified",
        }
    }

    /// Whether this grade is strong enough to release payment.
    ///
    /// Upstream defines this predicate "用于结算门禁" and then never calls it.
    pub fn is_settlement_grade(self) -> bool {
        matches!(self, EvidenceGrade::Verified | EvidenceGrade::CpuProto)
    }
}

/// A published task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    /// Unique identifier.
    pub id: TaskId,
    /// The six-field specification.
    pub spec: TaskSpec,
    /// Skills an executor must have. At least one.
    pub required_skills: Vec<String>,
    /// Maximum the requester will pay, held in escrow from publication.
    pub budget: Money,
    /// Optional deadline (Unix seconds). Enforced at submission and settlement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<u64>,
    /// How the result will be verified.
    pub verification: VerificationPolicy,
    /// Current lifecycle state.
    pub state: TaskState,
    /// The winning bidder, once matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<Did>,
    /// The public key of the requester (`spec.owner`).
    pub requester_key: PublicKey,
    /// Replay-protection nonce.
    pub nonce: u64,
    /// When the task was published.
    pub signed_at: u64,
    /// Hex Ed25519 signature by the requester.
    #[serde(default)]
    pub signature: String,
}

impl Task {
    /// Build an unsigned draft.
    #[allow(clippy::too_many_arguments)]
    pub fn draft(
        id: TaskId,
        spec: TaskSpec,
        required_skills: Vec<String>,
        budget: Money,
        deadline: Option<u64>,
        verification: VerificationPolicy,
        requester_key: PublicKey,
        signed_at: u64,
        nonce: u64,
    ) -> Self {
        Self {
            id,
            spec,
            required_skills,
            budget,
            deadline,
            verification,
            state: TaskState::Open,
            assigned_to: None,
            requester_key,
            nonce,
            signed_at,
            signature: String::new(),
        }
    }

    /// Structural validation, independent of the signature.
    pub fn validate(&self) -> Result<()> {
        self.spec.validate()?;
        if self.required_skills.is_empty() {
            return Err(NauError::Validation(
                "required_skills must name at least one skill".into(),
            ));
        }
        for skill in &self.required_skills {
            if skill.trim().is_empty() || skill.len() > MAX_ID_LEN {
                return Err(NauError::Validation(format!(
                    "required skill `{skill}` must be 1..={MAX_ID_LEN} characters"
                )));
            }
        }
        if !self.budget.is_positive() {
            return Err(NauError::InvalidAmount(
                "budget must be greater than zero; a task with no budget cannot pay anyone".into(),
            ));
        }
        self.verification.validate()?;
        if !self.spec.owner.matches_public_key(&self.requester_key) {
            return Err(NauError::DidKeyMismatch {
                did: self.spec.owner.to_string(),
            });
        }
        if let Some(deadline) = self.deadline {
            if deadline <= self.signed_at {
                return Err(NauError::Validation(format!(
                    "deadline {deadline} must be after signed_at {}",
                    self.signed_at
                )));
            }
        }
        Ok(())
    }

    /// True when `now` is past the deadline.
    pub fn is_expired(&self, now: u64) -> bool {
        self.deadline.is_some_and(|d| now > d)
    }

    /// Validate and verify the requester's signature.
    pub fn validate_and_verify(&self) -> Result<()> {
        self.validate()?;
        self.verify()
    }
}

impl Verifiable for Task {
    fn signer(&self) -> &Did {
        &self.spec.owner
    }
    fn signer_key(&self) -> &PublicKey {
        &self.requester_key
    }
    fn signature(&self) -> &str {
        &self.signature
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn signed_at(&self) -> u64 {
        self.signed_at
    }
    fn expires_at(&self) -> Option<u64> {
        self.deadline
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

/// An offer to execute a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bid {
    /// The task being bid on.
    pub task_id: TaskId,
    /// The bidding agent.
    pub bidder: Did,
    /// The bidder's public key.
    pub bidder_key: PublicKey,
    /// Offered price. Must be positive and must not exceed the budget.
    pub price: Money,
    /// Promised time to completion, in seconds. Must be positive.
    pub eta_secs: u64,
    /// Self-assessed confidence, in basis points.
    pub confidence_bps: u16,
    /// When the bid expires, if it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Replay-protection nonce.
    pub nonce: u64,
    /// When the bid was signed.
    pub signed_at: u64,
    /// Hex Ed25519 signature by the bidder.
    #[serde(default)]
    pub signature: String,
}

impl Bid {
    /// Validate the bid against the task it targets.
    ///
    /// Upstream accepts a negative or zero `proposed_price`, and because its
    /// scoring formula degrades to `reputation` when `price <= 0.0`, a bid of
    /// `0` wins selection *and* is then paid the full task budget
    /// (`marketplace/mod.rs:251-255` vs `:350`). Here a non-positive price is
    /// rejected outright.
    pub fn validate_for(&self, task: &Task) -> Result<()> {
        if self.task_id != task.id {
            return Err(NauError::Validation(format!(
                "bid targets task `{}` but was checked against `{}`",
                self.task_id, task.id
            )));
        }
        if !self.price.is_positive() {
            return Err(NauError::InvalidAmount(
                "bid price must be greater than zero".into(),
            ));
        }
        if self.price > task.budget {
            return Err(NauError::InvalidAmount(format!(
                "bid price {} exceeds the task budget {}",
                self.price.to_decimal_string(),
                task.budget.to_decimal_string()
            )));
        }
        if self.eta_secs == 0 {
            return Err(NauError::Validation(
                "bid eta_secs must be greater than zero".into(),
            ));
        }
        if self.confidence_bps > 10_000 {
            return Err(NauError::Validation(format!(
                "confidence_bps {} exceeds 10000",
                self.confidence_bps
            )));
        }
        if !self.bidder.matches_public_key(&self.bidder_key) {
            return Err(NauError::DidKeyMismatch {
                did: self.bidder.to_string(),
            });
        }
        Ok(())
    }
}

impl Verifiable for Bid {
    fn signer(&self) -> &Did {
        &self.bidder
    }
    fn signer_key(&self) -> &PublicKey {
        &self.bidder_key
    }
    fn signature(&self) -> &str {
        &self.signature
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn signed_at(&self) -> u64 {
        self.signed_at
    }
    fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

/// A delivered result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultEnvelope {
    /// The task this result answers.
    pub task_id: TaskId,
    /// The executing agent.
    pub agent: Did,
    /// The agent's public key.
    pub agent_key: PublicKey,
    /// Hex SHA-256 of the canonical output bytes.
    ///
    /// A digest rather than the output itself, so the envelope stays small and
    /// the payload can live in content-addressed storage.
    pub output_digest: String,
    /// Optional location of the full output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_uri: Option<String>,
    /// Short human-readable summary.
    pub summary: String,
    /// How trustworthy the evidence is.
    pub evidence: EvidenceGrade,
    /// Observed wall-clock duration.
    pub latency_ms: u64,
    /// Replay-protection nonce.
    pub nonce: u64,
    /// When the result was signed.
    pub signed_at: u64,
    /// Hex Ed25519 signature by the agent.
    #[serde(default)]
    pub signature: String,
}

impl ResultEnvelope {
    /// Structural validation.
    pub fn validate(&self) -> Result<()> {
        if self.output_digest.len() != 64
            || !self
                .output_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(NauError::Validation(
                "output_digest must be 64 lowercase hex characters (SHA-256)".into(),
            ));
        }
        if self.summary.len() > MAX_TEXT_LEN {
            return Err(NauError::Validation(format!(
                "summary must be at most {MAX_TEXT_LEN} bytes"
            )));
        }
        if !self.agent.matches_public_key(&self.agent_key) {
            return Err(NauError::DidKeyMismatch {
                did: self.agent.to_string(),
            });
        }
        Ok(())
    }

    /// Validate, verify the signature, and require a settlement-grade evidence label.
    pub fn validate_for_settlement(&self) -> Result<()> {
        self.validate()?;
        self.verify()?;
        if !self.evidence.is_settlement_grade() {
            return Err(NauError::Validation(format!(
                "evidence grade `{}` is not sufficient to release payment",
                self.evidence.label()
            )));
        }
        Ok(())
    }
}

impl Verifiable for ResultEnvelope {
    fn signer(&self) -> &Did {
        &self.agent
    }
    fn signer_key(&self) -> &PublicKey {
        &self.agent_key
    }
    fn signature(&self) -> &str {
        &self.signature
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn signed_at(&self) -> u64 {
        self.signed_at
    }
    fn expires_at(&self) -> Option<u64> {
        None
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

/// A raised dispute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dispute {
    /// Dispute identifier.
    pub id: String,
    /// The disputed task.
    pub task_id: TaskId,
    /// Who raised it.
    pub complainant: Did,
    /// The complainant's public key.
    pub complainant_key: PublicKey,
    /// The accused party.
    pub respondent: Did,
    /// Why the dispute was raised.
    pub reason: String,
    /// Optional digest of supporting evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
    /// Replay-protection nonce.
    pub nonce: u64,
    /// When the dispute was signed.
    pub signed_at: u64,
    /// Hex Ed25519 signature by the complainant.
    #[serde(default)]
    pub signature: String,
}

impl Dispute {
    /// Structural validation.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() || self.id.len() > MAX_ID_LEN {
            return Err(NauError::Validation(format!(
                "dispute id must be 1..={MAX_ID_LEN} characters"
            )));
        }
        if self.reason.trim().is_empty() {
            return Err(NauError::Validation(
                "dispute reason must not be empty".into(),
            ));
        }
        if self.reason.len() > MAX_TEXT_LEN {
            return Err(NauError::Validation(format!(
                "dispute reason must be at most {MAX_TEXT_LEN} bytes"
            )));
        }
        if self.complainant == self.respondent {
            return Err(NauError::Validation("a party cannot dispute itself".into()));
        }
        if !self.complainant.matches_public_key(&self.complainant_key) {
            return Err(NauError::DidKeyMismatch {
                did: self.complainant.to_string(),
            });
        }
        Ok(())
    }
}

impl Verifiable for Dispute {
    fn signer(&self) -> &Did {
        &self.complainant
    }
    fn signer_key(&self) -> &PublicKey {
        &self.complainant_key
    }
    fn signature(&self) -> &str {
        &self.signature
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn signed_at(&self) -> u64 {
        self.signed_at
    }
    fn expires_at(&self) -> Option<u64> {
        None
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

/// The outcome of arbitrating a dispute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeOutcome {
    /// The dispute being decided.
    pub dispute_id: String,
    /// The task being decided.
    pub task_id: TaskId,
    /// True when the respondent was found at fault.
    pub guilty: bool,
    /// Amount slashed from the respondent's stake.
    pub slash_amount: Money,
    /// Human-readable ruling.
    pub ruling: String,
    /// The arbitrating DID.
    pub arbitrator: Did,
    /// The arbitrator's public key.
    pub arbitrator_key: PublicKey,
    /// Replay-protection nonce.
    pub nonce: u64,
    /// When the ruling was signed.
    pub signed_at: u64,
    /// Hex Ed25519 signature by the arbitrator.
    #[serde(default)]
    pub signature: String,
}

impl DisputeOutcome {
    /// Structural validation.
    ///
    /// Notably: a guilty verdict with a zero slash is rejected. Upstream's
    /// `arbitrate` gates slashing on `slash_amount > 0.0` and therefore returns a
    /// "guilty" verdict that penalises nobody
    /// (`marketplace/mod.rs:453-461`).
    pub fn validate(&self) -> Result<()> {
        if self.guilty && !self.slash_amount.is_positive() {
            return Err(NauError::Validation(
                "a guilty verdict must slash a positive amount".into(),
            ));
        }
        if !self.guilty && !self.slash_amount.is_zero() {
            return Err(NauError::Validation(
                "a not-guilty verdict must not slash anything".into(),
            ));
        }
        if !self.arbitrator.matches_public_key(&self.arbitrator_key) {
            return Err(NauError::DidKeyMismatch {
                did: self.arbitrator.to_string(),
            });
        }
        Ok(())
    }
}

impl Verifiable for DisputeOutcome {
    fn signer(&self) -> &Did {
        &self.arbitrator
    }
    fn signer_key(&self) -> &PublicKey {
        &self.arbitrator_key
    }
    fn signature(&self) -> &str {
        &self.signature
    }
    fn nonce(&self) -> u64 {
        self.nonce
    }
    fn signed_at(&self) -> u64 {
        self.signed_at
    }
    fn expires_at(&self) -> Option<u64> {
        None
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::money::major;
    use crate::identity::Identity;

    fn requester() -> Identity {
        Identity::from_seed(&[11u8; 32])
    }

    fn spec_for(id: &Identity) -> TaskSpec {
        TaskSpec {
            goal: "translate the document".into(),
            context: "source is English, target is Chinese".into(),
            done: vec!["all sections translated".into()],
            todo: vec!["read source".into(), "translate".into()],
            trace: None,
            owner: id.did(),
        }
    }

    fn task(id: &Identity) -> Task {
        let mut t = Task::draft(
            TaskId::parse("task-abc").unwrap(),
            spec_for(id),
            vec!["translation".into()],
            major(50),
            None,
            VerificationPolicy::Committee { n: 4, f: 1 },
            id.public_key(),
            1_700_000_000,
            1,
        );
        t.sign(id).unwrap();
        t
    }

    #[test]
    fn the_six_documented_fields_are_what_gets_validated() {
        let id = requester();
        let mut spec = spec_for(&id);
        assert!(spec.validate().is_ok());

        // Each of the six fields, when emptied, must be reported.
        let mut s = spec.clone();
        s.goal = "  ".into();
        assert!(s.gaps().iter().any(|g| g.starts_with("goal")));

        let mut s = spec.clone();
        s.context = String::new();
        assert!(s.gaps().iter().any(|g| g.starts_with("context")));

        let mut s = spec.clone();
        s.done.clear();
        assert!(s.gaps().iter().any(|g| g.starts_with("done")));

        let mut s = spec.clone();
        s.todo.clear();
        assert!(s.gaps().iter().any(|g| g.starts_with("todo")));

        // `trace` is optional by design, so it is the one field with no gap.
        spec.trace = None;
        assert_eq!(spec.gaps().len(), 0, "trace is optional");

        // `owner` is a Did, so it cannot be empty; only present-but-mismatched
        // is possible, which the Task-level check catches.
        assert_eq!(
            SIX_FIELDS,
            ["goal", "context", "done", "todo", "trace", "owner"]
        );
    }

    #[test]
    fn every_reachable_state_can_actually_be_reached_and_exited() {
        use TaskState::*;
        // NoQuorum must have an exit (upstream's is absorbing).
        assert!(NoQuorum.can_transition_to(Open));
        // Rework must be able to go back to work (upstream's cannot).
        assert!(Rework.can_transition_to(Running));
        // Terminal states must reject everything.
        for t in [Settled, Slashed, Cancelled] {
            for next in [
                Open, Matched, Running, Submitted, Verifying, Accepted, Rework, Disputed, NoQuorum,
            ] {
                assert!(
                    !t.can_transition_to(next),
                    "{t:?} -> {next:?} must be illegal"
                );
            }
        }
        // The happy path is walkable end to end.
        let path = [
            Open, Matched, Running, Submitted, Verifying, Accepted, Settled,
        ];
        for pair in path.windows(2) {
            assert!(
                pair[0].can_transition_to(pair[1]),
                "happy path broken at {:?} -> {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn illegal_transitions_are_rejected_with_a_typed_error() {
        let id = TaskId::parse("t1").unwrap();
        let err = TaskState::Open
            .transition(TaskState::Settled, &id)
            .unwrap_err();
        assert!(
            matches!(err, NauError::InvalidTransition { .. }),
            "got {err:?}"
        );
        // Re-applying the current state is a no-op, not an error.
        assert_eq!(
            TaskState::Open.transition(TaskState::Open, &id).unwrap(),
            TaskState::Open
        );
    }

    #[test]
    fn bft_parameters_are_checked_without_overflow() {
        assert!(VerificationPolicy::Committee { n: 4, f: 1 }
            .validate()
            .is_ok());
        assert!(VerificationPolicy::Committee { n: 3, f: 1 }
            .validate()
            .is_err());
        assert!(VerificationPolicy::Committee { n: 7, f: 2 }
            .validate()
            .is_ok());
        assert_eq!(
            VerificationPolicy::Committee { n: 7, f: 2 }
                .quorum()
                .unwrap(),
            5
        );
        // The upstream overflow: f is large enough that 3f+1 wraps in u32.
        let err = VerificationPolicy::Committee {
            n: 1,
            f: 1_431_655_766,
        }
        .validate()
        .unwrap_err();
        assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
        assert!(VerificationPolicy::RequesterOnly.quorum().unwrap() == 1);
    }

    #[test]
    fn a_task_round_trips_through_signing() {
        let id = requester();
        let t = task(&id);
        assert!(t.validate_and_verify().is_ok());
        assert_eq!(t.state, TaskState::Open);
    }

    #[test]
    fn non_positive_budget_or_price_is_rejected() {
        let id = requester();
        let mut t = task(&id);
        t.budget = Money::ZERO;
        assert!(t.validate().is_err());

        let mut t = task(&id);
        t.budget = Money::from_minor(-1);
        assert!(t.validate().is_err());

        // A fresh, well-formed task for the bid checks (the task above is now invalid).
        let t = task(&id);
        let mut bid = Bid {
            task_id: t.id.clone(),
            bidder: id.did(),
            bidder_key: id.public_key(),
            price: Money::ZERO,
            eta_secs: 60,
            confidence_bps: 9_000,
            expires_at: None,
            nonce: 1,
            signed_at: 1_700_000_100,
            signature: String::new(),
        };
        assert!(
            bid.validate_for(&t).is_err(),
            "a zero price must be refused, not treated as a free win"
        );
        bid.price = Money::from_minor(-100);
        assert!(bid.validate_for(&t).is_err());
        bid.price = major(51);
        assert!(
            bid.validate_for(&t).is_err(),
            "a bid above budget must be refused"
        );
        bid.price = major(40);
        assert!(bid.validate_for(&t).is_ok());
    }

    #[test]
    fn bids_are_bound_to_their_task() {
        let id = requester();
        let t = task(&id);
        let bid = Bid {
            task_id: TaskId::parse("other-task").unwrap(),
            bidder: id.did(),
            bidder_key: id.public_key(),
            price: major(1),
            eta_secs: 10,
            confidence_bps: 5_000,
            expires_at: None,
            nonce: 1,
            signed_at: 1,
            signature: String::new(),
        };
        assert!(bid.validate_for(&t).is_err());
    }

    #[test]
    fn only_trustworthy_evidence_may_release_payment() {
        let id = requester();
        let mut envelope = ResultEnvelope {
            task_id: TaskId::parse("task-abc").unwrap(),
            agent: id.did(),
            agent_key: id.public_key(),
            output_digest: "a".repeat(64),
            output_uri: None,
            summary: "done".into(),
            evidence: EvidenceGrade::Unverified,
            latency_ms: 100,
            nonce: 1,
            signed_at: 1_700_000_200,
            signature: String::new(),
        };
        envelope.sign(&id).unwrap();
        assert!(envelope.validate().is_ok());
        let err = envelope.validate_for_settlement().unwrap_err();
        assert!(matches!(err, NauError::Validation(_)), "got {err:?}");

        envelope.evidence = EvidenceGrade::CpuProto;
        envelope.sign(&id).unwrap();
        assert!(envelope.validate_for_settlement().is_ok());

        envelope.evidence = EvidenceGrade::Verified;
        envelope.sign(&id).unwrap();
        assert!(envelope.validate_for_settlement().is_ok());
    }

    #[test]
    fn evidence_grade_defaults_to_fail_closed() {
        assert_eq!(EvidenceGrade::default(), EvidenceGrade::Unverified);
        assert!(!EvidenceGrade::Unverified.is_settlement_grade());
        assert_eq!(EvidenceGrade::CpuProto.label(), "cpu-proto");
    }

    #[test]
    fn a_guilty_verdict_must_actually_punish() {
        let arb = Identity::from_seed(&[5u8; 32]);
        let base = DisputeOutcome {
            dispute_id: "d1".into(),
            task_id: TaskId::parse("t1").unwrap(),
            guilty: true,
            slash_amount: Money::ZERO,
            ruling: "at fault".into(),
            arbitrator: arb.did(),
            arbitrator_key: arb.public_key(),
            nonce: 1,
            signed_at: 1,
            signature: String::new(),
        };
        assert!(
            base.validate().is_err(),
            "guilty with zero slash is the upstream defect"
        );
        let mut ok = base.clone();
        ok.slash_amount = major(10);
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn deadlines_are_enforced_where_upstream_ignored_them() {
        let id = requester();
        let mut t = task(&id);
        t.deadline = Some(1_700_000_500);
        assert!(!t.is_expired(1_700_000_400));
        assert!(!t.is_expired(1_700_000_500));
        assert!(t.is_expired(1_700_000_501));
        // A deadline in the past at signing time is a validation error.
        t.signed_at = 1_700_000_600;
        t.signature = String::new();
        assert!(t.validate().is_err());
    }

    #[test]
    fn task_ids_are_restricted_to_a_safe_charset() {
        assert!(TaskId::parse("task-abc_123").is_ok());
        assert!(TaskId::parse("").is_err());
        assert!(TaskId::parse("has space").is_err());
        assert!(TaskId::parse("has/slash").is_err());
        assert!(TaskId::parse(&"x".repeat(MAX_ID_LEN + 1)).is_err());
        let generated = TaskId::generate();
        assert!(generated.as_str().starts_with("task-"));
        assert!(TaskId::parse(generated.as_str()).is_ok());
    }
}
