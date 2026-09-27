//! Stage one: reading a source tree into a [`MigrationPlan`].
//!
//! # Layout this tool reads
//!
//! ```text
//! <root>/agents.json          an ARRAY of AgentCard objects (optional)
//! <root>/agents/*.json        one AgentCard object per file (optional)
//! <root>/tasks.json           an ARRAY of TaskRecord objects (optional)
//! <root>/tasks/*.json         one TaskRecord object per file (optional)
//! <root>/ledger.jsonl         one settlement/transfer entry per line
//! <root>/keys.json            {"<did>": "<public key hex>"}   (optional)
//! <root>/balances.json        {"<account>": <decimal balance>} (optional)
//! ```
//!
//! The layout is **this tool's reading convention over upstream-shaped objects**;
//! it is not a claim about upstream's own directory layout. Every field is looked
//! up by more than one name where the audit records more than one spelling (see
//! the alias lists in each converter below).
//!
//! # Two stages, and why
//!
//! [`plan_from_dir`] reads, verifies and converts; it never writes anything.
//! [`crate::apply()`] writes and never reads the source tree. That split is what
//! makes `--dry-run` a real run: the CLI's dry run is `apply` against an in-memory
//! store, i.e. the same code path that writes to disk, minus the disk.
//!
//! # Nothing is coerced silently
//!
//! A record that cannot be migrated honestly becomes a [`Warning`] with
//! `Severity::Rejection` — naming the file, the field and the value — and the rest
//! of the tree is still migrated. Every record that *is* migrated carries an
//! explicit note about what had to be decided (see [`Finding`]).

use std::collections::BTreeMap;
use std::path::Path;

use nau_core::{
    AgentCard, AgentCategory, Money, Pricing, PricingModel, PricingUnit, PublicKey, Skill, Sla,
    Task, TaskId, TaskSpec, TaskState, VerificationPolicy,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::amount::amount_from_decimal;
use crate::error::{MigrateError, Result};
use crate::field;
use crate::ledger::{self, AccountBalance, LedgerKind, PlannedEntry};
use crate::legacy::{self, KeyRegistry, RecordSource};
use crate::rawjson::{self, RawScalar};
use crate::warning::{Defect, Finding, Severity, Warning};

/// Aggregate file read in addition to `agents/`.
pub const AGENTS_AGGREGATE: &str = "agents.json";
/// Directory of one-card-per-file artifacts.
pub const AGENTS_SUBDIR: &str = "agents";
/// Aggregate file read in addition to `tasks/`.
pub const TASKS_AGGREGATE: &str = "tasks.json";
/// Directory of one-task-per-file artifacts.
pub const TASKS_SUBDIR: &str = "tasks";
/// The ledger journal.
pub const LEDGER_FILE: &str = "ledger.jsonl";
/// Optional `DID → public key` registry, modelling upstream's out-of-band keys.
pub const KEYS_FILE: &str = "keys.json";
/// Optional `account → claimed balance` snapshot.
pub const BALANCES_FILE: &str = "balances.json";

/// Metadata key under which [`crate::apply()`] records the plan digest.
pub const SOURCE_DIGEST_KEY: &str = "nau-migrate.source-digest";
/// Metadata key recording the schema of the migrated records.
pub const SCHEMA_KEY: &str = "nau-migrate.schema";
/// Value written to [`SCHEMA_KEY`].
pub const SCHEMA_VALUE: &str = "nau-migrate/1";

/// An agent card that passed conversion, with the evidence for it.
#[derive(Debug, Clone, Serialize)]
pub struct PlannedAgent {
    /// Source file (and `#<index>`).
    pub source_file: String,
    /// The DID exactly as upstream wrote it (a `did:aip:` prefix is kept).
    pub legacy_did: String,
    /// True when the DID carries upstream's legacy prefix.
    pub legacy_prefix: bool,
    /// The verified legacy signature, kept as provenance.
    pub legacy_signature: String,
    /// The exact canonical payload the legacy signature covers. [`crate::apply()`]
    /// re-verifies the signature over these bytes before writing.
    pub legacy_canonical_payload: String,
    /// The converted card, which is stored **unsigned** (see
    /// [`Finding::TargetNotWireValid`]).
    pub card: AgentCard,
}

/// A task record that passed conversion, with the evidence for it.
#[derive(Debug, Clone, Serialize)]
pub struct PlannedTask {
    /// Source file (and `#<index>`).
    pub source_file: String,
    /// The DID of the requester, exactly as upstream wrote it.
    pub legacy_did: String,
    /// True when the DID carries upstream's legacy prefix.
    pub legacy_prefix: bool,
    /// The verified legacy signature, kept as provenance.
    pub legacy_signature: String,
    /// The exact canonical payload the legacy signature covers.
    pub legacy_canonical_payload: String,
    /// The upstream status string, verbatim.
    pub upstream_status: String,
    /// The converted task, stored unsigned.
    pub task: Task,
}

/// Everything a migration would import, plus everything it would not.
///
/// The four fields are the whole plan: `cards`, `tasks` and `ledger` hold only
/// records that were verified and converted, and `warnings` holds every finding —
/// notes, warnings and rejections — in the order they were made. Use
/// [`MigrationPlan::rejections`] to separate the refusals from the notes.
#[derive(Debug, Clone, Serialize)]
pub struct MigrationPlan {
    /// Agent cards to import, ordered by DID.
    pub cards: Vec<PlannedAgent>,
    /// Tasks to import, ordered by task id.
    pub tasks: Vec<PlannedTask>,
    /// Ledger entries to append, in source order (a journal's order is semantic).
    pub ledger: Vec<PlannedEntry>,
    /// Every finding, in the order it was produced.
    pub warnings: Vec<Warning>,
}

/// Counts and money totals derivable from a plan alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanSummary {
    /// Cards that would be imported.
    pub cards: usize,
    /// Tasks that would be imported.
    pub tasks: usize,
    /// Ledger entries that would be appended.
    pub ledger_entries: usize,
    /// Records that were refused.
    pub rejections: usize,
    /// Findings that are neither notes nor rejections.
    pub warnings: usize,
    /// Findings that merely record a difference.
    pub notes: usize,
    /// Sum of the amounts regardless of direction — compare this against the
    /// source to see that nothing was dropped or rounded.
    pub moved: Money,
    /// Sum of the signed movements; exactly zero for a closed journal.
    pub net: Money,
    /// Number of accounts the journal touches.
    pub accounts: usize,
}

impl MigrationPlan {
    /// The findings that refused a record.
    pub fn rejections(&self) -> impl Iterator<Item = &Warning> {
        self.warnings
            .iter()
            .filter(|warning| warning.is_rejection())
    }

    /// The findings that record a difference without refusing anything.
    pub fn notes_and_warnings(&self) -> impl Iterator<Item = &Warning> {
        self.warnings
            .iter()
            .filter(|warning| !warning.is_rejection())
    }

    /// Counts and totals.
    ///
    /// # Errors
    ///
    /// [`MigrateError::TotalOverflow`] if a total leaves the `i64` minor-unit range.
    pub fn summary(&self) -> Result<PlanSummary> {
        let (moved, net) = ledger::totals(&self.ledger)?;
        let accounts = ledger::derive_balances(&self.ledger)?.len();
        let mut summary = PlanSummary {
            cards: self.cards.len(),
            tasks: self.tasks.len(),
            ledger_entries: self.ledger.len(),
            rejections: 0,
            warnings: 0,
            notes: 0,
            moved,
            net,
            accounts,
        };
        for warning in &self.warnings {
            match warning.severity {
                Severity::Rejection => summary.rejections += 1,
                Severity::Warning => summary.warnings += 1,
                Severity::Info => summary.notes += 1,
            }
        }
        Ok(summary)
    }

    /// The plan as canonical JSON.
    ///
    /// This doubles as a check on the plan itself: the canonical form refuses
    /// floats, so a plan that canonicalizes is a plan in which no amount ever
    /// reached a floating-point value.
    ///
    /// # Errors
    ///
    /// [`MigrateError::PlanDigest`] if the plan cannot be serialized or
    /// canonicalized.
    pub fn canonical_json(&self) -> Result<String> {
        let value =
            serde_json::to_value(self).map_err(|e| MigrateError::PlanDigest(e.to_string()))?;
        nau_core::canonical::canonical_object(&value)
            .map_err(|e| MigrateError::PlanDigest(e.to_string()))
    }

    /// SHA-256 of [`MigrationPlan::canonical_json`], hex.
    ///
    /// Recorded in the store by [`crate::apply()`] and used to refuse a second
    /// application of the same plan (the journal is append-only, so a second run
    /// would duplicate every entry).
    ///
    /// # Errors
    ///
    /// [`MigrateError::PlanDigest`].
    pub fn digest(&self) -> Result<String> {
        let json = self.canonical_json()?;
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }
}

/// Read, verify and convert everything under `root`.
///
/// # Errors
///
/// [`MigrateError::NotADirectory`] when `root` is not a directory, and
/// [`MigrateError::Io`] when a directory cannot be listed. Problems with
/// individual files are reported as findings, not as errors.
pub fn plan_from_dir(root: &Path) -> Result<MigrationPlan> {
    if !root.is_dir() {
        return Err(MigrateError::NotADirectory {
            path: root.display().to_string(),
        });
    }
    let mut warnings = Vec::new();
    note_database_files(root, &mut warnings);
    let registry = read_key_registry(root, &mut warnings)?;

    // ---- agent cards -------------------------------------------------------
    let mut cards: BTreeMap<String, PlannedAgent> = BTreeMap::new();
    for source in legacy::read_record_sources(root, AGENTS_AGGREGATE, AGENTS_SUBDIR, &mut warnings)?
    {
        match plan_card(&source, &registry, &mut warnings) {
            Ok(planned) => {
                let key = planned.card.owner.to_string();
                if let Some(earlier) = cards.insert(key.clone(), planned) {
                    // upstream v2.5.6 fix: upstream's repeat registration silently
                    // replaced the map entry *and* deposited the stake a second
                    // time, while appending a duplicate id to its skill index
                    // (GAP §2.6). Here the later record wins and the earlier one is
                    // named in the report.
                    warnings.push(Warning::warn(
                        Finding::DuplicateSourceRecord,
                        Some(source.label.clone()),
                        format!(
                            "two records claim `{key}`: `{}` wins and `{}` is discarded. Upstream \
                             silently overwrote the map entry *and* deposited the stake a second \
                             time (GAP §2.6), so the earlier record is reported rather than merged",
                            source.label, earlier.source_file
                        ),
                    ));
                }
            }
            Err(defect) => warnings.push(defect.into()),
        }
    }

    // ---- tasks -------------------------------------------------------------
    let mut tasks: BTreeMap<String, PlannedTask> = BTreeMap::new();
    for source in legacy::read_record_sources(root, TASKS_AGGREGATE, TASKS_SUBDIR, &mut warnings)? {
        match plan_task(&source, &registry, &mut warnings) {
            Ok(planned) => {
                let key = planned.task.id.to_string();
                if let Some(earlier) = tasks.insert(key.clone(), planned) {
                    warnings.push(Warning::warn(
                        Finding::DuplicateSourceRecord,
                        Some(source.label.clone()),
                        format!(
                            "two records claim task `{key}`: `{}` wins and `{}` is discarded",
                            source.label, earlier.source_file
                        ),
                    ));
                }
            }
            Err(defect) => warnings.push(defect.into()),
        }
    }

    // ---- ledger ------------------------------------------------------------
    let entries = read_ledger(root, &mut warnings)?;

    // ---- claimed balances versus the re-derived journal --------------------
    let claims = read_balance_claims(root, &mut warnings)?;
    report_discrepancies(&entries, &claims, &mut warnings)?;

    if cards.is_empty() && tasks.is_empty() && entries.is_empty() {
        warnings.push(Warning::info(
            Finding::NoSourceArtifacts,
            None,
            format!(
                "nothing was found under `{}`: expected `{AGENTS_AGGREGATE}` or `{AGENTS_SUBDIR}/`, \
                 `{TASKS_AGGREGATE}` or `{TASKS_SUBDIR}/`, and `{LEDGER_FILE}` (see the crate \
                 documentation for the layout this tool reads)",
                root.display()
            ),
        ));
    }

    Ok(MigrationPlan {
        cards: cards.into_values().collect(),
        tasks: tasks.into_values().collect(),
        ledger: entries,
        warnings,
    })
}

/// The documented status table: upstream spelling → this project's state.
///
/// Returns `None` when the status has no counterpart, which is a **rejection**
/// naming the status, never a guess. The audit records two upstream-only states
/// (`docs/GAP-ANALYSIS.md` §3.4): `Arbitration`, which upstream never assigned, and
/// the `ViewChange` its documentation promised but its code did not have.
///
/// Accepted spellings are matched after lowercasing and normalising spaces and
/// hyphens to `_`.
pub fn map_status(status: &str) -> Option<TaskState> {
    Some(match normalise_status(status).as_str() {
        "open" | "created" | "published" | "pending" => TaskState::Open,
        "matched" | "assigned" | "selected" => TaskState::Matched,
        "running" | "in_progress" | "executing" => TaskState::Running,
        "submitted" | "delivered" => TaskState::Submitted,
        "verifying" | "review" => TaskState::Verifying,
        "accepted" | "approved" | "completed" | "complete" | "verified" => TaskState::Accepted,
        "rework" | "rejected" => TaskState::Rework,
        "settled" | "paid" | "closed" => TaskState::Settled,
        "disputed" | "dispute" => TaskState::Disputed,
        "slashed" => TaskState::Slashed,
        "cancelled" | "canceled" => TaskState::Cancelled,
        "no_quorum" | "noquorum" => TaskState::NoQuorum,
        _ => return None,
    })
}

/// The canonical spelling of a state, for reporting a remapping.
pub const fn state_name(state: TaskState) -> &'static str {
    match state {
        TaskState::Open => "open",
        TaskState::Matched => "matched",
        TaskState::Running => "running",
        TaskState::Submitted => "submitted",
        TaskState::Verifying => "verifying",
        TaskState::Accepted => "accepted",
        TaskState::Rework => "rework",
        TaskState::Settled => "settled",
        TaskState::Disputed => "disputed",
        TaskState::Slashed => "slashed",
        TaskState::Cancelled => "cancelled",
        TaskState::NoQuorum => "no_quorum",
    }
}

fn normalise_status(status: &str) -> String {
    status.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

/// Convert one agent-card record.
fn plan_card(
    source: &RecordSource,
    registry: &KeyRegistry,
    findings: &mut Vec<Warning>,
) -> std::result::Result<PlannedAgent, Defect> {
    let label = source.label.as_str();
    let value = &source.value;

    let did_text = field::required_str(label, value, &["did", "agent_id"])?;
    let did = field::parse_did(label, "did", &did_text)?;
    let legacy_prefix = did.prefix() == nau_core::DID_PREFIX_LEGACY;
    if legacy_prefix {
        findings.push(Warning::info(
            Finding::LegacyDidPrefix,
            Some(label.to_string()),
            format!(
                "`{did_text}` carries upstream's `did:aip:` prefix and is kept verbatim; this \
                 project mints `did:nau:` but parses both, so the identity and its signatures \
                 remain verifiable (ATTRIBUTION §3)"
            ),
        ));
    }

    let public_key = resolve_key(label, value, &did, registry, findings)?;
    let verified = legacy::verify_legacy_record(label, value, did.clone(), public_key)?;

    let name = field::required_str(label, value, &["name"])?;
    let skills = skills_field(label, value, findings)?;
    let endpoints = endpoints_field(label, value)?;
    let description = field::optional_str(label, value, &["description", "summary", "about"])?;
    let price = field::money_field(
        label,
        &source.text,
        value,
        &["price_per_task", "price", "unit_price"],
    )?;
    let stake = match field::money_field(label, &source.text, value, &["stake", "bond"])? {
        Some(stake) => stake,
        None => return Err(Defect::new(
            Finding::MissingField,
            label,
            "required field `stake` is missing: this project's AgentCard must carry a positive \
                 stake (upstream tolerated 0 and even `NaN`, GAP §2.6), so a card without one \
                 cannot be admitted",
        )),
    };
    if !stake.is_positive() {
        // upstream v2.5.6 fix: upstream admitted `stake = 0`, a negative stake and
        // even `NaN` (because `NaN < min_stake` is `false`) and silently overwrote a
        // repeat registration while depositing the stake again (GAP §2.6).
        return Err(Defect::new(
            Finding::NonPositiveAmount,
            label,
            format!(
                "field `stake` = {} is not positive; upstream accepted a zero or negative stake and \
                 even `NaN` (because `NaN < min_stake` is false, GAP §2.6), this project does not",
                stake.to_decimal_string()
            ),
        ));
    }
    let signed_at_field = field::optional_u64(label, value, &["signed_at", "created_at"])?;
    let nonce_field = field::optional_u64(label, value, &["nonce"])?;
    let signed_at = signed_at_field.unwrap_or(0);
    let nonce = nonce_field.unwrap_or(0);
    let expires_at = field::optional_u64(label, value, &["expires_at"])?;

    let mut defaults = vec![
        "category (General: upstream cards carry no category)".to_string(),
        "pricing.model (Fixed) and pricing.unit (Task)".to_string(),
        "sla (this project's documented defaults)".to_string(),
        format!(
            "pricing.unit_price ({})",
            price.unwrap_or(Money::ZERO).to_decimal_string()
        ),
    ];
    if signed_at_field.is_none() {
        defaults.push("signed_at (0: upstream records carry no signing time)".to_string());
    }
    if nonce_field.is_none() {
        defaults.push("nonce (0: upstream records carry no replay nonce)".to_string());
    }
    if expires_at.is_none() {
        defaults.push("expires_at (none)".to_string());
    }
    findings.push(Warning::info(
        Finding::DefaultsFilled,
        Some(label.to_string()),
        format!("defaults applied: {}", defaults.join("; ")),
    ));
    findings.push(Warning::info(
        Finding::TargetNotWireValid,
        Some(label.to_string()),
        "the imported card is stored UNSIGNED: its verified legacy signature covers upstream's \
         canonical payload, which is not the payload of this converted card, and a migration has no \
         private key to re-sign with. The legacy signature and the exact bytes it verified are \
         preserved in the plan; the owner must re-sign before the card is served on the wire."
            .to_string(),
    ));

    let card = AgentCard {
        owner: did.clone(),
        owner_key: public_key,
        name,
        description,
        category: AgentCategory::General,
        skills,
        pricing: Pricing {
            model: PricingModel::Fixed,
            unit_price: price.unwrap_or(Money::ZERO),
            unit: PricingUnit::Task,
        },
        sla: Sla::default(),
        stake,
        endpoints,
        signed_at,
        expires_at,
        nonce,
        signature: String::new(),
    };
    card.validate().map_err(|error| {
        Defect::new(
            Finding::TargetValidationFailed,
            label,
            format!("the converted card failed this project's validation: {error}"),
        )
    })?;

    Ok(PlannedAgent {
        source_file: label.to_string(),
        legacy_did: did_text,
        legacy_prefix,
        legacy_signature: verified.signature,
        legacy_canonical_payload: verified.canonical_payload,
        card,
    })
}

/// Convert one task record.
fn plan_task(
    source: &RecordSource,
    registry: &KeyRegistry,
    findings: &mut Vec<Warning>,
) -> std::result::Result<PlannedTask, Defect> {
    let label = source.label.as_str();
    let value = &source.value;

    let id_text = field::required_str(label, value, &["task_id", "id", "task"])?;
    let id = TaskId::parse(&id_text).map_err(|error| {
        Defect::new(
            Finding::InvalidTaskId,
            label,
            format!(
                "field `task_id` = `{id_text}` is outside this project's safe identifier charset: \
                 {error}"
            ),
        )
    })?;

    let requester = field::required_did(
        label,
        value,
        &["requester", "requester_did", "publisher", "owner"],
    )?;
    if let (Some(declared), Some(owner)) = (
        field::optional_did(label, value, &["requester"])?,
        field::optional_did(label, value, &["owner"])?,
    ) {
        if declared != owner {
            return Err(Defect::new(
                Finding::ConflictingFields,
                label,
                format!(
                    "field `requester` = `{declared}` and field `owner` = `{owner}` disagree; \
                     refusing to choose between them"
                ),
            ));
        }
    }

    let status_text = field::required_str(label, value, &["status", "state"])?;
    // upstream v2.5.6 fix: an upstream status this project's state machine has no
    // counterpart for is *named and refused*, never mapped onto a plausible state.
    // The audit records `Arbitration` as never assigned and the documented
    // `ViewChange` as absent from the code altogether (GAP §3.4).
    let state = map_status(&status_text).ok_or_else(|| {
        Defect::new(
            Finding::UnsupportedStatus,
            label,
            format!(
                "upstream status `{status_text}` has no counterpart in this project's state machine \
                 ({}). The status is named here rather than mapped onto a guess; the audit records \
                 `Arbitration` as never assigned and `ViewChange` as documented but absent \
                 (GAP §3.4)",
                status_table()
            ),
        )
    })?;
    if state_name(state) != normalise_status(&status_text) {
        findings.push(Warning::info(
            Finding::StatusRemapped,
            Some(label.to_string()),
            format!(
                "upstream status `{status_text}` was mapped to `{}`",
                state_name(state)
            ),
        ));
    }

    let legacy_prefix = requester.prefix() == nau_core::DID_PREFIX_LEGACY;
    if legacy_prefix {
        findings.push(Warning::info(
            Finding::LegacyDidPrefix,
            Some(label.to_string()),
            format!(
                "requester `{requester}` carries upstream's `did:aip:` prefix and is kept verbatim"
            ),
        ));
    }

    let goal = field::required_str(label, value, &["goal", "objective"])?;
    let context = field::required_str(label, value, &["context", "background"])?;
    let done = required_text_list(label, value, &["done", "acceptance", "acceptance_criteria"])?;
    let todo = required_text_list(label, value, &["todo", "steps", "plan"])?;
    let trace = field::optional_str(label, value, &["trace", "trace_id"])?;
    let required_skills = required_text_list(
        label,
        value,
        &["required_skills", "skills", "required_capabilities"],
    )?;

    let reward = field::money_field(label, &source.text, value, &["reward"])?;
    let budget_field = field::money_field(label, &source.text, value, &["budget"])?;
    if let (Some(reward), Some(budget)) = (reward, budget_field) {
        if reward != budget {
            return Err(Defect::new(
                Finding::ConflictingFields,
                label,
                format!(
                    "field `reward` = {} and field `budget` = {} disagree; refusing to choose \
                     between them",
                    reward.to_decimal_string(),
                    budget.to_decimal_string()
                ),
            ));
        }
    }
    let budget =
        match reward.or(budget_field) {
            Some(budget) => budget,
            None => return Err(Defect::new(
                Finding::MissingField,
                label,
                "required field `reward` is missing: this project's Task must carry a positive \
                 budget (it is escrowed on publication), so a task without one cannot be imported",
            )),
        };
    if !budget.is_positive() {
        return Err(Defect::new(
            Finding::NonPositiveAmount,
            label,
            format!(
                "field `reward` = {} is not positive; upstream neither escrowed on publication nor \
                 checked the requester's balance (GAP §2.3), this project escrows and refuses",
                budget.to_decimal_string()
            ),
        ));
    }

    let executor = field::optional_did(
        label,
        value,
        &["executor", "assigned_to", "assignee", "winner"],
    )?;
    let deadline = field::optional_u64(label, value, &["deadline", "expires_at"])?;
    let signed_at_field = field::optional_u64(label, value, &["signed_at", "created_at"])?;
    let nonce_field = field::optional_u64(label, value, &["nonce"])?;
    let signed_at = signed_at_field.unwrap_or(0);
    let nonce = nonce_field.unwrap_or(0);

    if let Some((name, found)) = field::find_present(
        value,
        &["committee", "committee_size", "approvals", "verification"],
    ) {
        // upstream v2.5.6 fix: upstream's acceptance committee was synthesised by
        // the caller from request fields, its `n` was decorative, and it never
        // checked that a verified result was settlement-grade (GAP §3.1/§3.2).
        // Reconstructing a committee from such a record would be a fabrication, so
        // the field is reported and discarded.
        findings.push(Warning::warn(
            Finding::FieldNotMapped,
            Some(label.to_string()),
            format!(
                "field `{name}` = {found} was discarded: upstream's acceptance committee was \
                 synthesised by the caller and its `n` was decorative (`api/market_actor.rs:360-386`, \
                 GAP §3.1/§3.2), so this task is migrated as `RequesterOnly` and the upstream value \
                 is reported rather than believed"
            ),
        ));
    }

    let public_key = resolve_key(label, value, &requester, registry, findings)?;
    let verified = legacy::verify_legacy_record(label, value, requester.clone(), public_key)?;

    let mut defaults = vec!["verification (RequesterOnly)".to_string()];
    if signed_at_field.is_none() {
        defaults.push("signed_at (0: upstream records carry no signing time)".to_string());
    }
    if nonce_field.is_none() {
        defaults.push("nonce (0: upstream records carry no replay nonce)".to_string());
    }
    findings.push(Warning::info(
        Finding::DefaultsFilled,
        Some(label.to_string()),
        format!("defaults applied: {}", defaults.join("; ")),
    ));
    findings.push(Warning::info(
        Finding::TargetNotWireValid,
        Some(label.to_string()),
        "the imported task is stored UNSIGNED for the same reason as the cards: the legacy signature \
         covers upstream's canonical payload, and no private key is available to re-sign. The \
         verified legacy signature is preserved in the plan."
            .to_string(),
    ));

    let spec = TaskSpec {
        goal,
        context,
        done,
        todo,
        trace,
        owner: requester,
    };
    let mut task = Task::draft(
        id,
        spec,
        required_skills,
        budget,
        deadline,
        VerificationPolicy::RequesterOnly,
        public_key,
        signed_at,
        nonce,
    );
    task.state = state;
    task.assigned_to = executor;
    task.signature = String::new();
    task.validate().map_err(|error| {
        Defect::new(
            Finding::TargetValidationFailed,
            label,
            format!("the converted task failed this project's validation: {error}"),
        )
    })?;

    Ok(PlannedTask {
        source_file: label.to_string(),
        legacy_did: verified.did.to_string(),
        legacy_prefix,
        legacy_signature: verified.signature,
        legacy_canonical_payload: verified.canonical_payload,
        upstream_status: status_text,
        task,
    })
}

/// The statuses this tool accepts, for the rejection message.
fn status_table() -> String {
    [
        "open",
        "matched",
        "running",
        "submitted",
        "verifying",
        "accepted",
        "rework",
        "settled",
        "disputed",
        "slashed",
        "cancelled",
        "no_quorum",
    ]
    .join(", ")
}

/// Resolve the public key: inline in the record, or from `keys.json`.
fn resolve_key(
    source: &str,
    value: &Value,
    did: &nau_core::Did,
    registry: &KeyRegistry,
    findings: &mut Vec<Warning>,
) -> std::result::Result<PublicKey, Defect> {
    let names = ["public_key", "owner_key", "requester_key", "pubkey"];
    if let Some((name, found)) = field::find_present(value, &names) {
        let text = found.as_str().ok_or_else(|| {
            Defect::new(
                Finding::InvalidFieldType,
                source,
                format!(
                    "field `{name}` must be a hex string, found {}",
                    field::kind_of(found)
                ),
            )
        })?;
        return PublicKey::from_hex(text).map_err(|error| {
            Defect::new(
                Finding::InvalidFieldValue,
                source,
                format!("field `{name}` = `{text}` is not a public key: {error}"),
            )
        });
    }
    match registry.get(did.as_str()) {
        Some(key) => {
            findings.push(Warning::info(
                Finding::KeyFromRegistry,
                Some(source.to_string()),
                format!("the public key for `{did}` came from `{KEYS_FILE}`, not from the record"),
            ));
            Ok(key)
        }
        None => Err(Defect::new(
            Finding::MissingPublicKey,
            source,
            format!(
                "no public key for `{did}`: a DID is only the fingerprint `sha256(pubkey)[..8]`, so \
                 it cannot verify a signature by itself. Put the key in the record as `public_key`, \
                 or list it in `{KEYS_FILE}` as {{\"{did}\": \"<64 hex characters>\"}} — upstream \
                 transported the key out of band, and so must a migration"
            ),
        )),
    }
}

/// Read a capability list that may hold strings or `{id, version, description}`.
fn skills_field(
    source: &str,
    value: &Value,
    findings: &mut Vec<Warning>,
) -> std::result::Result<Vec<Skill>, Defect> {
    let names = ["capabilities", "skills", "capability"];
    let Some((name, found)) = field::find_present(value, &names) else {
        return Err(Defect::new(
            Finding::MissingField,
            source,
            "required field `capabilities` is missing: this project's AgentCard must declare at \
             least one skill to be discoverable",
        ));
    };
    let items = found.as_array().ok_or_else(|| {
        Defect::new(
            Finding::InvalidFieldType,
            source,
            format!(
                "field `{name}` must be an array of capability ids, found {}",
                field::kind_of(found)
            ),
        )
    })?;
    if items.is_empty() {
        return Err(Defect::new(
            Finding::InvalidFieldValue,
            source,
            format!("field `{name}` is empty; an agent that offers nothing cannot be matched"),
        ));
    }

    let mut skills = Vec::with_capacity(items.len());
    let mut lowercased = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let (id, version, description) = match item {
            Value::String(id) => (id.clone(), 1u32, None),
            Value::Object(_) => {
                let id = item
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        Defect::new(
                            Finding::InvalidFieldType,
                            source,
                            format!(
                                "field `{name}[{index}]` must be a string or an object with a string \
                                 `id`, found {}",
                                field::kind_of(item)
                            ),
                        )
                    })?
                    .to_string();
                let version = match item.get("version") {
                    None => 1u32,
                    Some(version_value) => {
                        let raw = version_value.as_u64().ok_or_else(|| {
                            Defect::new(
                                Finding::InvalidFieldType,
                                source,
                                format!(
                                    "field `{name}[{index}].version` must be a non-negative \
                                     integer, found {}",
                                    field::kind_of(version_value)
                                ),
                            )
                        })?;
                        u32::try_from(raw).map_err(|_| {
                            Defect::new(
                                Finding::InvalidFieldValue,
                                source,
                                format!(
                                    "field `{name}[{index}].version` = {raw} does not fit in u32"
                                ),
                            )
                        })?
                    }
                };
                let description = item
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                (id, version, description)
            }
            other => {
                return Err(Defect::new(
                    Finding::InvalidFieldType,
                    source,
                    format!(
                        "field `{name}[{index}]` must be a string or an object, found {}",
                        field::kind_of(other)
                    ),
                ))
            }
        };
        if id != id.to_ascii_lowercase() {
            lowercased.push(id.clone());
        }
        let mut skill = Skill::new(id, version);
        if let Some(description) = description {
            skill = skill.with_description(description);
        }
        skills.push(skill);
    }

    if !lowercased.is_empty() {
        findings.push(Warning::warn(
            Finding::CapabilityNormalised,
            Some(source.to_string()),
            format!(
                "capability ids {lowercased:?} were lowercased to satisfy this project's skill index \
                 (lookups lowercase the query, so a mixed-case id could never be found); the original \
                 spellings are recorded here and nowhere else"
            ),
        ));
    }
    Ok(skills)
}

/// Read `endpoint` / `endpoints` as a string or an array of strings.
fn endpoints_field(source: &str, value: &Value) -> std::result::Result<Vec<String>, Defect> {
    let names = ["endpoint", "endpoints", "url", "endpoint_url"];
    match field::find_present(value, &names) {
        None => Ok(Vec::new()),
        Some((name, found)) => match found {
            Value::String(text) => Ok(vec![text.clone()]),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    match item.as_str() {
                        Some(text) => out.push(text.to_string()),
                        None => {
                            return Err(Defect::new(
                                Finding::InvalidFieldType,
                                source,
                                format!(
                                    "field `{name}[{index}]` must be a string, found {}",
                                    field::kind_of(item)
                                ),
                            ))
                        }
                    }
                }
                Ok(out)
            }
            other => Err(Defect::new(
                Finding::InvalidFieldType,
                source,
                format!(
                    "field `{name}` must be a string or an array of strings, found {}",
                    field::kind_of(other)
                ),
            )),
        },
    }
}

/// A required array of strings that must not be empty.
fn required_text_list(
    source: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<Vec<String>, Defect> {
    match field::string_list(source, value, names)? {
        Some(items) if !items.is_empty() => Ok(items),
        Some(_) => Err(Defect::new(
            Finding::InvalidFieldValue,
            source,
            format!(
                "field `{}` is present but empty; this project enforces the six-field task \
                 specification that upstream only documented (`marketplace/task.rs:78`, GAP §1)",
                names[0]
            ),
        )),
        None => Err(Defect::new(
            Finding::MissingField,
            source,
            format!(
                "required field `{}` is missing: this project enforces the six documented TaskSpec \
                 fields (goal/context/done/todo/trace/owner), where upstream's `validate()` checked \
                 budget and skills instead and never looked at `done`, `trace` or `owner` \
                 (`marketplace/task.rs:78`, GAP §1)",
                names[0]
            ),
        )),
    }
}

/// Read every line of `ledger.jsonl`.
fn read_ledger(root: &Path, findings: &mut Vec<Warning>) -> Result<Vec<PlannedEntry>> {
    let path = root.join(LEDGER_FILE);
    let mut entries = Vec::new();
    if !path.is_file() {
        return Ok(entries);
    }
    let label = legacy::path_label(root, &path);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            findings.push(Warning::reject(
                Finding::UnreadableFile,
                Some(label),
                format!("the ledger could not be read: {error}"),
            ));
            return Ok(entries);
        }
    };
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let line_label = format!("{LEDGER_FILE}#{line_number}");
        let value: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(error) => {
                findings.push(Warning::reject(
                    Finding::MalformedJson,
                    Some(line_label),
                    format!("line {line_number} is not valid JSON: {error}"),
                ));
                continue;
            }
        };
        if !value.is_object() {
            findings.push(Warning::reject(
                Finding::RecordNotAnObject,
                Some(line_label),
                format!(
                    "line {line_number} must be a JSON object, found {}",
                    field::kind_of(&value)
                ),
            ));
            continue;
        }
        match plan_entry(&line_label, line_number, trimmed, &value, findings) {
            Ok(entry) => entries.push(entry),
            Err(defect) => findings.push(defect.into()),
        }
    }
    Ok(entries)
}

/// Convert one ledger line.
fn plan_entry(
    label: &str,
    line: usize,
    text: &str,
    value: &Value,
    findings: &mut Vec<Warning>,
) -> std::result::Result<PlannedEntry, Defect> {
    let (amount, raw_amount) = match field::money_field_with_literal(
        label,
        text,
        value,
        &["amount", "reward", "value"],
    )? {
        Some(found) => found,
        None => {
            return Err(Defect::new(
                Finding::MissingField,
                label,
                "required field `amount` is missing",
            ))
        }
    };
    if !amount.is_positive() {
        // upstream v2.5.6 fix: upstream accepted `deposit(-1000)` and
        // `slash(-1000)` — both passed its conservation check, because all three
        // counters moved together — and exposed the deposit route without
        // authentication (GAP §2.2). A non-positive movement is refused here.
        return Err(Defect::new(
            Finding::NonPositiveAmount,
            label,
            format!(
                "field `amount` = {} is not positive; upstream accepted negative deposits and \
                 slashes, and its tolerance-based conservation check could not see them because all \
                 three counters moved together (GAP §2.2), this project refuses them",
                amount.to_decimal_string()
            ),
        ));
    }

    let from = account_field(label, value, &["from", "payer", "sender", "source_account"])?;
    let to = account_field(
        label,
        value,
        &[
            "to",
            "payee",
            "recipient",
            "destination_account",
            "agent",
            "agent_id",
        ],
    )?;
    if from.is_none() && to.is_none() {
        return Err(Defect::new(
            Finding::MissingField,
            label,
            "required field `to` is missing and no `from` is present: an entry that moves nothing \
             between nobody cannot be migrated",
        ));
    }

    let reason = field::optional_str(label, value, &["reason", "settlement_reason", "memo"])?
        .unwrap_or_else(|| "unspecified".to_string());
    let task_id = field::optional_str(label, value, &["task_id", "task"])?;
    let at = field::optional_u64(label, value, &["at", "ts", "timestamp", "settled_at"])?;

    let kind = match LedgerKind::from_upstream_reason(&reason) {
        Some(kind) => kind,
        None => {
            let inferred = LedgerKind::from_parties(from.is_some(), to.is_some());
            findings.push(Warning::info(
                Finding::LedgerKindInferred,
                Some(label.to_string()),
                format!(
                    "upstream reason `{reason}` does not name a movement this project records, so the \
                     kind `{}` was inferred from which parties are present",
                    inferred.as_str()
                ),
            ));
            inferred
        }
    };

    let flat_reason = reason.trim().to_ascii_lowercase().replace([' ', '-'], "_");
    if matches!(
        flat_reason.as_str(),
        "duplicatework" | "duplicate_work" | "rejected"
    ) {
        findings.push(Warning::info(
            Finding::UpstreamUnreachableReason,
            Some(label.to_string()),
            format!(
                "upstream reason `{reason}` is carried verbatim and not interpreted: the audit found \
                 that `settle_task` always passed `Completed`, so this variant was unreachable in \
                 upstream's own production path (`settlement.rs:17-19` vs `marketplace/mod.rs:362`, \
                 GAP §2.8)"
            ),
        ));
    }

    for party in [&from, &to].into_iter().flatten() {
        if ledger::is_system_account(party) {
            findings.push(Warning::info(
                Finding::SystemAccountKept,
                Some(label.to_string()),
                format!(
                    "`{party}` is a reserved internal account and is kept verbatim: holding escrow \
                     and stake in namespaced accounts is upstream's good idea and this project keeps \
                     it (ATTRIBUTION §2.2)"
                ),
            ));
        }
    }
    if from.is_none() || to.is_none() {
        findings.push(Warning::warn(
            Finding::ExternalParty,
            Some(label.to_string()),
            format!(
                "the entry has {}; the journal is therefore not closed, the migrated net movement is \
                 not zero, and the report says so instead of pretending conservation holds",
                if from.is_none() {
                    "no payer, so funds enter from outside the ledger"
                } else {
                    "no payee, so funds leave the ledger"
                }
            ),
        ));
    }

    Ok(PlannedEntry {
        source_file: label.to_string(),
        line,
        task_id,
        from,
        to,
        amount,
        kind,
        reason,
        at,
        raw_amount,
    })
}

/// Read one optional account field.
fn account_field(
    source: &str,
    value: &Value,
    names: &[&str],
) -> std::result::Result<Option<String>, Defect> {
    let Some((name, found)) = field::find_present(value, names) else {
        return Ok(None);
    };
    let label = found.as_str().ok_or_else(|| {
        Defect::new(
            Finding::InvalidFieldType,
            source,
            format!(
                "field `{name}` must be an account string, found {}",
                field::kind_of(found)
            ),
        )
    })?;
    if !ledger::is_valid_account_label(label) {
        return Err(Defect::new(
            Finding::InvalidAccountLabel,
            source,
            format!(
                "field `{name}` = `{label}` is outside this project's account-label charset \
                 ([A-Za-z0-9_-:.] and at most {} bytes, or a reserved `{}`/`{}` namespace account)",
                ledger::MAX_ACCOUNT_LABEL_LEN,
                ledger::ESCROW_PREFIX,
                ledger::STAKE_PREFIX
            ),
        ));
    }
    Ok(Some(label.to_string()))
}

/// Read `<root>/keys.json`.
fn read_key_registry(root: &Path, findings: &mut Vec<Warning>) -> Result<KeyRegistry> {
    let path = root.join(KEYS_FILE);
    if !path.is_file() {
        return Ok(KeyRegistry::new());
    }
    let label = legacy::path_label(root, &path);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            findings.push(Warning::reject(
                Finding::UnreadableFile,
                Some(label),
                format!("`{KEYS_FILE}` could not be read: {error}"),
            ));
            return Ok(KeyRegistry::new());
        }
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(value) => Ok(legacy::keys_from_json(&label, &value, findings)),
        Err(error) => {
            findings.push(Warning::reject(
                Finding::MalformedJson,
                Some(label),
                format!("`{KEYS_FILE}` is not valid JSON: {error}"),
            ));
            Ok(KeyRegistry::new())
        }
    }
}

/// Read `<root>/balances.json`, the claimed end state of every account.
///
/// # Contract
///
/// The file is modelled on an export of upstream's in-memory
/// `SettlementEngine.balances` (`settlement.rs:47`). Upstream never persisted it
/// (GAP §6.1), so this is the only way an operator can hand the claims to a
/// migration — and the claims are then checked, not trusted.
fn read_balance_claims(
    root: &Path,
    findings: &mut Vec<Warning>,
) -> Result<BTreeMap<String, Money>> {
    let mut claims = BTreeMap::new();
    let path = root.join(BALANCES_FILE);
    if !path.is_file() {
        return Ok(claims);
    }
    let label = legacy::path_label(root, &path);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            findings.push(Warning::reject(
                Finding::UnreadableFile,
                Some(label),
                format!("`{BALANCES_FILE}` could not be read: {error}"),
            ));
            return Ok(claims);
        }
    };
    let value: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            findings.push(Warning::reject(
                Finding::MalformedJson,
                Some(label),
                format!("`{BALANCES_FILE}` is not valid JSON: {error}"),
            ));
            return Ok(claims);
        }
    };
    let Some(object) = value.as_object() else {
        findings.push(Warning::reject(
            Finding::RecordNotAnObject,
            Some(label),
            format!(
                "`{BALANCES_FILE}` must be an object of account → decimal balance, found {}",
                field::kind_of(&value)
            ),
        ));
        return Ok(claims);
    };
    for account in object.keys() {
        let literal = match rawjson::top_level_scalar(&text, account) {
            Ok(Some(RawScalar::Number(literal))) | Ok(Some(RawScalar::Str(literal))) => literal,
            Ok(None) => {
                findings.push(Warning::reject(
                    Finding::InvalidFieldType,
                    Some(label.clone()),
                    format!(
                        "the claimed balance for `{account}` must be a decimal number or a decimal \
                         string, found {}",
                        field::kind_of(&object[account])
                    ),
                ));
                continue;
            }
            Err(error) => {
                findings.push(Warning::reject(
                    Finding::RawLiteralUnavailable,
                    Some(label.clone()),
                    format!(
                        "the claimed balance for `{account}` could not be read verbatim: {error}"
                    ),
                ));
                continue;
            }
        };
        match amount_from_decimal(&label, account, &literal) {
            Ok(balance) => {
                claims.insert(account.clone(), balance);
            }
            Err(error) => findings.push(Warning::reject(
                field::defect_from_amount(&label, &error).code,
                Some(label.clone()),
                error.to_string(),
            )),
        }
    }
    Ok(claims)
}

/// Compare claimed balances against the re-derived journal, exactly.
fn report_discrepancies(
    entries: &[PlannedEntry],
    claims: &BTreeMap<String, Money>,
    findings: &mut Vec<Warning>,
) -> Result<()> {
    let derived: Vec<AccountBalance> = ledger::derive_balances(entries)?;
    for balance in &derived {
        let Some(claimed) = claims.get(&balance.account) else {
            continue;
        };
        if *claimed == balance.derived {
            continue;
        }
        let difference = balance
            .derived
            .checked_sub(*claimed)
            .map_err(|_| MigrateError::TotalOverflow)?;
        let sign = if difference.is_negative() { "" } else { "+" };
        findings.push(Warning::warn(
            Finding::BalanceDiscrepancy,
            Some(BALANCES_FILE.to_string()),
            format!(
                "account `{}` claims a balance of {} but the journal re-derives {} \
                 (difference {sign}{} minor units); the re-derived value is used and the claim is \
                 NOT smoothed over. Upstream compared balances with a 0.001 tolerance against two \
                 other counters its own code updated, and never re-derived from its journal \
                 (`settlement.rs:171-183`, `audit_full_scan` at `:186-204` had no call site, \
                 GAP §2.1/§2.4)",
                balance.account,
                claimed.to_decimal_string(),
                balance.derived.to_decimal_string(),
                difference.to_decimal_string()
            ),
        ));
    }
    for (account, claimed) in claims {
        if derived.iter().any(|balance| &balance.account == account) || claimed.is_zero() {
            continue;
        }
        findings.push(Warning::warn(
            Finding::BalanceDiscrepancy,
            Some(BALANCES_FILE.to_string()),
            format!(
                "account `{account}` claims a balance of {} but no journal entry mentions it at all \
                 (re-derived 0); the claim is reported, not imported",
                claimed.to_decimal_string()
            ),
        ));
    }
    Ok(())
}

/// Note any database file in the tree, because this crate will not read it.
fn note_database_files(root: &Path, findings: &mut Vec<Warning>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let extension = path
            .extension()
            .map(|ext| ext.to_string_lossy().to_ascii_lowercase());
        if matches!(extension.as_deref(), Some("db" | "sqlite" | "sqlite3")) {
            findings.push(Warning::info(
                Finding::DatabaseIgnored,
                Some(legacy::path_label(root, &path)),
                "a database file is present and will NOT be read: this crate reads JSON/JSONL only. \
                 Upstream's SQLite store had four tables (agents, tasks, kv_meta, relays), no ledger \
                 or balance table at all, and nothing ever read it back (`load_agents`/`load_tasks` \
                 had zero call sites, GAP §6.1), so the JSON artifacts carry everything that ever \
                 had semantic force"
                    .to_string(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::Identity;
    use serde_json::json;

    fn source(label: &str, text: &str) -> RecordSource {
        RecordSource {
            label: label.to_string(),
            text: text.to_string(),
            value: serde_json::from_str(text).expect("fixture is valid JSON"),
        }
    }

    fn signed_record(mut value: Value, identity: &Identity) -> RecordSource {
        value["signature"] = json!("");
        let signature = identity.sign_payload(&value).expect("signs");
        value["signature"] = json!(signature);
        let text = serde_json::to_string(&value).expect("serializes");
        source("agents/card.json", &text)
    }

    fn card_fixture() -> (Identity, RecordSource) {
        let identity = Identity::from_seed(&[1u8; 32]);
        let value = json!({
            "did": identity.public_key().legacy_did().as_str(),
            "name": "CrossLang",
            "capabilities": ["text-generation", "mcp"],
            "stake": 100,
            // A decimal string, not a float: a signed payload cannot contain a
            // float at all (that case has its own test in `legacy`).
            "price_per_task": "0.001",
            "endpoint": "tcp://127.0.0.1:4001",
            "public_key": identity.public_key().to_hex(),
            "signature": ""
        });
        let mut source = signed_record(value, &identity);
        source.label = "agents/card-crosslang.json".to_string();
        (identity, source)
    }

    #[test]
    fn a_card_with_a_legacy_did_is_planned_with_the_prefix_kept_and_the_signature_verified() {
        let (_identity, record) = card_fixture();
        let mut findings = Vec::new();
        let planned = plan_card(&record, &KeyRegistry::new(), &mut findings).expect("plans");
        assert_eq!(planned.legacy_did, "did:aip:34750f98bd59fcfc");
        assert!(planned.legacy_prefix);
        assert_eq!(planned.card.owner.as_str(), "did:aip:34750f98bd59fcfc");
        assert!(planned
            .card
            .owner
            .matches_public_key(&planned.card.owner_key));
        assert_eq!(planned.card.stake.minor(), 100_000_000);
        // `1e-3` migrated exactly, from the verbatim literal.
        assert_eq!(planned.card.pricing.unit_price.minor(), 1_000);
        assert_eq!(planned.card.endpoints, vec!["tcp://127.0.0.1:4001"]);
        assert!(
            planned.card.signature.is_empty(),
            "the converted card cannot carry the legacy signature"
        );
        let codes: Vec<Finding> = findings.iter().map(|warning| warning.code).collect();
        assert!(codes.contains(&Finding::LegacyDidPrefix));
        assert!(codes.contains(&Finding::DefaultsFilled));
        assert!(codes.contains(&Finding::TargetNotWireValid));
        assert!(findings.iter().all(|warning| !warning.is_rejection()));
    }

    #[test]
    fn a_card_whose_signature_does_not_match_is_rejected_not_partially_imported() {
        let (_identity, mut record) = card_fixture();
        record.value["name"] = json!("Tampered");
        let mut findings = Vec::new();
        let defect = plan_card(&record, &KeyRegistry::new(), &mut findings).expect_err("rejected");
        assert_eq!(defect.code, Finding::SignatureInvalid);
        assert_eq!(defect.source, "agents/card-crosslang.json");
    }

    #[test]
    fn a_card_without_a_stake_is_refused_because_the_target_requires_one() {
        let identity = Identity::from_seed(&[2u8; 32]);
        let value = json!({
            "did": identity.public_key().legacy_did().as_str(),
            "name": "NoStake",
            "capabilities": ["text-generation"],
            "public_key": identity.public_key().to_hex(),
            "signature": ""
        });
        let record = signed_record(value, &identity);
        let mut findings = Vec::new();
        let defect = plan_card(&record, &KeyRegistry::new(), &mut findings).expect_err("rejected");
        assert_eq!(defect.code, Finding::MissingField);
        assert!(defect.detail.contains("stake"), "{}", defect.detail);
    }

    #[test]
    fn a_missing_public_key_is_a_typed_rejection_that_says_where_to_put_one() {
        let identity = Identity::from_seed(&[3u8; 32]);
        let value = json!({
            "did": identity.public_key().legacy_did().as_str(),
            "name": "Keyless",
            "capabilities": ["text-generation"],
            "stake": 10,
            "signature": "00"
        });
        let record = signed_record(value, &identity);
        let mut findings = Vec::new();
        let defect = plan_card(&record, &KeyRegistry::new(), &mut findings).expect_err("rejected");
        assert_eq!(defect.code, Finding::MissingPublicKey);
        assert!(defect.detail.contains("keys.json"), "{}", defect.detail);

        // With the registry, the same record plans and says where the key came from.
        let mut registry = KeyRegistry::new();
        registry.insert(
            identity.public_key().legacy_did().to_string(),
            identity.public_key(),
        );
        let mut findings = Vec::new();
        let planned = plan_card(&record, &registry, &mut findings).expect("plans");
        assert_eq!(planned.card.stake.minor(), 10_000_000);
        assert!(findings
            .iter()
            .any(|warning| warning.code == Finding::KeyFromRegistry));
    }

    #[test]
    fn mixed_case_capabilities_are_lowercased_with_a_warning_that_records_the_original() {
        let identity = Identity::from_seed(&[4u8; 32]);
        let value = json!({
            "did": identity.public_key().legacy_did().as_str(),
            "name": "Mixed",
            "capabilities": ["Text-Generation", {"id": "MCP", "version": 2, "description": "tools"}],
            "stake": 10,
            "public_key": identity.public_key().to_hex(),
            "signature": ""
        });
        let record = signed_record(value, &identity);
        let mut findings = Vec::new();
        let planned = plan_card(&record, &KeyRegistry::new(), &mut findings).expect("plans");
        assert_eq!(planned.card.skills[0].id, "text-generation");
        assert_eq!(planned.card.skills[1].id, "mcp");
        assert_eq!(planned.card.skills[1].version, 2);
        let warning = findings
            .iter()
            .find(|warning| warning.code == Finding::CapabilityNormalised)
            .expect("reported");
        assert!(
            warning.detail.contains("Text-Generation"),
            "{}",
            warning.detail
        );
    }

    fn task_fixture(status: &str) -> (Identity, RecordSource) {
        let identity = Identity::from_seed(&[7u8; 32]);
        let value = json!({
            "task_id": "task-translate-1",
            "requester": identity.public_key().legacy_did().as_str(),
            "executor": identity.public_key().legacy_did().as_str(),
            "reward": "12.5",
            "status": status,
            "goal": "translate the document",
            "context": "English to Chinese",
            "done": ["every section translated"],
            "todo": ["read", "translate"],
            "required_skills": ["translation"],
            "public_key": identity.public_key().to_hex(),
            "signature": ""
        });
        let mut source = signed_record(value, &identity);
        source.label = "tasks/task-translate-1.json".to_string();
        (identity, source)
    }

    #[test]
    fn a_task_migrates_with_its_six_field_spec_and_its_status_mapped() {
        let (_identity, record) = task_fixture("completed");
        let mut findings = Vec::new();
        let planned = plan_task(&record, &KeyRegistry::new(), &mut findings).expect("plans");
        assert_eq!(planned.task.id.as_str(), "task-translate-1");
        assert_eq!(planned.task.state, TaskState::Accepted);
        assert_eq!(planned.task.budget.minor(), 12_500_000);
        assert_eq!(planned.task.spec.goal, "translate the document");
        assert_eq!(planned.task.spec.done.len(), 1);
        // The legacy DID is kept, so the owner is the `did:aip:` spelling while
        // `requester_key.did()` is the `did:nau:` spelling of the same key: what
        // matters is that the fingerprint binds them.
        assert!(planned
            .task
            .spec
            .owner
            .matches_public_key(&planned.task.requester_key));
        assert_eq!(planned.task.spec.owner.as_str(), planned.legacy_did);
        assert_eq!(planned.upstream_status, "completed");
        assert!(findings
            .iter()
            .any(|warning| warning.code == Finding::StatusRemapped));
    }

    #[test]
    fn upstream_only_statuses_are_rejected_with_the_status_named() {
        for status in ["view_change", "arbitration", "expired", "teleported"] {
            let (_identity, record) = task_fixture(status);
            let mut findings = Vec::new();
            let defect =
                plan_task(&record, &KeyRegistry::new(), &mut findings).expect_err("rejected");
            assert_eq!(defect.code, Finding::UnsupportedStatus);
            assert!(defect.detail.contains(status), "{}", defect.detail);
        }
        assert_eq!(map_status("no-quorum"), Some(TaskState::NoQuorum));
        assert_eq!(map_status("NoQuorum"), Some(TaskState::NoQuorum));
        assert_eq!(map_status("ARBITRATION"), None);
        assert_eq!(state_name(TaskState::NoQuorum), "no_quorum");
    }

    #[test]
    fn a_task_missing_a_six_field_spec_field_is_rejected() {
        let identity = Identity::from_seed(&[8u8; 32]);
        let value = json!({
            "task_id": "task-no-spec",
            "requester": identity.public_key().legacy_did().as_str(),
            "reward": 5,
            "status": "open",
            "public_key": identity.public_key().to_hex(),
            "signature": ""
        });
        let mut source = signed_record(value, &identity);
        source.label = "tasks/task-no-spec.json".to_string();
        let mut findings = Vec::new();
        let defect = plan_task(&source, &KeyRegistry::new(), &mut findings).expect_err("rejected");
        assert_eq!(defect.code, Finding::MissingField);
        assert!(defect.detail.contains("goal"), "{}", defect.detail);
    }

    #[test]
    fn a_committee_field_is_discarded_with_a_warning_rather_than_believed() {
        let identity = Identity::from_seed(&[9u8; 32]);
        let value = json!({
            "task_id": "task-committee",
            "requester": identity.public_key().legacy_did().as_str(),
            "reward": 5,
            "status": "open",
            "goal": "g",
            "context": "c",
            "done": ["d"],
            "todo": ["t"],
            "required_skills": ["s"],
            "committee_size": 4,
            "public_key": identity.public_key().to_hex(),
            "signature": ""
        });
        let mut source = signed_record(value, &identity);
        source.label = "tasks/task-committee.json".to_string();
        let mut findings = Vec::new();
        let planned = plan_task(&source, &KeyRegistry::new(), &mut findings).expect("plans");
        assert_eq!(planned.task.verification, VerificationPolicy::RequesterOnly);
        assert!(findings
            .iter()
            .any(|warning| warning.code == Finding::FieldNotMapped));
    }

    #[test]
    fn ledger_entries_must_be_positive_and_exactly_representable() {
        let ok_text = r#"{"task_id":"t1","from":"alice","to":"bob","amount":"12.5","reason":"Completed","ts":1700000000}"#;
        let mut findings = Vec::new();
        let entry = plan_entry(
            "ledger.jsonl#1",
            1,
            ok_text,
            &serde_json::from_str(ok_text).expect("json"),
            &mut findings,
        )
        .expect("plans");
        assert_eq!(entry.amount.minor(), 12_500_000);
        assert_eq!(entry.raw_amount, "12.5");
        assert_eq!(entry.kind, LedgerKind::Release);
        assert_eq!(entry.at, Some(1_700_000_000));

        let negative = r#"{"from":"alice","to":"bob","amount":-1000}"#;
        let mut findings = Vec::new();
        let defect = plan_entry(
            "ledger.jsonl#2",
            2,
            negative,
            &serde_json::from_str(negative).expect("json"),
            &mut findings,
        )
        .expect_err("rejected");
        assert_eq!(defect.code, Finding::NonPositiveAmount);

        let inexact = r#"{"from":"alice","to":"bob","amount":0.0000001}"#;
        let mut findings = Vec::new();
        let defect = plan_entry(
            "ledger.jsonl#3",
            3,
            inexact,
            &serde_json::from_str(inexact).expect("json"),
            &mut findings,
        )
        .expect_err("rejected");
        assert_eq!(defect.code, Finding::AmountNotExact);
        assert!(defect.detail.contains("0.0000001"), "{}", defect.detail);

        let nobody = r#"{"amount":1}"#;
        let mut findings = Vec::new();
        let defect = plan_entry(
            "ledger.jsonl#4",
            4,
            nobody,
            &serde_json::from_str(nobody).expect("json"),
            &mut findings,
        )
        .expect_err("rejected");
        assert_eq!(defect.code, Finding::MissingField);
    }

    #[test]
    fn a_closed_journal_plan_canonicalizes_and_has_a_digest() {
        // A plan is built by hand here so that `summary`, `canonical_json` and
        // `digest` are exercised without touching the filesystem.
        let (_identity, record) = card_fixture();
        let (_task_identity, task_record) = task_fixture("settled");
        let mut findings = Vec::new();
        let card = plan_card(&record, &KeyRegistry::new(), &mut findings).expect("plans");
        let task = plan_task(&task_record, &KeyRegistry::new(), &mut findings).expect("plans");
        let entry = PlannedEntry {
            source_file: "ledger.jsonl#1".to_string(),
            line: 1,
            task_id: Some("task-translate-1".to_string()),
            from: Some("alice".to_string()),
            to: Some("did:aip:34750f98bd59fcfc".to_string()),
            amount: amount_from_decimal("ledger.jsonl", "amount", "0.1").expect("exact"),
            kind: LedgerKind::Release,
            reason: "Completed".to_string(),
            at: Some(1_700_000_000),
            raw_amount: "0.1".to_string(),
        };
        let plan = MigrationPlan {
            cards: vec![card],
            tasks: vec![task],
            ledger: vec![entry],
            warnings: findings,
        };
        let summary = plan.summary().expect("summary");
        assert_eq!(summary.cards, 1);
        assert_eq!(summary.tasks, 1);
        assert_eq!(summary.ledger_entries, 1);
        assert_eq!(summary.rejections, 0);
        assert_eq!(summary.moved.minor(), 100_000);
        let canonical = plan.canonical_json().expect("canonicalizes");
        assert!(
            canonical.contains("\"amount\":100000"),
            "money is an integer count of minor units: {canonical}"
        );
        assert!(
            !canonical.contains(":0.1"),
            "no money field is a bare JSON float in the canonical form: {canonical}"
        );
        assert_eq!(plan.digest().expect("digest").len(), 64);
        assert_eq!(plan.rejections().count(), 0);
        assert!(plan.notes_and_warnings().count() > 0);
    }

    #[test]
    fn a_plan_that_does_not_exist_is_an_error_not_an_empty_plan() {
        let error = plan_from_dir(Path::new("this/does/not/exist")).expect_err("error");
        assert!(matches!(error, MigrateError::NotADirectory { .. }));
    }
}
