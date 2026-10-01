//! Stage two: writing a verified plan into a store.
//!
//! [`apply`] never reads the source tree — that already happened in
//! [`crate::plan_from_dir`], and the tree may be gone by the time this runs. What
//! it *does* do is re-check the evidence the plan carries, so that a plan edited
//! after it was produced cannot be applied:
//!
//! * every card and task re-verifies its recorded legacy signature over its
//!   recorded canonical payload, plus the DID↔key binding;
//! * every ledger entry re-parses its recorded verbatim decimal text and must
//!   produce exactly the recorded minor-unit amount.
//!
//! What this proves: the plan was not altered after `plan_from_dir` read the
//! source. What it does **not** prove: that the source tree said what the plan says
//! — that check happened at plan time, against the source bytes, and the plan is
//! the record of it.
//!
//! # Idempotence
//!
//! The journal is append-only, so applying the same plan twice would append a
//! second copy of every entry. `apply` therefore refuses to run when the store's
//! metadata already records this plan's digest. Cards and tasks are keyed by
//! identity and would have been idempotent; the ledger is not, and the stricter
//! rule covers both.

use nau_core::{Did, Money, PublicKey, Signature64};
use nau_store::Store;
use serde::Serialize;

use crate::amount::amount_from_decimal;
use crate::error::{MigrateError, Result};
use crate::ledger::{self, AccountBalance};
use crate::plan::{MigrationPlan, SCHEMA_KEY, SCHEMA_VALUE, SOURCE_DIGEST_KEY};
use crate::warning::{Defect, Finding, Severity, Warning};

/// Metadata key holding the number of records one migration imported.
pub const IMPORTED_KEY: &str = "nau-migrate.imported";

/// What one [`apply`] did.
///
/// The counts an operator needs to reconcile a migration are here: what was
/// written, what was refused, how many findings there were, and the exact total of
/// migrated money.
#[derive(Debug, Clone, Serialize)]
pub struct MigrationReport {
    /// SHA-256 of the plan's canonical form, also stored in the store's metadata.
    pub source_digest: String,
    /// Cards written.
    pub cards_imported: usize,
    /// Tasks written.
    pub tasks_imported: usize,
    /// Ledger entries appended.
    pub ledger_entries_imported: usize,
    /// Cards the plan carried.
    pub cards_planned: usize,
    /// Tasks the plan carried.
    pub tasks_planned: usize,
    /// Ledger entries the plan carried.
    pub ledger_entries_planned: usize,
    /// Every record refused, plan time and apply time together.
    pub rejected: usize,
    /// Records the plan carried that failed the apply-time re-check. Zero for a
    /// plan that was not edited after it was produced.
    pub rejected_at_apply: usize,
    /// Findings that are neither notes nor rejections.
    pub warnings: usize,
    /// Findings that only record a difference.
    pub notes: usize,
    /// Sum of the migrated amounts regardless of direction, in minor units.
    pub migrated_total: Money,
    /// Sum of the signed migrated movements; exactly zero for a closed journal.
    pub migrated_net: Money,
    /// True when the imported journal's books balance exactly: the net movement is
    /// zero *and* the re-derived balances sum to it.
    pub conserved: bool,
    /// Balances re-derived from the imported entries, ordered by account.
    pub accounts: Vec<AccountBalance>,
    /// Every finding, plan time first.
    pub findings: Vec<Warning>,
}

impl MigrationReport {
    /// The findings that refused a record.
    pub fn rejections(&self) -> impl Iterator<Item = &Warning> {
        self.findings
            .iter()
            .filter(|warning| warning.is_rejection())
    }
}

/// Write `plan` into `store`.
///
/// # Errors
///
/// * [`MigrateError::AlreadyApplied`] when this store already records this plan's
///   digest;
/// * [`MigrateError::PlanDigest`] when the plan cannot be canonicalized;
/// * [`MigrateError::Store`] when the store refuses an operation;
/// * [`MigrateError::TotalOverflow`] when a total leaves the `i64` minor-unit
///   range.
///
/// Records refused by the apply-time re-check are **not** an error: they are
/// counted in [`MigrationReport::rejected`] and reported in
/// [`MigrationReport::findings`], and everything else is still written.
pub fn apply(plan: &MigrationPlan, store: &mut dyn Store) -> Result<MigrationReport> {
    let digest = plan.digest()?;

    if let Some(previous) = store.get_meta(SOURCE_DIGEST_KEY)? {
        if previous == digest {
            // upstream v2.5.6 fix: upstream's settlement was the one place with a
            // real idempotence guard (`settled_tasks`, `settlement.rs:97-107`) while
            // every other mutation was replayable; a migration must not be. Applying
            // twice would append a second copy of every entry to an append-only
            // journal.
            return Err(MigrateError::AlreadyApplied {
                digest,
                meta_key: SOURCE_DIGEST_KEY.to_string(),
            });
        }
    }

    let mut findings = plan.warnings.clone();
    let mut rejected_at_apply = 0usize;
    let mut cards_imported = 0usize;
    let mut tasks_imported = 0usize;
    let mut ledger_entries_imported = 0usize;

    // ---- cards -------------------------------------------------------------
    for planned in &plan.cards {
        match reverify(
            &planned.source_file,
            &planned.legacy_did,
            &planned.card.owner_key,
            &planned.legacy_signature,
            &planned.legacy_canonical_payload,
        ) {
            Ok(()) => {
                store.save_agent(&planned.card)?;
                cards_imported += 1;
            }
            Err(defect) => {
                rejected_at_apply += 1;
                findings.push(defect.into());
            }
        }
    }

    // ---- tasks -------------------------------------------------------------
    for planned in &plan.tasks {
        match reverify(
            &planned.source_file,
            &planned.legacy_did,
            &planned.task.requester_key,
            &planned.legacy_signature,
            &planned.legacy_canonical_payload,
        ) {
            Ok(()) => {
                store.save_task(&planned.task)?;
                tasks_imported += 1;
            }
            Err(defect) => {
                rejected_at_apply += 1;
                findings.push(defect.into());
            }
        }
    }

    // ---- ledger ------------------------------------------------------------
    // Sequence numbers continue from whatever the store already holds, so an
    // import into a store with history does not renumber it.
    let offset = u64::try_from(store.load_ledger()?.len()).unwrap_or(u64::MAX);
    for (index, entry) in plan.ledger.iter().enumerate() {
        // Re-derive the amount from the verbatim text the plan recorded: a plan
        // whose `amount` was edited no longer matches its own evidence.
        match amount_from_decimal(&entry.source_file, "raw_amount", &entry.raw_amount) {
            Ok(money) if money == entry.amount => {}
            Ok(money) => {
                rejected_at_apply += 1;
                findings.push(
                    Defect::new(
                        Finding::InvalidFieldValue,
                        &entry.source_file,
                        format!(
                            "the plan records `amount` = {} minor units but its own verbatim text \
                             `{}` converts to {} minor units; refusing to append an entry whose \
                             evidence contradicts it",
                            entry.amount.minor(),
                            entry.raw_amount,
                            money.minor()
                        ),
                    )
                    .into(),
                );
                continue;
            }
            Err(error) => {
                rejected_at_apply += 1;
                findings.push(
                    Defect::new(
                        Finding::InvalidFieldValue,
                        &entry.source_file,
                        format!(
                            "the plan's recorded verbatim amount `{}` no longer converts: {error}",
                            entry.raw_amount
                        ),
                    )
                    .into(),
                );
                continue;
            }
        }
        let seq = offset.saturating_add(u64::try_from(index).unwrap_or(u64::MAX));
        store.append_ledger(&entry.to_ledger_value(seq))?;
        ledger_entries_imported += 1;
    }

    // ---- provenance --------------------------------------------------------
    store.set_meta(SCHEMA_KEY, SCHEMA_VALUE)?;
    store.set_meta(SOURCE_DIGEST_KEY, &digest)?;
    store.set_meta(
        IMPORTED_KEY,
        &serde_json::json!({
            "cards": cards_imported,
            "tasks": tasks_imported,
            "ledger_entries": ledger_entries_imported,
            "plan": digest,
        })
        .to_string(),
    )?;
    store.flush()?;

    // ---- report ------------------------------------------------------------
    let accounts = ledger::derive_balances(&plan.ledger)?;
    let (migrated_total, migrated_net) = ledger::totals(&plan.ledger)?;
    let balance_sum = ledger::sum_balances(&accounts)?;
    let mut report = MigrationReport {
        source_digest: digest,
        cards_imported,
        tasks_imported,
        ledger_entries_imported,
        cards_planned: plan.cards.len(),
        tasks_planned: plan.tasks.len(),
        ledger_entries_planned: plan.ledger.len(),
        rejected: 0,
        rejected_at_apply,
        warnings: 0,
        notes: 0,
        migrated_total,
        migrated_net,
        conserved: migrated_net.is_zero() && balance_sum.is_zero(),
        accounts,
        findings,
    };
    for warning in &report.findings {
        match warning.severity {
            Severity::Rejection => report.rejected += 1,
            Severity::Warning => report.warnings += 1,
            Severity::Info => report.notes += 1,
        }
    }
    Ok(report)
}

/// Re-check the evidence a plan carries for one signed record.
fn reverify(
    source: &str,
    did_text: &str,
    key: &PublicKey,
    signature_hex: &str,
    canonical_payload: &str,
) -> std::result::Result<(), Defect> {
    let did = Did::parse(did_text).map_err(|error| {
        Defect::new(
            Finding::InvalidDid,
            source,
            format!("the plan's DID `{did_text}` no longer parses: {error}"),
        )
    })?;
    if !did.matches_public_key(key) {
        return Err(Defect::new(
            Finding::DidKeyMismatch,
            source,
            format!(
                "the plan's DID `{did_text}` does not fingerprint the public key it carries \
                 (`{}`)",
                key.to_hex()
            ),
        ));
    }
    let signature = Signature64::from_hex(signature_hex).map_err(|error| {
        Defect::new(
            Finding::SignatureEncodingInvalid,
            source,
            format!("the plan's signature is not 64 bytes of hex: {error}"),
        )
    })?;
    key.verify(canonical_payload.as_bytes(), signature.as_bytes())
        .map_err(|error| {
            Defect::new(
                Finding::SignatureInvalid,
                source,
                format!(
                    "the plan's recorded signature does not verify over its recorded canonical \
                     payload: {error}"
                ),
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{LedgerKind, PlannedEntry};
    use crate::parse_decimal_exact;
    use crate::plan::PlannedAgent;
    use nau_core::{
        AgentCard, AgentCategory, Identity, Pricing, Skill, Sla, TaskId, TaskSpec, TaskState,
        VerificationPolicy,
    };
    use nau_store::MemoryStore;

    fn entry(amount: &str, raw: &str) -> PlannedEntry {
        PlannedEntry {
            source_file: "ledger.jsonl#1".to_string(),
            line: 1,
            task_id: None,
            from: Some("alice".to_string()),
            to: Some("bob".to_string()),
            amount: parse_decimal_exact(amount).expect("exact"),
            kind: LedgerKind::Release,
            reason: "Completed".to_string(),
            at: Some(1_700_000_000),
            raw_amount: raw.to_string(),
        }
    }

    fn planned_agent(seed: u8) -> PlannedAgent {
        let identity = Identity::from_seed(&[seed; 32]);
        let did = identity.public_key().legacy_did();
        let payload = format!(
            "{{\"capabilities\":[\"text-generation\"],\"did\":\"{did}\",\"name\":\"CrossLang\",\"stake\":100}}"
        );
        let signature = identity.sign_raw(payload.as_bytes());
        let card = AgentCard {
            owner: did.clone(),
            owner_key: identity.public_key(),
            name: "CrossLang".to_string(),
            description: None,
            category: AgentCategory::General,
            skills: vec![Skill::new("text-generation", 1)],
            pricing: Pricing::default(),
            sla: Sla::default(),
            stake: Money::from_minor(100_000_000),
            endpoints: Vec::new(),
            signed_at: 0,
            expires_at: None,
            nonce: 0,
            signature: String::new(),
        };
        PlannedAgent {
            source_file: "agents/card.json".to_string(),
            legacy_did: did.to_string(),
            legacy_prefix: true,
            legacy_signature: signature,
            legacy_canonical_payload: payload,
            card,
        }
    }

    fn empty_plan() -> MigrationPlan {
        MigrationPlan {
            cards: Vec::new(),
            tasks: Vec::new(),
            ledger: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn an_intact_plan_is_written_and_the_totals_are_exact() {
        let mut plan = empty_plan();
        plan.ledger = vec![entry("0.1", "0.1"), entry("0.2", "0.2")];
        let mut store = MemoryStore::new();
        let report = apply(&plan, &mut store).expect("applies");
        assert_eq!(report.cards_imported, 0);
        assert_eq!(report.ledger_entries_imported, 2);
        assert_eq!(report.rejected, 0);
        assert_eq!(report.rejected_at_apply, 0);
        assert_eq!(report.migrated_total.minor(), 300_000);
        assert!(report.migrated_net.is_zero());
        assert!(report.conserved, "0.1 + 0.2 books balance exactly");
        let bob = report
            .accounts
            .iter()
            .find(|balance| balance.account == "bob")
            .expect("bob has a balance");
        assert_eq!(bob.derived.minor(), 300_000);
        assert_eq!(store.load_ledger().expect("ledger").len(), 2);
        assert_eq!(
            store.get_meta(SOURCE_DIGEST_KEY).expect("meta"),
            Some(report.source_digest.clone())
        );
        assert_eq!(
            store.get_meta(SCHEMA_KEY).expect("meta"),
            Some(SCHEMA_VALUE.to_string())
        );
        let imported: serde_json::Value =
            serde_json::from_str(&store.get_meta(IMPORTED_KEY).expect("meta").expect("set"))
                .expect("json");
        assert_eq!(imported["ledger_entries"], serde_json::json!(2));
    }

    #[test]
    fn applying_the_same_plan_twice_is_refused_instead_of_duplicating_the_journal() {
        let mut plan = empty_plan();
        plan.ledger = vec![entry("1", "1")];
        let mut store = MemoryStore::new();
        apply(&plan, &mut store).expect("first apply");
        let error = apply(&plan, &mut store).expect_err("second apply must be refused");
        assert!(matches!(error, MigrateError::AlreadyApplied { .. }));
        assert_eq!(
            store.load_ledger().expect("ledger").len(),
            1,
            "the journal was not appended to a second time"
        );
    }

    #[test]
    fn a_plan_edited_after_it_was_produced_is_refused_at_apply_time() {
        let planned = planned_agent(1);

        // Intact: written.
        let mut plan = empty_plan();
        plan.cards = vec![planned.clone()];
        let mut store = MemoryStore::new();
        let report = apply(&plan, &mut store).expect("applies");
        assert_eq!(report.cards_imported, 1);
        assert!(store.load_agents().expect("agents").len() == 1);

        // Payload edited: the recorded signature no longer covers it.
        let mut tampered = planned.clone();
        tampered.legacy_canonical_payload = tampered
            .legacy_canonical_payload
            .replace("CrossLang", "CrossLane");
        let mut plan = empty_plan();
        plan.cards = vec![tampered];
        let mut store = MemoryStore::new();
        let report = apply(&plan, &mut store).expect("applies the rest");
        assert_eq!(report.cards_imported, 0);
        assert_eq!(report.rejected_at_apply, 1);
        assert!(
            store.load_agents().expect("agents").is_empty(),
            "a record that fails verification is never imported"
        );
        assert!(report
            .rejections()
            .any(|warning| warning.code == Finding::SignatureInvalid));

        // Key swapped for a different identity's: the binding check refuses it.
        let mut swapped = planned.clone();
        swapped.card.owner_key = Identity::from_seed(&[9u8; 32]).public_key();
        let mut plan = empty_plan();
        plan.cards = vec![swapped];
        let mut store = MemoryStore::new();
        let report = apply(&plan, &mut store).expect("applies the rest");
        assert_eq!(report.cards_imported, 0);
        assert!(report
            .rejections()
            .any(|warning| warning.code == Finding::DidKeyMismatch));
    }

    #[test]
    fn an_entry_whose_recorded_amount_contradicts_its_verbatim_text_is_refused() {
        // Someone edited `amount` in the plan but left the evidence alone.
        let mut plan = empty_plan();
        let mut edited = entry("1", "1");
        edited.amount = Money::from_minor(999_000_000);
        plan.ledger = vec![edited];
        let mut store = MemoryStore::new();
        let report = apply(&plan, &mut store).expect("applies the rest");
        assert_eq!(report.ledger_entries_imported, 0);
        assert_eq!(report.rejected_at_apply, 1);
        assert!(store.load_ledger().expect("ledger").is_empty());
        assert!(report
            .rejections()
            .any(|warning| warning.code == Finding::InvalidFieldValue));
    }

    #[test]
    fn report_counts_separate_notes_warnings_and_rejections() {
        let mut plan = empty_plan();
        plan.warnings = vec![
            Warning::info(Finding::LegacyDidPrefix, Some("a".into()), "note"),
            Warning::warn(Finding::BalanceDiscrepancy, Some("b".into()), "warning"),
            Warning::reject(Finding::SignatureInvalid, Some("c".into()), "rejection"),
        ];
        plan.ledger = vec![entry("1", "1")];
        let mut store = MemoryStore::new();
        let report = apply(&plan, &mut store).expect("applies");
        assert_eq!(report.notes, 1);
        assert_eq!(report.warnings, 1);
        assert_eq!(report.rejected, 1, "the plan-time rejection is counted");
        assert_eq!(report.rejected_at_apply, 0);
        assert_eq!(report.rejections().count(), 1);
    }

    #[test]
    fn a_task_that_cannot_be_re_verified_is_not_saved() {
        let identity = Identity::from_seed(&[21u8; 32]);
        let payload = "{\"did\":\"did:aip:34750f98bd59fcfc\",\"name\":\"x\",\"stake\":1}";
        let task = nau_core::Task::draft(
            TaskId::parse("task-1").expect("id"),
            TaskSpec {
                goal: "g".into(),
                context: "c".into(),
                done: vec!["d".into()],
                todo: vec!["t".into()],
                trace: None,
                owner: identity.public_key().legacy_did(),
            },
            vec!["s".into()],
            Money::from_minor(1),
            None,
            VerificationPolicy::RequesterOnly,
            identity.public_key(),
            0,
            0,
        );
        let mut plan = empty_plan();
        plan.tasks = vec![crate::plan::PlannedTask {
            source_file: "tasks/task-1.json".to_string(),
            legacy_did: identity.public_key().legacy_did().to_string(),
            legacy_prefix: true,
            legacy_signature: identity.sign_raw(payload.as_bytes()),
            legacy_canonical_payload: payload.to_string(),
            upstream_status: "open".to_string(),
            task,
        }];
        let mut store = MemoryStore::new();
        let report = apply(&plan, &mut store).expect("applies");
        assert_eq!(report.tasks_imported, 1);
        let loaded = store.load_tasks().expect("tasks");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].state, TaskState::Open);
        assert!(loaded[0].signature.is_empty());
    }
}
