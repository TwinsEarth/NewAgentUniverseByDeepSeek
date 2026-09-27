//! The six-field handoff bundle.
//!
//! `goal / context / done / todo / trace / owner`, plus the evidence grade that
//! travels with the handoff. Validation is mechanical and **bounded**.
//!
//! upstream v2.5.6 fix: upstream's `TransferBundle::validate`
//! (`gsn-core/src/memory/handoff.rs`) checked exactly six `is_empty()` calls and
//! nothing else, so a legitimate-looking bundle could carry an unbounded blob in
//! any field, a `done`/`todo` list of a million entries, or an `owner` string
//! that was not a DID at all (upstream's `owner` was a bare `String`). Here every
//! field has a byte cap, every list has an entry cap, and `owner` must parse as a
//! real `did:nau:` identifier.

use nau_core::{Did, EvidenceGrade, NauError, Result};
use serde::{Deserialize, Serialize};

/// Maximum size of any single string field, in bytes.
pub const MAX_FIELD_BYTES: usize = 16_384;

/// Maximum number of entries in any list field.
pub const MAX_ENTRIES: usize = 256;

/// A validated handoff from one owner to the next.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TransferBundle {
    /// What the receiver must achieve.
    pub goal: String,
    /// Everything the receiver needs to know that is not in the goal.
    pub context: String,
    /// What the sender already finished.
    pub done: Vec<String>,
    /// What remains.
    pub todo: Vec<String>,
    /// Pointers into the sender's audit trail.
    pub trace: Vec<String>,
    /// The DID accountable for this bundle.
    pub owner: Did,
    /// How well evidenced the handoff is.
    pub evidence: EvidenceGrade,
}

impl TransferBundle {
    /// The maximum size of any single string field, in bytes.
    pub const MAX_FIELD_BYTES: usize = MAX_FIELD_BYTES;

    /// The maximum number of entries in any list field.
    pub const MAX_ENTRIES: usize = MAX_ENTRIES;

    /// All six fields, mechanically validated.
    ///
    /// Every problem is collected and reported together (upstream returned on
    /// the first one), so a caller can fix the whole bundle in one pass.
    pub fn validate(&self) -> Result<()> {
        let mut gaps: Vec<String> = Vec::new();

        check_scalar("goal", &self.goal, &mut gaps);
        check_scalar("context", &self.context, &mut gaps);
        check_list("done", &self.done, &mut gaps);
        check_list("todo", &self.todo, &mut gaps);
        check_list("trace", &self.trace, &mut gaps);

        if self.evidence != EvidenceGrade::Unverified
            && self.trace.iter().all(|t| t.trim().is_empty())
        {
            // A grade above `Unverified` is a claim of evidence; a bundle that
            // claims it while pointing at nothing is not mechanically sound.
            gaps.push(
                "trace must point at evidence when the bundle claims a grade above `unverified`"
                    .into(),
            );
        }

        if gaps.is_empty() {
            Ok(())
        } else {
            Err(NauError::Validation(gaps.join("; ")))
        }
    }

    /// The evidence grade, as a machine label.
    pub fn evidence_label(&self) -> &'static str {
        self.evidence.label()
    }
}

fn check_scalar(field: &str, value: &str, gaps: &mut Vec<String>) {
    if value.trim().is_empty() {
        gaps.push(format!("{field} must not be empty"));
    }
    if value.len() > MAX_FIELD_BYTES {
        gaps.push(format!(
            "{field} is {} bytes, over the {MAX_FIELD_BYTES}-byte cap",
            value.len()
        ));
    }
}

fn check_list(field: &str, values: &[String], gaps: &mut Vec<String>) {
    if values.is_empty() || values.iter().all(|v| v.trim().is_empty()) {
        gaps.push(format!("{field} must contain at least one non-empty entry"));
    }
    if values.len() > MAX_ENTRIES {
        gaps.push(format!(
            "{field} has {} entries, over the {MAX_ENTRIES}-entry cap",
            values.len()
        ));
    }
    let mut total = 0usize;
    for value in values {
        total = total.saturating_add(value.len());
    }
    if total > MAX_FIELD_BYTES {
        gaps.push(format!(
            "{field} totals {total} bytes, over the {MAX_FIELD_BYTES}-byte cap for the field"
        ));
    }
}
