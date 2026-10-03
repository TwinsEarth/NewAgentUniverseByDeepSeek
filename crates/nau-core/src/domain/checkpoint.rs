//! Checkpointing an execution, so a resume continues instead of replaying.
//!
//! # What this is for
//!
//! An agent's execution loop can be interrupted — a preemptible worker is reclaimed, a process is
//! migrated, a node is drained. The requirement is that the work **resumes from where it stopped**,
//! and the failure it must not have is the obvious one: resuming by re-running everything, which
//! is slower and, for any step that reached outside, **wrong**. That is the same problem
//! [`crate::domain::fork`] refuses a fork point for, and the checkpoint is the other half of the
//! answer: a fork is refused because a branch has no record; a resume is safe because the
//! checkpoint **is** that record.
//!
//! # Why a step is recorded before it runs as well as after
//!
//! The interesting state is not "done" but **"may have happened"**. A step that was interrupted
//! while it held a connection to somebody's API has either happened or not, and the checkpoint
//! cannot know which — so it says so. The alternative is to record only completed steps, in which
//! case an uncertain effect looks like an unstarted one and the resume **re-runs it**, which is
//! precisely the duplication the fork rule exists to prevent, arrived at from the other side.
//!
//! [`ExecutionCheckpoint::resume_from`] therefore reports uncertain steps rather than stepping over
//! them, and [`ExecutionCheckpoint::resume_from`] refuses to advance past one unless the caller
//! says what to do. A resume that silently retried a payment would be indistinguishable, in the
//! log, from one that retried a file write.
//!
//! # What is counted
//!
//! [`ResumePoint::skipped`] is the number of steps a resume does **not** run. That is the whole
//! claim — "it continues rather than replays" — expressed as a count, in the same shape every
//! other incrementality claim in this workspace takes. A test asserts it; a comment would not.

use serde::{Deserialize, Serialize};

use crate::error::{NauError, Result};

/// What happened to one step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    /// It finished. A resume skips it.
    Completed,
    /// It reached outside and its completion is **unknown**.
    ///
    /// The state a checkpoint finds itself in when a worker is reclaimed mid-call. It is neither
    /// safe to skip (the effect may not have happened) nor safe to re-run (it may have), which is
    /// why it is its own variant rather than a flag on `Completed`.
    Uncertain {
        /// What the step reached.
        target: String,
    },
}

impl StepOutcome {
    /// Whether a resume may skip this step without asking.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        matches!(self, StepOutcome::Completed)
    }

    /// Whether the effect may or may not have happened.
    #[must_use]
    pub fn is_uncertain(&self) -> bool {
        matches!(self, StepOutcome::Uncertain { .. })
    }
}

/// Where a resume continues from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResumePoint {
    /// Steps that will not be run again.
    pub skipped: usize,
    /// The index of the first step the resume should run.
    pub next_step: usize,
    /// Steps whose external effect may or may not have happened, by name.
    ///
    /// Non-empty means the caller has to decide before continuing: settlement is a fact only the
    /// outside world can supply.
    pub unresolved: Vec<String>,
}

impl ResumePoint {
    /// Whether the resume may proceed without asking about an uncertain effect.
    #[must_use]
    pub fn is_unambiguous(&self) -> bool {
        self.unresolved.is_empty()
    }
}

/// How a caller resolves an uncertain step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// The effect is confirmed to have happened. Skipped on resume.
    Happened,
    /// The effect is confirmed **not** to have happened. Re-run on resume.
    DidNotHappen,
}

/// A recorded execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCheckpoint {
    steps: Vec<(String, StepOutcome)>,
}

impl ExecutionCheckpoint {
    /// An empty checkpoint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many steps are recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Record a step that is about to run, or is running.
    ///
    /// Called **before** the step, so that an interruption during it leaves a record. A checkpoint
    /// written only after each step cannot describe the step that was interrupted, which is the
    /// only one in doubt.
    pub fn begin(&mut self, name: &str) {
        self.steps.push((name.to_string(), StepOutcome::Completed));
    }

    /// Mark the most recent step as having reached outside, with an unknown outcome.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when there is no step to mark — a record of an uncertain effect
    /// with no step it belongs to cannot be resumed, so it is refused rather than filed.
    pub fn mark_uncertain(&mut self, target: &str) -> Result<()> {
        let last = self.steps.last_mut().ok_or_else(|| {
            NauError::Validation(
                "no step is in progress, so there is nothing for an uncertain effect to belong to"
                    .to_string(),
            )
        })?;
        last.1 = StepOutcome::Uncertain {
            target: target.to_string(),
        };
        Ok(())
    }

    /// Record that the most recent step finished.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when there is no step in progress.
    pub fn complete(&mut self) -> Result<()> {
        let last = self.steps.last_mut().ok_or_else(|| {
            NauError::Validation("no step is in progress, so none can be completed".to_string())
        })?;
        last.1 = StepOutcome::Completed;
        Ok(())
    }

    /// The outcome of each recorded step, in order.
    #[must_use]
    pub fn steps(&self) -> &[(String, StepOutcome)] {
        &self.steps
    }

    /// Resolve an uncertain step by name.
    ///
    /// # Errors
    ///
    /// [`NauError::NotFound`] when no step with that name is uncertain. Refused rather than
    /// ignored: a caller that resolved the wrong name would believe it had settled something it
    /// had not, and the resume would run with the uncertainty still in place.
    pub fn resolve(&mut self, name: &str, resolution: Resolution) -> Result<()> {
        let step = self
            .steps
            .iter_mut()
            .find(|(n, o)| n == name && o.is_uncertain())
            .ok_or_else(|| {
                NauError::NotFound(format!(
                    "no uncertain step named `{name}`; a resolution for one that is not in doubt \
                     settles nothing"
                ))
            })?;
        step.1 = match resolution {
            // Confirmed to have happened: a resume skips it.
            Resolution::Happened => StepOutcome::Completed,
            // Confirmed not to have happened: a resume must NOT skip it, so it is removed and the
            // step is re-run.
            Resolution::DidNotHappen => {
                return Err(NauError::Validation(format!(
                    "`{name}` was confirmed not to have happened; the caller must remove it from \
                     the checkpoint rather than mark it settled, or the resume would skip a step \
                     that never ran"
                )));
            }
        };
        Ok(())
    }

    /// Where a resume continues from.
    ///
    /// Skipping is **not** "everything recorded" — that is the distinction this type exists for.
    /// A step recorded as uncertain is neither skipped nor re-run by this method; it is
    /// **reported**, and the caller settles it. A resume that silently retried a payment would be
    /// indistinguishable, in the log, from one that retried a file write.
    #[must_use]
    pub fn resume_from(&self) -> ResumePoint {
        let skipped = self.steps.iter().filter(|(_, o)| o.is_settled()).count();
        let unresolved = self
            .steps
            .iter()
            .filter(|(_, o)| o.is_uncertain())
            .map(|(n, _)| n.clone())
            .collect();
        ResumePoint {
            skipped,
            // The next step is the first recorded step that is **not** settled: an uncertain one
            // has to be dealt with before anything after it runs, because the steps after it may
            // depend on its effect.
            next_step: self
                .steps
                .iter()
                .position(|(_, o)| !o.is_settled())
                .unwrap_or(self.steps.len()),
            unresolved,
        }
    }

    /// The first uncertain step, if any.
    #[must_use]
    pub fn first_uncertain(&self) -> Option<(&str, &str)> {
        self.steps.iter().find_map(|(n, o)| match o {
            StepOutcome::Uncertain { target } => Some((n.as_str(), target.as_str())),
            StepOutcome::Completed => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resume_skips_completed_steps_and_reports_the_count() {
        // The whole claim -- "it continues rather than replays" -- as a number.
        let mut cp = ExecutionCheckpoint::new();
        for name in ["fetch", "build", "test"] {
            cp.begin(name);
            cp.complete().expect("complete");
        }
        let point = cp.resume_from();
        assert_eq!(point.skipped, 3, "three steps are not run again");
        assert_eq!(point.next_step, 3, "the resume starts after them");
        assert!(point.is_unambiguous());
        assert!(point.unresolved.is_empty());
    }

    #[test]
    fn an_uncertain_effect_is_reported_rather_than_skipped_or_re_run() {
        // The state a reclaimed worker leaves behind. Neither skipping nor re-running is safe, so
        // the checkpoint does neither and says which step is in doubt.
        let mut cp = ExecutionCheckpoint::new();
        cp.begin("fetch");
        cp.complete().expect("complete");
        cp.begin("charge the customer");
        cp.mark_uncertain("payments.example").expect("mark");

        let point = cp.resume_from();
        assert_eq!(point.skipped, 1, "only the completed step is skipped");
        assert_eq!(point.next_step, 1, "the resume stops AT the uncertain step");
        assert!(!point.is_unambiguous());
        assert_eq!(point.unresolved, vec!["charge the customer"]);
        assert_eq!(
            cp.first_uncertain(),
            Some(("charge the customer", "payments.example"))
        );
    }

    #[test]
    fn a_step_after_an_uncertain_one_is_not_skipped_either() {
        // The steps after it may depend on its effect, so settling it is not optional.
        let mut cp = ExecutionCheckpoint::new();
        cp.begin("charge");
        cp.mark_uncertain("payments.example").expect("mark");
        cp.begin("ship");
        cp.complete().expect("complete");

        let point = cp.resume_from();
        assert_eq!(point.skipped, 1, "only `ship` is settled");
        assert_eq!(point.next_step, 0, "the resume starts at `charge`");
        assert_eq!(point.unresolved, vec!["charge"]);
    }

    #[test]
    fn resolving_a_confirmed_effect_makes_a_resume_skip_it() {
        let mut cp = ExecutionCheckpoint::new();
        cp.begin("charge");
        cp.mark_uncertain("payments.example").expect("mark");
        cp.resolve("charge", Resolution::Happened)
            .expect("resolved");

        let point = cp.resume_from();
        assert_eq!(point.skipped, 1);
        assert!(point.is_unambiguous());
    }

    #[test]
    fn resolving_a_negative_is_refused_and_says_what_to_do_instead() {
        // The caller must remove the step, not mark it settled: marking it settled would make the
        // resume SKIP a step that never ran.
        let mut cp = ExecutionCheckpoint::new();
        cp.begin("charge");
        cp.mark_uncertain("payments.example").expect("mark");
        let err = cp
            .resolve("charge", Resolution::DidNotHappen)
            .expect_err("must refuse");
        let text = format!("{err}");
        assert!(
            text.contains("must remove it from the checkpoint"),
            "got: {text}"
        );
        assert!(
            cp.first_uncertain().is_some(),
            "the refusal must leave the step in doubt"
        );
    }

    #[test]
    fn resolving_a_name_that_is_not_in_doubt_is_refused() {
        // A caller that resolved the wrong name would believe it had settled something it had not.
        let mut cp = ExecutionCheckpoint::new();
        cp.begin("fetch");
        cp.complete().expect("complete");
        cp.begin("charge");
        cp.mark_uncertain("payments.example").expect("mark");

        let err = cp
            .resolve("fetch", Resolution::Happened)
            .expect_err("must refuse");
        assert!(
            format!("{err}").contains("no uncertain step named"),
            "got: {err}"
        );
        let err = cp
            .resolve("nope", Resolution::Happened)
            .expect_err("must refuse");
        assert!(
            format!("{err}").contains("no uncertain step named"),
            "got: {err}"
        );
    }

    #[test]
    fn marking_uncertain_with_no_step_in_progress_is_refused() {
        // A record of an uncertain effect with no step it belongs to cannot be resumed, so it is
        // refused rather than filed.
        let mut cp = ExecutionCheckpoint::new();
        assert!(cp.mark_uncertain("payments.example").is_err());
        assert!(cp.complete().is_err());
        assert!(cp.is_empty());
    }

    #[test]
    fn an_empty_checkpoint_resumes_from_the_beginning() {
        let cp = ExecutionCheckpoint::new();
        let point = cp.resume_from();
        assert_eq!(point.skipped, 0);
        assert_eq!(point.next_step, 0);
        assert!(point.is_unambiguous());
    }

    #[test]
    fn a_checkpoint_survives_a_round_trip_through_json() {
        // It is written to disk between runs, so the serialised form has to come back as the same
        // value and still report the same resume point.
        let mut cp = ExecutionCheckpoint::new();
        cp.begin("fetch");
        cp.complete().expect("complete");
        cp.begin("charge");
        cp.mark_uncertain("payments.example").expect("mark");

        let text = serde_json::to_string(&cp).expect("serialise");
        let back: ExecutionCheckpoint = serde_json::from_str(&text).expect("deserialise");
        assert_eq!(cp, back);
        assert_eq!(back.resume_from(), cp.resume_from());
        assert_eq!(back.first_uncertain(), cp.first_uncertain());
    }

    #[test]
    fn an_outcome_classifies_exactly_one_way() {
        let done = StepOutcome::Completed;
        let unsure = StepOutcome::Uncertain {
            target: "x".to_string(),
        };
        assert!(done.is_settled() && !done.is_uncertain());
        assert!(!unsure.is_settled() && unsure.is_uncertain());
    }
}
