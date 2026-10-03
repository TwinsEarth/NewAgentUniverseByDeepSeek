//! Forking a trajectory, and the steps a fork must not be placed after.
//!
//! # The premise that holds inside a sandbox and fails outside one
//!
//! The design says the environment and data before a branch point can be **shared**, and only the
//! changes after it need recording. That is exactly right for sandbox-local state: a snapshot
//! captures it, a branch resumes from it, and nothing outside the sandbox is affected.
//!
//! It is exactly wrong for an external side effect. A `git push`, a payment, an HTTP `POST` to
//! somebody's API — none of those are in the snapshot. A branch resumed from a snapshot has no
//! record that the effect happened, so the ordinary recovery behaviour — re-run the step, because
//! there is no evidence it completed — **executes it again**. Three branches execute it three
//! times. The sandbox state stays consistent; the world outside does not.
//!
//! So a step is classified, and [`Trace::fork_after`] refuses to place a fork point after a step
//! whose effect escaped. This is B-06's whole mechanism, and it is a **refusal** rather than a
//! warning because a warning is a thing an automated pipeline learns to scroll past.
//!
//! # Why the classification is declared and not deduced
//!
//! [`classify`] recognises common shapes — `git push`, `curl`, `POST` — and it is a **helper, not
//! an oracle**. A step whose name happens to contain "push" but writes a local file would be
//! misclassified by any name-based rule, in the safe direction here, and a step that reaches the
//! network through a name nobody anticipated would be misclassified in the **unsafe** direction.
//!
//! That asymmetry is why a step may declare its own effect, and why the declaration wins over the
//! classifier: a heuristic can promote a step to `External` (refusing more forks than necessary,
//! which is safe) but it cannot demote one a caller declared, because the caller knows something
//! the name does not.

use serde::{Deserialize, Serialize};

use crate::error::{NauError, Result};

/// What a step touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepEffect {
    /// Confined to the sandbox: a snapshot captures it and a branch can resume past it.
    SandboxLocal,
    /// Reached the world outside the sandbox, which no snapshot can capture.
    ///
    /// The `target` is what was reached — a remote, a host, an endpoint — so that a refusal can
    /// say what would have been replayed rather than only that something would have been.
    External {
        /// The thing that was reached.
        target: String,
    },
}

impl StepEffect {
    /// Whether this effect escapes the sandbox.
    #[must_use]
    pub fn is_external(&self) -> bool {
        matches!(self, StepEffect::External { .. })
    }

    /// The target, if the effect escaped.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        match self {
            StepEffect::External { target } => Some(target.as_str()),
            StepEffect::SandboxLocal => None,
        }
    }

    /// A label for reports.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            StepEffect::SandboxLocal => "sandbox-local",
            StepEffect::External { .. } => "external",
        }
    }
}

/// One step of a trajectory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// What the step is called.
    pub name: String,
    /// What it touched. Declared by the caller; see the module documentation.
    pub effect: StepEffect,
}

impl Step {
    /// A step confined to the sandbox.
    #[must_use]
    pub fn local(name: &str) -> Self {
        Self {
            name: name.to_string(),
            effect: StepEffect::SandboxLocal,
        }
    }

    /// A step that reached outside.
    #[must_use]
    pub fn external(name: &str, target: &str) -> Self {
        Self {
            name: name.to_string(),
            effect: StepEffect::External {
                target: target.to_string(),
            },
        }
    }
}

/// Recognise a step that probably reaches outside, from its name and arguments.
///
/// A **helper, not an oracle**. It recognises the shapes this repository's own tooling produces,
/// and it can only ever promote a step to [`StepEffect::External`] — never demote one a caller
/// declared. See the module documentation for why that asymmetry is deliberate.
#[must_use]
pub fn classify(name: &str, args: &[&str]) -> StepEffect {
    let joined = format!("{name} {}", args.join(" "));
    let lowered = joined.to_ascii_lowercase();

    // `git push` and friends: the local repository is unchanged by the push, the remote is not.
    if lowered.starts_with("git ") || lowered.contains(" git ") {
        for verb in ["push", "fetch", "pull", "clone", "remote update"] {
            if lowered.contains(verb) {
                return StepEffect::External {
                    target: format!("git {verb}"),
                };
            }
        }
    }

    // Anything that names a URL, in the tools that usually do.
    for tool in ["curl", "wget", "http", "https"] {
        if lowered.starts_with(tool) || lowered.contains(&format!(" {tool} ")) {
            return StepEffect::External {
                target: "network".to_string(),
            };
        }
    }

    // Package managers and deploy tools: all of them reach a registry or a host.
    for tool in [
        "npm publish",
        "cargo publish",
        "pnpm publish",
        "docker push",
        "kubectl apply",
    ] {
        if lowered.contains(tool) {
            return StepEffect::External {
                target: tool.to_string(),
            };
        }
    }

    StepEffect::SandboxLocal
}

/// A fork: the shared prefix, and how many branches continue from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fork {
    /// The index of the last shared step.
    pub fork_after: usize,
    /// How many branches continue from there.
    pub branches: usize,
    /// The shared steps, by name.
    pub shared: Vec<String>,
    /// The steps that would have escaped if the branch re-ran its prefix.
    pub external_in_prefix: Vec<String>,
}

impl Fork {
    /// How many steps each branch owns — the ones after the fork point.
    #[must_use]
    pub fn branch_owned(&self, total_steps: usize) -> usize {
        total_steps.saturating_sub(self.fork_after + 1)
    }
}

/// A trajectory: an ordered list of steps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trace {
    steps: Vec<Step>,
}

impl Trace {
    /// An empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a step.
    pub fn push(&mut self, step: Step) {
        self.steps.push(step);
    }

    /// The steps.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// How many steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the trace has no steps.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// The first step that escaped, with its index.
    #[must_use]
    pub fn first_external(&self) -> Option<(usize, &Step)> {
        self.steps
            .iter()
            .enumerate()
            .find(|(_, s)| s.effect.is_external())
    }

    /// Whether a fork may be placed after step `at`.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `at` is past the end of the trace, and
    /// [`NauError::Conflict`] when any step **at or before** `at` escaped the sandbox — naming it
    /// and what it reached.
    ///
    /// The check is over the prefix and not over the whole trace: a step that escapes *after* the
    /// fork point belongs to a branch, and a branch is allowed to have its own effects. What is
    /// forbidden is placing the fork point **past** one, because a branch resumed from there would
    /// have no record of it.
    pub fn can_fork_after(&self, at: usize) -> Result<()> {
        if at >= self.steps.len() {
            return Err(NauError::Validation(format!(
                "step {at} is past the end of a {}-step trace",
                self.steps.len()
            )));
        }
        if let Some((index, step)) = self
            .steps
            .iter()
            .take(at + 1)
            .enumerate()
            .find(|(_, s)| s.effect.is_external())
        {
            let target = step.effect.target().unwrap_or("the outside");
            return Err(NauError::Conflict(format!(
                "a fork cannot be placed after step {at}: step {index} (`{}`) reached {target}, \
                 and no snapshot captures that. A branch resumed from here has no record that it \
                 happened, so the ordinary recovery -- re-run the step, because there is no \
                 evidence it completed -- would execute it again, once per branch",
                step.name
            )));
        }
        Ok(())
    }

    /// Place a fork after step `at`, with `branches` branches continuing from it.
    ///
    /// # Errors
    ///
    /// As [`Trace::can_fork_after`], plus [`NauError::Validation`] when `branches` is less than
    /// two: a fork with one branch is a rename, and accepting it would make "how many branches"
    /// unanswerable from the record.
    pub fn fork_after(&self, at: usize, branches: usize) -> Result<Fork> {
        self.can_fork_after(at)?;
        if branches < 2 {
            return Err(NauError::Validation(format!(
                "a fork needs at least two branches; {branches} is a rename"
            )));
        }
        Ok(Fork {
            fork_after: at,
            branches,
            shared: self.steps[..=at].iter().map(|s| s.name.clone()).collect(),
            // Empty by construction, and stated so that a caller reading a `Fork` can see the
            // property was checked rather than infer it from the absence of an error.
            external_in_prefix: Vec::new(),
        })
    }

    /// The fork points this trace admits.
    #[must_use]
    pub fn forkable_points(&self) -> Vec<usize> {
        (0..self.steps.len())
            .filter(|i| self.can_fork_after(*i).is_ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trace whose fourth step pushes to a remote.
    fn trace_with_a_push() -> Trace {
        let mut t = Trace::new();
        t.push(Step::local("write source"));
        t.push(Step::local("run tests"));
        t.push(Step::local("commit"));
        t.push(Step::external("publish", "git push"));
        t.push(Step::local("write notes"));
        t
    }

    #[test]
    fn a_step_that_pushes_is_recognised_as_external() {
        // B-06's second acceptance criterion, for the shapes this repository produces.
        for (name, args, expected) in [
            ("git", vec!["push", "origin", "main"], true),
            ("git", vec!["push"], true),
            ("git", vec!["status"], false),
            ("curl", vec!["https://example.invalid"], true),
            ("npm", vec!["publish"], true),
            ("cargo", vec!["test"], false),
            ("kubectl", vec!["apply", "-f", "x.yaml"], true),
        ] {
            let effect = classify(name, &args);
            assert_eq!(
                effect.is_external(),
                expected,
                "`{name} {}` classified as {}",
                args.join(" "),
                effect.label()
            );
        }
    }

    #[test]
    fn forking_after_an_external_step_is_refused_and_names_it() {
        // B-06's third acceptance criterion.
        let t = trace_with_a_push();
        let err = t.fork_after(3, 3).expect_err("must refuse");
        let text = format!("{err}");
        assert!(
            text.contains("publish"),
            "it must name the step, got: {text}"
        );
        assert!(
            text.contains("git push"),
            "it must name what was reached, got: {text}"
        );
        assert!(
            text.contains("once per branch"),
            "it must say what would go wrong, got: {text}"
        );
    }

    #[test]
    fn forking_before_an_external_step_is_allowed() {
        // The effect has not happened yet, so no branch can replay it. The rule is about the
        // prefix, not about the trace.
        let t = trace_with_a_push();
        let fork = t.fork_after(2, 3).expect("forking before the push is fine");
        assert_eq!(fork.fork_after, 2);
        assert_eq!(fork.branches, 3);
        assert_eq!(fork.shared, vec!["write source", "run tests", "commit"]);
        assert!(fork.external_in_prefix.is_empty());
    }

    #[test]
    fn forking_after_the_push_but_before_anything_else_is_still_refused() {
        // The failure a "check only the fork point" rule would miss: step 3 is external, step 4
        // is not, and a fork after step 4 would still resume past the push.
        let t = trace_with_a_push();
        assert!(
            t.can_fork_after(3).is_err(),
            "the fork point itself is external"
        );
        assert!(
            t.can_fork_after(4).is_err(),
            "step 4 is local, but its prefix contains the push -- and a branch resumed there \
             has no record of it"
        );
    }

    #[test]
    fn the_forkable_points_are_exactly_the_prefix_before_the_first_escape() {
        let t = trace_with_a_push();
        assert_eq!(t.forkable_points(), vec![0, 1, 2]);
    }

    #[test]
    fn a_trace_with_no_external_step_is_forkable_anywhere() {
        let mut t = Trace::new();
        for name in ["a", "b", "c"] {
            t.push(Step::local(name));
        }
        assert_eq!(t.forkable_points(), vec![0, 1, 2]);
        for at in 0..3 {
            t.fork_after(at, 2).expect("every point is forkable");
        }
    }

    #[test]
    fn forking_past_the_end_is_refused() {
        let t = trace_with_a_push();
        let err = t.fork_after(99, 2).expect_err("must refuse");
        assert!(format!("{err}").contains("past the end"), "got: {err}");
    }

    #[test]
    fn a_fork_with_one_branch_is_refused() {
        // A fork with one branch is a rename, and accepting it would make "how many branches"
        // unanswerable from the record.
        let t = trace_with_a_push();
        let err = t.fork_after(1, 1).expect_err("must refuse");
        assert!(format!("{err}").contains("a rename"), "got: {err}");
    }

    #[test]
    fn an_empty_trace_admits_no_fork_point() {
        let t = Trace::new();
        assert!(t.is_empty());
        assert!(t.forkable_points().is_empty());
        assert!(t.fork_after(0, 2).is_err());
        assert!(t.first_external().is_none());
    }

    #[test]
    fn the_first_external_step_is_reported_with_its_index() {
        let t = trace_with_a_push();
        let (index, step) = t.first_external().expect("there is one");
        assert_eq!(index, 3);
        assert_eq!(step.name, "publish");
        assert_eq!(step.effect.target(), Some("git push"));
        assert!(!Step::local("x").effect.is_external());
        assert!(Step::local("x").effect.target().is_none());
    }

    #[test]
    fn a_declared_effect_is_not_overridden_by_the_classifier() {
        // The asymmetry the module documentation argues for: the classifier may promote, and a
        // caller's declaration is what the trace carries. This test pins the half that matters --
        // a step named like a local one but declared external stays external.
        let mut t = Trace::new();
        t.push(Step::local("write source"));
        // A name the classifier would never flag, declared external by a caller who knows it
        // reaches a private service through a wrapper.
        t.push(Step::external("sync", "internal registry"));
        assert_eq!(
            t.first_external().map(|(i, _)| i),
            Some(1),
            "a declared effect must be carried, not re-derived from the name"
        );
        let err = t.fork_after(1, 2).expect_err("must refuse");
        assert!(
            format!("{err}").contains("internal registry"),
            "the refusal must name the declared target, got: {err}"
        );
    }

    #[test]
    fn the_branch_owned_count_is_the_steps_after_the_fork_point() {
        let t = trace_with_a_push();
        let fork = t.fork_after(2, 4).expect("fork");
        assert_eq!(
            fork.branch_owned(t.len()),
            2,
            "steps 3 and 4 belong to the branches"
        );
    }

    #[test]
    fn a_trace_survives_a_round_trip_through_json() {
        let t = trace_with_a_push();
        let text = serde_json::to_string(&t).expect("serialise");
        let back: Trace = serde_json::from_str(&text).expect("deserialise");
        assert_eq!(t, back);
        assert_eq!(back.forkable_points(), vec![0, 1, 2]);
    }
}
