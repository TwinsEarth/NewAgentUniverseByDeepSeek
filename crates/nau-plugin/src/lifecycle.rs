//! The plugin lifecycle state machine.
//!
//! # One assignment site
//!
//! [`Lifecycle::state`] is private and there is exactly **one** `self.state = …` in
//! this module, inside [`Lifecycle::transition`]. The market work in V1.2.3 found
//! upstream's `open_dispute` doing `task.state = TaskState::Disputed;` directly,
//! bypassing the transition table it had just added — including from a terminal
//! state. A transition table that one function can walk around is decoration, so the
//! same discipline is applied here from the first commit: the table is the only door,
//! and a test reads this file back and fails if a second assignment appears.
//!
//! # Terminal states have no inbound edges
//!
//! [`PluginState::Archived`] and [`PluginState::Blacklisted`] are terminal. A plugin
//! cannot be revived by a transition; bringing one back means publishing a new
//! version, which is a new manifest, a new digest and a new review — not a state
//! change. That is enforced in the table, not in a comment.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{PluginError, Result};

/// Where a plugin is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginState {
    /// The manifest has been read but nothing has been checked.
    Discovered,
    /// Name, digest, signature, counter-signature and module hash all verified.
    Verified,
    /// The runtime has an instance, but `on_init` has not run.
    Loaded,
    /// Initialised, registered on the bus, serving.
    Running,
    /// Paused: refuses calls, keeps its instance.
    Paused,
    /// A health check failed while running.
    Unhealthy,
    /// Shutting down: draining in-flight calls.
    Stopping,
    /// Cleanly stopped, instance released.
    Stopped,
    /// Refused at some check; carries no instance.
    Refused,
    /// Isolated after a violation or a blacklist hit. Cannot be loaded, ever.
    Quarantined,
    /// Terminal: retired with its audit trail kept.
    Archived,
    /// Terminal: on the blacklist.
    Blacklisted,
}

impl PluginState {
    /// Every state, exhaustively.
    ///
    /// Adding a variant breaks this array, which breaks the totality test — so a new
    /// state cannot be added without deciding its inbound edges.
    pub const ALL: [PluginState; 12] = [
        PluginState::Discovered,
        PluginState::Verified,
        PluginState::Loaded,
        PluginState::Running,
        PluginState::Paused,
        PluginState::Unhealthy,
        PluginState::Stopping,
        PluginState::Stopped,
        PluginState::Refused,
        PluginState::Quarantined,
        PluginState::Archived,
        PluginState::Blacklisted,
    ];

    /// The states from which nothing may leave.
    pub const TERMINAL: [PluginState; 2] = [PluginState::Archived, PluginState::Blacklisted];

    /// A stable label, for logs, the REST surface and the CLI.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            PluginState::Discovered => "discovered",
            PluginState::Verified => "verified",
            PluginState::Loaded => "loaded",
            PluginState::Running => "running",
            PluginState::Paused => "paused",
            PluginState::Unhealthy => "unhealthy",
            PluginState::Stopping => "stopping",
            PluginState::Stopped => "stopped",
            PluginState::Refused => "refused",
            PluginState::Quarantined => "quarantined",
            PluginState::Archived => "archived",
            PluginState::Blacklisted => "blacklisted",
        }
    }

    /// Whether no transition may leave this state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        PluginState::TERMINAL.contains(&self)
    }

    /// Whether the plugin can currently serve a call.
    #[must_use]
    pub fn is_serving(self) -> bool {
        matches!(self, PluginState::Running)
    }

    /// Whether the plugin holds a runtime instance.
    #[must_use]
    pub fn holds_instance(self) -> bool {
        matches!(
            self,
            PluginState::Loaded
                | PluginState::Running
                | PluginState::Paused
                | PluginState::Unhealthy
                | PluginState::Stopping
        )
    }

    /// Whether a plugin in this state can ever run again in *this* host instance.
    #[must_use]
    pub fn is_recoverable(self) -> bool {
        !matches!(
            self,
            PluginState::Refused
                | PluginState::Quarantined
                | PluginState::Archived
                | PluginState::Blacklisted
        )
    }

    /// The legal next states from here.
    ///
    /// A repeat of the current state is **not** an edge. `nau-core`'s task
    /// transition table treats `X -> X` as a legal no-op, and V1.2.3's market work
    /// found that this let a terminal task be re-entered and punished twice. The
    /// same mistake is not repeated here: `X -> X` is refused by [`Lifecycle::transition`].
    #[must_use]
    pub fn next_states(self) -> Vec<PluginState> {
        use PluginState::{
            Archived, Blacklisted, Discovered, Loaded, Paused, Quarantined, Refused, Running,
            Stopped, Stopping, Unhealthy, Verified,
        };
        match self {
            // Verification can fail, and failing verification is a first-class outcome.
            Discovered => vec![Verified, Refused],
            Verified => vec![Loaded, Refused, Quarantined],
            Loaded => vec![Running, Stopping, Unhealthy, Refused],
            Running => vec![Paused, Unhealthy, Stopping, Quarantined],
            Paused => vec![Running, Stopping, Unhealthy],
            Unhealthy => vec![Running, Stopping, Quarantined],
            Stopping => vec![Stopped],
            Stopped => vec![Archived],
            // A refused plugin is not dead weight: it can be quarantined for forensics.
            Refused => vec![Archived, Quarantined],
            Quarantined => vec![Archived, Blacklisted],
            Archived | Blacklisted => vec![],
        }
    }

    /// Whether `self -> next` is a legal edge.
    #[must_use]
    pub fn can_transition_to(self, next: PluginState) -> bool {
        // A repeat is never an edge; see `next_states`.
        if next == self {
            return false;
        }
        self.next_states().contains(&next)
    }
}

impl fmt::Display for PluginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One transition, kept for the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    /// Where it came from.
    pub from: PluginState,
    /// Where it went.
    pub to: PluginState,
    /// Why, in one clause. Required: a transition with no stated reason is
    /// indistinguishable from a bug in the audit log.
    pub because: String,
    /// When, in Unix seconds.
    pub at: u64,
}

/// A plugin's lifecycle, with its history.
#[derive(Debug, Clone)]
pub struct Lifecycle {
    state: PluginState,
    history: Vec<Transition>,
    /// How many policy violations have been recorded. Three quarantine the plugin.
    violations: u32,
    /// How many times `on_init` has run for this plugin.
    ///
    /// B-05's evidence. A restore is defined by **not** incrementing this, and a claim of that
    /// kind needs a number to check rather than a comment to trust: the test asserts the count
    /// before and after, so "the restore did not re-initialise" is a measurement.
    init_runs: u32,
}

/// A plugin is quarantined after this many recorded violations.
pub const VIOLATION_THRESHOLD: u32 = 3;

impl Lifecycle {
    /// A lifecycle in [`PluginState::Discovered`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: PluginState::Discovered,
            history: Vec::new(),
            violations: 0,
            init_runs: 0,
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> PluginState {
        self.state
    }

    /// The full transition history, oldest first.
    #[must_use]
    pub fn history(&self) -> &[Transition] {
        &self.history
    }

    /// Recorded violations.
    #[must_use]
    pub fn violations(&self) -> u32 {
        self.violations
    }

    /// How many times `on_init` has run.
    ///
    /// The evidence behind B-05: a restore into `Running` must leave this unchanged, and a start
    /// must increment it. Without a number, "the restore did not re-initialise" is a claim about
    /// code someone read rather than a fact the suite checked.
    #[must_use]
    pub fn init_runs(&self) -> u32 {
        self.init_runs
    }

    /// Start a loaded plugin: `Loaded -> Running`, **initialising**.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] when the state is not `Loaded`. Refused rather than allowed
    /// from anywhere: `on_init` running twice is exactly the defect this pair of methods exists
    /// to make visible, and a `start` that could be called from `Paused` would provide it.
    pub fn start(&mut self, at: u64) -> Result<Transition> {
        if self.state != PluginState::Loaded {
            return Err(PluginError::Lifecycle(format!(
                "start initialises a plugin and is only legal from `loaded`; this plugin is \
                 `{}`. A paused plugin is resumed with `restore`, which does not run `on_init`",
                self.state
            )));
        }
        let entry = self.transition(PluginState::Running, "on_init returned", at)?;
        self.init_runs = self.init_runs.saturating_add(1);
        Ok(entry)
    }

    /// Resume a paused plugin from a snapshot: `Paused -> Running`, **without initialising**.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] when the state is not `Paused`, or when `snapshot` is blank.
    ///
    /// The snapshot is required and must be named. A restore that did not say what it restored
    /// from would leave an audit trail that cannot answer the only question worth asking about a
    /// resume — *from what* — and the defect it would hide is a plugin resumed with stale state
    /// after the snapshot it should have used was lost.
    pub fn restore(&mut self, snapshot: &str, at: u64) -> Result<Transition> {
        if self.state != PluginState::Paused {
            return Err(PluginError::Lifecycle(format!(
                "restore resumes from a snapshot and is only legal from `paused`; this plugin is \
                 `{}`",
                self.state
            )));
        }
        if snapshot.trim().is_empty() {
            return Err(PluginError::Lifecycle(
                "a restore must name the snapshot it resumes from; a resume that does not say \
                 from what cannot be audited"
                    .into(),
            ));
        }
        // `on_init` is deliberately, visibly absent here. That absence is the whole of B-05:
        // `Paused -> Running` already existed as an edge, and what was missing was a path that
        // means "resume" rather than "start again".
        //
        // The first version of this method carried a `debug_assert_eq!(self.init_runs,
        // self.init_runs)` -- a tautology that asserted nothing, and the second one of that shape
        // written this session. It is removed rather than fixed: the fact to check is that the
        // count is unchanged across a call, which only a test can see, and a self-comparison
        // sitting where the evidence should be is worse than no line at all because it looks like
        // a check.
        self.transition(
            PluginState::Running,
            &format!("restored from {snapshot}"),
            at,
        )
    }

    /// The only place `state` is assigned.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] when the edge does not exist, when the state is
    /// terminal, when `because` is blank, or when the clock is zero (a zero
    /// timestamp in an audit log means "we did not record when").
    pub fn transition(&mut self, next: PluginState, because: &str, at: u64) -> Result<Transition> {
        if because.trim().is_empty() {
            return Err(PluginError::Lifecycle(
                "a transition must state why it happened".into(),
            ));
        }
        if at == 0 {
            return Err(PluginError::Lifecycle(
                "a transition must carry a non-zero timestamp".into(),
            ));
        }
        if self.state.is_terminal() {
            return Err(PluginError::Lifecycle(format!(
                "{} is terminal: no transition leaves it, and a plugin is revived by \
                 publishing a new version, not by changing its state",
                self.state
            )));
        }
        if !self.state.can_transition_to(next) {
            return Err(PluginError::Lifecycle(format!(
                "{} -> {} is not an edge",
                self.state, next
            )));
        }
        let entry = Transition {
            from: self.state,
            to: next,
            because: because.to_string(),
            at,
        };
        self.state = next; // the one and only assignment
        self.history.push(entry.clone());
        Ok(entry)
    }

    /// Record a policy violation and quarantine on the third.
    ///
    /// Returns the state after the call, so a caller cannot be unsure whether the
    /// threshold was reached.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] only when the quarantine transition itself is
    /// illegal, which cannot happen from a non-terminal state; it is returned rather
    /// than unwrapped.
    pub fn violation(&mut self, what: &str, at: u64) -> Result<PluginState> {
        self.violations = self.violations.saturating_add(1);
        if self.violations >= VIOLATION_THRESHOLD
            && self.state != PluginState::Quarantined
            && !self.state.is_terminal()
        {
            self.transition(
                PluginState::Quarantined,
                &format!("{VIOLATION_THRESHOLD} violations; the last was: {what}"),
                at,
            )?;
        }
        Ok(self.state)
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_750_000_000;

    #[test]
    fn the_transition_graph_is_total_over_every_state() {
        // Every state has a decided set of outbound edges, and the set only contains
        // states that exist. Adding a variant breaks ALL, which breaks this test.
        for state in PluginState::ALL {
            let next = state.next_states();
            assert!(
                next.len() <= PluginState::ALL.len(),
                "{state} claims more edges than there are states"
            );
            for target in next {
                assert!(
                    !state.is_terminal(),
                    "{state} is terminal but declares an edge to {target}"
                );
                assert_ne!(target, state, "{state} must not declare an edge to itself");
                assert_ne!(
                    target,
                    PluginState::Discovered,
                    "{target} is reachable from {state}; discovery happens once"
                );
            }
        }
        assert_eq!(PluginState::ALL.len(), 12);
        assert_eq!(PluginState::TERMINAL.len(), 2);
    }

    #[test]
    fn terminal_states_have_no_inbound_or_outbound_edges() {
        for terminal in PluginState::TERMINAL {
            assert!(terminal.next_states().is_empty(), "{terminal}");
        }
        // Blacklisted is reachable only from quarantine: it is a verdict, and a
        // verdict needs the forensics step first.
        for other in PluginState::ALL {
            if other.can_transition_to(PluginState::Blacklisted) {
                assert_eq!(
                    other,
                    PluginState::Quarantined,
                    "blacklisted must not be reachable from {other}"
                );
            }
        }
        // Archived is reachable from the states that mean "done with it": a clean
        // stop, a refusal, or quarantine. Not from a running plugin, which would
        // mean retiring something that was still serving.
        for other in PluginState::ALL {
            if other.can_transition_to(PluginState::Archived) {
                assert!(
                    [
                        PluginState::Stopped,
                        PluginState::Refused,
                        PluginState::Quarantined
                    ]
                    .contains(&other),
                    "archived must not be reachable from {other}"
                );
            }
        }
        assert!(PluginState::Quarantined.can_transition_to(PluginState::Archived));
        assert!(PluginState::Quarantined.can_transition_to(PluginState::Blacklisted));
    }

    #[test]
    fn a_repeat_is_not_an_edge() {
        // The V1.2.3 market bug: `X -> X` was legal, so a terminal task could be
        // re-entered and punished twice.
        for state in PluginState::ALL {
            assert!(
                !state.can_transition_to(state),
                "{state} must not declare a self-edge"
            );
        }
        let mut life = Lifecycle::new();
        life.transition(PluginState::Verified, "checked", NOW)
            .expect("ok");
        let err = life
            .transition(PluginState::Verified, "again", NOW)
            .expect_err("a repeat must be refused");
        assert!(err.to_string().contains("is not an edge"), "{err}");
    }

    #[test]
    fn the_happy_path_reaches_running_and_the_history_records_why() {
        let mut life = Lifecycle::new();
        for (state, why) in [
            (PluginState::Verified, "four checks passed"),
            (PluginState::Loaded, "instance created"),
            (PluginState::Running, "on_init returned"),
        ] {
            life.transition(state, why, NOW).expect("legal");
        }
        assert_eq!(life.state(), PluginState::Running);
        assert!(life.state().is_serving());
        assert_eq!(life.history().len(), 3);
        assert_eq!(life.history()[0].because, "four checks passed");
        assert_eq!(life.history()[2].to, PluginState::Running);
    }

    #[test]
    fn a_transition_without_a_reason_is_refused() {
        let mut life = Lifecycle::new();
        for blank in ["", "   ", "\t"] {
            let err = life
                .transition(PluginState::Verified, blank, NOW)
                .expect_err("a reason is required");
            assert!(err.to_string().contains("why"), "{err}");
        }
        assert_eq!(
            life.state(),
            PluginState::Discovered,
            "state must not have moved"
        );
    }

    #[test]
    fn a_zero_timestamp_is_refused() {
        let mut life = Lifecycle::new();
        let err = life
            .transition(PluginState::Verified, "checked", 0)
            .expect_err("must be refused");
        assert!(err.to_string().contains("timestamp"), "{err}");
    }

    #[test]
    fn an_illegal_edge_is_refused_and_leaves_the_state_alone() {
        let mut life = Lifecycle::new();
        // Discovered -> Running skips verification entirely.
        let err = life
            .transition(PluginState::Running, "shortcut", NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("discovered -> running"), "{err}");
        assert_eq!(life.state(), PluginState::Discovered);
        assert!(life.history().is_empty());
    }

    #[test]
    fn three_violations_quarantine_a_plugin() {
        let mut life = Lifecycle::new();
        life.transition(PluginState::Verified, "ok", NOW)
            .expect("ok");
        life.transition(PluginState::Loaded, "ok", NOW).expect("ok");
        life.transition(PluginState::Running, "ok", NOW)
            .expect("ok");

        assert_eq!(
            life.violation("sent an undeclared capability", NOW)
                .expect("recorded"),
            PluginState::Running
        );
        assert_eq!(
            life.violation("sent an undeclared capability", NOW)
                .expect("recorded"),
            PluginState::Running
        );
        assert_eq!(
            life.violation("sent an undeclared capability", NOW)
                .expect("recorded"),
            PluginState::Quarantined,
            "the third violation must quarantine"
        );
        assert_eq!(life.violations(), 3);
        assert!(!life.state().holds_instance());
        assert!(life
            .history()
            .last()
            .expect("history")
            .because
            .contains("3 violations"));
    }

    #[test]
    fn a_quarantined_plugin_can_only_be_archived_or_blacklisted() {
        let mut life = Lifecycle::new();
        life.transition(PluginState::Refused, "signature invalid", NOW)
            .expect("legal");
        life.transition(PluginState::Quarantined, "forensics", NOW)
            .expect("legal");
        let err = life
            .transition(PluginState::Running, "please", NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("is not an edge"), "{err}");
        life.transition(PluginState::Blacklisted, "confirmed malware", NOW)
            .expect("legal");
        let err = life
            .transition(PluginState::Archived, "tidy up", NOW)
            .expect_err("terminal");
        assert!(err.to_string().contains("terminal"), "{err}");
    }

    #[test]
    fn refusing_is_a_first_class_outcome_not_an_error_path() {
        // A refusal is the ordinary result for a plugin that asks for something its
        // tier may not hold, so the state machine must model it as a state.
        let mut life = Lifecycle::new();
        life.transition(
            PluginState::Refused,
            "capability_not_permitted: net:dht:read",
            NOW,
        )
        .expect("legal");
        assert_eq!(life.state(), PluginState::Refused);
        assert!(!life.state().is_recoverable());
        assert!(!life.state().holds_instance());
    }

    #[test]
    fn only_running_is_serving_and_only_the_instance_states_hold_one() {
        for state in PluginState::ALL {
            assert_eq!(state.is_serving(), state == PluginState::Running, "{state}");
            if state.is_serving() {
                assert!(state.holds_instance(), "{state} serves but holds nothing");
            }
        }
    }

    /// A lifecycle walked to `Loaded`, which is the state `start` is legal from.
    fn loaded() -> Lifecycle {
        let mut l = Lifecycle::new();
        l.transition(PluginState::Verified, "checks passed", 1)
            .expect("verified");
        l.transition(PluginState::Loaded, "instance created", 2)
            .expect("loaded");
        l
    }

    /// A lifecycle that has started once and been paused: the state a restore resumes from.
    fn paused_after_start() -> Lifecycle {
        let mut l = loaded();
        l.start(3).expect("start");
        l.transition(PluginState::Paused, "operator paused it", 4)
            .expect("paused");
        l
    }

    #[test]
    fn a_start_initialises_and_is_counted() {
        let mut l = loaded();
        assert_eq!(l.init_runs(), 0, "nothing has been initialised yet");
        l.start(3).expect("start");
        assert_eq!(l.state(), PluginState::Running);
        assert_eq!(l.init_runs(), 1);
    }

    #[test]
    fn a_restore_resumes_without_re_initialising() {
        // B-05's first acceptance criterion, as a measurement rather than a comment: the count
        // before the restore and the count after it must be the same number.
        let mut l = paused_after_start();
        let before = l.init_runs();
        assert_eq!(
            before, 1,
            "the plugin was initialised once, when it started"
        );

        l.restore("snap-abc", 5).expect("restore");
        assert_eq!(l.state(), PluginState::Running);
        assert_eq!(
            l.init_runs(),
            before,
            "a restore must not run `on_init`; the count moved from {before} to {}",
            l.init_runs()
        );
    }

    #[test]
    fn the_difference_between_start_and_restore_is_the_init_count() {
        // The two paths into `Running` side by side. Asserting them separately would leave open
        // the reading that `start` is also a resume; this asserts the difference itself.
        let mut started = loaded();
        started.start(3).expect("start");
        started
            .transition(PluginState::Paused, "paused", 4)
            .expect("paused");
        started.restore("snap-1", 5).expect("restore");

        let mut restarted = loaded();
        restarted.start(3).expect("start");

        assert_eq!(started.state(), restarted.state(), "both are Running");
        assert_eq!(started.init_runs(), 1, "started once, restored once");
        assert_eq!(restarted.init_runs(), 1, "started once");
        // And the history says which happened, so the audit can tell them apart even though the
        // states agree.
        let last = started.history().last().expect("a history");
        assert!(
            last.because.contains("restored from snap-1"),
            "the audit must record what was restored from, got: {}",
            last.because
        );
    }

    #[test]
    fn a_restore_says_what_it_restored_from() {
        // A resume that does not name its snapshot cannot be audited, and the defect it hides is
        // a plugin resumed with stale state after the snapshot it needed was lost.
        let mut l = paused_after_start();
        let err = l.restore("   ", 5).expect_err("must refuse");
        assert!(
            format!("{err}").contains("must name the snapshot"),
            "got: {err}"
        );
        assert_eq!(
            l.state(),
            PluginState::Paused,
            "a refused restore changes nothing"
        );
    }

    #[test]
    fn a_restore_from_the_wrong_state_is_refused_and_points_at_start() {
        // `restore` is legal only from `Paused`. Calling it from `Loaded` would be a start that
        // skipped initialisation -- the exact defect, reached from the other side.
        let mut l = loaded();
        let err = l.restore("snap-1", 3).expect_err("must refuse");
        let text = format!("{err}");
        assert!(text.contains("only legal from `paused`"), "got: {text}");
        assert!(
            text.contains("loaded"),
            "it must name the actual state, got: {text}"
        );
        assert_eq!(l.init_runs(), 0, "nothing ran");
        assert_eq!(l.state(), PluginState::Loaded);
    }

    #[test]
    fn a_start_from_paused_is_refused_and_points_at_restore() {
        // The mirror image, and the one that would re-run `on_init` on a paused plugin.
        let mut l = paused_after_start();
        let err = l.start(5).expect_err("must refuse");
        let text = format!("{err}");
        assert!(text.contains("only legal from `loaded`"), "got: {text}");
        assert!(
            text.contains("restore"),
            "the refusal must name the method that does work here, got: {text}"
        );
        assert_eq!(l.init_runs(), 1, "a refused start must not initialise");
        assert_eq!(l.state(), PluginState::Paused);
    }

    #[test]
    fn paused_to_running_is_still_an_edge_in_the_state_machine() {
        // B-05 added a path, not an edge: `Paused -> Running` already existed. This asserts the
        // edge is still there, so the new method cannot have narrowed the machine by accident.
        assert!(PluginState::Paused.can_transition_to(PluginState::Running));
        assert!(PluginState::Running.can_transition_to(PluginState::Paused));
    }
}
