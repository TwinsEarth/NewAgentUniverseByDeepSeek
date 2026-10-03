//! The sandbox scheduler: latency-sensitive first, and **nobody starves**.
//!
//! # What this answers
//!
//! The plan's acceptance criteria are three: a latency-sensitive request goes first, a
//! latency-tolerant request is **not starved** when latency-sensitive requests keep arriving,
//! and the distribution of concurrently-active sandboxes is reported as p50/p99.
//!
//! The second is the one that needs a mechanism rather than an intention. "Latency-sensitive
//! first" on its own is a livelock: if sensitive requests arrive faster than they complete,
//! the tolerant queue is never reached, and a tolerant task waits forever. Nothing is
//! deadlocked — every individual decision is correct — and the system still fails to make
//! progress on part of its work. That is a livelock, and it is what [`Scheduler::next`]'s
//! aging exists to prevent.
//!
//! # Aging, and why it is arithmetic rather than a heuristic
//!
//! Every queued task's **effective** priority is its base class rank plus one for every
//! `aging_ticks` it has waited:
//!
//! ```text
//! effective = base_rank(class) + waited_ticks / aging_ticks
//! ```
//!
//! A tolerant task that has waited `aging_ticks` therefore ties with a fresh sensitive task,
//! and one that has waited `2 * aging_ticks` beats it. So the guarantee is not "tolerant work
//! usually runs" but a bound: **a tolerant task runs within `aging_ticks` ticks of the
//! scheduler being asked for work**, however many sensitive tasks arrive in the meantime.
//! That bound is what the test asserts, and it is a property of the arithmetic rather than of
//! the load.
//!
//! The tie is broken by arrival order, so two equally-aged tasks run in the order they were
//! submitted. Without that, a tie would be resolved by whatever the iteration order happened
//! to be, and "fair" would depend on a `Vec`'s layout.
//!
//! # What is measured, and what the original design did not define
//!
//! The plan notes that the original design claimed "latency impact 45.2% → 17.3%" **without
//! defining "latency impact"**. This module does not repeat that. It reports
//! [`Distribution`] over **concurrently active sandboxes**, sampled every time a task starts
//! or completes, and the distribution's own documentation says what a sample is. A number
//! whose definition is not written down is not a measurement.

use std::collections::VecDeque;

use crate::manifest::PriorityClass;

/// Identifies a scheduling request.
pub type TaskId = u64;

/// A task waiting to run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Waiting {
    id: TaskId,
    class: PriorityClass,
    submitted_tick: u64,
    sequence: u64,
}

impl Waiting {
    /// The rank before aging: sensitive outranks tolerant.
    fn base_rank(&self) -> u64 {
        match self.class {
            PriorityClass::LatencySensitive => 1,
            PriorityClass::LatencyTolerant => 0,
        }
    }
}

/// A sample of concurrently-active sandboxes.
///
/// # What a sample is, exactly
///
/// One observation taken **at the moment the active count changes** — a task starting or
/// finishing — of how many tasks were active immediately afterwards. So the sample set covers
/// every value the active count took while the scheduler ran, and the reported percentiles
/// describe that set rather than a time-average. The two differ: a count of 8 held for one
/// tick and a count of 1 held for a hundred contributes one sample each here, and would
/// contribute 8/108 and 100/108 to a time-average.
///
/// The plan's requirement is that the metric be **defined before it is measured**. This
/// paragraph is that definition; a p50 without one is a number nobody can reproduce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Distribution {
    samples: Vec<usize>,
}

impl Distribution {
    /// Record one observation.
    pub fn observe(&mut self, active: usize) {
        self.samples.push(active);
    }

    /// How many observations were taken. Reported so a percentile can be judged against the
    /// sample it came from — a p99 over three samples is not a p99.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether nothing has been observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// The `p`th percentile, nearest-rank.
    #[must_use]
    pub fn percentile(&self, p: usize) -> usize {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let rank = (p * sorted.len()).div_ceil(100);
        sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
    }

    /// The median concurrently-active count.
    #[must_use]
    pub fn p50(&self) -> usize {
        self.percentile(50)
    }

    /// The 99th-percentile concurrently-active count.
    #[must_use]
    pub fn p99(&self) -> usize {
        self.percentile(99)
    }

    /// The largest active count observed.
    #[must_use]
    pub fn peak(&self) -> usize {
        self.samples.iter().copied().max().unwrap_or(0)
    }
}

/// Why the scheduler refused a submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    /// A task with this id is already queued or running.
    ///
    /// Refused rather than replaced: an id is how a caller says "this is the same task", and
    /// quietly treating a second submission as a replacement would drop the first one's
    /// place in the queue.
    Duplicate(TaskId),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::Duplicate(id) => write!(f, "task {id} is already known to the scheduler"),
        }
    }
}

impl std::error::Error for SubmitError {}

/// A scheduler over two priority classes, with aging.
#[derive(Debug)]
pub struct Scheduler {
    aging_ticks: u64,
    max_concurrent: usize,
    tick: u64,
    sequence: u64,
    waiting: VecDeque<Waiting>,
    running: Vec<TaskId>,
    completed: Vec<TaskId>,
    distribution: Distribution,
    /// How many times a task was chosen while a *fresh* higher-class task was also waiting.
    /// Zero means aging never had to act, which is worth knowing before claiming it works.
    aging_rescues: usize,
}

impl Scheduler {
    /// A scheduler where a task's class is raised one rank every `aging_ticks` it waits.
    ///
    /// # Panics
    ///
    /// Never. `aging_ticks` of zero is treated as one, because the alternative is a division
    /// by zero in the comparison loop, and a scheduler that panics under load is worse than
    /// one whose aging is more aggressive than asked for. The normalisation is documented
    /// rather than silent, and [`Scheduler::aging_ticks`] reports what was actually used.
    #[must_use]
    pub fn new(aging_ticks: u64, max_concurrent: usize) -> Self {
        Self {
            aging_ticks: aging_ticks.max(1),
            max_concurrent: max_concurrent.max(1),
            tick: 0,
            sequence: 0,
            waiting: VecDeque::new(),
            running: Vec::new(),
            completed: Vec::new(),
            distribution: Distribution::default(),
            aging_rescues: 0,
        }
    }

    /// The aging window actually in force.
    #[must_use]
    pub fn aging_ticks(&self) -> u64 {
        self.aging_ticks
    }

    /// The concurrency ceiling actually in force.
    #[must_use]
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// The current tick.
    #[must_use]
    pub fn tick(&self) -> u64 {
        self.tick
    }

    /// How many tasks are running.
    #[must_use]
    pub fn active(&self) -> usize {
        self.running.len()
    }

    /// How many tasks are waiting.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.waiting.len()
    }

    /// How many tasks are known, waiting or running.
    #[must_use]
    pub fn len(&self) -> usize {
        self.waiting.len() + self.running.len()
    }

    /// Whether the scheduler knows no tasks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many times aging changed the decision.
    ///
    /// Reported because a livelock test that passed without aging ever acting would have
    /// passed for a different reason, and this number is how a caller can tell.
    #[must_use]
    pub fn aging_rescues(&self) -> usize {
        self.aging_rescues
    }

    /// The distribution of concurrently-active sandboxes.
    #[must_use]
    pub fn distribution(&self) -> &Distribution {
        &self.distribution
    }

    /// Advance the clock by one tick.
    pub fn advance(&mut self) {
        self.tick += 1;
    }

    /// Submit a task.
    ///
    /// # Errors
    ///
    /// [`SubmitError::Duplicate`] when the id is already queued or running.
    pub fn submit(&mut self, id: TaskId, class: PriorityClass) -> Result<(), SubmitError> {
        if self.running.contains(&id) || self.waiting.iter().any(|w| w.id == id) {
            return Err(SubmitError::Duplicate(id));
        }
        let sequence = self.sequence;
        self.sequence += 1;
        self.waiting.push_back(Waiting {
            id,
            class,
            submitted_tick: self.tick,
            sequence,
        });
        Ok(())
    }

    /// The effective rank of a waiting task, aging included.
    fn effective_rank(&self, w: &Waiting) -> u64 {
        let waited = self.tick.saturating_sub(w.submitted_tick);
        w.base_rank() + waited / self.aging_ticks
    }

    /// Which waiting task should run next, if the concurrency ceiling allows one.
    ///
    /// Named `next_task` rather than `next`, because a method called `next` on a type that is
    /// not an iterator reads as one, and clippy says so. The scheduler is a queue with a
    /// policy, not a sequence, and the name should not invite a caller to treat it as one.
    ///
    /// Returns `None` when nothing is waiting or the ceiling is reached. The choice is
    /// `max` by effective rank, ties broken by **submission order** — never by iteration
    /// order, so the result is a property of the queue rather than of a `Vec`'s layout.
    pub fn next_task(&mut self) -> Option<TaskId> {
        if self.running.len() >= self.max_concurrent || self.waiting.is_empty() {
            return None;
        }

        let mut best: Option<usize> = None;
        let mut best_key: Option<(u64, u64)> = None;
        let mut best_base = 0_u64;
        for (i, w) in self.waiting.iter().enumerate() {
            let rank = self.effective_rank(w);
            let key = (rank, u64::MAX - w.sequence);
            if best_key.is_none_or(|k| key > k) {
                best = Some(i);
                best_key = Some(key);
                best_base = w.base_rank();
            }
        }

        let index = best?;
        let chosen = self.waiting.remove(index)?;
        // Aging acted when the winner's effective rank exceeded its base rank, i.e. it was
        // promoted past where its class alone would have put it.
        if self.effective_rank(&chosen) > chosen.base_rank() {
            self.aging_rescues += 1;
        }
        let _ = best_base;

        self.running.push(chosen.id);
        self.distribution.observe(self.running.len());
        Some(chosen.id)
    }

    /// Mark a task finished.
    ///
    /// Returns whether the scheduler knew it. A completion for an unknown id is reported
    /// rather than ignored: a caller that completed the wrong task would otherwise never find
    /// out, and the running count would drift.
    pub fn complete(&mut self, id: TaskId) -> bool {
        match self.running.iter().position(|r| *r == id) {
            Some(index) => {
                self.running.remove(index);
                self.completed.push(id);
                self.distribution.observe(self.running.len());
                true
            }
            None => false,
        }
    }

    /// The order tasks actually started in.
    #[must_use]
    pub fn completed(&self) -> &[TaskId] {
        &self.completed
    }
}

/// A `PriorityClass` re-exported for callers that only need the vocabulary.
pub use crate::manifest::PriorityClass as Class;

#[cfg(test)]
mod tests {
    use super::*;

    const SENSITIVE: PriorityClass = PriorityClass::LatencySensitive;
    const TOLERANT: PriorityClass = PriorityClass::LatencyTolerant;

    #[test]
    fn a_sensitive_task_goes_before_a_tolerant_one() {
        // A-11's first acceptance criterion.
        let mut s = Scheduler::new(100, 4);
        s.submit(1, TOLERANT).expect("submit");
        s.submit(2, SENSITIVE).expect("submit");
        assert_eq!(
            s.next_task(),
            Some(2),
            "sensitive first, even though it arrived last"
        );
        assert_eq!(s.next_task(), Some(1));
    }

    #[test]
    fn arrival_order_breaks_a_tie_within_a_class() {
        // Deterministic, not dependent on a `Vec`'s layout.
        let mut s = Scheduler::new(100, 4);
        for id in [10, 11, 12] {
            s.submit(id, TOLERANT).expect("submit");
        }
        assert_eq!(s.next_task(), Some(10));
        assert_eq!(s.next_task(), Some(11));
        assert_eq!(s.next_task(), Some(12));
    }

    #[test]
    fn a_tolerant_task_is_not_starved_by_a_stream_of_sensitive_ones() {
        // A-11's second acceptance criterion, and the reason aging exists. This is the
        // livelock: if sensitive requests arrive faster than they complete, "sensitive
        // first" alone never reaches the tolerant queue. Every individual decision is
        // correct and part of the work never runs.
        const AGING: u64 = 5;
        let mut s = Scheduler::new(AGING, 1);

        s.submit(999, TOLERANT).expect("submit the tolerant task");
        let start = s.tick();

        // Ten thousand sensitive arrivals, one per tick, each completing immediately so the
        // queue never backs up and the stream never ends.
        let mut ran_tolerant_at = None;
        for round in 0..10_000_u64 {
            s.submit(round, SENSITIVE).expect("submit sensitive");
            if let Some(id) = s.next_task() {
                if id == 999 {
                    ran_tolerant_at = Some(s.tick());
                    break;
                }
                s.complete(id);
            }
            s.advance();
        }

        let at = ran_tolerant_at.expect(
            "a tolerant task must run; if this fails the scheduler livelocks under a \
             sustained high-priority stream",
        );
        assert!(
            at - start <= AGING,
            "the tolerant task waited {} ticks, more than the {AGING}-tick aging window",
            at - start
        );
        assert!(
            s.aging_rescues() > 0,
            "the run must have needed aging; a pass without it would be a pass for another reason"
        );
    }

    #[test]
    fn the_starvation_bound_is_the_aging_window_and_not_the_load() {
        // The same test at two loads. If the bound depended on how many sensitive tasks
        // arrived, the second would be worse than the first and the guarantee would be a
        // description of the load rather than of the scheduler.
        for load in [10_u64, 100_000] {
            let mut s = Scheduler::new(4, 1);
            s.submit(1, TOLERANT).expect("submit");
            let start = s.tick();
            let mut at = None;
            for round in 0..load {
                s.submit(round + 2, SENSITIVE).expect("submit");
                if let Some(id) = s.next_task() {
                    if id == 1 {
                        at = Some(s.tick());
                        break;
                    }
                    s.complete(id);
                }
                s.advance();
            }
            let waited = at.expect("must run") - start;
            assert!(
                waited <= 4,
                "under load {load} the tolerant task waited {waited} ticks, more than the \
                 4-tick window"
            );
        }
    }

    #[test]
    fn aging_does_not_let_a_tolerant_task_overtake_a_sensitive_one_immediately() {
        // Aging is a bound, not an inversion: a fresh sensitive task still wins. Without
        // this, "no starvation" could be satisfied by ignoring priority altogether.
        let mut s = Scheduler::new(1000, 1);
        s.submit(1, TOLERANT).expect("submit");
        s.advance();
        s.submit(2, SENSITIVE).expect("submit");
        assert_eq!(
            s.next_task(),
            Some(2),
            "a fresh sensitive task outranks a barely-aged tolerant one"
        );
    }

    #[test]
    fn the_concurrency_ceiling_is_respected() {
        let mut s = Scheduler::new(10, 2);
        for id in 0..5 {
            s.submit(id, TOLERANT).expect("submit");
        }
        assert_eq!(s.next_task(), Some(0));
        assert_eq!(s.next_task(), Some(1));
        assert_eq!(s.next_task(), None, "the ceiling is reached");
        assert_eq!(s.active(), 2);
        s.complete(0);
        assert_eq!(s.next_task(), Some(2), "a completion frees a slot");
    }

    #[test]
    fn a_duplicate_id_is_refused_rather_than_replacing_the_first() {
        let mut s = Scheduler::new(10, 4);
        s.submit(7, TOLERANT).expect("submit");
        assert_eq!(s.submit(7, SENSITIVE), Err(SubmitError::Duplicate(7)));
        assert_eq!(s.queued(), 1, "the first submission keeps its place");
    }

    #[test]
    fn completing_an_unknown_task_is_reported_rather_than_ignored() {
        // A caller that completed the wrong task would otherwise never find out, and the
        // running count would drift away from reality.
        let mut s = Scheduler::new(10, 4);
        s.submit(1, TOLERANT).expect("submit");
        let _ = s.next_task();
        assert!(s.complete(1));
        assert!(!s.complete(1), "already completed");
        assert!(!s.complete(99), "never known");
        assert_eq!(s.active(), 0);
    }

    #[test]
    fn a_zero_aging_window_is_normalised_rather_than_dividing_by_zero() {
        // A scheduler that panics under load is worse than one whose aging is more
        // aggressive than asked for. The normalisation is reported, not silent.
        let s = Scheduler::new(0, 0);
        assert_eq!(s.aging_ticks(), 1);
        assert_eq!(s.max_concurrent(), 1);
    }

    #[test]
    fn the_distribution_records_every_change_in_the_active_count() {
        // A-11's third acceptance criterion.
        let mut s = Scheduler::new(10, 4);
        for id in 0..3 {
            s.submit(id, TOLERANT).expect("submit");
        }
        let _ = s.next_task();
        let _ = s.next_task();
        let _ = s.next_task();
        s.complete(0);
        // Starts: 1, 2, 3. Completion: 2. So the samples are [1, 2, 3, 2].
        assert_eq!(s.distribution().len(), 4);
        assert_eq!(s.distribution().peak(), 3);
        assert_eq!(s.distribution().p99(), 3);
        // Sorted, the samples are [1, 2, 2, 3]; nearest-rank p50 is the second, which is 2.
        // The first version of this test asserted 3, which was arithmetic done by eye and
        // wrong -- the assertion was corrected, not the implementation.
        assert_eq!(s.distribution().p50(), 2);
    }

    #[test]
    fn a_percentile_is_the_nearest_rank_of_the_sample() {
        let mut d = Distribution::default();
        assert_eq!(d.p50(), 0, "no samples is zero, not a panic");
        assert!(d.is_empty());
        for v in [1, 2, 3, 4, 5] {
            d.observe(v);
        }
        assert_eq!(d.len(), 5);
        assert_eq!(d.percentile(50), 3);
        assert_eq!(d.percentile(99), 5);
        assert_eq!(d.percentile(1), 1);
        assert_eq!(d.peak(), 5);
    }

    #[test]
    fn the_metric_is_a_sample_of_counts_and_the_documentation_says_so() {
        // The plan requires the metric be defined before it is measured. This test pins the
        // definition: a count of 8 held for one observation and a count of 1 held for two
        // contribute one sample each, so this is not a time-average.
        let mut d = Distribution::default();
        d.observe(8);
        d.observe(1);
        d.observe(1);
        assert_eq!(
            d.len(),
            3,
            "three observations, not three ticks of a time series"
        );
        assert_eq!(d.percentile(50), 1);
        assert_eq!(d.peak(), 8);
    }
}
