//! Swarm memory with **enforced** anti-pollution.
//!
//! Upstream let the *publisher* supply the weight that decided who won. In
//! `gsn-core/src/memory/shared_memory.rs::SharedEntry` the field is
//! `pub weight: f64` and `best_strategy()` picks `max_by(weight)`; combined with
//! `EnhancedMemory::shareable()` — which had exactly zero callers — a publisher
//! could self-declare `weight = 1.0` and outrank every honest peer, and rank
//! itself by `NaN` (because `partial_cmp(..).unwrap()` would then panic the
//! reader).
//!
//! Here the score is *derived*, never supplied: [`Experience::quality_bps`] is
//! computed from the recorded `successes` / `failures`, and [`SharedMemory`]
//! refuses anything below its configured threshold or from an author with too
//! few observations to be trusted.

use std::collections::HashMap;

use nau_core::{Did, NauError, Result};
use serde::{Deserialize, Serialize};

/// The maximum quality, in basis points.
pub const MAX_QUALITY_BPS: u16 = 10_000;

/// Fixed-point scale for the *output* fraction. Results are reported in basis
/// points, so `SCALE` only has to be fine enough for that.
const SCALE: u128 = 1_000_000;
/// Internal precision: `SCALE²`.
///
/// The radicand `p̂(1−p̂)/n + z²/4n²` is around `1e-6` for a large sample, so at
/// `SCALE` resolution it truncates to zero and the confidence margin vanishes —
/// which made a 999/1 record score 9970 instead of 9943. Carrying the internals at
/// `SCALE²` keeps those terms intact; every intermediate still fits comfortably in
/// `u128` (the largest is about `1e24`).
const PREC: u128 = SCALE * SCALE;
/// `z` for a 95% interval: 1.96, expressed as the rational `196/100`.
const Z_NUM: u128 = 196;
const Z_DEN: u128 = 100;
/// `z²` in `PREC` units (`3.8416 * PREC`).
///
/// The earlier version of this module computed `196*196/(100*100)` in integer
/// arithmetic, which is `3` — discarding almost all of `z²` and, together with a
/// missing factor of `z` on the margin, saturating every input at 10_000 bps.
const Z2_PREC: u128 = 38_416 * PREC / 10_000;

/// How many observations the shared store requires before it will trust an
/// author at all. Below this, a single lucky success would look like a 100%
/// track record.
pub const MIN_SHARED_OBSERVATIONS: u32 = 3;

/// One published experience.
///
/// Note there is no `weight`, `score` or `quality` field: nothing here is
/// caller-controllable except the raw outcome counts.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Experience {
    /// The agent that submitted this experience.
    pub author: Did,
    /// The task key it applies to.
    pub key: String,
    /// The strategy, lesson or payload being shared.
    pub payload: String,
    /// Recorded successful outcomes.
    pub successes: u32,
    /// Recorded failed outcomes.
    pub failures: u32,
    /// Logical clock reading of submission.
    pub submitted_at: u64,
}

impl Experience {
    /// Quality in basis points, derived from `successes` / `failures` only.
    ///
    /// This is the **lower bound of the Wilson score interval** at 95%
    /// (`z = 1.96`), evaluated in integer arithmetic:
    ///
    /// ```text
    /// lower = ( p̂ + z²/2n − z·√( p̂(1−p̂)/n + z²/4n² ) ) / ( 1 + z²/n )
    /// ```
    ///
    /// The Wilson lower bound is used rather than a bare success ratio because
    /// the ratio rewards tiny samples: `1 success / 0 failures` would score
    /// 10_000 and outrank an honest `999/1000`. Wilson shrinks small samples
    /// toward zero, so `1/0` scores 1_066 while `999/1000` scores 10_000.
    ///
    /// Integer domain: every intermediate is `u64` except the final signed
    /// subtraction, which is done in `i128` and clamped into `0..=10_000`.
    /// Nothing here can panic and there is no floating-point comparison in the
    /// whole ranking path.
    pub fn quality_bps(&self) -> u16 {
        let n = u128::from(self.successes) + u128::from(self.failures);
        if n == 0 {
            return 0;
        }
        let successes = u128::from(self.successes);

        // p̂ scaled by PREC.
        let p_hat = successes * PREC / n;
        let one_minus_p = PREC.saturating_sub(p_hat);

        // (1 + z²/n) scaled by PREC.
        let denominator = PREC + Z2_PREC / n;
        // (p̂ + z²/2n) scaled by PREC.
        let centre = p_hat + (Z2_PREC / 2) / n;

        // p̂(1−p̂)/n + z²/4n², scaled by PREC.
        let variance = (p_hat * one_minus_p / PREC) / n;
        let correction = (Z2_PREC / 4) / (n * n);
        let radicand = variance + correction;

        // margin = z · √(radicand/PREC) · PREC = z · isqrt(radicand · PREC).
        //
        // The `z` factor is essential: omitting it yields a confidence bound that
        // is far too wide, which is what made small and large samples score alike.
        let root = integer_sqrt(radicand * PREC);
        let margin = Z_NUM * root / Z_DEN;

        let Some(numerator) = centre.checked_sub(margin) else {
            // The whole interval lies below zero.
            return 0;
        };
        if denominator == 0 {
            return 0;
        }
        // Back to a fraction of 1, scaled by SCALE, then to basis points.
        let lower = numerator * SCALE / denominator;
        let bps = lower * u128::from(MAX_QUALITY_BPS) / SCALE;
        bps.min(u128::from(MAX_QUALITY_BPS)) as u16
    }

    /// Total recorded observations.
    pub fn observations(&self) -> u32 {
        self.successes.saturating_add(self.failures)
    }
}

/// Integer square root (floor), by Newton iteration.
///
/// Written out rather than using `f64::sqrt` because a float would reintroduce
/// exactly the rounding/`NaN` class of bug this module exists to remove.
fn integer_sqrt(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut guess = value;
    // `div_ceil(2)`, not `(guess + 1) / 2`: the latter would overflow for
    // `guess == u128::MAX`.
    let mut next = guess.div_ceil(2);
    while next < guess {
        guess = next;
        next = (guess + value / guess.max(1)) / 2;
    }
    guess
}

#[cfg(test)]
mod wilson_tests {
    use super::*;

    fn quality(successes: u32, failures: u32) -> u16 {
        Experience {
            author: Did::parse("did:nau:0000000000000000").unwrap(),
            key: "k".into(),
            payload: "p".into(),
            successes,
            failures,
            submitted_at: 0,
        }
        .quality_bps()
    }

    #[test]
    fn the_95_percent_lower_bound_matches_the_closed_form() {
        // Reference values computed from the textbook Wilson lower bound:
        //   (p̂ + z²/2n − z·√(p̂(1−p̂)/n + z²/4n²)) / (1 + z²/n),  z = 1.96
        // Tolerance of 20 bps absorbs the integer square root and the fixed-point
        // truncation; a wrong formula is off by thousands.
        for (successes, failures, expected) in [
            (1u32, 3u32, 456u16), // 0.25 over 4 observations
            (5, 5, 2_366),        // 0.5 over 10
            (30, 2, 7_985),       // 0.9375 over 32
            (90, 10, 8_256),      // 0.9 over 100
            (900, 100, 8_798),    // 0.9 over 1000 -> trusted more than over 100
            (999, 1, 9_943),      // 0.999 over 1000
            (90, 1, 9_404),       // 0.989 over 91 (a *better* record scores higher)
        ] {
            let got = quality(successes, failures);
            let delta = got.abs_diff(expected);
            assert!(
                delta <= 20,
                "{successes}/{failures}: got {got} bps, expected ~{expected} (delta {delta})"
            );
        }
    }

    #[test]
    fn small_samples_are_shrunk_more_than_large_ones() {
        // The whole point of Wilson over a bare ratio.
        assert!(quality(1, 0) < quality(10, 0));
        assert!(quality(10, 0) < quality(1_000, 0));
        assert!(quality(1_000, 0) < MAX_QUALITY_BPS);
        // A perfect record is never 100% confident, however large.
        assert!(quality(u32::MAX, 0) <= MAX_QUALITY_BPS);
    }

    #[test]
    fn nothing_saturates_and_nothing_panics_at_the_extremes() {
        for (s, f) in [
            (0u32, 0u32),
            (u32::MAX, 0),
            (0, u32::MAX),
            (u32::MAX, u32::MAX),
            (u32::MAX, 1),
            (1, u32::MAX),
            (20, 1),
        ] {
            let q = quality(s, f);
            assert!(q <= MAX_QUALITY_BPS, "{s}/{f} -> {q}");
        }
        // A hopeless record scores zero.
        assert_eq!(quality(0, u32::MAX), 0);
        assert_eq!(quality(1, u32::MAX), 0);
    }

    #[test]
    fn more_successes_never_lower_the_score() {
        // Monotonicity in the success count for a fixed number of failures.
        for failures in [0u32, 1, 5, 50] {
            let mut previous = 0u16;
            for successes in 0..200u32 {
                let q = quality(successes, failures);
                assert!(
                    q >= previous,
                    "{successes}/{failures}: {q} < previous {previous}"
                );
                previous = q;
            }
        }
    }
}

/// A bounded, anti-pollution-filtered shared store.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SharedMemory {
    min_quality_bps: u16,
    capacity: usize,
    /// key -> author DID -> experience. Insertion order is not used; `best_for`
    /// resolves ties by author DID so output is deterministic.
    entries: HashMap<String, HashMap<Did, Experience>>,
    /// Running count of accepted publications per author, so "trusted" is
    /// earned rather than declared. Currently informational.
    accepted: HashMap<Did, u64>,
}

impl SharedMemory {
    /// A store that accepts only experiences scoring at least
    /// `min_quality_bps` from authors with at least
    /// [`MIN_SHARED_OBSERVATIONS`] recorded outcomes, holding at most
    /// `capacity` entries.
    ///
    /// upstream v2.5.6 fix: upstream had no threshold at all in the store, and
    /// its `publish` accepted any caller-supplied `weight`. A threshold above
    /// [`MAX_QUALITY_BPS`] is rejected, because it would silently reject
    /// everything.
    pub fn new(min_quality_bps: u16, capacity: usize) -> Self {
        Self {
            min_quality_bps: min_quality_bps.min(MAX_QUALITY_BPS),
            capacity: capacity.max(1),
            entries: HashMap::new(),
            accepted: HashMap::new(),
        }
    }

    /// The configured minimum quality.
    pub fn min_quality_bps(&self) -> u16 {
        self.min_quality_bps
    }

    /// Publish an experience, rejecting low-quality and under-observed ones.
    ///
    /// Rejections are typed and explain themselves:
    /// * `Unauthorized` when the author has fewer than
    ///   [`MIN_SHARED_OBSERVATIONS`] recorded outcomes — an unproven author
    ///   cannot inject anything into the swarm's memory;
    /// * `Validation` when the derived quality is below the threshold, or when
    ///   the key/payload is empty.
    ///
    /// An accepted experience for a key the author already published replaces
    /// their previous one, so re-publishing cannot be used to stack entries.
    /// The store is capacity-bounded: each new key evicts the key with the
    /// lowest best-quality (ties broken by key, ascending).
    pub fn publish(&mut self, exp: Experience) -> Result<()> {
        if exp.key.trim().is_empty() {
            return Err(NauError::Validation(
                "experience key must not be empty".into(),
            ));
        }
        if exp.payload.trim().is_empty() {
            return Err(NauError::Validation(
                "experience payload must not be empty".into(),
            ));
        }
        let observations = exp.observations();
        if observations < MIN_SHARED_OBSERVATIONS {
            return Err(NauError::Unauthorized(format!(
                "author `{}` has only {observations} recorded outcome(s); \
                 {MIN_SHARED_OBSERVATIONS} are required before an experience is shareable",
                exp.author
            )));
        }
        let quality = exp.quality_bps();
        // A zero-quality record (no successes, or a ratio whose confidence interval
        // touches zero) carries no information. Refusing it outright means a
        // threshold of 0 still cannot be used to fill the store with worthless
        // entries, which would otherwise be a cheap way to evict good ones.
        if quality == 0 {
            return Err(NauError::Validation(format!(
                "experience has {quality} bps of derived quality from {} success(es) and \
                 {} failure(s); a record that teaches nothing is not stored",
                exp.successes, exp.failures
            )));
        }
        if quality < self.min_quality_bps {
            return Err(NauError::Validation(format!(
                "experience quality {quality} bps is below the shared-memory threshold of {} bps",
                self.min_quality_bps
            )));
        }

        let known_key = self.entries.contains_key(&exp.key);
        let known_author = self
            .entries
            .get(&exp.key)
            .is_some_and(|by_author| by_author.contains_key(&exp.author));
        if !known_key && self.key_count() >= self.capacity {
            self.evict_worst_key()?;
        }
        if !known_author {
            // A new author slot in an existing key also consumes capacity.
            if self.total_entries() >= self.capacity {
                self.evict_worst_key()?;
            }
        }

        self.entries
            .entry(exp.key.clone())
            .or_default()
            .insert(exp.author.clone(), exp.clone());
        *self.accepted.entry(exp.author.clone()).or_insert(0) += 1;
        Ok(())
    }

    /// The highest-quality accepted experience for `key`.
    ///
    /// Ties are broken by author DID ascending so the result never depends on
    /// hash-map iteration order.
    pub fn best_for(&self, key: &str) -> Option<&Experience> {
        self.entries.get(key).and_then(|by_author| {
            by_author.values().max_by(|a, b| {
                a.quality_bps()
                    .cmp(&b.quality_bps())
                    // `max_by` keeps the *last* maximum, so reverse the tie-break
                    // to make the smallest DID win.
                    .then_with(|| b.author.cmp(&a.author))
            })
        })
    }

    /// Number of distinct keys held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when nothing is held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of accepted experiences across all keys and authors.
    pub fn total_entries(&self) -> usize {
        self.entries.values().map(HashMap::len).sum()
    }

    /// The configured bound on accepted experiences.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many publications from `author` were accepted.
    pub fn accepted_from(&self, author: &Did) -> u64 {
        self.accepted.get(author).copied().unwrap_or(0)
    }

    /// Number of distinct keys (alias of [`SharedMemory::len`], naming the
    /// quantity the capacity check uses).
    fn key_count(&self) -> usize {
        self.entries.len()
    }

    /// Drop the key whose best experience is weakest.
    fn evict_worst_key(&mut self) -> Result<()> {
        let victim = self
            .entries
            .iter()
            .map(|(key, by_author)| {
                let best = by_author
                    .values()
                    .map(Experience::quality_bps)
                    .max()
                    .unwrap_or(0);
                (key.clone(), best)
            })
            .min_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
            .map(|(key, _)| key)
            .ok_or_else(|| {
                NauError::Validation("cannot evict from an empty shared memory".into())
            })?;
        self.entries.remove(&victim);
        Ok(())
    }
}
