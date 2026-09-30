//! Time as an injected port.
//!
//! Upstream v2.5.6 calls `SystemTime::now()` directly inside domain logic and
//! `unwrap()`s it (e.g. `marketplace/settlement.rs::now()`), which makes expiry
//! and replay behaviour untestable and adds a panic path on a mis-set clock.
//! Here, everything that needs "now" takes a [`Clock`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of wall-clock time, in seconds since the Unix epoch.
pub trait Clock: Send + Sync {
    /// Seconds since 1970-01-01T00:00:00Z. Never panics.
    fn now_unix(&self) -> u64;
}

/// Reads the real system clock. Saturates at 0 for a pre-epoch clock instead of
/// panicking.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A hand-driven clock for tests and deterministic simulations.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: AtomicU64,
}

impl ManualClock {
    /// Start at the given Unix timestamp.
    pub fn at(now: u64) -> Self {
        Self {
            now: AtomicU64::new(now),
        }
    }

    /// Move the clock forward by `secs` and return the new time.
    pub fn advance(&self, secs: u64) -> u64 {
        self.now.fetch_add(secs, Ordering::SeqCst) + secs
    }

    /// Set the clock to an absolute Unix timestamp.
    pub fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_unix(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances_deterministically() {
        let c = ManualClock::at(1_000);
        assert_eq!(c.now_unix(), 1_000);
        assert_eq!(c.advance(60), 1_060);
        assert_eq!(c.now_unix(), 1_060);
        c.set(42);
        assert_eq!(c.now_unix(), 42);
    }

    #[test]
    fn system_clock_is_monotonic_enough_to_be_sane() {
        let c = SystemClock;
        // Must be after 2020-01-01 and before 2200-01-01, and must not panic.
        assert!(c.now_unix() > 1_577_836_800);
        assert!(c.now_unix() < 7_258_118_400);
    }
}
