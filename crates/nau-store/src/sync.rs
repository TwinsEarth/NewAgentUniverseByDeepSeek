//! Poison-recovering lock helpers.
//!
//! Upstream v2.5.6 acquires its storage mutex with `.lock().unwrap()` in 18
//! places. A `Mutex`/`RwLock` in the standard library panics that *unwrap* once
//! the lock is poisoned — i.e. once **any** thread panicked while holding it —
//! so a single panicking request turned every later storage call into a panic,
//! permanently, until the process was restarted.
//!
//! Every acquisition in this crate goes through [`read`] or [`write`], which
//! recover the guard from a poisoned lock instead of panicking:
//! `.unwrap_or_else(|e| e.into_inner())`. Recovering is sound here because the
//! guarded data is written with plain field assignment and is only ever
//! *replaced*, never left in a torn state by a panic (there is no invariant that
//! spans two fields).

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Acquire a shared guard, recovering from poisoning.
pub(crate) fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    // upstream v2.5.6 fix: `.read().unwrap()` panicked forever after any poison.
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Acquire an exclusive guard, recovering from poisoning.
pub(crate) fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    // upstream v2.5.6 fix: `.lock().unwrap()` panicked forever after any poison.
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_poisoned_lock_is_recovered_instead_of_panicking() {
        let lock = Arc::new(RwLock::new(7u32));
        let poisoner = Arc::clone(&lock);
        let handle = std::thread::spawn(move || {
            let _guard = poisoner.write().expect("fresh lock is not poisoned");
            panic!("simulated panic while holding the storage lock");
        });
        // The poisoning thread must have died while holding the write guard.
        assert!(handle.join().is_err(), "the thread was supposed to panic");
        assert!(lock.is_poisoned(), "the lock must now be poisoned");

        // Reading must still work, and must observe the last committed value.
        assert_eq!(*read(&lock), 7);
        // Writing must still work too.
        *write(&lock) = 8;
        assert_eq!(*read(&lock), 8);
    }
}
