//! Poison-recovering lock helpers.
//!
//! Upstream v2.5.6 reaches its shared state through `.lock().unwrap()`, so one
//! panicking task poisons the lock and every later call panics too. Every
//! acquisition in this crate recovers the guard instead
//! (`.unwrap_or_else(|e| e.into_inner())`).

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Acquire a mutex guard, recovering from poisoning.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // upstream v2.5.6 fix: `.lock().unwrap()` panicked forever after any poison.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Acquire a shared `RwLock` guard, recovering from poisoning.
pub(crate) fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Acquire an exclusive `RwLock` guard, recovering from poisoning.
pub(crate) fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_poisoned_lock_is_recovered_instead_of_panicking() {
        let mutex = Arc::new(Mutex::new(1u32));
        let poisoner = Arc::clone(&mutex);
        let handle = std::thread::spawn(move || {
            let _guard = poisoner.lock().expect("fresh");
            panic!("simulated panic while holding the lock");
        });
        assert!(handle.join().is_err());
        assert!(mutex.is_poisoned());
        assert_eq!(*lock(&mutex), 1, "the committed value is still readable");
    }
}
