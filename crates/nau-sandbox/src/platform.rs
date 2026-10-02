//! The platform edge: the one place in this crate where `unsafe` is permitted.
//!
//! # Why the exception exists
//!
//! The crate is `#![deny(unsafe_code)]`. Enforcing "the whole process tree dies
//! with the sandbox", "memory is capped", "the process count is capped" and "the
//! child sees only the environment we built" is not possible in pure safe Rust:
//! those are `CreateJobObjectW` / `SetInformationJobObject` /
//! `AssignProcessToJobObject` / `TerminateJobObject` calls on Windows and
//! `setsid` / `setrlimit` / `killpg` calls on Unix, reachable only through the C
//! ABI. Pretending otherwise would mean shipping a sandbox whose central claim is
//! documentation, which is exactly the upstream defect this crate answers
//! (`sandbox/runtime/process.rs:153` — `Command::new("bash")` and nothing else).
//!
//! # How narrowly the exception is drawn
//!
//! * `#![deny(unsafe_code)]` stays on the crate, so `unsafe` anywhere outside this
//!   module is a compile error rather than a review question.
//! * This module is private, so the exception is not part of the public API.
//! * The FFI surface is a handful of declarations with the exact Win32 or POSIX
//!   layouts, and every `unsafe` block carries a `// SAFETY:` comment naming the
//!   invariant that makes it sound.
//! * Process creation, pipes, quoting and reaping stay in `std::process`; nothing
//!   here implements fork/exec or argument splitting by hand.
//!
//! # Tests
//!
//! The code here cannot be tested in a unit test — it has to run real processes —
//! so its tests live in `crates/nau-sandbox/tests/enforcement.rs`, and each one
//! names the upstream finding it closes. Anything that could not be verified on
//! this machine is reported as a SKIP with a reason rather than a silent pass.

#![allow(unsafe_code)]

// `rt` holds the Win32 types and `#[link(name = "kernel32")]` declarations, and
// `windows.rs` is its only consumer. It was declared unconditionally, so on Linux and
// macOS the linker was asked for `-lkernel32` and `nau-node`'s binaries failed to link
// with `cannot find -lkernel32` -- after the whole workspace had type-checked cleanly,
// because `cargo check` does not link. CI caught it; a Windows machine cannot.
#[cfg(windows)]
pub(crate) mod rt;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{process_is_alive, spawn};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::{process_is_alive, spawn};

/// Which platform backend this build uses, for the report and for
/// [`crate::Capabilities`].
///
/// Kept as a `const` so the claim travels with the binary rather than living only
/// in a commit message.
pub const PLATFORM_BACKEND: &str = if cfg!(windows) {
    "windows-jobobject"
} else {
    "unix-setrlimit"
};
