//! Unix process backend: `setsid` plus `setrlimit` in the child, between `fork`
//! and `exec`.
//!
//! # Status: compiled and capability-declared, **not verified on this machine**
//!
//! This machine is Windows, so nothing in this module has been executed. It is
//! included because the alternative — declaring the Unix capabilities unenforced
//! on every platform — would understate what can be delivered, and because the
//! refusal model in [`crate::Capabilities`] only means something if a second
//! backend exists with a *different* declaration. Its verification status is part
//! of the backend's own documentation and of the report accompanying this crate.
//!
//! # Why these two calls, and why in the child
//!
//! * `setsid()` puts the child in a new session and process group, so a signal
//!   aimed at the daemon's group cannot reach it and, more importantly, the
//!   daemon can kill the whole group with one `killpg` even if the direct child
//!   has already exited.
//! * `setrlimit(RLIMIT_AS, …)` caps address space and `setrlimit(RLIMIT_CPU, …)`
//!   caps CPU seconds. Both are **inherited across `exec` and across `fork`**, so
//!   a grandchild starts already limited and cannot raise the cap back up. That is
//!   strictly stronger than the Windows path, where the cap is on the job.
//! * `RLIMIT_NPROC` is attempted but deliberately non-fatal: on Linux it counts
//!   the calling *user's* processes rather than the sandbox's, so a failure to set
//!   it must not be reported as a process-count limit that was applied.
//!
//! Only async-signal-safe operations run in this window: no allocation, no
//! locking, no Rust formatting.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

use crate::error::{Result, SandboxError};
use crate::spec::SandboxSpec;

/// `RLIMIT_AS` (address space), the same value on Linux and macOS.
const RLIMIT_AS: i32 = 9;
/// `RLIMIT_CPU` (CPU seconds), the same value on Linux and macOS.
const RLIMIT_CPU: i32 = 0;
/// `RLIMIT_NPROC` (processes per user) on Linux; absent on macOS.
#[cfg(target_os = "linux")]
const RLIMIT_NPROC: i32 = 6;

/// A spawned child in its own session.
pub(crate) struct ChildProcess {
    child: Child,
}

/// `struct rlimit` on glibc and on macOS alike: two `rlim_t` fields.
#[repr(C)]
struct RLimit {
    rlim_cur: u64,
    rlim_max: u64,
}

extern "C" {
    /// `setrlimit(2)`.
    fn setrlimit(resource: i32, limit: *const RLimit) -> i32;
    /// `setsid(2)`.
    fn setsid() -> i32;
}

/// Set one resource limit.
///
/// Both the soft and the hard limit are set, so the child cannot raise the cap
/// back up before `exec`.
fn set_rlimit(resource: i32, value: u64) -> i32 {
    let limit = RLimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `resource` is one of the `RLIMIT_*` constants defined in this module,
    // and `limit` references a live `RLimit` for the duration of the call — which
    // is precisely the contract of `setrlimit(2)`. The kernel reads the struct
    // before returning.
    unsafe { setrlimit(resource, &limit) }
}

/// What the child applies for itself before `exec`.
#[derive(Debug, Clone, Copy)]
struct ChildLimits {
    memory_bytes: u64,
    cpu_ms: u64,
    // Retained for the `RLIMIT_NPROC` attempt; on Linux only.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    max_processes: u32,
}

/// Configure `cmd` so the child gets its own session and its rlimits.
///
/// # Safety
///
/// The closure runs in the forked child before `exec`. It performs only
/// async-signal-safe operations, so it is sound to run there.
pub(crate) fn spawn(cmd: &mut Command, spec: &SandboxSpec) -> Result<ChildProcess> {
    let limits = ChildLimits {
        memory_bytes: spec.limits.memory_bytes,
        cpu_ms: spec.limits.cpu_ms,
        max_processes: spec.limits.max_processes,
    };
    // SAFETY: `pre_exec` requires the closure to be async-signal-safe. This one
    // calls `setsid` and `setrlimit` and nothing else: no allocation, no locking,
    // no Rust formatting, no I/O. Any failure is reported by the closed `Err`
    // value, which aborts the exec rather than continuing without the limit.
    unsafe {
        cmd.pre_exec(move || {
            if setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if set_rlimit(RLIMIT_AS, limits.memory_bytes) != 0 {
                return Err(io::Error::last_os_error());
            }
            // CPU time is in whole seconds; a value under one second would read as
            // "no CPU at all", so it is rounded up.
            let cpu_secs = limits.cpu_ms.div_ceil(1_000).max(1);
            if set_rlimit(RLIMIT_CPU, cpu_secs) != 0 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            {
                // Non-fatal on purpose: on Linux this limit is per *user*, so it
                // may be refused for reasons that have nothing to do with this
                // sandbox. The capability declaration says the process count is
                // capped by this call only on Linux, and the report says it is
                // unverified on this machine.
                let _ = set_rlimit(RLIMIT_NPROC, u64::from(limits.max_processes));
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| SandboxError::Start(format!("cannot create the sandbox process: {e}")))?;
    Ok(ChildProcess { child })
}

impl ChildProcess {
    /// Take stdout.
    pub(crate) fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    /// Take stderr.
    pub(crate) fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    /// Take stdin.
    pub(crate) fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    /// The `std::process::Child`, for polling and reaping.
    pub(crate) fn inner_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Kill the child's whole process group.
    ///
    /// The child called `setsid`, so its group id equals its pid and the negative
    /// pid addresses the group. A group that is already gone makes `killpg` return
    /// `ESRCH`, which is success for our purposes.
    pub(crate) fn terminate_job(&mut self) -> Result<()> {
        let pid = self.child.id() as i32;
        // SAFETY: `killpg` takes two integers and has no memory contract.
        let rc = unsafe { killpg(-pid, SIGKILL) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(ESRCH) {
                return Ok(());
            }
            return Err(SandboxError::Internal(format!(
                "cannot kill the sandbox process group: {e}"
            )));
        }
        Ok(())
    }
}

/// `ESRCH`: no such process (group).
const ESRCH: i32 = 3;
/// `EPERM`: the process exists but is not ours to signal.
const EPERM: i32 = 1;
/// `SIGKILL`.
const SIGKILL: i32 = 9;

extern "C" {
    /// `killpg(2)`.
    fn killpg(pgrp: i32, sig: i32) -> i32;
    /// `kill(2)`.
    fn kill(pid: i32, sig: i32) -> i32;
}

/// True when a process with this pid exists.
///
/// Used by the orphan sweep as a *hint* that a sandbox directory belongs to a live
/// run; it can only make the sweep more conservative, never authorise a deletion.
/// It cannot distinguish a live process from a reused pid, which is why the sweep
/// also requires an age margin.
pub(crate) fn process_is_alive(pid: u32) -> bool {
    // `kill` takes an `i32`, and in that type three values do NOT name a single
    // process: 0 means "my process group", -1 means "every process I may signal",
    // and any other negative value names a process GROUP. So a `u32` pid above
    // `i32::MAX` casts to a negative number and silently changes the question.
    //
    // Concretely: `u32::MAX` casts to -1, `kill(-1, 0)` succeeds (it is a valid
    // "does the caller have any signalable process" question), and a dead run is
    // reported as alive. That is not a test-fixture curiosity -- this probe is what
    // the orphan sweep consults before reclaiming a directory, and the failure only
    // appears on Unix: Windows uses `OpenProcess`, which simply fails for 0xFFFFFFFF.
    // Refuse anything that cannot be a real pid instead of letting the cast invent one.
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    // SAFETY: `kill` with signal 0 performs an existence and permission check and
    // delivers no signal; it has no memory contract.
    let rc = unsafe { kill(pid as i32, 0) };
    if rc == 0 {
        return true;
    }
    // `EPERM` means the process exists but belongs to another user: still alive.
    std::io::Error::last_os_error().raw_os_error() == Some(EPERM)
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        let _ = self.terminate_job();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
