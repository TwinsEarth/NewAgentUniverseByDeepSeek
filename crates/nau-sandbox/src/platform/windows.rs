//! Windows process backend: a Win32 **Job Object** per sandbox.
//!
//! # What the job object buys, and why it is the right primitive
//!
//! Upstream v2.8.2 fix: the Windows branch of the upstream sandbox applied **no
//! limits at all**, the timeout killed a single pid, and a `try_wait` error
//! returned without killing anything, so a backgrounded grandchild outlived the
//! sandbox. A job object is the Windows kernel object for exactly this problem:
//!
//! * `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — closing the last handle to the job
//!   terminates every process in it. A daemon that crashes still takes its
//!   sandbox tree with it, which is the property "no orphans" needs.
//! * `JOB_OBJECT_LIMIT_PROCESS_MEMORY` — each process's committed memory is
//!   capped, so an allocation beyond the cap fails instead of the host swapping.
//! * `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` — the process count is capped by the
//!   kernel, so a fork bomb fails inside the job at `CreateProcess`.
//! * `TerminateJobObject` — kills the whole tree, so a grandchild cannot outlive
//!   its parent.
//!
//! # The race the `CREATE_SUSPENDED` dance removes
//!
//! `AssignProcessToJobObject` can only be called once a process exists, and a
//! process created normally starts executing immediately — a grandchild spawned
//! in that window would be outside the job. The child is therefore created with
//! `CREATE_SUSPENDED`, assigned to the job, and only then resumed. The window is
//! zero instructions wide instead of "usually fast enough".
//!
//! # What this backend cannot do
//!
//! There is no egress filter and no filesystem confinement here, so those
//! capabilities are declared **unenforced** and any request that asks for them is
//! refused by name (see [`crate::Capabilities`]).

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

use super::rt;
use crate::error::{Result, SandboxError};
use crate::spec::SandboxSpec;

/// A spawned child plus the job object that owns it.
pub(crate) struct ChildProcess {
    child: Child,
    job: JobHandle,
}

/// An owned job-object handle, closed exactly once.
struct JobHandle(rt::Handle);

impl JobHandle {
    /// The raw handle.
    fn raw(&self) -> rt::Handle {
        self.0
    }
}

impl Drop for JobHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != rt::INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` came from `CreateJobObjectW` and is owned by this
            // value, so it is closed exactly once, here. With
            // `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` set, this is also the guarantee
            // that the tree dies even if `terminate_job` was never called.
            unsafe {
                rt::CloseHandle(self.0);
            }
        }
    }
}

/// Create a job object with the limits implied by `spec`.
fn create_job(spec: &SandboxSpec) -> io::Result<JobHandle> {
    // SAFETY: `CreateJobObjectW` takes two nullable pointers and returns a new
    // handle or null. Passing null for both means "unnamed job, default
    // security"; the call borrows nothing.
    let raw = unsafe { rt::CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
    if raw.is_null() || raw == rt::INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let job = JobHandle(raw);

    let mut info = rt::ExtendedLimitInformation::default();
    info.basic_limit_information.limit_flags =
        rt::JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | rt::JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    // `max_processes` counts the direct child, so the kernel cap is exactly it.
    info.basic_limit_information.limit_flags |= rt::JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    info.basic_limit_information.active_process_limit = spec.limits.max_processes;
    info.basic_limit_information.limit_flags |= rt::JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.process_memory_limit = spec.limits.memory_bytes as usize;

    // SAFETY: `job` is a live job handle this function owns. `info` is a
    // `#[repr(C)]` struct whose layout matches
    // `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`, and `size_of` is exactly the length
    // the API expects. The API copies the struct before returning, so the borrow
    // ends with the call.
    let ok = unsafe {
        rt::SetInformationJobObject(
            job.raw(),
            rt::JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            (&mut info as *mut rt::ExtendedLimitInformation).cast::<c_void>(),
            std::mem::size_of::<rt::ExtendedLimitInformation>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

/// Create the process suspended, put it in a capped job, then resume it.
pub(crate) fn spawn(cmd: &mut Command, spec: &SandboxSpec) -> Result<ChildProcess> {
    cmd.creation_flags(rt::CREATE_SUSPENDED);
    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::Start(format!("cannot create the sandbox process: {e}")))?;

    let job = match create_job(spec) {
        Ok(job) => job,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SandboxError::Start(format!(
                "cannot create the sandbox job object: {e}"
            )));
        }
    };

    // SAFETY: `child` owns both handles and both are valid:
    // `as_raw_handle` on a spawned `std::process::Child` never returns null, and
    // `job` was just created. The call takes ownership of neither handle, so no
    // double close can occur.
    let assigned =
        unsafe { rt::AssignProcessToJobObject(job.raw(), child.as_raw_handle() as rt::Handle) };
    if assigned == 0 {
        let e = io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        return Err(SandboxError::Start(format!(
            "cannot assign the sandbox process to its job object: {e}"
        )));
    }

    resume(&mut child, &job)?;
    Ok(ChildProcess { child, job })
}

/// Resume the process's main thread; on failure the job is terminated first.
///
/// The thread handle is discovered through a system thread snapshot filtered to
/// this process id. That is reliable here for a specific reason: the process was
/// created suspended and has executed nothing, so it has exactly one thread and
/// that thread is its main thread. `ResumeThread` on a thread that is not
/// suspended returns 0, which this function treats as success.
fn resume(child: &mut Child, job: &JobHandle) -> Result<()> {
    let pid = child.id();
    // SAFETY: `CreateToolhelp32Snapshot` with `TH32CS_SNAPTHREAD` returns a
    // snapshot handle this function owns and closes below. The `entry` pointer
    // references a live, correctly initialised `THREADENTRY32` with `dw_size` set
    // as the API requires, and the API writes only within that struct.
    let thread_id = unsafe {
        let snapshot = rt::CreateToolhelp32Snapshot(rt::TH32CS_SNAPTHREAD, 0);
        if snapshot.is_null() || snapshot == rt::INVALID_HANDLE_VALUE {
            None
        } else {
            let mut entry = rt::ThreadEntry32 {
                dw_size: std::mem::size_of::<rt::ThreadEntry32>() as u32,
                ..rt::ThreadEntry32::default()
            };
            let mut found = None;
            if rt::Thread32First(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32_owner_process_id == pid {
                        found = Some(entry.th32_thread_id);
                        break;
                    }
                    if rt::Thread32Next(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            rt::CloseHandle(snapshot);
            found
        }
    };

    let Some(thread_id) = thread_id else {
        let _ = terminate_job(job);
        let _ = child.kill();
        let _ = child.wait();
        return Err(SandboxError::Start(
            "cannot find the suspended sandbox process's main thread to resume it".to_string(),
        ));
    };

    // SAFETY: `thread_id` came from a snapshot of a suspended single-threaded
    // process. The handle is opened with `THREAD_SUSPEND_RESUME` only, so the only
    // operation it permits is resuming. The handle is owned here and closed
    // exactly once.
    let resumed = unsafe {
        let handle = rt::OpenThread(rt::THREAD_SUSPEND_RESUME, 0, thread_id);
        if handle.is_null() {
            u32::MAX
        } else {
            let r = rt::ResumeThread(handle);
            rt::CloseHandle(handle);
            r
        }
    };
    if resumed == u32::MAX {
        let e = io::Error::last_os_error();
        let _ = terminate_job(job);
        let _ = child.kill();
        let _ = child.wait();
        return Err(SandboxError::Start(format!(
            "cannot resume the suspended sandbox process: {e}"
        )));
    }
    Ok(())
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

    /// Terminate every process in the job.
    ///
    /// Called on the timeout path, on the "child exited but a pipe is still open"
    /// path, and defensively after a normal exit so that a detached descendant
    /// cannot outlive the sandbox. The error is returned rather than swallowed, so
    /// the caller never silently believes a tree was killed.
    pub(crate) fn terminate_job(&mut self) -> Result<()> {
        terminate_job(&self.job)
    }
}

/// Terminate every process in `job`.
fn terminate_job(job: &JobHandle) -> Result<()> {
    // SAFETY: `job.raw()` is a live job handle owned by `job`. `TerminateJobObject`
    // takes an exit code by value and borrows nothing.
    let ok = unsafe { rt::TerminateJobObject(job.raw(), 1) };
    if ok == 0 {
        let e = io::Error::last_os_error();
        // ERROR_ACCESS_DENIED is reported when the job has already finished, which
        // is success for our purposes: there is nothing left to kill.
        if e.raw_os_error() == Some(5) {
            return Ok(());
        }
        return Err(SandboxError::Internal(format!(
            "cannot terminate the sandbox job object: {e}"
        )));
    }
    Ok(())
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        // Killing is idempotent, and doing it explicitly means the tree is dead
        // *before* the handle closes rather than as a side effect of closing it.
        let _ = terminate_job(&self.job);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// True when a process with this pid is still running.
///
/// Used by the orphan sweep as a *hint* that a sandbox directory belongs to a live
/// run; it can only ever make the sweep more conservative, never authorise a
/// deletion. `OpenProcess` cannot tell a live process from a reused pid, which is
/// why the sweep also requires an age margin.
pub(crate) fn process_is_alive(pid: u32) -> bool {
    // SAFETY: `OpenProcess` takes three scalars and returns a handle or null. The
    // handle is owned here and closed exactly once below. A null return means the
    // pid does not exist or is not queryable; both are treated as "not alive",
    // which is the conservative reading for a *hint* used only to skip work.
    unsafe {
        let handle = rt::OpenProcess(rt::PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let ok = rt::GetExitCodeProcess(handle, &mut code);
        rt::CloseHandle(handle);
        ok != 0 && code == rt::STILL_ACTIVE
    }
}
