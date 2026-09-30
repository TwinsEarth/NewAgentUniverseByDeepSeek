//! Raw Win32 declarations used by the Windows process backend.
//!
//! Only what is needed: a job object, its limits, and the two calls that put a
//! process in it and terminate it. Every layout matches `winnt.h` for
//! x86_64-pc-windows-msvc; the `JOBOBJECT_*_INFORMATION` structures are
//! `#[repr(C)]` and use `u64`/`i64` for `LARGE_INTEGER`, which is the correct
//! width and alignment on 64-bit Windows.

#![allow(dead_code)]

use std::ffi::c_void;

/// A Win32 handle. `INVALID_HANDLE_VALUE` is the sentinel `-1`.
pub(crate) type Handle = *mut c_void;

/// The `HANDLE` value that means "no handle".
pub(crate) const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

/// `JOB_OBJECT_LIMIT_PROCESS_MEMORY`: cap each process's committed memory.
pub(crate) const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x0000_0100;
/// `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: cap the number of active processes.
pub(crate) const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: kill the tree when the last handle
/// closes, so a crashed daemon does not leave a live tree behind.
pub(crate) const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
/// `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`.
pub(crate) const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x0000_0400;

/// `JobObjectExtendedLimitInformation`.
pub(crate) const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: u32 = 9;

// `JobObjectBasicUIRestrictions` is deliberately unused: no UI limit is claimed.
// (A `//` note rather than a `///` one: a doc comment here would document nothing,
// which `clippy::empty_line_after_doc_comments` refuses.)

// `STARTUPINFOEX`/`PROC_THREAD_ATTRIBUTE_LIST` are not used; the process is
// created suspended instead, so the assignment below happens before the child
// executes its first instruction. (A `//` note, not a `///` one: it documents no
// item, and `clippy::empty_line_after_doc_comments` refuses a doc comment that is
// followed by a blank line.)

/// `CREATE_SUSPENDED`: create the process without running its first instruction.
pub(crate) const CREATE_SUSPENDED: u32 = 0x0000_0004;
/// `CREATE_UNICODE_ENVIRONMENT`: the environment block is UTF-16. Always set,
/// because `std::process::Command` always builds a UTF-16 environment block.
pub(crate) const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

/// `TH32CS_SNAPTHREAD`: snapshot every thread in the system.
pub(crate) const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
/// `THREAD_SUSPEND_RESUME`: the only right the resume path needs.
pub(crate) const THREAD_SUSPEND_RESUME: u32 = 0x0000_0002;

/// `PROCESS_QUERY_LIMITED_INFORMATION`: the least right that answers "is this pid
/// alive?".
pub(crate) const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x0000_1000;
/// `STILL_ACTIVE`: the exit code of a process that has not exited.
pub(crate) const STILL_ACTIVE: u32 = 259;

/// `IO_COUNTERS`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct IoCounters {
    /// Bytes read.
    pub read_operation_count: u64,
    /// Write operations.
    pub write_operation_count: u64,
    /// Bytes other than read/write.
    pub other_operation_count: u64,
    /// Bytes read.
    pub read_transfer_count: u64,
    /// Bytes written.
    pub write_transfer_count: u64,
    /// Bytes other than read/write.
    pub other_transfer_count: u64,
}

/// `JOBOBJECT_BASIC_LIMIT_INFORMATION`.
///
/// `per_process_user_time`/`per_job_user_time` are `LARGE_INTEGER`, represented
/// as `i64`; `LARGE_INTEGER` is a union of a struct and an `i64`, so its
/// alignment is 8 and its size is 8.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BasicLimitInformation {
    /// `PerProcessUserTimeLimit`.
    pub per_process_user_time: i64,
    /// `PerJobUserTimeLimit`.
    pub per_job_user_time: i64,
    /// The `JOB_OBJECT_LIMIT_*` bits that are in effect.
    pub limit_flags: u32,
    /// `MinimumWorkingSetSize`.
    pub minimum_working_set_size: usize,
    /// `MaximumWorkingSetSize`.
    pub maximum_working_set_size: usize,
    /// `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: the cap when it is set.
    pub active_process_limit: u32,
    /// `Affinity` is a `ULONG_PTR`, declared as an opaque `u64`.
    pub affinity: u64,
    /// `PriorityClass`.
    pub priority_class: u32,
    /// `SchedulingClass`.
    pub scheduling_class: u32,
}

/// `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ExtendedLimitInformation {
    /// Basic limits.
    pub basic_limit_information: BasicLimitInformation,
    /// I/O counters.
    pub io_info: IoCounters,
    /// `JOB_OBJECT_LIMIT_PROCESS_MEMORY`: the cap when it is set.
    pub process_memory_limit: usize,
    /// `JOB_OBJECT_LIMIT_JOB_MEMORY`: the cap when it is set.
    pub job_memory_limit: usize,
    /// `PeakProcessMemoryUsed`.
    pub peak_process_memory_used: usize,
    /// `PeakJobMemoryUsed`.
    pub peak_job_memory_used: usize,
}

#[link(name = "kernel32")]
extern "system" {
    /// `CreateJobObjectW`.
    pub(crate) fn CreateJobObjectW(job_attributes: *mut c_void, name: *const u16) -> Handle;

    /// `SetInformationJobObject`.
    pub(crate) fn SetInformationJobObject(
        job: Handle,
        information_class: u32,
        information: *mut c_void,
        information_length: u32,
    ) -> i32;

    /// `AssignProcessToJobObject`.
    pub(crate) fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;

    /// `TerminateJobObject`.
    pub(crate) fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;

    /// `ResumeThread`.
    pub(crate) fn ResumeThread(thread: Handle) -> u32;

    /// `CloseHandle`.
    pub(crate) fn CloseHandle(object: Handle) -> i32;

    /// `CreateToolhelp32Snapshot`.
    pub(crate) fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;

    /// `Thread32First`.
    pub(crate) fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;

    /// `Thread32Next`.
    pub(crate) fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> i32;

    /// `OpenThread`.
    pub(crate) fn OpenThread(desired_access: u32, inherit: i32, thread_id: u32) -> Handle;

    /// `OpenProcess`.
    pub(crate) fn OpenProcess(desired_access: u32, inherit: i32, process_id: u32) -> Handle;

    /// `GetExitCodeProcess`.
    pub(crate) fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
}

/// `THREADENTRY32`.
///
/// **Layout matters, and `dw_size` is checked by the API.** `Thread32First`
/// refuses the call with `ERROR_INVALID_PARAMETER` unless `dwSize` is exactly
/// `sizeof(THREADENTRY32)`, so a missing field here is not a cosmetic defect: it
/// makes the suspended child's main thread unfindable, and with it every
/// execution through this backend fails with "cannot find the suspended sandbox
/// process's main thread to resume it". `tp_delta_pri` was missing, which is
/// exactly what happened; `tests/windows_resume_probe.rs` pins the size at 28.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ThreadEntry32 {
    /// `dwSize`, set by the caller to `size_of::<THREADENTRY32>()`.
    pub dw_size: u32,
    /// `cntUsage`.
    pub cnt_usage: u32,
    /// `th32ThreadID`.
    pub th32_thread_id: u32,
    /// `th32OwnerProcessID`.
    pub th32_owner_process_id: u32,
    /// `tpBasePri`.
    pub tp_base_pri: i32,
    /// `tpDeltaPri`.
    pub tp_delta_pri: i32,
    /// `dwFlags`.
    pub dw_flags: u32,
}

/// The last Win32 error, for diagnostics.
pub(crate) fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}
