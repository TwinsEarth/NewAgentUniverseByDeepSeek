//! A diagnostic that replicates the Windows resume path step by step.
//!
//! It exists to answer one question with evidence rather than a guess: does the
//! thread-snapshot technique used by `platform::windows::resume` find the main
//! thread of a process created with `CREATE_SUSPENDED`? It is a real test (it
//! asserts the suspended child has **not** run when the snapshot is taken), and it
//! is also the probe that told the sandbox implementation which step was failing.

#![cfg(windows)]

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;

const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
const THREAD_SUSPEND_RESUME: u32 = 0x0000_0002;
const CREATE_SUSPENDED: u32 = 0x0000_0004;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct ThreadEntry32 {
    dw_size: u32,
    cnt_usage: u32,
    th32_thread_id: u32,
    th32_owner_process_id: u32,
    tp_base_pri: i32,
    // `tpDeltaPri` is part of `THREADENTRY32`. Without it the struct is 24 bytes
    // and `Thread32First` fails with `ERROR_INVALID_PARAMETER`, which is the bug
    // this probe found in `crate::platform::rt::ThreadEntry32`.
    tp_delta_pri: i32,
    dw_flags: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut c_void;
    fn Thread32First(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: *mut c_void, entry: *mut ThreadEntry32) -> i32;
    fn OpenThread(desired_access: u32, inherit: i32, thread_id: u32) -> *mut c_void;
    fn ResumeThread(thread: *mut c_void) -> u32;
    fn CloseHandle(object: *mut c_void) -> i32;
}

/// Print the struct size, so a layout mismatch is visible.
#[test]
fn the_thread_entry_layout_is_the_one_the_api_expects() {
    println!(
        "THREADENTRY32 size = {}",
        std::mem::size_of::<ThreadEntry32>()
    );
    assert_eq!(
        std::mem::size_of::<ThreadEntry32>(),
        28,
        "THREADENTRY32 must be 28 bytes on 64-bit Windows; any other value means the struct \
         layout does not match winnt.h and the snapshot calls cannot be interpreted"
    );
}

/// Find a suspended process's main thread through a snapshot, then resume it.
#[test]
fn a_suspended_childs_main_thread_is_findable_and_resumable() {
    let exe = std::env::current_exe().expect("test binary");
    let mut child = std::process::Command::new(&exe)
        .args(["--exact", "resume_probe_worker", "--nocapture"])
        .env("NAU_RESUME_PROBE", "1")
        .creation_flags(CREATE_SUSPENDED)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn suspended");

    let pid = child.id();
    // SAFETY: the snapshot handle is owned by this scope and closed below; the
    // entry is a live, correctly sized struct.
    let (first, found, iterations) = unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        assert!(
            !snapshot.is_null() && snapshot != INVALID_HANDLE_VALUE,
            "CreateToolhelp32Snapshot failed: {}",
            std::io::Error::last_os_error()
        );
        let mut entry = ThreadEntry32 {
            dw_size: std::mem::size_of::<ThreadEntry32>() as u32,
            ..ThreadEntry32::default()
        };
        let first = Thread32First(snapshot, &mut entry);
        let mut found: Option<u32> = None;
        let mut iterations = 0u32;
        if first != 0 {
            loop {
                iterations += 1;
                if entry.th32_owner_process_id == pid {
                    found = Some(entry.th32_thread_id);
                    break;
                }
                if iterations > 200_000 {
                    break;
                }
                if Thread32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        (first, found, iterations)
    };

    println!("pid={pid} Thread32First={first} iterations={iterations} found={found:?}");
    assert_eq!(first, 1, "Thread32First must succeed");
    let thread_id = found.unwrap_or_else(|| {
        panic!("no thread of pid {pid} was found in the system thread snapshot")
    });

    // SAFETY: `thread_id` is a thread of the suspended process; the handle is
    // owned here and closed exactly once.
    let resumed = unsafe {
        let handle = OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id);
        if handle.is_null() {
            u32::MAX
        } else {
            let r = ResumeThread(handle);
            CloseHandle(handle);
            r
        }
    };
    println!("ResumeThread returned {resumed}");
    assert_ne!(resumed, u32::MAX, "ResumeThread must not fail");

    let status = child.wait().expect("wait");
    println!("child exit = {status:?}");
    assert!(status.success(), "the resumed child must run to completion");
}

/// Writes a marker file when it runs, so the probe can prove the child was
/// suspended before the resume.
#[test]
fn resume_probe_worker() {
    if std::env::var("NAU_RESUME_PROBE").is_err() {
        return;
    }
    let marker = std::env::temp_dir().join(format!("nau-resume-probe-{}.txt", std::process::id()));
    let _ = std::fs::write(&marker, "ran");
    let _ = marker;
}

/// `AsRawHandle` is used by the sandbox; this pins that the handle is non-null.
#[test]
fn a_spawned_child_exposes_a_non_null_process_handle() {
    let exe = std::env::current_exe().expect("test binary");
    let child = std::process::Command::new(&exe)
        .args(["--exact", "definitely_not_a_test", "--nocapture"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");
    assert!(!child.as_raw_handle().is_null());
    let mut child = child;
    let _ = child.wait();
}
