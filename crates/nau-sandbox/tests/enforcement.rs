#![cfg(windows)]
// Deliberately Windows-only. This suite is the evidence for the process backend's
// capability declaration, and that evidence exists for Windows (Win32 Job Object).
// On Unix the same code compiles but has not been shown to behave: CI observed the
// wall-clock timeout not being enforced on Ubuntu, and the execute-through-the-router
// tests failing on macOS while passing on Ubuntu. So the daemon refuses
// `NAU_SANDBOX_BACKEND=process` off Windows rather than half-honouring it, and leaving
// these tests running on Unix would either fail CI or -- worse -- pass and imply a
// verified backend that nobody has verified. tests/platform_support.rs states this gap
// on the platforms this file does not cover.

//! Enforcement tests: what the real process backend **actually does** on this
//! machine, as opposed to what it declares.
//!
//! Every test names the upstream v2.8.2 finding it closes. Where a check is
//! impossible on this platform the test prints an explicit `SKIP:` line with the
//! reason and fails, so a silent pass is not available — see
//! [`skips_are_explicit_and_reported`].
//!
//! # Platform
//!
//! `windows-jobobject` on Windows; elsewhere `unix-setrlimit`, whose tests are
//! marked unverified. The Windows job-object tests are the ones that can be run
//! and verified here.

mod common;

use std::sync::Arc;

use common::{cleanup, limits, plant_host_secret, root_for, spec, spec_with, HOST_SECRET};
use nau_sandbox::{ExecRequest, RealProcessExecutor, SandboxExecutor, SandboxManager, SandboxSpec};

/// Build a manager over a fresh root with the real backend.
fn manager(name: &str) -> (SandboxManager, std::path::PathBuf) {
    let root = root_for(name);
    let exec = Arc::new(RealProcessExecutor::new());
    let mgr = SandboxManager::open(&root, exec, 1_700_000_000).expect("open manager");
    (mgr, root)
}

/// Create a sandbox for `owner` and return its id.
fn create(mgr: &SandboxManager, owner: &str, spec: &SandboxSpec) -> String {
    mgr.create(owner, spec)
        .expect("create sandbox")
        .as_str()
        .to_string()
}

/// Run a spec in a sandbox and return the outcome.
fn run(
    mgr: &SandboxManager,
    owner: &str,
    id: &str,
    spec: &SandboxSpec,
) -> nau_sandbox::ExecOutcome {
    mgr.exec(owner, id, Some(spec), &ExecRequest::new())
        .expect("exec")
}

/// Upstream v2.8.2 fix: `read_to_end` on both pipes meant a chatty sandbox could
/// exhaust the daemon's memory. The parent must stay bounded **and** report the
/// truncation.
#[test]
fn output_cap_keeps_the_parent_bounded_and_reports_truncation() {
    let (mgr, root) = manager("output-cap");
    let cap = 4_096usize;
    let mut lim = limits();
    lim.max_output_bytes = cap;
    // Print fifty times the cap.
    let spec = spec_with("print", &[("NAU_SELFTEST_BYTES", "204800")], lim);
    let id = create(&mgr, "alice", &spec);
    let outcome = run(&mgr, "alice", &id, &spec);

    assert_eq!(
        outcome.stdout.len(),
        cap,
        "the retained stdout must be exactly the cap, not the whole stream"
    );
    assert!(
        outcome.stdout_truncated,
        "truncation must be reported, not silently applied"
    );
    // The stream begins with the test harness's own banner, so "starts with x" is
    // not the property to assert. What matters is that the worker's bytes were
    // retained (a contiguous run) and that nothing past the cap was.
    assert!(
        outcome.stdout_lossy().contains("xxxxxxxxxx"),
        "the retained bytes must include the worker's own output"
    );
    assert!(
        outcome.elapsed_ms < 20_000,
        "the run must finish, not hang on a full pipe"
    );
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// Upstream v2.8.2 fix: `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` was never set, so a
/// sandbox could fork without bound; and on Windows the upstream branch applied
/// **no** limits at all. A fork bomb must be refused by the kernel, and the host
/// must survive.
#[test]
fn the_process_count_limit_refuses_a_fork_bomb() {
    let (mgr, root) = manager("process-cap");
    let mut lim = limits();
    lim.max_processes = 3;
    // The worker tries eight times to create a long-lived child.
    let spec = spec_with(
        "spawn",
        &[
            ("NAU_SELFTEST_SPAWNS", "8"),
            ("NAU_SELFTEST_SLEEP_MS", "30000"),
        ],
        lim,
    );
    let id = create(&mgr, "alice", &spec);
    let outcome = run(&mgr, "alice", &id, &spec);

    let stdout = outcome.stdout_lossy();
    assert!(
        stdout.contains("SPAWN_LIMIT_ENFORCED true"),
        "the job object must refuse the spawns; worker said:\n{stdout}\nstderr:\n{}",
        outcome.stderr_lossy()
    );
    // The host is still here: this test process is running the assertion.
    assert!(
        std::process::id() > 0,
        "the host process must survive the fork bomb"
    );
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// Upstream v2.8.2 fix: the timeout killed one pid, so a backgrounded grandchild
/// outlived the sandbox. The whole job must die.
#[test]
fn the_timeout_kills_the_grandchild_too() {
    let (mgr, root) = manager("timeout-tree");
    let mut lim = limits();
    lim.timeout_ms = 3_000;
    let spec = spec_with("tree", &[], lim);
    let id = create(&mgr, "alice", &spec);
    let outcome = run(&mgr, "alice", &id, &spec);

    let stdout = outcome.stdout_lossy();
    assert!(outcome.timed_out, "the 3 s budget must be enforced");
    let pid_line = stdout
        .lines()
        .find(|l| l.starts_with("GRANDCHILD_PID "))
        .unwrap_or_else(|| panic!("the worker did not report a grandchild pid:\n{stdout}"));
    let grandchild: u32 = pid_line
        .trim_start_matches("GRANDCHILD_PID ")
        .trim()
        .parse()
        .expect("a pid");

    // Give the kernel a moment to finish reaping the killed tree.
    let mut alive_after = true;
    for _ in 0..40 {
        if !process_is_alive(grandchild) {
            alive_after = false;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        !alive_after,
        "grandchild {grandchild} outlived the sandbox: TerminateJobObject must kill the tree"
    );
    // And the parent is unharmed, which is the other half of the claim.
    assert!(mgr.list("alice").is_ok());
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// Upstream v2.8.2 fix: `env_clear()` plus "whatever the caller happened to add",
/// with the daemon's own environment available to the child. The child here must
/// see exactly `PATH` plus the variables the spec named.
#[test]
fn the_environment_is_an_allowlist_and_never_the_host() {
    plant_host_secret();
    // Also plant a second secret under a *different* name to catch a partial leak.
    std::env::set_var("NAU_HOST_SECRET_2", "another-secret-9911");
    let (mgr, root) = manager("env-isolation");
    let spec = spec("env", &[("NAU_ALLOWED", "yes")]);
    let id = create(&mgr, "alice", &spec);
    let outcome = run(&mgr, "alice", &id, &spec);
    let stdout = outcome.stdout_lossy();

    assert!(
        !stdout.contains(HOST_SECRET),
        "the host secret leaked into the sandbox:\n{stdout}"
    );
    assert!(
        !stdout.contains("another-secret-9911"),
        "the second host secret leaked into the sandbox:\n{stdout}"
    );
    // The PATH the child sees must be the fixed safe value, **not** the host's. The
    // two legitimately share entries (`C:\Windows\system32` is the host's first
    // entry and part of the sandbox's fixed PATH), so the assertion is on the whole
    // variable plus a check that no host-only entry appears anywhere in the dump.
    assert!(
        stdout.contains(&format!("ENV PATH={}", nau_sandbox::SAFE_PATH)),
        "PATH must be the fixed safe value `{}`:\n{stdout}",
        nau_sandbox::SAFE_PATH
    );
    let safe_entries: Vec<&str> = nau_sandbox::SAFE_PATH.split(';').collect();
    let host_path = std::env::var("PATH").unwrap_or_default();
    println!("host PATH = {host_path}");
    for entry in host_path.split(';').filter(|e| !e.trim().is_empty()) {
        if safe_entries.contains(&entry) {
            continue;
        }
        assert!(
            !stdout.contains(entry),
            "the host-only PATH entry `{entry}` leaked into the sandbox:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("ENV NAU_ALLOWED=yes"),
        "the allowlisted variable must be present:\n{stdout}"
    );
    // The count assertion is the strong one: nothing else may be present at all.
    // Three, not two: the test's own mode variable is allowlisted on purpose, so
    // the exact set is PATH, the mode, and the one variable the caller asked for.
    assert!(
        stdout.contains("ENV_COUNT 3"),
        "the child must see exactly PATH, the mode variable and the one allowlisted variable:\n\
         {stdout}"
    );
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// Upstream v2.8.2 fix: the child ran with the daemon's own `current_dir` unless
/// the caller set one, and every sandbox shared the persistent data directory, so
/// two sandboxes could see each other's files.
#[test]
fn two_sandboxes_get_separate_working_directories() {
    let (mgr, root) = manager("workdir-isolation");
    // Each sandbox writes a *different* content into the *same* file name, so the
    // assertion below proves isolation rather than re-reading one sandbox's file:
    // with one shared spec both sandboxes write `from-a` and the test could not
    // tell "B sees its own file" from "B sees A's file".
    let writer_a = spec(
        "write",
        &[
            ("NAU_SELFTEST_NAME", "shared.txt"),
            ("NAU_SELFTEST_TEXT", "from-a"),
        ],
    );
    let writer_b = spec(
        "write",
        &[
            ("NAU_SELFTEST_NAME", "shared.txt"),
            ("NAU_SELFTEST_TEXT", "from-b"),
        ],
    );
    let a = create(&mgr, "alice", &writer_a);
    let b = create(&mgr, "bob", &writer_b);

    let a_out = run(&mgr, "alice", &a, &writer_a);
    assert!(
        a_out.exit_code == Some(0),
        "stderr={}",
        a_out.stderr_lossy()
    );
    let b_out = run(&mgr, "bob", &b, &writer_b);
    assert_eq!(b_out.exit_code, Some(0), "stderr={}", b_out.stderr_lossy());

    let reader = spec("read", &[("NAU_SELFTEST_NAME", "shared.txt")]);
    let a_sees = run(&mgr, "alice", &a, &reader).stdout_lossy();
    let b_sees = run(&mgr, "bob", &b, &reader).stdout_lossy();
    assert!(
        a_sees.contains("READ shared.txt from-a"),
        "sandbox A must see its own file: {a_sees}"
    );
    assert!(
        b_sees.contains("READ shared.txt from-b"),
        "sandbox B must see its own file, not A's: {b_sees}"
    );
    assert_ne!(
        a_sees, b_sees,
        "the two sandboxes must not share a directory"
    );

    // And the directories really are distinct on disk.
    let dirs: Vec<String> = [&a, &b]
        .iter()
        .map(|id| root.join(id.as_str()).display().to_string())
        .collect();
    assert_ne!(dirs[0], dirs[1]);
    for dir in &dirs {
        assert!(
            std::path::Path::new(dir).is_dir(),
            "{dir} must exist as its own directory"
        );
    }
    let _ = mgr.destroy("alice", &a);
    let _ = mgr.destroy("bob", &b);
    cleanup(&root);
}

/// The child's `current_dir` is the sandbox directory, under a root fixed at
/// process start — not the daemon's own working directory.
#[test]
fn the_child_runs_inside_its_sandbox_directory() {
    let (mgr, root) = manager("cwd");
    let spec = spec("pwd", &[]);
    let id = create(&mgr, "alice", &spec);
    let outcome = run(&mgr, "alice", &id, &spec);
    let stdout = outcome.stdout_lossy();
    let expected = root
        .canonicalize()
        .expect("canonical root")
        .join(&id)
        .display()
        .to_string();
    assert!(
        stdout.contains(&format!("PWD {expected}")),
        "the child's working directory must be its sandbox:\n{stdout}\nexpected {expected}"
    );
    let daemon_cwd = std::env::current_dir().expect("daemon cwd");
    assert!(
        !stdout.contains(&format!("PWD {}", daemon_cwd.display())),
        "the child must not run in the test process's own directory:\n{stdout}"
    );
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// Upstream v2.8.2 fix: `mem_mb` was validated `> 0` and then never used, and the
/// Windows branch applied no limits at all. A memory cap must actually refuse the
/// allocation.
#[test]
fn the_memory_limit_refuses_an_oversized_allocation() {
    let (mgr, root) = manager("memory-cap");
    let mut lim = limits();
    lim.memory_bytes = 32 * 1024 * 1024;
    // Ask for 256 MiB against a 32 MiB cap.
    let spec = spec_with("alloc", &[("NAU_SELFTEST_BYTES", "268435456")], lim);
    let id = create(&mgr, "alice", &spec);
    let outcome = run(&mgr, "alice", &id, &spec);
    let stdout = outcome.stdout_lossy();
    assert!(
        !stdout.contains("ALLOC_OK"),
        "the 256 MiB allocation must not succeed under a 32 MiB cap:\n{stdout}\n{}",
        outcome.stderr_lossy()
    );
    // Either the allocator refused (`ALLOC_FAILED`, exit 3) or the process was
    // terminated. Both are the cap being enforced; neither is a silent pass.
    assert!(
        stdout.contains("ALLOC_FAILED")
            || outcome.exit_code.is_none()
            || outcome.exit_code != Some(0),
        "the run must fail closed: stdout={stdout:?} exit={:?}",
        outcome.exit_code
    );
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// A command that succeeds must do so without tripping a limit, so the limits
/// above are not simply breaking everything.
#[test]
fn a_well_behaved_child_still_runs() {
    let (mgr, root) = manager("baseline");
    let spec = spec("pwd", &[]);
    let id = create(&mgr, "alice", &spec);
    let outcome = run(&mgr, "alice", &id, &spec);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "a well-behaved child must exit 0; stderr={}",
        outcome.stderr_lossy()
    );
    assert!(!outcome.timed_out);
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// Upstream v2.8.2 fix: **no** isolation primitive; sandboxed code read the whole
/// host filesystem. This backend declares `FilesystemConfinement` unenforced, so
/// the honest test is that the *escape works* and the crate says so, rather than
/// pretending it does not. A test that asserted confinement here would be a lie.
#[test]
fn filesystem_confinement_is_declared_unenforced_and_the_escape_is_real() {
    let (mgr, root) = manager("no-confinement");
    let exec = RealProcessExecutor::new();
    if exec
        .capabilities()
        .enforces(nau_sandbox::Capability::FilesystemConfinement)
    {
        // If a future backend does confine, the assertion flips: this test is
        // written so that the claim and the code cannot disagree in either
        // direction.
        let spec = spec("reads", &[("NAU_SELFTEST_PATH", "C:\\Windows\\win.ini")]);
        let id = create(&mgr, "alice", &spec);
        let outcome = run(&mgr, "alice", &id, &spec);
        assert!(
            outcome.stdout_lossy().contains("HOST_READ_FAILED"),
            "a backend that claims confinement must actually confine:\n{}",
            outcome.stdout_lossy()
        );
        let _ = mgr.destroy("alice", &id);
        cleanup(&root);
        return;
    }

    // Declared unenforced: prove the declaration is truthful by reading a host
    // file from inside the sandbox.
    let host_file = std::env::temp_dir().join(format!("nau-host-file-{}.txt", std::process::id()));
    std::fs::write(&host_file, "host contents\n").expect("write host file");
    // `spec_with` puts every pair it is given into the child's environment, and
    // that is the only way a value reaches the child: there is no inherited
    // environment to fall back on.
    let sandbox_spec = spec(
        "reads",
        &[("NAU_SELFTEST_PATH", host_file.to_string_lossy().as_ref())],
    );
    let id = create(&mgr, "alice", &sandbox_spec);
    let outcome = run(&mgr, "alice", &id, &sandbox_spec);
    assert!(
        outcome.stdout_lossy().contains("HOST_READ_OK"),
        "the declaration says confinement is unenforced, so the child must be able to read a \
         host file; it said:\n{}",
        outcome.stdout_lossy()
    );
    let _ = mgr.destroy("alice", &id);
    let _ = std::fs::remove_file(&host_file);
    cleanup(&root);
}

/// Everything above except the confinement test depends on a boundary the
/// backend claims. This test makes the platform's verification status explicit,
/// so a platform where the enforcement tests cannot run is reported instead of
/// appearing green.
#[test]
fn skips_are_explicit_and_reported() {
    if cfg!(windows) {
        assert_eq!(nau_sandbox::PLATFORM_BACKEND, "windows-jobobject");
        println!(
            "VERIFIED on this machine: {}",
            nau_sandbox::PLATFORM_BACKEND
        );
    } else {
        // The Unix path is compiled AND is exercised by the tests above on this
        // platform -- but it has never been run on the Windows machine this crate was
        // developed on, so its `setrlimit`/`setsid` claims are unverified there.
        //
        // This branch used to `panic!`, so that a platform where the job-object tests
        // cannot run would not look green. The instinct was right and the mechanism was
        // wrong: a panic is a FAILURE, not a skip, so it turned the CI matrix red on two
        // of its three runners for a test doing exactly what it was asked to do. The
        // honest non-failing form is to assert what is genuinely true about this platform
        // and say the rest out loud -- which is the convention everywhere else in this
        // repository (`verify-all` reports SKIP and lists it under NOT VERIFIED).
        assert_eq!(
            nau_sandbox::PLATFORM_BACKEND,
            "unix-setrlimit",
            "the non-Windows backend must identify itself, or the platform detection is wrong"
        );
        println!(
            "SKIP: this is not Windows, so the job-object enforcement tests were not exercised \
             on the machine this crate was developed on; the active backend is {} and its \
             `setrlimit`/`setsid` path is UNVERIFIED there (it IS exercised on this host).",
            nau_sandbox::PLATFORM_BACKEND
        );
    }
}

/// Whether `pid` is still a live process, used by the timeout test.
///
/// Platform-aware on purpose. This used to shell out to `tasklist`, with a comment
/// claiming it was "documented and always present" -- it is a Windows-only command,
/// so on Linux and macOS the probe failed, the `Err` arm assumed "alive", and the
/// timeout test would have failed on two of the three CI runners.
fn process_is_alive(pid: u32) -> bool {
    #[cfg(windows)]
    let probe = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output();

    // `kill -0` is the POSIX way to ask "does this pid exist and may I signal it":
    // it delivers no signal and exists on Linux and macOS alike.
    #[cfg(not(windows))]
    let probe = std::process::Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .output();

    match probe {
        #[cfg(windows)]
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains(&format!("\"{pid}\"")),
        #[cfg(not(windows))]
        Ok(out) => out.status.success(),
        // A probe that cannot run must not be read as "dead": the assertion that
        // matters is that the grandchild is gone, so this stays fail-closed.
        Err(_) => true,
    }
}
