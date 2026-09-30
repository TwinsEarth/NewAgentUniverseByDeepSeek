//! A **worker** that the enforcement tests run *as the sandboxed child*.
//!
//! This machine has no Python and no Node, so a test that needs "some program that
//! misbehaves in a specific way" cannot reach for an interpreter. Instead the
//! sandboxed program is this very test binary, launched with
//! `--exact common::worker::selftest_worker` and told what to do by
//! `NAU_SELFTEST_MODE`. That is strictly better than depending on an interpreter:
//! the misbehaviour is written in Rust, the exit codes are deliberate, and the
//! test cannot silently pass because a tool was missing.
//!
//! When `NAU_SELFTEST_MODE` is unset the test is a no-op, which is what happens
//! during an ordinary `cargo test` run.
//!
//! # Why the output does not use `println!`
//!
//! `println!` goes through the process's line-buffered `Stdout`, and this worker
//! ends with `std::process::exit`, which does **not** flush it. The first version
//! of this file printed through `println!` and the enforcement tests saw an empty
//! string: the child had produced the evidence and thrown it away. [`say`] writes
//! through `stdout()` and flushes on every line, so what the worker says is what
//! the parent reads. That distinction is load-bearing for a suite whose whole point
//! is that every claim is backed by observed output.
//!
//! # Modes
//!
//! | mode | what the worker does |
//! |---|---|
//! | `env` | prints every environment variable it can see |
//! | `alloc` | tries to commit `NAU_SELFTEST_BYTES` and reports whether it succeeded |
//! | `spawn` | tries `NAU_SELFTEST_SPAWNS` times to create a long-lived child, reporting how many succeeded |
//! | `tree` | spawns one long-lived grandchild, prints its pid, then sleeps |
//! | `sleep` | sleeps for `NAU_SELFTEST_SLEEP_MS` |
//! | `print` | prints `NAU_SELFTEST_BYTES` bytes to stdout |
//! | `pwd` | prints its working directory and its process id |
//! | `write` | writes `NAU_SELFTEST_NAME` with contents `NAU_SELFTEST_TEXT` |
//! | `read` | tries to read `NAU_SELFTEST_NAME`, reporting whether it succeeded |
//! | `reads` | tries to read an absolute path in `NAU_SELFTEST_PATH` (the privilege probe) |

use std::io::Write;

/// The mode variable.
const MODE: &str = "NAU_SELFTEST_MODE";
/// A byte count.
const BYTES: &str = "NAU_SELFTEST_BYTES";
/// A spawn attempt count.
const SPAWNS: &str = "NAU_SELFTEST_SPAWNS";
/// A sleep duration in milliseconds.
const SLEEP_MS: &str = "NAU_SELFTEST_SLEEP_MS";
/// A file name.
const NAME: &str = "NAU_SELFTEST_NAME";
/// File contents.
const TEXT: &str = "NAU_SELFTEST_TEXT";
/// An absolute path.
const PATH: &str = "NAU_SELFTEST_PATH";

/// The `#[test]` name of this worker **as libtest sees it in the binary that
/// includes it**.
///
/// It is the module path because the module is declared in `tests/common/mod.rs`
/// as `pub mod worker`; the bare `selftest_worker` target is a second, harmless
/// copy of the same function.
const WORKER_TEST: &str = "common::worker::selftest_worker";

/// Write one line to this process's standard output and flush it.
///
/// See the module docs for why this is not `println!`.
///
/// The leading newline matters: libtest prints `test <name> ... ` with **no**
/// trailing newline, so a worker's first line would otherwise be glued to that
/// banner (`test common::worker::selftest_worker ... GRANDCHILD_PID 5952`) and no
/// `lines()`-based assertion could ever match it. Starting on a fresh line is what
/// makes each worker line addressable.
fn say(line: &str) {
    let mut out = std::io::stdout();
    let _ = out.write_all(b"\n");
    let _ = out.write_all(line.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// Write raw bytes to standard output and flush.
fn say_bytes(bytes: &[u8]) {
    let mut out = std::io::stdout();
    let _ = out.write_all(bytes);
    let _ = out.flush();
}

/// Run the worker if `NAU_SELFTEST_MODE` is set.
pub fn maybe_run() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    match mode.as_str() {
        "env" => dump_env(),
        "alloc" => alloc(),
        "spawn" => spawn_many(),
        "tree" => tree(),
        "sleep" => sleep(),
        "print" => print_bytes(),
        "pwd" => pwd(),
        "write" => write_file(),
        "read" => read_file(),
        "reads" => read_absolute(),
        other => {
            say(&format!("UNKNOWN_MODE {other}"));
            let _ = std::io::stdout().flush();
            std::process::exit(97);
        }
    }
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

/// Print every visible environment variable, one `NAME=value` per line.
///
/// Sorted so the test's assertions are stable. The upstream defect this serves:
/// the child ran with the daemon's own environment, so a sandbox could read host
/// secrets.
fn dump_env() {
    let mut vars: Vec<(String, String)> = std::env::vars().collect();
    vars.sort();
    say(&format!("ENV_COUNT {}", vars.len()));
    for (name, value) in vars {
        say(&format!("ENV {name}={value}"));
    }
}

/// Try to commit `BYTES` bytes, reporting the outcome.
fn alloc() {
    let bytes = env_usize(BYTES, 64 * 1024 * 1024);
    // `try_reserve` is used rather than a raw allocation so that a refusal is an
    // `Err` the worker can report rather than an abort with no output.
    let mut block: Vec<u8> = Vec::new();
    match block.try_reserve_exact(bytes) {
        Ok(()) => {
            // Touch every page: reserving address space is not committing memory,
            // and the limit under test is a commit limit.
            let mut i = 0;
            while i < bytes {
                block.push((i % 251) as u8);
                i += 4096;
            }
            say(&format!("ALLOC_OK {} bytes", block.len()));
            let _ = std::io::stdout().flush();
            std::process::exit(0);
        }
        Err(e) => {
            say(&format!("ALLOC_FAILED {e}"));
            let _ = std::io::stdout().flush();
            std::process::exit(3);
        }
    }
}

/// Try to create long-lived children, reporting how many were created.
///
/// The point is the *count that succeeded*: with a job-object active-process cap
/// the kernel refuses the spawn, and the child reports zero. The children are
/// sleepers, and every one of them dies with the job, so a test that runs this
/// cannot leave a process behind.
fn spawn_many() {
    let attempts = env_usize(SPAWNS, 8);
    let mut spawned = 0usize;
    let mut first_error: Option<String> = None;
    for _ in 0..attempts {
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(e) => {
                say(&format!("SPAWN_FAILED current_exe: {e}"));
                std::process::exit(4);
            }
        };
        match std::process::Command::new(exe)
            .arg("--exact")
            .arg(WORKER_TEST)
            .arg("--test-threads=1")
            .env_clear()
            .env("PATH", "C:\\Windows\\system32")
            .env(MODE, "sleep")
            .env(SLEEP_MS, "30000")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(_child) => spawned += 1,
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(e.to_string());
                }
                break;
            }
        }
    }
    say(&format!("SPAWNED {spawned} of {attempts}"));
    if let Some(e) = first_error {
        say(&format!("SPAWN_ERROR {e}"));
    }
    say(&format!("SPAWN_LIMIT_ENFORCED {}", spawned < attempts));
}

/// Spawn one long-lived grandchild, print its pid, then sleep.
///
/// The upstream defect this serves: the timeout killed a single pid, so a
/// backgrounded grandchild outlived the sandbox.
fn tree() {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            say(&format!("GRANDCHILD_FAILED {e}"));
            std::process::exit(5);
        }
    };
    match std::process::Command::new(exe)
        .arg("--exact")
        .arg(WORKER_TEST)
        .arg("--test-threads=1")
        .env_clear()
        .env("PATH", "C:\\Windows\\system32")
        .env(MODE, "sleep")
        .env(SLEEP_MS, "60000")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => {
            say(&format!("GRANDCHILD_PID {}", child.id()));
            say("GRANDCHILD_SPAWNED");
            sleep_ms(60_000);
        }
        Err(e) => {
            say(&format!("GRANDCHILD_FAILED {e}"));
            std::process::exit(6);
        }
    }
}

/// Sleep.
fn sleep() {
    sleep_ms(env_usize(SLEEP_MS, 1_000) as u64);
}

/// Print `BYTES` bytes to stdout.
fn print_bytes() {
    let bytes = env_usize(BYTES, 1_024);
    let chunk = vec![b'x'; 8_192];
    let mut written = 0usize;
    while written < bytes {
        let take = chunk.len().min(bytes - written);
        say_bytes(&chunk[..take]);
        written += take;
    }
}

/// Print the working directory and the process id.
fn pwd() {
    say(&format!(
        "PWD {}",
        std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|e| format!("<error: {e}>"))
    ));
    say(&format!("PID {}", std::process::id()));
}

/// Write a file in the working directory.
fn write_file() {
    let name = std::env::var(NAME).unwrap_or_else(|_| "out.txt".to_string());
    let text = std::env::var(TEXT).unwrap_or_else(|_| "written\n".to_string());
    match std::fs::write(&name, text) {
        Ok(()) => say(&format!("WROTE {name}")),
        Err(e) => {
            say(&format!("WRITE_FAILED {name}: {e}"));
            let _ = std::io::stdout().flush();
            std::process::exit(7);
        }
    }
}

/// Try to read a file in the working directory.
fn read_file() {
    let name = std::env::var(NAME).unwrap_or_else(|_| "out.txt".to_string());
    match std::fs::read_to_string(&name) {
        Ok(text) => say(&format!("READ {name} {}", text.trim())),
        Err(e) => say(&format!("READ_FAILED {name}: {e}")),
    }
}

/// Try to read an absolute path, to separate "the working directory is isolated"
/// from "the child is confined to it".
fn read_absolute() {
    let path = std::env::var(PATH).unwrap_or_default();
    match std::fs::read_to_string(&path) {
        Ok(text) => say(&format!("HOST_READ_OK {} {}", text.len(), path)),
        Err(e) => say(&format!("HOST_READ_FAILED {path}: {e}")),
    }
}

/// Sleep in small steps so a kill ends it promptly.
fn sleep_ms(ms: u64) {
    let step = std::time::Duration::from_millis(50);
    let mut left = ms;
    while left > 0 {
        std::thread::sleep(step);
        left = left.saturating_sub(50);
    }
}

/// Read a `usize` environment variable, with a default.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn selftest_worker() {
    maybe_run();
}
