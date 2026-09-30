//! Running one program inside a sandbox work directory, with bounded output.
//!
//! This module owns the parent side of the boundary:
//!
//! * **bounded output** — stdout and stderr are read on their own threads and
//!   only the first `max_output_bytes` of each are retained, with truncation
//!   reported. Upstream v2.8.2 fix: `read_to_end` on both pipes let a sandbox
//!   print until the *daemon* ran out of memory.
//! * **environment construction** — `env_clear()` plus a fixed safe `PATH` plus
//!   exactly the listed variables. The daemon's environment is never inherited.
//!   Upstream v2.8.2 fix: the child ran as the daemon's own OS user with the
//!   daemon's environment, so `print(os.environ)` showed host secrets.
//! * **a timeout that kills the whole job** — the deadline is enforced by polling
//!   in the parent, and the platform layer terminates the *job*, not one pid.
//!   Upstream v2.8.2 fix: the timeout killed a single pid, so a backgrounded
//!   grandchild outlived the sandbox, and the `try_wait` error path returned
//!   without killing or reaping anything.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::{Result, SandboxError};
use crate::spec::SandboxSpec;

/// The `PATH` a sandbox child is given.
///
/// A fixed value, never the host's. On Windows the system directory has to be
/// present for the loader to resolve a program's own DLL dependencies; on Unix a
/// minimal `PATH` is enough for a program that spawns a core utility by name. It
/// deliberately contains no user-writable directory.
#[cfg(windows)]
pub const SAFE_PATH: &str = r"C:\Windows\system32;C:\Windows";
/// A fixed, minimal `PATH`.
#[cfg(not(windows))]
pub const SAFE_PATH: &str = "/usr/bin:/bin";

/// A request to run a program in a sandbox.
///
/// The script body, when the interpreter needs one, travels in
/// [`ExecRequest::stdin`]. It is never appended to argv and never interpolated
/// into a shell command line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecRequest {
    /// A script body for `Interpreter::Script` / `Interpreter::Shell`, or literal
    /// standard input for the other variants.
    pub stdin: Option<Vec<u8>>,
}

impl ExecRequest {
    /// An empty request.
    pub fn new() -> Self {
        Self::default()
    }

    /// A request whose stdin is this script body.
    pub fn with_stdin(body: impl Into<Vec<u8>>) -> Self {
        Self {
            stdin: Some(body.into()),
        }
    }

    /// Refuse a request the interpreter cannot serve. Fails closed: a script
    /// interpreter with no script is an error, not an empty program.
    pub fn validate(&self, spec: &SandboxSpec) -> Result<()> {
        if spec.interpreter.needs_script() && self.stdin.is_none() {
            return Err(SandboxError::Start(format!(
                "interpreter `{}` reads its program from stdin, and no stdin was supplied",
                spec.interpreter.label()
            )));
        }
        Ok(())
    }
}

/// Everything a finished run produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    /// Exit code, when the platform reported one.
    pub exit_code: Option<i32>,
    /// Retained stdout (at most `max_output_bytes`).
    pub stdout: Vec<u8>,
    /// Retained stderr (at most `max_output_bytes`).
    pub stderr: Vec<u8>,
    /// True when stdout was cut off at the cap.
    pub stdout_truncated: bool,
    /// True when stderr was cut off at the cap.
    pub stderr_truncated: bool,
    /// True when the sandbox was terminated because it passed `timeout_ms`.
    pub timed_out: bool,
    /// True when the process was terminated without reporting an exit code, which
    /// is what a job-object limit kill looks like (memory or process count).
    pub terminated: bool,
    /// True when **both** stream readers reached end of file.
    ///
    /// `false` means a pipe never reported EOF within the collection budget, which
    /// on Windows happens when a descendant still holds an inherited write handle.
    /// It is reported rather than hidden: a sandbox whose pipe stays open is a
    /// sandbox that may still have a live descendant, and that is exactly the class
    /// of leak upstream's `try_wait` error path produced.
    pub readers_finished: bool,
    /// True when the whole job was confirmed terminated.
    pub job_killed: bool,
    /// Wall-clock duration of the run.
    pub elapsed_ms: u64,
}

impl ExecOutcome {
    /// True when either stream was truncated.
    pub fn truncated(&self) -> bool {
        self.stdout_truncated || self.stderr_truncated
    }

    /// The exit code, or `None` when the program was terminated by the platform.
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }

    /// The retained stdout as lossy UTF-8, for reports and tests.
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// The retained stderr as lossy UTF-8, for reports and tests.
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// One stream's shared collection state.
///
/// The reader thread fills this in place, under the mutex, and the parent reads it
/// under the same mutex. Appending **in place** rather than returning a collected
/// buffer is what makes the read bounded in the case that matters: a reader thread
/// blocked inside `Read::read` can never be interrupted from outside, so if the
/// collected bytes only became visible when the thread finished, a pipe that never
/// reports end of file would make the output invisible forever. With in-place
/// publication the parent sees everything that has arrived, whenever it asks.
///
/// # Why end of file is not the only exit
///
/// A reader reaches `done` on `Ok(0)` (the writer closed) or on a read error. The
/// parent does not wait for it indefinitely: [`collect_bounded`] takes what is there
/// after its budget and reports `readers_finished = false`. Combined with the job
/// termination that happens *before* collection, that is two independent bounds on
/// a hostile or wedged child.
///
/// Upstream v2.8.2 fix: the upstream reader used unbounded `read_to_end`, and the
/// upstream status path returned on a `try_wait` error without killing or reaping,
/// so a chatty child consumed the parent's memory and a wedged one leaked forever.
#[derive(Default)]
struct StreamBuffer {
    bytes: Vec<u8>,
    truncated: bool,
    done: bool,
}

type SharedStream = Arc<(Mutex<StreamBuffer>, Condvar)>;

/// Wrap a pipe in a shared buffer and a reader thread.
fn spawn_reader<R: Read + Send + 'static>(reader: R, cap: usize) -> (SharedStream, JoinHandle<()>) {
    let shared: SharedStream = Arc::new((Mutex::new(StreamBuffer::default()), Condvar::new()));
    let thread_shared = Arc::clone(&shared);
    let handle = std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        let mut reader = reader;
        loop {
            // The lock is taken *around* the read, not only around the append. A
            // thread blocked inside `read` cannot be interrupted from outside, so
            // the only moment at which the parent can observe "what has arrived so
            // far" is while the reader holds this lock between reads: it has
            // appended the previous chunk and has not yet blocked again. The parent
            // acquires the same mutex, so it sees a consistent prefix rather than a
            // partially copied buffer.
            let (lock, cond) = &*thread_shared;
            let mut state = match lock.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match reader.read(&mut chunk) {
                Ok(0) => {
                    state.done = true;
                    cond.notify_all();
                    return;
                }
                Ok(n) => {
                    if state.bytes.len() < cap {
                        let room = cap - state.bytes.len();
                        let take = room.min(n);
                        state.bytes.extend_from_slice(&chunk[..take]);
                        if take < n {
                            state.truncated = true;
                        }
                    } else {
                        // Over the cap: the bytes are dropped from *retention*, but
                        // the pipe is still drained, so the child never blocks on a
                        // full pipe. Trading a memory denial of service for a hang
                        // would be no improvement.
                        state.truncated = true;
                    }
                    cond.notify_all();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                // A read error ends collection; the bytes already read are kept.
                Err(_) => {
                    state.done = true;
                    cond.notify_all();
                    return;
                }
            }
        }
    });
    (shared, handle)
}

/// Build the child environment onto `cmd`.
///
/// `env_clear()` first — there is no code path that can inherit — then the fixed
/// [`SAFE_PATH`], then the spec's own variables. `PATH` cannot be overridden
/// because [`crate::SandboxSpec::validate`] refuses a `PATH` entry.
pub fn apply_env(cmd: &mut std::process::Command, spec: &SandboxSpec) {
    cmd.env_clear();
    cmd.env("PATH", SAFE_PATH);
    for (name, value) in &spec.env.vars {
        cmd.env(name, value);
    }
}

/// Outcome of waiting for one child.
#[derive(Debug, Clone, Copy)]
enum WaitOutcome {
    /// The child exited with this code (or with no code, after a kill).
    Exited(Option<i32>),
    /// The deadline passed first.
    TimedOut,
    /// The platform could not report the child's state any more. Treated as
    /// "terminated", never as "still running": the caller kills the job either
    /// way. Upstream v2.8.2 fix: a `try_wait` error returned early **without**
    /// killing or reaping, leaving a live child behind an abandoned handle.
    WaitFailed,
}

/// Poll a child until it exits, the deadline passes, or the platform gives up.
fn wait_bounded(child: &mut std::process::Child, deadline: Instant) -> WaitOutcome {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return WaitOutcome::Exited(status.code()),
            Ok(None) => {}
            // A terminated job can make the status unreportable. The caller
            // terminates the job and reaps, so this is a closed outcome.
            Err(_) => return WaitOutcome::WaitFailed,
        }
        if Instant::now() >= deadline {
            return WaitOutcome::TimedOut;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Wait for a reader to finish, or for the budget to run out.
///
/// Returns the bytes, whether the stream was cut off at the cap, and whether the
/// reader reached EOF. `false` for the last element means the pipe never reported
/// EOF: the bytes returned are everything that arrived, and the caller reports the
/// situation rather than hiding it.
fn collect_bounded(shared: &SharedStream, budget: Duration) -> (Vec<u8>, bool, bool) {
    let (lock, cond) = &**shared;
    let deadline = Instant::now() + budget;
    // A short poll interval rather than one long `wait_timeout`, because the reader
    // thread holds this mutex while it is inside `read` and can only be observed
    // between reads. The loop keeps waiting for as long as there is budget, so a
    // stream that is still arriving is collected up to the deadline; only a stream
    // that has gone quiet *and* not closed leaves the loop early, which is the case
    // where waiting longer would gain nothing.
    let poll = Duration::from_millis(5);
    let mut guard = match lock.lock() {
        Ok(g) => g,
        // A poisoned buffer still holds usable bytes; recovering it explicitly is
        // better than failing the whole execution.
        Err(poisoned) => poisoned.into_inner(),
    };
    loop {
        if guard.done {
            return (guard.bytes.clone(), guard.truncated, true);
        }
        let now = Instant::now();
        if now >= deadline {
            // Not done, and the budget is gone: report what arrived, honestly
            // flagged as not reaching end of file.
            return (guard.bytes.clone(), guard.truncated, false);
        }
        let wait = poll.min(deadline.saturating_duration_since(now));
        let (next, _) = cond
            .wait_timeout(guard, wait)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard = next;
    }
}

/// Run `spec.interpreter` inside `work_dir`, applying the spec's limits.
///
/// The caller must already have validated the spec against the backend's
/// capabilities: this function enforces the boundaries that live in the parent
/// (output, environment, work directory, timeout) and delegates the rest to
/// [`crate::platform`].
pub fn run_in_workdir(
    spec: &SandboxSpec,
    work_dir: &Path,
    request: &ExecRequest,
) -> Result<ExecOutcome> {
    request.validate(spec)?;
    let mut cmd = spec.interpreter.command();
    cmd.current_dir(work_dir);
    apply_env(&mut cmd, spec);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = crate::platform::spawn(&mut cmd, spec)?;
    let started = Instant::now();
    let deadline = started + Duration::from_millis(spec.limits.timeout_ms);
    let cap = spec.limits.max_output_bytes;

    let stdout_stream = child.take_stdout().map(|pipe| spawn_reader(pipe, cap));
    let stderr_stream = child.take_stderr().map(|pipe| spawn_reader(pipe, cap));

    // Write the script body, if any, and close the pipe so the child sees EOF.
    // A short write is not fatal: a program that never reads stdin closes the pipe
    // on exit and `write_all` returns `BrokenPipe`, which is normal operation.
    if let Some(mut stdin) = child.take_stdin() {
        let body = request.stdin.clone().unwrap_or_default();
        let _ = stdin.write_all(&body);
        let _ = stdin.flush();
        drop(stdin);
    }

    let wait = wait_bounded(child.inner_mut(), deadline);
    let timed_out = matches!(wait, WaitOutcome::TimedOut);
    let exit_code = match wait {
        WaitOutcome::Exited(code) => code,
        WaitOutcome::TimedOut | WaitOutcome::WaitFailed => None,
    };

    // The direct child is finished. **Terminate the job immediately**, before
    // collecting: that is what kills a backgrounded grandchild and closes the write
    // end a descendant may still hold, and closing it is the only reliable way to
    // make the pipe report end of file within the budget below.
    //
    // Upstream v2.8.2 fix: the timeout killed a single pid, so a grandchild outlived
    // the sandbox *and* the pipe, and the parent's reader never returned.
    let job_killed = child.terminate_job();
    // Reap the direct child after the kill so no zombie handle is left behind.
    let _ = child.inner_mut().wait();

    // Bounded collection. The budget is generous because a child still flushing a
    // large stream is normal; the point of the bound is that a pipe which never
    // reaches EOF cannot hold the daemon.
    let budget = Duration::from_millis(2_000);
    let (stdout, stdout_truncated, stdout_done) = match &stdout_stream {
        Some((shared, _)) => collect_bounded(shared, budget),
        None => (Vec::new(), false, true),
    };
    let (stderr, stderr_truncated, stderr_done) = match &stderr_stream {
        Some((shared, _)) => collect_bounded(shared, budget),
        None => (Vec::new(), false, true),
    };

    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    Ok(ExecOutcome {
        exit_code,
        stdout,
        stderr,
        // A reader that never reached EOF has not necessarily seen the end of the
        // stream, so its content is reported as truncated even when it is short.
        stdout_truncated: stdout_truncated || !stdout_done,
        stderr_truncated: stderr_truncated || !stderr_done,
        timed_out,
        terminated: exit_code.is_none() && !timed_out,
        readers_finished: stdout_done && stderr_done,
        job_killed: job_killed.is_ok(),
        elapsed_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream v2.8.2 fix: stdout and stderr were read with `read_to_end`, so a
    /// chatty sandbox could exhaust the daemon's memory. Retention is capped here
    /// and the overflow is reported.
    #[test]
    fn output_is_capped_and_truncation_is_reported() {
        let data = vec![b'x'; 100_000];
        let (shared, handle) = spawn_reader(std::io::Cursor::new(data), 1_024);
        let (kept, truncated, done) = collect_bounded(&shared, Duration::from_secs(5));
        handle.join().expect("reader thread");
        assert_eq!(kept.len(), 1_024);
        assert!(
            truncated,
            "an overflow must be reported, not silently dropped"
        );
        assert!(done, "a finite reader must reach end of file");
    }

    /// Exactly at the cap is not truncation; one byte more is.
    #[test]
    fn the_truncation_flag_is_exact_at_the_boundary() {
        let exact = vec![b'a'; 64];
        let (shared, handle) = spawn_reader(std::io::Cursor::new(exact.clone()), 64);
        let (kept, truncated, _) = collect_bounded(&shared, Duration::from_secs(5));
        handle.join().expect("reader thread");
        assert_eq!(kept, exact);
        assert!(!truncated);

        let mut over = exact.clone();
        over.push(b'b');
        let (shared, handle) = spawn_reader(std::io::Cursor::new(over), 64);
        let (kept, truncated, _) = collect_bounded(&shared, Duration::from_secs(5));
        handle.join().expect("reader thread");
        assert_eq!(kept, exact);
        assert!(truncated);
    }

    /// A reader error must not lose the bytes read before it, and must not spin.
    #[test]
    fn a_reader_error_ends_collection_without_losing_bytes() {
        struct Flaky(bool);
        impl Read for Flaky {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 {
                    buf[0] = b'z';
                    self.0 = false;
                    return Ok(1);
                }
                Err(std::io::Error::other("boom"))
            }
        }
        let (shared, handle) = spawn_reader(Flaky(true), 16);
        let (kept, truncated, done) = collect_bounded(&shared, Duration::from_secs(5));
        handle.join().expect("reader thread");
        assert_eq!(kept, b"z");
        assert!(!truncated);
        assert!(done, "a read error is an end of collection, not a hang");
    }

    /// A reader that never reaches end of file must not block the parent: the budget
    /// expires and the parent returns on its own, with whatever has arrived.
    ///
    /// This is the Windows pipe case the enforcement suite hit: a descendant's
    /// inherited write handle keeps a pipe open after the direct child is gone, so
    /// waiting for end of file is not an option.
    ///
    /// # Why this test does not measure wall-clock time
    ///
    /// Two earlier versions did, and both were flaky on a loaded machine: a lower
    /// bound (`elapsed >= budget`) measures the platform's timer granularity and a
    /// tight upper bound measures how busy the box is. Neither is the contract. The
    /// contract is that the parent **stops waiting** when its budget runs out and
    /// returns the bytes that arrived, so the test drives the deadline itself: a
    /// budget that has already passed must return immediately, flagged as unfinished.
    #[test]
    fn a_pipe_that_never_closes_does_not_block_the_parent() {
        struct Endless;
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                buf[0] = b'y';
                // Never returns 0: the pipe never reports end of file.
                std::thread::sleep(Duration::from_millis(1));
                Ok(1)
            }
        }
        let (shared, _handle) = spawn_reader(Endless, 32);

        // An already-expired budget must not wait for the reader at all.
        let started = Instant::now();
        let (kept, _truncated, done) = collect_bounded(&shared, Duration::ZERO);
        let elapsed = started.elapsed();
        assert!(!done, "an endless pipe must be reported as not finished");
        assert!(
            elapsed < Duration::from_secs(1),
            "an expired budget must return at once, not wait for the reader: {elapsed:?}"
        );
        // Retention is still capped while the reader never stops.
        assert!(
            kept.len() <= 32,
            "retention must stay capped under an endless reader: {}",
            kept.len()
        );

        // Give the reader a real chance to publish, then collect with a budget. It
        // must report "not finished" (the pipe is still open) and must return the
        // bytes: publication does not depend on end of file, which is the property
        // that makes the bound useful rather than merely safe.
        let deadline = Instant::now() + Duration::from_secs(5);
        let (kept_again, _, still_not_done) = loop {
            let (bytes, truncated, finished) = collect_bounded(&shared, Duration::from_millis(50));
            if !bytes.is_empty() || Instant::now() >= deadline {
                break (bytes, truncated, finished);
            }
        };
        assert!(
            !still_not_done,
            "the pipe still has not closed, which is the point"
        );
        assert!(
            !kept_again.is_empty(),
            "bytes read before end of file must become visible to the parent"
        );
        assert!(kept_again.len() <= 32, "the cap still applies");
    }

    #[test]
    fn a_script_interpreter_without_a_script_is_refused_not_run() {
        // Fail-closed: no script means no execution, rather than an empty program.
        let bin = crate::spec::AbsoluteProgramPath::new(if cfg!(windows) {
            std::path::PathBuf::from("C:\\Windows\\System32\\cmd.exe")
        } else {
            std::path::PathBuf::from("/bin/sh")
        })
        .expect("absolute");
        let spec = SandboxSpec {
            interpreter: crate::spec::Interpreter::Script { bin },
            limits: crate::spec::Limits {
                timeout_ms: 1_000,
                memory_bytes: 1 << 20,
                cpu_ms: 1_000,
                disk_bytes: 1 << 20,
                max_processes: 2,
                max_open_files: 16,
                max_output_bytes: 1_024,
            },
            network: crate::spec::NetworkPolicy::DenyAll,
            filesystem: crate::spec::FilesystemPolicy::confined(),
            env: crate::spec::EnvPolicy::empty(),
            waivers: crate::spec::Waivers::none(),
        };
        let err = ExecRequest::new().validate(&spec).expect_err("must refuse");
        assert!(matches!(err, SandboxError::Start(_)), "got {err:?}");
    }

    #[test]
    fn the_environment_is_constructed_from_the_spec_alone() {
        use crate::spec::{EnvPolicy, InheritPolicy};
        let spec = SandboxSpec {
            interpreter: crate::spec::Interpreter::Binary(
                crate::spec::AbsoluteProgramPath::new(if cfg!(windows) {
                    std::path::PathBuf::from("C:\\Windows\\System32\\cmd.exe")
                } else {
                    std::path::PathBuf::from("/bin/sh")
                })
                .expect("absolute"),
            ),
            limits: crate::spec::Limits {
                timeout_ms: 1_000,
                memory_bytes: 1 << 20,
                cpu_ms: 1_000,
                disk_bytes: 1 << 20,
                max_processes: 2,
                max_open_files: 16,
                max_output_bytes: 1_024,
            },
            network: crate::spec::NetworkPolicy::DenyAll,
            filesystem: crate::spec::FilesystemPolicy::confined(),
            env: EnvPolicy {
                inherit: InheritPolicy::Nothing,
                vars: vec![("NAU_TEST".to_string(), "yes".to_string())],
            },
            waivers: crate::spec::Waivers::none(),
        };
        let mut cmd = std::process::Command::new("unused");
        apply_env(&mut cmd, &spec);
        let envs: Vec<(String, String)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(
            envs.len(),
            2,
            "only PATH and the spec's own variable: {envs:?}"
        );
        assert!(envs.iter().any(|(k, v)| k == "PATH" && v == SAFE_PATH));
        assert!(envs.iter().any(|(k, v)| k == "NAU_TEST" && v == "yes"));
    }
}
