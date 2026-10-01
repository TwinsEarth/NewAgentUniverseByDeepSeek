//! Shared test scaffolding for the sandbox test suites.
//!
//! Included with `mod common;` from each integration test file. It builds valid
//! sandbox specs, creates per-test temporary roots, and launches the self-test
//! worker (see [`worker`]) as a sandboxed child.
//!
//! Nothing here hides a missing prerequisite: the sandboxed program is this same
//! test binary, so no interpreter has to exist on `PATH`. A test that genuinely
//! cannot run on a platform reports a SKIP with a reason rather than passing
//! silently.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use nau_sandbox::{
    AbsoluteProgramPath, Confinement, EnvPolicy, FilesystemPolicy, InheritPolicy, Interpreter,
    Limits, NetworkPolicy, SandboxSpec, Waivers,
};

/// The worker the enforcement tests run **as the sandboxed child**.
///
/// # Why this is a module here *and* a test target of its own
///
/// [`worker`] below runs `std::env::current_exe()`, which inside an integration
/// test is *that test's own binary* — cargo does not tell a test where its sibling
/// targets were built, and artefact names carry an unpredictable hash. So the
/// worker has to exist in the binary that runs it: this declaration shares
/// `tests/selftest.rs` into every test binary that says `mod common;`, and
/// `tests/selftest.rs` stays a test target in its own right, so a plain
/// `cargo test -p nau-sandbox` still exercises the worker as a test.
///
/// Before this, [`worker`] launched `current_exe()` with
/// `--exact selftest::selftest_worker`: a name that exists in no binary, so the
/// child ran **zero tests**, exited `0`, produced no output, and eight of the ten
/// enforcement tests failed against a worker that had never run.
#[path = "../selftest.rs"]
pub mod worker;

/// The `#[test]` name of the worker **in the binary that includes this module**.
///
/// It has to be the full path of the shared module, which is why it is
/// `common::worker::selftest_worker` rather than the bare name the `selftest`
/// target uses for the same function.
pub const WORKER_TEST: &str = "common::worker::selftest_worker";

/// A value that must never appear in a sandboxed child's environment.
///
/// Set by the test process; the child runs with `env_clear()` plus an explicit
/// allowlist, so finding this string inside the sandbox means the daemon
/// environment leaked. Upstream v2.8.2 fix: the child ran with the daemon's own
/// environment, so a sandbox could read host secrets.
pub const HOST_SECRET: &str = "nau-sandbox-host-secret-3f9a1c";

/// Set the host secret in the current test process.
pub fn plant_host_secret() {
    std::env::set_var("NAU_HOST_SECRET", HOST_SECRET);
}

/// A unique, temporary sandbox root for one test.
pub fn root_for(name: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("nau-sandbox-tests/{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create test root");
    root
}

/// Remove a test root.
pub fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

/// Limits that are small but not tight, for tests not about a specific limit.
pub fn limits() -> Limits {
    Limits {
        timeout_ms: 20_000,
        memory_bytes: 512 * 1024 * 1024,
        cpu_ms: 20_000,
        disk_bytes: 32 * 1024 * 1024,
        max_processes: 4,
        max_open_files: 256,
        max_output_bytes: 256 * 1024,
    }
}

/// An interpreter that runs the self-test worker in `mode`.
///
/// The mode travels in the child's environment, not in argv, so no test has to
/// build a varying argv vector.
///
/// The argv order is deliberate: `--exact <name>` **before** `--test-threads=1`,
/// because libtest parses its own flags and stops at the first non-flag argument.
/// Single-threaded because the worker writes the marker file a reading sandbox then
/// looks for. One argv element is one argument — there is no command-line string
/// anywhere in this crate — so `Interpreter::Argv` carries the vector as data.
pub fn worker() -> Interpreter {
    Interpreter::Argv {
        bin: AbsoluteProgramPath::new(std::env::current_exe().expect("test binary path"))
            .expect("the test binary path is absolute"),
        args: vec![
            "--exact".to_string(),
            WORKER_TEST.to_string(),
            "--test-threads=1".to_string(),
        ],
    }
}

/// A spec that runs the worker in `mode` with `vars` in its environment, using
/// `limits`.
///
/// The network policy is `Unrestricted` and confinement is `WholeHost`, both with
/// justifications, because the real backend on this platform cannot deny egress or
/// confine the filesystem. That is the crate's only honest way to run: the waiver
/// is explicit, validated, and written to the audit log.
pub fn spec_with(mode: &str, vars: &[(&str, &str)], limits: Limits) -> SandboxSpec {
    let mut env_vars: Vec<(String, String)> =
        vec![("NAU_SELFTEST_MODE".to_string(), mode.to_string())];
    for (k, v) in vars {
        env_vars.push((k.to_string(), v.to_string()));
    }
    SandboxSpec {
        interpreter: worker(),
        limits,
        network: NetworkPolicy::Unrestricted {
            justification: "unit test on a host with no egress filter available".to_string(),
        },
        filesystem: FilesystemPolicy {
            confinement: Confinement::WholeHost,
            extra_readable: Vec::new(),
            writable: Vec::new(),
        },
        env: EnvPolicy {
            inherit: InheritPolicy::Nothing,
            vars: env_vars,
        },
        waivers: Waivers {
            filesystem_confinement: Some("unit test: no confinement primitive".to_string()),
            disk_bytes: Some("unit test: no quota primitive".to_string()),
            cpu_ms: cfg!(windows).then(|| "unit test: no CPU-time limit on Windows".to_string()),
            max_open_files: cfg!(windows)
                .then(|| "unit test: no handle limit on Windows".to_string()),
        },
    }
}

/// [`spec_with`] with the shared default limits.
pub fn spec(mode: &str, vars: &[(&str, &str)]) -> SandboxSpec {
    spec_with(mode, vars, limits())
}
