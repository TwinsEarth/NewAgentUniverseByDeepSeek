//! The process-plugin binary and the host ABI frame.
//!
//! `nau-plugin-echo` is a real executable in `src/bin/`. These tests do two things
//! with it: they drive it as a child process over the documented frame format, and
//! they point [`ProcessRuntime`] at it — which is the whole reason it exists, because
//! a runtime port that has never been given a real artefact to start is a claim
//! rather than a capability.
//!
//! What these tests do **not** do is run the plugin through `ProcessRuntime::call`:
//! that port's exec belongs to the host (`nau-node` owns the sandbox manager). They
//! *do* run the same binary inside the real sandbox backend directly, so the claim
//! "a plugin in a real sandboxed process" is executed rather than asserted.

mod common;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
// `Arc`, and the sandbox types further down, are used only by the Windows-gated
// sandboxed-execution test and the spec builder that feeds it. Gating the *imports* as
// well as the test is not tidiness: on Unix the test compiles out, the imports become
// unused, and CI runs `clippy --all-targets -- -D warnings` on every platform -- so an
// unused import is a red build. That is exactly how the first attempt at this gate
// failed on macOS.
#[cfg(windows)]
use std::sync::Arc;
use std::time::{Duration, Instant};

use nau_plugin::runtime::{Boundary, PluginInstance, PluginRuntime, ProcessRuntime, StartSpec};
use nau_plugin::{PluginId, Tier};
use nau_plugins::frame::{self, Request, Response};
// These two are used on every platform, by
// `the_process_backend_declares_only_boundaries_it_can_enforce`.
use nau_sandbox::{RealProcessExecutor, SandboxExecutor};
// The rest exist here only to build the spec the Windows-gated execution test uses.
#[cfg(windows)]
use nau_sandbox::{
    AbsoluteProgramPath, Confinement, EnvPolicy, ExecRequest, FilesystemPolicy, InheritPolicy,
    Interpreter, NetworkPolicy, SandboxManager, SandboxSpec, Waivers,
};
use serde_json::json;

/// The binary cargo built for this test run.
fn echo_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_nau-plugin-echo"))
}

/// The limits a plugin declares for the start spec.
fn limits() -> nau_plugin::Limits {
    nau_plugins::sign::limits()
}

/// Full waivers for every boundary the process runtime cannot enforce.
fn waivers() -> BTreeMap<String, String> {
    nau_plugins::sign::process_waivers(nau_plugins::sign::FIXTURE_WAIVER_REASON)
}

/// One request for the echo plugin.
fn request(op: &str, payload: serde_json::Value) -> Request {
    Request {
        abi: frame::abi_version(),
        id: "req-1".into(),
        op: op.into(),
        payload,
    }
}

/// Run one frame through the real binary and decode its answer.
///
/// The wait is bounded: a plugin that hangs must fail the test rather than the suite,
/// which is the same rule the runtime applies to a call it makes.
fn call_binary(request: &Request) -> (Response, Option<i32>) {
    let mut child = Command::new(echo_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the echo plugin must start");

    {
        let mut stdin = child.stdin.take().expect("stdin is piped");
        let encoded = serde_json::to_vec(request).expect("encodes");
        frame::write_frame(&mut stdin, &encoded).expect("writes the request frame");
    }

    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut bytes = Vec::new();
    stdout.read_to_end(&mut bytes).expect("reads the answer");

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait().expect("waits") {
            Some(status) => break status,
            None if Instant::now() > deadline => {
                let _ = child.kill();
                panic!("the echo plugin did not exit within ten seconds");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };

    let payload = frame::read_frame(&mut bytes.as_slice())
        .expect("reads a frame")
        .expect("one frame");
    let response = frame::decode_response(&payload).expect("decodes the response");
    (response, status.code())
}

#[test]
fn the_echo_binary_answers_a_frame_with_the_echo_and_its_version() {
    let (response, code) = call_binary(&request("echo", json!({ "hello": "world" })));
    assert_eq!(code, Some(0));
    assert!(response.ok, "{response:?}");
    assert_eq!(response.plugin, frame::ECHO_PLUGIN);
    assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(response.abi, frame::abi_version());
    assert_eq!(response.id, "req-1");
    assert_eq!(
        response.payload.expect("a payload")["hello"],
        json!("world")
    );
}

#[test]
fn the_echo_binary_refuses_an_unknown_operation_with_a_code_and_a_non_zero_exit() {
    let (response, code) = call_binary(&request("sing", json!({})));
    assert_eq!(code, Some(1));
    assert!(!response.ok);
    assert_eq!(
        response.code.as_deref(),
        Some(nau_plugins::payload::CODE_UNKNOWN_OPERATION)
    );
}

#[test]
fn the_echo_binary_is_not_confused_by_a_frame_larger_than_it_will_read() {
    // 8 MiB announced, nothing behind it: the binary must refuse from the prefix
    // rather than allocate, and must exit with the I/O code because it never got a
    // request to answer.
    let mut child = Command::new(echo_binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starts");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(&(8u32 * 1024 * 1024).to_be_bytes())
            .expect("writes the prefix");
        stdin.flush().expect("flushes");
    }
    let mut stdout = child.stdout.take().expect("stdout");
    let mut bytes = Vec::new();
    stdout.read_to_end(&mut bytes).expect("reads");
    let status = child.wait().expect("waits");
    assert_eq!(
        status.code(),
        Some(2),
        "an unreadable frame is not a refusal"
    );
    assert!(bytes.is_empty(), "nothing was answered");
}

#[test]
fn the_frame_codec_refuses_the_shapes_the_binary_would_die_on() {
    // The same refusals, in-process, so a failure points at the codec rather than at
    // a child process.
    assert!(frame::encode_frame(b"").is_err());
    assert!(frame::read_frame(&mut &[0u8, 0, 0, 0][..]).is_err());
    assert!(frame::read_frame(&mut &[0x7f, 0xff, 0xff, 0xff][..]).is_err());
    assert!(frame::read_frame(&mut &[0u8, 0, 0][..]).is_err());
    assert!(frame::read_frame(&mut &[][..])
        .expect("clean eof")
        .is_none());
    assert!(frame::decode_request(b"{}").is_err());
}

#[test]
fn the_process_runtime_starts_the_real_binary() {
    let runtime = ProcessRuntime::new();
    let spec = StartSpec {
        plugin: PluginId::parse(frame::ECHO_PLUGIN).expect("a valid name"),
        tier: Tier::ThirdParty,
        entry: echo_binary(),
        limits: limits(),
        waivers: waivers(),
    };
    let instance: PluginInstance = runtime.start(&spec).expect("starts");
    assert_eq!(instance.kind, nau_plugin::runtime::RuntimeKind::Process);
    assert_eq!(instance.plugin, frame::ECHO_PLUGIN);
    assert!(
        instance.handle.contains("mem=268435456"),
        "{}",
        instance.handle
    );
    assert!(instance.handle.contains("procs=4"), "{}", instance.handle);
    runtime.stop(&instance).expect("stops");
}

#[test]
fn the_process_runtime_refuses_the_real_binary_without_the_waivers_it_cannot_enforce() {
    // The same file, the same tier, no waivers: refused by name, because a boundary
    // this build cannot enforce is not silently dropped.
    let runtime = ProcessRuntime::new();
    let spec = StartSpec {
        plugin: PluginId::parse(frame::ECHO_PLUGIN).expect("a valid name"),
        tier: Tier::ThirdParty,
        entry: echo_binary(),
        limits: limits(),
        waivers: BTreeMap::new(),
    };
    let err = runtime.start(&spec).expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains("isolation_not_enforceable"), "{text}");
    assert!(text.contains(Boundary::NetworkDeny.label()), "{text}");

    // And a system plugin is refused by this runtime whatever waivers it brings:
    // the tier gate is structural, not a boundary question.
    let spec = StartSpec {
        tier: Tier::System,
        plugin: PluginId::parse("com.twinsearth.sys.identity").expect("a valid name"),
        ..spec
    };
    let err = runtime.start(&spec).expect_err("must be refused");
    assert!(err.to_string().contains("must run natively"), "{err}");
}

#[test]
fn the_process_runtime_refuses_an_entry_that_is_not_there() {
    let runtime = ProcessRuntime::new();
    let spec = StartSpec {
        plugin: PluginId::parse(frame::ECHO_PLUGIN).expect("a valid name"),
        tier: Tier::ThirdParty,
        entry: common::scratch("absent").join("nau-plugin-not-here"),
        limits: limits(),
        waivers: waivers(),
    };
    let err = runtime.start(&spec).expect_err("must be refused");
    assert!(err.to_string().contains("does not exist"), "{err}");
}

/// The sandbox specification for the plugin, declared as the backend can honour it.
///
/// The network policy is `Unrestricted` and the confinement `WholeHost`, both with
/// reasons, because this build's backend has no egress filter and no confinement
/// primitive — asking for the policies it cannot enforce would be refused, which is
/// the correct behaviour and a different test. The waived boundaries are exactly the
/// four `Waivers` carries.
///
/// Windows-only, like its only caller: on other platforms this function would be dead
/// code, and dead code is a `-D warnings` failure too.
#[cfg(windows)]
fn plugin_sandbox_spec() -> SandboxSpec {
    let reason = "end-to-end test: this build has no primitive for it behind a child process";
    SandboxSpec {
        interpreter: Interpreter::Binary(
            AbsoluteProgramPath::new(echo_binary()).expect("the binary path is absolute"),
        ),
        limits: nau_sandbox::Limits {
            timeout_ms: 20_000,
            memory_bytes: 256 * 1024 * 1024,
            cpu_ms: 20_000,
            disk_bytes: 32 * 1024 * 1024,
            max_processes: 4,
            max_open_files: 256,
            max_output_bytes: 256 * 1024,
        },
        network: NetworkPolicy::Unrestricted {
            justification: "end-to-end test on a host with no egress filter available".to_string(),
        },
        filesystem: FilesystemPolicy {
            confinement: Confinement::WholeHost,
            extra_readable: Vec::new(),
            writable: Vec::new(),
        },
        env: EnvPolicy {
            inherit: InheritPolicy::Nothing,
            vars: Vec::new(),
        },
        waivers: Waivers {
            filesystem_confinement: Some(reason.to_string()),
            disk_bytes: Some(reason.to_string()),
            cpu_ms: cfg!(windows).then(|| reason.to_string()),
            max_open_files: cfg!(windows).then(|| reason.to_string()),
        },
    }
}

/// The plugin runs inside a real sandbox **on Windows**, where the process backend can
/// honour the limits it is asked for.
///
/// # Why this is Windows-only, and not a quiet skip
///
/// The V1.2.3 audit concluded that the Unix process backend cannot honour the
/// boundaries it would have to claim — there is no egress primitive, no filesystem
/// confinement and no disk quota reachable without privileges — and so
/// `nau_sandbox::executor_for("process")` **refuses** on Unix rather than pretend. This
/// test constructs `RealProcessExecutor` directly, walking around that door, and on
/// macOS it dies inside the manager with `EINVAL`.
///
/// The honest resolution is not to weaken the test but to stop asserting this capability
/// where the backend cannot be shown to deliver it. Leaving the test ungated published a
/// red CI on 2026-10-01 (macOS: `EINVAL`), and the gate is the fix.
///
/// A first attempt at a non-Windows counterpart asserted that the process plugin is
/// *refused* here. CI disproved that too: on Ubuntu the plugin starts. See
/// `the_process_backend_declares_only_boundaries_it_can_enforce` below for what replaced
/// it, and `docs/VERIFICATION.md` §5.2 for the three-platform matrix.
#[cfg(windows)]
#[test]
fn the_echo_plugin_runs_inside_a_real_sandbox_and_answers_a_frame() {
    let root = common::scratch("sandbox");
    let manager = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), common::NOW)
        .expect("the manager opens");
    let owner = "nau-plugins-test";
    let id = manager
        .create(owner, &plugin_sandbox_spec())
        .expect("the sandbox is created")
        .as_str()
        .to_string();

    let mut wire = Vec::new();
    let encoded =
        serde_json::to_vec(&request("echo", json!({ "sandboxed": true }))).expect("encodes");
    frame::write_frame(&mut wire, &encoded).expect("frames the request");

    let outcome = manager
        .exec(owner, &id, None, &ExecRequest::with_stdin(wire))
        .expect("the plugin runs inside the sandbox");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    assert!(!outcome.timed_out, "the plugin must not hit the timeout");
    assert!(!outcome.terminated, "the plugin must exit by itself");

    let payload = frame::read_frame(&mut outcome.stdout.as_slice())
        .expect("reads a frame")
        .expect("one frame");
    let response = frame::decode_response(&payload).expect("decodes");
    assert!(response.ok, "{response:?}");
    assert_eq!(response.plugin, frame::ECHO_PLUGIN);
    assert_eq!(
        response.payload.expect("a payload")["sandboxed"],
        json!(true)
    );

    manager
        .destroy(owner, &id)
        .expect("the sandbox is destroyed");
    let _ = std::fs::remove_dir_all(&root);
}

/// What the process backend claims it can enforce, checked on every platform.
///
/// # Why this, and not a launch
///
/// The first attempt at a non-Windows test asserted that a process plugin is *refused*
/// here. CI proved that wrong: on **Ubuntu the plugin starts**, and on **macOS** the
/// manager refuses with `EINVAL`. So "the Unix backend cannot run a process" is not a
/// fact — it is a fact about macOS, and a false statement about Linux.
///
/// What *is* portable is the backend's own declaration, and it is the thing worth
/// pinning: a backend must not claim a boundary it cannot enforce, and the four
/// boundaries it cannot enforce on any platform must appear as unenforced. That is true
/// everywhere, needs no privileges, and fails loudly if someone widens the claim.
#[test]
fn the_process_backend_declares_only_boundaries_it_can_enforce() {
    let executor = RealProcessExecutor::new();
    let caps = executor.capabilities();
    let unenforced = caps.unenforced();

    // A backend that reports no unenforced boundary is claiming it can do everything,
    // which is exactly the defect `Capabilities` exists to prevent.
    assert!(
        !unenforced.is_empty(),
        "the process backend reports that it can enforce every boundary on {}; no backend in \
         this project can, so the declaration is wrong",
        std::env::consts::OS
    );

    // And nothing may be both enforced and unenforced.
    for entry in unenforced {
        assert!(
            !caps.enforces(entry.boundary),
            "{:?} is listed as unenforced ({}) and also as enforced",
            entry.boundary,
            entry.reason
        );
    }

    eprintln!(
        "process backend `{}` on {}: {} unenforced boundary(ies) -- {}",
        executor.name(),
        std::env::consts::OS,
        unenforced.len(),
        unenforced
            .iter()
            .map(|e| e.boundary.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}
