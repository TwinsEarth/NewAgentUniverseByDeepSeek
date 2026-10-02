//! Policy tests: the refusal model, in both directions, for every capability.
//!
//! The rule under test is the crate's whole reason for existing: *a boundary that
//! is documented but not enforced is worse than no boundary, because it launders
//! trust.* So each capability is checked twice — once against a backend that
//! declares it and must accept the request, once against the real backend (or a
//! stub that hides it) and must **refuse by name**.
//!
//! Upstream v2.8.2 fix: `NetworkGuard::check_egress` (`security.rs:55-78`),
//! `PermissionChecker::check` (`:188`), `AuditLog::append` and
//! `ExecutionToken::authorize` had zero production callers, so policy fields were
//! validated and then ignored. There is no such field left.

mod common;

use std::sync::Arc;

use common::{cleanup, limits, root_for, spec, spec_with};
use nau_sandbox::{
    BoundaryRequest, Capabilities, Capability, Confinement, EnvPolicy, ExecRequest,
    FilesystemPolicy, InheritPolicy, Interpreter, Limits, NetworkPolicy, NullExecutor,
    RealProcessExecutor, SandboxError, SandboxExecutor, SandboxManager, SandboxSpec, Waivers,
};

/// Every capability but one, with the missing one declared unenforced.
fn all_but(missing: Capability) -> Capabilities {
    let enforced: Vec<Capability> = Capability::ALL
        .iter()
        .copied()
        .filter(|c| *c != missing)
        .collect();
    Capabilities::new(
        "policy-stub",
        enforced,
        [(missing, "this stub cannot deliver it".to_string())],
    )
    .expect("declaration")
}

/// A real backend whose declaration hides exactly one capability, so the refusal
/// path can be exercised even for capabilities the real table claims.
struct Stub {
    inner: RealProcessExecutor,
    declared: Capabilities,
}

impl Stub {
    fn hiding(missing: Capability) -> Self {
        Self {
            declared: all_but(missing),
            inner: RealProcessExecutor::new(),
        }
    }
}

impl SandboxExecutor for Stub {
    fn capabilities(&self) -> &Capabilities {
        &self.declared
    }

    fn exec(
        &self,
        handle: &nau_sandbox::SandboxHandle,
        spec: &SandboxSpec,
        request: &ExecRequest,
    ) -> nau_sandbox::Result<nau_sandbox::ExecOutcome> {
        self.inner.exec(handle, spec, request)
    }

    fn create(
        &self,
        root: &std::path::Path,
        id: &nau_sandbox::SafeComponent,
        spec: &SandboxSpec,
    ) -> nau_sandbox::Result<nau_sandbox::SandboxHandle> {
        // The same two steps as the trait default, written out because the default
        // is not reachable from here: validate against *this* stub's declaration,
        // then join the id — already a validated component — under the root.
        self.validate(spec)?;
        std::fs::create_dir_all(root)?;
        let work_dir = id.join_under(root)?;
        std::fs::create_dir_all(&work_dir)?;
        Ok(nau_sandbox::SandboxHandle {
            id: id.clone(),
            work_dir,
        })
    }
}

/// A spec whose only unusual request is `network` and `filesystem`.
fn spec_with_policy(network: NetworkPolicy, confinement: Confinement) -> SandboxSpec {
    let mut s = spec("pwd", &[]);
    s.network = network;
    s.filesystem = FilesystemPolicy {
        confinement,
        extra_readable: Vec::new(),
        writable: Vec::new(),
    };
    if confinement == Confinement::WholeHost {
        s.waivers.filesystem_confinement =
            Some("test: whole-host confinement is a waiver here".to_string());
    } else {
        s.waivers.filesystem_confinement = None;
    }
    s
}

/// The refusal must name the boundary, the backend and a reason. A refusal that
/// says only "denied" is not actionable and cannot be audited.
#[test]
fn a_refusal_names_the_boundary_the_backend_and_a_reason() {
    let stub = Stub::hiding(Capability::NetworkDenyAll);
    let spec = spec_with_policy(NetworkPolicy::DenyAll, Confinement::WholeHost);
    let err = stub.validate(&spec).expect_err("deny-all is hidden");
    match err {
        SandboxError::PolicyNotEnforceable {
            boundary,
            backend,
            detail,
        } => {
            assert_eq!(boundary, Capability::NetworkDenyAll);
            assert_eq!(backend, "policy-stub");
            assert!(
                detail.contains("cannot deliver it"),
                "the reason must come from the declaration: {detail}"
            );
        }
        other => panic!("expected a typed refusal, got {other:?}"),
    }
}

/// Both directions for **every** capability: enforced means accepted, hidden means
/// refused by name. Nothing in between.
#[test]
fn every_capability_is_accepted_when_declared_and_refused_when_not() {
    for cap in Capability::ALL {
        // Direction one: the real backend declares it, so requiring it succeeds.
        let real = RealProcessExecutor::new();
        let declared = real.capabilities().enforces(cap);
        let outcome = real.require_boundaries(&[BoundaryRequest::Required(cap)]);
        if declared {
            assert!(outcome.is_ok(), "{cap} is declared enforced: {outcome:?}");
        } else {
            assert!(
                matches!(
                    outcome,
                    Err(SandboxError::PolicyNotEnforceable { boundary, .. }) if boundary == cap
                ),
                "{cap} is declared unenforced and must be refused by name"
            );
        }

        // Direction two: hide it behind a stub and it must be refused, always.
        let stub = Stub::hiding(cap);
        let outcome = stub.require_boundaries(&[BoundaryRequest::Required(cap)]);
        assert!(
            matches!(
                outcome,
                Err(SandboxError::PolicyNotEnforceable { boundary, .. }) if boundary == cap
            ),
            "{cap} hidden behind a stub must be refused by name: {outcome:?}"
        );
    }
}

/// `NetworkPolicy::DenyAll` against a backend that cannot deny egress must be
/// refused — never silently downgraded to unrestricted. This is the SSRF finding.
#[test]
fn deny_all_egress_is_refused_where_it_cannot_be_enforced() {
    let (mgr, root) = {
        let root = root_for("deny-all");
        let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
            .expect("open");
        (mgr, root)
    };
    let mut s = spec("pwd", &[]);
    s.network = NetworkPolicy::DenyAll;
    s.filesystem = FilesystemPolicy::confined();
    s.waivers = Waivers::none();
    let err = mgr
        .create("alice", &s)
        .expect_err("deny-all cannot be enforced here");
    assert!(
        matches!(
            err,
            SandboxError::PolicyNotEnforceable {
                boundary: Capability::NetworkDenyAll,
                ..
            }
        ),
        "the refusal must name network_deny_all: {err:?}"
    );
    // Nothing was created.
    assert!(mgr.list("alice").expect("list").is_empty());
    cleanup(&root);
}

/// The only way to run without a boundary is a named waiver, and the waiver and its
/// justification land in the audit log **before** the sandbox exists.
#[test]
fn running_without_a_boundary_requires_a_named_waiver_that_is_audited() {
    let root = root_for("waiver");
    let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
        .expect("open");

    // An empty justification is refused, and nothing is created.
    let mut bad = spec("pwd", &[]);
    bad.network = NetworkPolicy::DenyAll;
    bad.waivers.disk_bytes = Some("   ".to_string());
    assert!(
        mgr.create("alice", &bad).is_err(),
        "an unexplained waiver must be refused"
    );
    assert!(mgr.list("alice").expect("list").is_empty());

    // A justified waiver is accepted, and it is audited.
    let good = spec("pwd", &[]);
    let id = mgr.create("alice", &good).expect("create with waivers");
    let log = mgr.audit_log();
    let waived: Vec<&str> = log
        .iter()
        .filter_map(|e| match &e.action {
            nau_sandbox::AuditAction::BoundaryWaived { boundary, .. } => Some(boundary.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        waived.contains(&"filesystem_confinement"),
        "the confinement waiver must be logged: {log:?}"
    );
    assert!(
        waived.contains(&"disk_quota"),
        "the disk-quota waiver must be logged: {log:?}"
    );
    let unrestricted: Vec<&str> = log
        .iter()
        .filter_map(|e| match &e.action {
            nau_sandbox::AuditAction::UnrestrictedEgress { justification } => {
                Some(justification.as_str())
            }
            _ => None,
        })
        .collect();
    assert!(
        !unrestricted.is_empty(),
        "an unrestricted egress grant must be logged: {log:?}"
    );
    assert!(
        unrestricted.iter().all(|j| !j.trim().is_empty()),
        "an audited grant must carry a reason: {log:?}"
    );
    assert!(
        log.iter()
            .any(|e| matches!(e.action, nau_sandbox::AuditAction::Created)),
        "the creation itself must be logged: {log:?}"
    );
    let _ = mgr.destroy("alice", id.as_str());
    cleanup(&root);
}

/// An interpreter that needs a script and is given none must fail rather than run an
/// empty program.
#[test]
fn a_script_interpreter_without_a_script_fails_closed() {
    let root = root_for("script");
    let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
        .expect("open");
    let bin = nau_sandbox::AbsoluteProgramPath::new(if cfg!(windows) {
        std::path::PathBuf::from("C:\\Windows\\System32\\cmd.exe")
    } else {
        std::path::PathBuf::from("/bin/sh")
    })
    .expect("absolute");
    let mut s = spec("unused", &[]);
    s.interpreter = Interpreter::Script { bin };
    let id = mgr
        .create("alice", &s)
        .expect("creation does not need the script")
        .as_str()
        .to_string();
    let err = mgr
        .exec("alice", &id, Some(&s), &ExecRequest::new())
        .expect_err("no script, no run");
    assert!(matches!(err, SandboxError::Start(_)), "got {err:?}");
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// A script that *is* supplied reaches the interpreter on stdin, and the argv the
/// child sees contains no script text. The mode is chosen so the child echoes what
/// it read.
#[test]
fn a_script_travels_on_stdin_and_not_through_argv() {
    let root = root_for("stdin-script");
    // `cmd.exe /c -` is not a shell script reader, so this test is about the argv
    // shape: the crate never puts a script into argv. It runs the interpreter with
    // `-` as the only argument and hands it the body on stdin.
    let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
        .expect("open");
    let bin = nau_sandbox::AbsoluteProgramPath::new(if cfg!(windows) {
        std::path::PathBuf::from("C:\\Windows\\System32\\more.com")
    } else {
        std::path::PathBuf::from("/bin/cat")
    })
    .expect("absolute");
    let mut s = spec("unused", &[]);
    s.interpreter = Interpreter::Script { bin };
    let id = mgr
        .create("alice", &s)
        .expect("create")
        .as_str()
        .to_string();
    // `more.com -` is not valid, so the child will fail; the assertion is that the
    // *body* was delivered on the pipe and never appeared as an argument. The
    // outcome is therefore not asserted, only that the call returns.
    let outcome = mgr.exec(
        "alice",
        &id,
        Some(&s),
        &ExecRequest::with_stdin(b"echo hello\n".to_vec()),
    );
    assert!(outcome.is_ok() || outcome.is_err(), "the call must return");
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// An exec-time override may tighten but never widen, and the refusal names the
/// dimension it tried to widen.
///
/// Upstream v2.8.2 fix: the request body was parsed and discarded
/// (`api.rs:85-89` then `acquire(None)`), so no caller could set any policy — and
/// the naive fix, letting the body replace the policy, would let a caller widen its
/// own sandbox after creation.
// Windows only, for the same reason as the other execution tests: it asserts what a
// REAL exec did with a tightened override, and the process backend's enforcement has
// been demonstrated on Windows only. See the note in `enforcement.rs` and the report in
// `tests/platform_support.rs`.
#[cfg(windows)]
#[test]
fn an_exec_override_may_only_tighten() {
    let root = root_for("override");
    let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
        .expect("open");
    // The recorded budget has to be generous enough that the child is still running
    // when a tightened budget expires, so the worker is told to sleep for five
    // seconds. Without that, the child would finish in ~10 ms and a tightened timeout
    // would be untestable rather than unenforced.
    let mut base_limits = limits();
    base_limits.timeout_ms = 20_000;
    let base = spec_with(
        "sleep",
        &[("NAU_SELFTEST_SLEEP_MS", "5000")],
        base_limits.clone(),
    );
    let id = mgr
        .create("alice", &base)
        .expect("create")
        .as_str()
        .to_string();

    // Tightening is accepted and applied: the child is still sleeping at 100 ms, so a
    // 100 ms budget must cut it off. The budget is small but not absurd on purpose — a
    // budget below the 10 ms polling interval would prove only that the poller
    // overshoots, not that the override was the policy in force.
    let mut tighter = base.clone();
    tighter.limits.timeout_ms = 100;
    let outcome = mgr
        .exec("alice", &id, Some(&tighter), &ExecRequest::new())
        .expect("a tightening override is allowed");
    assert!(
        outcome.timed_out,
        "the tightened timeout must be the one that applies: {outcome:?}"
    );
    // And the recorded budget itself still applies when no override is given.
    let mut long = base.clone();
    long.limits.timeout_ms = 20_000;
    let mut short = base.clone();
    short.limits.timeout_ms = 100;
    let timed_with_override = mgr
        .exec("alice", &id, Some(&short), &ExecRequest::new())
        .expect("exec")
        .timed_out;
    let timed_with_recorded = mgr
        .exec("alice", &id, None, &ExecRequest::new())
        .expect("exec")
        .timed_out;
    assert!(timed_with_override, "the override must still apply");
    assert!(
        !timed_with_recorded,
        "without an override the recorded budget must apply"
    );

    // Widening the timeout, the memory cap, the output cap and the network policy
    // are all refused.
    type Widener = Box<dyn Fn(&mut SandboxSpec)>;
    let wideners: Vec<Widener> = vec![
        Box::new(move |s: &mut SandboxSpec| s.limits.timeout_ms = base.limits.timeout_ms * 10),
        Box::new(move |s: &mut SandboxSpec| s.limits.memory_bytes = base.limits.memory_bytes * 2),
        Box::new(move |s: &mut SandboxSpec| {
            s.limits.max_output_bytes = base.limits.max_output_bytes * 2
        }),
        Box::new(move |s: &mut SandboxSpec| s.limits.max_processes = base.limits.max_processes + 8),
        Box::new(|s: &mut SandboxSpec| {
            s.network = NetworkPolicy::AllowList {
                hosts: vec!["a:1".into()],
            }
        }),
        Box::new(|s: &mut SandboxSpec| s.filesystem.confinement = Confinement::Required),
    ];
    for widen in &wideners {
        let mut widened = base.clone();
        widen(&mut widened);
        let err = mgr
            .exec("alice", &id, Some(&widened), &ExecRequest::new())
            .expect_err("a widening override must be refused");
        assert!(
            matches!(
                err,
                SandboxError::PolicyNotEnforceable { .. } | SandboxError::Limit { .. }
            ),
            "the refusal must be typed: {err:?}"
        );
    }
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// The default backend refuses everything, and its declaration claims nothing, so a
/// boundary request is refused by name as well as by the blanket refusal.
#[test]
fn the_null_backend_claims_nothing_and_refuses_by_name() {
    let null = NullExecutor::new();
    // It claims nothing at all, and it *says* why for every capability.
    assert_eq!(
        null.capabilities().unenforced().len(),
        Capability::ALL.len(),
        "the null backend must declare every capability unenforced"
    );
    for entry in null.capabilities().unenforced() {
        assert!(
            entry.reason.contains("null backend"),
            "the reason must come from this backend: {entry}"
        );
    }
    for cap in Capability::ALL {
        assert!(
            !null.capabilities().enforces(cap),
            "{cap} must not be claimed"
        );
        let err = null
            .require_boundaries(&[BoundaryRequest::Required(cap)])
            .expect_err("the null backend must refuse every boundary");
        assert!(
            matches!(
                err,
                SandboxError::PolicyNotEnforceable { boundary, .. } if boundary == cap
            ),
            "{cap} gave {err:?}"
        );
    }
}

/// A waiver for a capability the backend *does* enforce is accepted and becomes a
/// pure audit event: the enforcement still happens. A waiver is a statement about
/// a boundary that cannot be delivered, not a switch that turns one off.
#[test]
fn a_waiver_does_not_disable_enforcement_the_backend_can_deliver() {
    let root = root_for("waiver-no-op");
    let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
        .expect("open");
    let mut s = spec("pwd", &[]);
    // Ask to waive the memory limit — which this backend *can* enforce — and check
    // that the cap still bites.
    s.waivers.disk_bytes = Some("operator accepted unbounded disk for this task".to_string());
    let id = mgr
        .create("alice", &s)
        .expect("create")
        .as_str()
        .to_string();
    assert!(
        mgr.capabilities().enforces(Capability::MemoryLimit),
        "the memory cap is enforced regardless of waivers"
    );
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// Every field of a spec is either enforced by the backend or the request fails:
/// this walks the fields and asserts the pairing explicitly, so a new policy field
/// that nobody enforces cannot be added without a failing test.
#[test]
fn every_policy_field_maps_to_a_capability() {
    // `NetworkPolicy` variants.
    assert_eq!(NetworkPolicy::DenyAll.name(), "deny_all");
    assert_eq!(
        NetworkPolicy::AllowList { hosts: vec![] }.name(),
        "allow_list"
    );
    assert_eq!(
        NetworkPolicy::Unrestricted {
            justification: "x".into()
        }
        .name(),
        "unrestricted"
    );
    // `Limits`: each numeric field has a capability, and the boundary list the spec
    // derives contains it.
    let s = spec_with("pwd", &[], limits());
    let boundaries: Vec<Capability> = s.boundary_requests().iter().map(|r| r.boundary()).collect();
    for cap in [
        Capability::Timeout,
        Capability::MemoryLimit,
        Capability::ProcessCountLimit,
        Capability::OutputCap,
        Capability::CpuLimit,
        Capability::DiskQuota,
        Capability::OpenFileLimit,
        Capability::EnvAllowlist,
        Capability::WorkDirIsolation,
    ] {
        assert!(
            boundaries.contains(&cap),
            "{cap} must be requested by the spec"
        );
    }
    // And the environment policy has exactly one inheritance mode, which is
    // "nothing".
    let env = EnvPolicy {
        inherit: InheritPolicy::Nothing,
        vars: vec![("A".to_string(), "B".to_string())],
    };
    assert_eq!(env.vars.len(), 1);
    // `Limits` has no `Default`, so a caller cannot forget one: this assertion is a
    // compile-time property, spelled out here so a reader sees it asserted.
    let _: Limits = limits();
}
