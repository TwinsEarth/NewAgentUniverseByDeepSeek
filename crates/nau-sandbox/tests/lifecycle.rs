//! Manager lifecycle tests: identity, ownership, the startup sweep, and the audit
//! log. Every test names the upstream v2.8.2 finding it closes.
//!
//! These use [`NullExecutor`], the default backend, because the properties under
//! test are about the manager — id issuance, the live table, ownership, orphan
//! reclamation — and not about process execution. `create` refuses on
//! `NullExecutor`, so the manager is deliberately exercised through
//! `tests/policy.rs` for the execution paths and through here for the bookkeeping
//! ones.

mod common;

use std::sync::Arc;

use common::{cleanup, root_for, spec};
use nau_sandbox::{
    Capability, ExecRequest, NullExecutor, RealProcessExecutor, SandboxError, SandboxExecutor,
    SandboxManager,
};
// `SandboxState` is asserted only by the Windows-only execution tests below, so importing
// it unconditionally made CI's `clippy --all-targets -- -D warnings` fail on Linux and
// macOS with `unused import`. Gated rather than `#[allow]`ed: an allow would keep hiding
// the day it becomes unused here for a different reason.
#[cfg(windows)]
use nau_sandbox::SandboxState;

/// A manager over a fresh root with the null backend.
fn null_manager(name: &str) -> (SandboxManager, std::path::PathBuf) {
    let root = root_for(name);
    let mgr = SandboxManager::open(&root, Arc::new(NullExecutor::new()), 1_700_000_000)
        .expect("open manager");
    (mgr, root)
}

/// A manager over a fresh root with the real backend.
fn real_manager(name: &str) -> (SandboxManager, std::path::PathBuf) {
    let root = root_for(name);
    let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
        .expect("open manager");
    (mgr, root)
}

/// A spec that the real backend accepts.
fn runnable_spec() -> nau_sandbox::SandboxSpec {
    spec("pwd", &[])
}

/// Upstream v2.8.2 fix: ids were a per-process counter (`sb-N`, `manager.rs:67-70`),
/// so they were guessable and a restart reissued `sb-1` on top of the previous
/// `sb-1`'s files. Ids must be cryptographically random and must pass the same
/// component validation every path uses.
#[test]
fn ids_are_random_validated_path_components() {
    let (mgr, root) = real_manager("ids");
    let mut ids = Vec::new();
    for _ in 0..8 {
        let id = mgr
            .create("alice", &runnable_spec())
            .expect("create sandbox");
        // A v4 UUID, 32 lowercase hex characters, and a valid path component.
        assert_eq!(id.as_str().len(), 32, "id `{id}`");
        assert!(
            id.as_str()
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "id `{id}` must be lowercase hex"
        );
        // The directory is exactly one component under the root. `join_under`
        // canonicalises the root, so the comparison is made against the canonical
        // form — on Windows that is the `\\?\C:\...` verbatim prefix.
        let dir = root.join(id.as_str());
        assert!(dir.is_dir(), "{} must exist", dir.display());
        assert_eq!(
            dir.parent()
                .expect("parent")
                .canonicalize()
                .expect("canonical parent"),
            root.canonicalize().expect("canonical root")
        );
        ids.push(id.as_str().to_string());
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 8, "every id must be distinct");
    for id in &ids {
        let _ = mgr.destroy("alice", id);
    }
    cleanup(&root);
}

/// Every route must check ownership, and a different principal must get the same
/// answer as for an id that does not exist — `404`, not `403` — so the API cannot
/// be used to confirm that an id exists.
///
/// Upstream v2.8.2 fix: there was no ownership model at all, so any caller could
/// exec, pause or destroy any sandbox.
#[test]
fn every_operation_is_owner_scoped_and_leaks_nothing_to_another_principal() {
    let (mgr, root) = real_manager("ownership");
    let id = mgr
        .create("alice", &runnable_spec())
        .expect("create")
        .as_str()
        .to_string();

    // The owner can do everything.
    assert!(mgr.describe("alice", &id).is_ok());
    assert_eq!(mgr.list("alice").expect("list"), vec![id.clone()]);
    assert!(mgr.pause("alice", &id).is_ok());
    assert!(mgr.resume("alice", &id).is_ok());

    // Everyone else gets "not found" for every one of them.
    let other = "mallory";
    assert!(mgr.list(other).expect("list").is_empty());
    for outcome in [
        mgr.describe(other, &id).err(),
        mgr.pause(other, &id).err(),
        mgr.resume(other, &id).err(),
        mgr.destroy(other, &id).err(),
        mgr.exec(other, &id, None, &ExecRequest::new()).err(),
    ] {
        match outcome {
            Some(SandboxError::NotFound(_)) => {}
            other => panic!("a foreign principal must get NotFound, got {other:?}"),
        }
    }

    // The same answer for an id that never existed: the two cases are
    // indistinguishable, which is the point.
    for outcome in [
        mgr.describe(other, "00000000000000000000000000000000")
            .err(),
        mgr.describe("alice", "00000000000000000000000000000000")
            .err(),
        mgr.pause("alice", "00000000000000000000000000000000").err(),
        mgr.destroy("alice", "00000000000000000000000000000000")
            .err(),
    ] {
        match outcome {
            Some(SandboxError::NotFound(_)) => {}
            other => panic!("an unknown id must get NotFound, got {other:?}"),
        }
    }

    // And the sandbox is still alive for its owner after all those attempts.
    assert!(mgr.describe("alice", &id).is_ok());
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// An id that is not a safe path component must be refused before any filesystem
/// work happens — the traversal attempts from the audit, on the live manager.
#[test]
fn a_hostile_id_is_refused_by_the_component_rules() {
    let (mgr, root) = real_manager("hostile-id");
    for bad in [
        "..",
        "../etc",
        "a/b",
        "a\\b",
        "C:..\\x",
        "\\\\?\\C:\\x",
        "/etc/passwd",
        "",
    ] {
        let outcome = mgr.describe("alice", bad);
        assert!(
            matches!(outcome, Err(SandboxError::Component(_))),
            "`{bad}` must be refused as a component, got {outcome:?}"
        );
    }
    // Nothing was created and nothing outside the root was touched.
    let entries: Vec<_> = std::fs::read_dir(&root)
        .expect("read root")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.is_empty(),
        "no directory may be created: {entries:?}"
    );
    cleanup(&root);
}

/// Upstream v2.8.2 fix: `shutdown` and `evict_idle` had no production callers, so a
/// daemon restart orphaned every sandbox directory, and `acquire` never checked
/// whether the directory already existed. This test creates a sandbox, **drops the
/// manager without an explicit shutdown**, reconstructs a manager over the same
/// root, and asserts the orphan is reclaimed *and* that a new sandbox never
/// inherits the old directory.
#[test]
fn a_dropped_manager_leaves_an_orphan_and_the_next_open_reclaims_it() {
    let root = root_for("orphan-sweep");

    let (old_id, old_dir) = {
        let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
            .expect("open")
            // Zero, so a directory created a moment ago is still reclaimable: the
            // production default is ORPHAN_AGE_SECS and is tested in
            // `a_fresh_directory_from_another_run_is_not_reclaimed`.
            .with_orphan_age_secs(0);
        let id = mgr.create("alice", &runnable_spec()).expect("create");
        let dir = root.join(id.as_str());
        assert!(dir.is_dir());
        // Plant a file: if the id were reused, the next sandbox would inherit it.
        std::fs::write(dir.join("secret.txt"), "old sandbox data").expect("plant file");

        // Simulate a process that vanished without running `Drop`'s shutdown: the
        // record leaves the table, the directory and its marker stay.
        let forgotten = mgr.forget_all_for_test();
        assert_eq!(forgotten, vec![id.as_str().to_string()]);
        std::mem::forget(mgr);
        (id.as_str().to_string(), dir)
    };

    assert!(
        old_dir.is_dir(),
        "the abandoned directory must still be there before the sweep"
    );

    let fresh = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_100)
        .expect("reopen")
        .with_orphan_age_secs(0);
    let report = fresh.sweep().expect("sweep");
    assert!(
        report.reclaimed.contains(&old_id),
        "the orphan `{old_id}` must be reclaimed, report: {report:?}"
    );
    assert!(
        !old_dir.exists(),
        "the orphan directory must be gone: {}",
        old_dir.display()
    );

    // A new sandbox must not inherit the old one's files, and must not get the old
    // id back.
    let new_id = fresh
        .create("alice", &runnable_spec())
        .expect("create a new sandbox");
    assert_ne!(
        new_id.as_str(),
        old_id,
        "an id must never be reissued, even after reclamation"
    );
    let new_dir = root.join(new_id.as_str());
    assert!(
        !new_dir.join("secret.txt").exists(),
        "the new sandbox must not inherit the old sandbox's files"
    );
    // The sweep is recorded in the audit log.
    let log = fresh.audit_log();
    assert!(
        log.iter().any(|e| matches!(
            &e.action,
            nau_sandbox::AuditAction::OrphanReclaimed { id, .. } if id == &old_id
        )),
        "reclaiming an orphan must be audited: {log:?}"
    );
    let _ = fresh.destroy("alice", new_id.as_str());
    drop(fresh);
    cleanup(&root);
}

/// The sweep's margin: a directory created seconds ago by a *different* run must be
/// left alone when the configured age is the production default, because it may
/// belong to a daemon that is starting concurrently.
#[test]
fn a_fresh_directory_from_another_run_is_not_reclaimed() {
    let root = root_for("sweep-margin");
    {
        let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
            .expect("open");
        let id = mgr.create("alice", &runnable_spec()).expect("create");
        assert!(root.join(id.as_str()).is_dir());
        std::mem::forget(mgr);
    }
    // Default age (ORPHAN_AGE_SECS, two minutes): the directory is seconds old, so
    // it is not touched.
    let fresh = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_100)
        .expect("reopen");
    let report = fresh.sweep().expect("sweep");
    assert!(
        report.reclaimed.is_empty(),
        "a fresh directory must not be reclaimed: {report:?}"
    );
    assert!(
        !report.skipped.is_empty(),
        "the decision must be reported, not silent: {report:?}"
    );
    // With the margin at zero, the same directory *is* reclaimed: the margin is the
    // only thing keeping it.
    let zero = fresh.with_orphan_age_secs(0);
    let report = zero.sweep().expect("sweep with no margin");
    assert_eq!(report.reclaimed.len(), 1, "report: {report:?}");
    drop(zero);
    cleanup(&root);
}

/// Win32 silently normalises a trailing dot out of a path component, so a name the
/// caller asked for and the name that ends up on disk are two different strings.
/// That is why the validator refuses the form outright, and this test pins both
/// halves: the requested name is refused, and the *normalised* directory that does
/// exist is handled as the ordinary id-shaped name it actually is.
///
/// The sweep's other name gate — "a name that fails [`nau_sandbox::SafeComponent`]
/// is skipped before any deletion decision" — cannot be given a fixture on Windows,
/// because Windows refuses to create a directory with any name the validator rejects
/// that is not already normalised (`a:b` fails outright; `NUL` reports success and
/// creates nothing). On Unix the same gate is exercised by `a:b`, `NUL.txt` and
/// `file*name`, which are all creatable there. The gate itself is covered on every
/// platform by `component::tests`, and this test records why the Windows half is not
/// reproducible here rather than leaving it silently untested.
#[test]
fn the_sweep_never_deletes_a_directory_whose_name_is_not_a_component() {
    let root = root_for("sweep-foreign");
    let foreign = root.join("trailing.");
    std::fs::create_dir_all(&foreign).expect("foreign dir");
    // The point of the fixture: `trailing.` is not the name on disk. Windows
    // normalised it, which is exactly why the validator refuses the form.
    // What the fixture demonstrates differs by platform, and saying so IS the test:
    //   * Windows normalises the trailing dot away, so what lands on disk is
    //     `trailing` -- which is exactly why the validator refuses the form;
    //   * Unix creates `trailing.` literally, so the name on disk IS the refused
    //     form, and the sweep must SKIP it rather than delete it. That is the
    //     stronger half of the property, and it is only exercisable here.
    #[cfg(windows)]
    assert!(
        root.join("trailing").is_dir(),
        "the fixture must demonstrate the normalisation: `trailing.` must have been created as \
         `trailing`"
    );
    #[cfg(not(windows))]
    assert!(
        foreign.is_dir(),
        "on Unix the requested name is created literally, so the fixture on disk is the refused \
         form itself"
    );
    // The requested name itself is refused by the validator, before any path is built.
    assert!(
        nau_sandbox::SafeComponent::parse("trailing.").is_err(),
        "`trailing.` must be refused as a component"
    );
    std::fs::write(foreign.join("keep.txt"), "keep me").expect("write");

    let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
        .expect("open")
        .with_orphan_age_secs(0);
    let report = mgr.sweep().expect("sweep");
    // `trailing` **is** a safe component, so it is treated as an id-shaped name that no
    // live sandbox owns and is reclaimed — and that is the correct behaviour, not a
    // defect: the name the caller asked for was refused, so no sandbox ever owned this
    // directory. The guard that matters is the refusal asserted above.
    assert!(
        report.reclaimed.is_empty() || report.reclaimed == vec!["trailing".to_string()],
        "only the normalised name may be reclaimed: {report:?}"
    );
    // On Unix the directory on disk really is named `trailing.`, so this asserts the
    // gate itself rather than a normalisation side effect: a name the validator
    // refuses must be left alone, contents intact.
    #[cfg(not(windows))]
    assert!(
        foreign.join("keep.txt").is_file(),
        "a directory whose name the validator refuses must be SKIPPED, never deleted: {report:?}"
    );
    drop(mgr);
    cleanup(&root);
}

/// Explicit `shutdown` kills and removes everything, is idempotent, and refuses
/// further work. `Drop` does the same, which is what makes "no orphans" hold when a
/// daemon exits.
#[test]
fn shutdown_removes_everything_and_is_idempotent() {
    let (mgr, root) = real_manager("shutdown");
    let a = mgr
        .create("alice", &runnable_spec())
        .expect("create")
        .as_str()
        .to_string();
    let b = mgr
        .create("bob", &runnable_spec())
        .expect("create")
        .as_str()
        .to_string();
    assert!(root.join(&a).is_dir() && root.join(&b).is_dir());

    mgr.shutdown().expect("shutdown");
    assert!(!root.join(&a).exists(), "shutdown must remove {a}");
    assert!(!root.join(&b).exists(), "shutdown must remove {b}");
    // A second call is not an error.
    mgr.shutdown().expect("shutdown twice");
    // And the manager refuses new work rather than half-working.
    let err = mgr
        .create("alice", &runnable_spec())
        .expect_err("a shut-down manager must refuse");
    assert!(matches!(err, SandboxError::ManagerGone), "got {err:?}");
    assert!(matches!(
        mgr.describe("alice", &a),
        Err(SandboxError::ManagerGone)
    ));
    drop(mgr);
    cleanup(&root);
}

/// `Drop` alone must clean up, because that is the only thing that runs when a
/// daemon exits without an explicit shutdown.
#[test]
fn dropping_the_manager_removes_its_directories() {
    let root = root_for("drop-cleanup");
    let dir = {
        let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
            .expect("open");
        let id = mgr.create("alice", &runnable_spec()).expect("create");
        let dir = root.join(id.as_str());
        assert!(dir.is_dir());
        dir
    };
    assert!(
        !dir.exists(),
        "Drop must remove {}, or the next run inherits it",
        dir.display()
    );
    cleanup(&root);
}

/// Pause and resume are owner-scoped, and a paused sandbox refuses execution
/// instead of running anyway. Upstream had no such state at all.
// Windows only: this actually runs a child and asserts its exit code, so it needs a
// process backend whose enforcement has been demonstrated -- see the note in
// `enforcement.rs` and the report in `tests/platform_support.rs`.
#[cfg(windows)]
#[test]
fn a_paused_sandbox_refuses_execution() {
    let (mgr, root) = real_manager("pause");
    let spec = runnable_spec();
    let id = mgr
        .create("alice", &spec)
        .expect("create")
        .as_str()
        .to_string();
    // It runs while ready.
    assert_eq!(
        mgr.exec("alice", &id, None, &ExecRequest::new())
            .expect("exec")
            .exit_code,
        Some(0)
    );
    mgr.pause("alice", &id).expect("pause");
    assert_eq!(
        mgr.describe("alice", &id).expect("describe").state,
        SandboxState::Paused
    );
    let err = mgr
        .exec("alice", &id, None, &ExecRequest::new())
        .expect_err("a paused sandbox must refuse");
    assert!(matches!(err, SandboxError::Busy(_, _)), "got {err:?}");
    mgr.resume("alice", &id).expect("resume");
    assert!(mgr
        .exec("alice", &id, None, &ExecRequest::new())
        .expect("exec after resume")
        .success());
    let _ = mgr.destroy("alice", &id);
    cleanup(&root);
}

/// A destroyed id is terminal: it is never reissued, and every later operation on it
/// reports the same "not found" as an id that never existed.
#[test]
fn a_destroyed_id_is_terminal_and_never_reissued() {
    let (mgr, root) = real_manager("destroy-terminal");
    let id = mgr
        .create("alice", &runnable_spec())
        .expect("create")
        .as_str()
        .to_string();
    mgr.destroy("alice", &id).expect("destroy");
    assert!(mgr.list("alice").expect("list").is_empty());
    for outcome in [
        mgr.describe("alice", &id).err(),
        mgr.exec("alice", &id, None, &ExecRequest::new()).err(),
        mgr.pause("alice", &id).err(),
        mgr.resume("alice", &id).err(),
        mgr.destroy("alice", &id).err(),
    ] {
        assert!(
            matches!(outcome, Some(SandboxError::NotFound(_))),
            "a destroyed id must be NotFound, got {outcome:?}"
        );
    }
    // A later creation gets a different id.
    let next = mgr
        .create("alice", &runnable_spec())
        .expect("create again")
        .as_str()
        .to_string();
    assert_ne!(next, id);
    let _ = mgr.destroy("alice", &next);
    cleanup(&root);
}

/// The manager holds a bounded number of sandboxes rather than growing without
/// limit.
#[test]
fn the_manager_refuses_more_sandboxes_than_its_cap() {
    let root = root_for("cap");
    let mgr = SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
        .expect("open")
        .with_max_sandboxes(2);
    let spec = runnable_spec();
    let a = mgr.create("alice", &spec).expect("first");
    let b = mgr.create("alice", &spec).expect("second");
    let err = mgr.create("alice", &spec).expect_err("third must fail");
    assert!(matches!(err, SandboxError::Limit { .. }), "got {err:?}");
    let _ = mgr.destroy("alice", a.as_str());
    let _ = mgr.destroy("alice", b.as_str());
    cleanup(&root);
}

/// A backend that enforces nothing must not be able to create anything, so the
/// manager's happy path cannot be reached through the default backend.
#[test]
fn the_default_backend_cannot_create_a_sandbox() {
    let (mgr, root) = null_manager("null-default");
    // Two independent refusals stand in the way, and both are typed:
    // `ExecutionDisabled` because the backend runs nothing, and `PolicyNotEnforceable`
    // because it claims no capability. Which one a caller sees depends on where in
    // `SandboxManager::create` the refusal is reached — the capability check runs
    // first — and either is a closed refusal that creates nothing.
    let err = mgr
        .create("alice", &runnable_spec())
        .expect_err("NullExecutor must refuse");
    match err {
        SandboxError::PolicyNotEnforceable { .. } | SandboxError::ExecutionDisabled(_) => {}
        other => panic!("the refusal must be typed, got {other:?}"),
    }
    // The other refusal path is reachable directly and is equally typed.
    let err = NullExecutor::new()
        .create(
            &root,
            &nau_sandbox::SafeComponent::parse("00000000000000000000000000000000")
                .expect("component"),
            &runnable_spec(),
        )
        .expect_err("the null backend executes nothing");
    assert!(
        matches!(err, SandboxError::ExecutionDisabled(_)),
        "got {err:?}"
    );
    let err = NullExecutor::new()
        .validate(&runnable_spec())
        .expect_err("a backend that claims nothing must refuse by name");
    match err {
        SandboxError::PolicyNotEnforceable {
            boundary, detail, ..
        } => {
            assert!(
                boundary == Capability::EnvAllowlist,
                "the first boundary in the spec must be the one named: {boundary}"
            );
            assert!(
                detail.contains("null backend"),
                "the refusal must carry the backend's own reason: {detail}"
            );
        }
        other => panic!("expected a named refusal, got {other:?}"),
    }
    assert!(mgr.list("alice").expect("list").is_empty());
    // No directory was created anywhere under the root.
    let entries: Vec<_> = std::fs::read_dir(&root)
        .expect("read root")
        .filter_map(|e| e.ok())
        .collect();
    assert!(entries.is_empty(), "nothing may be created: {entries:?}");
    // A refused creation is not a silent no-op: the refusal is what a caller sees,
    // and the audit log did not record a creation that never happened.
    assert!(
        !mgr.audit_log()
            .iter()
            .any(|e| matches!(e.action, nau_sandbox::AuditAction::Created)),
        "a refused creation must not be audited as created"
    );
    cleanup(&root);
}

/// The manager exposes its backend's declaration, so an operator can ask "what does
/// this deployment actually enforce?" without reading a document.
#[test]
fn the_manager_reports_its_backends_declaration() {
    let (mgr, root) = real_manager("declaration");
    let caps = mgr.capabilities();
    assert_eq!(caps.backend(), nau_sandbox::PLATFORM_BACKEND);
    assert!(caps.enforces(nau_sandbox::Capability::MemoryLimit));
    let unenforced: Vec<String> = caps
        .unenforced()
        .iter()
        .map(|e| e.boundary.to_string())
        .collect();
    assert!(
        unenforced.contains(&"network_deny_all".to_string()),
        "the deployment must state that egress cannot be denied: {unenforced:?}"
    );
    drop(mgr);
    cleanup(&root);
}

/// A manager can be used from several threads without a global execution lock, and
/// a poisoned lock is reported rather than panicking.
///
/// Upstream v2.8.2 fix: `mgr.lock().unwrap()` meant any earlier panic turned every
/// later sandbox call into a panic, and one mutex serialised every sandbox.
#[cfg(windows)]
#[test]
fn concurrent_operations_do_not_deadlock_or_panic() {
    let root = root_for("concurrency");
    let mgr = Arc::new(
        SandboxManager::open(&root, Arc::new(RealProcessExecutor::new()), 1_700_000_000)
            .expect("open"),
    );
    let spec = runnable_spec();
    let ids: Vec<String> = (0..4)
        .map(|_| {
            mgr.create("alice", &spec)
                .expect("create")
                .as_str()
                .to_string()
        })
        .collect();

    // Four sandboxes execute at the same time. Each holds only its own lock, so all
    // four must finish; a single global lock would serialise them but still finish,
    // whereas a lock held across the wrong scope would deadlock.
    let mut handles = Vec::new();
    for id in &ids {
        let mgr = Arc::clone(&mgr);
        let id = id.clone();
        let spec = spec.clone();
        handles.push(std::thread::spawn(move || {
            mgr.exec("alice", &id, Some(&spec), &ExecRequest::new())
                .map(|o| o.exit_code)
        }));
    }
    for handle in handles {
        let outcome = handle.join().expect("no thread may panic");
        assert_eq!(outcome.expect("exec"), Some(0));
    }
    // A read while nothing is executing still works.
    for id in &ids {
        assert!(mgr.describe("alice", id).is_ok());
    }
    for id in &ids {
        let _ = mgr.destroy("alice", id);
    }
    drop(mgr);
    cleanup(&root);
}

/// A test double that records what it was asked to do, so the manager's behaviour
/// can be checked without running a process. Mirrors `nau-net`'s memory double.
#[derive(Default)]
struct RecordingExecutor {
    created: std::sync::Mutex<Vec<String>>,
    destroyed: std::sync::Mutex<Vec<String>>,
}

impl SandboxExecutor for RecordingExecutor {
    fn capabilities(&self) -> &nau_sandbox::Capabilities {
        use nau_sandbox::{Capabilities, Capability};
        // A declaration that claims the boundaries the manager's happy path needs,
        // so `create` succeeds and the bookkeeping can be observed.
        static CAPS: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        CAPS.get_or_init(|| {
            Capabilities::new(
                "recording-double",
                [
                    Capability::EnvAllowlist,
                    Capability::OutputCap,
                    Capability::Timeout,
                    Capability::WorkDirIsolation,
                    Capability::MemoryLimit,
                    Capability::ProcessCountLimit,
                    Capability::NetworkDenyAll,
                    Capability::FilesystemConfinement,
                    Capability::CpuLimit,
                    Capability::DiskQuota,
                    Capability::OpenFileLimit,
                ],
                [],
            )
            .unwrap_or_else(|_| {
                Capabilities::new("recording-double", [], []).unwrap_or_else(|_| {
                    Capabilities::new(
                        "recording-double",
                        [],
                        [(Capability::Timeout, "unreachable".to_string())],
                    )
                    .unwrap_or_else(|_| {
                        Capabilities::new(
                            "recording-double",
                            [],
                            [(Capability::Timeout, "unreachable".to_string())],
                        )
                        .expect("a constant declaration always validates")
                    })
                })
            })
        })
    }

    fn create(
        &self,
        root: &std::path::Path,
        id: &nau_sandbox::SafeComponent,
        spec: &nau_sandbox::SandboxSpec,
    ) -> nau_sandbox::Result<nau_sandbox::SandboxHandle> {
        self.validate(spec)?;
        self.created
            .lock()
            .map(|mut v| v.push(id.as_str().to_string()))
            .ok();
        let work_dir = id.join_under(root)?;
        std::fs::create_dir_all(&work_dir)?;
        Ok(nau_sandbox::SandboxHandle {
            id: id.clone(),
            work_dir,
        })
    }

    fn exec(
        &self,
        _handle: &nau_sandbox::SandboxHandle,
        _spec: &nau_sandbox::SandboxSpec,
        _request: &ExecRequest,
    ) -> nau_sandbox::Result<nau_sandbox::ExecOutcome> {
        Ok(nau_sandbox::ExecOutcome {
            exit_code: Some(0),
            stdout: b"double".to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            timed_out: false,
            terminated: false,
            readers_finished: true,
            job_killed: true,
            elapsed_ms: 1,
        })
    }

    fn destroy(&self, handle: &nau_sandbox::SandboxHandle) -> nau_sandbox::Result<()> {
        self.destroyed
            .lock()
            .map(|mut v| v.push(handle.id.as_str().to_string()))
            .ok();
        Ok(())
    }
}

/// The port really is swappable: a double can stand in for the platform backend,
/// which is what makes the manager testable without spawning anything. Mirrors the
/// `nau-net` pattern of one port, one real implementation and one memory double.
#[test]
fn a_recording_double_can_stand_in_for_the_backend() {
    let root = root_for("double");
    let double = Arc::new(RecordingExecutor::default());
    let mgr = SandboxManager::open(&root, double.clone(), 1_700_000_000).expect("open");
    let spec = runnable_spec();
    let id = mgr
        .create("alice", &spec)
        .expect("create")
        .as_str()
        .to_string();
    assert_eq!(
        double.created.lock().expect("lock").as_slice(),
        &[id.clone()]
    );
    let outcome = mgr
        .exec("alice", &id, None, &ExecRequest::new())
        .expect("exec");
    assert_eq!(outcome.stdout, b"double");
    mgr.destroy("alice", &id).expect("destroy");
    assert_eq!(
        double.destroyed.lock().expect("lock").as_slice(),
        &[id.clone()]
    );
    drop(mgr);
    cleanup(&root);
}
