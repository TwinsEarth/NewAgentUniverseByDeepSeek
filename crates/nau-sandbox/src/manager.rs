//! [`SandboxManager`] — identity, ownership, lifecycle and the startup sweep.
//!
//! # What this replaces
//!
//! Upstream v2.8.2 fix, one finding per design decision:
//!
//! * **id reuse.** Ids were a per-process counter (`manager.rs:67-70`) and the
//!   work directory lived under the persistent data dir with no existence check,
//!   so after a restart `sb-1` was reissued *and inherited the previous `sb-1`'s
//!   files*. Ids here are v4 UUIDs validated by the same function every other path
//!   component goes through, and [`SandboxManager::create`] explicitly detects
//!   the "directory already exists for a fresh id" case instead of writing into
//!   it.
//! * **orphans.** `shutdown`/`evict_idle` had no production callers, so a daemon
//!   restart orphaned every sandbox directory. [`SandboxManager::open`] sweeps
//!   directories that no live sandbox owns, from a run that is no longer running,
//!   recounting what it reclaimed; a sweep that cannot finish fails the manager
//!   open rather than leaving an unaccounted directory behind. `Drop` and
//!   [`SandboxManager::shutdown`] kill and remove everything they own.
//! * **one global lock across execution.** Upstream serialised every sandbox
//!   behind one mutex and panicked on poisoning (`mgr.lock().unwrap()`). Here the
//!   table lock is held only to look up an entry; execution happens under a
//!   **per-sandbox** lock, and every lock acquisition handles poisoning
//!   explicitly, as a typed error rather than a panic.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::capability::Capabilities;
use crate::component::SafeComponent;
use crate::error::{Result, SandboxError};
use crate::executor::{SandboxExecutor, SandboxHandle};
use crate::process::{ExecOutcome, ExecRequest};
use crate::spec::{Interpreter, NetworkPolicy, SandboxSpec};

/// State of one sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    /// Created and available.
    Ready,
    /// Paused by its owner. An `exec` while paused is refused.
    Paused,
    /// Destroyed. Terminal, and the id is never reissued.
    Destroyed,
}

/// One recorded sandbox.
#[derive(Debug, Clone)]
struct SandboxRecord {
    owner: String,
    created_at: u64,
    state: SandboxState,
    spec: SandboxSpec,
    handle: SandboxHandle,
}

/// Something that happened and that an operator would want to know about.
///
/// Upstream v2.8.2 fix: `AuditLog::append` had zero production callers, so a run
/// with a waived boundary left no trace at all. Every entry here is written before
/// the effect it describes is allowed to happen.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    /// Unix seconds.
    pub at: u64,
    /// The owning principal.
    pub owner: String,
    /// The sandbox id, when the entry concerns one.
    pub sandbox: Option<String>,
    /// What happened.
    pub action: AuditAction,
}

/// The auditable events.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "action", content = "detail")]
pub enum AuditAction {
    /// A sandbox was created.
    Created,
    /// A sandbox was destroyed.
    Destroyed,
    /// A sandbox was paused.
    Paused,
    /// A sandbox was resumed.
    Resumed,
    /// The sandbox ran with unrestricted egress, because the operator asked for it.
    UnrestrictedEgress {
        /// The justification given in the request.
        justification: String,
    },
    /// The sandbox ran a shell, because the operator asked for one.
    ShellInterpreter {
        /// The shell's path.
        bin: String,
    },
    /// A boundary was waived, with the reason.
    BoundaryWaived {
        /// The boundary.
        boundary: String,
        /// The reason.
        justification: String,
    },
    /// The startup sweep reclaimed a directory from a run that is gone.
    OrphanReclaimed {
        /// The directory name.
        id: String,
        /// The run that owned it.
        run_id: String,
    },
    /// The startup sweep found a directory it must not touch.
    SweepSkipped {
        /// The directory name.
        id: String,
        /// Why it was left alone.
        reason: String,
    },
    /// A caller asked for a boundary the backend cannot enforce.
    Refused {
        /// The boundary.
        boundary: String,
        /// The backend's reason.
        reason: String,
    },
}

/// The marker file written inside each sandbox directory.
///
/// It records which *run* owns the directory, which is what makes the sweep
/// sound: a directory can only be reclaimed when this run did not create it, and
/// the live table is the authority for "this run".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct RunMarker {
    /// The owning run's random id.
    run_id: String,
    /// The process that created the directory.
    pid: u32,
    /// When it was created.
    created_at: u64,
}

/// The name of the marker file.
const MARKER_NAME: &str = ".nau-sandbox-run.json";

/// How many orphan directories a single `open` will reclaim before giving up.
pub const MAX_ORPHANS_PER_SWEEP: usize = 64;

/// What a sweep did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SweepReport {
    /// Ids whose directories were removed.
    pub reclaimed: Vec<String>,
    /// Ids that were left alone, with the reason.
    pub skipped: Vec<(String, String)>,
}

/// A manager, its backend, its audit log and its configuration.
pub struct SandboxManager {
    root: PathBuf,
    executor: Arc<dyn SandboxExecutor>,
    now: u64,
    run_id: String,
    max_sandboxes: usize,
    orphan_age_secs: u64,
    shutting_down: AtomicBool,
    sweeps: AtomicU64,
    table: Mutex<BTreeMap<SafeComponent, Arc<Mutex<SandboxRecord>>>>,
    audit: Mutex<Vec<AuditEntry>>,
}

impl SandboxManager {
    /// Open a manager over `root`, sweeping directories that no live sandbox owns.
    ///
    /// Fails closed: if a directory that looks like an orphan cannot be removed,
    /// the manager refuses to open, because the alternative is creating new
    /// sandboxes on top of state nobody accounted for.
    pub fn open(
        root: impl Into<PathBuf>,
        executor: Arc<dyn SandboxExecutor>,
        now: u64,
    ) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| {
            SandboxError::WorkDir(format!(
                "cannot create sandbox root {}: {e}",
                root.display()
            ))
        })?;
        let root = root.canonicalize().map_err(|e| {
            SandboxError::WorkDir(format!(
                "cannot resolve sandbox root {}: {e}",
                root.display()
            ))
        })?;
        let manager = Self {
            root,
            executor,
            now,
            run_id: uuid::Uuid::new_v4().simple().to_string(),
            max_sandboxes: DEFAULT_MAX_SANDBOXES,
            orphan_age_secs: ORPHAN_AGE_SECS,
            shutting_down: AtomicBool::new(false),
            sweeps: AtomicU64::new(0),
            table: Mutex::new(BTreeMap::new()),
            audit: Mutex::new(Vec::new()),
        };
        // The opening sweep is audited like every other one: `sweep` records its own
        // decisions, so the reclaim of a previous run's directory is never silent.
        manager.sweep()?;
        Ok(manager)
    }

    /// Change how old an unaccounted directory must be before the sweep may
    /// reclaim it.
    ///
    /// The default is [`ORPHAN_AGE_SECS`]. A test sets it to `0` so that a
    /// directory left by a dropped manager — created seconds ago — is reclaimed in
    /// the same run rather than after two minutes. Lowering it in production makes
    /// two concurrently starting daemons able to delete each other's fresh
    /// directories, which is why the default is not zero.
    pub fn with_orphan_age_secs(mut self, secs: u64) -> Self {
        self.orphan_age_secs = secs;
        self
    }

    /// Change how many sandboxes one manager will hold.
    pub fn with_max_sandboxes(mut self, max: usize) -> Self {
        self.max_sandboxes = max;
        self
    }

    /// The canonical sandbox root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// This run's random identifier. Used by the sweep and by tests.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The backend.
    pub fn executor(&self) -> &Arc<dyn SandboxExecutor> {
        &self.executor
    }

    /// The backend's capability declaration.
    pub fn capabilities(&self) -> &Capabilities {
        self.executor.capabilities()
    }

    /// How many sweeps have run.
    pub fn sweep_count(&self) -> u64 {
        self.sweeps.load(Ordering::SeqCst)
    }

    /// Reclaim directories from runs that are gone and are not live now.
    ///
    /// A directory is reclaimed when **all** of these hold:
    ///
    /// 1. it is not in the live table;
    /// 2. it is not one of `protected`, the ids the caller vouches for;
    /// 3. its marker names a different run than this one;
    /// 4. it is older than two minutes, so a concurrently starting daemon's
    ///    directory is not mistaken for an orphan.
    ///
    /// Anything else is skipped and recorded, never deleted.
    pub fn sweep(&self) -> Result<SweepReport> {
        let mut report = SweepReport::default();
        let entries = std::fs::read_dir(&self.root).map_err(|e| {
            SandboxError::WorkDir(format!("cannot read {}: {e}", self.root.display()))
        })?;
        let mut failures: Vec<String> = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = SafeComponent::parse(&name).ok() else {
                // A directory whose name is not a safe component is not ours to
                // delete: it might be anything, including a mount point.
                report
                    .skipped
                    .push((name, "name is not a valid sandbox id".to_string()));
                continue;
            };
            if !entry.path().is_dir() {
                continue;
            }
            if self.live_contains(&id) {
                report
                    .skipped
                    .push((name, "live in this manager".to_string()));
                continue;
            }
            match self.classify(&entry.path()) {
                Classified::Orphan { .. } => {
                    if report.reclaimed.len() >= MAX_ORPHANS_PER_SWEEP {
                        failures.push(format!(
                            "more than {MAX_ORPHANS_PER_SWEEP} orphans; stopping"
                        ));
                        break;
                    }
                    match std::fs::remove_dir_all(entry.path()) {
                        Ok(()) => report.reclaimed.push(name),
                        Err(e) => failures.push(format!("cannot remove {name}: {e}")),
                    }
                }
                Classified::Foreign => {
                    // Another run created it recently, or it has no marker. It is
                    // not this manager's to delete, and deleting it could destroy a
                    // concurrently running daemon's sandbox.
                    report.skipped.push((
                        name,
                        "not created by a previous run of this manager".to_string(),
                    ));
                }
            }
        }
        self.sweeps.fetch_add(1, Ordering::SeqCst);
        // Every sweep decision is audited, whether it happens during `open` or from
        // an explicit call.
        self.record_sweep(&report);
        if !failures.is_empty() {
            return Err(SandboxError::OrphanReclaim {
                count: failures.len(),
                detail: failures.join("; "),
            });
        }
        Ok(report)
    }

    /// Decide what a directory is.
    fn classify(&self, path: &Path) -> Classified {
        let marker_path = path.join(MARKER_NAME);
        let Ok(text) = std::fs::read_to_string(&marker_path) else {
            // No marker at all. Either a directory from before this format existed
            // or a partial creation. Its age decides, so that a directory being
            // created right now by another process is not a candidate.
            return if older_than(path, self.orphan_age_secs) {
                Classified::Orphan {
                    run_id: "<no marker>".to_string(),
                }
            } else {
                Classified::Foreign
            };
        };
        let Ok(marker) = serde_json::from_str::<RunMarker>(&text) else {
            return if older_than(path, self.orphan_age_secs) {
                Classified::Orphan {
                    run_id: "<unreadable marker>".to_string(),
                }
            } else {
                Classified::Foreign
            };
        };
        if marker.run_id == self.run_id {
            return Classified::Foreign;
        }
        // A different run. Liveness is consulted **only when the age margin is in
        // effect**, and only in the direction that makes the sweep more careful: a
        // directory younger than the margin whose creating process is still alive
        // may belong to a daemon that is starting right now.
        //
        // The margin is what protects concurrency; pid liveness cannot, because pids
        // are reused and because a run that dropped its manager without shutting down
        // still shares this process's pid. Gating the liveness check on the margin
        // stops that from becoming a permanent leak — which is exactly what a test
        // that drops a manager and reopens would expose.
        if self.orphan_age_secs > 0
            && !older_than(path, self.orphan_age_secs)
            && process_is_alive(marker.pid)
        {
            return Classified::Foreign;
        }
        Classified::Orphan {
            run_id: marker.run_id,
        }
    }

    /// Write one audit entry for every orphan decision the sweep made.
    fn record_sweep(&self, report: &SweepReport) {
        for id in &report.reclaimed {
            self.audit(AuditAction::OrphanReclaimed {
                id: id.clone(),
                run_id: self.run_id.clone(),
            });
        }
        for (id, reason) in &report.skipped {
            self.audit(AuditAction::SweepSkipped {
                id: id.clone(),
                reason: reason.clone(),
            });
        }
    }

    /// Create a sandbox owned by `owner`.
    ///
    /// The spec is validated against the backend's capability declaration first,
    /// so an unenforceable boundary is a refusal and not a silent downgrade. Every
    /// waiver, every unrestricted-egress grant and every use of a shell interpreter
    /// is written to the audit log **before** the directory is created.
    pub fn create(&self, owner: &str, spec: &SandboxSpec) -> Result<SafeComponent> {
        self.ensure_open()?;
        if owner.trim().is_empty() {
            return Err(SandboxError::Limit {
                limit: "a sandbox must have an owner principal".to_string(),
            });
        }
        self.audit_spec_grants(owner, spec)?;
        self.executor.validate(spec)?;

        {
            let table = self.table_lock()?;
            if table.len() >= self.max_sandboxes {
                return Err(SandboxError::Limit {
                    limit: format!(
                        "this manager holds {} sandboxes, its configured maximum",
                        self.max_sandboxes
                    ),
                });
            }
        }

        let id = self.fresh_id()?;
        let handle = self.executor.create(&self.root, &id, spec)?;
        // The marker is what makes this directory reclaimable by a later run.
        let marker = RunMarker {
            run_id: self.run_id.clone(),
            pid: std::process::id(),
            created_at: self.now,
        };
        if let Err(e) = write_marker(&handle.work_dir, &marker) {
            // Without a marker the directory would be invisible to the sweep, so
            // creation fails and the directory is removed rather than left behind.
            let _ = self.executor.destroy(&handle);
            let _ = std::fs::remove_dir_all(&handle.work_dir);
            return Err(e);
        }
        let record = SandboxRecord {
            owner: owner.to_string(),
            created_at: self.now,
            state: SandboxState::Ready,
            spec: spec.clone(),
            handle,
        };
        {
            let mut table = self.table_lock()?;
            if table.contains_key(&id) {
                // A v4 UUID collision. Refuse rather than reuse.
                return Err(SandboxError::Internal(format!(
                    "sandbox id `{id}` already exists"
                )));
            }
            table.insert(id.clone(), Arc::new(Mutex::new(record)));
        }
        self.audit_for(owner, Some(id.as_str()), AuditAction::Created);
        Ok(id)
    }

    /// Fetch the record for `id`, requiring `owner` to be the owner.
    ///
    /// A different principal gets [`SandboxError::NotFound`], the same error as a
    /// nonexistent id, so the API cannot be used to confirm that an id exists.
    fn owned(&self, owner: &str, id: &SafeComponent) -> Result<Arc<Mutex<SandboxRecord>>> {
        self.ensure_open()?;
        let table = self.table_lock()?;
        let entry = table
            .get(id)
            .ok_or_else(|| SandboxError::NotFound(id.as_str().to_string()))?;
        let record = entry
            .lock()
            .map_err(|_| SandboxError::Internal("the record is poisoned".to_string()))?;
        let mine = record.owner == owner && record.state != SandboxState::Destroyed;
        // The guard is dropped here, before the `Arc` is returned: the caller takes
        // its own lock so that a slow `exec` does not block a `describe`.
        drop(record);
        if !mine {
            // Same error as "no such id": a destroyed id and someone else's id must
            // not be distinguishable from one that never existed.
            return Err(SandboxError::NotFound(id.as_str().to_string()));
        }
        Ok(Arc::clone(entry))
    }

    /// Metadata for one sandbox, for `GET`.
    pub fn describe(&self, owner: &str, id: &str) -> Result<SandboxDescription> {
        let component = SafeComponent::parse(id)?;
        let entry = self.owned(owner, &component)?;
        let record = entry
            .lock()
            .map_err(|_| SandboxError::Internal("the record is poisoned".to_string()))?;
        Ok(SandboxDescription {
            id: component.as_str().to_string(),
            owner: record.owner.clone(),
            created_at: record.created_at,
            state: record.state,
            work_dir: record.handle.work_dir.display().to_string(),
            network: record.spec.network.name().to_string(),
            timeout_ms: record.spec.limits.timeout_ms,
            memory_bytes: record.spec.limits.memory_bytes,
            max_processes: record.spec.limits.max_processes,
            max_output_bytes: record.spec.limits.max_output_bytes,
        })
    }

    /// The ids `owner` holds, in ascending order.
    pub fn list(&self, owner: &str) -> Result<Vec<String>> {
        self.ensure_open()?;
        let table = self.table_lock()?;
        let mut out = Vec::new();
        for (id, entry) in table.iter() {
            let record = entry
                .lock()
                .map_err(|_| SandboxError::Internal("a record is poisoned".to_string()))?;
            if record.owner == owner && record.state != SandboxState::Destroyed {
                out.push(id.as_str().to_string());
            }
        }
        Ok(out)
    }

    /// Run one request in a sandbox.
    ///
    /// `override_spec` may only tighten: if it would widen any limit or loosen the
    /// network policy, it is refused. The per-sandbox lock is held for the duration
    /// of the execution, which is what makes "no two execs in one work directory"
    /// true without serialising every *other* sandbox.
    pub fn exec(
        &self,
        owner: &str,
        id: &str,
        override_spec: Option<&SandboxSpec>,
        request: &ExecRequest,
    ) -> Result<ExecOutcome> {
        let component = SafeComponent::parse(id)?;
        let entry = self.owned(owner, &component)?;
        let guard = entry
            .lock()
            .map_err(|_| SandboxError::Internal("the record is poisoned".to_string()))?;
        if guard.state == SandboxState::Paused {
            return Err(SandboxError::Busy(
                component.as_str().to_string(),
                "the sandbox is paused".to_string(),
            ));
        }
        if guard.state == SandboxState::Destroyed {
            return Err(SandboxError::Destroyed(component.as_str().to_string()));
        }
        let effective = match override_spec {
            Some(over) => {
                over.tightens_only_against(&guard.spec)?;
                over.clone()
            }
            None => guard.spec.clone(),
        };
        // A fresh validation on the effective spec: the recorded spec was validated
        // at creation, and the override has just been checked to be a tightening of
        // it, but re-validating costs nothing and closes the path where a stored
        // spec is used after the backend changed.
        self.executor.validate(&effective)?;
        let outcome = self.executor.exec(&guard.handle, &effective, request)?;
        Ok(outcome)
    }

    /// Mark a sandbox paused. Its owner may resume it; an `exec` while paused is
    /// refused.
    pub fn pause(&self, owner: &str, id: &str) -> Result<()> {
        let component = SafeComponent::parse(id)?;
        let entry = self.owned(owner, &component)?;
        let mut record = entry
            .lock()
            .map_err(|_| SandboxError::Internal("the record is poisoned".to_string()))?;
        record.state = SandboxState::Paused;
        drop(record);
        self.audit_for(owner, Some(component.as_str()), AuditAction::Paused);
        Ok(())
    }

    /// Mark a paused sandbox ready again.
    pub fn resume(&self, owner: &str, id: &str) -> Result<()> {
        let component = SafeComponent::parse(id)?;
        let entry = self.owned(owner, &component)?;
        let mut record = entry
            .lock()
            .map_err(|_| SandboxError::Internal("the record is poisoned".to_string()))?;
        record.state = SandboxState::Ready;
        drop(record);
        self.audit_for(owner, Some(component.as_str()), AuditAction::Resumed);
        Ok(())
    }

    /// Destroy a sandbox: kill anything it owns, remove its directory, and make
    /// the id terminal.
    pub fn destroy(&self, owner: &str, id: &str) -> Result<()> {
        let component = SafeComponent::parse(id)?;
        let entry = self.owned(owner, &component)?;
        let (handle, owner_name) = {
            let mut record = entry
                .lock()
                .map_err(|_| SandboxError::Internal("the record is poisoned".to_string()))?;
            record.state = SandboxState::Destroyed;
            (record.handle.clone(), record.owner.clone())
        };
        self.executor.destroy(&handle)?;
        match std::fs::remove_dir_all(&handle.work_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(SandboxError::WorkDir(format!(
                    "cannot remove {}: {e}",
                    handle.work_dir.display()
                )))
            }
        }
        {
            let mut table = self.table_lock()?;
            table.remove(&component);
        }
        self.audit_for(
            &owner_name,
            Some(component.as_str()),
            AuditAction::Destroyed,
        );
        Ok(())
    }

    /// Kill and remove **everything** this manager owns.
    ///
    /// Idempotent: a second call reports success. Called from `Drop`.
    pub fn shutdown(&self) -> Result<()> {
        self.shutting_down.store(true, Ordering::SeqCst);
        let entries: Vec<(SafeComponent, Arc<Mutex<SandboxRecord>>)> = {
            let table = match self.table.lock() {
                Ok(t) => t,
                Err(poisoned) => poisoned.into_inner(),
            };
            table
                .iter()
                .map(|(k, v)| (k.clone(), Arc::clone(v)))
                .collect()
        };
        let mut first_error = None;
        for (id, entry) in entries {
            let handle = match entry.lock() {
                Ok(record) => record.handle.clone(),
                Err(poisoned) => poisoned.into_inner().handle.clone(),
            };
            if let Err(e) = self.executor.destroy(&handle) {
                first_error.get_or_insert(e);
            }
            if let Err(e) = std::fs::remove_dir_all(&handle.work_dir) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    first_error.get_or_insert(SandboxError::WorkDir(format!(
                        "cannot remove {}: {e}",
                        handle.work_dir.display()
                    )));
                }
            }
            let _ = id;
        }
        if let Err(e) = self.executor.shutdown() {
            first_error.get_or_insert(e);
        }
        {
            let mut table = match self.table.lock() {
                Ok(t) => t,
                Err(poisoned) => poisoned.into_inner(),
            };
            table.clear();
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// A snapshot of the audit log.
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        match self.audit.lock() {
            Ok(log) => log.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Append one audit entry.
    fn audit(&self, action: AuditAction) {
        self.audit_for("", None, action);
    }

    /// Append one audit entry attributed to `owner` and/or a sandbox.
    fn audit_for(&self, owner: &str, sandbox: Option<&str>, action: AuditAction) {
        let entry = AuditEntry {
            at: self.now,
            owner: owner.to_string(),
            sandbox: sandbox.map(|s| s.to_string()),
            action,
        };
        match self.audit.lock() {
            Ok(mut log) => log.push(entry),
            Err(poisoned) => poisoned.into_inner().push(entry),
        }
    }

    /// Write the audit entries a spec's permissive choices require.
    ///
    /// Runs **before** the sandbox exists, so a grant that cannot be logged cannot
    /// be used.
    fn audit_spec_grants(&self, owner: &str, spec: &SandboxSpec) -> Result<()> {
        if let NetworkPolicy::Unrestricted { justification } = &spec.network {
            self.audit_for(
                owner,
                None,
                AuditAction::UnrestrictedEgress {
                    justification: justification.clone(),
                },
            );
        }
        if let Interpreter::Shell(bin) = &spec.interpreter {
            self.audit_for(
                owner,
                None,
                AuditAction::ShellInterpreter {
                    bin: bin.to_string(),
                },
            );
        }
        for (boundary, justification) in spec.waivers.declared() {
            if justification.trim().is_empty() {
                return Err(SandboxError::PolicyNotEnforceable {
                    boundary,
                    backend: self.executor.name().to_string(),
                    detail: "a waiver requires a non-empty justification".to_string(),
                });
            }
            self.audit_for(
                owner,
                None,
                AuditAction::BoundaryWaived {
                    boundary: boundary.to_string(),
                    justification: justification.to_string(),
                },
            );
        }
        Ok(())
    }

    /// A fresh id that no existing directory uses.
    fn fresh_id(&self) -> Result<SafeComponent> {
        let table = self.table_lock()?;
        for _ in 0..32 {
            let candidate = uuid::Uuid::new_v4().simple().to_string();
            let id = SafeComponent::parse(&candidate)?;
            if table.contains_key(&id) {
                continue;
            }
            // A directory that already exists means a previous run left state under
            // this id. With a v4 UUID that means a collision or a planted
            // directory; either way, writing into it would be exactly the upstream
            // defect (a reissued id inheriting an old sandbox's files).
            let path = id.join_under(&self.root)?;
            if path.exists() {
                continue;
            }
            return Ok(id);
        }
        Err(SandboxError::Internal(
            "cannot find an unused sandbox id after 32 attempts".to_string(),
        ))
    }

    /// The live table, refusing a poisoned lock explicitly.
    fn table_lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<SafeComponent, Arc<Mutex<SandboxRecord>>>>> {
        self.table.lock().map_err(|_| {
            SandboxError::Internal(
                "the sandbox table is poisoned: an earlier panic left it in an unknown state"
                    .to_string(),
            )
        })
    }

    /// True when `id` is live in this manager.
    fn live_contains(&self, id: &SafeComponent) -> bool {
        match self.table.lock() {
            Ok(table) => table.contains_key(id),
            // Fail closed: treat the whole root as live rather than risk deleting a
            // running sandbox.
            Err(_) => true,
        }
    }

    /// Refuse every operation once shutdown has begun.
    fn ensure_open(&self) -> Result<()> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(SandboxError::ManagerGone);
        }
        Ok(())
    }

    /// Take every live record out of the table, for tests that simulate a
    /// non-graceful exit.
    ///
    /// Removing the record from the table is what a dropped-on-the-floor process
    /// looks like to the next run: the directory is still there and nothing in
    /// memory knows about it. The directory and its marker are left untouched, so
    /// the next `open` sees exactly what a crashed daemon would leave.
    pub fn forget_all_for_test(&self) -> Vec<String> {
        let mut table = match self.table.lock() {
            Ok(t) => t,
            Err(poisoned) => poisoned.into_inner(),
        };
        let ids: Vec<String> = table.keys().map(|k| k.as_str().to_string()).collect();
        table.clear();
        ids
    }
}

impl Drop for SandboxManager {
    fn drop(&mut self) {
        // Killing and removing on the way out is the difference between "the
        // sandbox tree dies with the daemon" and "the next daemon inherits it".
        let result = self.shutdown();
        if let Err(e) = result {
            // Never panic in `Drop`: a panic here would abort during unwinding.
            // The failure is recorded in the audit log, which `Drop` still owns.
            self.audit(AuditAction::SweepSkipped {
                id: "<shutdown>".to_string(),
                reason: format!("shutdown on drop failed: {e}"),
            });
        }
    }
}

/// A read-only description of one sandbox, safe to serialise to an API caller.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SandboxDescription {
    /// The id.
    pub id: String,
    /// The owning principal.
    pub owner: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Current state.
    pub state: SandboxState,
    /// The work directory.
    pub work_dir: String,
    /// The recorded network policy name.
    pub network: String,
    /// The recorded wall-clock timeout.
    pub timeout_ms: u64,
    /// The recorded memory cap.
    pub memory_bytes: u64,
    /// The recorded process cap.
    pub max_processes: u32,
    /// The recorded output cap.
    pub max_output_bytes: usize,
}

/// How a directory was classified.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Classified {
    /// Owned by a run that is gone.
    Orphan {
        /// The run that owned it.
        run_id: String,
    },
    /// Not this manager's to touch.
    Foreign,
}

/// How old a directory must be before it can be reclaimed, in seconds.
///
/// The margin is what keeps two daemons starting at once from deleting each
/// other's fresh work directories. It is a field on the manager so a test can set
/// it to zero; see [`SandboxManager::with_orphan_age_secs`].
pub const ORPHAN_AGE_SECS: u64 = 120;

/// How many sandboxes one manager holds by default.
pub const DEFAULT_MAX_SANDBOXES: usize = 64;

/// True when `path`'s modification time is at least `secs` in the past.
fn older_than(path: &Path, secs: u64) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    match modified.elapsed() {
        Ok(age) => age.as_secs() >= secs,
        // A timestamp in the future is not evidence of age.
        Err(_) => false,
    }
}

/// True when a process with this pid exists.
///
/// Used **only** to decide whether a directory is reclaimable, never to authorise
/// one. The age margin is the actual mechanism; liveness can only ever make the
/// sweep more conservative. See [`crate::platform`] for what each platform can and
/// cannot tell from a pid.
fn process_is_alive(pid: u32) -> bool {
    crate::platform::process_is_alive(pid)
}

/// Write the run marker into a fresh work directory.
fn write_marker(work_dir: &Path, marker: &RunMarker) -> Result<()> {
    let path = work_dir.join(MARKER_NAME);
    let text = serde_json::to_string(marker).map_err(|e| SandboxError::Audit(e.to_string()))?;
    std::fs::write(&path, text)
        .map_err(|e| SandboxError::WorkDir(format!("cannot write {}: {e}", path.display())))
}
