//! The executor port, the `NullExecutor` default, and the real process backend.
//!
//! # The default runs nothing
//!
//! Upstream v2.8.2 fix: the sandbox's boundaries existed in documentation and in
//! unit tests while the execution path was `Command::new("bash")` with no
//! isolation primitive anywhere in the repository. The honest baseline is that
//! nothing runs, so [`NullExecutor`] is the default and
//! [`SandboxExecutor::create`] on it returns a typed "execution disabled" error.
//! A caller that wants execution must name a backend that declares what it
//! enforces, and must satisfy every boundary the request implies.
//!
//! # The port is stateless
//!
//! [`SandboxExecutor`] holds no per-sandbox state: it creates a directory, runs
//! one program in it, and removes it. A process is spawned and reaped inside one
//! [`SandboxExecutor::exec`] call, so there is no table that a restart can lose
//! and no lock that can be held across a child's lifetime. Everything durable —
//! identity, ownership, directories, the live table — belongs to
//! [`crate::SandboxManager`], and the backend is the platform edge.
//!
//! This mirrors the `Transport` port in `nau-net`: one trait, one real
//! implementation, one in-memory double.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::capability::{BoundaryRequest, Capabilities, UnenforcedCapability};
use crate::component::SafeComponent;
use crate::error::{Result, SandboxError};
use crate::process::{ExecOutcome, ExecRequest};
use crate::spec::SandboxSpec;

/// A handle to one sandbox work directory.
///
/// Holding it means the directory exists. It carries the id as a
/// [`SafeComponent`], so no later step can join an unvalidated string onto a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxHandle {
    /// The validated identifier.
    pub id: SafeComponent,
    /// The sandbox's own directory.
    pub work_dir: PathBuf,
}

/// What a backend can do, and how to run one program.
///
/// Object-safe on purpose: `Arc<dyn SandboxExecutor>` is how the daemon holds one.
pub trait SandboxExecutor: Send + Sync {
    /// The boundaries this backend enforces, and why for each it does not.
    fn capabilities(&self) -> &Capabilities;

    /// Refuse a spec the backend cannot serve.
    ///
    /// The default implementation is the correct one for every backend: it
    /// validates the spec, derives the boundary requests, and requires each against
    /// [`SandboxExecutor::capabilities`]. A backend that overrode this to relax it
    /// would be reintroducing the defect this crate removes, which is why the
    /// method has a body rather than being required.
    fn validate(&self, spec: &SandboxSpec) -> Result<()> {
        spec.validate()?;
        for request in spec.boundary_requests() {
            request.apply(self.capabilities())?;
        }
        for request in spec.waivers.requests() {
            request.apply(self.capabilities())?;
        }
        Ok(())
    }

    /// Refuse a set of boundary requests the backend cannot satisfy.
    fn require_boundaries(&self, requests: &[BoundaryRequest]) -> Result<()> {
        crate::capability::check_boundary(self.capabilities(), requests)
    }

    /// Create the working directory for `id` under `root` and return a handle.
    ///
    /// The default implementation validates the spec first, then joins the id —
    /// already a [`SafeComponent`] — under the root, re-checking the canonical
    /// result. A backend that needs a different layout overrides it, but the
    /// re-check is not optional.
    fn create(&self, root: &Path, id: &SafeComponent, spec: &SandboxSpec) -> Result<SandboxHandle> {
        self.validate(spec)?;
        create_work_dir(root, id)
    }

    /// Run one request inside a sandbox and return everything it produced.
    ///
    /// The process is spawned and reaped within this call.
    fn exec(
        &self,
        handle: &SandboxHandle,
        spec: &SandboxSpec,
        request: &ExecRequest,
    ) -> Result<ExecOutcome>;

    /// Backend-specific teardown for one sandbox. Runs before the manager removes
    /// the directory.
    ///
    /// The default does nothing, which is correct for a backend that keeps no
    /// state between calls.
    fn destroy(&self, _handle: &SandboxHandle) -> Result<()> {
        Ok(())
    }

    /// Backend-specific teardown for the whole process. The manager removes every
    /// directory it knows about; this hook exists for state the backend owns.
    fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    /// The backend's name, as it appears in refusals and the audit log.
    fn name(&self) -> &str {
        self.capabilities().backend()
    }
}

/// Create `root/id`, re-checking that the result is one component under `root`.
///
/// Shared by the trait default and by the real backend.
pub(crate) fn create_work_dir(root: &Path, id: &SafeComponent) -> Result<SandboxHandle> {
    std::fs::create_dir_all(root)
        .map_err(|e| SandboxError::WorkDir(format!("cannot create {}: {e}", root.display())))?;
    let work_dir = id.join_under(root)?;
    std::fs::create_dir_all(&work_dir)
        .map_err(|e| SandboxError::WorkDir(format!("cannot create {}: {e}", work_dir.display())))?;
    Ok(SandboxHandle {
        id: id.clone(),
        work_dir,
    })
}

/// The default backend: it executes nothing.
///
/// Every creating or executing call returns
/// [`SandboxError::ExecutionDisabled`]. This is deliberate and is the crate's
/// stated baseline: a deployment that wants execution must select a backend, and
/// in selecting one it must read that backend's capability declaration. The
/// declaration here claims nothing, so even a caller that ignored the blanket
/// refusal would be refused again, by name, for every boundary.
#[derive(Debug, Clone)]
pub struct NullExecutor {
    capabilities: Capabilities,
}

impl Default for NullExecutor {
    /// Deliberately not `derive`d: the interesting default here is the *refusal*,
    /// and a derived default would imply that "a sandbox with no backend" is a
    /// usable configuration rather than the crate's honest baseline.
    fn default() -> Self {
        Self::new()
    }
}

impl NullExecutor {
    /// Build the null backend with a declaration that claims nothing.
    ///
    /// Every capability is listed as unenforced, not just one, so that a boundary
    /// request against this backend is refused with the *backend's* reason rather
    /// than the generic "publishes no enforcement". Both are refusals; the point is
    /// that the reason names the backend.
    pub fn new() -> Self {
        Self {
            capabilities: Capabilities::from_parts(
                "null-executor",
                Vec::new(),
                crate::Capability::ALL
                    .iter()
                    .map(|cap| UnenforcedCapability {
                        boundary: *cap,
                        reason: "the null backend executes nothing, so it enforces nothing"
                            .to_string(),
                    })
                    .collect(),
            ),
        }
    }
}

impl SandboxExecutor for NullExecutor {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn create(
        &self,
        _root: &Path,
        _id: &SafeComponent,
        _spec: &SandboxSpec,
    ) -> Result<SandboxHandle> {
        Err(SandboxError::ExecutionDisabled(
            "the default backend is `NullExecutor`, which executes nothing; select a backend that \
             declares the boundaries it enforces"
                .to_string(),
        ))
    }

    fn exec(
        &self,
        _handle: &SandboxHandle,
        _spec: &SandboxSpec,
        _request: &ExecRequest,
    ) -> Result<ExecOutcome> {
        Err(SandboxError::ExecutionDisabled(
            "no execution backend is configured".to_string(),
        ))
    }
}

/// The real backend: [`crate::platform`] plus the parent-side limits.
///
/// # Declaration, and what it costs
///
/// On Windows this backend enforces: environment allowlist, output cap, timeout
/// with whole-tree kill, work-directory isolation, memory limit, and
/// process-count limit. It **cannot** deny egress, cannot confine the filesystem,
/// cannot cap disk usage, cannot cap CPU time (a job object's user-time limit
/// needs a monitoring loop, and reporting a limit that is only noticed after the
/// fact would be exactly the drift this crate removes), and cannot cap open
/// handles. Those five are declared unenforced with reasons, and a request that
/// needs one is refused naming it.
///
/// On Unix the same backend adds CPU time, open-file and process-count caps
/// through `setrlimit` in the child, and still cannot deny egress or confine the
/// filesystem. **That path is not verified on this machine.**
pub struct RealProcessExecutor {
    capabilities: Capabilities,
}

impl RealProcessExecutor {
    /// Build the backend for this platform.
    pub fn new() -> Self {
        Self {
            capabilities: platform_capabilities(),
        }
    }

    /// Build the backend with an explicit declaration.
    ///
    /// Exists so a test can ask "what happens when a backend claims less than this
    /// one could?" without editing the platform table. It changes no behaviour:
    /// the enforcement is whatever `crate::process` and `crate::platform` do, and
    /// the declaration only decides which requests are refused.
    pub fn with_capabilities(capabilities: Capabilities) -> Self {
        Self { capabilities }
    }
}

impl Default for RealProcessExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// The capability table for this platform.
///
/// Written as data, once, next to the code that implements it, so that the
/// declaration and the implementation cannot drift without the test that walks
/// every capability noticing.
fn platform_capabilities() -> Capabilities {
    use crate::Capability;
    let mut enforced = vec![
        Capability::EnvAllowlist,
        Capability::OutputCap,
        Capability::Timeout,
        Capability::WorkDirIsolation,
        Capability::MemoryLimit,
        Capability::ProcessCountLimit,
    ];
    let mut unenforced = vec![
        UnenforcedCapability {
            boundary: Capability::NetworkDenyAll,
            reason: "no egress filter is available to a plain child process on this platform; use \
                     a backend with a network namespace, or ask for `NetworkPolicy::Unrestricted` \
                     with a justification, which is recorded in the audit log"
                .to_string(),
        },
        UnenforcedCapability {
            boundary: Capability::NetworkAllowList,
            reason: "same as `network_deny_all`: nothing in this backend can restrict a child's \
                     destinations"
                .to_string(),
        },
        UnenforcedCapability {
            boundary: Capability::DiskQuota,
            reason:
                "this backend applies no filesystem quota: on Windows a quota is a volume-level \
                     policy, and on Unix it needs a filesystem with project-quota support"
                    .to_string(),
        },
    ];
    if cfg!(windows) {
        unenforced.push(UnenforcedCapability {
            boundary: Capability::FilesystemConfinement,
            reason: "Windows has no chroot-equivalent for a plain process; AppContainer or a \
                     container runtime would be a different backend"
                .to_string(),
        });
        unenforced.push(UnenforcedCapability {
            boundary: Capability::CpuLimit,
            reason: "a job object has no enforced CPU-time limit for a plain process; the \
                     wall-clock timeout is the enforced bound"
                .to_string(),
        });
        unenforced.push(UnenforcedCapability {
            boundary: Capability::OpenFileLimit,
            reason: "a job object has no open-handle limit: `JOB_OBJECT_LIMIT_*` covers memory, \
                     process count and user time, not handles"
                .to_string(),
        });
    } else {
        enforced.push(Capability::CpuLimit);
        enforced.push(Capability::OpenFileLimit);
        unenforced.push(UnenforcedCapability {
            boundary: Capability::FilesystemConfinement,
            reason:
                "this backend does not call chroot or pivot_root; a mount namespace would be a \
                     different backend"
                    .to_string(),
        });
    }
    Capabilities::from_parts(crate::platform::PLATFORM_BACKEND, enforced, unenforced)
}

impl SandboxExecutor for RealProcessExecutor {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn exec(
        &self,
        handle: &SandboxHandle,
        spec: &SandboxSpec,
        request: &ExecRequest,
    ) -> Result<ExecOutcome> {
        // Re-validate on every execution: a sandbox whose spec changed under it
        // must not keep running on a stale grant.
        self.validate(spec)?;
        if !handle.work_dir.is_dir() {
            return Err(SandboxError::WorkDir(format!(
                "the sandbox directory {} is gone",
                handle.work_dir.display()
            )));
        }
        crate::process::run_in_workdir(spec, &handle.work_dir, request)
    }
}

/// The default backend the daemon uses.
pub type DefaultExecutor = NullExecutor;

/// Wrap any backend in the shared handle the manager and daemon store.
pub fn shared(executor: impl SandboxExecutor + 'static) -> Arc<dyn SandboxExecutor> {
    Arc::new(executor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{
        AbsoluteProgramPath, EnvPolicy, FilesystemPolicy, Interpreter, Limits, NetworkPolicy,
        Waivers,
    };

    fn limits() -> Limits {
        Limits {
            timeout_ms: 1_000,
            memory_bytes: 1 << 20,
            cpu_ms: 1_000,
            disk_bytes: 1 << 20,
            max_processes: 2,
            max_open_files: 8,
            max_output_bytes: 1_024,
        }
    }

    fn binary_spec() -> SandboxSpec {
        SandboxSpec {
            interpreter: Interpreter::Binary(
                AbsoluteProgramPath::new(std::env::current_exe().expect("exe")).expect("absolute"),
            ),
            limits: limits(),
            network: NetworkPolicy::DenyAll,
            filesystem: FilesystemPolicy::confined(),
            env: EnvPolicy::empty(),
            waivers: Waivers::none(),
        }
    }

    /// Upstream v2.8.2 fix: the honest baseline is that nothing runs. The default
    /// backend must refuse to create anything, and must say so in a typed way.
    #[test]
    fn the_default_backend_executes_nothing_and_says_so() {
        let exec = NullExecutor::new();
        let root = std::env::temp_dir().join(format!("nau-null-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let id = SafeComponent::parse("sandbox-id").expect("component");
        let err = exec
            .create(&root, &id, &binary_spec())
            .expect_err("the null backend must refuse");
        assert!(
            matches!(err, SandboxError::ExecutionDisabled(_)),
            "got {err:?}"
        );
        // And it claims no capability, so the boundary check refuses too.
        let err = exec
            .validate(&binary_spec())
            .expect_err("no capability is claimed");
        assert!(
            matches!(err, SandboxError::PolicyNotEnforceable { .. }),
            "got {err:?}"
        );
        // Nothing was created: the refusal is not decorative.
        assert!(!root.join("sandbox-id").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Upstream v2.8.2 fix: a policy field with no enforcement site. Every
    /// capability is exercised against the real backend's declaration: enforced
    /// ones are accepted, unenforced ones are refused **by name**.
    #[test]
    fn the_real_backend_declares_and_then_honours_every_capability() {
        let exec = RealProcessExecutor::new();
        let caps = exec.capabilities();
        for cap in crate::Capability::ALL {
            let request = [BoundaryRequest::Required(cap)];
            let outcome = exec.require_boundaries(&request);
            if caps.enforces(cap) {
                assert!(outcome.is_ok(), "{cap} is declared enforced: {outcome:?}");
            } else {
                let err = outcome.expect_err("a declared-unenforced boundary must be refused");
                match err {
                    SandboxError::PolicyNotEnforceable {
                        boundary,
                        ref backend,
                        ref detail,
                    } => {
                        assert_eq!(boundary, cap);
                        assert!(!backend.is_empty());
                        assert!(!detail.is_empty(), "{cap} needs a reason");
                    }
                    other => panic!("{cap} gave {other:?}"),
                }
            }
        }
    }

    /// A default spec asks for egress denial and filesystem confinement, neither of
    /// which the real backend can deliver, so creation must FAIL rather than run
    /// unbounded. This is the single most important test in the crate.
    #[test]
    fn a_spec_asking_for_an_undeniable_boundary_is_refused_not_downgraded() {
        let exec = RealProcessExecutor::new();
        let root = std::env::temp_dir().join(format!("nau-refuse-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&root);
        let id = SafeComponent::parse("sandbox-id").expect("component");
        let err = exec
            .create(&root, &id, &binary_spec())
            .expect_err("deny-all egress is not enforceable here");
        assert!(
            matches!(
                err,
                SandboxError::PolicyNotEnforceable {
                    boundary: crate::Capability::NetworkDenyAll,
                    ..
                }
            ),
            "the refusal must name the boundary: {err:?}"
        );
        // Nothing was created on disk either.
        assert!(!root.join("sandbox-id").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The declared-unenforced boundaries each have a reason and are not also
    /// claimed as enforced.
    #[test]
    fn the_unenforced_set_is_explicit_and_reasoned() {
        let caps = platform_capabilities();
        let unenforced: Vec<crate::Capability> = caps
            .unenforced()
            .iter()
            .map(|entry| entry.boundary)
            .collect();
        assert!(unenforced.contains(&crate::Capability::NetworkDenyAll));
        assert!(unenforced.contains(&crate::Capability::FilesystemConfinement));
        for entry in caps.unenforced() {
            assert!(
                !entry.reason.trim().is_empty(),
                "{} needs a reason",
                entry.boundary
            );
            assert!(!caps.enforces(entry.boundary));
        }
        if cfg!(windows) {
            assert!(unenforced.contains(&crate::Capability::CpuLimit));
            assert!(unenforced.contains(&crate::Capability::OpenFileLimit));
            assert!(unenforced.contains(&crate::Capability::DiskQuota));
        } else {
            assert!(caps.enforces(crate::Capability::CpuLimit));
            assert!(caps.enforces(crate::Capability::OpenFileLimit));
        }
    }
}
