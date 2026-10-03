//! The isolation port and its backends.
//!
//! # The one rule
//!
//! A runtime **declares what it can enforce**, and a request for anything else is
//! refused **by name**. There is no "best effort" path and no silent downgrade: an
//! isolation claim that quietly became a no-op is the exact defect the V1.2.3 audit
//! found in upstream's sandbox, where `NetworkGuard::check_egress` and
//! `PermissionChecker::check` existed, were unit-tested, and had **zero production
//! callers**.
//!
//! # The three backends, and what is actually true about each
//!
//! | Backend | Used for | Enforced here | Not enforced here |
//! |---|---|---|---|
//! | [`NativeRuntime`] | T0 system plugins only | nothing — it is the host's own address space | everything isolation-shaped |
//! | [`ProcessRuntime`] | T1/T2/T3 | memory, process count, wall clock, output cap, work-dir isolation, environment allowlist | network denial, filesystem confinement, disk quota, CPU time |
//! | [`WasmRuntime`] | nothing in this build | — | everything: it refuses to start |
//!
//! # The honest part
//!
//! `ProcessRuntime` reaches the *same* boundary set the V1.2.3 sandbox does, because
//! it **is** that sandbox. On Windows a Job Object enforces memory and process count
//! and kills the whole tree; on any platform there is no primitive for denying
//! egress to a plain child process, no disk quota and no CPU-time cap. So a plugin
//! that needs those boundaries **must waive them explicitly, with a written reason**,
//! and that waiver is what the runtime records. Without the waiver the start is
//! refused with [`LoadRefusal::IsolationNotEnforceable`].
//!
//! This is why "a third-party plugin has no network access" is a statement about the
//! **bus**, not about the network: the tier holds no `net:*` capability, so no message
//! it sends may be routed — but a child process can always open a socket, and saying
//! otherwise would be the kind of claim this project exists to refuse.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{LoadRefusal, PluginError, Result};
use crate::manifest::Limits;
use crate::tier::{PluginId, Tier};

/// Which runtime backs a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    /// In the host's address space. T0 only.
    Native,
    /// In a separate OS process with enforced limits.
    Process,
    /// In a WASM instance. Not present in this build.
    Wasm,
    /// In a microVM (Firecracker-class hypervisor isolation).
    ///
    /// Declared so a manifest can ask for it and be **refused with a reason**; no
    /// backend exists in this build. See [`RuntimeKind::unavailability`].
    MicroVm,
    /// In a full virtual machine, able to run a complete operating system.
    ///
    /// Declared for the same reason as [`RuntimeKind::MicroVm`]: the vocabulary comes
    /// before the implementation, so that asking for it fails loudly instead of
    /// silently selecting something weaker.
    FullVm,
}

impl RuntimeKind {
    /// Every kind.
    ///
    /// Exhaustive: adding a variant breaks this array and the label-uniqueness test,
    /// so a new runtime cannot be introduced without naming it.
    pub const ALL: [RuntimeKind; 5] = [
        RuntimeKind::Native,
        RuntimeKind::Process,
        RuntimeKind::Wasm,
        RuntimeKind::MicroVm,
        RuntimeKind::FullVm,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            RuntimeKind::Native => "native",
            RuntimeKind::Process => "process",
            RuntimeKind::Wasm => "wasm",
            RuntimeKind::MicroVm => "micro_vm",
            RuntimeKind::FullVm => "full_vm",
        }
    }

    /// Why this runtime cannot be used here, or `None` when it can.
    ///
    /// The reason is part of the API rather than an internal detail: a manifest that
    /// asks for a runtime this build lacks must be refused **with the reason**, because
    /// silently running it on a weaker runtime would make the manifest's isolation
    /// claim false. `MicroVm` and `FullVm` are Linux-only by construction — they need a
    /// hypervisor — so on Windows and macOS they can never be available, and saying so
    /// is the whole point of declaring them.
    #[must_use]
    pub fn unavailability(self) -> Option<&'static str> {
        match self {
            RuntimeKind::Native | RuntimeKind::Process => None,
            RuntimeKind::Wasm => Some(
                "the WASM runtime is an optional feature that is not present in this build; \
                 asking for it is refused rather than downgraded",
            ),
            RuntimeKind::MicroVm => Some(
                "MicroVm needs a hypervisor (Firecracker-class, KVM on Linux) and no backend \
                 exists in this build; it is Linux-only by construction, so on Windows and \
                 macOS it is never available and is refused with this reason",
            ),
            RuntimeKind::FullVm => Some(
                "FullVm needs a hypervisor able to boot a complete operating system and no \
                 backend exists in this build; it is Linux-only by construction, so on Windows \
                 and macOS it is never available and is refused with this reason",
            ),
        }
    }

    /// Whether this build contains the runtime at all.
    #[must_use]
    pub fn is_available(self) -> bool {
        self.unavailability().is_none()
    }
}

/// A boundary a runtime may or may not be able to enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    /// A wall-clock deadline for one call.
    Timeout,
    /// A memory ceiling.
    Memory,
    /// A cap on processes in the plugin's tree.
    ProcessCount,
    /// A cap on retained stdout/stderr.
    OutputCap,
    /// A cap on bytes written to the plugin's directory.
    DiskQuota,
    /// A cap on CPU time.
    CpuLimit,
    /// A cap on open handles.
    OpenFileLimit,
    /// Refusing outbound network access.
    NetworkDeny,
    /// Confining filesystem access to the plugin's directory.
    FilesystemConfinement,
    /// Constructing the environment from an allowlist rather than inheriting it.
    EnvAllowlist,
    /// Giving the plugin a working directory of its own.
    WorkDirIsolation,
    /// A page cache shared with other instances on this host, mapped **read-only**.
    ///
    /// Separate from [`Boundary::Memory`] on purpose. Memory says "how much"; this says
    /// "shared, and the sharing is only safe because a writer cannot exist". A host that
    /// maps one page into several tenants and lets any of them write it has not saved
    /// memory, it has created a cross-tenant write primitive — so a runtime that cannot
    /// prove the read-only mapping must say so rather than accept the optimisation.
    PmemSharedReadOnly,
    /// Filtering the ioctl set a sandbox may reach.
    ///
    /// Some ioctls move data between files by block address rather than by path, so a
    /// permission check on the path never sees them. `XFS_IOC_SWAPEXT` is the concrete
    /// case: it exchanges two files' extents, which is how a sandboxed process can read
    /// a file it was never granted access to.
    IoctlFilter,
    /// An **allowlist** for outbound traffic, as opposed to [`Boundary::NetworkDeny`].
    ///
    /// Deny is all-or-nothing. An allowlist is the weaker-sounding but stricter-typed
    /// claim: "may reach exactly these host/port/protocol triples" is checkable, while
    /// "has network access" is not.
    NetworkEgressAllowlist,
    /// Which scheduling class the plugin's CPU time is accounted to.
    ///
    /// Two classes are defined: latency-sensitive, which is guaranteed service, and
    /// latency-tolerant, which runs on what is left. The inverse — every plugin equally
    /// important — is what makes a tail-latency claim unmeasurable.
    PriorityClass,
}

impl Boundary {
    /// Every boundary.
    ///
    /// Exhaustive: adding a variant breaks this array and the totality test, so a new
    /// boundary cannot be introduced without declaring who enforces it.
    pub const ALL: [Boundary; 15] = [
        Boundary::Timeout,
        Boundary::Memory,
        Boundary::ProcessCount,
        Boundary::OutputCap,
        Boundary::DiskQuota,
        Boundary::CpuLimit,
        Boundary::OpenFileLimit,
        Boundary::NetworkDeny,
        Boundary::FilesystemConfinement,
        Boundary::EnvAllowlist,
        Boundary::WorkDirIsolation,
        Boundary::PmemSharedReadOnly,
        Boundary::IoctlFilter,
        Boundary::NetworkEgressAllowlist,
        Boundary::PriorityClass,
    ];

    /// The key a manifest uses to waive this boundary.
    #[must_use]
    pub fn waiver_key(self) -> &'static str {
        match self {
            Boundary::Timeout => "timeout",
            Boundary::Memory => "memory",
            Boundary::ProcessCount => "process_count",
            Boundary::OutputCap => "output_cap",
            Boundary::DiskQuota => "disk_bytes",
            Boundary::CpuLimit => "cpu_ms",
            Boundary::OpenFileLimit => "max_open_files",
            Boundary::NetworkDeny => "network",
            Boundary::FilesystemConfinement => "filesystem_confinement",
            Boundary::EnvAllowlist => "env_allowlist",
            Boundary::WorkDirIsolation => "work_dir_isolation",
            Boundary::PmemSharedReadOnly => "pmem_shared_read_only",
            Boundary::IoctlFilter => "ioctl_filter",
            Boundary::NetworkEgressAllowlist => "network_egress_allowlist",
            Boundary::PriorityClass => "priority_class",
        }
    }

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Boundary::Timeout => "timeout",
            Boundary::Memory => "memory",
            Boundary::ProcessCount => "process_count",
            Boundary::OutputCap => "output_cap",
            Boundary::DiskQuota => "disk_quota",
            Boundary::CpuLimit => "cpu_limit",
            Boundary::OpenFileLimit => "open_file_limit",
            Boundary::NetworkDeny => "network_deny",
            Boundary::FilesystemConfinement => "filesystem_confinement",
            Boundary::EnvAllowlist => "env_allowlist",
            Boundary::WorkDirIsolation => "work_dir_isolation",
            Boundary::PmemSharedReadOnly => "pmem_shared_read_only",
            Boundary::IoctlFilter => "ioctl_filter",
            Boundary::NetworkEgressAllowlist => "network_egress_allowlist",
            Boundary::PriorityClass => "priority_class",
        }
    }
}

/// What a runtime can enforce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCapabilities {
    /// Which runtime this describes.
    pub kind: RuntimeKind,
    /// The boundaries it enforces.
    pub enforced: BTreeSet<Boundary>,
    /// Why, for each boundary it does **not** enforce.
    pub unenforced_reasons: BTreeMap<Boundary, String>,
}

impl RuntimeCapabilities {
    /// Whether a boundary is enforced.
    #[must_use]
    pub fn enforces(&self, boundary: Boundary) -> bool {
        self.enforced.contains(&boundary)
    }

    /// The boundaries this runtime cannot enforce, with reasons.
    #[must_use]
    pub fn unenforced(&self) -> Vec<(Boundary, &str)> {
        self.unenforced_reasons
            .iter()
            .map(|(b, why)| (*b, why.as_str()))
            .collect()
    }

    /// Refuse unless every boundary in `needed` is either enforced or waived.
    ///
    /// # Errors
    ///
    /// [`PluginError::Runtime`] whose message begins with
    /// [`LoadRefusal::IsolationNotEnforceable`] and names **every** boundary that is
    /// neither enforced nor waived, together with the reason it cannot be enforced —
    /// so an operator learns the whole list in one refusal instead of one item per
    /// attempt.
    pub fn require(&self, needed: &[Boundary], waivers: &BTreeMap<String, String>) -> Result<()> {
        let mut unhandled: Vec<String> = Vec::new();
        for boundary in needed {
            if self.enforces(*boundary) {
                continue;
            }
            let key = boundary.waiver_key();
            match waivers.get(key) {
                Some(reason) if !reason.trim().is_empty() => {}
                _ => {
                    let why = self
                        .unenforced_reasons
                        .get(boundary)
                        .map(String::as_str)
                        .unwrap_or("this runtime does not enforce it");
                    unhandled.push(format!(
                        "{} ({why}); waive it with `{key}` and a reason if that is acceptable here",
                        boundary.label()
                    ));
                }
            }
        }
        if unhandled.is_empty() {
            return Ok(());
        }
        Err(PluginError::Runtime(format!(
            "{}: {} cannot enforce: {}",
            LoadRefusal::IsolationNotEnforceable.code(),
            self.kind.label(),
            unhandled.join("; ")
        )))
    }
}

/// What the host asks a runtime to start.
#[derive(Debug, Clone)]
pub struct StartSpec {
    /// The plugin's id.
    pub plugin: PluginId,
    /// Its tier. Decides which runtime may run it at all.
    pub tier: Tier,
    /// Absolute path to the entry artefact.
    pub entry: PathBuf,
    /// The limits the manifest asked for.
    pub limits: Limits,
    /// Boundaries the plugin waived, keyed by [`Boundary::waiver_key`].
    pub waivers: BTreeMap<String, String>,
}

/// A started plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginInstance {
    /// Which runtime started it.
    pub kind: RuntimeKind,
    /// The plugin.
    pub plugin: String,
    /// The handle the runtime needs to address it.
    pub handle: String,
}

/// The port every isolation backend implements.
pub trait PluginRuntime: Send + Sync + std::fmt::Debug {
    /// Which runtime this is.
    fn kind(&self) -> RuntimeKind;
    /// What it can enforce.
    fn declares(&self) -> &RuntimeCapabilities;
    /// Start a plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::Runtime`] when the tier may not run here, when a needed
    /// boundary is neither enforced nor waived, or when the process will not start.
    fn start(&self, spec: &StartSpec) -> Result<PluginInstance>;
    /// Run one call.
    ///
    /// # Errors
    ///
    /// [`PluginError::Runtime`] when the plugin fails, times out, or exceeds a limit.
    fn call(&self, instance: &PluginInstance, request: &[u8]) -> Result<Vec<u8>>;
    /// Stop and release.
    ///
    /// # Errors
    ///
    /// [`PluginError::Runtime`] when the instance cannot be torn down.
    fn stop(&self, instance: &PluginInstance) -> Result<()>;
}

/// The boundaries the process runtime can enforce, and the reasons for the rest.
fn process_capabilities() -> RuntimeCapabilities {
    let enforced: BTreeSet<Boundary> = [
        Boundary::Timeout,
        Boundary::Memory,
        Boundary::ProcessCount,
        Boundary::OutputCap,
        Boundary::EnvAllowlist,
        Boundary::WorkDirIsolation,
    ]
    .into_iter()
    .collect();
    let mut unenforced_reasons = BTreeMap::new();
    unenforced_reasons.insert(
        Boundary::NetworkDeny,
        "neither a Win32 Job Object nor a plain Unix child has an egress primitive; the bus \
         refuses `net:*` capabilities, but a child process can still open a socket"
            .to_string(),
    );
    unenforced_reasons.insert(
        Boundary::FilesystemConfinement,
        "no chroot on Unix without privileges and no AppContainer on Windows".to_string(),
    );
    unenforced_reasons.insert(
        Boundary::DiskQuota,
        "no volume policy or project quota primitive is reachable from here".to_string(),
    );
    unenforced_reasons.insert(
        Boundary::CpuLimit,
        "CPU time is only capped by `setrlimit` on Unix, which is not verified on this machine"
            .to_string(),
    );
    unenforced_reasons.insert(
        Boundary::OpenFileLimit,
        "handle caps are only enforced by `setrlimit` on Unix, not on Windows".to_string(),
    );
    unenforced_reasons.insert(
        Boundary::PmemSharedReadOnly,
        "the process runtime shares no page cache between instances: each plugin gets its own \
         process and its own private pages, so there is nothing to map read-only and nothing to \
         protect from a writing neighbour"
            .to_string(),
    );
    unenforced_reasons.insert(
        Boundary::IoctlFilter,
        "filtering ioctls needs `seccomp` on Linux or an equivalent filter on Windows, and \
         neither a Win32 Job Object nor a plain Unix child provides one; a path-based permission \
         check does not see an ioctl that moves data by block address"
            .to_string(),
    );
    unenforced_reasons.insert(
        Boundary::NetworkEgressAllowlist,
        "an allowlist is a refinement of `network`, and the process runtime has no egress \
         primitive at all — so it can enforce neither the deny nor the allowlist form"
            .to_string(),
    );
    unenforced_reasons.insert(
        Boundary::PriorityClass,
        "children start at the host's default scheduling priority; this build has no scheduler \
         integration, so a latency-sensitive claim cannot be made about a process plugin here"
            .to_string(),
    );
    debug_assert_eq!(
        enforced.len() + unenforced_reasons.len(),
        Boundary::ALL.len(),
        "every boundary must be either enforced or reasoned about"
    );
    RuntimeCapabilities {
        kind: RuntimeKind::Process,
        enforced,
        unenforced_reasons,
    }
}

/// Runs T0 plugins in the host's own address space.
///
/// # Why this exists at all
///
/// System plugins are part of the kernel: they are compiled in, they are not
/// downloaded, and they cannot be hot-plugged. Putting them behind a process
/// boundary would be theatre — the host already trusts them with its own memory — and
/// it would add a serialisation hop to the hot path. What matters is that the
/// *refusal* is real: this runtime refuses every tier except `System`, so a
/// third-party plugin cannot reach it by asking.
#[derive(Debug)]
pub struct NativeRuntime {
    capabilities: RuntimeCapabilities,
}

impl Default for NativeRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeRuntime {
    /// A native runtime.
    #[must_use]
    pub fn new() -> Self {
        let mut unenforced_reasons = BTreeMap::new();
        for boundary in Boundary::ALL {
            unenforced_reasons.insert(
                boundary,
                "the native runtime runs in the host's address space, so it enforces nothing"
                    .to_string(),
            );
        }
        Self {
            capabilities: RuntimeCapabilities {
                kind: RuntimeKind::Native,
                enforced: BTreeSet::new(),
                unenforced_reasons,
            },
        }
    }

    /// The boundaries a native plugin is not asked to waive.
    ///
    /// A T0 plugin is not a guest: it is part of the kernel and the limits in its
    /// manifest are documentation. The set is empty because there is nothing to
    /// waive — the refusal that matters is the tier check below, not a boundary list.
    #[must_use]
    pub fn required_boundaries() -> &'static [Boundary] {
        &[]
    }
}

impl PluginRuntime for NativeRuntime {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Native
    }

    fn declares(&self) -> &RuntimeCapabilities {
        &self.capabilities
    }

    fn start(&self, spec: &StartSpec) -> Result<PluginInstance> {
        if spec.tier != Tier::System {
            return Err(PluginError::Runtime(format!(
                "{}: the native runtime runs system plugins only; `{}` is {} and must run in an \
                 isolated process",
                LoadRefusal::IsolationNotEnforceable.code(),
                spec.plugin,
                spec.tier
            )));
        }
        Ok(PluginInstance {
            kind: RuntimeKind::Native,
            plugin: spec.plugin.as_str().to_string(),
            handle: format!("native:{}", spec.plugin),
        })
    }

    fn call(&self, instance: &PluginInstance, _request: &[u8]) -> Result<Vec<u8>> {
        // A native plugin is linked into the host, so a "call" through this port is a
        // dispatch the host performs itself; reaching here means the wiring is wrong,
        // and saying so is better than returning an empty success.
        Err(PluginError::Runtime(format!(
            "`{}` is a native plugin: it is called in-process by the host and must not be \
             dispatched through the runtime port",
            instance.plugin
        )))
    }

    fn stop(&self, _instance: &PluginInstance) -> Result<()> {
        // Nothing to release: the instance is a value in the host.
        Ok(())
    }
}

/// Runs T1/T2/T3 plugins in a separate process with enforced limits.
///
/// The enforcement is `nau-sandbox`'s, which is the point: the isolation this runtime
/// claims for untrusted code is the isolation that already has tests, a Job Object on
/// Windows, an orphan sweep, and a startup reclaim.
#[derive(Debug)]
pub struct ProcessRuntime {
    capabilities: RuntimeCapabilities,
}

impl ProcessRuntime {
    /// A process runtime.
    #[must_use]
    pub fn new() -> Self {
        Self {
            capabilities: process_capabilities(),
        }
    }

    /// The boundaries a plugin must either have enforced or explicitly waive.
    ///
    /// This is what the arbiter consults to build its refusal message, so the list and
    /// the runtime cannot disagree.
    #[must_use]
    pub fn required_boundaries() -> Vec<Boundary> {
        let caps = process_capabilities();
        let mut needed: Vec<Boundary> = Boundary::ALL
            .into_iter()
            .filter(|b| !caps.enforces(*b))
            .collect();
        needed.extend(caps.enforced.iter().copied());
        needed
    }
}

impl Default for ProcessRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRuntime for ProcessRuntime {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Process
    }

    fn declares(&self) -> &RuntimeCapabilities {
        &self.capabilities
    }

    fn start(&self, spec: &StartSpec) -> Result<PluginInstance> {
        // The tier gate first: a system plugin in a separate process would not be part
        // of the kernel any more, and that is a structural decision, not a limit.
        if spec.tier == Tier::System {
            return Err(PluginError::Runtime(format!(
                "`{}` is a system plugin and must run natively, not behind a process boundary",
                spec.plugin
            )));
        }
        if spec.tier == Tier::Blacklisted {
            return Err(PluginError::Blacklist(format!(
                "{}: `{}` is quarantined and cannot be started on any runtime",
                LoadRefusal::Blacklisted.code(),
                spec.plugin
            )));
        }
        // Every boundary this runtime cannot enforce must be waived with a reason.
        let needed: Vec<Boundary> = Boundary::ALL
            .into_iter()
            .filter(|b| !self.capabilities.enforces(*b))
            .collect();
        self.capabilities.require(&needed, &spec.waivers)?;

        if !spec.entry.is_absolute() {
            return Err(PluginError::Runtime(format!(
                "the entry path for `{}` must be absolute; got {}",
                spec.plugin,
                spec.entry.display()
            )));
        }
        if !spec.entry.exists() {
            return Err(PluginError::Runtime(format!(
                "the entry artefact for `{}` does not exist: {}",
                spec.plugin,
                spec.entry.display()
            )));
        }

        // The concrete launch is the sandbox's; this runtime contributes the mapping
        // from a plugin's declared limits and waivers onto the sandbox's spec.
        Ok(PluginInstance {
            kind: RuntimeKind::Process,
            plugin: spec.plugin.as_str().to_string(),
            handle: format!(
                "process:{}:mem={}:procs={}:timeout={}ms",
                spec.plugin,
                spec.limits.memory_bytes,
                spec.limits.max_processes,
                spec.limits.cpu_ms
            ),
        })
    }

    fn call(&self, instance: &PluginInstance, _request: &[u8]) -> Result<Vec<u8>> {
        // The host owns the sandbox manager (it holds the data directory and the
        // executor), so the actual exec is performed by `nau-node` against the
        // instance handle this returned. What belongs here is the invariant, and it
        // is asserted rather than assumed.
        if instance.kind != RuntimeKind::Process {
            return Err(PluginError::Runtime(format!(
                "`{}` was not started by the process runtime",
                instance.plugin
            )));
        }
        Err(PluginError::Runtime(format!(
            "the process runtime's exec is performed by the host against handle `{}`; calling the \
             port directly is a wiring error, not a plugin failure",
            instance.handle
        )))
    }

    fn stop(&self, instance: &PluginInstance) -> Result<()> {
        if instance.kind != RuntimeKind::Process {
            return Err(PluginError::Runtime(format!(
                "`{}` was not started by the process runtime",
                instance.plugin
            )));
        }
        Ok(())
    }
}

/// The WASM runtime this build does not contain.
///
/// # Why a type rather than a comment
///
/// The draft architecture made Wasmtime the standard plugin format. This build has
/// no WASM runtime: the dependency is not in `Cargo.lock`, not in the local registry
/// cache, and a tree that heavy cannot be introduced and *verified* in this
/// environment — and something introduced but not verified is exactly what this
/// project refuses to ship.
///
/// So the port is here, it declares that it enforces nothing, and it **refuses to
/// start anything**. A manifest asking for `wasm` gets a typed refusal naming the
/// reason, instead of being quietly run in the process backend while the
/// documentation still says "WASM sandbox". The refusal is the feature: it is what
/// makes the eventual Wasmtime implementation a drop-in rather than a rewrite.
#[derive(Debug)]
pub struct WasmRuntime {
    capabilities: RuntimeCapabilities,
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmRuntime {
    /// The WASM runtime placeholder.
    #[must_use]
    pub fn new() -> Self {
        let mut unenforced_reasons = BTreeMap::new();
        for boundary in Boundary::ALL {
            unenforced_reasons.insert(
                boundary,
                "this build contains no WASM runtime, so it enforces nothing at all".to_string(),
            );
        }
        Self {
            capabilities: RuntimeCapabilities {
                kind: RuntimeKind::Wasm,
                enforced: BTreeSet::new(),
                unenforced_reasons,
            },
        }
    }
}

impl PluginRuntime for WasmRuntime {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Wasm
    }

    fn declares(&self) -> &RuntimeCapabilities {
        &self.capabilities
    }

    fn start(&self, spec: &StartSpec) -> Result<PluginInstance> {
        Err(PluginError::Runtime(format!(
            "{}: this build has no WASM runtime, so `{}` cannot be started as a WASM plugin; the \
             process runtime is the only isolation backend available, and V3.0.0 adds the WASM \
             backend behind this same port",
            LoadRefusal::IsolationNotEnforceable.code(),
            spec.plugin
        )))
    }

    fn call(&self, _instance: &PluginInstance, _request: &[u8]) -> Result<Vec<u8>> {
        Err(PluginError::Runtime(
            "no instance can exist: this build has no WASM runtime".into(),
        ))
    }

    fn stop(&self, _instance: &PluginInstance) -> Result<()> {
        Err(PluginError::Runtime(
            "no instance can exist: this build has no WASM runtime".into(),
        ))
    }
}

/// A runtime chosen by name, for the `NAU_PLUGIN_RUNTIME` environment variable.
///
/// # Errors
///
/// [`PluginError::Runtime`] naming the accepted values, so a typo is loud rather than
/// a silent fallback to a different isolation level — the defect the sandbox work
/// already fixed once for `NAU_SANDBOX_BACKEND`.
pub fn runtime_for(selection: &str) -> Result<Box<dyn PluginRuntime>> {
    match selection.trim().to_ascii_lowercase().as_str() {
        "" | "native" => Ok(Box::new(NativeRuntime::new())),
        "process" => Ok(Box::new(ProcessRuntime::new())),
        "wasm" => Ok(Box::new(WasmRuntime::new())),
        other => Err(PluginError::Runtime(format!(
            "`{other}` is not a runtime; use `native`, `process` or `wasm` (wasm exists so that \
             asking for it produces a typed refusal rather than a silent downgrade)"
        ))),
    }
}

/// The sandbox limits a plugin's declared limits map onto.
///
/// Kept as its own function so the mapping is testable without starting a process,
/// and so the two places that must agree — the limit a plugin declares and the limit
/// the sandbox enforces — cannot drift apart unnoticed.
#[must_use]
pub fn sandbox_limits(limits: &Limits) -> Limits {
    *limits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Limits;

    const NOW: u64 = 1_750_000_000;

    fn limits() -> Limits {
        Limits {
            memory_bytes: 128 * 1024 * 1024,
            cpu_ms: 10_000,
            disk_bytes: 16 * 1024 * 1024,
            max_processes: 4,
            max_output_bytes: 64 * 1024,
        }
    }

    fn spec(tier: Tier) -> StartSpec {
        StartSpec {
            plugin: PluginId::parse(match tier {
                Tier::System => "com.twinsearth.sys.identity",
                Tier::Official => "com.twinsearth.official.market",
                Tier::Certified => "com.twinsearth.certified.analytics",
                _ => "io.example.analytics",
            })
            .expect("id"),
            tier,
            entry: std::env::current_exe().expect("current exe"),
            limits: limits(),
            waivers: BTreeMap::new(),
        }
    }

    fn full_waivers() -> BTreeMap<String, String> {
        Boundary::ALL
            .into_iter()
            .map(|b| {
                (
                    b.waiver_key().to_string(),
                    "test: accepted for this fixture".to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn every_boundary_is_either_enforced_or_reasoned_about() {
        // The declaration must be total: a boundary that is neither is one the
        // refusal message cannot name, which is how a boundary silently stops being
        // enforced.
        //
        // Iterating `RuntimeKind::ALL` rather than a hand-written list is the point. A
        // new runtime kind must be classified here, and `MicroVm`/`FullVm` are
        // classified as *declared but unavailable, with a reason* rather than skipped:
        // the vocabulary exists so a manifest can ask and be refused, so the assertion
        // that matters for them is that the refusal is typed and readable.
        for kind in RuntimeKind::ALL {
            let caps = match kind {
                RuntimeKind::Native => NativeRuntime::new().declares().clone(),
                RuntimeKind::Process => ProcessRuntime::new().declares().clone(),
                RuntimeKind::Wasm => WasmRuntime::new().declares().clone(),
                RuntimeKind::MicroVm | RuntimeKind::FullVm => {
                    assert!(
                        !kind.is_available(),
                        "{kind:?} has no backend in this build and must not report itself \
                         available"
                    );
                    let why = kind.unavailability();
                    assert!(
                        why.is_some_and(|w| w.contains("hypervisor")),
                        "{kind:?} must name the missing hypervisor in its refusal, got {why:?}"
                    );
                    continue;
                }
            };
            for boundary in Boundary::ALL {
                let enforced = caps.enforces(boundary);
                let reasoned = caps.unenforced_reasons.contains_key(&boundary);
                assert!(
                    enforced ^ reasoned,
                    "{kind:?} must either enforce or explain {}",
                    boundary.label()
                );
            }
            assert_eq!(caps.kind, kind);
        }
    }

    #[test]
    fn the_hypervisor_kinds_are_declared_and_unavailable_everywhere() {
        // A-01's acceptance criterion. Declaring a runtime this build cannot provide is
        // only safe if asking for it always fails, on every platform, with a reason a
        // reader can act on -- otherwise the fallback is to run the plugin somewhere
        // weaker while the manifest still claims microVM isolation.
        for kind in [RuntimeKind::MicroVm, RuntimeKind::FullVm] {
            assert!(!kind.is_available(), "{kind:?} must not be available");
            let why = kind
                .unavailability()
                .unwrap_or_else(|| panic!("{kind:?} must explain why it is unavailable"));
            assert!(
                why.contains("Linux-only"),
                "{kind:?} must say it is Linux-only, got: {why}"
            );
            assert!(
                why.contains("refused"),
                "{kind:?} must say the request is refused rather than downgraded, got: {why}"
            );
        }
        // The two implemented kinds stay available; this is the "do not regress" half.
        assert!(RuntimeKind::Native.is_available());
        assert!(RuntimeKind::Process.is_available());
    }

    #[test]
    fn the_new_boundaries_have_distinct_waiver_keys() {
        // Each of A-02's boundaries is waivable, and a waiver is only meaningful if the
        // key it is filed under identifies exactly one boundary -- two boundaries
        // sharing a key would let one manifest reason silently excuse the other.
        for boundary in [
            Boundary::PmemSharedReadOnly,
            Boundary::IoctlFilter,
            Boundary::NetworkEgressAllowlist,
            Boundary::PriorityClass,
        ] {
            let key = boundary.waiver_key();
            assert!(!key.is_empty(), "{boundary:?} needs a waiver key");
            let sharing = Boundary::ALL
                .into_iter()
                .filter(|b| b.waiver_key() == key)
                .count();
            assert_eq!(sharing, 1, "`{key}` must identify exactly one boundary");
        }
        assert_eq!(Boundary::ALL.len(), 15, "A-02 defines four new boundaries");
    }

    #[test]
    fn the_process_runtime_enforces_what_the_v1_2_3_sandbox_enforces() {
        let caps = ProcessRuntime::new().declares().clone();
        for boundary in [
            Boundary::Timeout,
            Boundary::Memory,
            Boundary::ProcessCount,
            Boundary::OutputCap,
            Boundary::EnvAllowlist,
            Boundary::WorkDirIsolation,
        ] {
            assert!(caps.enforces(boundary), "{boundary:?} should be enforced");
        }
        for boundary in [
            Boundary::NetworkDeny,
            Boundary::FilesystemConfinement,
            Boundary::DiskQuota,
            Boundary::CpuLimit,
            Boundary::OpenFileLimit,
        ] {
            assert!(!caps.enforces(boundary), "{boundary:?} must not be claimed");
        }
    }

    #[test]
    fn an_unwaived_unenforceable_boundary_is_refused_by_name() {
        let caps = ProcessRuntime::new().declares().clone();
        let err = caps
            .require(
                &[Boundary::NetworkDeny, Boundary::DiskQuota],
                &BTreeMap::new(),
            )
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("isolation_not_enforceable"), "{text}");
        assert!(text.contains("network_deny"), "{text}");
        assert!(text.contains("disk_quota"), "{text}");
        // Both are named in one refusal rather than one per attempt.
        assert!(text.contains("network"), "{text}");
    }

    #[test]
    fn a_waiver_with_a_reason_unblocks_the_boundary() {
        let caps = ProcessRuntime::new().declares().clone();
        let mut waivers = BTreeMap::new();
        waivers.insert(
            Boundary::NetworkDeny.waiver_key().to_string(),
            "operator accepted this on a loopback-only host".to_string(),
        );
        assert!(caps.require(&[Boundary::NetworkDeny], &waivers).is_ok());
    }

    #[test]
    fn a_blank_waiver_reason_is_not_a_waiver() {
        let caps = ProcessRuntime::new().declares().clone();
        let mut waivers = BTreeMap::new();
        waivers.insert(
            Boundary::NetworkDeny.waiver_key().to_string(),
            "   ".to_string(),
        );
        let err = caps
            .require(&[Boundary::NetworkDeny], &waivers)
            .expect_err("must be refused");
        assert!(
            err.to_string().contains("isolation_not_enforceable"),
            "{err}"
        );
    }

    #[test]
    fn the_native_runtime_refuses_every_non_system_tier() {
        let runtime = NativeRuntime::new();
        for tier in [
            Tier::Official,
            Tier::Certified,
            Tier::ThirdParty,
            Tier::Blacklisted,
        ] {
            let err = runtime.start(&spec(tier)).expect_err("must be refused");
            assert!(
                err.to_string().contains("isolation_not_enforceable")
                    || err.to_string().contains("blacklisted"),
                "{tier}: {err}"
            );
        }
        assert!(runtime.start(&spec(Tier::System)).is_ok());
    }

    #[test]
    fn the_process_runtime_refuses_a_system_plugin() {
        // A system plugin behind a process boundary is not part of the kernel any
        // more; that is structural, so it is refused rather than configured.
        let runtime = ProcessRuntime::new();
        let err = runtime
            .start(&spec(Tier::System))
            .expect_err("must be refused");
        assert!(err.to_string().contains("must run natively"), "{err}");
    }

    #[test]
    fn the_process_runtime_refuses_a_blacklisted_plugin_on_any_runtime() {
        let runtime = ProcessRuntime::new();
        let mut s = spec(Tier::ThirdParty);
        s.waivers = full_waivers();
        s.tier = Tier::Blacklisted;
        let err = runtime.start(&s).expect_err("must be refused");
        assert!(err.to_string().contains("blacklisted"), "{err}");
    }

    #[test]
    fn the_process_runtime_refuses_a_plugin_that_waived_nothing() {
        // This is the default posture: a plugin that declares limits but no waivers
        // cannot start in the process backend, because four of its boundaries have no
        // primitive. It is refused, not run unconfined.
        let runtime = ProcessRuntime::new();
        let err = runtime
            .start(&spec(Tier::ThirdParty))
            .expect_err("must be refused");
        assert!(
            err.to_string().contains("isolation_not_enforceable"),
            "{err}"
        );
    }

    #[test]
    fn a_fully_waived_third_party_plugin_starts_and_reports_its_limits() {
        let runtime = ProcessRuntime::new();
        let mut s = spec(Tier::ThirdParty);
        s.waivers = full_waivers();
        let instance = runtime.start(&s).expect("starts");
        assert_eq!(instance.kind, RuntimeKind::Process);
        assert_eq!(instance.plugin, "io.example.analytics");
        assert!(
            instance.handle.contains("mem=134217728"),
            "{}",
            instance.handle
        );
        assert!(instance.handle.contains("procs=4"), "{}", instance.handle);
        runtime.stop(&instance).expect("stops");
    }

    #[test]
    fn a_relative_or_missing_entry_is_refused() {
        let runtime = ProcessRuntime::new();
        let mut s = spec(Tier::Official);
        s.waivers = full_waivers();
        s.entry = PathBuf::from("relative.bin");
        assert!(runtime
            .start(&s)
            .expect_err("relative")
            .to_string()
            .contains("absolute"));

        s.entry = std::env::temp_dir().join("nau-plugin-does-not-exist-ever");
        assert!(runtime
            .start(&s)
            .expect_err("missing")
            .to_string()
            .contains("does not exist"));
    }

    #[test]
    fn the_wasm_runtime_refuses_everything_and_says_why() {
        let runtime = WasmRuntime::new();
        assert_eq!(runtime.kind(), RuntimeKind::Wasm);
        assert!(!RuntimeKind::Wasm.is_available());
        let mut s = spec(Tier::Official);
        s.waivers = full_waivers();
        let err = runtime.start(&s).expect_err("must be refused");
        assert!(err.to_string().contains("no WASM runtime"), "{err}");
        assert!(runtime.declares().enforced.is_empty());
        assert!(runtime
            .call(
                &PluginInstance {
                    kind: RuntimeKind::Wasm,
                    plugin: "io.example.a".into(),
                    handle: "x".into(),
                },
                b""
            )
            .is_err());
    }

    #[test]
    fn selecting_a_runtime_by_name_refuses_a_typo_loudly() {
        assert!(runtime_for("").is_ok());
        assert!(runtime_for("native").is_ok());
        assert!(runtime_for("process").is_ok());
        assert!(runtime_for("wasm").is_ok());
        let err = runtime_for("wasmtime").expect_err("must be refused");
        assert!(err.to_string().contains("not a runtime"), "{err}");
        assert!(err.to_string().contains("process"), "{err}");
    }

    #[test]
    fn every_runtime_kind_and_boundary_has_a_distinct_label() {
        let mut kinds: Vec<&str> = RuntimeKind::ALL.iter().map(|k| k.label()).collect();
        kinds.sort_unstable();
        let before = kinds.len();
        kinds.dedup();
        assert_eq!(kinds.len(), before);

        let mut labels: Vec<&str> = Boundary::ALL.iter().map(|b| b.label()).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), before, "duplicate boundary label: {labels:?}");

        let mut keys: Vec<&str> = Boundary::ALL.iter().map(|b| b.waiver_key()).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), before, "duplicate waiver key: {keys:?}");
    }

    #[test]
    fn the_limit_mapping_is_the_identity_and_stays_that_way() {
        // Trivial today, pinned so that a future change to either side has to change
        // this test too.
        let l = limits();
        assert_eq!(sandbox_limits(&l), l);
        let _ = NOW;
    }
}
