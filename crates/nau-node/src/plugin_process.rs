//! The host half of the process-plugin runtime.
//!
//! # Why this module exists
//!
//! [`ProcessRuntime`](nau_plugin::runtime::ProcessRuntime) validates a start request,
//! refuses the tiers it must not carry, requires a written waiver for every boundary the
//! process backend cannot enforce, and hands back a
//! [`PluginInstance`](nau_plugin::runtime::PluginInstance) whose handle is a string. Its
//! [`call`](nau_plugin::runtime::PluginRuntime::call) then **refuses on purpose**, with:
//!
//! > the process runtime's exec is performed by the host against handle `…`; calling the
//! > port directly is a wiring error, not a plugin failure
//!
//! That sentence named a host that did not exist. `nau-node` referenced the sandbox, the
//! frame codec, and the process runtime nowhere, so a process plugin could be *started* —
//! a `PluginInstance` came back and `stop` succeeded — and could never be *called*. The
//! documentation claimed a working path and the executable half of it was absent, which is
//! the "written but not wired" defect this project exists to refuse.
//!
//! This module is that host. It frames a request, runs the plugin as a real child process
//! **through the same `SandboxManager`** the rest of the system uses, and decodes the
//! response frame. Going through the manager is the point: mapping the plugin's declared
//! limits onto `SandboxSpec` and letting the manager enforce them is what makes the process
//! runtime's boundary claims true, and a `std::process::Command` here would make every one
//! of them false while looking identical from the outside.
//!
//! # Platform behaviour, stated rather than assumed
//!
//! The plugin runs where the sandbox backend can run it, and that differs by platform — a
//! three-platform fact established by CI, not by reading the source:
//!
//! | Platform | Behaviour |
//! |---|---|
//! | Windows | Runs, limits enforced (Job Objects) |
//! | Linux | Runs; the boundaries the backend cannot enforce are the waived ones |
//! | macOS | The manager refuses with `EINVAL` before anything starts |
//!
//! So this module is portable and its *tests* are not: the end-to-end test that drives a
//! real plugin is `#[cfg(windows)]`, and the Linux and macOS behaviours are pinned by the
//! portable declaration test in `nau-plugins`. See `docs/VERIFICATION.md` §5.2.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use nau_plugin::hot::{Abi, HotSwapper, PluginSlot, SwapRecord};
use nau_plugin::runtime::{Boundary, PluginInstance, PluginRuntime, RuntimeKind, StartSpec};
use nau_sandbox::{
    AbsoluteProgramPath, Confinement, EnvPolicy, ExecRequest, FilesystemPolicy, InheritPolicy,
    Interpreter, NetworkPolicy, RealProcessExecutor, SandboxManager, SandboxSpec, Waivers,
};

/// An owner string for sandboxes this host creates.
///
/// Constant rather than per-plugin: the manager already namespaces by owner, and a
/// per-plugin owner would let one plugin enumerate another's sandboxes through
/// [`SandboxManager::list`](nau_sandbox::SandboxManager::list).
const OWNER: &str = "nau-node/process-plugin";

/// A plugin the host has started, and everything needed to call it again.
///
/// It holds no manager of its own. The host owns one, and a second `Arc` here would be the
/// same manager reached two ways -- which is how a "which one is authoritative" question
/// gets invented for no reason. A caller needs the host to call anything anyway.
pub struct ProcessPlugin {
    /// What the runtime reported when it accepted the start.
    pub instance: PluginInstance,
    /// The sandbox holding it.
    sandbox: nau_sandbox::SafeComponent,
}

impl std::fmt::Debug for ProcessPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written rather than derived: `SandboxManager` is not `Debug`, and the useful
        // thing to print is the identity of the plugin and its sandbox, not the manager's
        // internals. Deriving would either not compile or expose the whole manager.
        f.debug_struct("ProcessPlugin")
            .field("plugin", &self.instance.plugin)
            .field("kind", &self.instance.kind)
            .field("sandbox", &self.sandbox.as_str())
            .finish_non_exhaustive()
    }
}

impl ProcessPlugin {
    /// The runtime's handle for this plugin.
    #[must_use]
    pub fn handle(&self) -> &str {
        &self.instance.handle
    }

    /// The sandbox id, for an operator who has to look it up in the audit log.
    #[must_use]
    pub fn sandbox_id(&self) -> &str {
        self.sandbox.as_str()
    }
}

/// Deliver the messages a process plugin declared, **as that plugin**, through the bus.
///
/// # Why the host delivers rather than the plugin
///
/// The plugin cannot. It is a child process that answers one frame and exits: it holds no
/// capability token, no bus handle and no session key, so it has no way to put anything on PMB
/// and no way to forge a source. What it can do is declare an intent in its answer, and the host
/// — which holds the token the load pipeline minted — presents that token and lets the bus
/// decide.
///
/// **No check is skipped and none is re-implemented.** `Bus::send` still asks whether the sender
/// is running, whether the token holds the capability the message names, whether the size and
/// rate are within limits, and whether every recipient is running. A declaration that names a
/// capability the plugin does not hold is refused exactly as a system plugin's queued message
/// is, which is the property that makes this field an intent rather than an authority.
///
/// A malformed declaration — both `to` and `topic`, or neither — is refused by name rather than
/// guessed at: silently choosing one of two contradictory targets is the kind of quiet widening
/// this build refuses everywhere else.
#[must_use]
pub fn deliver_declared(
    bus: &mut nau_plugin::bus::Bus,
    membership: &dyn nau_plugin::bus::BusMembership,
    token: &nau_plugin::CapabilityToken,
    source: &nau_plugin::PluginId,
    declared: &[nau_plugins::frame::OutboxRequest],
    now_ms: u64,
) -> Vec<Declared> {
    let mut outcomes = Vec::with_capacity(declared.len());
    for (index, request) in declared.iter().enumerate() {
        let target = match (&request.to, &request.topic) {
            (Some(name), None) => nau_plugin::bus::Target::Plugin(name.clone()),
            (None, Some(_)) => nau_plugin::bus::Target::Broadcast,
            (Some(_), Some(_)) => {
                outcomes.push(Declared {
                    index,
                    target: "(ambiguous)".to_string(),
                    outcome: Err(
                        "a declaration sets both `to` and `topic`; exactly one decides \
                                  where the message goes"
                            .to_string(),
                    ),
                });
                continue;
            }
            (None, None) => {
                outcomes.push(Declared {
                    index,
                    target: "(none)".to_string(),
                    outcome: Err(
                        "a declaration sets neither `to` nor `topic`, so there is nowhere \
                                  to deliver it"
                            .to_string(),
                    ),
                });
                continue;
            }
        };
        let label = target.label();
        // The capability is parsed rather than trusted: an unknown name is a refusal from the
        // parser, not a string forwarded to the bus to fail obscurely later.
        let capability = match nau_plugin::Capability::parse(&request.capability) {
            Ok(capability) => capability,
            Err(e) => {
                outcomes.push(Declared {
                    index,
                    target: label,
                    outcome: Err(format!(
                        "`{}` is not a capability this kernel knows: {e}",
                        request.capability
                    )),
                });
                continue;
            }
        };
        let mut message = nau_plugin::bus::PmbMessage::new(
            source,
            target,
            capability,
            nau_plugin::bus::PmbKind::Event,
            request.payload.clone(),
            now_ms / 1_000,
        );
        if let Some(topic) = &request.topic {
            message = message.with_topic(topic);
        }
        let outcome = bus
            .send(membership, token, &message, now_ms)
            .map(|delivery| delivery.recipients)
            .map_err(|e| e.to_string());
        outcomes.push(Declared {
            index,
            target: label,
            outcome,
        });
    }
    outcomes
}

/// One declared message and what became of it.
#[derive(Debug, Clone)]
pub struct Declared {
    /// Where it was in the plugin's declaration.
    pub index: usize,
    /// Who it was for, or why that could not be determined.
    pub target: String,
    /// The recipients, or the bus's own refusal.
    pub outcome: Result<Vec<String>, String>,
}

/// The routing-table entry for a plugin this host has running.
///
/// `generation` is left at zero here: [`HotSwapper::swap`](nau_plugin::hot::HotSwapper::swap)
/// assigns the real generation itself when it performs the switch, and a value invented here
/// would be a second opinion about which generation is current.
///
/// The ABI recorded is **this host's**, not the plugin's declared one: the table answers
/// "what can this host serve", and a plugin the compat stage adapted is served *at the host's
/// ABI* — recording the plugin's would describe the artefact rather than the route.
fn slot_for(
    spec: &StartSpec,
    plugin: &ProcessPlugin,
    version: &str,
    generation: u64,
) -> PluginSlot {
    PluginSlot {
        id: spec.plugin.as_str().to_string(),
        version: version.to_string(),
        abi: Abi::new(nau_plugin::ABI_MAJOR, nau_plugin::ABI_MINOR),
        generation,
        runtime: RuntimeKind::Process,
        instance: Some(plugin.instance.clone()),
    }
}

/// The host's side of [`ProcessRuntime`](nau_plugin::runtime::ProcessRuntime).
///
/// Holds one [`SandboxManager`] for the node, because the manager is where the audit log,
/// the orphan sweep and the per-sandbox locks live; a manager per call would give each of
/// those a shorter life than the thing it protects.
pub struct ProcessPluginHost {
    manager: Arc<SandboxManager>,
    /// The routing table, and **the reason `HOT_SWAP_SUPPORTED` is true**.
    ///
    /// `nau-plugin`'s `hot::HotSwapper` implemented the whole mechanism — prepare beside the
    /// running version, health-check before the switch, one pointer replacement, then drain —
    /// and **no production code constructed one**: its only references outside its own module
    /// were its own tests and a doc comment. So the version's headline claim rested on a
    /// mechanism nothing used. This field is the caller it was missing.
    ///
    /// The switch is one pointer replacement under a write lock, so a reader sees either the
    /// whole old table or the whole new one, never a half-applied change.
    routes: HotSwapper,
}

impl std::fmt::Debug for ProcessPluginHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessPluginHost")
            .field("root", &self.manager.root())
            .field("run_id", &self.manager.run_id())
            .field("generation", &self.routes.generation())
            .field("routable", &self.routes.snapshot().len())
            .finish_non_exhaustive()
    }
}

impl ProcessPluginHost {
    /// Open the host over a data directory.
    ///
    /// # Errors
    ///
    /// The manager's own open failure, as text: a root that cannot be created, or an
    /// orphan sweep that cannot run.
    pub fn open(root: &Path, now: u64) -> Result<Self, String> {
        let manager = SandboxManager::open(root, Arc::new(RealProcessExecutor::new()), now)
            .map_err(|e| format!("cannot open the sandbox manager at {}: {e}", root.display()))?;
        Ok(Self {
            manager: Arc::new(manager),
            routes: HotSwapper::new(),
        })
    }

    /// The generation currently serving `plugin`, if it is routable.
    #[must_use]
    pub fn generation_of(&self, plugin: &str) -> Option<u64> {
        self.routes
            .snapshot()
            .get(plugin)
            .map(|slot| slot.generation)
    }

    /// Every swap this host has performed, oldest first.
    ///
    /// Exposed because a swap that cannot be audited is indistinguishable from a restart:
    /// the point of preparing a replacement beside the running version is that both existed
    /// for a moment, and the record is what says so afterwards.
    #[must_use]
    pub fn swap_history(&self) -> Vec<SwapRecord> {
        self.routes.history()
    }

    /// The version currently serving `plugin`, if it is routable.
    #[must_use]
    pub fn version_of(&self, plugin: &str) -> Option<String> {
        self.routes
            .snapshot()
            .get(plugin)
            .map(|slot| slot.version.clone())
    }

    /// The manager, for a caller that wants the audit log or the sweep count.
    #[must_use]
    pub fn manager(&self) -> &SandboxManager {
        &self.manager
    }

    /// Start a plugin on `runtime`, then create the sandbox it will run in.
    ///
    /// The order matters and is not interchangeable. The runtime is asked **first**, so its
    /// tier gate, its boundary waiver requirements and its absolute-path and existence
    /// checks all answer before a sandbox directory is created. Creating the sandbox first
    /// would leave a directory behind for every refused plugin, and a refused plugin is a
    /// normal outcome here rather than an exceptional one.
    ///
    /// # Errors
    ///
    /// The runtime's refusal (verbatim), or the manager's; or a refusal from this host when
    /// the runtime is not the process runtime — a native plugin has no child process to
    /// start, and silently returning an empty sandbox for one would be the kind of quiet
    /// widening that makes a boundary meaningless.
    pub fn start(
        &self,
        runtime: &dyn PluginRuntime,
        spec: &StartSpec,
    ) -> Result<ProcessPlugin, String> {
        let plugin = self.prepare(runtime, spec)?;
        // Routable from here, or a later `swap` would have nothing to replace. A first start
        // records no version: the caller has not said what it started, and inventing one would
        // be the host's guess at a value the swap record later has to be precise about.
        self.routes
            .insert(slot_for(spec, &plugin, "unversioned", 0))
            .map_err(|e| format!("`{}` started but could not be routed: {e}", spec.plugin))?;
        Ok(plugin)
    }

    /// Start a plugin **without routing it** — the preparation half of a swap.
    ///
    /// # Why this is separate
    ///
    /// `RoutingTable::insert` refuses a second entry for a name that is already routable, and
    /// its refusal names the reason: a replacement is meant to be prepared beside the running
    /// instance and only then switched to. A `swap` built on `start` therefore cannot work,
    /// and the kernel's own error message is what said so — *"use `swap` so the running
    /// instance is drained"*. The split is not cosmetic; without it a swap is impossible.
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start), minus the routing.
    pub fn prepare(
        &self,
        runtime: &dyn PluginRuntime,
        spec: &StartSpec,
    ) -> Result<ProcessPlugin, String> {
        if runtime.kind() != RuntimeKind::Process {
            return Err(format!(
                "this host drives the process runtime; `{}` was given a {} runtime",
                spec.plugin,
                runtime.kind().label()
            ));
        }
        let instance = runtime
            .start(spec)
            .map_err(|e| format!("`{}` was refused: {e}", spec.plugin))?;
        let sandbox_spec = sandbox_spec_for(spec)?;
        let sandbox = self
            .manager
            .create(OWNER, &sandbox_spec)
            .map_err(|e| format!("cannot create a sandbox for `{}`: {e}", spec.plugin))?;
        Ok(ProcessPlugin { instance, sandbox })
    }

    /// Replace a running plugin with a new build, atomically and only if it is healthy.
    ///
    /// # The three steps, and why the order is the point
    ///
    /// 1. **prepare** — the replacement is started in its own sandbox *beside* the running
    ///    one. Both exist for a moment; nothing has been switched yet.
    /// 2. **health** — the replacement is called with `probe`, through the ordinary
    ///    [`call`](Self::call) path. A build that fails here **never reaches the routing
    ///    table**, so a bad release is a failed swap rather than an outage. This is the step
    ///    that makes the operation safe rather than merely quick, and the probe reaching the
    ///    **new** instance rather than the old one is the whole value of it.
    /// 3. **switch and drain** — one pointer replacement under a write lock, then the old
    ///    sandbox is destroyed. A drain that fails is recorded and does **not** put the old
    ///    version back: the new one is already serving, and resurrecting the old because it
    ///    would not stop cleanly would be a downgrade wearing a rollback's name.
    ///
    /// The caller keeps the old [`ProcessPlugin`] until it does not need it; the replacement
    /// is returned, because the host does not hold the sandboxes — the routing table answers
    /// *which generation is current*, and the caller answers *how it is run*.
    ///
    /// # Errors
    ///
    /// The runtime's or the manager's refusal when starting the replacement; the health
    /// probe's own refusal; or the swap refusal (the plugin is not running). In every case
    /// the running version keeps serving and the replacement's sandbox is destroyed.
    pub fn swap(
        &self,
        old: &ProcessPlugin,
        runtime: &dyn PluginRuntime,
        spec: &StartSpec,
        version: &str,
        probe: &[u8],
    ) -> Result<(ProcessPlugin, SwapRecord), String> {
        let id = spec.plugin.as_str().to_string();
        // `prepare`, not `start`: routing the replacement would be publishing it before it
        // has been health-checked, which is the one thing the order exists to prevent.
        let replacement = self.prepare(runtime, spec)?;
        let slot = slot_for(spec, &replacement, version, 0);

        let health = |_candidate: &PluginSlot| -> std::result::Result<(), String> {
            // **A refusal is not health.** `call` returns the payload for a refusal frame
            // too — the frame is the protocol and the exit code is a hint — so a probe that
            // only checked for a transport error would pass a replacement that answers "no"
            // to everything. A health check has to mean "it answered the question it was
            // asked", which is why the response is decoded here and `ok` is required.
            let payload = self.call(&replacement, probe)?;
            let response = nau_plugins::frame::decode_response(&payload).map_err(|e| {
                format!("the replacement answered a frame that is not a response: {e}")
            })?;
            if response.ok {
                Ok(())
            } else {
                Err(format!(
                    "the replacement refused the health probe: {} {}",
                    response.code.unwrap_or_else(|| "(no code)".to_string()),
                    response
                        .message
                        .unwrap_or_else(|| "(no message)".to_string())
                ))
            }
        };
        let drain = |_old_slot: &PluginSlot| -> std::result::Result<(), String> { self.stop(old) };

        match self.routes.swap(slot, health, drain) {
            Ok(record) => Ok((replacement, record)),
            Err(e) => {
                // The replacement never took traffic, so its sandbox must not outlive the
                // attempt: leaving it running would be a leaked process for every failed
                // release, and the leak would be invisible because nothing routes to it.
                let _ = self.stop(&replacement);
                Err(format!("swapping `{id}`: {e}"))
            }
        }
    }

    /// Run one request through a started plugin and return the response payload.
    ///
    /// # Errors
    ///
    /// A refusal for every way this can fail, each naming what happened: the plugin exiting
    /// non-zero, the plugin being killed by the sandbox (timeout or termination), an empty
    /// or malformed response frame, and a response frame that is not a valid
    /// [`Response`](nau_plugins::frame::Response).
    ///
    /// A refusal is returned rather than an error propagated, because a plugin that
    /// misbehaves is a fact the caller has to *see*, not an exception that unwinds past the
    /// audit log.
    pub fn call(&self, plugin: &ProcessPlugin, request: &[u8]) -> Result<Vec<u8>, String> {
        let mut wire = Vec::new();
        nau_plugins::frame::write_frame(&mut wire, request)
            .map_err(|e| format!("cannot frame the request: {e}"))?;

        let outcome = self
            .manager
            .exec(
                OWNER,
                plugin.sandbox.as_str(),
                None,
                &ExecRequest::with_stdin(wire),
            )
            .map_err(|e| format!("`{}` could not be run: {e}", plugin.instance.plugin))?;

        if outcome.timed_out {
            // Checked before the exit code: a killed process has one, and reporting
            // "exited with X" for something the sandbox killed would blame the plugin.
            return Err(format!(
                "`{}` hit its {}ms deadline and was stopped",
                plugin.instance.plugin, plugin.instance.handle
            ));
        }
        if outcome.terminated {
            return Err(format!(
                "`{}` was terminated by the sandbox rather than exiting",
                plugin.instance.plugin
            ));
        }

        // **The frame is the protocol; the exit code is a hint.** The frame is read before
        // the exit code is judged, and that order is the whole point of this block.
        //
        // A plugin that answers with a typed refusal exits non-zero -- `nau-plugin-market`
        // uses `EXIT_REFUSED = 1` for exactly that -- so a host that checked the exit code
        // first would discard a valid, useful answer and report "exited with 1; stderr:"
        // instead. That is the "a refusal is a value, not an error" rule this system applies
        // everywhere else, and the first version of this function broke it. The end-to-end
        // test found it, which is what that test is for.
        match nau_plugins::frame::read_frame(&mut outcome.stdout.as_slice()) {
            Ok(Some(payload)) => {
                // Decoded here rather than handed on: a plugin that writes a frame which is
                // not a `Response` has broken the ABI, and a caller finding that out later,
                // somewhere else, is how a broken ABI survives a release.
                nau_plugins::frame::decode_response(&payload).map_err(|e| {
                    format!(
                        "`{}` wrote a frame that is not a response: {e}",
                        plugin.instance.plugin
                    )
                })?;
                Ok(payload)
            }
            // No frame at all: *now* the exit code is the only evidence there is.
            Ok(None) => Err(format!(
                "`{}` wrote no response frame and exited with {:?}; stderr: {}",
                plugin.instance.plugin,
                outcome.exit_code,
                String::from_utf8_lossy(&outcome.stderr).trim()
            )),
            Err(e) => Err(format!(
                "`{}` wrote a malformed frame: {e}; stderr: {}",
                plugin.instance.plugin,
                String::from_utf8_lossy(&outcome.stderr).trim()
            )),
        }
    }

    /// Stop a plugin and destroy its sandbox.
    ///
    /// # Errors
    ///
    /// The runtime's or the manager's, as text.
    pub fn stop(&self, plugin: &ProcessPlugin) -> Result<(), String> {
        self.manager
            .destroy(OWNER, plugin.sandbox.as_str())
            .map_err(|e| {
                format!(
                    "cannot destroy the sandbox for `{}`: {e}",
                    plugin.instance.plugin
                )
            })
    }
}

/// Map a plugin's `StartSpec` onto a sandbox specification.
///
/// # What is copied and what is declared
///
/// The limits and the waivers are the plugin's; the network and filesystem policies and the
/// environment policy are this build's honest position, and the reasons say so. This build
/// has no egress filter and no filesystem-confinement primitive behind a child process, so
/// asking for `NetworkPolicy::Deny` or `Confinement::PluginDir` would be refused by the
/// manager — which is the correct behaviour and a different test. What is not negotiable is
/// that the boundaries actually waived are the ones the *manifest* waived: a host that
/// filled in waivers on the plugin's behalf would be granting authority nobody applied for.
fn sandbox_spec_for(spec: &StartSpec) -> Result<SandboxSpec, String> {
    let mut waivers = Waivers::none();
    for boundary in Boundary::ALL {
        let declared = spec.waivers.get(boundary.waiver_key()).cloned();
        match boundary {
            Boundary::FilesystemConfinement => waivers.filesystem_confinement = declared,
            Boundary::DiskQuota => waivers.disk_bytes = declared,
            Boundary::CpuLimit => waivers.cpu_ms = declared,
            Boundary::OpenFileLimit => waivers.max_open_files = declared,
            // Every other boundary is either enforced by the backend or waived through a
            // mechanism the manager reaches by another route; neither belongs in `Waivers`.
            _ => {}
        }
    }

    // The runtime has already refused a non-absolute entry, so this failure is unreachable
    // in practice -- and it is still returned rather than unwrapped, because "unreachable"
    // is a claim about code that changes, and a panic here would be a host crash for a bad
    // manifest.
    let program = AbsoluteProgramPath::new(spec.entry.clone())
        .map_err(|e| format!("the entry for `{}` is not usable: {e}", spec.plugin))?;

    Ok(SandboxSpec {
        interpreter: Interpreter::Binary(program),
        limits: sandbox_limits(&spec.limits),
        network: NetworkPolicy::Unrestricted {
            justification: "no egress filter available behind a child process in this build"
                .to_string(),
        },
        filesystem: FilesystemPolicy {
            confinement: Confinement::WholeHost,
            extra_readable: Vec::new(),
            writable: Vec::new(),
        },
        // Nothing is inherited. A plugin's environment is constructed, not taken, so a
        // variable the host happens to hold is not a variable the plugin receives.
        env: EnvPolicy {
            inherit: InheritPolicy::Nothing,
            vars: Vec::new(),
        },
        waivers,
    })
}

/// The open-file cap for a process plugin.
///
/// # Why this is the host's number and not the manifest's
///
/// [`nau_plugin::manifest::Limits`] has no open-file field, so there is nothing for a
/// plugin to declare and nothing for this host to read. Rather than pick a number silently,
/// it is named here: the boundary is still *waivable* through the manifest's
/// `max_open_files` key, and a plugin that waives it is saying it does not want the cap
/// enforced. A plugin that does not waive it gets this cap, applied by the backend.
const HOST_OPEN_FILE_CAP: u32 = 256;

/// Map the manifest's limits onto the sandbox's.
///
/// # Why this conversion is written out rather than delegated
///
/// [`nau_plugin::runtime::sandbox_limits`] has a name that suggests it does this, and it
/// does not: it takes and returns `nau_plugin::manifest::Limits`, an identity. The two
/// `Limits` types are different structs — the sandbox's carries a wall-clock deadline and an
/// open-file cap that the manifest's does not — so the mapping has to exist somewhere, and
/// it belongs next to the code that builds the `SandboxSpec`.
///
/// The wall-clock deadline is the manifest's CPU budget. That is not a coincidence of this
/// function: `ProcessRuntime`'s own handle string reports `timeout={cpu_ms}ms`, so the
/// runtime already treats the two as the same quantity, and a plugin that asked for *N* ms
/// of CPU has not asked to live longer than that in wall-clock terms either.
fn sandbox_limits(limits: &nau_plugin::manifest::Limits) -> nau_sandbox::Limits {
    nau_sandbox::Limits {
        timeout_ms: limits.cpu_ms,
        memory_bytes: limits.memory_bytes,
        cpu_ms: limits.cpu_ms,
        disk_bytes: limits.disk_bytes,
        max_processes: limits.max_processes,
        max_open_files: HOST_OPEN_FILE_CAP,
        // The manifest's cap is `u32` and the sandbox's is `usize`. Widened rather than
        // cast, so the conversion cannot silently truncate on a target where `usize` is
        // narrower than `u32` -- which the type system then makes a reported value instead
        // of a wrapped one.
        max_output_bytes: usize::try_from(limits.max_output_bytes).unwrap_or(usize::MAX),
    }
}

/// The waivers a manifest must carry for a plugin to run on this host, for a caller that
/// wants to *report* them rather than discover them one refusal at a time.
#[must_use]
pub fn required_waivers() -> BTreeMap<String, String> {
    // Owned strings rather than borrowed ones: the reasons live in the runtime's capability
    // table, so returning `&str` would mean returning references into a local.
    let runtime = nau_plugin::runtime::ProcessRuntime::new();
    runtime
        .declares()
        .unenforced()
        .into_iter()
        .map(|(boundary, why)| (boundary.waiver_key().to_string(), why.to_string()))
        .collect()
}
