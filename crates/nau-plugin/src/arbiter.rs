//! The arbiter: the pipeline that turns a manifest into a running plugin, or into a
//! typed refusal with a full trace.
//!
//! # Why a pipeline object rather than a `load` function
//!
//! Every step has to be *reportable*. When a plugin does not load, the operator's
//! question is never just "did it fail" but "which check refused it, and what would
//! have to change" — and the answer has to be the same one the REST surface, the CLI
//! and the tests give. So the arbiter records a [`LoadStep`] for each stage it
//! reaches, successful or not, and a failure carries the whole trace.
//!
//! # Refusals leave nothing behind
//!
//! A refused load must not leave a half-registered plugin: not in the registry, not
//! on the bus, not holding a runtime instance. Every step that mutates shared state
//! happens **after** every step that can refuse, and `a_refused_load_leaves_no_trace`
//! asserts it. This is the failure mode that makes a plugin system untrustworthy —
//! a phantom entry that the next load trips over — so it is checked rather than
//! assumed.
//!
//! # The order of the checks, and why
//!
//! 1. **parse** — a malformed document cannot be reasoned about any further;
//! 2. **blacklist** — cheapest decisive answer, and it must come before anything
//!    that could have a side effect;
//! 3. **verify** — the four checks (name/tier, digest, publisher signature,
//!    counter-signature, module hash);
//! 4. **limits** — clamp to the tier ceiling and record the clamping;
//! 5. **runtime** — pick a backend whose declared capabilities cover the request, or
//!    refuse with the boundary names;
//! 6. **state** — only now do the registry, the bus and the lifecycle change.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::blacklist::Blacklist;
use crate::bus::Bus;
use crate::capability::{Approval, Capability, Grant};
use crate::error::{LoadRefusal, PluginError, Result};
use crate::hot::{AdapterRegistry, Compat};
use crate::lifecycle::PluginState;
use crate::manifest::{Limits, Manifest, TrustStore};
use crate::registry::{Dependency, Registry};
use crate::runtime::{PluginInstance, PluginRuntime, RuntimeKind, StartSpec};
use crate::tier::{PluginId, Tier};

/// One stage of the load pipeline, with its outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadStep {
    /// The stage name.
    pub step: &'static str,
    /// What happened, in one clause.
    pub outcome: String,
    /// Whether the stage passed.
    pub passed: bool,
}

impl LoadStep {
    fn ok(step: &'static str, outcome: impl Into<String>) -> Self {
        Self {
            step,
            outcome: outcome.into(),
            passed: true,
        }
    }

    fn refused(step: &'static str, outcome: impl Into<String>) -> Self {
        Self {
            step,
            outcome: outcome.into(),
            passed: false,
        }
    }
}

/// A load that did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadFailure {
    /// The machine-readable reason.
    pub refusal: LoadRefusal,
    /// The human-readable detail.
    pub detail: String,
    /// Every stage reached, in order, including the one that refused.
    pub trace: Vec<LoadStep>,
}

impl LoadFailure {
    /// A one-line summary for a log.
    #[must_use]
    pub fn summary(&self) -> String {
        format!("{}: {}", self.refusal.code(), self.detail)
    }
}

impl std::fmt::Display for LoadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.summary())
    }
}

/// What the host hands the arbiter.
#[derive(Debug, Clone)]
pub struct LoadRequest {
    /// The manifest document.
    pub manifest_json: String,
    /// The entry artefact's bytes, hashed and compared against the manifest.
    pub module: Vec<u8>,
    /// Where the entry lives on disk, for the process runtime.
    pub entry: PathBuf,
    /// The dependencies the publisher declares.
    pub dependencies: Vec<Dependency>,
}

impl LoadRequest {
    /// A request whose dependencies come from the manifest it carries.
    ///
    /// # Why the edges are read from the manifest rather than defaulted to nothing
    ///
    /// They used to be `Vec::new()`, always, and `depending_on` — the only other way to set
    /// them — was called from **one kernel test and nowhere else**. So the registry every load
    /// produced had no edges, `Registry::load_order` returned the insertion order, and the
    /// dependency machinery the architecture describes (`HotPlug::start_order`, `stop_plan`, and
    /// `sys.orchestrator`, whose whole job is to report the order) could not do anything for any
    /// plugin that existed. A declaration that only a fixture can make is not a declaration.
    ///
    /// The extraction is deliberately forgiving: a manifest whose `dependencies` section is
    /// malformed fails the pipeline's own `parse` stage, which deserialises the whole manifest
    /// with `deny_unknown_fields`, so this cannot admit something the pipeline would reject.
    /// Reading it here rather than after the parse keeps `LoadRequest` a plain description of
    /// what to load.
    #[must_use]
    pub fn new(manifest_json: impl Into<String>, module: Vec<u8>, entry: PathBuf) -> Self {
        let manifest_json = manifest_json.into();
        let dependencies = serde_json::from_str::<serde_json::Value>(&manifest_json)
            .ok()
            .and_then(|value| value.get("dependencies")?.as_array().cloned())
            .and_then(|list| {
                serde_json::from_value::<Vec<Dependency>>(serde_json::Value::Array(list)).ok()
            })
            .unwrap_or_default();
        Self {
            manifest_json,
            module,
            entry,
            dependencies,
        }
    }

    /// Declare a dependency.
    #[must_use]
    pub fn depending_on(mut self, dependencies: Vec<Dependency>) -> Self {
        self.dependencies = dependencies;
        self
    }
}

/// A load that happened.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The plugin.
    pub id: PluginId,
    /// Its tier.
    pub tier: Tier,
    /// The backend that started it.
    pub runtime: RuntimeKind,
    /// The runtime's handle, when it has one.
    pub instance: Option<PluginInstance>,
    /// The state it ended in.
    pub state: PluginState,
    /// The capabilities it holds.
    pub granted: Vec<Capability>,
    /// How this host serves the plugin's ABI: directly, or through a named adapter.
    pub compat: Compat,
    /// Every stage, in order.
    pub trace: Vec<LoadStep>,
}

/// The load pipeline.
#[derive(Debug)]
pub struct Arbiter {
    trust: TrustStore,
    blacklist: Blacklist,
    runtimes: BTreeMap<RuntimeKind, Box<dyn PluginRuntime>>,
    /// An empty registry is the fail-closed default: a host that has registered no
    /// adapter runs only plugins built for its own ABI. Compatibility is opted into.
    adapters: AdapterRegistry,
    /// Approvals, **keyed by plugin name**.
    ///
    /// Keyed rather than global on purpose: an approval granted for one plugin must not
    /// silently authorise another's capability requests, and a flat list applied at every
    /// load is exactly how that happens.
    approvals: BTreeMap<String, Vec<(Capability, Approval)>>,
    /// Certifications, **keyed by plugin name**.
    ///
    /// # Why this field is the point of the whole `certify` module
    ///
    /// [`Certification::require_within_scope`](crate::certify::Certification::require_within_scope)
    /// existed, was tested, and was **called by nothing but its own tests** — so a
    /// certification was a record no loader read. Worse, the review CLI printed "the loader
    /// enforces this scope" at the operator, which made it a claim rather than a gap.
    ///
    /// A certification's scope is the control that distinguishes "the vendor signed this
    /// manifest" from "the vendor reviewed these capabilities". Without a reader the second
    /// statement is unenforced, and a plugin may hold anything its counter-signature allows.
    ///
    /// Keyed by name for the same reason approvals are: a review of plugin A must not widen
    /// plugin B.
    certifications: BTreeMap<String, crate::certify::Certification>,
}

impl Arbiter {
    /// An arbiter that trusts nobody and has no runtime registered.
    ///
    /// Starting from nothing is deliberate: an arbiter that came with a default
    /// runtime and a permissive trust store would load plugins before an operator
    /// had decided anything.
    #[must_use]
    pub fn new(trust: TrustStore, blacklist: Blacklist) -> Self {
        Self {
            trust,
            blacklist,
            runtimes: BTreeMap::new(),
            adapters: AdapterRegistry::new(),
            approvals: BTreeMap::new(),
            certifications: BTreeMap::new(),
        }
    }

    /// Record that a review certified `plugin` over a scope.
    ///
    /// # A certification **is** the authority's decision, so it carries the approvals
    ///
    /// A capability the tier holds only with approval (`net:dht:read` at the certified tier,
    /// where the authority is the certification committee) needs two things to load: an
    /// approval, so the token may include it, and a scope covering it, so nothing wider slips
    /// through. Requiring an operator to supply both separately made the second redundant and
    /// the first easy to forget — and a review flow that issues a scope for a capability,
    /// while the load path separately refuses for want of an approval from the same
    /// committee, is one decision split into two places that can disagree.
    ///
    /// So this records the approvals the scope implies, derived from the same
    /// [`Capability::decision`] the rest of the system reads. A capability the tier refuses
    /// outright is never approved here, and a capability outside the scope is never
    /// approved, because the scope is where the approval comes from.
    #[must_use]
    pub fn with_certification(mut self, certification: crate::certify::Certification) -> Self {
        if let Ok(tier) = Tier::from_name(&certification.plugin) {
            for capability in &certification.scope {
                if let Grant::RequiresApproval(authority) = capability.decision(tier) {
                    self.approvals
                        .entry(certification.plugin.clone())
                        .or_default()
                        .push((*capability, authority));
                }
            }
        }
        self.certifications
            .insert(certification.plugin.clone(), certification);
        self
    }

    /// The certification recorded for a plugin, if any.
    #[must_use]
    pub fn certification_for(&self, plugin: &str) -> Option<&crate::certify::Certification> {
        self.certifications.get(plugin)
    }

    /// Record that `authority` approved `capability` for `plugin`.
    ///
    /// This is the production door the approval half of the tier matrix needed: without
    /// it, `Grant::RequiresApproval` was reachable in the capability module and
    /// unreachable from a load, so an Official plugin could still hold nothing but the
    /// basic set.
    #[must_use]
    pub fn with_approval(
        mut self,
        plugin: &str,
        capability: Capability,
        authority: Approval,
    ) -> Self {
        self.approvals
            .entry(plugin.to_string())
            .or_default()
            .push((capability, authority));
        self
    }

    /// The approvals recorded for a plugin.
    #[must_use]
    pub fn approvals_for(&self, plugin: &str) -> &[(Capability, Approval)] {
        self.approvals.get(plugin).map_or(&[], Vec::as_slice)
    }

    /// Register a runtime backend.
    pub fn with_runtime(mut self, runtime: Box<dyn PluginRuntime>) -> Self {
        self.runtimes.insert(runtime.kind(), runtime);
        self
    }

    /// Accept plugins built for older ABIs, through the adapters given.
    ///
    /// Not the default, and deliberately so: a host that has not decided which older
    /// ABIs it can serve should refuse them rather than guess. Use
    /// [`crate::hot::AdapterRegistry::with_shipped_adapters`] for the set this build
    /// knows how to translate.
    #[must_use]
    pub fn with_adapters(mut self, adapters: AdapterRegistry) -> Self {
        self.adapters = adapters;
        self
    }

    /// The adapters in force.
    #[must_use]
    pub fn adapters(&self) -> &AdapterRegistry {
        &self.adapters
    }

    /// The blacklist, for reporting.
    #[must_use]
    pub fn blacklist(&self) -> &Blacklist {
        &self.blacklist
    }

    /// The trust store, for reporting.
    #[must_use]
    pub fn trust(&self) -> &TrustStore {
        &self.trust
    }

    /// Which runtimes are available.
    #[must_use]
    pub fn runtimes(&self) -> Vec<RuntimeKind> {
        self.runtimes.keys().copied().collect()
    }

    /// Run the pipeline.
    ///
    /// # Errors
    ///
    /// Returns `Err(LoadFailure)` — not a bare error — so the caller gets the machine
    /// code, the detail and the stage trace together, which is what a UI or a log
    /// line actually needs.
    pub fn load(
        &self,
        registry: &mut Registry,
        bus: &mut Bus,
        request: &LoadRequest,
        now: u64,
    ) -> std::result::Result<Loaded, LoadFailure> {
        let mut trace = Vec::new();

        // 1. parse
        let manifest = match Manifest::parse(&request.manifest_json) {
            Ok(m) => {
                trace.push(LoadStep::ok(
                    "parse",
                    format!("{} {}", m.plugin.name, m.plugin.version),
                ));
                m
            }
            Err(e) => {
                trace.push(LoadStep::refused("parse", e.to_string()));
                // Not hard-coded to `ManifestInvalid`. A parse-stage failure can be an
                // ABI from the future, which `parse` refuses because it is a property of
                // the document; collapsing that into "the manifest is invalid" throws away
                // the one fact an operator needs, and `refusal_of` exists to keep it.
                return Err(LoadFailure {
                    refusal: refusal_of(&e),
                    detail: e.to_string(),
                    trace,
                });
            }
        };

        // 2. blacklist, before anything with a side effect
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&request.module));
        if let Err(e) = self
            .blacklist
            .require_allowed(&manifest.plugin.name, Some(&digest))
        {
            trace.push(LoadStep::refused("blacklist", e.to_string()));
            return Err(LoadFailure {
                refusal: LoadRefusal::Blacklisted,
                detail: e.to_string(),
                trace,
            });
        }
        trace.push(LoadStep::ok("blacklist", "not listed"));

        // 3. verify: name/tier, digest, publisher signature, counter-signature, module
        let approvals = self.approvals_for(&manifest.plugin.name);
        let verified =
            match manifest.verify_with_approvals(&request.module, &self.trust, now, approvals) {
                Ok(v) => v,
                Err(e) => {
                    let refusal = refusal_of(&e);
                    trace.push(LoadStep::refused("verify", e.to_string()));
                    return Err(LoadFailure {
                        refusal,
                        detail: e.to_string(),
                        trace,
                    });
                }
            };
        trace.push(LoadStep::ok(
            "verify",
            format!(
                "tier {} · publisher {} · module {}",
                verified.tier,
                short(&verified.manifest.signature.publisher_key),
                short(&verified.module_digest)
            ),
        ));

        // 3b. certification: **what did a review actually approve?**
        //
        // This is a distinct question from the one `verify` just answered, and the
        // distinction is why the two artifacts exist at all. `verify` proved the vendor
        // signed *this manifest*; a certification says the vendor reviewed *a set of
        // capabilities*. A counter-signature is a statement about a document; a
        // certification scope is a statement about what somebody looked at.
        //
        // The check is here because it was nowhere. `require_within_scope` was written,
        // tested, and called by nothing but its own tests, so a certification was a record
        // no loader read -- and the review CLI printed "the loader enforces this scope" at
        // the operator, which made it a false claim rather than a known gap. A control that
        // is documented and not enforced is worse than no control.
        match self.certifications.get(&verified.manifest.plugin.name) {
            Some(certification) => {
                if let Err(e) = certification.require_within_scope(&verified.manifest) {
                    trace.push(LoadStep::refused("certification", e.to_string()));
                    return Err(LoadFailure {
                        // The capability *is* permitted at this tier; what is missing is the
                        // review that covered it. The detail carries the kernel's own
                        // sentence, which names the capability and prints the whole scope.
                        refusal: LoadRefusal::CapabilityNotPermitted,
                        detail: e.to_string(),
                        trace,
                    });
                }
                trace.push(LoadStep::ok(
                    "certification",
                    format!(
                        "scope covers {} capability/ies, certified at {}",
                        certification.scope.len(),
                        certification.certified_at
                    ),
                ));
            }
            None => {
                if verified.tier == Tier::Certified {
                    let detail = format!(
                        "`{}` is a certified plugin and no certification covers it. The tier \
                         requires the review that granted the scope: a counter-signature proves \
                         the vendor signed the manifest, not that anyone reviewed what it may do",
                        verified.manifest.plugin.name
                    );
                    trace.push(LoadStep::refused("certification", detail.clone()));
                    return Err(LoadFailure {
                        refusal: LoadRefusal::CertificationMissing,
                        detail,
                        trace,
                    });
                }
                trace.push(LoadStep::ok(
                    "certification",
                    "no certification supplied, and this tier does not require one",
                ));
            }
        }

        // 4. compatibility: can this host *serve* that ABI?
        //
        //    Separate from verification on purpose. `verify` answered "is this manifest
        //    what its publisher signed"; this answers "can this host run it". A 2.x
        //    plugin is authentic and is neither silently accepted nor blindly refused --
        //    it is adapted by name, or refused with the adapters that exist listed.
        let compat = match self
            .adapters
            .compatibility(verified.manifest.abi().map_err(|e| {
                let refusal = refusal_of(&e);
                trace.push(LoadStep::refused("compat", e.to_string()));
                LoadFailure {
                    refusal,
                    detail: e.to_string(),
                    trace: trace.clone(),
                }
            })?) {
            Ok(compat) => compat,
            Err(e) => {
                let refusal = refusal_of(&e);
                trace.push(LoadStep::refused("compat", e.to_string()));
                return Err(LoadFailure {
                    refusal,
                    detail: e.to_string(),
                    trace,
                });
            }
        };
        trace.push(LoadStep::ok(
            "compat",
            match &compat {
                Compat::Direct => format!(
                    "ABI {} is this host's own",
                    verified
                        .manifest
                        .abi()
                        .map_or_else(|_| "?".to_string(), |a| a.to_string())
                ),
                Compat::Adapted { adapter, from } => {
                    format!("ABI {from} translated by `{adapter}`")
                }
            },
        ));

        // 5. limits against the tier ceiling
        let ceiling = tier_ceiling(verified.tier);
        let clamped = verified.manifest.limits.clamped_to(ceiling);
        let clamped_note = if clamped == verified.manifest.limits {
            "within the tier ceiling".to_string()
        } else {
            format!(
                "clamped to the {} ceiling in {}",
                verified.tier,
                verified
                    .manifest
                    .limits
                    .exceeds(ceiling)
                    .unwrap_or("at least one dimension")
            )
        };
        trace.push(LoadStep::ok("limits", clamped_note));

        // 5. runtime
        let kind = runtime_for_tier(verified.tier);
        let Some(runtime) = self.runtimes.get(&kind) else {
            let detail = format!(
                "no `{}` runtime is registered, and tier {} requires one",
                kind.label(),
                verified.tier
            );
            trace.push(LoadStep::refused("runtime", detail.clone()));
            return Err(LoadFailure {
                refusal: LoadRefusal::IsolationNotEnforceable,
                detail,
                trace,
            });
        };

        let start_spec = StartSpec {
            plugin: verified.id.clone(),
            tier: verified.tier,
            entry: request.entry.clone(),
            limits: clamped,
            waivers: verified.manifest.waivers.clone(),
        };
        let instance = match runtime.start(&start_spec) {
            Ok(i) => i,
            Err(e) => {
                trace.push(LoadStep::refused("runtime", e.to_string()));
                return Err(LoadFailure {
                    refusal: refusal_of(&e),
                    detail: e.to_string(),
                    trace,
                });
            }
        };
        trace.push(LoadStep::ok(
            "runtime",
            format!("started on {}", kind.label()),
        ));

        // 6. shared state. Everything above could refuse; nothing below can leave a
        //    half-registered plugin, because each step is undone on the next failure.
        if let Err(e) = registry.insert(verified.clone(), request.dependencies.clone()) {
            let _ = runtime.stop(&instance);
            trace.push(LoadStep::refused("registry", e.to_string()));
            return Err(LoadFailure {
                refusal: LoadRefusal::DependencyUnsatisfied,
                detail: e.to_string(),
                trace,
            });
        }
        if let Err(e) = bus.register(verified.token.clone()) {
            let _ = registry.remove(verified.id.as_str());
            let _ = runtime.stop(&instance);
            trace.push(LoadStep::refused("bus", e.to_string()));
            return Err(LoadFailure {
                refusal: LoadRefusal::ManifestInvalid,
                detail: e.to_string(),
                trace,
            });
        }

        // 7. lifecycle: Discovered -> Verified -> Loaded -> Running, each with a
        //    reason, through the one assignment site.
        let mut failure: Option<String> = None;
        if let Some(entry) = registry.get_mut(verified.id.as_str()) {
            for (state, because) in [
                (PluginState::Verified, "four checks passed"),
                (PluginState::Loaded, "runtime started"),
                (PluginState::Running, "registered on the bus"),
            ] {
                if let Err(e) = entry.lifecycle.transition(state, because, now) {
                    failure = Some(e.to_string());
                    break;
                }
            }
        } else {
            failure = Some("the registry lost the entry between insert and transition".into());
        }
        if let Some(detail) = failure {
            bus.deregister(verified.id.as_str());
            let _ = registry.remove(verified.id.as_str());
            let _ = runtime.stop(&instance);
            trace.push(LoadStep::refused("lifecycle", detail.clone()));
            return Err(LoadFailure {
                refusal: LoadRefusal::ManifestInvalid,
                detail,
                trace,
            });
        }

        let state = registry
            .get(verified.id.as_str())
            .map_or(PluginState::Discovered, |e| e.state());
        trace.push(LoadStep::ok("lifecycle", format!("running ({state})")));

        Ok(Loaded {
            id: verified.id.clone(),
            tier: verified.tier,
            runtime: kind,
            instance: Some(instance),
            state,
            granted: verified.token.granted().iter().copied().collect(),
            compat,
            trace,
        })
    }

    /// Stop and retire a plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] when a transition is refused, or
    /// [`PluginError::Manifest`] when the plugin is not registered.
    pub fn unload(
        &self,
        registry: &mut Registry,
        bus: &mut Bus,
        name: &str,
        runtime: RuntimeKind,
        instance: Option<&PluginInstance>,
        now: u64,
    ) -> Result<PluginState> {
        // Stopping first means no new work is accepted while the teardown runs.
        if let Some(entry) = registry.get_mut(name) {
            if entry.state() == PluginState::Running {
                entry
                    .lifecycle
                    .transition(PluginState::Stopping, "unload requested", now)?;
            }
        }
        if let Some(runtime) = self.runtimes.get(&runtime) {
            if let Some(instance) = instance {
                runtime.stop(instance)?;
            }
        }
        bus.deregister(name);
        if let Some(entry) = registry.get_mut(name) {
            if entry.state() == PluginState::Stopping {
                entry
                    .lifecycle
                    .transition(PluginState::Stopped, "instance released", now)?;
            }
            entry
                .lifecycle
                .transition(PluginState::Archived, "retired", now)?;
            return Ok(entry.state());
        }
        Err(PluginError::Manifest(format!("`{name}` is not registered")))
    }
}

/// The largest limits a tier may hold.
///
/// The per-tier numbers are the ones `docs/PLUGIN-ARCHITECTURE.md` §10 states, kept
/// here as the single source so a document and a constant cannot drift.
#[must_use]
pub fn tier_ceiling(tier: Tier) -> Limits {
    match tier {
        Tier::System => Limits {
            memory_bytes: u64::MAX,
            cpu_ms: u64::MAX,
            disk_bytes: u64::MAX,
            max_processes: u32::MAX,
            max_output_bytes: u32::MAX,
        },
        Tier::Official => Limits {
            memory_bytes: 512 * 1024 * 1024,
            cpu_ms: 60_000,
            disk_bytes: 1024 * 1024 * 1024,
            max_processes: 8,
            max_output_bytes: 1024 * 1024,
        },
        Tier::Certified => Limits {
            memory_bytes: 256 * 1024 * 1024,
            cpu_ms: 30_000,
            disk_bytes: 512 * 1024 * 1024,
            max_processes: 4,
            max_output_bytes: 512 * 1024,
        },
        Tier::ThirdParty => Limits {
            memory_bytes: 128 * 1024 * 1024,
            cpu_ms: 10_000,
            disk_bytes: 256 * 1024 * 1024,
            max_processes: 2,
            max_output_bytes: 256 * 1024,
        },
        Tier::Blacklisted => Limits {
            memory_bytes: 1,
            cpu_ms: 1,
            disk_bytes: 1,
            max_processes: 1,
            max_output_bytes: 1,
        },
    }
}

/// Which runtime a tier must run on.
///
/// Total over the tiers, and deliberately not configurable: letting an operator run
/// a third-party plugin in-process would make the isolation a preference rather than
/// a property of the tier.
#[must_use]
pub fn runtime_for_tier(tier: Tier) -> RuntimeKind {
    if tier.runs_in_process() {
        RuntimeKind::Native
    } else {
        RuntimeKind::Process
    }
}

/// Map an error to the refusal it represents.
fn refusal_of(error: &PluginError) -> LoadRefusal {
    let text = error.to_string();
    for refusal in [
        LoadRefusal::NameInvalid,
        LoadRefusal::ManifestInvalid,
        LoadRefusal::SignatureInvalid,
        LoadRefusal::UntrustedPublisher,
        LoadRefusal::CounterSignatureMissing,
        LoadRefusal::ModuleDigestMismatch,
        LoadRefusal::Blacklisted,
        LoadRefusal::CapabilityNotPermitted,
        LoadRefusal::CapabilityNotApproved,
        LoadRefusal::IsolationNotEnforceable,
        LoadRefusal::DependencyUnsatisfied,
        LoadRefusal::AbiIncompatible,
    ] {
        if text.contains(refusal.code()) {
            return refusal;
        }
    }
    match error {
        PluginError::Signature(_) => LoadRefusal::SignatureInvalid,
        PluginError::Blacklist(_) => LoadRefusal::Blacklisted,
        PluginError::Capability(_) => LoadRefusal::CapabilityNotPermitted,
        PluginError::Runtime(_) => LoadRefusal::IsolationNotEnforceable,
        // A name that does not classify is its own refusal, not "the manifest is invalid".
        // The two tell an operator different things -- fix the name, versus fix the document
        // -- and folding them together left `name_invalid` in the vocabulary with no pipeline
        // stage able to produce it. That was reported by the system plugin that reads the
        // vocabulary, which found two codes nothing could emit.
        PluginError::Name(_) => LoadRefusal::NameInvalid,
        PluginError::Tier(_) | PluginError::Manifest(_) => LoadRefusal::ManifestInvalid,
        _ => LoadRefusal::ManifestInvalid,
    }
}

/// First 12 characters of a hex string.
fn short(s: &str) -> &str {
    &s[..s.len().min(12)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blacklist::Blacklist;
    use crate::bus::BusLimits;
    use crate::runtime::{NativeRuntime, ProcessRuntime};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;

    const NOW: u64 = 1_750_000_000;

    fn module() -> Vec<u8> {
        b"#!/bin/sh\nexit 0\n".to_vec()
    }

    /// The executable this test process is running: an entry path that exists.
    fn entry() -> PathBuf {
        std::env::current_exe().expect("current exe")
    }

    fn limits() -> Limits {
        Limits {
            memory_bytes: 64 * 1024 * 1024,
            cpu_ms: 5_000,
            disk_bytes: 8 * 1024 * 1024,
            max_processes: 2,
            max_output_bytes: 32 * 1024,
        }
    }

    /// Build a signed manifest document. `tier_prefix` decides the tier; `counter`
    /// adds a vendor counter-signature.
    fn manifest_json(
        name: &str,
        caps: &[&str],
        publisher: &SigningKey,
        vendor: Option<&SigningKey>,
        waivers: &[(&str, &str)],
    ) -> String {
        manifest_json_at_abi(name, caps, publisher, vendor, waivers, &host_abi())
    }

    /// The same, with dependencies declared — and re-signed, because the digest covers them.
    ///
    /// The other builders have no parameter for edges, which is why the ordering tests need
    /// their own: a manifest signed without the edges and given them afterwards would fail
    /// verification, so the declaration has to be in place **before** the signature. That is the
    /// same property the schema test pins from the other side.
    fn manifest_json_depending_on(
        name: &str,
        caps: &[&str],
        publisher: &SigningKey,
        vendor: Option<&SigningKey>,
        waivers: &[(&str, &str)],
        dependencies: &[(&str, &str)],
    ) -> String {
        let text = manifest_json(name, caps, publisher, vendor, waivers);
        let mut m: Manifest = serde_json::from_str(&text).expect("the fixture parses");
        m.dependencies = dependencies
            .iter()
            .map(|(n, v)| Dependency {
                name: (*n).to_string(),
                min_version: (*v).to_string(),
            })
            .collect();
        m.signature.manifest_digest = m.digest_hex().expect("digest");
        let digest = m.signature.manifest_digest.clone();
        m.signature.sig = hex::encode(publisher.sign(digest.as_bytes()).to_bytes());
        if let Some(vendor) = vendor {
            m.signature.counter_sig = Some(hex::encode(vendor.sign(digest.as_bytes()).to_bytes()));
            m.signature.counter_key = Some(hex::encode(vendor.verifying_key().to_bytes()));
        }
        serde_json::to_string(&m).expect("serialise")
    }

    /// The ABI a current plugin declares.
    fn host_abi() -> String {
        format!("{}.{}", crate::ABI_MAJOR, crate::ABI_MINOR)
    }

    /// The same, at an ABI of the caller's choosing — for the compatibility tests.
    fn manifest_json_at_abi(
        name: &str,
        caps: &[&str],
        publisher: &SigningKey,
        vendor: Option<&SigningKey>,
        waivers: &[(&str, &str)],
        abi: &str,
    ) -> String {
        let module_digest = hex::encode(sha2::Sha256::digest(module()));
        let waiver_map: BTreeMap<String, String> = waivers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let mut m = Manifest {
            plugin: crate::manifest::PluginSection {
                name: name.to_string(),
                // The plugin's own version, not the kernel's.
                version: "1.4.0".into(),
                abi: abi.to_string(),
                entry: "plugin.bin".into(),
                publisher: "did:nau:0011223344556677".into(),
                module_sha256: module_digest,
            },
            capabilities: crate::manifest::CapabilitySection {
                grant: caps.iter().map(|s| (*s).to_string()).collect(),
            },
            limits: limits(),
            waivers: waiver_map,
            dependencies: Vec::new(),
            // A-11: the class this manifest runs at. Stated explicitly here rather than
            // relying on serde's default, so that adding the field is a decision this
            // construction site made rather than a value it inherited.
            priority: crate::manifest::PriorityClass::LatencyTolerant,
            signature: crate::manifest::SignatureSection {
                publisher_key: hex::encode(publisher.verifying_key().to_bytes()),
                manifest_digest: String::new(),
                sig: String::new(),
                counter_sig: None,
                counter_key: None,
            },
        };
        m.signature.manifest_digest = m.digest_hex().expect("digest");
        let digest = m.signature.manifest_digest.clone();
        m.signature.sig = hex::encode(publisher.sign(digest.as_bytes()).to_bytes());
        if let Some(vendor) = vendor {
            m.signature.counter_sig = Some(hex::encode(vendor.sign(digest.as_bytes()).to_bytes()));
            m.signature.counter_key = Some(hex::encode(vendor.verifying_key().to_bytes()));
        }
        serde_json::to_string(&m).expect("serialise")
    }

    /// Every boundary the process runtime leaves unenforced, waived with a test reason.
    ///
    /// Derived from the runtime's own declaration rather than a hand-written list. The
    /// previous version named five keys literally; A-02 added four boundaries, and that
    /// list silently became incomplete, so every arbiter test failed with
    /// `IsolationNotEnforceable` while the code under test was correct. A fixture that
    /// asks the runtime what it lacks cannot go stale when the runtime changes.
    fn waivers() -> Vec<(&'static str, &'static str)> {
        let declared = ProcessRuntime::new();
        let caps = declared.declares();
        caps.unenforced()
            .into_iter()
            .map(|(boundary, _why)| {
                (
                    boundary.waiver_key(),
                    "test: accepted for this fixture, the boundary is not under test here",
                )
            })
            .collect()
    }

    fn arbiter(trust: TrustStore) -> Arbiter {
        Arbiter::new(trust, Blacklist::new())
            .with_runtime(Box::new(NativeRuntime::new()))
            .with_runtime(Box::new(ProcessRuntime::new()))
    }

    fn stores() -> (Registry, Bus) {
        (
            Registry::new(),
            Bus::new(BusLimits::default()).expect("bus"),
        )
    }

    #[test]
    fn an_official_plugin_loads_end_to_end_and_the_trace_names_every_stage() {
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        let json = manifest_json(
            "com.twinsearth.official.market",
            &["plugin:message:send", "plugin:storage:own"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );

        let loaded = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect("loads");

        assert_eq!(loaded.tier, Tier::Official);
        assert_eq!(loaded.runtime, RuntimeKind::Process);
        assert_eq!(loaded.state, PluginState::Running);
        assert_eq!(loaded.granted.len(), 2);
        let steps: Vec<&str> = loaded.trace.iter().map(|s| s.step).collect();
        assert_eq!(
            steps,
            [
                "parse",
                "blacklist",
                "verify",
                "certification",
                "compat",
                "limits",
                "runtime",
                "lifecycle"
            ],
            "the compat stage sits between authenticity and the tier ceiling: a manifest is \
             first proven authentic, then either served or refused"
        );
        assert!(loaded.trace.iter().all(|s| s.passed));

        // State is consistent across the three places it lives.
        assert_eq!(
            registry
                .get("com.twinsearth.official.market")
                .expect("registered")
                .state(),
            PluginState::Running
        );
        assert!(bus.token("com.twinsearth.official.market").is_some());
        assert_eq!(
            registry.load_order().expect("order"),
            vec!["com.twinsearth.official.market"]
        );
    }

    #[test]
    fn a_system_plugin_uses_the_native_runtime() {
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        let json = manifest_json(
            "com.twinsearth.sys.identity",
            &["plugin:message:send", "kernel:policy:write"],
            &publisher,
            Some(&vendor),
            &[],
        );
        let loaded = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect("loads");
        assert_eq!(loaded.runtime, RuntimeKind::Native);
        // The native runtime needs no waivers: it enforces nothing, which is the
        // point of it being the kernel's own runtime.
        assert!(loaded.granted.contains(&Capability::KernelPolicyWrite));
    }

    #[test]
    fn a_blacklisted_plugin_is_refused_before_verification() {
        use crate::blacklist::{BlacklistEntry, BlacklistReason};
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");

        let mut entry_value = BlacklistEntry {
            plugin_name: "io.example.bad".into(),
            module_sha256: Some(hex::encode(sha2::Sha256::digest(module()))),
            reason: BlacklistReason::Malware,
            blacklisted_at: NOW,
            evidence_cid: "bafyevidence".into(),
            signer_key: hex::encode(vendor.verifying_key().to_bytes()),
            signature: String::new(),
        };
        entry_value.signature = hex::encode(vendor.sign(&entry_value.signing_bytes()).to_bytes());
        let mut blacklist = Blacklist::new();
        blacklist.add(entry_value, &trust).expect("added");

        let a = Arbiter::new(trust, blacklist)
            .with_runtime(Box::new(NativeRuntime::new()))
            .with_runtime(Box::new(ProcessRuntime::new()));
        let (mut registry, mut bus) = stores();
        // The manifest is otherwise perfectly valid and correctly signed: the
        // blacklist alone must stop it, and it must stop it before verification.
        let json = manifest_json(
            "io.example.bad",
            &["plugin:message:send"],
            &publisher,
            None,
            &waivers(),
        );
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("refused");
        assert_eq!(failure.refusal, LoadRefusal::Blacklisted);
        let steps: Vec<&str> = failure.trace.iter().map(|s| s.step).collect();
        assert_eq!(
            steps,
            ["parse", "blacklist"],
            "verification must not have run"
        );
        assert!(failure.summary().starts_with("blacklisted"));
    }

    #[test]
    fn an_untrusted_third_party_publisher_is_refused_at_verification() {
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let a = arbiter(TrustStore::deny_all());
        let (mut registry, mut bus) = stores();
        let json = manifest_json(
            "io.example.analytics",
            &["plugin:message:send"],
            &publisher,
            None,
            &waivers(),
        );
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("refused");
        assert_eq!(failure.refusal, LoadRefusal::UntrustedPublisher);
        assert_eq!(failure.trace.last().expect("last").step, "verify");
    }

    #[test]
    fn a_plugin_that_waived_nothing_is_refused_by_the_runtime_with_the_boundary_names() {
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_third_party_key(&hex::encode(publisher.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        let json = manifest_json(
            "io.example.analytics",
            &["plugin:message:send"],
            &publisher,
            None,
            &[],
        );
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("refused");
        assert_eq!(failure.refusal, LoadRefusal::IsolationNotEnforceable);
        assert!(
            failure.detail.contains("network_deny"),
            "{}",
            failure.detail
        );
        assert!(failure.detail.contains("disk_quota"), "{}", failure.detail);
        assert_eq!(failure.trace.last().expect("last").step, "runtime");
    }

    #[test]
    fn a_refused_load_leaves_no_trace_in_the_registry_or_the_bus() {
        // The failure mode this pins: a phantom registry entry or a token on the bus
        // for a plugin that never started -- which the next load would trip over.
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_third_party_key(&hex::encode(publisher.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();

        // Refused at the runtime stage.
        let json = manifest_json(
            "io.example.analytics",
            &["plugin:message:send"],
            &publisher,
            None,
            &[],
        );
        assert!(a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW
            )
            .is_err());
        assert!(registry.is_empty(), "the registry must be untouched");
        assert!(
            bus.token("io.example.analytics").is_none(),
            "the bus must be untouched"
        );

        // Refused at the dependency stage, after the runtime already started.
        let json = manifest_json(
            "io.example.analytics",
            &["plugin:message:send"],
            &publisher,
            None,
            &waivers(),
        );
        let req = LoadRequest::new(json, module(), entry()).depending_on(vec![Dependency {
            name: "com.twinsearth.sys.absent".into(),
            min_version: "1.0.0".into(),
        }]);
        let failure = a
            .load(&mut registry, &mut bus, &req, NOW)
            .expect_err("refused");
        assert_eq!(failure.refusal, LoadRefusal::DependencyUnsatisfied);
        assert!(registry.is_empty(), "the registry must be rolled back");
        assert!(
            bus.token("io.example.analytics").is_none(),
            "the bus must be rolled back"
        );
    }

    #[test]
    fn a_tier_with_no_registered_runtime_is_refused_rather_than_run_in_process() {
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_third_party_key(&hex::encode(publisher.verifying_key().to_bytes()))
            .expect("trust");
        // Only a native runtime: a third-party plugin must not fall back to it.
        let a = Arbiter::new(trust, Blacklist::new()).with_runtime(Box::new(NativeRuntime::new()));
        let (mut registry, mut bus) = stores();
        let json = manifest_json(
            "io.example.analytics",
            &["plugin:message:send"],
            &publisher,
            None,
            &waivers(),
        );
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("refused");
        assert_eq!(failure.refusal, LoadRefusal::IsolationNotEnforceable);
        assert!(failure.detail.contains("process"), "{}", failure.detail);
    }

    #[test]
    fn limits_above_the_tier_ceiling_are_clamped_and_the_clamping_is_recorded() {
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let third_ceiling = tier_ceiling(Tier::ThirdParty);
        assert!(limits().memory_bytes <= third_ceiling.memory_bytes);
        // Official's ceiling is larger than the fixture asks for, so nothing clamps
        // there; the interesting case is a tier whose ceiling is smaller.
        assert!(tier_ceiling(Tier::Official).memory_bytes > limits().memory_bytes);

        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        let json = manifest_json(
            "com.twinsearth.official.market",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        let loaded = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect("loads");
        let limits_step = loaded
            .trace
            .iter()
            .find(|s| s.step == "limits")
            .expect("step");
        assert_eq!(limits_step.outcome, "within the tier ceiling");
    }

    #[test]
    fn the_tier_ceilings_match_the_documented_matrix_and_are_ordered() {
        let sys = tier_ceiling(Tier::System);
        let official = tier_ceiling(Tier::Official);
        let certified = tier_ceiling(Tier::Certified);
        let third = tier_ceiling(Tier::ThirdParty);
        assert_eq!(official.memory_bytes, 512 * 1024 * 1024);
        assert_eq!(certified.memory_bytes, 256 * 1024 * 1024);
        assert_eq!(third.memory_bytes, 128 * 1024 * 1024);
        // Trust must be monotone in the ceiling, or a lower tier could ask for more.
        assert!(sys.memory_bytes >= official.memory_bytes);
        assert!(official.memory_bytes >= certified.memory_bytes);
        assert!(certified.memory_bytes >= third.memory_bytes);
        assert!(sys.max_processes >= official.max_processes);
        assert!(official.max_processes >= certified.max_processes);
        assert!(certified.max_processes >= third.max_processes);
    }

    #[test]
    fn the_runtime_choice_is_a_property_of_the_tier_not_a_preference() {
        assert_eq!(runtime_for_tier(Tier::System), RuntimeKind::Native);
        for tier in [Tier::Official, Tier::Certified, Tier::ThirdParty] {
            assert_eq!(runtime_for_tier(tier), RuntimeKind::Process, "{tier}");
        }
    }

    #[test]
    fn unloading_retires_a_running_plugin_and_frees_its_registration() {
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        let json = manifest_json(
            "com.twinsearth.official.market",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        let loaded = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect("loads");
        let state = a
            .unload(
                &mut registry,
                &mut bus,
                loaded.id.as_str(),
                loaded.runtime,
                loaded.instance.as_ref(),
                NOW + 1,
            )
            .expect("unloads");
        assert_eq!(state, PluginState::Archived);
        assert!(bus.token(loaded.id.as_str()).is_none());
        // Archived is terminal: the entry stays for the audit trail but cannot run.
        assert_eq!(
            registry
                .get(loaded.id.as_str())
                .expect("still registered")
                .state(),
            PluginState::Archived
        );
    }

    #[test]
    fn a_malformed_document_is_refused_at_parse_with_no_side_effects() {
        let a = arbiter(TrustStore::deny_all());
        let (mut registry, mut bus) = stores();
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new("{ not json", module(), entry()),
                NOW,
            )
            .expect_err("refused");
        assert_eq!(failure.refusal, LoadRefusal::ManifestInvalid);
        assert_eq!(failure.trace.len(), 1);
        assert!(!failure.trace[0].passed);
        assert!(registry.is_empty() && bus.token("x").is_none());
    }

    #[test]
    fn three_authority_violations_at_the_bus_quarantine_the_sender() {
        // The join between two rules that were separately true and jointly unenforced:
        // the bus refuses an over-reaching message, and the lifecycle quarantines on the
        // third violation. Before `send_checked` existed, nothing connected them and the
        // rule was a sentence in a document.
        use crate::bus::{PmbKind, PmbMessage, Target};

        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        let name = "com.twinsearth.official.market";
        let json = manifest_json(
            name,
            &["plugin:message:send", "plugin:storage:own"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        let loaded = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect("loads");
        assert_eq!(loaded.state, PluginState::Running);

        // Three messages that claim to come from a plugin the token does not belong to.
        // This is a forgery, so each one is a violation as well as a refusal.
        let mut quarantined_at = None;
        for attempt in 0..3u64 {
            let forged = PmbMessage::new(
                &PluginId::parse("io.example.other").expect("id"),
                Target::Host,
                Capability::MessageSend,
                PmbKind::Event,
                serde_json::json!({}),
                NOW,
            );
            // Bound before the call: `send_checked` needs a mutable registry, so the
            // token cannot be fetched inside the same expression.
            let token = loaded_token(&registry, name);
            let err = bus
                .send_checked(&mut registry, &token, &forged, NOW * 1_000 + attempt)
                .expect_err("a forged source must be refused");
            assert!(err.to_string().contains("bus_source_forged"), "{err}");
            let state = registry.get(name).expect("registered").state();
            if state == PluginState::Quarantined {
                quarantined_at = Some(attempt + 1);
                break;
            }
        }
        assert_eq!(
            quarantined_at,
            Some(3),
            "the third authority violation must quarantine, not the first or second"
        );
        assert_eq!(
            registry.get(name).expect("registered").state(),
            PluginState::Quarantined
        );
        // The refusal still stands: escalation is an addition, never a replacement.
        let eligible = PmbMessage::new(
            &PluginId::parse(name).expect("id"),
            Target::Host,
            Capability::MessageSend,
            PmbKind::Event,
            serde_json::json!({}),
            NOW,
        );
        // A quarantined plugin holds nothing and is not running, so even a message that
        // would otherwise be fine is refused -- and refused for the state, not for the
        // capability, which is what tells an operator the plugin was already stopped.
        let token = loaded_token(&registry, name);
        let err = bus
            .send_checked(&mut registry, &token, &eligible, NOW * 1_000 + 9)
            .expect_err("a quarantined plugin is not running");
        assert!(err.to_string().contains("bus_sender_not_running"), "{err}");
    }

    /// The token a loaded plugin holds, for presenting to the bus.
    fn loaded_token(registry: &Registry, name: &str) -> crate::capability::CapabilityToken {
        registry
            .get(name)
            .expect("registered")
            .verified
            .token
            .clone()
    }

    #[test]
    fn an_official_plugin_can_hold_a_reviewed_capability_only_with_the_right_authority() {
        // The end-to-end version of the reachability fix. `economy:settle` at the official
        // tier is `RequiresApproval(VendorTeam)`: expressible in the matrix since the
        // capability module was written, and unreachable from a load until the arbiter
        // could pass approvals into verification. All three outcomes are asserted, because
        // "it loads when approved" alone would pass even if the approval were ignored.
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let name = "com.twinsearth.official.market";
        let json = manifest_json(
            name,
            &["plugin:message:send", "economy:settle"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );

        // 1. no approval: refused, and the refusal names the authority.
        let bare = arbiter(trust.clone());
        let (mut r1, mut b1) = stores();
        let failure = bare
            .load(
                &mut r1,
                &mut b1,
                &LoadRequest::new(json.clone(), module(), entry()),
                NOW,
            )
            .expect_err("an unapproved capability must be refused");
        // `CapabilityNotApproved`, not `CapabilityNotPermitted`: the capability *is*
        // permitted at this tier, it simply has not been approved yet, and an operator who
        // sees the wrong code asks the wrong question. Distinguishing them is also what
        // made the code reachable at all -- it was in the vocabulary and nothing emitted it.
        assert_eq!(failure.refusal, LoadRefusal::CapabilityNotApproved);
        assert!(failure.detail.contains("vendor-team"), "{}", failure.detail);

        // 2. the wrong authority: still refused. An operator cannot stand in for the team
        //    whose review is the reason the tier is trusted.
        let wrong = arbiter(trust.clone()).with_approval(
            name,
            Capability::EconomySettle,
            Approval::Operator,
        );
        let (mut r2, mut b2) = stores();
        let failure = wrong
            .load(
                &mut r2,
                &mut b2,
                &LoadRequest::new(json.clone(), module(), entry()),
                NOW,
            )
            .expect_err("the wrong authority must not grant it");
        assert!(
            failure.detail.contains("different authority"),
            "{}",
            failure.detail
        );

        // 3. the right authority: it loads, and the token records who let it through.
        let approved =
            arbiter(trust).with_approval(name, Capability::EconomySettle, Approval::VendorTeam);
        let (mut r3, mut b3) = stores();
        let loaded = approved
            .load(
                &mut r3,
                &mut b3,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect("an approved capability must load");
        assert!(loaded.granted.contains(&Capability::EconomySettle));
        let token = &r3.get(name).expect("registered").verified.token;
        assert!(token
            .approvals()
            .contains(&(Capability::EconomySettle, Approval::VendorTeam)));
    }

    #[test]
    fn an_approval_for_one_plugin_does_not_authorise_another() {
        // The approvals are keyed by name for this reason. A flat list applied at every
        // load would let a review of plugin A authorise plugin B's capability request,
        // which is the kind of quiet widening that never shows up in a happy-path test.
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust).with_approval(
            "com.twinsearth.official.other",
            Capability::EconomySettle,
            Approval::VendorTeam,
        );
        let (mut registry, mut bus) = stores();
        let json = manifest_json(
            "com.twinsearth.official.market",
            &["economy:settle"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("an approval for another plugin must not apply");
        // Also `CapabilityNotApproved`: from this plugin's point of view the approval simply
        // is not there, which is the same situation as never having asked.
        assert_eq!(failure.refusal, LoadRefusal::CapabilityNotApproved);
        assert!(
            failure.detail.contains("vendor-team"),
            "the refusal must still name who has to approve: {}",
            failure.detail
        );
    }

    #[test]
    fn a_name_that_does_not_classify_is_refused_as_a_name_not_as_a_manifest() {
        // The other code that was in the vocabulary with nothing able to emit it. A name
        // that does not classify and a document that is malformed are different problems,
        // and the operator's next action differs: fix the name, or fix the document.
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        // A name with no dot: not a reverse-domain name, so the classifier refuses it before
        // any of the four checks run.
        let json = manifest_json(
            "nodots",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("an unclassifiable name must be refused");
        assert_eq!(
            failure.refusal,
            LoadRefusal::NameInvalid,
            "detail: {}",
            failure.detail
        );
    }

    /// A review walked to `certified`, which is what a `Certification` must come from.
    fn certified_review(plugin: &str) -> crate::certify::Review {
        let mut review =
            crate::certify::Review::open(plugin, "did:nau:0011223344556677", 1_750_000_000)
                .expect("a review opens");
        for (stage, because, at) in [
            (crate::certify::ReviewStage::AutoScanned, "scanned", 1),
            (crate::certify::ReviewStage::ManualReview, "read", 2),
            (crate::certify::ReviewStage::GreyRun, "trialled", 3),
            (crate::certify::ReviewStage::Certified, "approved", 4),
        ] {
            review
                .advance(stage, because, 1_750_000_000 + at)
                .expect("the stage order is the kernel's");
        }
        review
    }

    #[test]
    fn a_certification_scope_refuses_a_capability_the_review_never_covered() {
        // **The property `certify.rs` exists for, and the one nothing checked before.**
        //
        // The manifest is authentic: the publisher signed it and a trusted vendor
        // counter-signed it, so `verify` passes and the capabilities it asks for are ones the
        // certified tier may hold without further approval. What refuses it is the
        // certification's scope -- the vendor signed *this document*, but the review only
        // ever looked at a narrower set of capabilities.
        //
        // `require_within_scope` was written and unit-tested for exactly this and was called
        // by nothing but its own tests, so a certified plugin could hold anything its
        // counter-signature allowed. This test is the caller.
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let name = "com.twinsearth.certified.analytics";

        // The review certified only `plugin:message:send`.
        let certification = crate::certify::Certification::issue(
            &certified_review(name),
            &[Capability::MessageSend],
            Tier::Certified,
            &hex::encode(vendor.verifying_key().to_bytes()),
            1_750_000_010,
        )
        .expect("the review is certified");

        // The manifest also asks for `lifecycle:read`, which the review never covered.
        let json = manifest_json(
            name,
            &["plugin:message:send", "plugin:lifecycle:read"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        let a = arbiter(trust).with_certification(certification);
        let (mut registry, mut bus) = stores();
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("a capability outside the certified scope must be refused");
        assert_eq!(failure.refusal, LoadRefusal::CapabilityNotPermitted);
        assert!(
            failure.detail.contains("plugin:lifecycle:read"),
            "the refusal must name the capability the review did not cover: {}",
            failure.detail
        );
        assert!(
            failure.detail.contains("did not review"),
            "the refusal must say the review is what is missing, not the signature: {}",
            failure.detail
        );
        // And the trace shows it got as far as authenticating the manifest: this is a
        // scope refusal, not a signature one, and a trace that did not say so would send an
        // operator to the wrong document.
        assert!(
            failure.trace.iter().any(|s| s.step == "verify" && s.passed),
            "the manifest is authentic; the scope is what refused it: {:?}",
            failure.trace
        );
    }

    #[test]
    fn a_certified_plugin_inside_its_scope_loads() {
        // The other half. Without this, the test above would pass on a check that refuses
        // everything, which is not enforcement.
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let name = "com.twinsearth.certified.analytics";
        let certification = crate::certify::Certification::issue(
            &certified_review(name),
            &[Capability::MessageSend, Capability::LifecycleRead],
            Tier::Certified,
            &hex::encode(vendor.verifying_key().to_bytes()),
            1_750_000_010,
        )
        .expect("the review is certified");

        let json = manifest_json(
            name,
            &["plugin:message:send", "plugin:lifecycle:read"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        let a = arbiter(trust).with_certification(certification);
        let (mut registry, mut bus) = stores();
        let loaded = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect("a manifest inside its certified scope loads");
        assert_eq!(loaded.tier, Tier::Certified);
        assert!(
            loaded.trace.iter().any(|s| s.step == "certification"),
            "the certification step must appear in the trace: {:?}",
            loaded.trace
        );
    }

    #[test]
    fn a_certified_plugin_with_no_certification_is_refused_by_its_own_code() {
        // The tier's defining requirement, checked at load for the first time: the tier is
        // called "certified", and until now nothing asked for the certification.
        //
        // The refusal code is `certification_missing` and not `counter_signature_missing`,
        // because the counter-signature **is** present. Telling an operator the wrong
        // document is missing is how an hour gets spent looking at the right file.
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let json = manifest_json(
            "com.twinsearth.certified.analytics",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("a certified plugin needs a certification");
        assert_eq!(failure.refusal, LoadRefusal::CertificationMissing);
        assert_eq!(failure.refusal.code(), "certification_missing");
        assert!(
            failure
                .detail
                .contains("counter-signature proves the vendor signed the manifest"),
            "the refusal must draw the distinction it is making: {}",
            failure.detail
        );
    }

    /// A request takes its edges from the manifest it carries.
    ///
    /// # Why this is asserted rather than assumed
    ///
    /// The edges used to be `Vec::new()` unconditionally, so **no** load ever produced a
    /// registry with an edge, and the dependency machinery had nothing to sort. This is the
    /// one line that turns a manifest's declaration into the registry's graph, and a change
    /// that quietly reverted it would leave every other test green — an order over no edges
    /// looks exactly like an order over edges that happen to be satisfied.
    #[test]
    fn a_request_takes_its_dependencies_from_the_manifest_it_carries() {
        let json = r#"{"dependencies":[{"name":"io.example.a","min_version":"1.2.0"}]}"#;
        let request = LoadRequest::new(json, Vec::new(), PathBuf::from("/tmp/plugin.bin"));
        assert_eq!(
            request.dependencies.len(),
            1,
            "the declared edge must survive"
        );
        assert_eq!(request.dependencies[0].name, "io.example.a");
        assert_eq!(request.dependencies[0].min_version, "1.2.0");

        // A manifest with no section declares nothing, which is the case for every plugin this
        // build ships.
        let none = LoadRequest::new(
            r#"{"plugin":{"name":"io.example.a"}}"#,
            Vec::new(),
            PathBuf::from("/tmp/plugin.bin"),
        );
        assert!(none.dependencies.is_empty());

        // A section that is not a list of dependencies yields **no** edges rather than a guess.
        // The pipeline's own `parse` stage deserialises the whole manifest with
        // `deny_unknown_fields`, so a shape this forgiving extraction skips is refused there
        // rather than loaded here.
        let malformed = LoadRequest::new(
            r#"{"dependencies":"not-a-list"}"#,
            Vec::new(),
            PathBuf::from("/tmp/plugin.bin"),
        );
        assert!(malformed.dependencies.is_empty());
    }

    /// A declared dependency is **ordered** before its dependent, through the real pipeline.
    ///
    /// # Why this is the test the dependency feature needed
    ///
    /// `LoadRequest::new` is where a manifest's declaration becomes a graph edge, and the test
    /// above it only asserts the extraction. This one drives two real loads through the whole
    /// pipeline — parse, blacklist, verify, certification, compat, limits, runtime, registry —
    /// and then asks the registry whose order `HotPlug` and `sys.orchestrator` report. Without
    /// it the mechanism could be complete and still never have ordered anything.
    #[test]
    fn a_declared_dependency_is_ordered_before_its_dependent() {
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();

        let base = manifest_json(
            "com.twinsearth.official.dependency",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        a.load(
            &mut registry,
            &mut bus,
            &LoadRequest::new(base, module(), entry()),
            NOW,
        )
        .expect("the dependency loads");

        let dependent = manifest_json_depending_on(
            "com.twinsearth.official.dependent",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
            &[("com.twinsearth.official.dependency", "1.0.0")],
        );
        let request = LoadRequest::new(dependent, module(), entry());
        assert_eq!(
            request.dependencies.len(),
            1,
            "the declaration must reach the request, or no load will ever produce an edge"
        );
        a.load(&mut registry, &mut bus, &request, NOW)
            .expect("the dependent loads once its dependency is registered");

        let order = registry.load_order().expect("the graph has no cycle");
        let position = |name: &str| {
            order
                .iter()
                .position(|n| n == name)
                .unwrap_or_else(|| panic!("`{name}` must be in the order: {order:?}"))
        };
        assert!(
            position("com.twinsearth.official.dependency")
                < position("com.twinsearth.official.dependent"),
            "a declared dependency must come first: {order:?}"
        );
    }

    /// A declaration the registry cannot satisfy is **refused**, not recorded and ignored.
    ///
    /// The registry orders edges; an edge pointing at nothing is a broken graph, and a plugin
    /// that needs something which is not there must not reach `Running` on the strength of
    /// having written the requirement down.
    #[test]
    fn a_dependency_that_is_not_registered_is_refused() {
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();

        let orphan = manifest_json_depending_on(
            "com.twinsearth.official.orphan",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
            &[("com.twinsearth.official.absent", "1.0.0")],
        );
        let refused = a.load(
            &mut registry,
            &mut bus,
            &LoadRequest::new(orphan, module(), entry()),
            NOW,
        );
        let failure = refused.expect_err("a dependency on nothing must be refused");
        assert!(
            failure.detail.contains("absent"),
            "the refusal must name the dependency that is missing: {}",
            failure.detail
        );
    }

    #[test]
    fn a_plugin_at_this_hosts_own_abi_loads_directly() {
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        let json = manifest_json(
            "com.twinsearth.official.market",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
        );
        let loaded = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect("loads");
        assert_eq!(loaded.compat, Compat::Direct);
        let steps: Vec<&str> = loaded.trace.iter().map(|s| s.step).collect();
        assert_eq!(
            steps,
            [
                "parse",
                "blacklist",
                "verify",
                "certification",
                "compat",
                "limits",
                "runtime",
                "lifecycle"
            ]
        );
    }

    #[test]
    fn an_older_abi_is_refused_when_the_host_has_registered_no_adapter() {
        // The fail-closed default. The manifest is perfectly authentic; the host simply
        // cannot serve its ABI, and says so with the adapters it does have (none).
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust);
        let (mut registry, mut bus) = stores();
        let json = manifest_json_at_abi(
            "com.twinsearth.official.market",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
            "2.2",
        );
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("must be refused");
        assert_eq!(failure.refusal, LoadRefusal::AbiIncompatible);
        assert!(
            failure.detail.contains("no adapter covers that step"),
            "{}",
            failure.detail
        );
        assert_eq!(failure.trace.last().expect("last").step, "compat");
        assert!(
            registry.is_empty(),
            "a compat refusal leaves nothing behind"
        );
    }

    #[test]
    fn an_older_abi_loads_through_the_shipped_adapter_and_the_trace_says_so() {
        // The same manifest as the test above, with one difference: this host decided to
        // carry the adapter. That decision -- not a code change -- is what makes a 2.x
        // plugin runnable on a 3.x host, and the load trace records which adapter did it.
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust).with_adapters(crate::hot::AdapterRegistry::with_shipped_adapters());
        let (mut registry, mut bus) = stores();
        let json = manifest_json_at_abi(
            "com.twinsearth.official.market",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
            "2.2",
        );
        let loaded = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect("a 2.x plugin loads through the adapter");
        assert_eq!(
            loaded.compat,
            Compat::Adapted {
                adapter: "abi-2-to-3".to_string(),
                from: crate::hot::Abi::new(2, 0),
            }
        );
        let compat_step = loaded
            .trace
            .iter()
            .find(|s| s.step == "compat")
            .expect("the compat stage is in the trace");
        assert!(
            compat_step.outcome.contains("abi-2-to-3"),
            "{}",
            compat_step.outcome
        );
        assert_eq!(loaded.state, PluginState::Running);
    }

    #[test]
    fn an_abi_from_the_future_is_refused_at_verification_not_at_compatibility() {
        // It cannot be adapted downwards, so there is nothing for the compat stage to
        // decide and the refusal happens earlier -- which is why the stage is *after*
        // verification rather than replacing part of it.
        let vendor = SigningKey::from_bytes(&[9u8; 32]);
        let publisher = SigningKey::from_bytes(&[7u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        let a = arbiter(trust).with_adapters(crate::hot::AdapterRegistry::with_shipped_adapters());
        let (mut registry, mut bus) = stores();
        let json = manifest_json_at_abi(
            "com.twinsearth.official.market",
            &["plugin:message:send"],
            &publisher,
            Some(&vendor),
            &waivers(),
            "4.0",
        );
        let failure = a
            .load(
                &mut registry,
                &mut bus,
                &LoadRequest::new(json, module(), entry()),
                NOW,
            )
            .expect_err("must be refused");
        assert_eq!(failure.refusal, LoadRefusal::AbiIncompatible);
        assert_eq!(
            failure.trace.last().expect("last").step,
            "parse",
            "a future ABI never reaches the compat stage -- `parse` validates the ABI shape \
             and refuses one from the future before anything else runs, which is earlier than \
             this test first assumed and strictly better"
        );
    }
}
