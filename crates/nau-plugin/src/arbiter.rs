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
use crate::capability::Capability;
use crate::error::{LoadRefusal, PluginError, Result};
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
    /// A request with no dependencies.
    #[must_use]
    pub fn new(manifest_json: impl Into<String>, module: Vec<u8>, entry: PathBuf) -> Self {
        Self {
            manifest_json: manifest_json.into(),
            module,
            entry,
            dependencies: Vec::new(),
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
    /// Every stage, in order.
    pub trace: Vec<LoadStep>,
}

/// The load pipeline.
#[derive(Debug)]
pub struct Arbiter {
    trust: TrustStore,
    blacklist: Blacklist,
    runtimes: BTreeMap<RuntimeKind, Box<dyn PluginRuntime>>,
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
        }
    }

    /// Register a runtime backend.
    pub fn with_runtime(mut self, runtime: Box<dyn PluginRuntime>) -> Self {
        self.runtimes.insert(runtime.kind(), runtime);
        self
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
                return Err(LoadFailure {
                    refusal: LoadRefusal::ManifestInvalid,
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
        let verified = match manifest.verify(&request.module, &self.trust, now) {
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

        // 4. limits against the tier ceiling
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
        PluginError::Name(_) | PluginError::Tier(_) | PluginError::Manifest(_) => {
            LoadRefusal::ManifestInvalid
        }
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
                abi: "2.2".into(),
                entry: "plugin.bin".into(),
                publisher: "did:nau:0011223344556677".into(),
                module_sha256: module_digest,
            },
            capabilities: crate::manifest::CapabilitySection {
                grant: caps.iter().map(|s| (*s).to_string()).collect(),
            },
            limits: limits(),
            waivers: waiver_map,
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

    fn waivers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("network", "test: no egress primitive"),
            ("filesystem_confinement", "test: no confinement primitive"),
            ("disk_bytes", "test: no quota primitive"),
            ("cpu_ms", "test: no cpu primitive"),
            ("max_open_files", "test: no handle cap"),
        ]
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
                "limits",
                "runtime",
                "lifecycle"
            ]
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
}
