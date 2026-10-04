//! Booting the compiled-in system plugins.
//!
//! # Why the manifests are signed at boot
//!
//! A T0 system plugin is compiled into this binary. It still goes through the same
//! door as a downloaded one: a manifest, a publisher signature, a vendor
//! counter-signature, a module digest, a capability token, a lifecycle. The
//! alternative — special-casing system plugins so they skip verification — would mean
//! the one code path that runs in the host's own address space is the one path with
//! no verification, which is backwards.
//!
//! So the host mints an **ephemeral** Ed25519 key pair at boot, signs each system
//! manifest in memory, verifies it against the ephemeral key, and registers the
//! plugin against the resulting token.
//!
//! # What that signature is, and is not
//!
//! It is a **structural** check: the manifest is well formed, the capability set the
//! plugin declares is exactly the set its token grants, and the module digest matches.
//! It is **not** an attestation of provenance across restarts — the vendor key exists
//! only in this process's memory, so nothing can be checked against it tomorrow. That
//! is the correct trade for code that is compiled into the same binary that verifies
//! it: shipping a private key inside the binary to sign itself would add a secret to
//! protect without adding a fact to check. A release-time signature over the whole
//! binary is the thing that would attest provenance, and that belongs to the release
//! process, not here.
//!
//! The refusal that *does* carry weight is the tier one: [`SystemPluginHost::register`]
//! refuses any manifest that is not [`Tier::System`], so a plugin from any other tier
//! cannot reach the in-process host by presenting a manifest.

use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use nau_plugin::bus::PmbMessage;
use nau_plugin::hot::HotPlug;
use nau_plugin::lifecycle::PluginState;
use nau_plugin::manifest::VerifiedManifest;
use nau_plugin::registry::Registry;
use nau_plugins::host::{standard_declarations, standard_plugins, HostLimits, SystemPluginHost};
use nau_plugins::sign;

/// A booted system-plugin host, with what it took to get there.
#[derive(Debug)]
pub struct SystemBoot {
    /// The host, with every plugin registered.
    pub host: SystemPluginHost,
    /// The registered names, in order.
    pub names: Vec<String>,
    /// The ephemeral vendor key's public half, as hex, for reporting.
    pub vendor_key_hex: String,
    /// The dependency graph the boot computed its start order from.
    ///
    /// Kept so a **stop** can be ordered as well as a start. It is the same registry the
    /// orchestrator reads through its port, shared rather than copied, so a plugin cannot see
    /// one graph and be stopped by another.
    registry: Arc<Registry>,
}

impl SystemBoot {
    /// How many plugins are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether nothing registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The lifecycle state of a plugin.
    #[must_use]
    pub fn state(&self, name: &str) -> Option<PluginState> {
        self.host.state(name)
    }

    /// Record a violation against a plugin, quarantining it on the third.
    ///
    /// C-03's behaviour, reached from where the police can reach it. The police observes and
    /// reports; **this** is where the report becomes a state change, because the lifecycles are
    /// here. See [`SystemPluginHost::record_violation`] for why a plugin cannot do it itself.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Lifecycle`] when `name` is not a registered plugin.
    pub fn record_violation(
        &mut self,
        name: &str,
        what: &str,
        at: u64,
    ) -> Result<PluginState, nau_plugin::PluginError> {
        self.host.record_violation(name, what, at)
    }

    /// How many violations a plugin has accumulated.
    #[must_use]
    pub fn violations(&self, name: &str) -> Option<u32> {
        self.host.violations(name)
    }

    /// Carry the bus messages a plugin queued, delivering each or reporting why not.
    ///
    /// The host answers "which plugins are running?" itself (the kernel's `BusMembership`),
    /// so this no longer needs a load registry the system tier does not appear in — which is
    /// what made the drain impossible to call before.
    ///
    /// # Errors
    ///
    /// A refusal when `name` is not a registered system plugin.
    pub fn flush_outbox(
        &mut self,
        name: &str,
        bus: &mut nau_plugin::bus::Bus,
        now_ms: u64,
    ) -> nau_plugin::Result<Vec<nau_plugins::host::OutboxOutcome>> {
        self.host.flush_outbox(name, bus, now_ms)
    }

    /// Stop every plugin, **dependents first**, and report each outcome.
    ///
    /// # The gap this closes
    ///
    /// The daemon has had a shutdown path since it gained a signal handler, and until now it
    /// did nothing to the plugins: seventeen of them ran and then the process exited.
    /// `SystemPluginHost::shutdown` existed and was called only from tests, and
    /// `HotPlug::stop_plan` — the function that computes which dependents must be paused before
    /// a plugin can be stopped safely — **had no caller anywhere in the repository**.
    ///
    /// # Why the order is computed rather than chosen
    ///
    /// Stopping something that another plugin still calls moves the failure somewhere else, and
    /// the whole reason `stop_plan` exists is that the caller cannot be trusted to work that
    /// out. With the graph this build ships the plan for each plugin is a single name, because
    /// no shipped plugin declares a dependency — so the order this produces is the reverse of
    /// the start order and nothing more. The point is that it is **computed from the graph the
    /// boot used**, so the day an edge exists the stop order is right without anyone editing
    /// this function.
    ///
    /// A plugin already `Stopped` is skipped rather than reported as a failure: stopping in the
    /// reverse of the start order visits a dependent before its dependency, and the dependency's
    /// own plan names the dependent again.
    pub fn shutdown(&mut self, now: u64) -> Vec<(String, Result<(), String>)> {
        let mut outcomes = Vec::new();
        for name in self.names.clone().into_iter().rev() {
            // The plan is the safe answer for this name: its dependents first, then it.
            let plan =
                HotPlug::stop_plan(&self.registry, &name).unwrap_or_else(|_| vec![name.clone()]);
            for target in plan {
                if self.host.state(&target) == Some(PluginState::Stopped) {
                    continue;
                }
                let outcome = self.host.shutdown(&target, now).map_err(|e| e.to_string());
                outcomes.push((target, outcome));
            }
        }
        outcomes
    }

    /// How many bus messages a plugin has queued and not yet sent.
    ///
    /// Exposed because the carrier is missing: nothing in the running node drains an outbox
    /// (see [`SystemPluginHost::outbox_len`]), so this number is the only evidence that a
    /// plugin tried to send something. A count that stays at zero and a count that grows are
    /// very different facts, and without this they look the same.
    #[must_use]
    pub fn outbox_len(&self, name: &str) -> Option<usize> {
        self.host.outbox_len(name)
    }

    /// Dispatch one message to a plugin and return its answer.
    ///
    /// # Errors
    ///
    /// Whatever the host reports: an unknown target, a plugin that is not running, or
    /// the plugin's own typed refusal.
    pub fn call(
        &mut self,
        target: &str,
        capability: &str,
        payload: serde_json::Value,
        now: u64,
    ) -> Result<serde_json::Value, String> {
        let plugin = nau_plugin::tier::PluginId::parse(target).map_err(|e| e.to_string())?;
        let cap =
            nau_plugin::capability::Capability::parse(capability).map_err(|e| e.to_string())?;
        // The host is the source, not a plugin: system plugins answer the host, and the
        // bus rule that a plugin may not send to itself does not apply to it.
        let mut message = PmbMessage::new(
            &plugin,
            nau_plugin::bus::Target::Plugin(target.to_string()),
            cap,
            nau_plugin::bus::PmbKind::Request,
            payload,
            now,
        );
        message.source = HOST_NAME.to_string();
        self.host.handle(&message).map_err(|e| e.to_string())
    }

    /// The log lines a plugin emitted, as `(level, message)`.
    #[must_use]
    pub fn logs(&self, name: &str) -> Vec<(String, String)> {
        self.host
            .logs(name)
            .unwrap_or_default()
            .into_iter()
            .map(|r| (r.level.label().to_string(), r.message))
            .collect()
    }
}

/// The name the host uses as a message source.
pub const HOST_NAME: &str = "host";

/// Boot every system plugin this build ships.
///
/// # Errors
///
/// A string naming what failed: the host limits, a plugin that cannot be constructed
/// (for instance a storage directory that cannot be created), or a manifest that did
/// not verify. Each is a startup failure, so it is reported rather than defaulted.
pub fn boot_system_plugins(
    storage_dir: &Path,
    now: u64,
    books: std::sync::Arc<std::sync::Mutex<nau_ledger::Ledger>>,
) -> Result<SystemBoot, String> {
    let mut host = SystemPluginHost::new(HostLimits::default()).map_err(|e| e.to_string())?;

    // One ephemeral pair, generated here and never written anywhere. See the module
    // documentation for what this signature does and does not attest.
    let mut rng = rand::rngs::OsRng;
    let vendor = SigningKey::generate(&mut rng);
    let publisher = SigningKey::generate(&mut rng);
    let vendor_key_hex = sign::key_hex(&vendor);

    // **Every manifest first, then the registry, then the plugin objects — in that order.**
    //
    // The registry used to be created empty and handed to the orchestrator with a comment
    // saying it would be "filled as plugins register". **Nothing filled it**, and nothing
    // could have: `Arc<Registry>` is shared and immutable, and `host.register` writes to the
    // host's own map rather than to it. So `sys.orchestrator` — the plugin whose entire job is
    // to answer "in what order should plugins start?" — answered an **empty list, always**,
    // and the only caller of `LoadRequest::depending_on` in the whole repository is a kernel
    // test.
    //
    // `standard_declarations` is the single source of truth for what each plugin needs, so the
    // manifest and the plugin object cannot disagree: `register` refuses when the token does
    // not cover what the plugin declares.
    let declarations = standard_declarations();
    let mut registry = Registry::new();
    let mut verified: Vec<(String, VerifiedManifest)> = Vec::with_capacity(declarations.len());
    for (name, capabilities) in &declarations {
        let manifest = sign::verified_system(name, capabilities, &publisher, &vendor)
            .map_err(|e| format!("the system manifest for `{name}` did not verify: {e}"))?;
        // No dependencies: `Manifest` has **no field for them**, so a plugin cannot declare
        // one, and the only producer of a non-empty edge set is a kernel test. Inserting each
        // entry with an empty edge set is what makes the orchestrator's answer complete rather
        // than absent — and it is also why the order below cannot reorder anything yet.
        registry
            .insert(manifest.clone(), Vec::new())
            .map_err(|e| format!("registering `{name}` in the boot registry: {e}"))?;
        verified.push((name.to_string(), manifest));
    }

    // The order the architecture promises, **computed rather than assumed**. `HotPlug` had no
    // production caller at all until this line; it still cannot reorder anything, because an
    // order over a graph with no edges is the insertion order.
    let order = HotPlug::start_order(&registry)
        .map_err(|e| format!("the start order could not be computed: {e}"))?;
    // Shared, not moved: the orchestrator reads this graph through its port and the shutdown
    // path reads the same one to decide what must stop first. Two copies would be two graphs,
    // and the day they disagreed the stop order would be computed from a graph no plugin ever
    // saw.
    let registry = Arc::new(registry);
    let order_source: Arc<dyn nau_plugins::plugins::orchestrator::LoadOrderSource> =
        registry.clone();
    // `sys.ledger` is built over the node's own books. The parameter is what makes giving it
    // an empty ledger impossible to do by accident: a caller has to name the ledger it runs,
    // and there is no default that quietly answers `0` to everything.
    let plugins = standard_plugins(storage_dir, order_source, books).map_err(|e| e.to_string())?;

    let mut by_name: std::collections::BTreeMap<String, Box<dyn nau_plugins::SystemPlugin + Send>> =
        plugins
            .into_iter()
            .map(|plugin| (plugin.id().as_str().to_string(), plugin))
            .collect();
    if by_name.len() != declarations.len() {
        return Err(format!(
            "{} plugin object(s) but {} declaration(s); they are built from the same list, so a \
             mismatch means one of them changed",
            by_name.len(),
            declarations.len()
        ));
    }

    let mut names = Vec::with_capacity(order.len());
    for name in &order {
        let Some(plugin) = by_name.remove(name) else {
            return Err(format!(
                "the start order names `{name}`, which this build does not ship; the registry and \
                 the plugin set have disagreed"
            ));
        };
        let Some((_, manifest)) = verified.iter().find(|(n, _)| n == name) else {
            return Err(format!(
                "`{name}` is in the order but has no verified manifest"
            ));
        };
        host.register(plugin, manifest, now)
            .map_err(|e| format!("registering `{name}`: {e}"))?;
        // Registration lands the plugin in `Loaded`; `init` runs the plugin's own
        // initialisation and moves it to `Running`. Leaving that out is the difference
        // between a host that has plugins and a host that can call them, and the first
        // version of this function did leave it out: `nau plugin system` printed four
        // plugins in state `loaded` and every call came back "not running". The
        // refusal was correct; the boot was incomplete.
        host.init(name, now)
            .map_err(|e| format!("initialising `{name}`: {e}"))?;
        names.push(name.clone());
    }
    // A plugin the order never mentioned would mean the registry and the shipped set disagree,
    // and silently leaving it unstarted is the failure mode this whole function exists to
    // avoid.
    if !by_name.is_empty() {
        let mut left: Vec<&String> = by_name.keys().collect();
        left.sort();
        return Err(format!(
            "the start order does not mention {} plugin(s): {}",
            left.len(),
            left.iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    Ok(SystemBoot {
        host,
        names,
        vendor_key_hex,
        registry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_750_000_000;

    /// A ledger no market is writing to.
    ///
    /// Correct for a test that only boots plugins: there is no second set of books for
    /// `sys.ledger` to disagree with, and the signature exists so that a host which *does*
    /// have books cannot omit them by accident.
    fn empty_books() -> std::sync::Arc<std::sync::Mutex<nau_ledger::Ledger>> {
        std::sync::Arc::new(std::sync::Mutex::new(nau_ledger::Ledger::new()))
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nau-node-plugin-host-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn every_shipped_system_plugin_boots_and_runs() {
        let dir = temp_dir("boot");
        let boot =
            boot_system_plugins(&dir, NOW, empty_books()).expect("the system plugins should boot");
        // Compared against the declarations rather than a literal. This assertion said
        // "four" while four existed, and went red the moment ten more were wired -- which
        // is a test doing its job, but the durable form is the one that cannot go stale:
        // the two lists are built from the same source, so a mismatch means one was edited
        // and the other was not.
        let declared = nau_plugins::host::standard_declarations();
        assert_eq!(
            boot.len(),
            declared.len(),
            "the host booted {} plugin(s) but {} are declared",
            boot.len(),
            declared.len()
        );
        for (name, _) in &declared {
            assert!(
                boot.names.iter().any(|n| n == name),
                "`{name}` is declared but did not boot"
            );
        }
        assert!(!boot.is_empty());
        for name in &boot.names {
            assert_eq!(
                boot.state(name),
                Some(PluginState::Running),
                "`{name}` did not reach Running"
            );
        }
        assert_eq!(boot.vendor_key_hex.len(), 64, "a 32-byte key in hex");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_policy_plugin_answers_with_the_matrix_the_kernel_enforces() {
        // The plugin wraps `Capability::decision`, so its answer and the kernel's own
        // answer must agree. Asking the plugin is what proves the wiring; asking the
        // kernel is how the test knows what the answer should be.
        let dir = temp_dir("policy");
        let mut boot = boot_system_plugins(&dir, NOW, empty_books()).expect("boot");
        let answer = boot
            .call(
                "com.twinsearth.sys.policy",
                "plugin:message:send",
                serde_json::json!({ "op": "matrix" }),
                NOW,
            )
            .expect("the policy plugin should answer");
        assert!(
            answer.is_object(),
            "the matrix should be an object: {answer}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_plugin_refuses_a_message_that_declares_a_capability_it_does_not_hold() {
        // The identity plugin holds the basic set; asking it to write policy must be
        // refused by name, and the refusal must come from the token rather than from
        // the plugin's own discretion.
        let dir = temp_dir("refuse");
        let mut boot = boot_system_plugins(&dir, NOW, empty_books()).expect("boot");
        let err = boot
            .call(
                "com.twinsearth.sys.identity",
                "kernel:policy:write",
                serde_json::json!({ "op": "verify" }),
                NOW,
            )
            .expect_err("must be refused");
        assert!(
            err.contains("kernel:policy:write"),
            "the refusal must name the capability: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every plugin stops, and a stopped plugin does not answer.
    ///
    /// # What this covers that nothing did
    ///
    /// The daemon had a shutdown path and used none of it on the plugins, and
    /// `HotPlug::stop_plan` had **no caller anywhere in the repository**. A shutdown that runs
    /// but leaves plugins in `Running` would look identical from outside, so the assertion is on
    /// the state rather than on the function having returned.
    #[test]
    fn the_third_violation_quarantines_a_plugin_through_the_one_transition_table() {
        // C-03's first two criteria, end to end: the count accumulates, the third violation
        // quarantines, and the state is reached by `Lifecycle::transition` -- the one function
        // that assigns a state. If a second path to `Quarantined` existed, this test would still
        // pass and the history below would not have the transition in it, which is why the
        // history is checked and not only the state.
        let dir = temp_dir("violation");
        let mut boot = boot_system_plugins(&dir, NOW, empty_books()).expect("boot");
        let victim = "com.twinsearth.sys.security.police";
        assert_eq!(boot.state(victim), Some(PluginState::Running));

        // The threshold is the kernel's, not a number chosen here.
        let threshold = nau_plugin::lifecycle::VIOLATION_THRESHOLD;
        assert_eq!(threshold, 3);

        for n in 1..threshold {
            let state = boot
                .record_violation(victim, &format!("violation {n}"), NOW + u64::from(n))
                .expect("recorded");
            assert_eq!(
                state,
                PluginState::Running,
                "violation {n} of {threshold} must not quarantine on its own"
            );
            assert_eq!(boot.violations(victim), Some(n));
        }

        let state = boot
            .record_violation(victim, "the last one", NOW + 100)
            .expect("recorded");
        assert_eq!(
            state,
            PluginState::Quarantined,
            "the {threshold}th violation must quarantine"
        );
        assert_eq!(boot.violations(victim), Some(threshold));

        // And it got there by the edge, recorded in the history rather than assigned directly.
        let history = boot.host.history(victim).expect("a history");
        let last = history.last().expect("at least one transition");
        assert_eq!(last.to, PluginState::Quarantined);
        assert!(
            last.because.contains("violations"),
            "the transition must say why, got: {}",
            last.because
        );
    }

    #[test]
    fn a_violation_against_an_unknown_plugin_is_refused() {
        // A report against a name nobody recognises is either a typo or an attempt to act on
        // something outside this host, and both want an answer rather than a silent no-op.
        let dir = temp_dir("violation-unknown");
        let mut boot = boot_system_plugins(&dir, NOW, empty_books()).expect("boot");
        let err = boot
            .record_violation("com.example.not.here", "whatever", NOW)
            .expect_err("must refuse");
        assert!(format!("{err}").contains("no plugin named"), "got: {err}");
        assert_eq!(boot.violations("com.example.not.here"), None);
    }

    #[test]
    fn a_quarantined_plugin_has_nothing_to_stop_and_that_is_not_a_failure() {
        // The deployment check found this, twice, on the two platforms where the shutdown check
        // runs and nowhere else.
        //
        // v3.7.1's C-03 check quarantines a plugin on purpose. The shutdown check runs later in
        // the same suite, asks that plugin to stop, and `Quarantined` has no edge to `Stopping` --
        // its only successors are `Archived` and `Blacklisted`. The transition was refused, the
        // failure was counted, and the deployment reported "1 plugin(s) could not be stopped"
        // about a plugin that holds no instance and cannot be loaded.
        //
        // The local run was green and could not have been otherwise: Windows does not deliver a
        // graceful stop through `child.kill()`, so that check skips there. A test that runs
        // everywhere is the only way this stays fixed.
        let dir = temp_dir("quarantined-shutdown");
        let mut boot = boot_system_plugins(&dir, NOW, empty_books()).expect("boot");
        let victim = "com.twinsearth.sys.security.tribunal";

        for n in 1..=nau_plugin::lifecycle::VIOLATION_THRESHOLD {
            boot.record_violation(victim, "for the shutdown test", NOW + u64::from(n))
                .expect("recorded");
        }
        assert_eq!(boot.state(victim), Some(PluginState::Quarantined));

        let outcomes = boot.shutdown(NOW + 100);
        let (_, result) = outcomes
            .iter()
            .find(|(name, _)| name == victim)
            .expect("the quarantined plugin must appear in the outcomes");
        assert!(
            result.is_ok(),
            "a quarantined plugin has nothing to stop, so stopping it must not be a failure: \
             {result:?}"
        );
        // And it stays quarantined rather than becoming `Stopped`, which is the truth: it was
        // never running, so it did not stop.
        assert_eq!(boot.state(victim), Some(PluginState::Quarantined));

        // Every other plugin still stops normally, so the early return did not become a way to
        // skip shutting anything down.
        for (name, result) in &outcomes {
            assert!(result.is_ok(), "{name} refused to stop: {result:?}");
            if name != victim {
                assert_eq!(boot.state(name), Some(PluginState::Stopped), "{name}");
            }
        }
    }

    #[test]
    fn every_plugin_stops_and_a_stopped_plugin_does_not_answer() {
        let dir = temp_dir("shutdown");
        let mut boot = boot_system_plugins(&dir, NOW, empty_books()).expect("boot");
        // The count is a tripwire: adding a T0 plugin must make someone look here and add it
        // to the shipped set deliberately. 18 as of A-03, which added
        // `com.twinsearth.sys.ausec`; 24 as of C-01, which added the six security
        // organisations; 25 as of D-01, which added `com.twinsearth.sys.resource`; 26 as of E-01,
        // which added `com.twinsearth.sys.settlement`. It has fired every time, which is what it
        // is for.
        assert_eq!(boot.names.len(), 26, "the shipped set");
        for name in &boot.names {
            assert_eq!(boot.state(name), Some(PluginState::Running), "{name}");
        }

        let outcomes = boot.shutdown(NOW + 1);
        assert_eq!(
            outcomes.len(),
            boot.names.len(),
            "every plugin must be stopped exactly once: {outcomes:?}"
        );
        assert!(
            outcomes.iter().all(|(_, r)| r.is_ok()),
            "no shipped plugin refuses to stop: {outcomes:?}"
        );
        for (name, _) in &outcomes {
            assert_eq!(boot.state(name), Some(PluginState::Stopped), "{name}");
        }

        // And the host refuses to dispatch to one: `Stopped` is terminal, so a second stop is a
        // refusal rather than a second stop.
        let refused = boot.call(
            &outcomes[0].0,
            "plugin:lifecycle:read",
            serde_json::json!({ "op": "anything" }),
            NOW + 2,
        );
        assert!(
            refused.is_err(),
            "a stopped plugin must not answer: {refused:?}"
        );

        // Stopping again is refused rather than silently succeeding, which is what makes
        // "was it stopped?" answerable from the outside.
        assert!(
            boot.host.shutdown(&outcomes[0].0, NOW + 3).is_err(),
            "a second stop must be refused"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The orchestrator answers the order, and nothing but the order.
    ///
    /// # What this test used to assert, and why that was the defect written down
    ///
    /// Its first version asserted `order == 0`, reasoning that "the registry it was handed is
    /// empty". That was not a property; it was **the bug stated as a requirement**. The boot
    /// handed `sys.orchestrator` an empty registry and a comment promising it would be "filled
    /// as plugins register", and nothing filled it — or could have, because `Arc<Registry>` is
    /// shared and immutable while `host.register` writes to the host's own map. So the plugin
    /// whose whole job is to report the start order reported nothing, and **this test made that
    /// look deliberate**, which is why nothing caught it for as long as the boot has existed.
    ///
    /// The property worth keeping is the **port**: a T0 plugin cannot reach the registry, it can
    /// only receive this one answer. That is asserted by the answer's *shape* — a list of names
    /// and a count, and nothing about the plugins themselves.
    ///
    /// The declared capability matters too: the orchestrator refuses a request declaring
    /// `plugin:message:send` for an operation needing `kernel:plugin:manage`, which is stronger
    /// than the original test assumed, so its first version failed on a correct refusal.
    #[test]
    fn the_orchestrator_answers_the_order_and_nothing_but_the_order() {
        let dir = temp_dir("order");
        let mut boot = boot_system_plugins(&dir, NOW, empty_books()).expect("boot");

        let refused = boot
            .call(
                "com.twinsearth.sys.orchestrator",
                "plugin:message:send",
                serde_json::json!({ "op": "start_order" }),
                NOW,
            )
            .expect_err("an under-declared request must be refused");
        assert!(
            refused.contains("kernel:plugin:manage"),
            "the refusal must name the capability the operation needs: {refused}"
        );

        let answer = boot
            .call(
                "com.twinsearth.sys.orchestrator",
                "kernel:plugin:manage",
                serde_json::json!({ "op": "start_order" }),
                NOW,
            )
            .expect("the orchestrator should answer a properly declared request");
        let order: Vec<String> = answer
            .get("order")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        // **Every** plugin the host booted, not zero. The agreement is the fact: `/plugins`
        // showing seventeen while the orchestrator says none is the state this replaced.
        assert_eq!(
            order.len(),
            boot.names.len(),
            "the orchestrator must name every plugin the host booted: {answer}"
        );
        assert!(
            !order.is_empty(),
            "a booted host has a start order: {answer}"
        );

        // The port: the answer carries names and a count, and nothing about the plugins. No
        // capability list, no token, no path -- a plugin cannot enumerate its peers' authority
        // through this door.
        let text = answer.to_string().to_ascii_lowercase();
        for forbidden in ["capabilit", "token", "grant", "digest"] {
            assert!(
                !text.contains(forbidden),
                "the order port must not leak `{forbidden}`: {answer}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
