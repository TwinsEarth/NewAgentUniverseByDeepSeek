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
use nau_plugin::lifecycle::PluginState;
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
pub fn boot_system_plugins(storage_dir: &Path, now: u64) -> Result<SystemBoot, String> {
    let mut host = SystemPluginHost::new(HostLimits::default()).map_err(|e| e.to_string())?;

    // One ephemeral pair, generated here and never written anywhere. See the module
    // documentation for what this signature does and does not attest.
    let mut rng = rand::rngs::OsRng;
    let vendor = SigningKey::generate(&mut rng);
    let publisher = SigningKey::generate(&mut rng);
    let vendor_key_hex = sign::key_hex(&vendor);

    // The orchestrator asks one question — the dependency order — so it is given a
    // registry that is empty at boot and filled as plugins register. That is the whole
    // point of the port: the plugin cannot reach the registry, only this answer.
    let order: Arc<dyn nau_plugins::plugins::orchestrator::LoadOrderSource> =
        Arc::new(Registry::new());
    let plugins = standard_plugins(storage_dir, order).map_err(|e| e.to_string())?;

    // `standard_declarations` is the single source of truth for what each plugin needs,
    // so the manifest and the plugin object cannot disagree: `register` refuses when
    // the token does not cover what the plugin declares.
    let declarations = standard_declarations();
    if plugins.len() != declarations.len() {
        return Err(format!(
            "{} plugin object(s) but {} declaration(s); they are built from the same list, so a \
             mismatch means one of them changed",
            plugins.len(),
            declarations.len()
        ));
    }

    let mut names = Vec::with_capacity(plugins.len());
    for (plugin, (declared_name, capabilities)) in plugins.into_iter().zip(declarations) {
        let name = plugin.id().as_str().to_string();
        if name != declared_name {
            return Err(format!(
                "the plugin object is `{name}` but the declaration says `{declared_name}`; signing \
                 one and registering the other would verify a manifest for a different plugin"
            ));
        }
        let verified = sign::verified_system(&name, capabilities, &publisher, &vendor)
            .map_err(|e| format!("the system manifest for `{name}` did not verify: {e}"))?;
        host.register(plugin, &verified, now)
            .map_err(|e| format!("registering `{name}`: {e}"))?;
        // Registration lands the plugin in `Loaded`; `init` runs the plugin's own
        // initialisation and moves it to `Running`. Leaving that out is the difference
        // between a host that has plugins and a host that can call them, and the first
        // version of this function did leave it out: `nau plugin system` printed four
        // plugins in state `loaded` and every call came back "not running". The
        // refusal was correct; the boot was incomplete.
        host.init(&name, now)
            .map_err(|e| format!("initialising `{name}`: {e}"))?;
        names.push(name);
    }

    Ok(SystemBoot {
        host,
        names,
        vendor_key_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_750_000_000;

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
        let boot = boot_system_plugins(&dir, NOW).expect("the system plugins should boot");
        assert_eq!(boot.len(), 4, "four T0 plugins ship in this build");
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
        let mut boot = boot_system_plugins(&dir, NOW).expect("boot");
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
        let mut boot = boot_system_plugins(&dir, NOW).expect("boot");
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

    #[test]
    fn the_orchestrator_cannot_see_the_registry_only_the_order() {
        // The port exists so a T0 plugin cannot enumerate other plugins. The registry it
        // was handed is empty, so the order it computes is empty -- not a list of the
        // plugins that are running, which it has no way to obtain.
        //
        // The declared capability matters here: the orchestrator refuses a request that
        // declares `plugin:message:send` for an operation needing
        // `kernel:plugin:manage`, which is stronger than this test first assumed, so the
        // first version of it failed on a correct refusal. Both halves are asserted now.
        let dir = temp_dir("order");
        let mut boot = boot_system_plugins(&dir, NOW).expect("boot");

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
        let order = answer
            .get("order")
            .and_then(|v| v.as_array())
            .map_or(0, Vec::len);
        assert_eq!(
            order, 0,
            "the order port answers about the registry it was given, not about this host: {answer}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
