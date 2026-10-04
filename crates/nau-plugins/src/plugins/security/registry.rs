//! `com.twinsearth.sys.security.registry` — the body that admits a plugin and cannot anchor it.
//!
//! # What it does, and the authority that needs
//!
//! `registry` registers plugins, verifies their signatures and keeps the trust store. In this
//! repository every one of those already exists: [`Manifest`] verification, the signature checks,
//! and [`TrustStore`] with its persistence. C-06 wires them; this release declares the body.
//!
//! It holds `kernel:plugin:manage` — admitting a plugin is a change to the plugin set — and
//! `plugin:storage:own`, because a trust store is state it owns and must survive a restart.
//!
//! # What it does **not** hold, and why the omission is deliberate
//!
//! `chain:evm:write` belongs to `security.report`, not here. Registering a plugin and anchoring
//! evidence about one are different acts with different consequences — the first is reversible
//! inside this node, the second is a write to a chain that is not. A registry that could anchor
//! would be able to make a registration permanent without the reporting desk's involvement.
//!
//! [`Manifest`]: nau_plugin::Manifest
//! [`TrustStore`]: nau_plugin::TrustStore

use std::path::Path;

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

use super::trust::TrustFile;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "trust", "verify", "trust-add", "revoke"];

/// The registry system plugin.
pub struct RegistryPlugin {
    id: PluginId,
    grant: PluginGrant,
    /// The keys this node has decided to trust, on disk.
    ///
    /// A store in memory would re-verify every plugin at every boot, which is not forgetting a
    /// decision so much as never recording one. See `trust.rs`.
    trust: TrustFile,
}

impl RegistryPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.security.registry";

    /// The capabilities the plugin declares.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::StorageOwn,
        // Admitting a plugin changes the plugin set.
        Capability::KernelPluginManage,
    ];

    /// Build the plugin, keeping its trust store under `dir`.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if the id is not a valid plugin name, or a refusal when an
    /// existing trust store cannot be read.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            trust: TrustFile::open(dir.as_ref().join("trust.json"))?,
        })
    }

    /// A plugin with a store in a scratch place, for tests that do not care where it is.
    ///
    /// # Errors
    ///
    /// As [`RegistryPlugin::open`].
    pub fn new() -> Result<Self> {
        Self::open(std::env::temp_dir().join("nau-registry-unplaced"))
    }
}

impl SystemPlugin for RegistryPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        ctx.log(
            LogLevel::Info,
            "security.registry ready; it registers and does not anchor",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        // A self-description needs no authority beyond the read every plugin holds; every
        // other op needs the authority this body exists to exercise. Requiring the body's own
        // authority to ask what it holds would make the answer unavailable to exactly the caller
        // most likely to need it -- a reviewer checking a deployment.
        let needed = match op {
            // A self-description and a question about the store need no authority beyond the read
            // every plugin holds; adding or removing a key does, because it changes who this node
            // will admit.
            "capabilities" | "trust" | "verify" => Capability::LifecycleRead,
            _ => Capability::KernelPluginManage,
        };
        self.grant.require_operation(declared, needed)?;

        match op {
            "capabilities" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "declares": Self::CAPABILITIES.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "operations": OPERATIONS,
                    "may_not": ["chain:evm:write"],
                    "why_not": "registering a plugin is reversible inside this node and anchoring \
                                is a write to a chain that is not; a registry that could anchor \
                                would make a registration permanent without the reporting desk",
                }),
            )),
            "trust" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    // Read from the file, so the number is what was actually written and survived
                    // a restart rather than a counter that would reset and look the same.
                    "trusted": self.trust.len(),
                    "vendor": self.trust.vendor_keys(),
                    "third_party": self.trust.third_party_keys(),
                    "store": self.trust.path().display().to_string(),
                    "empty_means": "nobody: the store starts from `TrustStore::deny_all` and adds \
                                    only what the file holds, so a missing or empty file trusts no \
                                    key at all rather than every key",
                    "signature_policy": "fail-closed: an unverifiable manifest is refused rather \
                                         than admitted with a warning",
                }),
            )),
            "trust-add" => {
                let hex = payload::string_field(&msg.payload, "key")?;
                let kind = payload::optional_string(&msg.payload, "kind")?
                    .unwrap_or_else(|| "vendor".to_string());
                match kind.as_str() {
                    "vendor" => self.trust.trust_vendor(hex)?,
                    "third_party" => self.trust.trust_third_party(hex)?,
                    other => {
                        return Err(payload::protocol(
                            "unknown_kind",
                            format!(
                                "`{other}` is not a kind of key this store keeps; it holds \
                                 `vendor` and `third_party`"
                            ),
                        ))
                    }
                }
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "trusted": self.trust.len(),
                        "kind": kind,
                        // The key is echoed back lowercased, which is how it is stored: a caller
                        // comparing what it sent with what is held should not have to know that.
                        "key": hex.to_ascii_lowercase(),
                        "store": self.trust.path().display().to_string(),
                    }),
                ))
            }
            "revoke" => {
                let hex = payload::string_field(&msg.payload, "key")?;
                let was = self.trust.revoke(hex)?;
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "was_trusted": was,
                        "trusted": self.trust.len(),
                        // Revoking a key that is not there is not an error: an operator ensuring a
                        // key is gone should not have to know whether it was ever added.
                        "note": if was { "revoked" } else { "it was not trusted, which is the \
                                                              state that was asked for" },
                    }),
                ))
            }
            "verify" => {
                let hex = payload::string_field(&msg.payload, "key")?;
                let kind = payload::optional_string(&msg.payload, "kind")?
                    .unwrap_or_else(|| "vendor".to_string());
                let store = self.trust.store()?;
                let trusted = match kind.as_str() {
                    "vendor" => store.is_trusted_vendor_key(hex),
                    "third_party" => store.is_trusted_third_party_key(hex),
                    other => {
                        return Err(payload::protocol(
                            "unknown_kind",
                            format!("`{other}` is not a kind of key this store keeps"),
                        ))
                    }
                };
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "key": hex.to_ascii_lowercase(),
                        "kind": kind,
                        "trusted": trusted,
                        // The direction, said on every answer: an untrusted key is refused, not
                        // admitted with a warning, and a node with an empty store refuses every
                        // key there is.
                        "policy": "fail-closed",
                        "if_untrusted": "the manifest is refused, and no key is trusted when the \
                                         store is empty",
                        "trusted_keys": store.len(),
                    }),
                ))
            }
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_may_admit_a_plugin_and_may_not_anchor_one() {
        assert!(RegistryPlugin::CAPABILITIES.contains(&Capability::KernelPluginManage));
        assert!(
            !RegistryPlugin::CAPABILITIES.contains(&Capability::ChainEvmWrite),
            "anchoring belongs to security.report: a chain write is not reversible inside this node"
        );
    }

    #[test]
    fn it_keeps_state_it_owns() {
        // A trust store that did not survive a restart would re-verify every plugin at every boot
        // and forget every decision an operator made.
        assert!(RegistryPlugin::CAPABILITIES.contains(&Capability::StorageOwn));
    }

    #[test]
    fn its_id_is_in_the_security_namespace() {
        assert!(RegistryPlugin::ID.starts_with("com.twinsearth.sys.security."));
        RegistryPlugin::new().expect("a valid id");
    }
}
