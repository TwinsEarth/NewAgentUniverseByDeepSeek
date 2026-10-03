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

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "trust", "verify"];

/// The registry system plugin.
pub struct RegistryPlugin {
    id: PluginId,
    grant: PluginGrant,
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

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if the id is not a valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
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
            "capabilities" => Capability::LifecycleRead,
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
                    "store": "nau_plugin::TrustStore",
                    // The property C-06 has to preserve, stated where the plugin is read.
                    "persistence": "on disk, and surviving a restart",
                    "signature_policy": "fail-closed: an unverifiable manifest is refused rather \
                                         than admitted with a warning",
                    "implemented": false,
                }),
            )),
            "verify" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "uses": ["nau_plugin::Manifest", "nau_plugin::TrustStore"],
                    "implemented": false,
                    "why": "C-06 wires the existing verification; this release declares the body \
                            and its authority so that a manifest granting it can be reviewed",
                }),
            )),
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
