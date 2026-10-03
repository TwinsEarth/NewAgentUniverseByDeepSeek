//! `com.twinsearth.sys.security.tribunal` — the body that writes policy and cannot move a plugin.
//!
//! # The split from the police, in both directions
//!
//! `tribunal` rules on violations, executes penalties and approves unsealing, and its results reach
//! the blacklist. In this repository the blacklist is [`Blacklist`], and an entry's fields are
//! **real field names** — the plan calls out that the original design named `wasm_sha256` and
//! `evidence_hash`, neither of which exists anywhere in this codebase.
//!
//! It holds `kernel:policy:write` and **not** `kernel:plugin:manage`. Both halves matter:
//!
//! * a tribunal that could **move plugins** would execute its own sentences without the police,
//!   which is a court with an army;
//! * and the police, symmetrically, cannot write the policy it enforces.
//!
//! # The two rules C-08 will have to enforce, stated where they will be read
//!
//! **A penalty is decided by server-side rules, not by the request body.** A request that names
//! its own punishment is a request to be judged by the accused.
//!
//! **Unsealing needs an explicit approval.** A blacklist entry is the one state in this repository
//! that is meant to be hard to leave; a path that removes one without a recorded decision would
//! make it advisory.
//!
//! [`Blacklist`]: nau_plugin::blacklist::Blacklist

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "penalties", "unseal"];

/// The tribunal system plugin.
pub struct TribunalPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl TribunalPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.security.tribunal";

    /// The capabilities the plugin declares.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        // To write the blacklist. Not `KernelPluginManage`: see the module documentation.
        Capability::KernelPolicyWrite,
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

impl SystemPlugin for TribunalPlugin {
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
            "security.tribunal ready; it writes policy and does not move plugins",
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
            _ => Capability::KernelPolicyWrite,
        };
        self.grant.require_operation(declared, needed)?;

        match op {
            "capabilities" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "declares": Self::CAPABILITIES.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "operations": OPERATIONS,
                    "may_not": ["kernel:plugin:manage"],
                    "why": "a court that could execute its own sentences without the police is a \
                            court with an army; the police, symmetrically, cannot write the \
                            policy it enforces",
                }),
            )),
            "penalties" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "rule": "a penalty is decided by server-side rules, never by the request body",
                    "why": "a request that names its own punishment is a request to be judged by \
                            the accused",
                    "blacklist_fields": ["did", "reason", "since", "evidence"],
                    "original_design_fields": ["wasm_sha256", "evidence_hash"],
                    "note": "the two names in the original design exist nowhere in this codebase; \
                             an entry with those fields could not be written or read",
                    "implemented": false,
                }),
            )),
            "unseal" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "requires": "an explicit recorded approval",
                    "why": "a blacklist entry is the one state here meant to be hard to leave; a \
                            path that removes one without a decision makes it advisory",
                    "implemented": false,
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
    fn it_may_write_policy_and_may_not_move_a_plugin() {
        assert!(TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite));
        assert!(
            !TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPluginManage),
            "a court that executes its own sentences is a court with an army"
        );
    }

    #[test]
    fn it_and_the_police_hold_complementary_authorities() {
        // Checked as a property of the pair rather than of each, because the reason for the split
        // is the relationship and not either body on its own.
        let police = super::super::PolicePlugin::CAPABILITIES;
        assert!(police.contains(&Capability::KernelPluginManage));
        assert!(!police.contains(&Capability::KernelPolicyWrite));
        assert!(TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite));
        assert!(!TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPluginManage));
    }

    #[test]
    fn its_id_is_in_the_security_namespace() {
        assert!(TribunalPlugin::ID.starts_with("com.twinsearth.sys.security."));
        TribunalPlugin::new().expect("a valid id");
    }
}
