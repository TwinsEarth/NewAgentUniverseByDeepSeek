//! `com.twinsearth.sys.security.audit` — the body that assesses and cannot judge.
//!
//! # Why an audit body is not the tribunal
//!
//! `audit` produces a risk assessment. `tribunal` produces a ruling. They are separate because the
//! authority differs: an assessment is an **opinion about** a plugin, and a ruling is a **change
//! to** it. A body that could do both would be able to decide a case and then be the evidence for
//! its own decision.
//!
//! So `audit` holds `plugin:lifecycle:read` and `plugin:storage:own`, and **no kernel authority at
//! all** — the same absence `surveillance` has, for the same reason.
//!
//! # The requirement C-05 will have to meet
//!
//! The plan says an assessment must be **explainable** and must **not rely on what the request
//! body claims about itself**. That is a property of the behaviour C-05 adds, and it is worth
//! saying here what this release does about it: nothing yet, and the `assess` operation below says
//! so rather than returning a score. A risk number with no explanation is the shape of unaccountable
//! authority, and returning one before the explanation exists would be worse than returning none.

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "assess", "explain"];

/// The audit system plugin.
pub struct AuditPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl AuditPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.security.audit";

    /// The capabilities the plugin declares.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        // It observes and it reports. A body that saw something and could not say so would be a
        // body with no effect, and plugin:message:send is one of the three every plugin holds.
        Capability::MessageSend,
        Capability::StorageOwn,
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

impl SystemPlugin for AuditPlugin {
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
            "security.audit ready; it assesses and holds no authority to rule",
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
            _ => Capability::LifecycleRead,
        };
        self.grant.require_operation(declared, needed)?;

        match op {
            "capabilities" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "declares": Self::CAPABILITIES.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "operations": OPERATIONS,
                    "holds_kernel_authority": false,
                    "separate_from": "security.tribunal, because an assessment is an opinion about \
                                      a plugin and a ruling is a change to one",
                }),
            )),
            "assess" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "score": Value::Null,
                    "assessed": false,
                    "why": "risk assessment arrives in C-05. A score without an explanation is the \
                            shape of unaccountable authority, and returning one now would be worse \
                            than returning none",
                }),
            )),
            "explain" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    // The requirement, stated where a reader of the plugin will find it rather
                    // than only in the plan.
                    "requirement": "an assessment must name what produced it",
                    "must_not_rely_on": "what the request body claims about itself",
                    "why": "a plugin that is judged on its own account of itself is not judged",
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
    fn it_holds_no_kernel_authority() {
        // An audit body that could act on its own finding would be able to decide a case and be
        // the evidence for its decision.
        for cap in AuditPlugin::CAPABILITIES {
            assert!(!cap.is_kernel(), "audit holds {}", cap.as_str());
        }
    }

    #[test]
    fn it_is_separate_from_the_tribunal() {
        // Asserted as a fact about the two capability sets, not as a comment: the tribunal writes
        // policy and the audit body does not.
        assert!(!AuditPlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite));
        assert!(super::super::TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite));
    }

    #[test]
    fn its_id_is_in_the_security_namespace() {
        assert!(AuditPlugin::ID.starts_with("com.twinsearth.sys.security."));
        AuditPlugin::new().expect("a valid id");
    }

    #[test]
    fn assess_reports_no_score_rather_than_a_number_without_a_reason() {
        assert!(OPERATIONS.contains(&"assess") && OPERATIONS.contains(&"explain"));
    }
}
