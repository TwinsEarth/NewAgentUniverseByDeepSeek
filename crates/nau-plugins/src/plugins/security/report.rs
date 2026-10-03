//! `com.twinsearth.sys.security.report` — the body that records and cannot act.
//!
//! # Why a reporting desk holds `chain:evm:write`
//!
//! It is the only body that does, and the reason is what a report is for. An anomaly report whose
//! evidence is not anchored is an assertion this node makes about itself; anchoring it writes the
//! digest to a chain the node does not control, which is what makes the report checkable by
//! somebody who does not trust this node.
//!
//! That is also why it holds **no `kernel:*`**: a body that could both record an anomaly and act
//! on it would be a police force that writes its own incident reports.
//!
//! # The evidence rule this body will have to enforce
//!
//! C-07 requires that a `verified` grade **points at something re-checkable**, and that a report
//! failing that is refused **at the moment it is recorded** rather than at review time. The
//! repository already has the vocabulary — [`EvidenceGrade`] — and the rule belongs with it.
//!
//! This release does not grade anything, and [`EvidenceGrade`]'s own documentation is the reason
//! to say so rather than to return a placeholder: a grade is a claim about how well something was
//! checked, and a claim made before the checking exists is a false one.
//!
//! [`EvidenceGrade`]: nau_core::domain::EvidenceGrade

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "grades", "anchor"];

/// The reporting system plugin.
pub struct ReportPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl ReportPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.security.report";

    /// The capabilities the plugin declares.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        // To anchor evidence. The only body that holds it.
        Capability::ChainEvmWrite,
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

impl SystemPlugin for ReportPlugin {
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
            "security.report ready; it records and anchors, and holds no authority to act",
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
            _ => Capability::ChainEvmWrite,
        };
        self.grant.require_operation(declared, needed)?;

        match op {
            "capabilities" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "declares": Self::CAPABILITIES.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "operations": OPERATIONS,
                    "may_not": ["kernel:plugin:manage", "kernel:policy:write"],
                    "why": "a body that could record an anomaly and act on it would write its own \
                            incident reports",
                }),
            )),
            "grades" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "rule": "a `verified` grade must point at something re-checkable, and a report \
                             that does not is refused when it is recorded rather than at review",
                    "vocabulary": "nau_core::domain::EvidenceGrade",
                    "grading": false,
                    "why": "a grade is a claim about how well something was checked; making one \
                            before the checking exists would be a false claim, not a placeholder",
                }),
            )),
            "anchor" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "capability": Capability::ChainEvmWrite.as_str(),
                    "reuses": "the existing com.twinsearth.official.chain-anchor plugin and \
                               record_anchor",
                    "implemented": false,
                    "why": "C-07 wires the anchoring; this release declares the authority so a \
                            manifest granting a chain write can be reviewed",
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
    fn it_is_the_only_body_holding_a_chain_write() {
        assert!(ReportPlugin::CAPABILITIES.contains(&Capability::ChainEvmWrite));
    }

    #[test]
    fn it_holds_no_kernel_authority() {
        for cap in ReportPlugin::CAPABILITIES {
            assert!(
                !cap.is_kernel(),
                "a body that could record an anomaly and act on it would write its own reports, \
                 but it holds {}",
                cap.as_str()
            );
        }
    }

    #[test]
    fn its_id_is_in_the_security_namespace() {
        assert!(ReportPlugin::ID.starts_with("com.twinsearth.sys.security."));
        ReportPlugin::new().expect("a valid id");
    }
}
