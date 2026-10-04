//! `com.twinsearth.sys.security.police` — the body that acts on a plugin.
//!
//! # What it is
//!
//! The police watches agent behaviour and, on a violation, moves a plugin out of service. In this
//! repository that move is already defined: [`PluginState::Quarantined`] after
//! `VIOLATION_THRESHOLD` recorded violations, or on a blacklist hit, and **every transition goes
//! through `Lifecycle::transition`**, the one function that assigns state.
//!
//! So this plugin does not implement policing. It **declares the authority** to do it, and C-03
//! gives it the behaviour. What is settled here is the authority, because that is the part a
//! manifest has to state and a reviewer has to agree with:
//!
//! * `kernel:plugin:manage` — to move a plugin;
//! * **not** `kernel:policy:write` — the police enforces the rules and does not write them.
//!
//! [`PluginState::Quarantined`]: nau_plugin::PluginState::Quarantined
//!
//! # What it refuses
//!
//! Every operation outside its list, with the list named. A plugin whose job is to act on
//! misbehaviour should be the last one to answer a request it does not understand.

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "authority", "violations", "report"];

/// The police system plugin.
pub struct PolicePlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl PolicePlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.security.police";

    /// The capabilities the plugin declares.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        // To act on a plugin. Not `KernelPolicyWrite`: the police enforces the rules.
        Capability::KernelPluginManage,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if [`PolicePlugin::ID`] is not a valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for PolicePlugin {
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
            "security.police ready; it may act on plugins and may not write policy",
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
                    // The authority it does not hold, said out loud rather than left to a reader
                    // to notice its absence from the list above.
                    "may_not": ["kernel:policy:write", "sandbox:create", "sandbox:configure"],
                    "acts_on": "one plugin's lifecycle state",
                }),
            )),
            "authority" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    // The threshold is the repository's own, not a number chosen here. A police
                    // force with its own idea of how many violations matter would be a second
                    // rule about the same thing.
                    "violation_threshold": nau_plugin::lifecycle::VIOLATION_THRESHOLD,
                    "states_it_may_reach": ["unhealthy", "quarantined"],
                    "transition_path": "Lifecycle::transition, the one function that assigns state",
                }),
            )),
            "violations" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    // No monitor exists yet, so it reports zero rather than a number it made up.
                    // A count of nothing is the honest answer while C-03 is unbuilt, and inventing
                    // one would make the deployment check that reads this meaningless.
                    "observed": 0,
                    "recording": false,
                    "why": "behaviour monitoring arrives in C-03; this release declares the \
                            authority and refuses to report an observation it did not make",
                }),
            )),
            "report" => {
                // The police **decides**; the host enforces. This operation validates a violation
                // report and returns it in canonical form, and the route that called it hands the
                // verdict to `SystemBoot::record_violation`.
                //
                // The split is not ceremony. The lifecycles are the host's, so a plugin cannot
                // change one; and a route that skipped this operation would quarantine any plugin
                // on request, with this body reduced to decoration.
                let subject = payload::string_field(&msg.payload, "subject")?;
                let what = payload::string_field(&msg.payload, "what")?;
                if what.trim().is_empty() {
                    return Err(payload::protocol(
                        "empty_violation",
                        "a violation must say what happened; a count of unreported violations is \
                         not something an operator can act on",
                    ));
                }
                // Refused here rather than at the host, so the refusal names the reason a caller
                // can fix. The host refuses an unknown name too, and that is the check that
                // matters -- this one is an earlier, more specific answer to the same question.
                if !subject.starts_with("com.twinsearth.") {
                    return Err(payload::protocol(
                        "unknown_subject",
                        format!(
                            "`{subject}` is outside this node's plugin namespace; the police acts \
                             on the plugins this host runs"
                        ),
                    ));
                }
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        // Echoed rather than re-derived, so the host applies exactly what was
                        // accepted. The route reads these two fields and does not re-parse the
                        // request, which would be a second parse that could disagree.
                        "subject": subject,
                        "what": what,
                        "accepted": true,
                        "enforced_by": "the host, through Lifecycle::violation and the one \
                                        transition table",
                        // The police does not say what the punishment is: that is the kernel's
                        // threshold, and a second opinion here would be a second rule.
                        "threshold": nau_plugin::lifecycle::VIOLATION_THRESHOLD,
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
    fn the_police_may_act_on_a_plugin_and_may_not_write_policy() {
        assert!(PolicePlugin::CAPABILITIES.contains(&Capability::KernelPluginManage));
        assert!(
            !PolicePlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite),
            "a body that could write the rules it enforces is not a police force"
        );
    }

    #[test]
    fn its_id_is_in_the_security_namespace() {
        assert!(PolicePlugin::ID.starts_with("com.twinsearth.sys.security."));
        PolicePlugin::new().expect("a valid id");
    }

    #[test]
    fn it_reports_the_repositorys_threshold_rather_than_its_own() {
        // A second rule about how many violations matter would be a second thing to keep in step.
        assert_eq!(nau_plugin::lifecycle::VIOLATION_THRESHOLD, 3);
    }

    #[test]
    fn it_offers_the_question_rather_than_an_answer_it_did_not_measure() {
        // The behaviour is C-03's, and what is checkable here without a host is that the question
        // exists at all -- the deployment check asserts the answer, in the running node.
        //
        // This test used to assert `!OPERATIONS.is_empty()`, which clippy rejected as an
        // expression that always evaluates the same way. It was right, and the assertion was
        // worse than useless: the compiler already knows a three-element const array is not
        // empty, so the line could never fail and was testing nothing while looking like a test.
        assert!(OPERATIONS.contains(&"violations"));
    }
}
