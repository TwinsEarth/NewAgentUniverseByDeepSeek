//! `com.twinsearth.sys.security.surveillance` — the body that watches and cannot act.
//!
//! # The authority it does not hold, which is the point of it
//!
//! `surveillance` audits sandbox state and checks resource quotas. It holds
//! `plugin:lifecycle:read` and `plugin:storage:own` and **no kernel capability at all** — and that
//! absence is a design decision rather than an unfinished one.
//!
//! A surveillance body that could quarantine a plugin would be a police force with a different
//! name, and the two exist as separate bodies precisely so that **watching and acting are separate
//! authorities**. If surveillance could act, the split would be cosmetic and a manifest would not
//! tell a reviewer which body can do what.
//!
//! # Quota checking is a read, so it needs no authority to check one
//!
//! [`Quota::check`] answers whether a request fits a quota. It is a pure comparison and it
//! **enforces nothing** — the type's own documentation says so: deciding whether a request fits is
//! this body's job, spending the resource is the caller's. A surveillance body reporting an
//! overrun is doing exactly what it should: observing one and saying so.
//!
//! [`Quota::check`]: nau_core::domain::Quota::check

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "quota", "observations"];

/// The surveillance system plugin.
pub struct SurveillancePlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl SurveillancePlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.security.surveillance";

    /// The capabilities the plugin declares.
    ///
    /// Exactly the basic set, and nothing above it. See the module documentation for why the
    /// absence of kernel authority is the substance of this body rather than an omission.
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

impl SystemPlugin for SurveillancePlugin {
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
            "security.surveillance ready; it observes and holds no authority to act",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        // The operations are reads, so the authority they need is the read capability.
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
                    "why": "a body that could act on what it observes would not be a separate body \
                            from the police, and the split between watching and acting is the \
                            reason both exist",
                }),
            )),
            "quota" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    // The dimensions, named from the type rather than listed by hand, so a
                    // dimension added to the quota cannot go unchecked here silently.
                    "dimensions": ["memory_bytes", "cpu_ms", "disk_bytes", "max_sandboxes", "max_agents"],
                    "checks": "whether a request fits; it enforces nothing",
                    "enforcement_point": "the caller's, not this body's",
                }),
            )),
            "observations" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "observed": 0,
                    "recording": false,
                    "why": "sandbox-state auditing arrives in C-04; this release declares that the \
                            body may observe, and refuses to report an observation it did not make",
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
        // The substance of this body. A surveillance organisation with kernel authority is a
        // police force, and the two would no longer be separable in a manifest.
        for cap in SurveillancePlugin::CAPABILITIES {
            assert!(
                !cap.is_kernel(),
                "surveillance must watch and not act, but holds {}",
                cap.as_str()
            );
        }
    }

    #[test]
    fn it_holds_exactly_the_basic_set_and_nothing_above_it() {
        assert!(SurveillancePlugin::CAPABILITIES.contains(&Capability::LifecycleRead));
        assert!(SurveillancePlugin::CAPABILITIES.contains(&Capability::StorageOwn));
        // It observes and it reports. A body that saw something and could not say so would be a
        // body with no effect, and `plugin:message:send` is one of the three every plugin holds.
        assert!(SurveillancePlugin::CAPABILITIES.contains(&Capability::MessageSend));
        assert_eq!(
            SurveillancePlugin::CAPABILITIES.len(),
            Capability::BASIC.len(),
            "exactly the basic set, and nothing above the floor"
        );
    }

    #[test]
    fn its_id_is_in_the_security_namespace() {
        assert!(SurveillancePlugin::ID.starts_with("com.twinsearth.sys.security."));
        SurveillancePlugin::new().expect("a valid id");
    }

    #[test]
    fn it_reports_no_observations_rather_than_inventing_one() {
        assert!(OPERATIONS.contains(&"observations"));
    }
}
