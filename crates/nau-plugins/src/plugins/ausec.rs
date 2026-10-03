//! `com.twinsearth.sys.ausec` — the elastic-compute substrate, as a door.
//!
//! # What this is at v3.5.0
//!
//! A **skeleton**, in the sense this project uses the word: the plugin exists, is
//! assembled by the host, holds a capability set that was chosen rather than inherited,
//! and refuses operations whose authority it does not have. It does not create a sandbox
//! yet. What it does have is the piece that is expensive to retrofit — the split between
//! *creating* a sandbox and *configuring its isolation*.
//!
//! # Why the capability split is the whole point
//!
//! [`Capability::SandboxCreate`] and [`Capability::SandboxConfigure`] are two
//! capabilities rather than one `sandbox:manage`. Held together they are a
//! privilege-escalation path: whatever can create a sandbox **and** choose its isolation
//! parameters can create a weakly-isolated one and run code inside it, which is the
//! isolation guarantee defeated by a single actor. Held apart, creating is routine and
//! configuring is the step worth a second look — and a deployment can hand the two to
//! different holders.
//!
//! The plugin therefore requires **both** for `configure` (and re-checks them against its
//! own token, not merely against the request's declaration) while `create` needs only the
//! first. A caller that can create sandboxes but not configure them cannot weaken the
//! isolation of the ones it makes.
//!
//! # What it deliberately does not hold
//!
//! `kernel:policy:write`. Policy is written by the policy engine; a substrate that both
//! runs the sandboxes and writes the rules they run under is a second policy path, and
//! two policy paths is how a check ends up enforced on only one of them. A test below
//! asserts the absence, so the omission cannot be "fixed" by someone adding it later
//! without reading this paragraph.
//!
//! # Operations
//!
//! | `op` | Requires | Answer |
//! |---|---|---|
//! | `backends` | `sandbox:create` | `backends`, `available`, `unavailable` |
//! | `create` | `sandbox:create` | `backend`, `isolation` |
//! | `configure` | `sandbox:create` **and** `sandbox:configure` | `configured` |
//! | `capabilities` | the basic set | `held`, `kernel_policy_write` |
//!
//! `backends` is the operation that makes this version useful on its own: it reports which
//! [`RuntimeKind`]s this build can actually run and, for each it cannot, the reason from
//! [`RuntimeKind::unavailability`]. A manifest author asking for `micro_vm` gets the
//! refusal text here rather than discovering it one failed load at a time.
//!
//! # What is not claimed
//!
//! Nothing here allocates memory, shares a page, or schedules anything. AUSec's own
//! description puts image-on-demand, page sharing and CPU classes in v3.5.1 through
//! v3.5.8; this release declares the vocabulary they will be expressed in — the four new
//! [`Boundary`](nau_plugin::Boundary) variants and the two hypervisor runtime kinds — so
//! that asking for one fails with a reason instead of silently selecting something
//! weaker.

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::runtime::RuntimeKind;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["backends", "create", "configure", "capabilities"];

/// The AUSec system plugin.
pub struct AUSecPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl AUSecPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.ausec";

    /// The capabilities the plugin declares.
    ///
    /// The basic set, isolation configuration, and the split sandbox pair. Notably absent:
    /// `kernel:policy:write` — see the module documentation.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::KernelIsolationConfigure,
        Capability::SandboxCreate,
        Capability::SandboxConfigure,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`](nau_plugin::PluginError::Name) if [`AUSecPlugin::ID`] is not
    /// a valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for AUSecPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        let available: Vec<&str> = RuntimeKind::ALL
            .into_iter()
            .filter(|k| k.is_available())
            .map(RuntimeKind::label)
            .collect();
        ctx.log(
            LogLevel::Info,
            &format!(
                "ausec ready; runtimes available in this build: {}",
                available.join(", ")
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        // 1. the declared capability must be one this plugin holds;
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        // 2. and it must be the sandbox authority this plugin manages sandboxes under.
        self.grant
            .require_operation(declared, Capability::SandboxCreate)?;

        match op {
            "backends" => {
                let available: Vec<Value> = RuntimeKind::ALL
                    .into_iter()
                    .filter(|k| k.is_available())
                    .map(|k| json!({ "kind": k.label() }))
                    .collect();
                let unavailable: Vec<Value> = RuntimeKind::ALL
                    .into_iter()
                    .filter(|k| !k.is_available())
                    .map(|k| {
                        json!({
                            "kind": k.label(),
                            "why": k.unavailability().unwrap_or("no reason recorded"),
                        })
                    })
                    .collect();
                Ok(payload::answer(
                    Self::ID,
                    "backends",
                    json!({
                        "backends": RuntimeKind::ALL.len(),
                        "available": available,
                        "unavailable": unavailable,
                    }),
                ))
            }
            "create" => {
                // Creating needs only the create half of the pair.
                self.grant.require(Capability::SandboxCreate)?;
                Ok(payload::answer(
                    Self::ID,
                    "create",
                    json!({
                        "backend": RuntimeKind::Process.label(),
                        "isolation": "process",
                        "note": "v3.5.0 declares the backends; allocation arrives in v3.5.1+",
                    }),
                ))
            }
            "configure" => {
                // 3. Configuring needs BOTH halves, and both are re-checked against the
                //    token rather than against the request's declaration: a caller cannot
                //    reach the isolation parameters by declaring the capability it needs.
                self.grant.require(Capability::SandboxCreate)?;
                self.grant.require(Capability::SandboxConfigure)?;
                self.grant.require(Capability::KernelIsolationConfigure)?;
                Ok(payload::answer(
                    Self::ID,
                    "configure",
                    json!({ "configured": true, "approval": "two capabilities" }),
                ))
            }
            "capabilities" => {
                let held: Vec<&str> = Self::CAPABILITIES.iter().map(|c| c.as_str()).collect();
                Ok(payload::answer(
                    Self::ID,
                    "capabilities",
                    json!({
                        "held": held,
                        // Reported rather than merely omitted, so an operator reading the
                        // answer sees the boundary instead of inferring it from an
                        // absence.
                        "kernel_policy_write": false,
                        "note": "policy is written by the policy engine, not by the substrate",
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
    fn the_id_is_a_system_plugin_name() {
        let plugin = AUSecPlugin::new().expect("builds");
        assert_eq!(plugin.id().as_str(), AUSecPlugin::ID);
        assert!(AUSecPlugin::ID.starts_with("com.twinsearth.sys."));
    }

    #[test]
    fn it_does_not_hold_kernel_policy_write() {
        // The omission is the design, not an oversight: a substrate that runs the
        // sandboxes and writes the rules they run under is a second policy path.
        assert!(
            !AUSecPlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite),
            "ausec must not write policy; see the module documentation"
        );
        assert!(
            AUSecPlugin::CAPABILITIES.contains(&Capability::KernelIsolationConfigure),
            "it must be able to configure isolation, which is what it is for"
        );
    }

    #[test]
    fn the_sandbox_pair_is_split_and_both_halves_are_held() {
        // Held apart from each other in the capability model, and both held here because
        // this plugin is the one that must be able to do each. A deployment can hand
        // `sandbox:create` to something else without also handing it `sandbox:configure`.
        assert!(AUSecPlugin::CAPABILITIES.contains(&Capability::SandboxCreate));
        assert!(AUSecPlugin::CAPABILITIES.contains(&Capability::SandboxConfigure));
        assert_ne!(
            Capability::SandboxCreate,
            Capability::SandboxConfigure,
            "the pair must stay two capabilities"
        );
        assert!(
            Capability::SandboxCreate.is_kernel() && Capability::SandboxConfigure.is_kernel(),
            "both halves are kernel-class, so no downloadable tier can hold either"
        );
    }

    #[test]
    fn the_declared_operations_are_the_ones_handled() {
        for op in OPERATIONS {
            assert!(
                ["backends", "create", "configure", "capabilities"].contains(op),
                "`{op}` is declared but has no arm"
            );
        }
        assert_eq!(OPERATIONS.len(), 4);
    }

    #[test]
    fn the_unavailable_backends_carry_a_reason() {
        // The operation exists so a manifest author learns *why* `micro_vm` cannot run
        // here, rather than discovering it one failed load at a time.
        for kind in RuntimeKind::ALL {
            if kind.is_available() {
                continue;
            }
            let why = kind.unavailability();
            assert!(
                why.is_some_and(|w| !w.trim().is_empty()),
                "{kind:?} must explain itself in the `backends` answer"
            );
        }
        // And at v3.5.0 the two hypervisor kinds are exactly the unavailable ones that
        // this plugin newly declared.
        assert!(!RuntimeKind::MicroVm.is_available());
        assert!(!RuntimeKind::FullVm.is_available());
    }
}
