//! The six security organisations, as `com.twinsearth.sys.security.*` system plugins.
//!
//! # Why six separate plugins rather than one
//!
//! The design describes a police, a surveillance body, an audit body, a registry, a reporting
//! desk and a tribunal. They could have been six operations of one plugin, and that would have
//! been wrong for a reason this workspace keeps arriving at: **a plugin's capability set is its
//! authority**, and one plugin holding all six authorities would be a single point that can
//! watch, judge and punish. Split, each body holds what its job needs and the split is visible in
//! a manifest.
//!
//! # The least-privilege table, and the two entries that matter
//!
//! | Plugin | Capabilities | Notably **not** |
//! |---|---|---|
//! | `police` | `plugin:lifecycle:read`, `plugin:message:send`, `kernel:plugin:manage` | `kernel:policy:write` — it acts on **plugins**, not on policy |
//! | `surveillance` | `plugin:lifecycle:read`, `plugin:storage:own` | **no kernel capability at all** |
//! | `audit` | `plugin:lifecycle:read`, `plugin:storage:own` | **no kernel capability at all** |
//! | `registry` | `plugin:lifecycle:read`, `plugin:storage:own`, `kernel:plugin:manage` | `chain:evm:write` — it registers, it does not anchor |
//! | `report` | `plugin:lifecycle:read`, `plugin:message:send`, `chain:evm:write` | `kernel:*` — a reporting desk does not act on plugins |
//! | `tribunal` | `plugin:lifecycle:read`, `plugin:message:send`, `plugin:storage:own`, `kernel:policy:write` | `kernel:plugin:manage` — it writes policy, it does not move plugins |
//!
//! **The two entries that matter are `surveillance` and `audit`.** Both hold no kernel authority:
//! they can **watch and cannot act**, which is the distinction the whole split exists to make.
//! A surveillance body that could quarantine would be a police force with a different name.
//!
//! The second is the `police`/`tribunal` split. `police` holds `kernel:plugin:manage` and not
//! `kernel:policy:write`; `tribunal` holds the opposite. Acting on **one plugin** and acting on
//! **the rules all plugins live under** are different authorities, and a body that held both
//! would be able to change the law and then enforce it.
//!
//! # What these are, and what they are not
//!
//! **Skeletons.** Each answers a small set of operations about what it is and what it may do, and
//! refuses everything else with a reason. The behaviour the design describes — real-time
//! interception, evidence grading, rulings — arrives in C-03 through C-08, one organisation per
//! release. Declaring the six bodies and their authorities first is the same order this plan has
//! used throughout: **the vocabulary before the mechanism**, so that a capability which cannot be
//! exercised yet is still a capability that can be **asked for and refused**.

pub mod audit;
pub mod police;
pub mod registry;
pub mod report;
pub mod surveillance;
pub mod trail;
pub mod tribunal;

pub use audit::AuditPlugin;
pub use police::PolicePlugin;
pub use registry::RegistryPlugin;
pub use report::ReportPlugin;
pub use surveillance::SurveillancePlugin;
pub use tribunal::TribunalPlugin;

/// Every security plugin's name, in the order they are assembled.
///
/// A `const` so a test can assert the host's roster matches it: adding a body without wiring it
/// would otherwise be a plugin that exists and never runs, which is the failure the roster test
/// in `host.rs` was written for.
pub const SECURITY_PLUGINS: [&str; 6] = [
    PolicePlugin::ID,
    SurveillancePlugin::ID,
    AuditPlugin::ID,
    RegistryPlugin::ID,
    ReportPlugin::ID,
    TribunalPlugin::ID,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_security_plugin_holds_the_basic_set() {
        // Each body reads the lifecycle and owns its own storage where it keeps any. A body that
        // could not read the lifecycle could not observe anything, which is what all six do.
        for caps in [
            PolicePlugin::CAPABILITIES,
            SurveillancePlugin::CAPABILITIES,
            AuditPlugin::CAPABILITIES,
            RegistryPlugin::CAPABILITIES,
            ReportPlugin::CAPABILITIES,
            TribunalPlugin::CAPABILITIES,
        ] {
            assert!(
                caps.contains(&nau_plugin::Capability::LifecycleRead),
                "every body observes the lifecycle: {caps:?}"
            );
        }
    }

    #[test]
    fn the_observers_hold_no_kernel_authority() {
        // The first of the two entries that matter. A surveillance body that could quarantine
        // would be a police force with a different name, and an audit body that could act would
        // not be an audit.
        for (name, caps) in [
            ("surveillance", SurveillancePlugin::CAPABILITIES),
            ("audit", AuditPlugin::CAPABILITIES),
        ] {
            let kernel: Vec<&str> = caps
                .iter()
                .filter(|c| c.is_kernel())
                .map(|c| c.as_str())
                .collect();
            assert!(
                kernel.is_empty(),
                "{name} must watch and not act, but holds {kernel:?}"
            );
        }
    }

    #[test]
    fn the_police_and_the_tribunal_hold_different_authorities() {
        // The second entry. Acting on one plugin and acting on the rules all plugins live under
        // are different authorities; a body holding both could change the law and enforce it.
        let police = PolicePlugin::CAPABILITIES;
        let tribunal = TribunalPlugin::CAPABILITIES;

        assert!(
            police.contains(&nau_plugin::Capability::KernelPluginManage),
            "the police must be able to act on a plugin"
        );
        assert!(
            !police.contains(&nau_plugin::Capability::KernelPolicyWrite),
            "the police must not write policy: that would let it change the rules it enforces"
        );

        assert!(
            tribunal.contains(&nau_plugin::Capability::KernelPolicyWrite),
            "the tribunal must be able to write policy"
        );
        assert!(
            !tribunal.contains(&nau_plugin::Capability::KernelPluginManage),
            "the tribunal must not move plugins: a court that executes its own sentences \
             without the police is a court with an army"
        );
    }

    #[test]
    fn no_body_holds_a_capability_the_others_have_no_use_for() {
        // Least privilege, checked rather than stated: `report` anchors and does not act;
        // `registry` registers and does not anchor.
        assert!(
            ReportPlugin::CAPABILITIES.contains(&nau_plugin::Capability::ChainEvmWrite),
            "the reporting desk anchors"
        );
        assert!(
            !RegistryPlugin::CAPABILITIES.contains(&nau_plugin::Capability::ChainEvmWrite),
            "the registry registers and does not anchor"
        );
        for caps in [
            ReportPlugin::CAPABILITIES,
            RegistryPlugin::CAPABILITIES,
            SurveillancePlugin::CAPABILITIES,
            AuditPlugin::CAPABILITIES,
        ] {
            assert!(
                !caps.contains(&nau_plugin::Capability::KernelPolicyWrite)
                    || caps == TribunalPlugin::CAPABILITIES,
                "only the tribunal writes policy: {caps:?}"
            );
        }
    }

    #[test]
    fn the_names_are_the_security_namespace_and_are_unique() {
        // A body named outside `com.twinsearth.sys.` would classify as a non-system tier and could
        // not hold the kernel authority its job needs; two sharing a name is a manifest collision.
        let mut names: Vec<&str> = SECURITY_PLUGINS.to_vec();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two bodies share a name");
        for name in SECURITY_PLUGINS {
            assert!(
                name.starts_with("com.twinsearth.sys.security."),
                "{name} is outside the security namespace"
            );
        }
    }
}
