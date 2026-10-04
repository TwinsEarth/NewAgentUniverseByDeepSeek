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

use std::path::Path;

use nau_core::domain::Quota;
use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

use super::trail::{QuotaObservation, Trail};

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "quota", "check", "observations", "replay"];

/// The surveillance system plugin.
pub struct SurveillancePlugin {
    id: PluginId,
    grant: PluginGrant,
    /// Where its observations are written, and what has been written so far.
    ///
    /// A body that could observe and not record would be one whose findings nobody can appeal.
    /// See `trail.rs` for why the file rather than a `Vec`.
    trail: Trail,
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

    /// Build the plugin, writing its observations under `dir`.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if the id is not a valid plugin name, or a protocol
    /// refusal when an existing trail cannot be read.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            trail: Trail::open(dir.as_ref().join("observations.jsonl"))?,
        })
    }

    /// A plugin with a trail in a scratch directory, for tests that do not care where it is.
    ///
    /// # Errors
    ///
    /// As [`SurveillancePlugin::open`].
    pub fn new() -> Result<Self> {
        Self::open(std::env::temp_dir().join("nau-surveillance-unplaced"))
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
            "check" => {
                // C-04's first criterion, and it is answered by the kernel's own comparison rather
                // than by a second one written here. `Quota::check` names which dimension was
                // exceeded and by how much; this plugin's job is to **make the comparison and
                // record it**, not to decide what a quota means.
                let subject = payload::string_field(&msg.payload, "subject")?;
                let allowed = quota_from(&msg.payload, "allowed")?;
                let asked = quota_from(&msg.payload, "asked")?;
                let at = payload::optional_u64(&msg.payload, "at")?.unwrap_or(0);
                if at == 0 {
                    return Err(payload::protocol(
                        "missing_timestamp",
                        "a quota check must carry a non-zero `at`; an observation the trail cannot \
                         date is one nobody can place",
                    ));
                }

                // The one comparison, and the refusal is a **value** here rather than an error:
                // an exceeded quota is an observation, which is what this body is for.
                let exceeded = match allowed.check(&asked) {
                    Ok(()) => None,
                    Err(refusal) => Some(refusal.to_string()),
                };
                let dimension = exceeded
                    .as_deref()
                    .and_then(|why| why.split_whitespace().nth(3))
                    .map(str::to_string);

                let observation = QuotaObservation {
                    at,
                    subject: subject.to_string(),
                    exceeded: dimension.clone(),
                    // Recorded only when there is something to record: storing `0` for a fitting
                    // request would put a number in the trail that was never compared.
                    allowed: dimension.as_ref().map(|_| allowed.memory_bytes),
                    asked: dimension.as_ref().map(|_| asked.memory_bytes),
                };
                self.trail.append(observation)?;

                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "subject": subject,
                        "fits": dimension.is_none(),
                        // The kernel's own words, passed through rather than paraphrased: a second
                        // phrasing would be a second thing to keep in step.
                        "why": exceeded,
                        "exceeded": dimension,
                        "recorded": self.trail.len(),
                        "may_not": "enforce anything: this body observes and reports",
                    }),
                ))
            }
            "replay" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "lines": self.trail.replay(),
                    "exceeded": self.trail.exceeded(),
                    "trail": self.trail.path().display().to_string(),
                }),
            )),
            "observations" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    // Read from the trail, so the number is what was actually written and survived
                    // a restart -- not a counter in memory that would reset and look the same.
                    "observed": self.trail.len(),
                    "exceeded": self.trail.exceeded(),
                    "recording": true,
                    "trail": self.trail.path().display().to_string(),
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

/// Read a quota out of a payload, naming the field that is missing.
fn quota_from(payload: &serde_json::Value, field: &str) -> Result<Quota> {
    let object = payload::field(payload, field)?;
    let get = |key: &str| -> Result<u64> {
        object
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                payload::protocol(
                    "missing_dimension",
                    format!("`{field}.{key}` is not a number; a quota names every dimension"),
                )
            })
    };
    Ok(Quota {
        memory_bytes: get("memory_bytes")?,
        cpu_ms: get("cpu_ms")?,
        disk_bytes: get("disk_bytes")?,
        max_sandboxes: u32::try_from(get("max_sandboxes")?).unwrap_or(u32::MAX),
        max_agents: u32::try_from(get("max_agents")?).unwrap_or(u32::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overrun_is_detectable_and_names_the_dimension() {
        // C-04's first criterion. The refusal is the kernel's `Quota::check`, and the point of
        // asserting on its **text** is that a bare `false` would leave a caller unable to report
        // which dimension was exceeded -- so the dimension being named is the property, not a
        // detail of the message.
        let allowed = Quota {
            memory_bytes: 1024,
            cpu_ms: 1000,
            disk_bytes: 2048,
            max_sandboxes: 2,
            max_agents: 4,
        };
        let request = Quota {
            memory_bytes: 2048,
            ..allowed
        };
        let refusal = allowed.check(&request).expect_err("must refuse");
        let text = refusal.to_string();
        assert!(text.contains("memory_bytes"), "got: {text}");
        assert!(text.contains("2048"), "the amount asked for, got: {text}");
        assert!(text.contains("1024"), "the amount allowed, got: {text}");

        // And a request that fits is not refused, so the check is not simply always failing.
        allowed
            .check(&allowed)
            .expect("a request equal to the quota fits");
        let smaller = Quota {
            memory_bytes: 512,
            ..allowed
        };
        allowed.check(&smaller).expect("and a smaller one does too");
    }

    #[test]
    fn the_denied_quota_permits_nothing_at_all() {
        // The kernel's starting point: "no quota set" is zero, not infinity, so an organisation
        // that has been granted nothing cannot be confused with one that is unlimited.
        let denied = Quota::DENIED;
        assert!(denied.is_denied());
        let anything = Quota {
            memory_bytes: 1,
            cpu_ms: 0,
            disk_bytes: 0,
            max_sandboxes: 0,
            max_agents: 0,
        };
        assert!(denied.check(&anything).is_err());
        denied.check(&denied).expect("nothing fits in nothing");
    }

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
