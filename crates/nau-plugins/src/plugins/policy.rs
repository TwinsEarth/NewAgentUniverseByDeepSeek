//! `com.twinsearth.sys.policy` — the capability ceiling table, as a door.
//!
//! # What the table is
//!
//! The ceiling is [`Capability::decision`]: a total function over
//! `Capability::ALL × Tier::ALL` that answers `always`, `requires_approval(who)` or
//! `refused(why)`. It lives in the kernel because the *bus* is where it must be
//! enforced — an ungranted call is refused at the token, not at a call site — and
//! this plugin is the door onto it for anything that needs to ask the question
//! without linking the kernel's internals.
//!
//! # Why there is no `write`
//!
//! The plugin holds `kernel:policy:write`, so the bus will route a policy-write
//! request to it. The operation exists, checks the capability, and is then
//! **refused**: the ceiling is a compile-time matrix, [`Capability::decision`] takes
//! no override, and there is nowhere an override would be enforced. Accepting a write
//! and storing it in this plugin's own memory would produce a policy that *looks*
//! changed and is consulted by nobody — which is precisely the upstream defect this
//! project exists to refuse (`NetworkGuard::check_egress`, `PermissionChecker::check`
//! and `AuditLog::append` all existed, were unit-tested, and had zero production
//! callers). A refusal that says so is worth more than a setter that does nothing.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `decide` | `capability`, `tier` | `capability`, `tier`, `decision`, and `approval` or `reason` |
//! | `resolve` | `tier`, `capabilities` | `granted`, each with the approval it rests on |
//! | `matrix` | — | `tiers`: the whole table, 5 tiers × 16 capabilities |
//! | `write` | `capability`, `tier`, `decision` | refused: `policy_table_immutable` |
//!
//! `decide`/`resolve`/`matrix` require the request to declare `plugin:message:send`;
//! `write` requires `kernel:policy:write`, so the bus checks the *caller's* token for
//! kernel authority before the message is delivered.

use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, Grant, PluginError, PluginId, Result, Tier};
use serde_json::{json, Map, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: the ceiling table is a compile-time matrix and cannot be written.
pub const CODE_IMMUTABLE: &str = "policy_table_immutable";
/// Error code: the tier name is not one of the five.
pub const CODE_UNKNOWN_TIER: &str = "policy_unknown_tier";

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["decide", "resolve", "matrix", "write"];

/// The policy system plugin.
pub struct PolicyPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl PolicyPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.policy";

    /// The capabilities the plugin declares: the basic set plus
    /// `kernel:policy:write`.
    ///
    /// It declares the kernel capability because it is the door a policy write would
    /// come through — a caller must hold `kernel:policy:write` for the bus to deliver
    /// one, and only the system tier can hold it. See the module documentation for
    /// why the write itself is refused today.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::KernelPolicyWrite,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`PolicyPlugin::ID`] is not a valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for PolicyPlugin {
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
            &format!(
                "policy ready: the ceiling is `Capability::decision`, {} capabilities × {} tiers",
                Capability::ALL.len(),
                Tier::ALL.len()
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "decide" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let capability =
                    parse_capability(payload::string_field(&msg.payload, "capability")?)?;
                let tier = parse_tier(payload::string_field(&msg.payload, "tier")?)?;
                Ok(payload::answer(
                    Self::ID,
                    "decide",
                    decision_json(capability, tier),
                ))
            }
            "resolve" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let tier = parse_tier(payload::string_field(&msg.payload, "tier")?)?;
                let names = payload::string_array(&msg.payload, "capabilities")?;
                let mut requested = Vec::with_capacity(names.len());
                for name in &names {
                    requested.push(parse_capability(name)?);
                }
                // All-or-nothing, exactly as the kernel's own `resolve` is: a caller
                // that learns "you may have two of these three" from this door would
                // learn something the kernel does not do.
                let granted = Capability::resolve(&requested, tier)
                    .map_err(|e| PluginError::Capability(format!("policy_resolve_refused: {e}")))?;
                let entries: Vec<Value> = granted
                    .iter()
                    .map(|(cap, approval)| {
                        json!({ "capability": cap.as_str(), "approval": approval.label() })
                    })
                    .collect();
                Ok(payload::answer(
                    Self::ID,
                    "resolve",
                    json!({ "tier": tier.label(), "granted": entries }),
                ))
            }
            "matrix" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let mut tiers = Map::new();
                for tier in Tier::ALL {
                    let mut caps = Map::new();
                    for capability in Capability::ALL {
                        caps.insert(
                            capability.as_str().to_string(),
                            decision_json(capability, tier),
                        );
                    }
                    tiers.insert(tier.label().to_string(), Value::Object(caps));
                }
                Ok(payload::answer(
                    Self::ID,
                    "matrix",
                    json!({ "tiers": Value::Object(tiers) }),
                ))
            }
            "write" => {
                self.grant
                    .require_operation(declared, Capability::KernelPolicyWrite)?;
                // Held, checked, and still refused -- see the module documentation.
                Err(PluginError::Capability(format!(
                    "{CODE_IMMUTABLE}: the ceiling table is the compile-time matrix \
                     `Capability::decision`, which takes no override; accepting a write would \
                     store a policy that nothing enforces, so this door refuses instead of \
                     pretending"
                )))
            }
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

/// The decision for one `(capability, tier)` pair, as JSON.
#[must_use]
pub fn decision_json(capability: Capability, tier: Tier) -> Value {
    match capability.decision(tier) {
        Grant::Always => json!({ "decision": "always", "approval": "host" }),
        Grant::RequiresApproval(approval) => json!({
            "decision": "requires_approval",
            "approval": approval.label(),
        }),
        Grant::Refused { reason } => json!({ "decision": "refused", "reason": reason }),
    }
}

/// Parse a capability wire name.
fn parse_capability(name: &str) -> Result<Capability> {
    Capability::parse(name)
}

/// Parse a tier name.
///
/// Both spellings are accepted: the kernel's short label (`sys`, `official`,
/// `certified`, `3rd`, `blk`), which logs and refusal messages use, and the
/// `serde`-derived name (`system`, `third_party`, …). The kernel has no
/// `Tier::from_label`, so the mapping lives here; it is small, it is tested against
/// every tier, and an unknown name is a typed refusal rather than a default.
fn parse_tier(name: &str) -> Result<Tier> {
    match name.trim().to_ascii_lowercase().as_str() {
        "sys" | "system" => Ok(Tier::System),
        "official" => Ok(Tier::Official),
        "certified" => Ok(Tier::Certified),
        "3rd" | "third_party" | "third-party" => Ok(Tier::ThirdParty),
        "blk" | "blacklisted" => Ok(Tier::Blacklisted),
        other => Err(PluginError::Tier(format!(
            "{CODE_UNKNOWN_TIER}: `{other}` is not a tier; the labels are {}",
            Tier::ALL
                .iter()
                .map(|t| t.label())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostLimits;
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::CapabilityToken;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn plugin() -> PolicyPlugin {
        let mut plugin = PolicyPlugin::new().expect("valid id");
        let token = CapabilityToken::issue(
            PolicyPlugin::ID,
            Tier::System,
            PolicyPlugin::CAPABILITIES,
            DIGEST,
            1,
        )
        .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.official.market").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(PolicyPlugin::ID.to_string()),
            Capability::parse(capability).expect("known"),
            PmbKind::Request,
            payload,
            1_750_000_000,
        )
    }

    #[test]
    fn the_kernels_three_way_decision_is_answered_through_the_plugin() {
        let mut plugin = plugin();

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "decide", "capability": "plugin:message:send", "tier": "3rd" }),
            ))
            .expect("answers");
        assert_eq!(answer["decision"], json!("always"));
        assert_eq!(answer["approval"], json!("host"));

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "decide", "capability": "economy:settle", "tier": "official" }),
            ))
            .expect("answers");
        assert_eq!(answer["decision"], json!("requires_approval"));
        assert_eq!(answer["approval"], json!("vendor-team"));

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "decide", "capability": "kernel:plugin:manage", "tier": "official" }),
            ))
            .expect("answers");
        assert_eq!(answer["decision"], json!("refused"));
        assert_eq!(
            answer["reason"],
            json!("kernel authority is reserved to the system tier")
        );
    }

    #[test]
    fn the_matrix_operation_returns_the_whole_table() {
        let mut plugin = plugin();
        let answer = plugin
            .handle(&request("plugin:message:send", json!({ "op": "matrix" })))
            .expect("answers");
        let tiers = answer["tiers"].as_object().expect("tiers object");
        assert_eq!(tiers.len(), Tier::ALL.len());
        for tier in Tier::ALL {
            let caps = tiers[tier.label()].as_object().expect("caps object");
            assert_eq!(caps.len(), Capability::ALL.len(), "{tier}");
        }
        // Sample the two rows an audit would check first.
        assert_eq!(
            tiers["3rd"]["net:dht:read"]["decision"],
            json!("refused"),
            "a third-party plugin holds the basic set only"
        );
        assert_eq!(
            tiers["sys"]["kernel:plugin:manage"]["decision"],
            json!("always")
        );
    }

    #[test]
    fn resolve_is_all_or_nothing_and_names_what_needs_approval() {
        let mut plugin = plugin();
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "resolve",
                    "tier": "certified",
                    "capabilities": ["plugin:message:send", "plugin:storage:own"],
                }),
            ))
            .expect("answers");
        assert_eq!(answer["granted"].as_array().expect("array").len(), 2);

        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({
                    "op": "resolve",
                    "tier": "certified",
                    "capabilities": ["plugin:message:send", "economy:settle"],
                }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("economy:settle"), "{text}");
        assert!(text.contains("certification-committee"), "{text}");
    }

    #[test]
    fn a_policy_write_is_refused_with_the_reason_that_no_override_is_enforced() {
        let mut plugin = plugin();
        let err = plugin
            .handle(&request(
                "kernel:policy:write",
                json!({
                    "op": "write",
                    "capability": "net:dht:read",
                    "tier": "3rd",
                    "decision": "always",
                }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(CODE_IMMUTABLE), "{text}");
        assert!(text.contains("nothing enforces"), "{text}");
    }

    #[test]
    fn a_policy_write_that_does_not_declare_kernel_authority_is_refused_by_name() {
        let mut plugin = plugin();
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "write", "capability": "net:dht:read", "tier": "3rd" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("kernel:policy:write"), "{text}");
        assert!(text.contains("plugin:message:send"), "{text}");
    }

    #[test]
    fn a_message_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let mut plugin = plugin();
        let err = plugin
            .handle(&request("swarm:consensus", json!({ "op": "matrix" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("swarm:consensus"), "{err}");
    }

    #[test]
    fn an_unknown_tier_is_refused_rather_than_defaulted() {
        let mut plugin = plugin();
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "decide", "capability": "net:dht:read", "tier": "fourth-party" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(CODE_UNKNOWN_TIER), "{text}");
        assert!(text.contains("3rd"), "{text}");
    }

    #[test]
    fn an_unknown_capability_is_refused_rather_than_ignored() {
        let mut plugin = plugin();
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "decide", "capability": "net:dht:reed", "tier": "official" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains("net:dht:read"), "{err}");
    }

    #[test]
    fn every_tier_spelling_the_kernel_uses_parses() {
        for tier in Tier::ALL {
            assert_eq!(parse_tier(tier.label()).expect("label"), tier);
        }
        assert_eq!(parse_tier("system").expect("serde name"), Tier::System);
        assert_eq!(
            parse_tier("third_party").expect("serde name"),
            Tier::ThirdParty
        );
        assert!(parse_tier("").is_err());
    }

    #[test]
    fn the_decision_json_agrees_with_the_kernel_for_every_pair() {
        // The plugin must not become a second source of truth: this walks the full
        // cross product and compares against `Capability::decision` itself.
        for tier in Tier::ALL {
            for capability in Capability::ALL {
                let rendered = decision_json(capability, tier);
                match capability.decision(tier) {
                    Grant::Always => assert_eq!(rendered["decision"], json!("always")),
                    Grant::RequiresApproval(a) => {
                        assert_eq!(rendered["decision"], json!("requires_approval"));
                        assert_eq!(rendered["approval"], json!(a.label()));
                    }
                    Grant::Refused { reason } => {
                        assert_eq!(rendered["decision"], json!("refused"));
                        assert_eq!(rendered["reason"], json!(reason));
                    }
                }
            }
        }
    }
}
