//! `com.twinsearth.sys.orchestrator` — start/stop order, from the kernel's own graph.
//!
//! # What it does and what it does not
//!
//! It answers *in what order*: dependencies before dependents for a start, the
//! reverse for a stop. It does not start or stop anything itself. Starting a plugin
//! means verifying a manifest, choosing a runtime, creating a process and moving a
//! lifecycle — the arbiter's job, in the host, with handles this plugin must not
//! have. An "orchestrator" that could load plugins would be a second load pipeline,
//! and two load pipelines is how a policy check ends up on only one of them.
//!
//! The order comes from [`Registry::load_order`], so the topological sort, the cycle
//! refusal and the dependency vocabulary are the kernel's; this plugin contributes
//! the door, not the algorithm.
//!
//! # The one question it may ask the host
//!
//! [`LoadOrderSource`] has exactly one method. That is deliberate: a system plugin
//! cannot reach the [`Registry`] through its context (see [`crate::host`]), and the
//! orchestrator is the one plugin that legitimately needs something out of it. Rather
//! than widening the door for everyone, the host compiles in a port that answers the
//! single question — which is a grant you can see in the constructor and audit,
//! instead of an ambient capability every plugin would inherit.
//!
//! # Signals
//!
//! After computing a start order the plugin *requests* a bus send: one event on
//! [`LOAD_ORDER_TOPIC`] announcing the plan. The request goes into the context's
//! outbox and the host runs it through the bus's five checks
//! ([`SystemPluginHost::flush_outbox`](crate::host::SystemPluginHost::flush_outbox)),
//! so a plugin cannot announce anything the bus would refuse. The event is stamped
//! with the *request's* issue time: a T0 plugin is given no clock, and reading one
//! inside `handle` is exactly the ambient authority this framework does not hand out.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `start_order` | — | `order`, `count` |
//! | `stop_order` | — | `order`, `count` (reverse dependency order) |
//! | `check` | — | `plugins`, `acyclic` |
//!
//! All three require the request to declare `kernel:plugin:manage`. Kernel authority
//! is reserved to the system tier, so in V2.2.2 the caller is the host's own
//! dispatch — no other plugin can hold the capability, and the bus refuses a
//! self-send, which is the intended shape rather than a gap: the ordering of the
//! kernel's own plugins is not a third-party question.

use std::sync::Arc;

use nau_plugin::bus::{PmbKind, PmbMessage, Target};
use nau_plugin::registry::Registry;
use nau_plugin::{Capability, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The topic a load-order plan is announced on.
pub const LOAD_ORDER_TOPIC: &str = "nau/plugin/2.2.2/load-order";

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["start_order", "stop_order", "check"];

/// The one question the orchestrator may ask the host.
pub trait LoadOrderSource: Send + Sync {
    /// Plugin names in dependency order: dependencies before dependents.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`](nau_plugin::PluginError::Manifest) with
    /// `dependency_unsatisfied` when the graph has a cycle, which is the kernel's
    /// refusal and is passed through unchanged.
    fn load_order(&self) -> Result<Vec<String>>;
}

impl LoadOrderSource for Registry {
    fn load_order(&self) -> Result<Vec<String>> {
        order_of(self)
    }
}

/// The orchestrator system plugin.
pub struct OrchestratorPlugin {
    id: PluginId,
    grant: PluginGrant,
    order: Arc<dyn LoadOrderSource>,
}

impl OrchestratorPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.orchestrator";

    /// The capabilities the plugin declares: the basic set plus
    /// `kernel:plugin:manage`.
    ///
    /// The kernel capability is what makes the bus check the *caller's* token for
    /// kernel authority before an order request is delivered, and it is what
    /// [`OrchestratorPlugin::handle`] re-checks before it answers.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::KernelPluginManage,
    ];

    /// Build the plugin with the port that answers its one question.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`OrchestratorPlugin::ID`] is not a valid plugin name.
    pub fn new(order: Arc<dyn LoadOrderSource>) -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            order,
        })
    }
}

impl SystemPlugin for OrchestratorPlugin {
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
            &format!("orchestrator ready; announcing plans on `{LOAD_ORDER_TOPIC}`"),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        // 1. the declared capability must be one this plugin holds;
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        // 2. and it must be the kernel authority this plugin manages plugins under.
        self.grant
            .require_operation(declared, Capability::KernelPluginManage)?;
        // 3. re-checked against the token, not merely against the declaration: a
        //    caller cannot reach the ordering by declaring the capability it needs.
        self.grant.require(Capability::KernelPluginManage)?;

        let order = self.order.load_order()?;
        match op {
            "start_order" => {
                self.announce(&order, "start", msg.issued_at)?;
                Ok(payload::answer(
                    Self::ID,
                    "start_order",
                    json!({ "order": order, "count": order.len() }),
                ))
            }
            "stop_order" => {
                let mut reversed = order;
                reversed.reverse();
                self.announce(&reversed, "stop", msg.issued_at)?;
                Ok(payload::answer(
                    Self::ID,
                    "stop_order",
                    json!({ "order": reversed, "count": reversed.len() }),
                ))
            }
            "check" => Ok(payload::answer(
                Self::ID,
                "check",
                json!({ "plugins": order.len(), "acyclic": true }),
            )),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

impl OrchestratorPlugin {
    /// Request one event announcing a plan.
    fn announce(&self, order: &[String], direction: &str, issued_at: u64) -> Result<()> {
        let message = PmbMessage::new(
            &self.id,
            Target::Broadcast,
            Capability::MessageSend,
            PmbKind::Event,
            json!({ "direction": direction, "order": order, "count": order.len() }),
            issued_at,
        )
        .with_topic(LOAD_ORDER_TOPIC);
        self.grant.bus()?.send(message)
    }
}

/// The registry's own topological sort.
///
/// A free function so the port's method and the inherent method cannot be confused:
/// inside it, `registry.load_order()` is unambiguously the kernel's.
fn order_of(registry: &Registry) -> Result<Vec<String>> {
    registry.load_order()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostLimits;
    use nau_plugin::registry::Dependency;
    use nau_plugin::{CapabilityToken, Tier};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A registry with `a` and `b`, where `b` depends on `a`.
    fn registry_with_pair() -> Registry {
        let mut registry = Registry::new();
        registry
            .insert(registered("io.example.a"), Vec::new())
            .expect("inserts");
        registry
            .insert(
                registered("io.example.b"),
                vec![Dependency {
                    name: "io.example.a".into(),
                    // A floor the fixture version satisfies, and nothing more: the test
                    // is about dependency order, so tying the floor to whatever
                    // `FIXTURE_VERSION` happens to be made the test fail the moment the
                    // fixture version was decoupled from the release version.
                    min_version: "1.0.0".into(),
                }],
            )
            .expect("inserts");
        registry
    }

    /// A verified third-party manifest, so the registry holds real entries.
    fn registered(name: &str) -> nau_plugin::VerifiedManifest {
        crate::sign::verified_third_party(name, &Capability::BASIC, &crate::sign::fixture_key(5))
            .expect("verifies")
    }

    fn plugin(order: Arc<dyn LoadOrderSource>) -> OrchestratorPlugin {
        let mut plugin = OrchestratorPlugin::new(order).expect("valid id");
        let token = CapabilityToken::issue(
            OrchestratorPlugin::ID,
            Tier::System,
            OrchestratorPlugin::CAPABILITIES,
            DIGEST,
            1,
        )
        .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.sys.policy").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(OrchestratorPlugin::ID.to_string()),
            Capability::parse(capability).expect("known"),
            PmbKind::Request,
            payload,
            1_750_000_000,
        )
    }

    #[test]
    fn a_start_order_puts_dependencies_first_and_a_stop_order_reverses_it() {
        let order: Arc<dyn LoadOrderSource> = Arc::new(registry_with_pair());
        let mut plugin = plugin(order);

        let answer = plugin
            .handle(&request(
                "kernel:plugin:manage",
                json!({ "op": "start_order" }),
            ))
            .expect("answers");
        assert_eq!(answer["order"], json!(["io.example.a", "io.example.b"]));

        let answer = plugin
            .handle(&request(
                "kernel:plugin:manage",
                json!({ "op": "stop_order" }),
            ))
            .expect("answers");
        assert_eq!(answer["order"], json!(["io.example.b", "io.example.a"]));
    }

    #[test]
    fn a_plan_is_queued_for_the_bus_and_the_plugin_cannot_deliver_it_itself() {
        let order: Arc<dyn LoadOrderSource> = Arc::new(registry_with_pair());
        let plugin = plugin(order);
        plugin
            .announce(&[], "start", 1_750_000_000)
            .expect("queues the announcement");

        let bus = plugin.grant.bus().expect("bus handle");
        bus.send(
            PmbMessage::new(
                &plugin.id,
                Target::Broadcast,
                Capability::MessageSend,
                PmbKind::Event,
                json!({}),
                1,
            )
            .with_topic(LOAD_ORDER_TOPIC),
        )
        .expect("queues");
        assert_eq!(bus.owner(), OrchestratorPlugin::ID);
    }

    #[test]
    fn a_cycle_is_refused_with_the_kernels_dependency_code() {
        let mut registry = registry_with_pair();
        // Make the dependency mutual: `a` now depends on `b`.
        registry
            .get_mut("io.example.a")
            .expect("registered")
            .dependencies
            .push(Dependency {
                name: "io.example.b".into(),
                min_version: "1.0.0".into(),
            });
        let order: Arc<dyn LoadOrderSource> = Arc::new(registry);
        let mut plugin = plugin(order);
        let err = plugin
            .handle(&request(
                "kernel:plugin:manage",
                json!({ "op": "start_order" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("dependency_unsatisfied"), "{text}");
        assert!(text.contains("cycle"), "{text}");
    }

    #[test]
    fn an_order_request_that_declares_something_else_is_refused_by_capability_name() {
        let order: Arc<dyn LoadOrderSource> = Arc::new(registry_with_pair());
        let mut plugin = plugin(order);

        // Held by the plugin, but not the capability this operation needs.
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "start_order" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("kernel:plugin:manage"), "{text}");

        // Not held at all: the declared-capability gate refuses first.
        let err = plugin
            .handle(&request(
                "kernel:policy:write",
                json!({ "op": "start_order" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains("kernel:policy:write"), "{err}");
    }

    #[test]
    fn the_check_operation_reports_an_acyclic_graph_without_announcing_it() {
        let order: Arc<dyn LoadOrderSource> = Arc::new(registry_with_pair());
        let mut plugin = plugin(order);
        let answer = plugin
            .handle(&request("kernel:plugin:manage", json!({ "op": "check" })))
            .expect("answers");
        assert_eq!(answer["plugins"], json!(2));
        assert_eq!(answer["acyclic"], json!(true));
    }

    #[test]
    fn an_unknown_operation_lists_the_known_ones() {
        let order: Arc<dyn LoadOrderSource> = Arc::new(Registry::new());
        let mut plugin = plugin(order);
        let err = plugin
            .handle(&request(
                "kernel:plugin:manage",
                json!({ "op": "load_all" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("start_order"), "{text}");
    }

    #[test]
    fn an_empty_registry_has_an_empty_order_rather_than_an_error() {
        let order: Arc<dyn LoadOrderSource> = Arc::new(Registry::new());
        let mut plugin = plugin(order);
        let answer = plugin
            .handle(&request(
                "kernel:plugin:manage",
                json!({ "op": "start_order" }),
            ))
            .expect("answers");
        assert_eq!(answer["order"], json!([]));
        assert_eq!(answer["count"], json!(0));
    }
}
