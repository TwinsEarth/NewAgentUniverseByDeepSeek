//! The pipeline: a signed T1 manifest, the registry, the bus, and a T0 plugin.
//!
//! This is the end-to-end shape V2.2.2 is built around, with every stage real:
//!
//! ```text
//! tests/fixtures/official-market.json
//!   └─ Manifest::verify(module, trust)      → VerifiedManifest + CapabilityToken
//!        └─ Registry::insert + Lifecycle    → Running
//!             └─ Bus::send                  → five checks, audit record
//!                  └─ SystemPluginHost::handle → a T0 plugin answers, or refuses by name
//! ```
//!
//! and the mirror image of it: a T0 plugin that asks the bus for something its token
//! does not hold is refused **at the bus**, with the refusal in the audit log.

mod common;

use std::sync::Arc;

use nau_plugin::bus::{Bus, BusLimits, PmbKind, PmbMessage, Target};
use nau_plugin::lifecycle::PluginState;
use nau_plugin::registry::Registry;
use nau_plugin::{Capability, PluginId, Result};
use nau_plugins::plugins::orchestrator::LoadOrderSource;
use nau_plugins::{
    standard_plugins, HostContext, HostLimits, IdentityPlugin, PluginGrant, SystemPlugin,
    SystemPluginHost,
};
use serde_json::{json, Value};

/// The verified market fixture, at [`common::NOW`].
fn market() -> nau_plugin::VerifiedManifest {
    common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "official-market.json")
        .expect("the fixture exists")
        .verify()
        .expect("the loadable fixture verifies")
}

/// The market fixture's capability token.
///
/// The bus takes the caller's *token* rather than trusting `message.source`, because a
/// message is data a plugin controls and its `source` field was therefore a way to
/// choose whose capabilities to act under. A test that wants to send as the market
/// plugin must hold its token, exactly as the real caller does.
fn market_token() -> nau_plugin::CapabilityToken {
    market().token
}

/// A message from one plugin to another, at [`common::NOW`].
fn request(from: &str, to: &str, capability: Capability, payload: Value) -> PmbMessage {
    let source = PluginId::parse(from).expect("a valid plugin name");
    PmbMessage::new(
        &source,
        Target::Plugin(to.to_string()),
        capability,
        PmbKind::Request,
        payload,
        common::NOW,
    )
}

/// A registry holding the four T0 plugins and the T1 market plugin, all `Running`.
fn pipeline_registry() -> Result<Arc<Registry>> {
    let mut registry = Registry::new();
    for (id, capabilities) in nau_plugins::standard_declarations() {
        let verified = common::system_manifest(id, capabilities)?;
        common::activate(&mut registry, &verified)?;
    }
    common::activate(&mut registry, &market())?;
    Ok(common::shared(registry))
}

/// A host whose four plugins are all registered, initialised and running.
fn pipeline_host(
    storage_dir: &std::path::Path,
    registry: Arc<Registry>,
) -> Result<(SystemPluginHost, Bus)> {
    // The tokens go on the bus before anything is sent: a T0 plugin's queued message
    // is refused with `bus_no_token` if its token was never registered, and that
    // would look like a capability refusal.
    let mut host = SystemPluginHost::new(HostLimits::default())?;
    for plugin in standard_plugins(
        storage_dir,
        Arc::clone(&registry) as Arc<dyn LoadOrderSource>,
    )? {
        let name = plugin.id().as_str().to_string();
        let verified = common::system_manifest(&name, plugin.capabilities())?;
        host.register(plugin, &verified, common::NOW)?;
    }
    let mut bus = Bus::new(BusLimits::default())?;
    for (_, token) in host.tokens() {
        bus.register(token)?;
    }
    bus.register(market().token)?;
    let names: Vec<String> = host.names().into_iter().map(str::to_string).collect();
    for name in names {
        host.init(&name, common::NOW)?;
    }
    Ok((host, bus))
}

#[test]
fn a_signed_t1_plugin_reaches_a_t0_plugin_through_the_bus() {
    let dir = common::scratch("e2e");
    let registry = pipeline_registry().expect("registry builds");
    let (mut host, mut bus) = pipeline_host(&dir, Arc::clone(&registry)).expect("host builds");

    let message = request(
        "com.twinsearth.official.market",
        IdentityPlugin::ID,
        Capability::MessageSend,
        json!({ "op": "did_from_seed", "seed_hex": "01".repeat(32) }),
    );

    // The bus's five checks, on a token that came from a signed manifest.
    let delivery = bus
        .send(&registry, &market_token(), &message, common::NOW_MS)
        .expect("the bus delivers");
    assert_eq!(delivery.recipients, vec![IdentityPlugin::ID.to_string()]);
    assert!(bus.audit().last().expect("audited").delivered);

    // And the T0 plugin answers.
    let answer = host.handle(&message).expect("answers");
    assert_eq!(answer["did"], json!("did:nau:34750f98bd59fcfc"));
    assert_eq!(answer["plugin"], json!(IdentityPlugin::ID));
    assert_eq!(answer["ok"], json!(true));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_message_the_sender_does_not_hold_the_capability_for_is_refused_and_audited() {
    let dir = common::scratch("e2e-refused");
    let registry = pipeline_registry().expect("registry builds");
    let (host, mut bus) = pipeline_host(&dir, Arc::clone(&registry)).expect("host builds");

    // The market plugin holds the basic set; it does not hold the DHT.
    let message = request(
        "com.twinsearth.official.market",
        IdentityPlugin::ID,
        Capability::DhtRead,
        json!({ "op": "binds", "public_key": "00".repeat(32), "did": "did:nau:00000000" }),
    );
    let err = bus
        .send(&registry, &market_token(), &message, common::NOW_MS)
        .expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains("bus_capability_refused"), "{text}");
    assert!(text.contains("net:dht:read"), "{text}");

    let audit = bus.audit().last().expect("audited");
    assert!(!audit.delivered);
    assert!(
        audit
            .refusal
            .as_deref()
            .expect("a reason")
            .contains("net:dht:read"),
        "{audit:?}"
    );

    // Nothing reached the plugin: its log holds the init line and no refusal.
    let logs = host.logs(IdentityPlugin::ID).expect("logs");
    assert!(
        !logs
            .iter()
            .any(|r| r.level == nau_plugins::LogLevel::Warn
                || r.level == nau_plugins::LogLevel::Error),
        "the refused message must not have been dispatched: {logs:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_t0_plugins_queued_announcement_travels_the_bus_and_is_audited() {
    let dir = common::scratch("e2e-outbox");
    let registry = pipeline_registry().expect("registry builds");
    let (mut host, mut bus) = pipeline_host(&dir, Arc::clone(&registry)).expect("host builds");

    let orchestrator = nau_plugins::OrchestratorPlugin::ID;
    host.handle(&request(
        "com.twinsearth.sys.policy",
        orchestrator,
        Capability::KernelPluginManage,
        json!({ "op": "start_order" }),
    ))
    .expect("answers");

    let outcomes = host
        .flush_outbox(orchestrator, &mut bus, common::NOW_MS)
        .expect("flushes");
    assert_eq!(outcomes.len(), 1, "one announcement was queued");
    let outcome = &outcomes[0];
    assert!(!outcome.refused(), "{outcome:?}");
    assert_eq!(outcome.capability, Capability::MessageSend.as_str());
    assert_eq!(outcome.source, orchestrator);
    assert!(
        outcome.delivered_to.is_empty(),
        "a broadcast to nobody is a delivered message with no recipients"
    );

    let audit = bus.audit().last().expect("audited");
    assert!(audit.delivered);
    assert_eq!(audit.source, orchestrator);
    assert_eq!(host.state(orchestrator), Some(PluginState::Running));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A system plugin that asks the bus for something it does not hold.
///
/// It is registered exactly like the four real ones — same door, same checks — and
/// its whole behaviour is to queue one message declaring `net:dht:write`, which its
/// basic token does not grant. The refusal must come from the **bus**, because the
/// bus is the only channel: a plugin cannot widen its token by being in-process.
struct Rogue {
    id: PluginId,
    grant: PluginGrant,
    target: String,
}

impl SystemPlugin for Rogue {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        &Capability::BASIC
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        self.grant.require_declared(msg)?;
        let message = PmbMessage::new(
            &self.id,
            Target::Plugin(self.target.clone()),
            Capability::DhtWrite,
            PmbKind::Event,
            json!({ "exfiltrate": true }),
            msg.issued_at,
        );
        self.grant.bus()?.send(message)?;
        Ok(json!({ "queued": true }))
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

#[test]
fn a_t0_plugin_cannot_widen_its_token_through_the_bus() {
    let dir = common::scratch("e2e-rogue");
    let registry = pipeline_registry().expect("registry builds");
    let (mut host, mut bus) = pipeline_host(&dir, Arc::clone(&registry)).expect("host builds");

    let name = "com.twinsearth.sys.rogue";
    let verified = common::system_manifest(name, &Capability::BASIC).expect("verifies");
    host.register(
        Box::new(Rogue {
            id: PluginId::parse(name).expect("valid id"),
            grant: PluginGrant::new(),
            target: IdentityPlugin::ID.to_string(),
        }),
        &verified,
        common::NOW,
    )
    .expect("registers like any other system plugin");
    bus.register(verified.token.clone()).expect("registers");
    host.init(name, common::NOW).expect("inits");

    // The plugin's own `handle` succeeds: requesting a send is not a violation.
    let answer = host
        .handle(&request(
            "com.twinsearth.sys.policy",
            name,
            Capability::MessageSend,
            json!({ "op": "go" }),
        ))
        .expect("queues");
    assert_eq!(answer["queued"], json!(true));

    // The bus is what refuses, and it names the capability.
    let outcomes = host
        .flush_outbox(name, &mut bus, common::NOW_MS)
        .expect("flushes");
    assert_eq!(outcomes.len(), 1);
    let refusal = outcomes[0].refusal.clone().expect("must be refused");
    assert!(refusal.contains("net:dht:write"), "{refusal}");
    assert!(
        refusal.contains(name),
        "the refusal names the plugin: {refusal}"
    );

    let audit = bus.audit().last().expect("audited");
    assert!(!audit.delivered);
    assert_eq!(audit.source, name);

    // And the plugin's own log records the refusal the host reported to it.
    let logs = host.logs(name).expect("logs");
    assert!(
        logs.iter().any(|r| r.message.contains("net:dht:write")),
        "{logs:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_plugin_the_bus_does_not_know_is_refused_with_bus_no_token() {
    let dir = common::scratch("e2e-no-token");
    let registry = pipeline_registry().expect("registry builds");
    let (mut host, mut bus) = pipeline_host(&dir, Arc::clone(&registry)).expect("host builds");

    // The rogue is registered in the host but never on the bus: its queued message
    // must be refused, not delivered on the strength of being in-process.
    let name = "com.twinsearth.sys.rogue";
    let verified = common::system_manifest(name, &Capability::BASIC).expect("verifies");
    host.register(
        Box::new(Rogue {
            id: PluginId::parse(name).expect("valid id"),
            grant: PluginGrant::new(),
            target: IdentityPlugin::ID.to_string(),
        }),
        &verified,
        common::NOW,
    )
    .expect("registers");
    host.init(name, common::NOW).expect("inits");
    host.handle(&request(
        "com.twinsearth.sys.policy",
        name,
        Capability::MessageSend,
        json!({ "op": "go" }),
    ))
    .expect("queues");

    let outcomes = host
        .flush_outbox(name, &mut bus, common::NOW_MS)
        .expect("flushes");
    let refusal = outcomes[0].refusal.clone().expect("must be refused");
    // This used to assert `bus_no_token`, from when the bus looked the sender up in a
    // map keyed by `message.source`. That lookup is gone -- it was the hole through
    // which a plugin could act under another's capabilities -- and with the caller's
    // own token now presented, the refusal that actually fires is the better one: the
    // rogue queued a message declaring `net:dht:write`, a capability its token does not
    // hold, so it cannot widen its own authority by sending. The refusal names the
    // capability and lists what it does hold.
    assert!(refusal.contains("bus_capability_refused"), "{refusal}");
    assert!(refusal.contains("net:dht:write"), "{refusal}");
    assert!(
        refusal.contains(name),
        "the refusal must name the sender: {refusal}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn three_over_reaches_through_a_flushed_outbox_quarantine_a_system_plugin() {
    // # The rule that stopped at the refusal
    //
    // `Bus::send_checked` has recorded a violation against a plugin whose message is refused
    // as *misconduct* since it was written, and three of those quarantine a sender. That path
    // needs a `&mut Registry`, which `SystemPluginHost` does not have — its plugins are not in
    // the load registry. So for a system plugin the rule ended at the refusal: it could
    // over-reach indefinitely and stay running, and "three violations quarantine a plugin" was
    // true of process plugins and a sentence for the compiled-in ones.
    //
    // The lifecycle is in this host, so the escalation is recorded here. This test drives the
    // same rogue as the one above, three times, and asserts the state the architecture
    // promises.
    let dir = common::scratch("e2e-escalation");
    let registry = pipeline_registry().expect("registry builds");
    let (mut host, mut bus) = pipeline_host(&dir, Arc::clone(&registry)).expect("host builds");

    let name = "com.twinsearth.sys.rogue";
    let verified = common::system_manifest(name, &Capability::BASIC).expect("verifies");
    host.register(
        Box::new(Rogue {
            id: PluginId::parse(name).expect("valid id"),
            grant: PluginGrant::new(),
            target: IdentityPlugin::ID.to_string(),
        }),
        &verified,
        common::NOW,
    )
    .expect("registers");
    host.init(name, common::NOW).expect("inits");
    assert_eq!(host.state(name), Some(PluginState::Running));

    for attempt in 1..=nau_plugin::lifecycle::VIOLATION_THRESHOLD {
        host.handle(&request(
            "com.twinsearth.sys.policy",
            name,
            Capability::MessageSend,
            json!({ "op": "go", "attempt": attempt }),
        ))
        .expect("queues");
        let outcomes = host
            .flush_outbox(name, &mut bus, common::NOW_MS)
            .expect("flushes");
        assert!(
            outcomes[0].refusal.is_some(),
            "attempt {attempt} must be refused"
        );

        let expected = if attempt == nau_plugin::lifecycle::VIOLATION_THRESHOLD {
            // The threshold attempt is the one that quarantines.
            PluginState::Quarantined
        } else {
            PluginState::Running
        };
        assert_eq!(
            host.state(name),
            Some(expected),
            "after {attempt} of {} violation(s)",
            nau_plugin::lifecycle::VIOLATION_THRESHOLD
        );
    }

    // And a quarantined plugin does not get to queue another one: the refusal comes from the
    // host, before the bus is even consulted. My first version of this test asserted that
    // queueing still worked "because the plugin object is still there" -- and the host's
    // answer was better than my assumption: *"a plugin that is not serving does not answer"*.
    // The escalation takes the plugin out of service for both halves of the exchange.
    let refused = host.handle(&request(
        "com.twinsearth.sys.policy",
        name,
        Capability::MessageSend,
        json!({ "op": "go", "attempt": "after quarantine" }),
    ));
    let why = refused.expect_err("a quarantined plugin must not queue");
    assert!(
        why.to_string().contains("quarantined"),
        "the refusal must name the state the plugin is in: {why}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_plugin_that_is_not_running_is_not_a_recipient() {
    // Two records of "is it running?" exist, and both must refuse: the bus consults
    // the *registry's* lifecycle, and the host owns the lifecycle of the plugin
    // object it dispatches to. This test asserts each on its own terms rather than
    // pretending they are one record.
    let mut registry = Registry::new();
    for (id, capabilities) in nau_plugins::standard_declarations() {
        let verified = common::system_manifest(id, capabilities).expect("verifies");
        if id == IdentityPlugin::ID {
            // Registered, verified and loaded — but never moved to Running.
            registry.insert(verified, Vec::new()).expect("inserts");
            let entry = registry.get_mut(id).expect("present");
            for state in [PluginState::Verified, PluginState::Loaded] {
                entry
                    .lifecycle
                    .transition(state, "test: registered but not started", common::NOW)
                    .expect("legal");
            }
            assert_eq!(entry.lifecycle.state(), PluginState::Loaded);
        } else {
            common::activate(&mut registry, &verified).expect("activates");
        }
    }
    common::activate(&mut registry, &market()).expect("activates");

    let message = request(
        "com.twinsearth.official.market",
        IdentityPlugin::ID,
        Capability::MessageSend,
        json!({ "op": "binds" }),
    );
    let mut bus = Bus::new(BusLimits::default()).expect("bus");
    bus.register(market().token).expect("registers");
    let err = bus
        .send(&registry, &market_token(), &message, common::NOW_MS)
        .expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains("bus_recipient_not_running"), "{text}");
    assert!(text.contains("loaded"), "{text}");

    // The host's own record, after a clean stop.
    let dir = common::scratch("e2e-not-running");
    let shared = pipeline_registry().expect("registry builds");
    let (mut host, _) = pipeline_host(&dir, shared).expect("host builds");
    host.shutdown(IdentityPlugin::ID, common::NOW)
        .expect("stops");
    assert_eq!(host.state(IdentityPlugin::ID), Some(PluginState::Stopped));
    let err = host.handle(&message).expect_err("must be refused");
    assert!(err.to_string().contains("stopped"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
