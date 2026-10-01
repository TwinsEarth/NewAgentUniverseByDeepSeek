//! The T0 framework and the four system plugins, through the host.
//!
//! These are integration tests rather than unit tests on purpose: a system plugin is
//! only meaningful as *part of the host*, and the things worth asserting here are the
//! framework's gates — registration against a verified system manifest, serving only
//! while `Running`, refusals that name the capability — not the individual functions.

mod common;

use std::sync::Arc;

use nau_plugin::bus::{PmbKind, PmbMessage, Target};
use nau_plugin::lifecycle::PluginState;
use nau_plugin::registry::{Dependency, Registry};
use nau_plugin::{Capability, PluginError, PluginId, Tier};
use nau_plugins::plugins::orchestrator::{LoadOrderSource, OrchestratorPlugin};
use nau_plugins::plugins::policy::PolicyPlugin;
use nau_plugins::plugins::storage::StoragePlugin;
use nau_plugins::sign;
use nau_plugins::{
    standard_declarations, standard_plugins, HostContext, HostLimits, IdentityPlugin, SystemPlugin,
    SystemPluginHost,
};

/// A message from a plugin to a system plugin, at [`common::NOW`].
fn request(from: &str, to: &str, capability: Capability, payload: serde_json::Value) -> PmbMessage {
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

/// A host with the four standard plugins registered and initialised.
///
/// The order source is the registry the caller passes: the orchestrator legitimately
/// needs one question answered, and the host is what wires the port in.
fn started_host(
    storage_dir: &std::path::Path,
    registry: Arc<Registry>,
) -> (SystemPluginHost, Vec<String>) {
    let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
    for plugin in standard_plugins(storage_dir, registry).expect("plugins build") {
        let name = plugin.id().as_str().to_string();
        let verified = common::system_manifest(&name, plugin.capabilities()).expect("verifies");
        host.register(plugin, &verified, common::NOW)
            .unwrap_or_else(|e| panic!("`{name}` must register: {e}"));
    }
    let mut names = Vec::new();
    for name in host
        .names()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<String>>()
    {
        host.init(&name, common::NOW)
            .unwrap_or_else(|e| panic!("`{name}` must init: {e}"));
        names.push(name);
    }
    (host, names)
}

#[test]
fn the_standard_set_is_the_four_documented_plugins_with_the_documented_capabilities() {
    let declarations = standard_declarations();
    let ids: Vec<&str> = declarations.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        ids,
        vec![
            "com.twinsearth.sys.identity",
            "com.twinsearth.sys.storage",
            "com.twinsearth.sys.policy",
            "com.twinsearth.sys.orchestrator",
        ]
    );
    // The two kernel capabilities, and only where they belong.
    assert!(declarations[2].1.contains(&Capability::KernelPolicyWrite));
    assert!(declarations[3].1.contains(&Capability::KernelPluginManage));
    for (id, capabilities) in &declarations {
        assert!(capabilities.len() >= Capability::BASIC.len(), "{id}");
        if *id != PolicyPlugin::ID && *id != OrchestratorPlugin::ID {
            assert_eq!(
                *capabilities,
                &Capability::BASIC,
                "{id} declares more than the basic set"
            );
        }
    }

    // Every declared capability is one the system tier can actually hold.
    for (id, capabilities) in &declarations {
        for capability in *capabilities {
            assert_eq!(
                capability.decision(Tier::System),
                nau_plugin::Grant::Always,
                "{id} declares {capability}, which the system tier does not hold"
            );
        }
    }
}

#[test]
fn all_four_plugins_register_initialise_and_answer_through_the_host() {
    let dir = common::scratch("started");
    let registry = common::shared(Registry::new());
    let (mut host, names) = started_host(&dir, Arc::clone(&registry));
    assert_eq!(names.len(), 4);
    assert_eq!(host.len(), 4);
    for name in &names {
        assert_eq!(
            host.state(name),
            Some(PluginState::Running),
            "`{name}` must be running"
        );
    }

    // Identity.
    let answer = host
        .handle(&request(
            "com.twinsearth.official.market",
            IdentityPlugin::ID,
            Capability::MessageSend,
            serde_json::json!({ "op": "did_from_seed", "seed_hex": "01".repeat(32) }),
        ))
        .expect("answers");
    assert_eq!(answer["did"], serde_json::json!("did:nau:34750f98bd59fcfc"));

    // Policy.
    let answer = host
        .handle(&request(
            "com.twinsearth.official.market",
            PolicyPlugin::ID,
            Capability::MessageSend,
            serde_json::json!({ "op": "decide", "capability": "economy:settle", "tier": "3rd" }),
        ))
        .expect("answers");
    assert_eq!(answer["decision"], serde_json::json!("refused"));

    // Storage, in its own directory.
    host.handle(&request(
        "com.twinsearth.official.market",
        StoragePlugin::ID,
        Capability::StorageOwn,
        serde_json::json!({ "op": "set", "key": "k", "value": "v" }),
    ))
    .expect("stores");
    let answer = host
        .handle(&request(
            "com.twinsearth.official.market",
            StoragePlugin::ID,
            Capability::StorageOwn,
            serde_json::json!({ "op": "get", "key": "k" }),
        ))
        .expect("answers");
    assert_eq!(answer["value"], serde_json::json!("v"));

    // Orchestrator: an empty registry is an empty plan, not an error.
    let answer = host
        .handle(&request(
            "com.twinsearth.sys.policy",
            OrchestratorPlugin::ID,
            Capability::KernelPluginManage,
            serde_json::json!({ "op": "check" }),
        ))
        .expect("answers");
    assert_eq!(answer["acyclic"], serde_json::json!(true));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_registered_plugin_serves_only_while_running() {
    let dir = common::scratch("states");
    let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
    let verified = common::system_manifest(IdentityPlugin::ID, IdentityPlugin::CAPABILITIES)
        .expect("verifies");
    host.register(
        Box::new(IdentityPlugin::new().expect("valid id")),
        &verified,
        common::NOW,
    )
    .expect("registers");
    assert_eq!(host.state(IdentityPlugin::ID), Some(PluginState::Loaded));
    assert_eq!(host.token(IdentityPlugin::ID), Some(&verified.token));

    let msg = request(
        "com.twinsearth.official.market",
        IdentityPlugin::ID,
        Capability::MessageSend,
        serde_json::json!({ "op": "binds", "public_key": "00".repeat(32), "did": "did:nau:0" }),
    );

    // Registered but not initialised: a typed refusal, not an empty answer.
    let err = host.handle(&msg).expect_err("must be refused");
    assert!(err.to_string().contains("loaded"), "{err}");

    host.init(IdentityPlugin::ID, common::NOW).expect("inits");
    assert_eq!(host.state(IdentityPlugin::ID), Some(PluginState::Running));
    assert!(
        host.handle(&msg).is_err(),
        "the payload is wrong on purpose"
    );

    host.shutdown(IdentityPlugin::ID, common::NOW)
        .expect("shuts down");
    assert_eq!(host.state(IdentityPlugin::ID), Some(PluginState::Stopped));
    let err = host.handle(&msg).expect_err("must be refused");
    assert!(err.to_string().contains("stopped"), "{err}");

    // The lifecycle history records why each step happened.
    let history = host.history(IdentityPlugin::ID).expect("history");
    let because: Vec<&str> = history.iter().map(|t| t.because.as_str()).collect();
    assert!(
        because.iter().any(|b| b.contains("verified")),
        "{because:?}"
    );
    assert!(because.iter().any(|b| b.contains("on_init")), "{because:?}");
    assert!(because.iter().any(|b| b.contains("stop")), "{because:?}");

    // Initialising twice is an illegal transition, not a silent no-op.
    let err = host
        .init(IdentityPlugin::ID, common::NOW)
        .expect_err("refused");
    assert!(err.to_string().contains("not the next step"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_host_refuses_a_manifest_from_another_tier() {
    // A third-party manifest is verified and loadable -- and still must not be able
    // to register a plugin that runs in the host's address space.
    let verified = sign::verified_third_party(
        "io.example.analytics",
        &Capability::BASIC,
        &common::third_party_key(),
    )
    .expect("verifies");
    let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
    let err = host
        .register(
            Box::new(IdentityPlugin::new().expect("valid id")),
            &verified,
            common::NOW,
        )
        .expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains("3rd"), "{text}");
    assert!(text.contains("address space"), "{text}");
    assert!(host.is_empty());
}

#[test]
fn the_host_refuses_a_manifest_that_names_a_different_plugin() {
    let verified =
        common::system_manifest(PolicyPlugin::ID, PolicyPlugin::CAPABILITIES).expect("verifies");
    let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
    let err = host
        .register(
            Box::new(IdentityPlugin::new().expect("valid id")),
            &verified,
            common::NOW,
        )
        .expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains(PolicyPlugin::ID), "{text}");
    assert!(text.contains(IdentityPlugin::ID), "{text}");
}

#[test]
fn the_host_refuses_a_token_that_undergrants_the_plugin_it_names() {
    // A system manifest for the policy plugin that grants only the basic set: the
    // plugin declares `kernel:policy:write`, so registration refuses by name.
    let verified = common::system_manifest(PolicyPlugin::ID, &Capability::BASIC).expect("verifies");
    let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
    let err = host
        .register(
            Box::new(PolicyPlugin::new().expect("valid id")),
            &verified,
            common::NOW,
        )
        .expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains("kernel:policy:write"), "{text}");
    assert!(text.contains("does not hold"), "{text}");
    assert!(host.is_empty());
}

#[test]
fn a_plugin_is_registered_only_once() {
    let verified = common::system_manifest(IdentityPlugin::ID, IdentityPlugin::CAPABILITIES)
        .expect("verifies");
    let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
    host.register(
        Box::new(IdentityPlugin::new().expect("valid id")),
        &verified,
        common::NOW,
    )
    .expect("registers");
    let err = host
        .register(
            Box::new(IdentityPlugin::new().expect("valid id")),
            &verified,
            common::NOW,
        )
        .expect_err("must be refused");
    assert!(err.to_string().contains("already registered"), "{err}");
}

#[test]
fn the_host_dispatches_point_to_point_only() {
    let dir = common::scratch("dispatch");
    let registry = common::shared(Registry::new());
    let (mut host, _) = started_host(&dir, registry);

    let mut to_host = request(
        "com.twinsearth.official.market",
        IdentityPlugin::ID,
        Capability::MessageSend,
        serde_json::json!({ "op": "binds" }),
    );
    to_host.target = Target::Host;
    let err = host.handle(&to_host).expect_err("must be refused");
    assert!(err.to_string().contains("addresses the host"), "{err}");

    let mut broadcast = request(
        "com.twinsearth.official.market",
        IdentityPlugin::ID,
        Capability::MessageSend,
        serde_json::json!({ "op": "binds" }),
    );
    broadcast.target = Target::Broadcast;
    let err = host.handle(&broadcast).expect_err("must be refused");
    assert!(err.to_string().contains("broadcast"), "{err}");

    let unknown = request(
        "com.twinsearth.official.market",
        "com.twinsearth.sys.absent",
        Capability::MessageSend,
        serde_json::json!({ "op": "binds" }),
    );
    let err = host.handle(&unknown).expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains("com.twinsearth.sys.absent"), "{text}");
    assert!(text.contains("registered:"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_message_declaring_a_capability_a_plugin_does_not_hold_is_refused_by_name_through_the_host() {
    let dir = common::scratch("refusal-names");
    let registry = common::shared(Registry::new());
    let (mut host, _) = started_host(&dir, registry);

    let err = host
        .handle(&request(
            "com.twinsearth.official.market",
            IdentityPlugin::ID,
            Capability::DhtRead,
            serde_json::json!({ "op": "binds" }),
        ))
        .expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains("net:dht:read"), "{text}");
    assert!(text.contains(IdentityPlugin::ID), "{text}");

    // And the refusal is recorded in the plugin's own bounded log sink.
    let logs = host.logs(IdentityPlugin::ID).expect("logs");
    assert!(
        logs.iter().any(|r| r.message.contains("net:dht:read")),
        "the refusal must be logged: {logs:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_capability_name_in_a_message_is_refused_rather_than_ignored() {
    let dir = common::scratch("unknown-cap");
    let registry = common::shared(Registry::new());
    let (mut host, _) = started_host(&dir, registry);

    let mut msg = request(
        "com.twinsearth.official.market",
        IdentityPlugin::ID,
        Capability::MessageSend,
        serde_json::json!({ "op": "binds" }),
    );
    msg.capability = "net:dht:reed".to_string();
    let err = host.handle(&msg).expect_err("must be refused");
    assert!(err.to_string().contains("net:dht:read"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_orchestrator_orders_the_registry_the_host_gave_it() {
    let dir = common::scratch("order");
    let mut registry = Registry::new();
    let first = sign::verified_third_party(
        "io.example.first",
        &Capability::BASIC,
        &common::third_party_key(),
    )
    .expect("verifies");
    common::activate(&mut registry, &first).expect("activates");
    registry
        .insert(
            sign::verified_third_party(
                "io.example.second",
                &Capability::BASIC,
                &common::third_party_key(),
            )
            .expect("verifies"),
            vec![Dependency {
                name: "io.example.first".into(),
                min_version: "1.0.0".into(),
            }],
        )
        .expect("inserts");

    let registry = common::shared(registry);
    let order: Arc<dyn LoadOrderSource> = Arc::clone(&registry) as Arc<dyn LoadOrderSource>;
    let mut plugin = OrchestratorPlugin::new(order).expect("valid id");
    let verified =
        common::system_manifest(OrchestratorPlugin::ID, OrchestratorPlugin::CAPABILITIES)
            .expect("verifies");
    let mut ctx = HostContext::new(verified.token.clone(), HostLimits::default()).expect("context");
    plugin.init(&mut ctx).expect("inits");

    let answer = plugin
        .handle(&request(
            "com.twinsearth.sys.policy",
            OrchestratorPlugin::ID,
            Capability::KernelPluginManage,
            serde_json::json!({ "op": "start_order" }),
        ))
        .expect("answers");
    assert_eq!(
        answer["order"],
        serde_json::json!(["io.example.first", "io.example.second"])
    );

    // The plan was queued for the bus, not delivered by the plugin.
    assert!(ctx.outbox_len() >= 1, "the announcement is queued");

    // The registry the host wired in is the same one, and it still answers.
    assert_eq!(registry.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_plugin_that_is_not_registered_is_not_reachable() {
    let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
    let err = host
        .handle(&request(
            "com.twinsearth.official.market",
            IdentityPlugin::ID,
            Capability::MessageSend,
            serde_json::json!({ "op": "binds" }),
        ))
        .expect_err("must be refused");
    assert!(matches!(err, PluginError::Bus(_)), "{err}");
    assert!(host.logs(IdentityPlugin::ID).is_none());
    assert!(host.state(IdentityPlugin::ID).is_none());
    assert!(host.shutdown(IdentityPlugin::ID, common::NOW).is_err());
}

#[test]
fn a_host_with_zero_limits_is_refused_rather_than_read_as_unlimited() {
    let limits = HostLimits {
        max_outbox: 0,
        ..HostLimits::default()
    };
    assert!(SystemPluginHost::new(limits).is_err());
    let limits = HostLimits {
        max_log_records: 0,
        ..HostLimits::default()
    };
    assert!(SystemPluginHost::new(limits).is_err());
}
