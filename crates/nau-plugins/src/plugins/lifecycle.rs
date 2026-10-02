//! `com.twinsearth.sys.lifecycle` — the state machine, as a door.
//!
//! # What this door can and cannot answer
//!
//! [`nau_plugin::lifecycle`] is the kernel's state machine: twelve states, a total
//! edge function, two terminal states, and exactly one assignment site — a transition
//! table that no code path can walk around. This plugin is the door onto that
//! *machine*.
//!
//! It is deliberately **not** the door onto any plugin's current state. A T0 plugin
//! cannot read another's lifecycle: [`HostContext`] carries a token, an outbox and a
//! log sink and nothing else, the framework's own lifecycles live in
//! [`SystemPluginHost`](crate::host::SystemPluginHost), and the registry's live in
//! `nau_plugin::registry::Registry`. A door that answered "where is plugin X?" from a
//! copy of that state would be a second source of truth, and the first caller to see
//! it disagree with the host would be right to trust neither.
//!
//! So the three questions answered here are the ones the *machine* answers:
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `state` | `state` | the state's properties: terminal, serving, holding an instance, recoverable, and its legal successors |
//! | `successors` | `state` | the legal next states, from [`PluginState::next_states`] |
//! | `explain` | `from`, `to` | `legal`, or the kernel's own refusal sentence for the edge plus what kind of refusal it is |
//! | `table` | — | all twelve states with the same properties, the terminal pair, and the violation threshold |
//!
//! All four require the request to declare `plugin:message:send`.
//!
//! # How `explain` gets the kernel's answer
//!
//! The plugin does not reimplement the transition rules. It asks
//! [`PluginState::can_transition_to`] whether the edge exists, and when it does not it
//! builds a **scratch** [`Lifecycle`], walks it to `from` along edges it discovers by
//! asking the kernel for [`PluginState::next_states`], and then attempts the edge —
//! so the sentence in `refusal` is the kernel's own wording from
//! [`Lifecycle::transition`], not a paraphrase that can drift from it.
//!
//! The scratch instance is not an audit record and is thrown away: it is a way to ask
//! the machine a question. That is also why it carries a fixed non-zero timestamp —
//! a plugin cannot read the clock here, and it must not appear to.
//!
//! `reason` classifies the refusal with the kernel's own predicates: `terminal` when
//! [`PluginState::is_terminal`] holds, `repeat` when `from == to` (a repeat is
//! deliberately not an edge), and `no_edge` otherwise.

use std::collections::VecDeque;

use nau_plugin::bus::PmbMessage;
use nau_plugin::lifecycle::{Lifecycle, PluginState, VIOLATION_THRESHOLD};
use nau_plugin::{Capability, PluginError, PluginId, Result};
use serde_json::{json, Map, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: the state name is not one of the twelve.
pub const CODE_UNKNOWN_STATE: &str = "lifecycle_unknown_state";
/// Error code: no sequence of legal transitions reaches the state named.
pub const CODE_UNREACHABLE_STATE: &str = "lifecycle_state_unreachable";

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["state", "successors", "explain", "table"];

/// The timestamp the scratch lifecycle carries.
///
/// One, not "now": the kernel refuses a zero timestamp, the plugin has no clock, and
/// the scratch instance is discarded — it is an enquiry, not an audit record.
const SCRATCH_AT: u64 = 1;

/// The reason a transition is not an edge, named with the kernel's own predicates.
const REASON_TERMINAL: &str = "terminal";
/// The reason: `from == to`, which the kernel refuses on purpose.
const REASON_REPEAT: &str = "repeat";
/// The reason: the kernel declares no edge from `from` to `to`.
const REASON_NO_EDGE: &str = "no_edge";

/// The lifecycle system plugin.
pub struct LifecyclePlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl LifecyclePlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.lifecycle";

    /// The capabilities the plugin declares: the basic set.
    ///
    /// The state machine is read-only knowledge, and every question this door answers
    /// is one any plugin may ask: a plugin that cannot learn which transitions are
    /// legal can only discover it by failing one.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`LifecyclePlugin::ID`] is not a valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for LifecyclePlugin {
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
                "lifecycle ready: {} states, {} terminal, {} violations quarantine",
                PluginState::ALL.len(),
                PluginState::TERMINAL.len(),
                VIOLATION_THRESHOLD
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "state" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let state = parse_state(payload::string_field(&msg.payload, "state")?)?;
                Ok(payload::answer(Self::ID, "state", state_json(state)))
            }
            "successors" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let state = parse_state(payload::string_field(&msg.payload, "state")?)?;
                Ok(payload::answer(
                    Self::ID,
                    "successors",
                    json!({
                        "state": state.label(),
                        "is_terminal": state.is_terminal(),
                        "next_states": labels(&state.next_states()),
                    }),
                ))
            }
            "explain" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let from = parse_state(payload::string_field(&msg.payload, "from")?)?;
                let to = parse_state(payload::string_field(&msg.payload, "to")?)?;
                let legal = from.can_transition_to(to);
                let mut body = Map::new();
                body.insert("from".to_string(), json!(from.label()));
                body.insert("to".to_string(), json!(to.label()));
                body.insert("legal".to_string(), json!(legal));
                body.insert(
                    "next_states".to_string(),
                    json!(labels(&from.next_states())),
                );
                body.insert("refusal".to_string(), Value::Null);
                if !legal {
                    body.insert("refusal".to_string(), json!(kernel_refusal(from, to)?));
                    body.insert("reason".to_string(), json!(refusal_reason(from, to)));
                }
                Ok(payload::answer(Self::ID, "explain", Value::Object(body)))
            }
            "table" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let states: Vec<Value> = PluginState::ALL.iter().map(|s| state_json(*s)).collect();
                Ok(payload::answer(
                    Self::ID,
                    "table",
                    json!({
                        "states": states,
                        "terminal": labels(&PluginState::TERMINAL),
                        "violation_threshold": VIOLATION_THRESHOLD,
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

/// Every property of one state, from the kernel's own predicates.
fn state_json(state: PluginState) -> Value {
    json!({
        "state": state.label(),
        "is_terminal": state.is_terminal(),
        "is_serving": state.is_serving(),
        "holds_instance": state.holds_instance(),
        "is_recoverable": state.is_recoverable(),
        "next_states": labels(&state.next_states()),
        "violation_threshold": VIOLATION_THRESHOLD,
    })
}

/// The labels of a state list, in the order the kernel returned them.
fn labels(states: &[PluginState]) -> Vec<&'static str> {
    states.iter().map(|state| state.label()).collect()
}

/// Parse a state name, refusing an unknown one rather than defaulting.
fn parse_state(name: &str) -> Result<PluginState> {
    let wanted = name.trim().to_ascii_lowercase();
    PluginState::ALL
        .into_iter()
        .find(|state| state.label() == wanted)
        .ok_or_else(|| {
            PluginError::Lifecycle(format!(
                "{CODE_UNKNOWN_STATE}: `{name}` is not a plugin state; the states are {}",
                PluginState::ALL
                    .iter()
                    .map(|s| s.label())
                    .collect::<Vec<&str>>()
                    .join(", ")
            ))
        })
}

/// Which kind of refusal an illegal edge is, using the kernel's own predicates.
fn refusal_reason(from: PluginState, to: PluginState) -> &'static str {
    if from.is_terminal() {
        REASON_TERMINAL
    } else if from == to {
        REASON_REPEAT
    } else {
        REASON_NO_EDGE
    }
}

/// The kernel's own refusal sentence for `from -> to`.
///
/// The plugin does not reimplement the rules the sentence comes from: it walks a
/// scratch [`Lifecycle`] to `from` along edges the kernel declares and then asks the
/// kernel to make the illegal move. `path_to` is a breadth-first search over
/// [`PluginState::next_states`], so a state added to the enum is reachable here
/// without this file changing.
///
/// # Errors
///
/// [`CODE_UNREACHABLE_STATE`] when no path exists, which cannot happen for today's
/// twelve states (`every_state_the_kernel_declares_is_reachable_along_kernel_legal_edges`
/// asserts it) but is returned rather than unwrapped, and whatever the kernel reports
/// while walking the path.
fn kernel_refusal(from: PluginState, to: PluginState) -> Result<String> {
    let path = path_to(from).ok_or_else(|| {
        PluginError::Lifecycle(format!(
            "{CODE_UNREACHABLE_STATE}: no sequence of legal transitions reaches {}",
            from.label()
        ))
    })?;
    let mut scratch = Lifecycle::new();
    for step in &path {
        scratch.transition(
            *step,
            "scratch: walking to the state whose edge is under explanation",
            SCRATCH_AT,
        )?;
    }
    match scratch.transition(
        to,
        "scratch: the transition this door was asked to explain",
        SCRATCH_AT,
    ) {
        Ok(_) => Ok(format!("{} -> {} is an edge", from.label(), to.label())),
        Err(refusal) => Ok(refusal.to_string()),
    }
}

/// The transitions a scratch lifecycle must make to arrive at `target`, in order.
///
/// A breadth-first walk of the kernel's own edge function — the graph is not copied
/// here, it is interrogated. The result is the list of *steps*, not of states: a
/// lifecycle that has made no step is already at `Discovered`, so `Some(vec![])` is
/// the answer for it and the initial state is never handed back as a transition the
/// caller could attempt (which the kernel would refuse, correctly, as
/// `discovered -> discovered is not an edge`).
fn path_to(target: PluginState) -> Option<Vec<PluginState>> {
    if target == PluginState::Discovered {
        return Some(Vec::new());
    }
    let mut queue: VecDeque<(PluginState, Vec<PluginState>)> = VecDeque::new();
    queue.push_back((PluginState::Discovered, Vec::new()));
    let mut seen: Vec<PluginState> = vec![PluginState::Discovered];
    while let Some((current, steps)) = queue.pop_front() {
        for next in current.next_states() {
            let mut extended = steps.clone();
            extended.push(next);
            if next == target {
                return Some(extended);
            }
            if !seen.contains(&next) {
                seen.push(next);
                queue.push_back((next, extended));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use crate::sign::{fixture_key, verified_system, FIXTURE_ISSUED_AT};
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::{CapabilityToken, Tier};

    const NOW: u64 = FIXTURE_ISSUED_AT;
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// The caller every fixture message comes from: a plugin that holds the basic set.
    const CALLER: &str = "com.twinsearth.official.market";

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse(CALLER).expect("a valid plugin name");
        PmbMessage::new(
            &id,
            Target::Plugin(LifecyclePlugin::ID.to_string()),
            Capability::parse(capability).expect("a known capability"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    /// Initialise a plugin exactly as the host would, without the host.
    fn initialised(mut plugin: LifecyclePlugin) -> LifecyclePlugin {
        let token = CapabilityToken::issue(
            LifecyclePlugin::ID,
            Tier::System,
            LifecyclePlugin::CAPABILITIES,
            DIGEST,
            NOW,
        )
        .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    /// A walk to `target` performed with the kernel, for tests that need a lifecycle
    /// parked on a state without borrowing the helper under test.
    fn parked(target: PluginState) -> Lifecycle {
        let mut life = Lifecycle::new();
        for step in [
            PluginState::Verified,
            PluginState::Loaded,
            PluginState::Running,
        ] {
            if life.state() == target {
                break;
            }
            life.transition(step, "test: parking a lifecycle", NOW)
                .expect("the happy path is legal");
        }
        if life.state() != target {
            for step in [
                PluginState::Stopping,
                PluginState::Stopped,
                PluginState::Archived,
            ] {
                if life.state() == target {
                    break;
                }
                life.transition(step, "test: parking a lifecycle", NOW)
                    .expect("the retiring path is legal");
            }
        }
        assert_eq!(life.state(), target, "the helper must park on {target}");
        life
    }

    #[test]
    fn the_plugin_registers_reaches_running_and_only_then_answers() {
        let verified = verified_system(
            LifecyclePlugin::ID,
            LifecyclePlugin::CAPABILITIES,
            &fixture_key(3),
            &fixture_key(9),
        )
        .expect("a system manifest for this plugin verifies");
        let mut host =
            SystemPluginHost::new(HostLimits::default()).expect("the default limits are usable");
        host.register(
            Box::new(LifecyclePlugin::new().expect("the constant id parses")),
            &verified,
            NOW,
        )
        .expect("registers against its own manifest");
        assert_eq!(host.state(LifecyclePlugin::ID), Some(PluginState::Loaded));

        // Registered is not running: the host refuses before the plugin is asked.
        let err = host
            .handle(&request("plugin:message:send", json!({ "op": "table" })))
            .expect_err("a loaded plugin does not serve");
        assert!(err.to_string().contains("not running"), "{err}");

        host.init(LifecyclePlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(LifecyclePlugin::ID), Some(PluginState::Running));
        assert!(host
            .handle(&request("plugin:message:send", json!({ "op": "table" })))
            .is_ok());
    }

    #[test]
    fn the_state_operation_reports_the_kernels_own_predicates_for_every_state() {
        let mut plugin = initialised(LifecyclePlugin::new().expect("id"));
        for state in PluginState::ALL {
            let answer = plugin
                .handle(&request(
                    "plugin:message:send",
                    json!({ "op": "state", "state": state.label() }),
                ))
                .expect("answers");
            assert_eq!(answer["state"], json!(state.label()));
            assert_eq!(answer["is_terminal"], json!(state.is_terminal()), "{state}");
            assert_eq!(answer["is_serving"], json!(state.is_serving()), "{state}");
            assert_eq!(
                answer["holds_instance"],
                json!(state.holds_instance()),
                "{state}"
            );
            assert_eq!(
                answer["is_recoverable"],
                json!(state.is_recoverable()),
                "{state}"
            );
            assert_eq!(answer["violation_threshold"], json!(VIOLATION_THRESHOLD));
            let next: Vec<&str> = answer["next_states"]
                .as_array()
                .expect("an array")
                .iter()
                .map(|v| v.as_str().expect("a label"))
                .collect();
            assert_eq!(
                next,
                state
                    .next_states()
                    .iter()
                    .map(|s| s.label())
                    .collect::<Vec<&str>>(),
                "{state}"
            );
        }
    }

    #[test]
    fn the_table_operation_covers_every_state_and_names_the_terminal_pair() {
        let mut plugin = initialised(LifecyclePlugin::new().expect("id"));
        let answer = plugin
            .handle(&request("plugin:message:send", json!({ "op": "table" })))
            .expect("answers");
        assert_eq!(
            answer["states"].as_array().expect("an array").len(),
            PluginState::ALL.len()
        );
        assert_eq!(
            answer["terminal"],
            json!(PluginState::TERMINAL
                .iter()
                .map(|s| s.label())
                .collect::<Vec<&str>>())
        );
        assert_eq!(answer["violation_threshold"], json!(VIOLATION_THRESHOLD));

        // `successors` is the same fact for one state, and a terminal state's answer is
        // an empty list rather than a refusal.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "successors", "state": "blacklisted" }),
            ))
            .expect("answers");
        assert_eq!(answer["next_states"], json!([]));
        assert_eq!(answer["is_terminal"], json!(true));

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "successors", "state": "running" }),
            ))
            .expect("answers");
        assert_eq!(
            answer["next_states"].as_array().expect("an array").len(),
            PluginState::Running.next_states().len()
        );
        assert_eq!(answer["is_terminal"], json!(false));
    }

    #[test]
    fn explain_agrees_with_the_kernel_for_every_pair_of_states() {
        let mut plugin = initialised(LifecyclePlugin::new().expect("id"));
        for from in PluginState::ALL {
            for to in PluginState::ALL {
                let answer = plugin
                    .handle(&request(
                        "plugin:message:send",
                        json!({ "op": "explain", "from": from.label(), "to": to.label() }),
                    ))
                    .expect("answers");
                let legal = from.can_transition_to(to);
                assert_eq!(answer["legal"], json!(legal), "{from} -> {to}");
                if legal {
                    assert_eq!(answer["refusal"], Value::Null, "{from} -> {to} is legal");
                } else {
                    let refusal = answer["refusal"].as_str().expect("a refusal sentence");
                    assert!(!refusal.is_empty(), "{from} -> {to}");
                    let expected = if from.is_terminal() {
                        REASON_TERMINAL
                    } else if from == to {
                        REASON_REPEAT
                    } else {
                        REASON_NO_EDGE
                    };
                    assert_eq!(answer["reason"], json!(expected), "{from} -> {to}");
                }
            }
        }
    }

    #[test]
    fn explain_repeats_the_kernels_own_refusal_wording() {
        let mut plugin = initialised(LifecyclePlugin::new().expect("id"));

        // The expected sentences are produced here by the kernel, from lifecycles this
        // test parks by hand -- not by the helper the plugin uses.
        let repeat = parked(PluginState::Running)
            .transition(PluginState::Running, "test: a repeat", NOW)
            .expect_err("a repeat is not an edge")
            .to_string();
        let terminal = parked(PluginState::Archived)
            .transition(PluginState::Running, "test: out of a terminal state", NOW)
            .expect_err("no transition leaves a terminal state")
            .to_string();
        let no_edge = Lifecycle::new()
            .transition(PluginState::Running, "test: skipping verification", NOW)
            .expect_err("discovery does not go straight to running")
            .to_string();

        for (from, to, expected, reason) in [
            (
                PluginState::Running,
                PluginState::Running,
                &repeat,
                REASON_REPEAT,
            ),
            (
                PluginState::Archived,
                PluginState::Running,
                &terminal,
                REASON_TERMINAL,
            ),
            (
                PluginState::Discovered,
                PluginState::Running,
                &no_edge,
                REASON_NO_EDGE,
            ),
        ] {
            let answer = plugin
                .handle(&request(
                    "plugin:message:send",
                    json!({ "op": "explain", "from": from.label(), "to": to.label() }),
                ))
                .expect("answers");
            assert_eq!(answer["legal"], json!(false), "{from} -> {to}");
            assert_eq!(answer["refusal"], json!(expected), "{from} -> {to}");
            assert_eq!(answer["reason"], json!(reason), "{from} -> {to}");
        }
    }

    #[test]
    fn every_state_the_kernel_declares_is_reachable_along_kernel_legal_edges() {
        // The scratch walk in `kernel_refusal` needs a path to every state it is asked
        // about, and the typed refusal for "no path" must never be the answer. This
        // proves each path with the kernel itself rather than with the search that
        // found it.
        for target in PluginState::ALL {
            let path = path_to(target).unwrap_or_else(|| panic!("{target} must be reachable"));
            let mut life = Lifecycle::new();
            for step in &path {
                life.transition(*step, "test: walking the path the helper found", NOW)
                    .expect("every step of a returned path is a legal edge");
            }
            assert_eq!(life.state(), target);
        }
    }

    #[test]
    fn an_unknown_state_is_refused_rather_than_defaulted() {
        let mut plugin = initialised(LifecyclePlugin::new().expect("id"));
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "state", "state": "sleeping" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(CODE_UNKNOWN_STATE), "{text}");
        assert!(text.contains("quarantined"), "{text}");
    }

    #[test]
    fn every_label_is_the_name_the_kernel_serialises() {
        // The plugin's vocabulary is the kernel's wire vocabulary, not a parallel one.
        for state in PluginState::ALL {
            assert_eq!(
                serde_json::to_value(state).expect("serialises"),
                json!(state.label())
            );
            assert_eq!(parse_state(state.label()).expect("parses"), state);
            assert_eq!(
                parse_state(&state.label().to_ascii_uppercase()).expect("case-insensitive"),
                state
            );
        }
    }

    #[test]
    fn a_message_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let mut plugin = initialised(LifecyclePlugin::new().expect("id"));
        let err = plugin
            .handle(&request("net:dht:write", json!({ "op": "table" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("net:dht:write"), "{err}");
    }

    #[test]
    fn an_unknown_operation_lists_the_vocabulary_this_door_implements() {
        let mut plugin = initialised(LifecyclePlugin::new().expect("id"));
        let err = plugin
            .handle(&request("plugin:message:send", json!({ "op": "pause" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("state, successors, explain, table"), "{text}");
    }
}
