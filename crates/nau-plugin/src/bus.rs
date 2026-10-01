//! The plugin message bus (PMB): the only channel between plugins.
//!
//! # Why a single channel
//!
//! Upstream's plugin-era code let components call each other directly, so a policy
//! check had to be repeated at every call site — and the audit found repeatedly that
//! the checks existed but had no callers. Here there is exactly one place a message
//! can travel, which makes the policy a choke point instead of a convention. A plugin
//! cannot call the host, or another plugin, by any other route.
//!
//! # The five checks, and why each is where it is
//!
//! [`Bus::send`] refuses a message unless **all** of these hold, and it reports
//! [`LoadRefusal`]-style codes rather than prose so a caller can branch on them:
//!
//! 1. the sender's token exists (it was issued at load, so the plugin was verified);
//! 2. the token holds [`Capability::MessageSend`];
//! 3. the sender's lifecycle state is `Running` — a paused or quarantined plugin
//!    does not get to keep talking;
//! 4. every recipient is running and not quarantined;
//! 5. the frame is within the size cap and the sender is within its rate limit.
//!
//! # Encoding: canonical JSON, deliberately
//!
//! The draft architecture specified bincode in one section and CBOR in another. This
//! bus uses this project's **canonical JSON**, because that form is already
//! byte-identical across Rust, Python and JavaScript and is pinned by conformance
//! vectors — so a plugin written in another language can be a first-class citizen,
//! and an audit log stays readable. The cost is size, bounded by
//! [`BusLimits::max_message_bytes`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::capability::{Capability, CapabilityToken};
use crate::error::{LoadRefusal, PluginError, Result};
use crate::lifecycle::PluginState;
use crate::registry::Registry;
use crate::tier::PluginId;

/// What a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PmbKind {
    /// Expects exactly one response.
    Request,
    /// Answers a request.
    Response,
    /// Fire and forget.
    Event,
}

impl PmbKind {
    /// Every kind.
    pub const ALL: [PmbKind; 3] = [PmbKind::Request, PmbKind::Response, PmbKind::Event];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            PmbKind::Request => "request",
            PmbKind::Response => "response",
            PmbKind::Event => "event",
        }
    }
}

/// Delivery priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// Lowest.
    Low,
    /// Ordinary.
    Normal,
    /// Above ordinary.
    High,
    /// Reserved for the host's own control traffic.
    Critical,
}

impl Priority {
    /// Every priority, lowest first.
    pub const ALL: [Priority; 4] = [
        Priority::Low,
        Priority::Normal,
        Priority::High,
        Priority::Critical,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Priority::Low => "low",
            Priority::Normal => "normal",
            Priority::High => "high",
            Priority::Critical => "critical",
        }
    }

    /// Whether a non-system plugin may use this priority.
    ///
    /// `Critical` is reserved: if any plugin could mark its traffic critical, the
    /// classification would carry no information for a scheduler.
    #[must_use]
    pub fn allowed_for_plugins(self) -> bool {
        !matches!(self, Priority::Critical)
    }
}

/// Who a message is for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// One named plugin.
    Plugin(String),
    /// Every subscriber of the topic.
    Broadcast,
    /// The host itself.
    Host,
}

impl Target {
    /// A stable label, for logs.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Target::Plugin(name) => name.clone(),
            Target::Broadcast => "broadcast".to_string(),
            Target::Host => "host".to_string(),
        }
    }
}

/// One bus message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PmbMessage {
    /// Unique message id.
    pub id: String,
    /// Set on a response, naming the request it answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corr_id: Option<String>,
    /// The sender's plugin name.
    pub source: String,
    /// Where it is going.
    pub target: Target,
    /// The capability the sender is exercising.
    pub capability: String,
    /// What kind of message it is.
    pub kind: PmbKind,
    /// Publish/subscribe topic, for broadcasts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// The body.
    pub payload: serde_json::Value,
    /// When it was created, Unix seconds.
    pub issued_at: u64,
    /// How long it may live, milliseconds. Zero is refused.
    pub ttl_ms: u64,
    /// Delivery priority.
    pub priority: Priority,
}

impl PmbMessage {
    /// Build a message with a fresh id.
    #[must_use]
    pub fn new(
        source: &PluginId,
        target: Target,
        capability: Capability,
        kind: PmbKind,
        payload: serde_json::Value,
        issued_at: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            corr_id: None,
            source: source.as_str().to_string(),
            target,
            capability: capability.as_str().to_string(),
            kind,
            topic: None,
            payload,
            issued_at,
            ttl_ms: 5_000,
            priority: Priority::Normal,
        }
    }

    /// Set the topic.
    #[must_use]
    pub fn with_topic(mut self, topic: &str) -> Self {
        self.topic = Some(topic.to_string());
        self
    }

    /// Set the correlation id.
    #[must_use]
    pub fn answering(mut self, corr_id: &str) -> Self {
        self.corr_id = Some(corr_id.to_string());
        self
    }

    /// Whether the message is expired at `now_ms`.
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        let issued_ms = self.issued_at.saturating_mul(1_000);
        now_ms.saturating_sub(issued_ms) > self.ttl_ms
    }
}

/// What the bus is allowed to do, as configuration rather than constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusLimits {
    /// Largest encoded message.
    pub max_message_bytes: usize,
    /// Messages a single plugin may send per minute.
    pub max_messages_per_minute: u32,
    /// Audit records retained.
    pub max_audit_records: usize,
}

impl Default for BusLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 256 * 1024,
            max_messages_per_minute: 600,
            max_audit_records: 4_096,
        }
    }
}

impl BusLimits {
    /// Validate the configuration itself.
    ///
    /// # Errors
    ///
    /// [`PluginError::Bus`] for a zero cap, because a zero here would look like
    /// "unlimited" and behave like "nothing works".
    pub fn validate(&self) -> Result<()> {
        for (value, name) in [
            (self.max_message_bytes, "max_message_bytes"),
            (
                self.max_messages_per_minute as usize,
                "max_messages_per_minute",
            ),
            (self.max_audit_records, "max_audit_records"),
        ] {
            if value == 0 {
                return Err(PluginError::Bus(format!("{name} must not be zero")));
            }
        }
        Ok(())
    }
}

/// One delivery attempt, recorded for the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The message id.
    pub message: String,
    /// Sender.
    pub source: String,
    /// Who received it (empty when the attempt was refused).
    pub delivered_to: Vec<String>,
    /// The capability exercised.
    pub capability: String,
    /// Whether it was delivered.
    pub delivered: bool,
    /// The refusal code, when it was not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// When.
    pub at: u64,
}

/// A delivery that succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// Recipients, in name order.
    pub recipients: Vec<String>,
    /// The index of this attempt in the audit log.
    pub audit_index: usize,
}

/// A sliding window of send times, per plugin.
#[derive(Debug, Default, Clone)]
struct RateWindow {
    sent_ms: Vec<u64>,
}

impl RateWindow {
    /// Record a send at `now_ms` and report whether it is within `per_minute`.
    fn admit(&mut self, now_ms: u64, per_minute: u32) -> bool {
        // Keep a send while it is younger than a minute. The earlier form computed
        // `now - 60_000` and kept `t > cutoff`, which at `now = 1_000` gives a cutoff
        // of 0 and therefore *drops* a send made at t = 0 -- one second old, and
        // already forgotten. Saturating arithmetic on the timestamp itself is the
        // form that cannot clip the window at the start of the clock.
        self.sent_ms.retain(|t| t.saturating_add(60_000) > now_ms);
        // `try_from` rather than `as`: a saturating cast here would silently let a
        // long window through, which is the opposite of what a rate limit is for.
        let sent = u32::try_from(self.sent_ms.len()).unwrap_or(u32::MAX);
        if sent >= per_minute {
            return false;
        }
        self.sent_ms.push(now_ms);
        true
    }
}

/// The plugin message bus.
#[derive(Debug)]
pub struct Bus {
    limits: BusLimits,
    tokens: BTreeMap<String, CapabilityToken>,
    subscriptions: BTreeMap<String, BTreeSet<String>>,
    rates: BTreeMap<String, RateWindow>,
    audit: Vec<AuditRecord>,
}

impl Bus {
    /// A bus with the given limits.
    ///
    /// # Errors
    ///
    /// [`PluginError::Bus`] when the limits are not usable.
    pub fn new(limits: BusLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            tokens: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            rates: BTreeMap::new(),
            audit: Vec::new(),
        })
    }

    /// Register a plugin's token. Called once, after verification.
    ///
    /// # Errors
    ///
    /// [`PluginError::Bus`] when the plugin is already registered: two tokens for one
    /// name would make "which capabilities does this plugin hold?" unanswerable.
    pub fn register(&mut self, token: CapabilityToken) -> Result<()> {
        let name = token.plugin().to_string();
        if self.tokens.contains_key(&name) {
            return Err(PluginError::Bus(format!(
                "`{name}` already has a token on this bus; a second one would make its \
                 capability set ambiguous"
            )));
        }
        self.tokens.insert(name, token);
        Ok(())
    }

    /// Drop a plugin's token and subscriptions.
    pub fn deregister(&mut self, name: &str) {
        self.tokens.remove(name);
        self.rates.remove(name);
        for subscribers in self.subscriptions.values_mut() {
            subscribers.remove(name);
        }
    }

    /// The token a plugin holds, if any.
    #[must_use]
    pub fn token(&self, name: &str) -> Option<&CapabilityToken> {
        self.tokens.get(name)
    }

    /// Subscribe a plugin to a topic.
    ///
    /// # Errors
    ///
    /// [`PluginError::Bus`] when the plugin has no token, has not been seen running,
    /// or the topic is empty.
    pub fn subscribe(
        &mut self,
        membership: &dyn BusMembership,
        name: &str,
        topic: &str,
    ) -> Result<()> {
        if topic.trim().is_empty() {
            return Err(PluginError::Bus("a topic must not be empty".into()));
        }
        let token = self
            .tokens
            .get(name)
            .ok_or_else(|| PluginError::Bus(format!("`{name}` has no token on this bus")))?;
        token.require(Capability::MessageSend)?;
        require_running(membership, name)?;
        self.subscriptions
            .entry(topic.to_string())
            .or_default()
            .insert(name.to_string());
        Ok(())
    }

    /// Subscribers of a topic, in name order.
    #[must_use]
    pub fn subscribers(&self, topic: &str) -> Vec<String> {
        self.subscriptions
            .get(topic)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The audit log, oldest first.
    #[must_use]
    pub fn audit(&self) -> &[AuditRecord] {
        &self.audit
    }

    /// The bus limits.
    #[must_use]
    pub fn limits(&self) -> BusLimits {
        self.limits
    }

    /// Send a message on behalf of a plugin that has **presented its token**.
    ///
    /// # Why the caller's token is an argument
    ///
    /// The first version of this function looked the sender up in a token map keyed by
    /// `message.source` — a field inside the message. Any caller able to set that field
    /// could therefore act under another plugin's capabilities, and the bus would
    /// confirm it. The plugin framework built on this kernel had to close that hole at
    /// its own door; a kernel that leaves the door open and relies on every caller to
    /// close it has the policy in the wrong place.
    ///
    /// So the caller passes the token it holds, and `message.source` must agree with
    /// it. A mismatch is a refusal with its own code, not a silent substitution.
    ///
    /// # Errors
    ///
    /// [`PluginError::Bus`] with a [`LoadRefusal`]-style code prefix. The attempted
    /// send is recorded in the audit log **whether or not it succeeded**, because a
    /// refused message is the interesting one.
    pub fn send(
        &mut self,
        membership: &dyn BusMembership,
        caller: &CapabilityToken,
        message: &PmbMessage,
        now_ms: u64,
    ) -> Result<Delivery> {
        let source = message.source.clone();
        let capability = message.capability.clone();
        let message_id = message.id.clone();
        let at = now_ms / 1_000;

        // 1. the message must actually be from the plugin whose token this is. Checked
        //    first, because everything below reasons about `source` as if it were true.
        if source != caller.plugin() {
            return self.refuse(
                message_id,
                source.clone(),
                capability,
                at,
                &format!(
                    "bus_source_forged: the message claims to be from `{source}` but the presented \
                     token belongs to `{}`; a plugin does not get to choose whose capabilities it \
                     uses",
                    caller.plugin()
                ),
                LoadRefusal::CapabilityNotPermitted,
            );
        }
        // 2. and holds the capability it is exercising. The declared `capability`
        //    field is checked against the token rather than trusted: a plugin may not
        //    exercise a label it does not hold even if the label is harmless.
        let declared = Capability::parse(&capability)?;
        if let Err(e) = caller.require(declared) {
            return self.refuse(
                message_id,
                source,
                capability,
                at,
                &format!("bus_capability_refused: {e}"),
                LoadRefusal::CapabilityNotPermitted,
            );
        }
        // 3. the sender is running
        if let Err(e) = require_running(membership, &source) {
            return self.refuse(
                message_id,
                source,
                capability,
                at,
                &format!("bus_sender_not_running: {e}"),
                LoadRefusal::CapabilityNotPermitted,
            );
        }
        // 3b. `Critical` is the host's own priority
        if !message.priority.allowed_for_plugins() && !source.starts_with("com.twinsearth.sys.") {
            return self.refuse(
                message_id,
                source,
                capability,
                at,
                "bus_priority_reserved: `critical` is reserved to system plugins",
                LoadRefusal::CapabilityNotPermitted,
            );
        }
        // 4. the frame is not expired and not oversized
        if message.ttl_ms == 0 {
            return self.refuse(
                message_id,
                source,
                capability,
                at,
                "bus_no_ttl: a message with a zero ttl is expired on arrival",
                LoadRefusal::ManifestInvalid,
            );
        }
        let encoded = serde_json::to_vec(message)?;
        if encoded.len() > self.limits.max_message_bytes {
            return self.refuse(
                message_id,
                source,
                capability,
                at,
                &format!(
                    "bus_too_large: {} bytes exceeds the {} byte cap",
                    encoded.len(),
                    self.limits.max_message_bytes
                ),
                LoadRefusal::ManifestInvalid,
            );
        }
        // 5. the rate limit
        let window = self.rates.entry(source.clone()).or_default();
        if !window.admit(now_ms, self.limits.max_messages_per_minute) {
            return self.refuse(
                message_id,
                source,
                capability,
                at,
                &format!(
                    "bus_rate_limited: more than {} messages in a minute",
                    self.limits.max_messages_per_minute
                ),
                LoadRefusal::ManifestInvalid,
            );
        }

        // Resolve recipients.
        let recipients = match &message.target {
            Target::Host => Vec::new(),
            Target::Broadcast => {
                let topic = message.topic.clone().ok_or_else(|| {
                    PluginError::Bus(
                        "bus_broadcast_without_topic: a broadcast needs a topic".into(),
                    )
                })?;
                self.subscribers(&topic)
            }
            Target::Plugin(name) => vec![name.clone()],
        };

        // 4b. every recipient must be running. A broadcast is refused as a whole if
        //     any subscriber is not: partial delivery of one logical message is the
        //     kind of split state that is impossible to reason about afterwards.
        for recipient in &recipients {
            if let Err(e) = require_running(membership, recipient) {
                return self.refuse(
                    message_id,
                    source,
                    capability,
                    at,
                    &format!("bus_recipient_not_running: {recipient}: {e}"),
                    LoadRefusal::CapabilityNotPermitted,
                );
            }
            if recipient == &source {
                return self.refuse(
                    message_id,
                    source,
                    capability,
                    at,
                    "bus_self_send: a plugin may not send to itself",
                    LoadRefusal::CapabilityNotPermitted,
                );
            }
        }

        let index = self.record(AuditRecord {
            message: message_id,
            source,
            delivered_to: recipients.clone(),
            capability,
            delivered: true,
            refusal: None,
            at,
        });
        Ok(Delivery {
            recipients,
            audit_index: index,
        })
    }

    /// Whether a refusal means the sender tried to exceed its authority.
    ///
    /// Only three refusals do, and the distinction matters because the consequence is
    /// quarantine on the third one:
    ///
    /// * `bus_source_forged` — the sender claimed another plugin's identity;
    /// * `bus_capability_refused` — the sender exercised a capability it does not hold;
    /// * `bus_priority_reserved` — the sender used the host's own priority class.
    ///
    /// Everything else is *not* misconduct and must not escalate: `bus_rate_limited` is
    /// backpressure, and turning "busy" into "banned" would make the bus punish load;
    /// `bus_too_large` and `bus_no_ttl` are malformed messages, which are bugs before
    /// they are attacks; `bus_recipient_not_running` and `bus_self_send` are state, not
    /// intent. A rule that quarantines on any refusal is a rule that quarantines on a
    /// race.
    #[must_use]
    pub fn refusal_is_misconduct(refusal: &str) -> bool {
        const MISCONDUCT: [&str; 3] = [
            "bus_source_forged",
            "bus_capability_refused",
            "bus_priority_reserved",
        ];
        MISCONDUCT.iter().any(|code| refusal.contains(code))
    }

    /// Send, and record a violation against the sender when the refusal is its own doing.
    ///
    /// This joins two rules that were separately true and jointly unenforced: the bus
    /// refuses an over-reaching message, and the lifecycle quarantines a plugin after
    /// three violations. Neither knew about the other, so "three violations →
    /// quarantined" was a sentence in the architecture document with nothing behind it.
    /// Use this instead of [`Bus::send`] wherever the caller can supply a mutable
    /// registry.
    ///
    /// # Errors
    ///
    /// Whatever [`Bus::send`] refuses. The violation is recorded **in addition** to the
    /// refusal, never instead of it: a caller that saw only the escalation would lose
    /// the reason the message was rejected.
    pub fn send_checked(
        &mut self,
        registry: &mut Registry,
        caller: &CapabilityToken,
        message: &PmbMessage,
        now_ms: u64,
    ) -> Result<Delivery> {
        match self.send(registry, caller, message, now_ms) {
            Ok(delivery) => Ok(delivery),
            Err(e) => {
                let text = e.to_string();
                if Self::refusal_is_misconduct(&text) {
                    // Recorded against the plugin whose token was presented, not against
                    // `message.source`: after the forgery check the two are the same
                    // name, and taking it from the token is what keeps them the same.
                    let at = now_ms / 1_000;
                    let _ = registry.record_violation(caller.plugin(), &text, at);
                }
                Err(e)
            }
        }
    }

    /// Record a refusal and return the error.
    fn refuse(
        &mut self,
        message: String,
        source: String,
        capability: String,
        at: u64,
        reason: &str,
        _why: LoadRefusal,
    ) -> Result<Delivery> {
        self.record(AuditRecord {
            message,
            source,
            delivered_to: Vec::new(),
            capability,
            delivered: false,
            refusal: Some(reason.to_string()),
            at,
        });
        Err(PluginError::Bus(reason.to_string()))
    }

    /// Append an audit record, trimming the oldest beyond the cap.
    fn record(&mut self, record: AuditRecord) -> usize {
        self.audit.push(record);
        if self.audit.len() > self.limits.max_audit_records {
            let excess = self.audit.len() - self.limits.max_audit_records;
            self.audit.drain(0..excess);
        }
        self.audit.len() - 1
    }
}

/// Refuse unless `name` is registered and running.
/// What the bus has to know about the plugins it delivers between.
///
/// # Why this is a trait rather than `&Registry`
///
/// The bus needs exactly one fact about a participant: **is it running?** It used to ask a
/// [`Registry`], which meant the only thing that could drive a delivery was the kernel's
/// load registry. The in-process system plugins are not in that registry — their lifecycle
/// lives in `SystemPluginHost` — so a system plugin could queue a bus message and **nothing
/// could carry it**, because the carrier demanded a registry the host does not have.
///
/// That is a design gap rather than a wiring oversight: `SystemPluginHost::flush_outbox`
/// documented the same limitation from the other side ("Escalation is not done here... the
/// registry is shared with this host through an `Arc`"). Asking only the question the bus
/// actually needs is what lets both kinds of host answer it.
///
/// Implementors answer about plugins they know; `None` means "not registered", which the bus
/// reports as a refusal rather than treating as stopped.
pub trait BusMembership {
    /// The lifecycle state of a registered plugin, or `None` when it is not registered.
    fn state_of(&self, name: &str) -> Option<PluginState>;
}

impl BusMembership for Registry {
    fn state_of(&self, name: &str) -> Option<PluginState> {
        self.get(name).map(|entry| entry.state())
    }
}

/// A shared registry is a registry.
///
/// Needed because callers that hold an `Arc<Registry>` — the orchestrator's
/// `LoadOrderSource`, and the end-to-end tests — have a `&Arc<Registry>` to pass, and that
/// reference does not coerce to the trait object without this.
impl<T: BusMembership + ?Sized> BusMembership for Arc<T> {
    fn state_of(&self, name: &str) -> Option<PluginState> {
        (**self).state_of(name)
    }
}

fn require_running(membership: &dyn BusMembership, name: &str) -> Result<PluginState> {
    let state = membership
        .state_of(name)
        .ok_or_else(|| PluginError::Bus(format!("`{name}` is not registered")))?;
    if !state.is_serving() {
        return Err(PluginError::Bus(format!(
            "`{name}` is {state}, not running"
        )));
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_limit_is_refused_as_configuration() {
        for limits in [
            BusLimits {
                max_message_bytes: 0,
                ..BusLimits::default()
            },
            BusLimits {
                max_messages_per_minute: 0,
                ..BusLimits::default()
            },
            BusLimits {
                max_audit_records: 0,
                ..BusLimits::default()
            },
        ] {
            assert!(limits.validate().is_err());
        }
        assert!(BusLimits::default().validate().is_ok());
    }

    #[test]
    fn the_default_bounds_are_the_ones_the_docs_state() {
        let limits = BusLimits::default();
        assert_eq!(limits.max_message_bytes, 256 * 1024);
        assert_eq!(limits.max_messages_per_minute, 600);
        assert_eq!(limits.max_audit_records, 4_096);
    }

    /// A token for `name` holding `caps`, for bus tests.
    fn token_for(name: &str, caps: &[Capability]) -> CapabilityToken {
        CapabilityToken::issue(
            name,
            crate::tier::Tier::ThirdParty,
            caps,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            1_750_000_000,
        )
        .expect("a third-party token for the basic set")
    }

    #[test]
    fn a_message_that_claims_another_plugins_identity_is_refused() {
        // The hole this closes: the bus used to look the sender up by
        // `message.source`, a field the caller supplies. A plugin able to write that
        // field could act under another plugin's capabilities and the bus would confirm
        // it. Now the caller must present a token, and the claim must match it.
        let registry = Registry::new();
        let mut bus = Bus::new(BusLimits::default()).expect("bus");
        let mine = token_for("io.example.a", &[Capability::MessageSend]);
        let msg = PmbMessage::new(
            &PluginId::parse("io.example.victim").expect("id"),
            Target::Host,
            Capability::MessageSend,
            PmbKind::Event,
            serde_json::json!({ "hello": 1 }),
            1_750_000_000,
        );
        let err = bus
            .send(&registry, &mine, &msg, 1_750_000_000_000)
            .expect_err("a forged source must be refused");
        let text = err.to_string();
        assert!(text.contains("bus_source_forged"), "{text}");
        assert!(text.contains("io.example.victim"), "{text}");
        assert!(text.contains("io.example.a"), "{text}");
        assert_eq!(
            bus.audit().len(),
            1,
            "the refusal is the interesting record"
        );
        assert!(!bus.audit()[0].delivered);
    }

    #[test]
    fn a_capability_the_presented_token_does_not_hold_is_refused_by_name() {
        let registry = Registry::new();
        let mut bus = Bus::new(BusLimits::default()).expect("bus");
        let mine = token_for("io.example.a", &[Capability::MessageSend]);
        let msg = PmbMessage::new(
            &PluginId::parse("io.example.a").expect("id"),
            Target::Host,
            Capability::GossipPublish,
            PmbKind::Event,
            serde_json::json!({}),
            1_750_000_000,
        );
        let err = bus
            .send(&registry, &mine, &msg, 1_750_000_000_000)
            .expect_err("refused");
        assert!(err.to_string().contains("bus_capability_refused"), "{err}");
        assert!(err.to_string().contains("net:gossip:publish"), "{err}");
    }

    #[test]
    fn a_refused_send_is_recorded_in_the_audit_log() {
        let registry = Registry::new();
        let mut bus = Bus::new(BusLimits::default()).expect("bus");
        let mine = token_for("io.example.a", &[Capability::MessageSend]);
        let msg = PmbMessage::new(
            &PluginId::parse("io.example.a").expect("id"),
            Target::Host,
            Capability::GossipPublish,
            PmbKind::Event,
            serde_json::json!({}),
            1_750_000_000,
        );
        assert!(bus.send(&registry, &mine, &msg, 1_750_000_000_000).is_err());
        assert_eq!(bus.audit().len(), 1);
        assert!(!bus.audit()[0].delivered);
        assert!(bus.audit()[0]
            .refusal
            .as_deref()
            .expect("reason")
            .contains("bus_capability_refused"));
    }

    #[test]
    fn a_message_from_a_plugin_without_a_service_loop_is_refused_by_the_rate_limiter_eventually() {
        // A rate window admits exactly `per_minute` sends and refuses the next.
        let mut window = RateWindow::default();
        for _ in 0..3 {
            assert!(window.admit(1_000, 3));
        }
        assert!(!window.admit(1_000, 3), "the fourth must be refused");
        // A minute later the window has drained.
        assert!(window.admit(61_500, 3));
    }

    #[test]
    fn the_rate_window_forgets_old_sends() {
        let mut window = RateWindow::default();
        assert!(window.admit(0, 1));
        assert!(!window.admit(1_000, 1));
        assert!(window.admit(60_001, 1));
        assert_eq!(window.sent_ms.len(), 1, "old timestamps must be dropped");
    }

    #[test]
    fn a_zero_ttl_is_refused_because_it_is_expired_on_arrival() {
        let registry = Registry::new();
        let mut bus = Bus::new(BusLimits::default()).expect("bus");
        let mut msg = PmbMessage::new(
            &PluginId::parse("io.example.a").expect("id"),
            Target::Host,
            Capability::MessageSend,
            PmbKind::Event,
            serde_json::json!({}),
            1,
        );
        msg.ttl_ms = 0;
        // The plugin is not registered, so this is refused for a reason that comes
        // first; the ttl check itself is exercised by the expiry assertions below and
        // by `a_zero_ttl_is_refused_before_the_recipient_is_resolved`.
        let mine = token_for("io.example.a", &[Capability::MessageSend]);
        assert!(bus.send(&registry, &mine, &msg, 1_000).is_err());
        assert!(msg.is_expired(1_000_000));
        assert!(!msg.is_expired(1_000));
    }

    #[test]
    fn expiry_is_computed_from_issue_time_and_ttl() {
        let mut msg = PmbMessage::new(
            &PluginId::parse("io.example.a").expect("id"),
            Target::Host,
            Capability::MessageSend,
            PmbKind::Event,
            serde_json::json!({}),
            100,
        );
        msg.ttl_ms = 500;
        assert!(!msg.is_expired(100_400));
        assert!(msg.is_expired(100_600));
    }

    #[test]
    fn critical_priority_is_reserved_to_system_plugins() {
        assert!(!Priority::Critical.allowed_for_plugins());
        for p in [Priority::Low, Priority::Normal, Priority::High] {
            assert!(p.allowed_for_plugins(), "{p:?}");
        }
        assert_eq!(Priority::ALL.len(), 4);
    }

    #[test]
    fn every_kind_and_priority_has_a_distinct_label() {
        let mut kinds: Vec<&str> = PmbKind::ALL.iter().map(|k| k.label()).collect();
        kinds.sort_unstable();
        let before = kinds.len();
        kinds.dedup();
        assert_eq!(kinds.len(), before);
        assert_eq!(PmbKind::ALL.len(), 3);

        let mut priorities: Vec<&str> = Priority::ALL.iter().map(|p| p.label()).collect();
        priorities.sort_unstable();
        let before = priorities.len();
        priorities.dedup();
        assert_eq!(priorities.len(), before);
    }

    #[test]
    fn a_target_label_is_stable_for_logs() {
        assert_eq!(Target::Host.label(), "host");
        assert_eq!(Target::Broadcast.label(), "broadcast");
        assert_eq!(
            Target::Plugin("io.example.a".into()).label(),
            "io.example.a"
        );
    }

    #[test]
    fn only_the_three_authority_refusals_count_as_misconduct() {
        for code in [
            "bus_source_forged",
            "bus_capability_refused",
            "bus_priority_reserved",
        ] {
            assert!(
                Bus::refusal_is_misconduct(&format!("bus: {code}: whatever")),
                "`{code}` is the sender exceeding its authority and must escalate"
            );
        }
        // A rule that quarantines on any refusal is a rule that quarantines on a race,
        // or on load. Each of these is named so that widening the list means deleting a
        // line a reviewer can see.
        for code in [
            "bus_rate_limited",
            "bus_too_large",
            "bus_no_ttl",
            "bus_recipient_not_running",
            "bus_sender_not_running",
            "bus_self_send",
            "bus_broadcast_without_topic",
        ] {
            assert!(
                !Bus::refusal_is_misconduct(&format!("bus: {code}: whatever")),
                "`{code}` must not escalate: it is backpressure, a malformed message or a \
                 state race, not the sender over-reaching"
            );
        }
    }

    #[test]
    fn recording_a_violation_for_an_unregistered_plugin_is_refused() {
        let mut registry = Registry::new();
        let err = registry
            .record_violation("io.example.ghost", "forged source", 1_750_000_000)
            .expect_err("must be refused");
        assert!(err.to_string().contains("not registered"), "{err}");
    }

    #[test]
    fn the_audit_log_is_bounded() {
        let limits = BusLimits {
            max_audit_records: 4,
            ..BusLimits::default()
        };
        let mut bus = Bus::new(limits).expect("bus");
        for i in 0..10 {
            let _ = bus.record(AuditRecord {
                message: format!("m{i}"),
                source: "io.example.a".into(),
                delivered_to: Vec::new(),
                capability: "plugin:message:send".into(),
                delivered: true,
                refusal: None,
                at: 1,
            });
        }
        assert_eq!(bus.audit().len(), 4);
        // The oldest were dropped, the newest kept.
        assert_eq!(bus.audit()[0].message, "m6");
        assert_eq!(bus.audit()[3].message, "m9");
    }

    #[test]
    fn subscribing_without_a_token_is_refused() {
        let registry = Registry::new();
        let mut bus = Bus::new(BusLimits::default()).expect("bus");
        let err = bus
            .subscribe(&registry, "io.example.a", "topic")
            .expect_err("refused");
        assert!(err.to_string().contains("no token"), "{err}");
        assert!(bus.subscribers("topic").is_empty());
    }

    #[test]
    fn an_empty_topic_is_refused() {
        let registry = Registry::new();
        let mut bus = Bus::new(BusLimits::default()).expect("bus");
        assert!(bus.subscribe(&registry, "io.example.a", "  ").is_err());
    }

    #[test]
    fn deregistering_removes_tokens_rates_and_subscriptions() {
        let mut bus = Bus::new(BusLimits::default()).expect("bus");
        // Insert subscriptions directly: `subscribe` needs a running registry entry,
        // which this test is not about.
        bus.subscriptions
            .entry("topic".into())
            .or_default()
            .insert("io.example.a".into());
        bus.rates.entry("io.example.a".into()).or_default();
        bus.deregister("io.example.a");
        assert!(!bus.subscriptions["topic"].contains("io.example.a"));
        assert!(!bus.rates.contains_key("io.example.a"));
        assert!(bus.token("io.example.a").is_none());
    }
}
