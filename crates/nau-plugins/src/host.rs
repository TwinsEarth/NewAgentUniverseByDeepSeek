//! The T0 system-plugin framework: one door, one gate, no ambient authority.
//!
//! # What a system plugin is
//!
//! A system plugin (`com.twinsearth.sys.*`) is compiled into the host, runs in the
//! host's address space and cannot be hot-plugged. That makes it *more* dangerous
//! than a guest, not less, so the framework gives it exactly one door and checks two
//! things at that door:
//!
//! | Question | Where it is answered | What a "no" looks like |
//! |---|---|---|
//! | May this plugin exist with these capabilities? | [`SystemPluginHost::register`] | a typed refusal naming the missing capability |
//! | May it act on this message? | the plugin, via [`PluginGrant::require_declared`] | a typed refusal naming the capability |
//!
//! The gate is deliberately *two* checks rather than one. The bus already refuses a
//! message whose declared capability the sender does not hold, and the kernel already
//! refuses a token for a capability the tier may not have. Both are re-checked here,
//! because a T0 plugin is in-process: if the framework is ever reached by a path that
//! is not the bus — a future host wiring, a test, a REPL — the refusal must still
//! happen, and it must still name the capability. Defence in depth is not redundancy
//! when the boundary is an address space.
//!
//! # What the context deliberately does not expose
//!
//! [`HostContext`] carries a token, an outbox and a log sink. It does **not** carry
//! the [`Registry`](nau_plugin::registry::Registry), the sandbox manager, the bus,
//! the arbiter, the blacklist or any other plugin's state — and the type has no
//! method that could reach them. A plugin that needs something else needs it as
//! constructor wiring the host chose to compile in (see
//! [`LoadOrderSource`](crate::plugins::orchestrator::LoadOrderSource)), which is a
//! visible grant rather than an ambient one.
//!
//! Two consequences are worth stating because they are deliberate:
//!
//! * **A plugin cannot read the clock.** [`SystemPlugin::handle`] receives no
//!   timestamp and the context has no `now`; a plugin that stamped its own audit
//!   records would be choosing the time it is logged at.
//! * **A plugin cannot send to itself or forge a source.** [`HostContext::request_send`]
//!   and [`BusHandle::send`] refuse a message whose `source` is not the plugin's own
//!   id. The kernel's bus trusts `msg.source` when it looks up the sender's token, so
//!   an in-process plugin that could set it freely could act under another plugin's
//!   capabilities. The bind lives at this door because this is where the forgery
//!   would be manufactured.
//!
//! # State
//!
//! A registered plugin is put through the kernel's own
//! [`Lifecycle`](nau_plugin::lifecycle::Lifecycle): `Verified` and `Loaded` at
//! registration, `Running` when [`SystemPlugin::init`] returns, `Stopping` and
//! `Stopped` at shutdown. [`SystemPluginHost::handle`] serves only a `Running`
//! plugin, so "it is registered" and "it is answering" are different facts with
//! different names.
//!
//! One seam is worth stating rather than discovering: there are **two** records of a
//! T0 plugin being alive. [`SystemPluginHost`] owns the plugin object and its
//! lifecycle; the [`Registry`](nau_plugin::registry::Registry) holds the entry the
//! [`Bus`](nau_plugin::bus::Bus) consults before it delivers to that name. This
//! framework keeps its own record in step with the object it actually calls, and the
//! bus keeps its own — so a host that stops a T0 plugin must move the registry entry
//! too, which is the arbiter's job because the arbiter is what holds `&mut Registry`.
//! A test in `tests/end_to_end.rs` asserts each record on its own terms rather than
//! pretending they are one.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use nau_plugin::bus::{Bus, Delivery, PmbMessage, Target};
use nau_plugin::lifecycle::{Lifecycle, PluginState};
use nau_plugin::{
    Capability, CapabilityToken, PluginError, PluginId, Result, Tier, VerifiedManifest,
};

/// Longest log message retained, in bytes; longer ones are truncated at a character
/// boundary and marked with `…`.
pub const MAX_LOG_MESSAGE_BYTES: usize = 512;

/// Error code: a plugin tried to send a message that claims another plugin as its
/// source.
pub const CODE_SOURCE_FORGED: &str = "host_source_forged";
/// Error code: a plugin's outbox is full.
pub const CODE_OUTBOX_FULL: &str = "host_outbox_full";

/// How much a T0 plugin may queue and log before the host intervenes.
///
/// Both fields must be non-zero: the kernel's rule for limits applies here too,
/// because a zero limit reads as "unlimited" and behaves as "nothing works".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostLimits {
    /// Log records retained per plugin; the oldest are dropped beyond this.
    pub max_log_records: usize,
    /// Messages a plugin may have queued for the bus at once.
    pub max_outbox: usize,
}

impl Default for HostLimits {
    fn default() -> Self {
        Self {
            max_log_records: 256,
            max_outbox: 64,
        }
    }
}

impl HostLimits {
    /// Refuse a zero limit.
    ///
    /// # Errors
    ///
    /// [`PluginError::Runtime`] naming the zero field.
    pub fn validate(&self) -> Result<()> {
        for (value, name) in [
            (self.max_log_records, "max_log_records"),
            (self.max_outbox, "max_outbox"),
        ] {
            if value == 0 {
                return Err(PluginError::Runtime(format!(
                    "{name} must not be zero: a zero limit is not an unlimited one"
                )));
            }
        }
        Ok(())
    }
}

/// Severity of a log record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Internal detail.
    Debug,
    /// Ordinary activity.
    Info,
    /// Something was refused.
    Warn,
    /// The plugin failed.
    Error,
}

impl LogLevel {
    /// Every level, least severe first.
    pub const ALL: [LogLevel; 4] = [
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One log record from a T0 plugin.
///
/// There is no timestamp field, and that is a decision rather than an omission: an
/// in-process plugin could otherwise backdate its own audit trail. The host stamps
/// the time when it drains the sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// Severity.
    pub level: LogLevel,
    /// The plugin that wrote it.
    pub plugin: String,
    /// The message, at most [`MAX_LOG_MESSAGE_BYTES`] bytes.
    pub message: String,
}

/// A cloneable handle for *requesting* a bus send during
/// [`SystemPlugin::handle`].
///
/// It queues; it does not deliver. The queue is drained by
/// [`SystemPluginHost::flush_outbox`], which runs each message through
/// [`Bus::send`] — so every one of the bus's five checks still applies, and a
/// refusal is recorded rather than lost.
#[derive(Clone)]
pub struct BusHandle {
    outbox: Arc<Mutex<Vec<PmbMessage>>>,
    owner: String,
    max_outbox: usize,
}

impl fmt::Debug for BusHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusHandle")
            .field("owner", &self.owner)
            .field("max_outbox", &self.max_outbox)
            .finish_non_exhaustive()
    }
}

impl BusHandle {
    /// Queue one message for the bus.
    ///
    /// # Errors
    ///
    /// [`PluginError::Bus`] with [`CODE_SOURCE_FORGED`] when `message.source` is not
    /// this plugin's id, and with [`CODE_OUTBOX_FULL`] when the queue is at its cap.
    /// Nothing else is checked here: whether the plugin holds the declared
    /// capability, whether it is running and whether the recipient is running are the
    /// bus's decisions, and duplicating them would create a second answer that can
    /// disagree with the first.
    pub fn send(&self, message: PmbMessage) -> Result<()> {
        enqueue(&self.outbox, &self.owner, self.max_outbox, message)
    }

    /// The plugin this handle sends as.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
}

/// What a T0 plugin is allowed to do, and nothing else.
///
/// Obtained once, from [`SystemPlugin::init`]. It is not retained by the plugin
/// itself; the plugin keeps a [`PluginGrant`] built from it, so the host-side outbox
/// and log sink stay the host's.
pub struct HostContext {
    token: CapabilityToken,
    outbox: Arc<Mutex<Vec<PmbMessage>>>,
    logs: VecDeque<LogRecord>,
    limits: HostLimits,
}

impl fmt::Debug for HostContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostContext")
            .field("plugin", &self.token.plugin())
            .field("token", &self.token)
            .field("logs", &self.logs.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl HostContext {
    /// A context for the plugin `token` was issued to.
    ///
    /// # Errors
    ///
    /// [`PluginError::Runtime`] when the limits are not usable.
    pub fn new(token: CapabilityToken, limits: HostLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            token,
            outbox: Arc::new(Mutex::new(Vec::new())),
            logs: VecDeque::new(),
            limits,
        })
    }

    /// This plugin's capability token, read-only.
    #[must_use]
    pub fn token(&self) -> &CapabilityToken {
        &self.token
    }

    /// This plugin's id.
    #[must_use]
    pub fn id(&self) -> &str {
        self.token.plugin()
    }

    /// The limits this context enforces.
    #[must_use]
    pub fn limits(&self) -> HostLimits {
        self.limits
    }

    /// Refuse unless this plugin holds `cap`, naming the capability.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] from
    /// [`CapabilityToken::require`](nau_plugin::CapabilityToken::require), which names
    /// the plugin, the capability and the manifest digest the token is bound to.
    pub fn require(&self, cap: Capability) -> Result<()> {
        self.token.require(cap)
    }

    /// Refuse unless this plugin holds the capability a message declares.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] when the name is unknown, or when this plugin does
    /// not hold it.
    pub fn require_declared(&self, declared: &str) -> Result<Capability> {
        let cap = Capability::parse(declared)?;
        self.require(cap)?;
        Ok(cap)
    }

    /// Request a bus send. The host performs it after the bus has checked it.
    ///
    /// # Errors
    ///
    /// As [`BusHandle::send`].
    pub fn request_send(&mut self, message: PmbMessage) -> Result<()> {
        enqueue(
            &self.outbox,
            self.token.plugin(),
            self.limits.max_outbox,
            message,
        )
    }

    /// A handle for requesting sends from inside
    /// [`SystemPlugin::handle`], where the context itself is not available.
    #[must_use]
    pub fn bus_handle(&self) -> BusHandle {
        BusHandle {
            outbox: Arc::clone(&self.outbox),
            owner: self.token.plugin().to_string(),
            max_outbox: self.limits.max_outbox,
        }
    }

    /// How many messages are queued for the bus.
    #[must_use]
    pub fn outbox_len(&self) -> usize {
        lock(&self.outbox).len()
    }

    /// Take every queued message, oldest first.
    pub fn drain_outbox(&mut self) -> Vec<PmbMessage> {
        std::mem::take(&mut *lock(&self.outbox))
    }

    /// Write to the bounded log sink.
    ///
    /// The oldest record is dropped once the cap is reached, and a message longer
    /// than [`MAX_LOG_MESSAGE_BYTES`] is truncated at a character boundary: a plugin
    /// that logs a megabyte per call must not be able to grow the host's heap, and a
    /// plugin that logs a multi-byte character at exactly the cap must not be able to
    /// panic the host by splitting it.
    pub fn log(&mut self, level: LogLevel, message: &str) {
        let record = LogRecord {
            level,
            plugin: self.token.plugin().to_string(),
            message: truncate(message, MAX_LOG_MESSAGE_BYTES),
        };
        self.logs.push_back(record);
        while self.logs.len() > self.limits.max_log_records {
            self.logs.pop_front();
        }
    }

    /// The log records, oldest first.
    pub fn logs(&self) -> impl Iterator<Item = &LogRecord> {
        self.logs.iter()
    }
}

/// What a plugin keeps from [`HostContext`] after `init`.
///
/// This is the whole of a plugin's authority: its token, and a way to ask for a send.
/// Every plugin in [`crate::plugins`] is written against it, which is what makes the
/// identical refusal shape — "refuse a message that declares something this plugin
/// does not hold, and name the capability" — one implementation rather than four.
#[derive(Debug, Clone, Default)]
pub struct PluginGrant {
    token: Option<CapabilityToken>,
    bus: Option<BusHandle>,
}

impl PluginGrant {
    /// A grant with nothing in it: the plugin is not initialised.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the token and the send handle from the context.
    pub fn adopt(&mut self, ctx: &HostContext) {
        self.token = Some(ctx.token().clone());
        self.bus = Some(ctx.bus_handle());
    }

    /// Give up the grant: the plugin is shut down and holds nothing.
    pub fn release(&mut self) {
        self.token = None;
        self.bus = None;
    }

    /// Whether [`SystemPlugin::init`] has run.
    #[must_use]
    pub fn is_initialised(&self) -> bool {
        self.token.is_some()
    }

    /// The plugin's token.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] when the plugin has not been initialised or has
    /// been shut down. A call with no token behind it is refused rather than served
    /// with an implicit full authority.
    pub fn token(&self) -> Result<&CapabilityToken> {
        self.token.as_ref().ok_or_else(|| {
            PluginError::Lifecycle(
                "this plugin holds no capability token: `init` has not run, or `shutdown` has"
                    .into(),
            )
        })
    }

    /// The plugin's own id, when it has one.
    ///
    /// # Errors
    ///
    /// As [`PluginGrant::token`].
    pub fn id(&self) -> Result<&str> {
        Ok(self.token()?.plugin())
    }

    /// Refuse unless the plugin holds `cap`, naming the capability.
    ///
    /// # Errors
    ///
    /// As [`PluginGrant::token`] and
    /// [`CapabilityToken::require`](nau_plugin::CapabilityToken::require).
    pub fn require(&self, cap: Capability) -> Result<()> {
        self.token()?.require(cap)
    }

    /// Refuse unless the plugin holds the capability `message` declares.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] when the declared name is unknown or unheld.
    pub fn require_declared(&self, message: &PmbMessage) -> Result<Capability> {
        let cap = Capability::parse(&message.capability)?;
        self.require(cap)?;
        Ok(cap)
    }

    /// Refuse unless the request declares exactly the capability the operation
    /// requires.
    ///
    /// This is the check that makes the declared capability mean something at the
    /// plugin, not only at the bus: a caller that wants a kernel-authority operation
    /// must declare the kernel capability, so the *bus* checks the caller's token for
    /// it before the message is ever delivered.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] naming both the required and the declared
    /// capability.
    pub fn require_operation(&self, declared: Capability, required: Capability) -> Result<()> {
        if declared == required {
            return Ok(());
        }
        Err(PluginError::Capability(format!(
            "`{}` requires a request that declares `{}`; this one declares `{}`",
            self.id().unwrap_or("<uninitialised>"),
            required.as_str(),
            declared.as_str()
        )))
    }

    /// The send handle, for use inside [`SystemPlugin::handle`].
    ///
    /// # Errors
    ///
    /// As [`PluginGrant::token`].
    pub fn bus(&self) -> Result<&BusHandle> {
        self.bus.as_ref().ok_or_else(|| {
            PluginError::Lifecycle(
                "this plugin holds no bus handle: `init` has not run, or `shutdown` has".into(),
            )
        })
    }
}

/// What happened to one queued outbound message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxOutcome {
    /// The message id.
    pub message_id: String,
    /// The sender, which is the plugin that queued it.
    pub source: String,
    /// The capability the message declares.
    pub capability: String,
    /// Where it was addressed.
    pub target: String,
    /// Who received it; empty on a refusal.
    pub delivered_to: Vec<String>,
    /// The refusal, when the bus refused it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

impl OutboxOutcome {
    /// Whether the bus refused this message.
    #[must_use]
    pub fn refused(&self) -> bool {
        self.refusal.is_some()
    }
}

/// A plugin that runs in the host's address space.
///
/// In-process and synchronous: there is no async runtime here and no isolation to
/// claim. A T0 plugin is part of the kernel, which is why the trait is small — five
/// methods, one of which is the whole outbound surface.
pub trait SystemPlugin {
    /// The plugin's id. It must be the name in the manifest the host verified.
    fn id(&self) -> &PluginId;

    /// The capabilities this plugin declares it needs.
    ///
    /// Checked against its token at registration: a plugin that declares more than
    /// its manifest grants is refused there, by name, rather than failing later at
    /// the first call that needed it.
    fn capabilities(&self) -> &'static [Capability];

    /// Initialise. The context is available here and nowhere else.
    ///
    /// # Errors
    ///
    /// Anything the plugin needs to report. A failed `init` leaves the plugin
    /// `Loaded`, never `Running`, so it cannot serve a call it is not ready for.
    fn init(&mut self, ctx: &mut HostContext) -> Result<()>;

    /// Handle one message, answering with one JSON value.
    ///
    /// # Errors
    ///
    /// A typed refusal. Returning `Err` is an ordinary outcome, not a host fault:
    /// the refusals are the behaviour most of this crate's tests assert.
    fn handle(&mut self, msg: &PmbMessage) -> Result<Value>;

    /// Release everything the plugin holds.
    ///
    /// # Errors
    ///
    /// Anything the plugin needs to report — a durability barrier that could not be
    /// met, for instance. A failed shutdown leaves the plugin `Stopping`, which does
    /// not serve.
    fn shutdown(&mut self) -> Result<()>;
}

/// The host side of the T0 framework: who is registered, in what state, and what
/// they are allowed to ask for.
///
/// It is not a registry (that is [`Registry`], which holds verified manifests for
/// every tier) and it is not a router (that is [`Bus`]). It owns the in-process
/// plugin objects, their contexts and their lifecycles.
pub struct SystemPluginHost {
    limits: HostLimits,
    entries: BTreeMap<String, HostEntry>,
}

struct HostEntry {
    plugin: Box<dyn SystemPlugin + Send>,
    ctx: HostContext,
    lifecycle: Lifecycle,
    module_digest: String,
}

impl fmt::Debug for SystemPluginHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemPluginHost")
            .field("plugins", &self.entries.keys().collect::<Vec<_>>())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl SystemPluginHost {
    /// An empty host.
    ///
    /// # Errors
    ///
    /// [`PluginError::Runtime`] when the limits are not usable.
    pub fn new(limits: HostLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            entries: BTreeMap::new(),
        })
    }

    /// How many plugins are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Registered plugin names, in name order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    /// Register a compiled-in plugin against a verified system manifest.
    ///
    /// Three checks, all of them structural, and each with its own refusal:
    ///
    /// 1. the manifest classifies as [`Tier::System`] — a T0 plugin runs in the
    ///    host's address space, so a manifest from any other tier must not reach it;
    /// 2. the manifest names *this* plugin — a token issued for one plugin must not
    ///    be usable by another;
    /// 3. the token grants every capability the plugin declares, checked with
    ///    [`CapabilityToken::require`] so an under-granted plugin is refused by
    ///    capability name.
    ///
    /// `now` is passed to the lifecycle, which refuses a zero timestamp.
    ///
    /// # Errors
    ///
    /// [`PluginError::Tier`], [`PluginError::Manifest`],
    /// [`PluginError::Capability`] or [`PluginError::Lifecycle`] as above, and
    /// [`PluginError::Runtime`] when a context cannot be built.
    pub fn register(
        &mut self,
        plugin: Box<dyn SystemPlugin + Send>,
        verified: &VerifiedManifest,
        now: u64,
    ) -> Result<()> {
        let name = plugin.id().as_str().to_string();
        if verified.tier != Tier::System {
            return Err(PluginError::Tier(format!(
                "`{name}` is declared at tier {}, which cannot run in the host's address space; \
                 only the system tier is in-process, and the process runtime is the door for the \
                 others",
                verified.tier
            )));
        }
        if verified.id != *plugin.id() {
            return Err(PluginError::Manifest(format!(
                "this manifest is for `{}` but the plugin's id is `{name}`; a token is bound to one \
                 plugin and cannot be lent to another",
                verified.id
            )));
        }
        for cap in plugin.capabilities() {
            verified.token.require(*cap)?;
        }
        if self.entries.contains_key(&name) {
            return Err(PluginError::Manifest(format!(
                "`{name}` is already registered; two instances would make `which one is running?` \
                 unanswerable"
            )));
        }
        let ctx = HostContext::new(verified.token.clone(), self.limits)?;
        let mut lifecycle = Lifecycle::new();
        lifecycle.transition(
            PluginState::Verified,
            "the host verified this system manifest against the compiled-in digest",
            now,
        )?;
        lifecycle.transition(
            PluginState::Loaded,
            "the plugin object exists in the host; on_init has not run",
            now,
        )?;
        self.entries.insert(
            name,
            HostEntry {
                plugin,
                ctx,
                lifecycle,
                module_digest: verified.module_digest.clone(),
            },
        );
        Ok(())
    }

    /// The token a registered plugin holds.
    #[must_use]
    pub fn token(&self, name: &str) -> Option<&CapabilityToken> {
        self.entries.get(name).map(|entry| entry.ctx.token())
    }

    /// Every registered plugin's token, for registering them on the bus.
    #[must_use]
    pub fn tokens(&self) -> Vec<(String, CapabilityToken)> {
        self.entries
            .iter()
            .map(|(name, entry)| (name.clone(), entry.ctx.token().clone()))
            .collect()
    }

    /// The digest the plugin's manifest covered.
    #[must_use]
    pub fn module_digest(&self, name: &str) -> Option<&str> {
        self.entries
            .get(name)
            .map(|entry| entry.module_digest.as_str())
    }

    /// Where a registered plugin is in its lifecycle.
    #[must_use]
    pub fn state(&self, name: &str) -> Option<PluginState> {
        self.entries.get(name).map(|entry| entry.lifecycle.state())
    }

    /// How many bus messages a registered plugin has queued and not yet sent.
    ///
    /// # Why this is exposed rather than left internal
    ///
    /// [`SystemPluginHost::flush_outbox`] is what carries a queued message to the bus, and
    /// **nothing in the running node calls it**: the daemon holds no `Bus`, and this host
    /// holds no `Registry` for `Bus::send` to resolve recipients against, so the drain cannot
    /// be wired as it stands. The consequence is that a system plugin which queues a message
    /// has that message wait forever — silently, because a queue nobody reads looks exactly
    /// like a queue that is always empty.
    ///
    /// A count does not fix that. It does make it **visible**, which is the honest minimum
    /// while the carrier is missing: an operator can see the number grow instead of
    /// discovering later that plugins were never talking to each other.
    #[must_use]
    pub fn outbox_len(&self, name: &str) -> Option<usize> {
        self.entries.get(name).map(|entry| entry.ctx.outbox_len())
    }

    /// A registered plugin's lifecycle history.
    #[must_use]
    pub fn history(&self, name: &str) -> Option<&[nau_plugin::lifecycle::Transition]> {
        self.entries
            .get(name)
            .map(|entry| entry.lifecycle.history())
    }

    /// A registered plugin's log records, oldest first.
    #[must_use]
    pub fn logs(&self, name: &str) -> Option<Vec<LogRecord>> {
        self.entries
            .get(name)
            .map(|entry| entry.ctx.logs().cloned().collect())
    }

    /// Run [`SystemPlugin::init`] and move the plugin to `Running`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when nothing is registered under `name`,
    /// [`PluginError::Lifecycle`] when the plugin is not `Loaded`, and whatever
    /// `init` returns — in which case the plugin stays `Loaded` and does not serve.
    pub fn init(&mut self, name: &str, now: u64) -> Result<()> {
        let entry = self.entries.get_mut(name).ok_or_else(|| {
            PluginError::Manifest(format!("`{name}` is not a registered system plugin"))
        })?;
        if entry.lifecycle.state() != PluginState::Loaded {
            return Err(PluginError::Lifecycle(format!(
                "`{name}` is {}, so `init` is not the next step",
                entry.lifecycle.state()
            )));
        }
        entry.plugin.init(&mut entry.ctx)?;
        let granted = entry.ctx.token().granted().len();
        entry.ctx.log(
            LogLevel::Info,
            &format!("initialised {name} with {granted} capability(ies)"),
        );
        entry.lifecycle.transition(
            PluginState::Running,
            "on_init returned; the plugin is serving",
            now,
        )?;
        Ok(())
    }

    /// Dispatch one message to the plugin it addresses.
    ///
    /// The message's `source`, `ttl_ms`, declared capability and the sender's token
    /// are the **bus's** checks, not this function's: by the time a message arrives
    /// here it has either passed them or arrived by the host's own dispatch, which is
    /// the same door T0 plugins are reached by in V2.2.2.
    ///
    /// # Errors
    ///
    /// [`PluginError::Bus`] when the target is not a registered system plugin, when
    /// it is addressed to the host or to a broadcast (both of which the bus expands;
    /// this is a point-to-point dispatch), or when the plugin is not `Running`; then
    /// whatever the plugin's `handle` returns.
    pub fn handle(&mut self, message: &PmbMessage) -> Result<Value> {
        let target = match &message.target {
            Target::Plugin(name) => name.clone(),
            Target::Host => {
                return Err(PluginError::Bus(format!(
                    "`{}` addresses the host, which handles its own messages; a system plugin is \
                     addressed by name",
                    message.id
                )))
            }
            Target::Broadcast => {
                return Err(PluginError::Bus(format!(
                    "`{}` is a broadcast: the bus expands subscribers and each delivery is a \
                     point-to-point message, which is what this dispatch takes",
                    message.id
                )))
            }
        };
        let names: Vec<String> = self.entries.keys().cloned().collect();
        let entry = self.entries.get_mut(&target).ok_or_else(|| {
            PluginError::Bus(format!(
                "`{target}` is not a registered system plugin; registered: {}",
                names.join(", ")
            ))
        })?;
        let state = entry.lifecycle.state();
        if state != PluginState::Running {
            return Err(PluginError::Bus(format!(
                "`{target}` is {state}, not running; a plugin that is not serving does not answer"
            )));
        }
        let outcome = entry.plugin.handle(message);
        match &outcome {
            Ok(_) => entry.ctx.log(
                LogLevel::Info,
                &format!(
                    "answered a `{}` {} from `{}`",
                    message.capability,
                    message.kind.label(),
                    message.source
                ),
            ),
            Err(err) => entry.ctx.log(
                LogLevel::Warn,
                &format!(
                    "refused a `{}` {} from `{}`: {err}",
                    message.capability,
                    message.kind.label(),
                    message.source
                ),
            ),
        }
        outcome
    }

    /// Stop a plugin and move it to `Stopped`.
    ///
    /// The state moves to `Stopping` *before* [`SystemPlugin::shutdown`] runs, so a
    /// shutdown that fails leaves the plugin unable to serve — which is the state a
    /// caller must be able to rely on.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when nothing is registered under `name`,
    /// [`PluginError::Lifecycle`] for an illegal transition, and whatever `shutdown`
    /// returns.
    pub fn shutdown(&mut self, name: &str, now: u64) -> Result<()> {
        let entry = self.entries.get_mut(name).ok_or_else(|| {
            PluginError::Manifest(format!("`{name}` is not a registered system plugin"))
        })?;
        entry.lifecycle.transition(
            PluginState::Stopping,
            "the host asked this plugin to stop",
            now,
        )?;
        entry.plugin.shutdown()?;
        entry
            .lifecycle
            .transition(PluginState::Stopped, "on_shutdown returned", now)?;
        entry
            .ctx
            .log(LogLevel::Info, "stopped; it will not answer again");
        Ok(())
    }

    /// Drain one plugin's outbox and put every queued message through the bus.
    ///
    /// The plugin's **own** token is presented to the bus, which is what binds a message
    /// to the plugin that sent it. (An earlier revision said the token had to be on the
    /// bus or the message would be refused with `bus_no_token`; that code is gone,
    /// because the lookup it came from — keyed by the message's self-declared `source` —
    /// was a way for a plugin to act under another plugin's capabilities.)
    ///
    /// Each message is reported as an [`OutboxOutcome`] with the refusal recorded,
    /// instead of the whole call failing on the first refusal: one plugin's bad
    /// request must not discard the messages queued behind it.
    ///
    /// **Escalation is not done here, and that is a limitation rather than a choice.**
    /// [`Bus::send_checked`] records a violation against a plugin which over-reaches,
    /// and three of those quarantine it. This method cannot use it: the registry is
    /// shared with this host through an `Arc` (it is the orchestrator's
    /// `LoadOrderSource`), so no `&mut Registry` exists to record against. The
    /// escalation is therefore wired and tested at the kernel
    /// (`arbiter::tests::three_authority_violations_at_the_bus_quarantine_the_sender`)
    /// but does **not** apply to T0 traffic flushed through here. Closing that needs the
    /// violation sink to live somewhere other than the registry.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when nothing is registered under `name`.
    pub fn flush_outbox(
        &mut self,
        name: &str,
        bus: &mut Bus,
        now_ms: u64,
    ) -> Result<Vec<OutboxOutcome>> {
        // The caller's token and the queue are taken out first, ending the `&mut self`
        // borrow: the bus needs to ask *this host* which plugins are running, and that is an
        // immutable question. Holding the entry across the loop made the two borrows overlap,
        // which is why the old signature wanted an external registry instead.
        let (caller, queued) = {
            let entry = self.entries.get_mut(name).ok_or_else(|| {
                PluginError::Manifest(format!("`{name}` is not a registered system plugin"))
            })?;
            // The bus demands the *caller's* token rather than trusting `message.source`,
            // because a message is data a plugin controls and its `source` field was therefore
            // a way to choose whose capabilities to act under. This host owns the plugin's
            // token, so it can present it.
            (entry.ctx.token().clone(), entry.ctx.drain_outbox())
        };
        let mut outcomes = Vec::with_capacity(queued.len());
        for message in queued {
            let delivery: Result<Delivery> = bus.send(
                &HostMembership {
                    entries: &self.entries,
                },
                &caller,
                &message,
                now_ms,
            );
            let outcome = match delivery {
                Ok(delivered) => OutboxOutcome {
                    message_id: message.id.clone(),
                    source: message.source.clone(),
                    capability: message.capability.clone(),
                    target: message.target.label(),
                    delivered_to: delivered.recipients,
                    refusal: None,
                },
                Err(err) => OutboxOutcome {
                    message_id: message.id.clone(),
                    source: message.source.clone(),
                    capability: message.capability.clone(),
                    target: message.target.label(),
                    delivered_to: Vec::new(),
                    refusal: Some(err.to_string()),
                },
            };
            if let Some(refusal) = &outcome.refusal {
                if let Some(entry) = self.entries.get_mut(name) {
                    entry.ctx.log(
                        LogLevel::Warn,
                        &format!("the bus refused a queued message: {refusal}"),
                    );
                    // **The escalation, for T0 traffic at last.**
                    //
                    // The kernel has recorded a violation against a plugin whose message was
                    // refused as *misconduct* since `send_checked` was written, and three of
                    // those quarantine a sender. That path needs a `&mut Registry`, which this
                    // host does not have — so for a system plugin the rule stopped at the
                    // refusal: a plugin could over-reach indefinitely and stay running. The
                    // lifecycle is here, so the violation is recorded here.
                    //
                    // Which refusals count is asked of the bus rather than decided locally:
                    // `Bus::refusal_is_misconduct` is the one authority on that, and a second
                    // list in this file would be a second thing to keep in step.
                    if Bus::refusal_is_misconduct(refusal) {
                        match entry.lifecycle.violation(refusal, now_ms / 1_000) {
                            Ok(PluginState::Quarantined) => entry.ctx.log(
                                LogLevel::Warn,
                                &format!(
                                    "this was violation {} of {}; the plugin is quarantined and \
                                     can no longer be called",
                                    entry.lifecycle.violations(),
                                    nau_plugin::lifecycle::VIOLATION_THRESHOLD
                                ),
                            ),
                            Ok(_) => entry.ctx.log(
                                LogLevel::Warn,
                                &format!(
                                    "recorded violation {} of {}; {} more quarantine this plugin",
                                    entry.lifecycle.violations(),
                                    nau_plugin::lifecycle::VIOLATION_THRESHOLD,
                                    nau_plugin::lifecycle::VIOLATION_THRESHOLD
                                        .saturating_sub(entry.lifecycle.violations())
                                ),
                            ),
                            // A refusal to record is itself reported rather than swallowed:
                            // an escalation that silently does not happen is the exact failure
                            // this code exists to remove.
                            Err(e) => entry.ctx.log(
                                LogLevel::Warn,
                                &format!("the violation could not be recorded: {e}"),
                            ),
                        }
                    }
                }
            }
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }
}

/// This host, answering the bus's one question about its own plugins.
///
/// The bus asks "is this plugin running?" and used to ask a kernel [`Registry`], which the
/// in-process system plugins are not in. Borrowing the entries rather than the host keeps the
/// answer possible while `flush_outbox` holds `&mut self`.
struct HostMembership<'a> {
    entries: &'a BTreeMap<String, HostEntry>,
}

impl nau_plugin::bus::BusMembership for HostMembership<'_> {
    fn state_of(&self, name: &str) -> Option<PluginState> {
        self.entries.get(name).map(|entry| entry.lifecycle.state())
    }
}

/// Queue one message, refusing a forged source and a full outbox.
fn enqueue(
    outbox: &Arc<Mutex<Vec<PmbMessage>>>,
    owner: &str,
    max_outbox: usize,
    message: PmbMessage,
) -> Result<()> {
    if message.source != owner {
        return Err(PluginError::Bus(format!(
            "{}: `{owner}` cannot send a message whose source is `{}`; the bus looks the sender's \
             token up by `source`, so a forged one would act under another plugin's capabilities",
            CODE_SOURCE_FORGED, message.source
        )));
    }
    let mut queue = lock(outbox);
    if queue.len() >= max_outbox {
        return Err(PluginError::Bus(format!(
            "{}: `{owner}` already has {max_outbox} messages queued for the bus",
            CODE_OUTBOX_FULL
        )));
    }
    queue.push(message);
    Ok(())
}

/// Lock the outbox, recovering from poisoning.
///
/// A panic while holding this lock would otherwise poison it and turn every later
/// send into a second panic — the failure mode `nau-store`'s `sync` module was
/// written to remove from that crate. The data behind the lock is a `Vec<PmbMessage>`
/// with no invariant that a half-finished push can break, so recovering is safe here
/// in a way that is worth stating rather than assuming.
fn lock(outbox: &Arc<Mutex<Vec<PmbMessage>>>) -> MutexGuard<'_, Vec<PmbMessage>> {
    outbox
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Truncate `message` to at most `max` bytes, at a character boundary.
fn truncate(message: &str, max: usize) -> String {
    if message.len() <= max {
        return message.to_string();
    }
    let mut end = max;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = message[..end].to_string();
    out.push('…');
    out
}

/// The standard four T0 plugins this build ships, in id order.
///
/// The storage plugin is given the directory it owns, and the orchestrator the port
/// that answers its one question — constructor wiring the host chose to compile in,
/// because the context deliberately carries neither.
///
/// # Three of these are wired to a deliberately degenerate default, and that is written
/// down rather than left to be discovered
///
/// The list below constructs every plugin with its parameterless constructor, which for
/// three of them means an object that answers correctly and usefully about **nothing**.
/// That is the right default for a standard set built for tests and for a fresh node — a
/// plugin must not invent state it was not given — but a deployment that expects real
/// answers has to wire the real thing, and a reader should not have to infer that from
/// empty results:
///
/// * `sys.ledger` is built over the `books` handle the **caller** supplies, so it reports the
///   node's real ledger. It used to be built with `LedgerPlugin::new()` -- an empty ledger --
///   which made every `balance` answer `0 / known:false` and every `escrow` answer
///   `open:false` no matter what the node held. The parameter is how a host says which ledger
///   it runs; the plugin cannot guess, and a default would have been the same silent wrong
///   answer with a shorter signature.
/// * `sys.attest` is built with `AttestPlugin::new()`, which pins **no** trusted roots, so
///   every envelope is refused `signer_not_trusted`. That is fail-closed and correct for a
///   node that has not been configured with roots; a deployment wants
///   [`AttestPlugin::with_roots`](crate::plugins::attest::AttestPlugin::with_roots).
/// * `sys.sandbox` describes the **process** backend's capability table — what the platform
///   *can* enforce — while the node's default executor is `NullExecutor`, which executes
///   nothing. The report is honest about the backend the plugin holds; it does not claim to
///   know what the host actually runs. Use
///   [`SandboxPlugin::with_executor`](crate::plugins::sandbox::SandboxPlugin::with_executor)
///   to make it describe the executor in force.
///
/// # Errors
///
/// Whatever constructing a plugin reports: a bad constant id, or a store directory
/// that cannot be created.
pub fn standard_plugins(
    storage_dir: &Path,
    order: Arc<dyn crate::plugins::orchestrator::LoadOrderSource>,
    books: Arc<Mutex<nau_ledger::Ledger>>,
) -> Result<Vec<Box<dyn SystemPlugin + Send>>> {
    Ok(vec![
        Box::new(crate::plugins::identity::IdentityPlugin::new()?),
        Box::new(crate::plugins::storage::StoragePlugin::open(storage_dir)?),
        Box::new(crate::plugins::policy::PolicyPlugin::new()?),
        Box::new(crate::plugins::orchestrator::OrchestratorPlugin::new(
            order,
        )?),
        Box::new(crate::plugins::blacklist::BlacklistPlugin::new()?),
        Box::new(crate::plugins::lifecycle::LifecyclePlugin::new()?),
        Box::new(crate::plugins::arbiter::ArbiterPlugin::new()?),
        Box::new(crate::plugins::sandbox::SandboxPlugin::new()?),
        Box::new(crate::plugins::erasure::ErasurePlugin::new()?),
        // The node's own books, not an empty ledger.
        //
        // This used to be `LedgerPlugin::new()`, and the note above this function predicted
        // exactly what that would do: "every `balance` answers `0 / known:false` and every
        // `escrow` answers `open:false`". The daemon therefore hosted a ledger plugin that had
        // never seen a penny of the node's money, which is not a reporting gap -- it is a plugin
        // whose every answer was structurally wrong, and anything built on it (a settlement gate,
        // say) would have refused everything while looking like a control.
        Box::new(crate::plugins::ledger::LedgerPlugin::sharing(books)?),
        Box::new(crate::plugins::attest::AttestPlugin::new()?),
        Box::new(crate::plugins::http::HttpPlugin::new()?),
        Box::new(crate::plugins::migrate::MigratePlugin::new()?),
        Box::new(crate::plugins::transport::TransportPlugin::new()?),
        Box::new(crate::plugins::net_dht::DhtPlugin::new()?),
        Box::new(crate::plugins::net_gossip::GossipPlugin::new()?),
        // A subdirectory, so the anchor log and `sys.storage`'s key/value store do not share
        // one store: they are different records with different lifetimes, and putting them in
        // one directory would make each invisible to the other's reader.
        Box::new(crate::plugins::chain::ChainPlugin::open(
            storage_dir.join("chain"),
        )?),
        // The elastic-compute substrate. A skeleton at v3.5.0: it answers which runtimes
        // this build can run and refuses the ones it cannot, with the reason. It holds
        // the split `sandbox:create` / `sandbox:configure` pair and no policy authority.
        Box::new(crate::plugins::ausec::AUSecPlugin::new()?),
    ])
}

/// The declared capability set of every T0 plugin this build ships.
///
/// A host builds one system manifest per entry ([`Manifest`] + [`sign`](crate::sign)),
/// verifies it and registers the plugin against it. The declaration lives here rather
/// than in the host so that the plugin object and the manifest cannot disagree without
/// [`SystemPluginHost::register`] refusing.
#[must_use]
pub fn standard_declarations() -> Vec<(&'static str, &'static [Capability])> {
    vec![
        (
            crate::plugins::identity::IdentityPlugin::ID,
            crate::plugins::identity::IdentityPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::storage::StoragePlugin::ID,
            crate::plugins::storage::StoragePlugin::CAPABILITIES,
        ),
        (
            crate::plugins::policy::PolicyPlugin::ID,
            crate::plugins::policy::PolicyPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::orchestrator::OrchestratorPlugin::ID,
            crate::plugins::orchestrator::OrchestratorPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::blacklist::BlacklistPlugin::ID,
            crate::plugins::blacklist::BlacklistPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::lifecycle::LifecyclePlugin::ID,
            crate::plugins::lifecycle::LifecyclePlugin::CAPABILITIES,
        ),
        (
            crate::plugins::arbiter::ArbiterPlugin::ID,
            crate::plugins::arbiter::ArbiterPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::sandbox::SandboxPlugin::ID,
            crate::plugins::sandbox::SandboxPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::erasure::ErasurePlugin::ID,
            crate::plugins::erasure::ErasurePlugin::CAPABILITIES,
        ),
        (
            crate::plugins::ledger::LedgerPlugin::ID,
            crate::plugins::ledger::LedgerPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::attest::AttestPlugin::ID,
            crate::plugins::attest::AttestPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::http::HttpPlugin::ID,
            crate::plugins::http::HttpPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::migrate::MigratePlugin::ID,
            crate::plugins::migrate::MigratePlugin::CAPABILITIES,
        ),
        (
            crate::plugins::transport::TransportPlugin::ID,
            crate::plugins::transport::TransportPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::net_dht::DhtPlugin::ID,
            crate::plugins::net_dht::DhtPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::net_gossip::GossipPlugin::ID,
            crate::plugins::net_gossip::GossipPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::chain::ChainPlugin::ID,
            crate::plugins::chain::ChainPlugin::CAPABILITIES,
        ),
        (
            crate::plugins::ausec::AUSecPlugin::ID,
            crate::plugins::ausec::AUSecPlugin::CAPABILITIES,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_plugin::bus::{PmbKind, Priority};

    fn context(caps: &[Capability]) -> HostContext {
        let token = CapabilityToken::issue(
            "com.twinsearth.sys.identity",
            Tier::System,
            caps,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            1_750_000_000,
        )
        .expect("issuable");
        HostContext::new(token, HostLimits::default()).expect("context")
    }

    fn message(source: &str, capability: Capability) -> PmbMessage {
        let id = PluginId::parse(source).expect("id");
        PmbMessage::new(
            &id,
            Target::Host,
            capability,
            PmbKind::Event,
            serde_json::json!({}),
            1_750_000_000,
        )
    }

    #[test]
    fn a_zero_host_limit_is_refused_rather_than_read_as_unlimited() {
        for limits in [
            HostLimits {
                max_log_records: 0,
                ..HostLimits::default()
            },
            HostLimits {
                max_outbox: 0,
                ..HostLimits::default()
            },
        ] {
            assert!(limits.validate().is_err());
        }
        assert!(HostLimits::default().validate().is_ok());
        assert!(SystemPluginHost::new(HostLimits::default()).is_ok());
    }

    #[test]
    fn requiring_an_unheld_capability_names_it() {
        let ctx = context(&[Capability::MessageSend]);
        assert!(ctx.require(Capability::MessageSend).is_ok());
        let err = ctx.require(Capability::DhtRead).expect_err("refused");
        assert!(err.to_string().contains("net:dht:read"), "{err}");
        assert!(ctx.require_declared("net:dht:write").is_err());
        assert!(ctx.require_declared("not:a:capability").is_err());
    }

    #[test]
    fn a_forged_source_is_refused_at_the_door() {
        let mut ctx = context(&[Capability::MessageSend]);
        let ok = message("com.twinsearth.sys.identity", Capability::MessageSend);
        ctx.request_send(ok).expect("own source is fine");

        let forged = message("com.twinsearth.sys.policy", Capability::MessageSend);
        let err = ctx.request_send(forged).expect_err("must be refused");
        assert!(err.to_string().contains(CODE_SOURCE_FORGED), "{err}");
        assert_eq!(ctx.outbox_len(), 1, "the forged message was not queued");

        // The same bind applies to the handle used from inside `handle`.
        let handle = ctx.bus_handle();
        let forged = message("com.twinsearth.sys.policy", Capability::MessageSend);
        let err = handle.send(forged).expect_err("must be refused");
        assert!(err.to_string().contains(CODE_SOURCE_FORGED), "{err}");
        handle
            .send(message(
                "com.twinsearth.sys.identity",
                Capability::MessageSend,
            ))
            .expect("an honest send through the handle is queued");
        assert_eq!(handle.owner(), "com.twinsearth.sys.identity");
        assert_eq!(ctx.outbox_len(), 2);
    }

    #[test]
    fn the_outbox_is_bounded_and_drains_oldest_first() {
        let limits = HostLimits {
            max_outbox: 2,
            ..HostLimits::default()
        };
        let token = CapabilityToken::issue(
            "com.twinsearth.sys.identity",
            Tier::System,
            &[Capability::MessageSend],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            1,
        )
        .expect("issuable");
        let mut ctx = HostContext::new(token, limits).expect("context");
        for _ in 0..2 {
            ctx.request_send(message(
                "com.twinsearth.sys.identity",
                Capability::MessageSend,
            ))
            .expect("queued");
        }
        assert!(ctx
            .request_send(message(
                "com.twinsearth.sys.identity",
                Capability::MessageSend
            ))
            .is_err());
        assert_eq!(ctx.drain_outbox().len(), 2);
        assert_eq!(ctx.outbox_len(), 0);
    }

    #[test]
    fn the_log_sink_is_bounded_and_truncates_at_a_character_boundary() {
        let limits = HostLimits {
            max_log_records: 2,
            ..HostLimits::default()
        };
        let token = CapabilityToken::issue(
            "com.twinsearth.sys.identity",
            Tier::System,
            &[],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            1,
        )
        .expect("issuable");
        let mut ctx = HostContext::new(token, limits).expect("context");
        for i in 0..5 {
            ctx.log(LogLevel::Info, &format!("record {i}"));
        }
        let records: Vec<&LogRecord> = ctx.logs().collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message, "record 3");

        // Three-byte characters at the cap: naive slicing would panic here.
        let long = "é".repeat(MAX_LOG_MESSAGE_BYTES);
        let truncated = truncate(&long, MAX_LOG_MESSAGE_BYTES);
        assert!(truncated.len() <= MAX_LOG_MESSAGE_BYTES + '…'.len_utf8());
        assert!(truncated.ends_with('…'));
        assert_eq!(truncate("short", 64), "short");
    }

    #[test]
    fn a_grant_without_init_holds_nothing() {
        let grant = PluginGrant::new();
        assert!(!grant.is_initialised());
        assert!(grant.token().is_err());
        assert!(grant.bus().is_err());
        assert!(grant.id().is_err());
        assert!(grant.require(Capability::MessageSend).is_err());
    }

    #[test]
    fn a_grant_adopts_and_releases_the_context() {
        let ctx = context(&[Capability::MessageSend, Capability::StorageOwn]);
        let mut grant = PluginGrant::new();
        grant.adopt(&ctx);
        assert!(grant.is_initialised());
        assert!(grant.require(Capability::MessageSend).is_ok());
        assert!(grant.bus().is_ok());
        assert_eq!(grant.id().expect("id"), "com.twinsearth.sys.identity");
        grant.release();
        assert!(!grant.is_initialised());
    }

    #[test]
    fn an_operation_that_declares_the_wrong_capability_is_refused_by_name() {
        let ctx = context(&[Capability::MessageSend, Capability::KernelPolicyWrite]);
        let mut grant = PluginGrant::new();
        grant.adopt(&ctx);
        assert!(grant
            .require_operation(Capability::KernelPolicyWrite, Capability::KernelPolicyWrite)
            .is_ok());
        let err = grant
            .require_operation(Capability::MessageSend, Capability::KernelPolicyWrite)
            .expect_err("refused");
        let text = err.to_string();
        assert!(text.contains("kernel:policy:write"), "{text}");
        assert!(text.contains("plugin:message:send"), "{text}");
    }

    #[test]
    fn the_declared_capability_of_a_message_is_checked_against_the_token() {
        let ctx = context(&[Capability::MessageSend]);
        let mut grant = PluginGrant::new();
        grant.adopt(&ctx);
        assert_eq!(
            grant
                .require_declared(&message(
                    "com.twinsearth.sys.identity",
                    Capability::MessageSend
                ))
                .expect("held"),
            Capability::MessageSend
        );
        let err = grant
            .require_declared(&message(
                "com.twinsearth.sys.identity",
                Capability::DhtWrite,
            ))
            .expect_err("refused");
        assert!(err.to_string().contains("net:dht:write"), "{err}");
    }

    #[test]
    fn priority_and_kind_labels_are_stable() {
        assert_eq!(
            message("com.twinsearth.sys.identity", Capability::MessageSend)
                .kind
                .label(),
            "event"
        );
        assert_eq!(Priority::Normal.label(), "normal");
        assert_eq!(LogLevel::Info.label(), "info");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::ALL.len(), 4);
    }
}
