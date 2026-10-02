//! # nau-node — composition root
//!
//! Wires the market to a store and exposes it over HTTP. This crate is the only
//! place that knows about *all* the layers; everything below it is a port or a pure
//! service.
//!
//! ## What this replaces upstream
//!
//! Upstream's daemon is `node.rs`: 1,228 lines of free functions where the swarm
//! event pump, the relay health state machine, the relay-pool writer, the DHT RPC
//! dispatcher and the admin API all share one `select!` loop with six `&mut`
//! parameters threaded through. The audit found (GAP-ANALYSIS §6, §5.1):
//!
//! * the HTTP router ignored the request method on almost every path, so
//!   `GET /api/v1/tasks/:id/settle` **settled a task**;
//! * HTTP status codes were chosen by substring-matching a Chinese error message
//!   (`if e.contains("不存在") { 404 } else { 422 }`);
//! * requests had no body-size cap and no timeout, and `listener.accept().await?`
//!   terminated the whole process on a transient `EMFILE`;
//! * the persisted agent row was rebuilt by re-parsing the raw request body, so it
//!   diverged from what the market had actually validated.
//!
//! Here the router is a **pure function** over `(method, target, body)`. It is tested
//! without opening a socket, it enforces the method per route, and it returns typed
//! statuses. The socket loop only frames bytes.
//!
//! ## upstream v2.8.2 fix: the request path is authenticated by default
//!
//! The remaining upstream defects are in the *request path*, and they are fixed in
//! [`auth`] and [`api`]:
//!
//! * **No authentication on the REST twins of the mutating tools**
//!   (`node.rs:1107-1152` calls the router with no auth at all), while the
//!   MCP-over-HTTP path gates 15 mutating tools behind one shared secret with no
//!   per-caller identity. [`api::route`] now consults a single scope table before
//!   routing, every caller is a [`auth::Principal`] with its own id and scopes,
//!   and [`auth::Authenticator::deny_all`] — the default — refuses rather than
//!   allows. A DID-bound principal can only act as itself.
//! * **Wildcard CORS on a privileged local API** (`node.rs:741-746`). There is no
//!   wildcard here, `Origin` and `Host` are validated before routing, and a
//!   hostile origin is refused with no `Access-Control-Allow-Origin` header.
//! * **An unbounded request read** (`node.rs:984-1007`). [`api::RequestLimits`]
//!   caps the body and bounds the whole read, yielding a typed `413`/`408`, and
//!   [`api::parse_request_head`] refuses a duplicated or malformed
//!   `Content-Length` and any `Transfer-Encoding` rather than guessing.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod auth;
pub mod p2p;
// The plugin kernel's external interface. It lives here rather than in `nau-plugin`
// because printing to a terminal is a host concern: the kernel decides, the host
// reports.
pub mod plugin_cli;
// Booting the compiled-in system plugins. Composition belongs to the host: the kernel
// decides, the plugins behave, and this brings the two together.
// The management driver for the blacklist the load pipeline consults. `nau-plugin`
// models signed entries and an appeal state machine; this is what lets an operator
// actually condemn a plugin or lift a condemnation, with integrity coming from the
// signature on each entry rather than from the file's permissions.
pub mod plugin_blacklist;
pub mod plugin_host;
// The driver for the third-party registration and review flow. `nau-plugin` models the
// six-stage state machine, the scan report and the scoped certification; this is what
// makes it a process an operator can actually walk a plugin through, with the journal
// as a replayable event log so the kernel state machine stays the authority.
pub mod plugin_review;
// The host half of the process-plugin runtime: `ProcessRuntime` validates a start and
// hands the host a handle, and its `call` refuses on purpose because the exec belongs to
// the host. This module is that host, and until it existed the hand-off named a caller
// that did not exist.
pub mod plugin_process;

use std::path::Path;

use nau_core::{NauError, Result};

/// Where the booted system plugins keep their state, under the node's data directory.
///
/// A subdirectory rather than the data directory itself: `sys.storage` opens a store, and
/// the ledger's `FileStore` already owns the top level. Two stores in one directory is how
/// a plugin's writes and the node's writes end up in each other's file.
const PLUGIN_STATE_DIR: &str = "plugin-state";
use nau_market::{Market, MarketConfig};
use nau_store::{FileStore, Store};

pub use api::{
    parse_request_head, required_scope_for, route, NodeSnapshot, Request, RequestHead,
    RequestLimits, Response, MAX_BODY_BYTES, MUTATING_TARGETS, READ_TIMEOUT_SECS,
};
pub use auth::{ApiPolicy, Authenticator, Credential, Principal, Refusal, Scope};

/// Node configuration.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Market tunables.
    pub market: MarketConfig,
    /// Directory holding the append-only store.
    pub data_dir: std::path::PathBuf,
    /// Address the HTTP API binds.
    pub api_addr: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            market: MarketConfig::default(),
            data_dir: std::path::PathBuf::from("nau-data"),
            api_addr: "127.0.0.1:4002".to_string(),
        }
    }
}

/// A running node's state: a market plus its durable store.
pub struct Node {
    market: Market,
    store: std::sync::Arc<dyn Store>,
    config: NodeConfig,
    /// What peers have told us. Empty unless a P2P bridge is running.
    directory: p2p::Directory,
    /// The compiled-in T0 plugins, booted when the node opened.
    plugins: crate::plugin_host::SystemBoot,
    /// The internal bus, so a plugin that queues a message has something to carry it.
    ///
    /// # Why the daemon owns one
    ///
    /// Until this field existed the node had **no bus at all**: `Bus::new` appeared in
    /// production only inside the one-shot load pipelines, and `SystemPluginHost::flush_outbox`
    /// had no caller. A system plugin could queue a bus message and nothing would carry it —
    /// the internal messaging protocol the architecture calls PMB was a kernel component with
    /// tests and no runtime. The host side is closed by `BusMembership` (the bus now asks "is
    /// this plugin running?" rather than demanding a load registry the T0 host does not have);
    /// this field is the other half.
    bus: nau_plugin::bus::Bus,
}

impl Node {
    /// Open a node, creating `data_dir` if needed and restoring prior state.
    ///
    /// Unlike upstream — which wrote agents to SQLite and never read them back, and
    /// never persisted the ledger at all — a restart here restores agents, tasks and
    /// the exact balances.
    pub fn open(config: NodeConfig, now: u64) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)?;
        let store = FileStore::open(&config.data_dir)?;
        // One ledger handle, two owners: the market mutates it and `sys.ledger` reads it.
        //
        // Built **before either**, because the whole point is that they are the same books --
        // a market over one ledger and a plugin over another is exactly the defect this
        // replaces, and it was invisible for as long as it existed because both answered
        // plausibly.
        let books = std::sync::Arc::new(std::sync::Mutex::new(nau_ledger::Ledger::new()));
        let market = Market::restore_sharing(
            config.market.clone(),
            std::sync::Arc::clone(&books),
            &store,
            now,
        )?;
        let plugins = Self::boot_plugins(&config.data_dir.join(PLUGIN_STATE_DIR), now, &books)?;
        let bus = Self::build_bus()?;
        Ok(Self {
            market,
            store: std::sync::Arc::new(store),
            config,
            directory: p2p::Directory::new(),
            plugins,
            bus,
        })
    }

    /// Build an in-memory node (tests, `--ephemeral`).
    ///
    /// The plugins are booted here too, and into a real directory, because a plugin's
    /// `sys.storage` opens a store and a plugin host is not an in-memory notion. Leaving
    /// them unbooted in this mode would have made "the daemon hosts its plugins" true only
    /// for nodes with a data directory -- and `--ephemeral` is the mode the deployment
    /// checks and most tests use, so the sentence would have been true exactly where nobody
    /// looked.
    pub fn ephemeral(config: NodeConfig) -> Result<Self> {
        let store = nau_store::MemoryStore::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("nau-ephemeral-plugins-{}", std::process::id()));
        // **The same handle the plugins get.** This constructor built its market with
        // `Market::new`, which makes its *own* ledger -- so in ephemeral mode the market and
        // `sys.ledger` were two different books again, and the settlement gate refused every
        // settlement. `Node::open` had been fixed and this one had not, which is the shape of
        // half-wiring this repository keeps finding: the deployment gate uses `open` and stayed
        // green, while the browser end-to-end -- which runs `--ephemeral` -- failed on the first
        // real settlement it attempted.
        let books = std::sync::Arc::new(std::sync::Mutex::new(nau_ledger::Ledger::new()));
        let market = Market::sharing(config.market.clone(), std::sync::Arc::clone(&books));
        let plugins = Self::boot_plugins(&dir, now, &books)?;
        let bus = Self::build_bus()?;
        Ok(Self {
            market,
            store: std::sync::Arc::new(store),
            config,
            directory: p2p::Directory::new(),
            plugins,
            bus,
        })
    }

    /// Boot the compiled-in T0 plugins, or fail the node.
    ///
    /// # Why a failure here is fatal rather than logged
    ///
    /// The whole point of this build is that the system's own functionality is plugins. A
    /// node that came up with none of them -- because a directory was unwritable, because a
    /// declaration and a manifest disagreed, because a capability token did not cover what a
    /// plugin declares -- would be a node that is not what it says it is, and the log line
    /// saying so is a log line nobody reads before the first request.
    ///
    /// So the boot is part of opening the node and its refusal is the node's refusal.
    /// Before this, `boot_system_plugins` was called by its own tests and by
    /// `nau plugin system`, and **the daemon never called it at all**: seventeen plugins
    /// existed, were registered, were tested, and ran only when an operator typed a command.
    /// Build a bus, or a node that says why it has none.
    ///
    /// Named `build_bus` rather than `bus` because `bus()` is the read-only accessor an
    /// external interface uses; a constructor and an accessor sharing a name is how a reader
    /// ends up believing a route can replace the bus.
    ///
    /// Separate from `Boot` rather than inline because the error type differs: the bus
    /// reports `PluginError`, and a node that could not build one has to say so in its own
    /// vocabulary rather than leaking a plugin error out of `Node::open`.
    fn build_bus() -> Result<nau_plugin::bus::Bus> {
        nau_plugin::bus::Bus::new(nau_plugin::bus::BusLimits::default()).map_err(|e| {
            NauError::Validation(format!(
                "the internal bus could not be built, so plugins could not exchange messages: {e}"
            ))
        })
    }

    fn boot_plugins(
        dir: &Path,
        now: u64,
        books: &std::sync::Arc<std::sync::Mutex<nau_ledger::Ledger>>,
    ) -> Result<crate::plugin_host::SystemBoot> {
        crate::plugin_host::boot_system_plugins(dir, now, std::sync::Arc::clone(books)).map_err(
            |e| {
                NauError::Validation(format!(
                "the system plugins could not be booted, so this node would not be the node it \
                 claims to be: {e}"
            ))
            },
        )
    }

    /// The booted system plugins.
    ///
    /// Exposed so the HTTP API can report them: a plugin host nobody can see is
    /// indistinguishable from one that is not running.
    pub fn plugins(&self) -> &crate::plugin_host::SystemBoot {
        &self.plugins
    }

    /// The booted system plugins, mutably, for dispatching a request to one.
    pub fn plugins_mut(&mut self) -> &mut crate::plugin_host::SystemBoot {
        &mut self.plugins
    }

    /// The internal bus, for an external interface to **observe**.
    ///
    /// Read-only on purpose. `Bus::send` demands the caller's capability token, and nothing
    /// outside a plugin has one — minting one for an HTTP route would invent an authority this
    /// host does not have, which is the widening this build exists to refuse. So PMB's external
    /// interface is what the protocol has carried and what it is allowed to carry, and the
    /// absence of a send route is stated in the payload rather than left to be read as an
    /// omission.
    #[must_use]
    pub fn bus(&self) -> &nau_plugin::bus::Bus {
        &self.bus
    }

    /// Carry the bus messages a plugin queued during its last call.
    ///
    /// # Why this is a method on the node rather than two accessors
    ///
    /// A drain needs the host and the bus **at the same time**, and they are two fields of
    /// this struct. Reached as `node.plugins_mut()` and `node.bus_mut()` the two method calls
    /// each borrow all of `node`, so the borrow checker refuses before the compiler ever sees
    /// the bus. Borrowing the fields directly is what makes it expressible ? and it belongs
    /// here, because the node is the only place that owns both.
    ///
    /// # Errors
    ///
    /// A refusal when `plugin` is not a registered system plugin.
    pub fn drain_plugin_outbox(
        &mut self,
        plugin: &str,
        now: u64,
    ) -> Result<Vec<nau_plugins::host::OutboxOutcome>> {
        self.plugins
            .flush_outbox(plugin, &mut self.bus, now)
            .map_err(|e| NauError::Validation(e.to_string()))
    }

    /// The market.
    pub fn market(&self) -> &Market {
        &self.market
    }

    /// What peers have told this node.
    ///
    /// Shared by clone, so a P2P bridge can fill it while the HTTP router reads it.
    pub fn directory(&self) -> &p2p::Directory {
        &self.directory
    }

    /// Mutable market access, for the router.
    pub fn market_mut(&mut self) -> &mut Market {
        &mut self.market
    }

    /// The configuration.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// The store.
    pub fn store(&self) -> &dyn Store {
        self.store.as_ref()
    }

    /// Flush market state to the store.
    ///
    /// Takes `&mut self` because `Market::persist` must record how much of the
    /// journal it has written; without that it re-appended the whole ledger on
    /// every call and a restart duplicated the balances.
    pub fn persist(&mut self) -> Result<()> {
        // Clone the Arc rather than calling `self.store()`: that would borrow
        // `self` immutably for the duration of a call that needs `&mut
        // self.market`. The clone is one refcount bump.
        let store = std::sync::Arc::clone(&self.store);
        self.market.persist(store.as_ref())
    }

    /// The address the API should bind.
    pub fn api_addr(&self) -> &str {
        &self.config.api_addr
    }

    /// A read-only summary for `/health` and `/version`.
    pub fn snapshot(&self) -> NodeSnapshot {
        NodeSnapshot {
            version: nau_core::VERSION.to_string(),
            protocol: nau_core::PROTOCOL_VERSION.to_string(),
            upstream: format!(
                "{} v{}",
                nau_core::UPSTREAM_PROJECT,
                nau_core::UPSTREAM_VERSION
            ),
            stats: self.market.stats(),
        }
    }
}

/// Resolve a `--data-dir` argument, expanding a leading `~`.
///
/// Upstream's `test/README.md:64` lists "literal `~` in data dirs must be expanded"
/// as a hard-won environment fact, i.e. it bit them in practice.
pub fn expand_home(dir: &str) -> std::path::PathBuf {
    if let Some(rest) = dir.strip_prefix("~/").or_else(|| dir.strip_prefix("~\\")) {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return Path::new(&home).join(rest);
        }
    }
    std::path::PathBuf::from(dir)
}

/// Parse `NAME=value` style flags: `--api-port 4002` or `--api-port=4002`.
pub fn arg_value(args: &[String], name: &str) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        if a == name {
            return args.get(i + 1).cloned();
        }
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

/// True when a bare flag is present.
pub fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Convert a market error into an HTTP status.
///
/// Typed, unlike upstream's `if e.contains("不存在")`.
pub fn status_for(err: &NauError) -> u16 {
    match err {
        NauError::NotFound(_) => 404,
        NauError::Conflict(_) => 409,
        NauError::Unauthorized(_) => 403,
        NauError::InvalidSignature | NauError::DidKeyMismatch { .. } => 401,
        NauError::Stale(_) => 410,
        NauError::InvalidAmount(_) | NauError::InsufficientBalance { .. } => 402,
        NauError::Validation(_)
        | NauError::Canonical(_)
        | NauError::Serde(_)
        | NauError::InvalidDid(_)
        | NauError::InvalidPublicKey(_)
        | NauError::InvalidSignatureEncoding(_)
        | NauError::InvalidTransition { .. }
        | NauError::Overflow(_) => 422,
        NauError::Consensus(_) => 409,
        NauError::Io(_) => 500,
        // `NauError` is `#[non_exhaustive]`, so adding a variant must not break this
        // build. An unmapped variant surfaces as a server error rather than being
        // silently mis-classified as a client error.
        _ => 500,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_is_typed_not_string_matched() {
        assert_eq!(status_for(&NauError::NotFound("x".into())), 404);
        assert_eq!(status_for(&NauError::Conflict("x".into())), 409);
        assert_eq!(status_for(&NauError::Unauthorized("x".into())), 403);
        assert_eq!(status_for(&NauError::InvalidSignature), 401);
        assert_eq!(status_for(&NauError::Stale("x".into())), 410);
        assert_eq!(
            status_for(&NauError::InsufficientBalance {
                account: "a".into(),
                available: 1,
                required: 2
            }),
            402
        );
        assert_eq!(status_for(&NauError::Validation("x".into())), 422);
        // A message that merely *contains* 不存在 must not become a 404 by accident.
        assert_eq!(
            status_for(&NauError::Validation("不存在但不是 not-found".into())),
            422
        );
    }

    #[test]
    fn flag_parsing_accepts_both_forms() {
        let args: Vec<String> = ["--api-port", "4002", "--data-dir=~/nau", "--ephemeral"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(arg_value(&args, "--api-port").as_deref(), Some("4002"));
        assert_eq!(arg_value(&args, "--data-dir").as_deref(), Some("~/nau"));
        assert!(has_flag(&args, "--ephemeral"));
        assert!(arg_value(&args, "--missing").is_none());
    }

    #[test]
    fn home_expansion_only_touches_a_leading_tilde() {
        let expanded = expand_home("~/somewhere");
        if std::env::var_os("HOME").is_some() || std::env::var_os("USERPROFILE").is_some() {
            assert!(!expanded.to_string_lossy().starts_with('~'));
            assert!(expanded.to_string_lossy().ends_with("somewhere"));
        }
        // A tilde elsewhere is left alone.
        assert_eq!(expand_home("/tmp/~x"), std::path::PathBuf::from("/tmp/~x"));
        assert_eq!(expand_home("plain"), std::path::PathBuf::from("plain"));
    }

    #[test]
    fn an_ephemeral_node_starts_empty_and_serves_its_snapshot() {
        let node = Node::ephemeral(NodeConfig::default()).unwrap();
        let snap = node.snapshot();
        assert_eq!(snap.version, nau_core::VERSION);
        assert_eq!(snap.protocol, "nau/1");
        assert!(snap.upstream.contains("agent-universe"));
        assert_eq!(snap.stats.agents, 0);
    }
}
