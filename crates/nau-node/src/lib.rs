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
pub mod plugin_host;

use std::path::Path;

use nau_core::{NauError, Result};
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
        let market = Market::restore(config.market.clone(), &store, now)?;
        Ok(Self {
            market,
            store: std::sync::Arc::new(store),
            config,
            directory: p2p::Directory::new(),
        })
    }

    /// Build an in-memory node (tests, `--ephemeral`).
    pub fn ephemeral(config: NodeConfig) -> Result<Self> {
        let store = nau_store::MemoryStore::new();
        let market = Market::new(config.market.clone());
        Ok(Self {
            market,
            store: std::sync::Arc::new(store),
            config,
            directory: p2p::Directory::new(),
        })
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
