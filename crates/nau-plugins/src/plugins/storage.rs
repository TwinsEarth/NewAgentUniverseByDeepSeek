//! `com.twinsearth.sys.storage` — the plugin's own directory, through `nau-store`.
//!
//! # Why it wraps the store rather than opening files
//!
//! `nau-store::FileStore` is already the durable path in this workspace: append-only
//! JSONL, one `write` per record followed by `sync_data`, atomic replacement for the
//! metadata object, torn-tail tolerance on load, and a poison-recovering lock. A
//! plugin that opened its own files would re-derive all of that and get at least one
//! of them wrong — and the audit of upstream found exactly that shape of bug: state
//! that was written but never read back.
//!
//! # Scope
//!
//! The plugin can touch **its own directory and nothing else**. That is not enforced
//! by a path check here — it is enforced by the constructor: the plugin is given one
//! directory and holds no handle to any other, and the operations it exposes have no
//! path parameter. There is no `read_file(path)` operation to get wrong.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `set` | `key`, `value` | `key`, `stored` |
//! | `get` | `key` | `key`, `value` (`null` when absent) |
//! | `append` | `value` (any JSON) | `appended` |
//! | `ledger` | — | `entries` |
//! | `flush` | — | `flushed` |
//! | `dir` | — | `dir` |
//!
//! Every operation requires the request to declare `plugin:storage:own`: the sender
//! is asking this plugin to store something, and the bus checks that declaration
//! against the sender's token before delivery.

use std::io;
use std::path::{Path, PathBuf};

use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginError, PluginId, Result};
use nau_store::{FileStore, Store};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: the store refused the operation.
pub const CODE_STORE: &str = "storage_store_refused";

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["set", "get", "append", "ledger", "flush", "dir"];

/// The storage system plugin.
pub struct StoragePlugin {
    id: PluginId,
    grant: PluginGrant,
    store: FileStore,
    dir: PathBuf,
}

impl StoragePlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.storage";

    /// The capabilities the plugin declares: the basic set. `plugin:storage:own` is
    /// the one that matters — it is what a plugin's own directory means — and there
    /// is deliberately no second storage capability for another plugin's files.
    pub const CAPABILITIES: &'static [Capability] = &Capability::BASIC;

    /// Open the plugin's directory, creating it if missing.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`StoragePlugin::ID`] is not a valid plugin name, and
    /// [`PluginError::Io`] when the store directory cannot be created.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let store = FileStore::open(&dir).map_err(|e| store_error("open", e))?;
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            store,
            dir,
        })
    }

    /// The directory this plugin owns.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl SystemPlugin for StoragePlugin {
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
                "storage ready at {}; every write is an fsynced append",
                self.dir.display()
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        self.grant
            .require_operation(declared, Capability::StorageOwn)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "set" => {
                let key = payload::string_field(&msg.payload, "key")?;
                let value = payload::string_field(&msg.payload, "value")?;
                self.store
                    .set_meta(key, value)
                    .map_err(|e| store_error("set_meta", e))?;
                Ok(payload::answer(
                    Self::ID,
                    "set",
                    json!({ "key": key, "stored": true }),
                ))
            }
            "get" => {
                let key = payload::string_field(&msg.payload, "key")?;
                let value = self
                    .store
                    .get_meta(key)
                    .map_err(|e| store_error("get_meta", e))?;
                Ok(payload::answer(
                    Self::ID,
                    "get",
                    json!({ "key": key, "value": value }),
                ))
            }
            "append" => {
                let value = payload::field(&msg.payload, "value")?;
                self.store
                    .append_ledger(value)
                    .map_err(|e| store_error("append_ledger", e))?;
                Ok(payload::answer(
                    Self::ID,
                    "append",
                    json!({ "appended": true }),
                ))
            }
            "ledger" => {
                let entries = self
                    .store
                    .load_ledger()
                    .map_err(|e| store_error("load_ledger", e))?;
                Ok(payload::answer(
                    Self::ID,
                    "ledger",
                    json!({ "entries": entries.len() }),
                ))
            }
            "flush" => {
                self.store.flush().map_err(|e| store_error("flush", e))?;
                Ok(payload::answer(
                    Self::ID,
                    "flush",
                    json!({ "flushed": true }),
                ))
            }
            "dir" => Ok(payload::answer(
                Self::ID,
                "dir",
                json!({ "dir": self.dir.display().to_string() }),
            )),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        // The durability barrier, run before the grant is given up: a plugin that
        // reports a clean stop and then loses its last write is worse than one that
        // reports the failure.
        self.store.flush().map_err(|e| store_error("flush", e))?;
        self.grant.release();
        Ok(())
    }
}

/// Map a store failure onto the kernel's error taxonomy.
///
/// An I/O failure keeps [`PluginError::Io`], so a caller can see that it is retryable
/// (`PluginError::is_retryable`); everything else — a validation refusal, a
/// conflict — is a [`PluginError::Runtime`] whose message begins with
/// [`CODE_STORE`].
fn store_error(what: &str, error: nau_core::NauError) -> PluginError {
    match error {
        nau_core::NauError::Io(err) => PluginError::Io(io::Error::new(err.kind(), err.to_string())),
        other => PluginError::Runtime(format!("{CODE_STORE}: {what}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::HostLimits;
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::{CapabilityToken, Tier};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn scratch(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nau-plugins-storage-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    fn plugin(tag: &str, caps: &[Capability]) -> (StoragePlugin, PathBuf) {
        let dir = scratch(tag);
        let mut plugin = StoragePlugin::open(&dir).expect("opens");
        let token =
            CapabilityToken::issue(StoragePlugin::ID, Tier::System, caps, DIGEST, 1_750_000_000)
                .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        (plugin, dir)
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.official.market").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(StoragePlugin::ID.to_string()),
            Capability::parse(capability).expect("known"),
            PmbKind::Request,
            payload,
            1_750_000_000,
        )
    }

    #[test]
    fn a_value_survives_a_reopen_of_the_plugin_directory() {
        let (mut plugin, dir) = plugin("round-trip", StoragePlugin::CAPABILITIES);
        plugin
            .handle(&request(
                "plugin:storage:own",
                json!({ "op": "set", "key": "schema", "value": "2" }),
            ))
            .expect("stores");
        plugin.shutdown().expect("flushes");

        // A *second* store over the same directory: this is the assertion that the
        // write was durable rather than in memory.
        let reopened = FileStore::open(&dir).expect("reopens");
        assert_eq!(
            reopened.get_meta("schema").expect("reads").as_deref(),
            Some("2")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_key_answers_null_rather_than_refusing() {
        let (mut plugin, dir) = plugin("absent", StoragePlugin::CAPABILITIES);
        let answer = plugin
            .handle(&request(
                "plugin:storage:own",
                json!({ "op": "get", "key": "never-written" }),
            ))
            .expect("answers");
        assert_eq!(answer["value"], json!(null));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appends_are_counted_by_the_ledger_operation() {
        let (mut plugin, dir) = plugin("append", StoragePlugin::CAPABILITIES);
        for i in 0..3 {
            plugin
                .handle(&request(
                    "plugin:storage:own",
                    json!({ "op": "append", "value": { "n": i } }),
                ))
                .expect("appends");
        }
        let answer = plugin
            .handle(&request("plugin:storage:own", json!({ "op": "ledger" })))
            .expect("answers");
        assert_eq!(answer["entries"], json!(3));
        plugin.shutdown().expect("flushes");
        assert!(dir.join("ledger.jsonl").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_plugin_reports_the_directory_it_owns_and_no_other() {
        let (mut plugin, dir) = plugin("dir", StoragePlugin::CAPABILITIES);
        let answer = plugin
            .handle(&request("plugin:storage:own", json!({ "op": "dir" })))
            .expect("answers");
        assert_eq!(answer["dir"], json!(dir.display().to_string()));
        assert_eq!(plugin.dir(), dir.as_path());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_message_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let (mut plugin, dir) = plugin("refused", StoragePlugin::CAPABILITIES);
        let err = plugin
            .handle(&request(
                "chain:evm:write",
                json!({ "op": "get", "key": "k" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains("chain:evm:write"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_operation_that_declares_the_wrong_capability_is_refused() {
        let (mut plugin, dir) = plugin("wrong-op-cap", StoragePlugin::CAPABILITIES);
        // `plugin:lifecycle:read` is held, so the declared-capability gate passes --
        // and the operation gate is what refuses, naming what it needed.
        let err = plugin
            .handle(&request(
                "plugin:lifecycle:read",
                json!({ "op": "set", "key": "k", "value": "v" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("plugin:storage:own"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_key_is_refused_by_the_store_rather_than_written() {
        let (mut plugin, dir) = plugin("empty-key", StoragePlugin::CAPABILITIES);
        let err = plugin
            .handle(&request(
                "plugin:storage:own",
                json!({ "op": "set", "key": "  ", "value": "v" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains(CODE_STORE), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_capability_token_without_storage_own_refuses_every_operation() {
        // The framework can be told to register a plugin whose token is narrower than
        // its declarations only by a host that grants less; here the token is built
        // directly to prove the plugin really checks its own token.
        let dir = scratch("narrow");
        let mut plugin = StoragePlugin::open(&dir).expect("opens");
        let token = CapabilityToken::issue(
            StoragePlugin::ID,
            Tier::System,
            &[Capability::LifecycleRead, Capability::MessageSend],
            DIGEST,
            1,
        )
        .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        let err = plugin
            .handle(&request(
                "plugin:storage:own",
                json!({ "op": "get", "key": "k" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains("plugin:storage:own"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
