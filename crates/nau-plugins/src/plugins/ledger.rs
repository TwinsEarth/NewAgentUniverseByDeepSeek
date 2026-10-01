//! `com.twinsearth.sys.ledger` — balances, escrow and conservation, read-only.
//!
//! # Why this door has no write side
//!
//! Moving money is an economic act, and the kernel reserves it to
//! `economy:settle` — a capability that only the official tier and above can hold, and
//! that this plugin deliberately does not declare. So a write cannot reach this plugin even
//! if a caller wants one: the bus refuses a message whose declared capability the sender's
//! token does not hold, and this plugin's
//! [`PluginGrant::require_declared`](crate::host::PluginGrant::require_declared) refuses it
//! again at the door, naming the capability. There is no `deposit` operation here to get
//! wrong, and no second ledger to drift from the first.
//!
//! What is left is the read side, which is what an auditor, a dashboard or a dispute
//! handler actually needs:
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `balance` | `account` | `account`, `known`, `minor`, `amount`, `system` |
//! | `escrow` | `task` | `task`, `open`, and when open `payer`, `minor`, `amount`, `opened_at` |
//! | `conservation` | — | `report`: the O(1) identity, plus the journal's integrity |
//! | `audit` | — | `report`: the O(N) replay, which can and does fail |
//!
//! Every read delegates to [`nau_ledger::Ledger`]: `balance`, `accounts`, `escrow_record`,
//! `conservation` and `audit`. Nothing is recomputed here — an independently derived
//! "balance" would be a second answer to a question that must have exactly one.
//!
//! # Where the ledger comes from
//!
//! [`LedgerPlugin::new`] reads an empty ledger. That is the honest baseline, not a useful
//! deployment: the ledger an agent cares about belongs to the market, not to this plugin.
//! [`LedgerPlugin::sharing`] is the constructor wiring for that — the host hands over the
//! same `Arc<Mutex<Ledger>>` it mutates elsewhere, and this plugin's reads then observe the
//! live books. The context deliberately carries no ledger, so this is a visible grant
//! rather than an ambient one.
//!
//! # Cost
//!
//! `balance`, `escrow` and `conservation` are O(1) (`balance` also scans the account list to
//! answer `known`); `audit` replays the whole journal, on purpose — it is the path upstream
//! v2.5.6 wrote and never called, and it is the only one that can notice an account whose
//! balance was changed behind the ledger's back. A caller that runs `audit` per request is
//! choosing that cost knowingly.

use std::sync::{Arc, Mutex, MutexGuard};

use nau_core::TaskId;
use nau_ledger::{AccountId, Ledger};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginError, PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: the ledger refused to read what was asked for, or could not be read.
pub const CODE_LEDGER: &str = "ledger_read_refused";

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["balance", "escrow", "conservation", "audit"];

/// The ledger system plugin, read-only.
pub struct LedgerPlugin {
    id: PluginId,
    grant: PluginGrant,
    /// The books this plugin reads. Shared, so the reads observe the same ledger the rest
    /// of the node mutates; a private copy would answer questions about a different world.
    ledger: Arc<Mutex<Ledger>>,
}

impl LedgerPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.ledger";

    /// The capabilities the plugin declares: the basic set, and nothing else.
    ///
    /// In particular **not** `economy:settle`: a settlement capability on a read-only door
    /// would let the bus route a money movement to a plugin that has no write path, and
    /// "the message was delivered" would then look like "the movement happened".
    pub const CAPABILITIES: &'static [Capability] = &Capability::BASIC;

    /// Build the plugin over an empty ledger.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if [`LedgerPlugin::ID`] is not a valid plugin
    /// name, which cannot happen for this constant but is returned rather than asserted.
    pub fn new() -> Result<Self> {
        Self::sharing(Arc::new(Mutex::new(Ledger::new())))
    }

    /// Build the plugin over a ledger the host already owns.
    ///
    /// # Errors
    ///
    /// As [`LedgerPlugin::new`].
    pub fn sharing(ledger: Arc<Mutex<Ledger>>) -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            ledger,
        })
    }

    /// The ledger this plugin reads.
    ///
    /// Exposed so a host can prove which books a plugin is describing, and so a test can
    /// mutate them. It is a shared handle, not a capability: holding it grants nothing that
    /// the host did not already have.
    #[must_use]
    pub fn shared_ledger(&self) -> &Arc<Mutex<Ledger>> {
        &self.ledger
    }

    /// Lock the ledger, recovering from poisoning.
    ///
    /// A panic while holding this lock would otherwise poison it and turn every later read
    /// into a second panic — the failure mode `nau-store`'s `sync` module was written to
    /// remove. The data behind the lock is a `Ledger` whose own mutation methods leave no
    /// half-updated invariant behind, so recovering is safe here in a way worth stating
    /// rather than assuming.
    fn books(&self) -> MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `balance`: what one account holds.
    fn balance(&self, request: &Value) -> Result<Value> {
        let account = parse_account(payload::string_field(request, "account")?)?;
        let ledger = self.books();
        let balance = ledger.balance(&account);
        Ok(payload::answer(
            Self::ID,
            "balance",
            json!({
                "account": account.as_str(),
                "minor": balance.minor(),
                "amount": balance.to_decimal_string(),
                "system": account.is_system(),
                // `Ledger::balance` answers zero for an account it has never seen, which is
                // the right arithmetic and the wrong thing for an operator to guess at from
                // a bare `0`. The account list is how the ledger itself distinguishes them.
                "known": ledger.accounts().contains(&account),
            }),
        ))
    }

    /// `escrow`: what is locked for one task.
    fn escrow(&self, request: &Value) -> Result<Value> {
        let task = parse_task(payload::string_field(request, "task")?)?;
        let ledger = self.books();
        match ledger.escrow_record(&task) {
            Some(record) => Ok(payload::answer(
                Self::ID,
                "escrow",
                json!({
                    "task": record.task.as_str(),
                    "open": true,
                    "payer": record.payer.as_str(),
                    "minor": record.amount.minor(),
                    "amount": record.amount.to_decimal_string(),
                    "opened_at": record.opened_at,
                }),
            )),
            None => Ok(payload::answer(
                Self::ID,
                "escrow",
                json!({ "task": task.as_str(), "open": false }),
            )),
        }
    }

    /// `conservation` / `audit`: the identity check, by one path or the other.
    fn conservation(&self, op: &str) -> Result<Value> {
        let ledger = self.books();
        let report = if op == "audit" {
            ledger.audit()
        } else {
            ledger.conservation()
        };
        let rendered = serde_json::to_value(&report).map_err(|e| {
            PluginError::Runtime(format!(
                "{CODE_LEDGER}: {op}: the conservation report could not be rendered: {e}"
            ))
        })?;
        Ok(payload::answer(Self::ID, op, json!({ "report": rendered })))
    }
}

impl SystemPlugin for LedgerPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        let (accounts, journal) = {
            let ledger = self.books();
            (ledger.account_count(), ledger.journal_len())
        };
        ctx.log(
            LogLevel::Info,
            &format!(
                "ledger ready read-only: {accounts} account(s), {journal} journal record(s); the \
                 write path needs `economy:settle`, which this plugin does not hold"
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        self.grant
            .require_operation(declared, Capability::MessageSend)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "balance" => self.balance(&msg.payload),
            "escrow" => self.escrow(&msg.payload),
            "conservation" | "audit" => self.conservation(op),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        // The books outlive this plugin: the handle is dropped, the ledger is not flushed
        // here because this plugin never wrote to it and does not own its durability.
        self.grant.release();
        Ok(())
    }
}

/// Parse an account identifier through the ledger's own validator.
///
/// # Errors
///
/// [`CODE_LEDGER`] when the identifier is empty, too long or outside the account alphabet.
fn parse_account(name: &str) -> Result<AccountId> {
    AccountId::parse(name).map_err(|e| {
        payload::protocol(
            CODE_LEDGER,
            format!("`{name}` is not a ledger account identifier: {e}"),
        )
    })
}

/// Parse a task identifier through the kernel's own validator.
///
/// # Errors
///
/// [`CODE_LEDGER`] when the identifier is not a task id.
fn parse_task(name: &str) -> Result<TaskId> {
    TaskId::parse(name).map_err(|e| {
        payload::protocol(
            CODE_LEDGER,
            format!("`{name}` is not a task identifier: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use ed25519_dalek::SigningKey;
    use nau_core::Money;
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::lifecycle::PluginState;
    use nau_plugin::{CapabilityToken, Tier, VerifiedManifest};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_750_000_000;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn verified_manifest(plugin: &impl SystemPlugin) -> VerifiedManifest {
        crate::sign::verified_system(
            plugin.id().as_str(),
            plugin.capabilities(),
            &signing_key(7),
            &signing_key(9),
        )
        .expect("the system manifest verifies")
    }

    fn started(caps: &[Capability]) -> (LedgerPlugin, Arc<Mutex<Ledger>>) {
        let ledger = Arc::new(Mutex::new(Ledger::new()));
        let mut plugin = LedgerPlugin::sharing(Arc::clone(&ledger)).expect("valid id");
        let token = CapabilityToken::issue(LedgerPlugin::ID, Tier::System, caps, DIGEST, NOW)
            .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        (plugin, ledger)
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.official.market").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(LedgerPlugin::ID.to_string()),
            Capability::parse(capability).expect("known"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    #[test]
    fn the_plugin_registers_initialises_and_reaches_running() {
        let plugin = LedgerPlugin::new().expect("valid id");
        assert_eq!(plugin.id().as_str(), LedgerPlugin::ID);
        let verified = verified_manifest(&plugin);
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(Box::new(plugin), &verified, NOW)
            .expect("registers against its own system manifest");
        assert_eq!(host.state(LedgerPlugin::ID), Some(PluginState::Loaded));
        host.init(LedgerPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(LedgerPlugin::ID), Some(PluginState::Running));
    }

    #[test]
    fn a_balance_query_reads_the_ledger_the_host_shared() {
        let (mut plugin, ledger) = started(LedgerPlugin::CAPABILITIES);
        let account = AccountId::parse("agent:alice").expect("account");
        ledger
            .lock()
            .expect("the test holds the ledger")
            .deposit(&account, Money::from_minor(2_500_000), "test funding", NOW)
            .expect("deposits");

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "balance", "account": "agent:alice" }),
            ))
            .expect("answers");
        assert_eq!(answer["known"], json!(true));
        assert_eq!(answer["minor"], json!(2_500_000));
        assert_eq!(answer["amount"], json!("2.5"));
        assert_eq!(answer["system"], json!(false));

        // An account the ledger has never seen answers zero *and* says it is unknown.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "balance", "account": "agent:nobody" }),
            ))
            .expect("answers");
        assert_eq!(answer["known"], json!(false));
        assert_eq!(answer["minor"], json!(0));

        // The escrow account of a task is a reserved internal account.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "balance", "account": "__escrow__:task-1" }),
            ))
            .expect("answers");
        assert_eq!(answer["system"], json!(true));

        // An identifier the ledger refuses is refused here too, with the code attached.
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "balance", "account": "" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains(CODE_LEDGER), "{err}");
    }

    #[test]
    fn an_escrow_query_reports_the_lock_and_the_conservation_paths_agree() {
        let (mut plugin, ledger) = started(LedgerPlugin::CAPABILITIES);
        let payer = AccountId::parse("agent:alice").expect("account");
        let task = TaskId::parse("task-42").expect("task");
        {
            let mut books = ledger.lock().expect("the test holds the ledger");
            books
                .deposit(&payer, Money::from_minor(1_000_000), "test funding", NOW)
                .expect("deposits");
            books
                .escrow(&task, &payer, Money::from_minor(400_000), NOW)
                .expect("escrows");
        }

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "escrow", "task": "task-42" }),
            ))
            .expect("answers");
        assert_eq!(answer["open"], json!(true));
        assert_eq!(answer["payer"], json!("agent:alice"));
        assert_eq!(answer["minor"], json!(400_000));

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "escrow", "task": "task-never-escrowed" }),
            ))
            .expect("answers");
        assert_eq!(answer["open"], json!(false));
        assert_eq!(answer["payer"], json!(null));

        // Both conservation paths, over the same books.
        for op in ["conservation", "audit"] {
            let answer = plugin
                .handle(&request("plugin:message:send", json!({ "op": op })))
                .expect("answers");
            assert_eq!(answer["report"]["conserved"], json!(true), "{op}");
            assert_eq!(answer["report"]["journal_intact"], json!(true), "{op}");
            assert_eq!(answer["report"]["total_escrowed"], json!(400_000), "{op}");
            assert_eq!(answer["report"]["journal_break_seq"], json!(null), "{op}");
        }
    }

    #[test]
    fn a_settlement_request_is_refused_by_the_token_because_this_plugin_holds_no_economy() {
        let (mut plugin, _ledger) = started(LedgerPlugin::CAPABILITIES);
        // The write capability exists at the kernel; this plugin does not declare it, and
        // the token it was issued does not hold it.
        assert!(!LedgerPlugin::CAPABILITIES.contains(&Capability::EconomySettle));
        let err = plugin
            .handle(&request(
                "economy:settle",
                json!({ "op": "balance", "account": "agent:alice" }),
            ))
            .expect_err("must be refused");
        assert!(err.to_string().contains("economy:settle"), "{err}");

        // Held, but not the capability this door needs.
        let err = plugin
            .handle(&request(
                "plugin:storage:own",
                json!({ "op": "balance", "account": "agent:alice" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("plugin:message:send"), "{text}");
        assert!(text.contains("plugin:storage:own"), "{text}");
    }
}
