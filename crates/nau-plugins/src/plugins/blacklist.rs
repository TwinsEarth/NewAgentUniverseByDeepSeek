//! `com.twinsearth.sys.blacklist` — the quarantine list, as a door.
//!
//! # What is behind the door
//!
//! [`nau_plugin::blacklist`] is the kernel's quarantine. An entry pins a plugin name
//! to the *exact* module digest that was condemned, is accepted only when a trusted
//! vendor key signs it, and has **no removal method** — the appeal path advances
//! stages instead, so lifting an appeal never erases the evidence that justified the
//! entry. This plugin is the door onto that logic for anything that needs the
//! question answered without linking the kernel's internals.
//!
//! Every answer is [`Blacklist`], [`BlacklistEntry`] or [`AppealOutcome`] read back
//! verbatim. Nothing here decides anything of its own, so a caller cannot get a
//! verdict from this door that the load pipeline would not reach.
//!
//! # Why the entries have to be wired in, and why `add` is refused
//!
//! [`HostContext`] carries a token, an outbox and a log sink — no blacklist and no
//! [`TrustStore`](nau_plugin::TrustStore) — and the arbiter's [`Blacklist`] has no
//! `Clone`, so the entries the load pipeline consults cannot be reached from in here.
//! [`BlacklistPlugin::with_list`] is therefore the only way a populated door exists:
//! the host builds the list with the kernel's own [`Blacklist::add`], which verifies
//! every entry against a trust store, and hands over the result.
//!
//! A door built with [`BlacklistPlugin::new`] holds nothing and says so. Every
//! `check` answer carries `list_entries` and `wired`, so `"condemned": false` from an
//! unwired door cannot be mistaken for "this artefact is safe" — the failure mode of
//! a read-only door onto another component's state is a confident false negative, and
//! the answer is shaped to make it visible rather than to avoid it.
//!
//! The write operation is the same story one step further on. The plugin declares
//! `kernel:policy:write` because a blacklist entry *is* a policy write, so the bus
//! will route one to it — and `add` checks that capability and then **refuses**,
//! because accepting an entry without checking its vendor signature is exactly the
//! denial of service the kernel module documents ("the first peer to reach a node
//! could ban its competitors"). A refusal that says so is worth more than an append
//! that trusts the caller.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `list` | — | `entries`, `count`, `wired`, `appeal_stages` |
//! | `check` | `name`, `module_sha256` (optional) | `condemned`, the entry, the kernel's own `require_allowed` refusal, and the appeal and unblock path |
//! | `appeal` | `from`, `to` | `outcome`: `advanced` or `refused`, with the kernel's reason |
//! | `add` | — | refused: `blacklist_write_needs_signed_entry` |
//!
//! `list`, `check` and `appeal` require the request to declare
//! `plugin:message:send`; `add` requires `kernel:policy:write`, so the bus checks the
//! *caller's* token for kernel authority before the message is delivered.
//!
//! # What an illegal appeal is
//!
//! `appeal` answers `outcome: "refused"` as an ordinary value rather than a typed
//! `Err`, because that is what [`AppealOutcome::advance`] does: "your appeal was
//! denied" is an answer to a request, not a fault. An `Err` is reserved for a request
//! this door cannot read — an unknown stage name, a payload that is not an object —
//! which is a different fact and deserves a different shape.

use nau_plugin::blacklist::{AppealOutcome, AppealStage, Blacklist, BlacklistEntry};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, LoadRefusal, PluginError, PluginId, Result};
use serde_json::{json, Map, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: a blacklist write is refused because this door cannot verify one.
pub const CODE_WRITE_UNVERIFIABLE: &str = "blacklist_write_needs_signed_entry";
/// Error code: the appeal stage name is not one of the five.
pub const CODE_UNKNOWN_APPEAL_STAGE: &str = "blacklist_unknown_appeal_stage";

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["list", "check", "appeal", "add"];

/// The blacklist system plugin.
pub struct BlacklistPlugin {
    id: PluginId,
    grant: PluginGrant,
    list: Blacklist,
    /// Whether a host handed this door its list. See [`BlacklistPlugin::is_wired`].
    wired: bool,
}

impl BlacklistPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.blacklist";

    /// The capabilities the plugin declares: the basic set plus
    /// `kernel:policy:write`.
    ///
    /// It declares the kernel capability because it is the door a blacklist write
    /// would come through — a caller must hold `kernel:policy:write` for the bus to
    /// deliver one, and only the system tier can hold it. See the module documentation
    /// for why the write itself is refused today.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::KernelPolicyWrite,
    ];

    /// Build the plugin with no list wired in: it answers, and every answer reports
    /// that it holds nothing.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`BlacklistPlugin::ID`] is not a valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            list: Blacklist::new(),
            wired: false,
        })
    }

    /// Build the plugin over a list the host built and verified.
    ///
    /// This is constructor wiring, in the same sense as the orchestrator's load-order
    /// port: a visible grant the host chose to compile in, rather than an ambient one
    /// the context would have to carry. Entries reach the list through
    /// [`Blacklist::add`], which refuses an entry whose signer is not a trusted vendor
    /// key, so a populated door cannot be populated with an unsigned entry.
    ///
    /// The list is marked `wired`, which every `check` answer reports, because a host
    /// that deliberately wired an empty list and a host that forgot to wire one are
    /// different operational facts.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] if [`BlacklistPlugin::ID`] is not a valid plugin name.
    pub fn with_list(list: Blacklist) -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            list,
            wired: true,
        })
    }

    /// How many names this door can see.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.list.len()
    }

    /// Whether a host handed this door a list, empty or not.
    ///
    /// A `false` here means the door was built with [`BlacklistPlugin::new`] and its
    /// `condemned: false` answers say only "nothing is in the list this door holds",
    /// which is not a statement about any artefact.
    #[must_use]
    pub fn is_wired(&self) -> bool {
        self.wired
    }
}

impl SystemPlugin for BlacklistPlugin {
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
                "blacklist ready: {} entr(ies), {} appeal stages, wired={}",
                self.list.len(),
                AppealStage::ALL.len(),
                self.wired
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "list" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let entries: Vec<Value> = self
                    .list
                    .names()
                    .into_iter()
                    .filter_map(|name| self.list.entry(name))
                    .map(entry_json)
                    .collect();
                Ok(payload::answer(
                    Self::ID,
                    "list",
                    json!({
                        "entries": entries,
                        "count": self.list.len(),
                        "wired": self.wired,
                        "appeal_stages": appeal_stages_json(),
                    }),
                ))
            }
            "check" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let name = payload::string_field(&msg.payload, "name")?;
                let digest = payload::optional_string(&msg.payload, "module_sha256")?;
                let found = self.list.check(name, digest.as_deref());
                // The load-time refusal, verbatim: a caller that wants to log "why was
                // this refused" gets the kernel's sentence, not a paraphrase.
                let refusal = self
                    .list
                    .require_allowed(name, digest.as_deref())
                    .err()
                    .map(|e| e.to_string());
                let mut body = Map::new();
                body.insert("name".to_string(), json!(name));
                body.insert("module_sha256".to_string(), json!(digest));
                body.insert("condemned".to_string(), json!(found.is_some()));
                body.insert("list_entries".to_string(), json!(self.list.len()));
                body.insert("wired".to_string(), json!(self.wired));
                body.insert("refusal".to_string(), json!(refusal));
                if let Some(entry) = found {
                    body.insert("entry".to_string(), entry_json(entry));
                    body.insert("appeal".to_string(), appeal_json());
                    body.insert("unblock".to_string(), unblock_json(entry));
                }
                Ok(payload::answer(Self::ID, "check", Value::Object(body)))
            }
            "appeal" => {
                self.grant
                    .require_operation(declared, Capability::MessageSend)?;
                let from = parse_stage(payload::string_field(&msg.payload, "from")?)?;
                let to = parse_stage(payload::string_field(&msg.payload, "to")?)?;
                let answer = match AppealOutcome::advance(from, to) {
                    AppealOutcome::Advanced(stage) => json!({
                        "outcome": "advanced",
                        "from": from.label(),
                        "stage": stage.label(),
                        "is_final": stage.is_final(),
                        "next_stages": stage
                            .next_stages()
                            .iter()
                            .map(|s| s.label())
                            .collect::<Vec<&str>>(),
                        // An appeal moves a review, never an entry: there is no stage
                        // at which the evidence disappears.
                        "entry_removed": false,
                    }),
                    AppealOutcome::Refused(why) => json!({
                        "outcome": "refused",
                        "from": from.label(),
                        "to": to.label(),
                        "reason": why,
                        "entry_removed": false,
                    }),
                };
                Ok(payload::answer(Self::ID, "appeal", answer))
            }
            "add" => {
                self.grant
                    .require_operation(declared, Capability::KernelPolicyWrite)?;
                // Held, checked, and still refused -- see the module documentation.
                Err(PluginError::Capability(format!(
                    "{CODE_WRITE_UNVERIFIABLE}: this door holds no trust store, so it cannot \
                     check the vendor signature an entry needs: `HostContext` carries a token, \
                     an outbox and a log sink and nothing else, and the constructor wiring has \
                     no trust store either. `Blacklist::add` refuses an entry whose signer is \
                     not a trusted vendor key, and accepting one here without that check would \
                     hand the first caller the denial of service the kernel documents. Build \
                     the list with `Blacklist::add` and hand it over with `with_list`."
                )))
            }
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

/// One entry, as JSON.
fn entry_json(entry: &BlacklistEntry) -> Value {
    json!({
        "plugin_name": entry.plugin_name.as_str(),
        "module_sha256": entry.module_sha256.as_deref(),
        "reason": entry.reason.label(),
        "blacklisted_at": entry.blacklisted_at,
        "evidence_cid": entry.evidence_cid.as_str(),
        "signer_key": entry.signer_key.as_str(),
        "condemns_every_build": entry.condemns_every_build(),
        "requires_review_on_republish": entry.reason.requires_review_on_republish(),
    })
}

/// Every appeal stage with its legal successors, from [`AppealStage`] itself.
fn appeal_stages_json() -> Value {
    let stages: Vec<Value> = AppealStage::ALL
        .iter()
        .map(|stage| {
            json!({
                "stage": stage.label(),
                "is_final": stage.is_final(),
                "next_stages": stage
                    .next_stages()
                    .iter()
                    .map(|s| s.label())
                    .collect::<Vec<&str>>(),
            })
        })
        .collect();
    json!(stages)
}

/// The appeal graph, and the fact that an entry does not record where in it the
/// appeal stands.
fn appeal_json() -> Value {
    json!({
        "stages": appeal_stages_json(),
        "entry_records_a_stage": false,
        "note": "nau_plugin::blacklist::BlacklistEntry carries the verdict, its evidence and \
                 its signer; it has no appeal-stage field, so the stage of a particular \
                 appeal is not a fact the kernel stores",
    })
}

/// The path back from a condemned digest, derived from the entry's own reason.
fn unblock_json(entry: &BlacklistEntry) -> Value {
    let mut steps: Vec<&str> = Vec::new();
    if entry.condemns_every_build() {
        steps.push(
            "this entry pins no digest, so it condemns every build of the name: a new digest \
             alone does not clear it",
        );
    } else {
        steps.push(
            "this entry pins one module digest, and a new build hashes to a different one, \
             which this entry does not match",
        );
    }
    if entry.reason.requires_review_on_republish() {
        steps.push(
            "the code itself was condemned, so the replacement build must pass review rather \
             than be auto-accepted",
        );
    } else {
        steps.push(
            "the reason is the publisher key, not the code, so the path is a build published \
             under a trusted key",
        );
    }
    steps.push(
        "the entry is never removed; an appeal ends at `lifted`, and the evidence it carries \
         stays on the list",
    );
    json!({
        "requires_review_on_republish": entry.reason.requires_review_on_republish(),
        "condemns_every_build": entry.condemns_every_build(),
        "steps": steps,
        "appeal_stages": AppealStage::ALL.iter().map(|s| s.label()).collect::<Vec<&str>>(),
        "load_refusal_code": LoadRefusal::Blacklisted.code(),
    })
}

/// Parse an appeal stage name, refusing an unknown one rather than defaulting.
fn parse_stage(name: &str) -> Result<AppealStage> {
    let wanted = name.trim().to_ascii_lowercase();
    AppealStage::ALL
        .into_iter()
        .find(|stage| stage.label() == wanted)
        .ok_or_else(|| {
            PluginError::Blacklist(format!(
                "{CODE_UNKNOWN_APPEAL_STAGE}: `{name}` is not an appeal stage; the stages are {}",
                AppealStage::ALL
                    .iter()
                    .map(|s| s.label())
                    .collect::<Vec<&str>>()
                    .join(", ")
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use crate::sign::{fixture_key, trust_store, verified_system, FIXTURE_ISSUED_AT};
    use ed25519_dalek::{Signer, SigningKey};
    use nau_plugin::blacklist::BlacklistReason;
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::lifecycle::PluginState;
    use nau_plugin::{CapabilityToken, Tier};

    const NOW: u64 = FIXTURE_ISSUED_AT;
    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    /// The caller every fixture message comes from: a plugin that holds the basic set.
    const CALLER: &str = "com.twinsearth.official.market";

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse(CALLER).expect("a valid plugin name");
        PmbMessage::new(
            &id,
            Target::Plugin(BlacklistPlugin::ID.to_string()),
            Capability::parse(capability).expect("a known capability"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    /// Initialise a plugin exactly as the host would, without the host.
    fn initialised(mut plugin: BlacklistPlugin) -> BlacklistPlugin {
        let token = CapabilityToken::issue(
            BlacklistPlugin::ID,
            Tier::System,
            BlacklistPlugin::CAPABILITIES,
            DIGEST_A,
            NOW,
        )
        .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    /// One entry signed by `key`, in the shape `Blacklist::add` accepts.
    fn signed_entry(
        key: &SigningKey,
        name: &str,
        digest: Option<&str>,
        reason: BlacklistReason,
    ) -> BlacklistEntry {
        let mut entry = BlacklistEntry {
            plugin_name: name.to_string(),
            module_sha256: digest.map(str::to_string),
            reason,
            blacklisted_at: NOW,
            evidence_cid: "bafyevidence".into(),
            signer_key: hex::encode(key.verifying_key().to_bytes()),
            signature: String::new(),
        };
        let signature = key.sign(&entry.signing_bytes());
        entry.signature = hex::encode(signature.to_bytes());
        entry
    }

    /// A list holding one pinned entry, built through the kernel's own `add`.
    fn condemned_list() -> Blacklist {
        let vendor = fixture_key(9);
        let trust = trust_store(&[&vendor], &[]).expect("the vendor key is trusted");
        let mut list = Blacklist::new();
        list.add(
            signed_entry(
                &vendor,
                "io.example.bad",
                Some(DIGEST_A),
                BlacklistReason::Malware,
            ),
            &trust,
        )
        .expect("a signed entry from a trusted vendor key is accepted");
        list
    }

    #[test]
    fn the_plugin_registers_reaches_running_and_only_then_answers() {
        let verified = verified_system(
            BlacklistPlugin::ID,
            BlacklistPlugin::CAPABILITIES,
            &fixture_key(3),
            &fixture_key(9),
        )
        .expect("a system manifest for this plugin verifies");
        let mut host =
            SystemPluginHost::new(HostLimits::default()).expect("the default limits are usable");
        host.register(
            Box::new(BlacklistPlugin::new().expect("the constant id parses")),
            &verified,
            NOW,
        )
        .expect("registers against its own manifest");
        assert_eq!(host.state(BlacklistPlugin::ID), Some(PluginState::Loaded));

        // Registered is not running: the host refuses before the plugin is asked.
        let err = host
            .handle(&request("plugin:message:send", json!({ "op": "list" })))
            .expect_err("a loaded plugin does not serve");
        assert!(err.to_string().contains("not running"), "{err}");

        host.init(BlacklistPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(BlacklistPlugin::ID), Some(PluginState::Running));
        assert!(host
            .handle(&request("plugin:message:send", json!({ "op": "list" })))
            .is_ok());
    }

    #[test]
    fn a_condemned_digest_is_the_kernels_verdict_and_the_answer_names_the_path_back() {
        let mut plugin = initialised(BlacklistPlugin::with_list(condemned_list()).expect("id"));

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "check", "name": "io.example.bad", "module_sha256": DIGEST_A }),
            ))
            .expect("answers");
        assert_eq!(answer["condemned"], json!(true));
        assert_eq!(answer["entry"]["reason"], json!("malware"));
        assert_eq!(answer["entry"]["module_sha256"], json!(DIGEST_A));
        assert_eq!(answer["entry"]["condemns_every_build"], json!(false));
        assert_eq!(answer["list_entries"], json!(1));
        assert_eq!(answer["wired"], json!(true));
        // The refusal is the kernel's own `require_allowed` sentence, code included.
        let refusal = answer["refusal"].as_str().expect("a refusal string");
        assert!(
            refusal.contains(LoadRefusal::Blacklisted.code()),
            "{refusal}"
        );
        assert!(refusal.contains("malware"), "{refusal}");
        assert_eq!(
            answer["unblock"]["requires_review_on_republish"],
            json!(true)
        );
        assert_eq!(answer["unblock"]["load_refusal_code"], json!("blacklisted"));
        assert_eq!(answer["appeal"]["entry_records_a_stage"], json!(false));

        // A pinned entry does not condemn a different build -- the property that makes
        // "publish a fixed version" a real path rather than a slogan.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "check", "name": "io.example.bad", "module_sha256": DIGEST_B }),
            ))
            .expect("answers");
        assert_eq!(answer["condemned"], json!(false));
        assert_eq!(answer["module_sha256"], json!(DIGEST_B));
        assert_eq!(answer["refusal"], Value::Null);

        // An unknown digest cannot be shown to match a pinned entry, so it does not.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "check", "name": "io.example.bad" }),
            ))
            .expect("answers");
        assert_eq!(answer["condemned"], json!(false));

        // A name the list has never seen.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "check", "name": "io.example.good", "module_sha256": DIGEST_A }),
            ))
            .expect("answers");
        assert_eq!(answer["condemned"], json!(false));
    }

    #[test]
    fn a_message_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let mut plugin = initialised(BlacklistPlugin::new().expect("id"));
        let err = plugin
            .handle(&request("swarm:consensus", json!({ "op": "list" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("swarm:consensus"), "{err}");
    }

    #[test]
    fn an_unwired_door_says_so_rather_than_implying_the_artefact_is_safe() {
        let mut plugin = initialised(BlacklistPlugin::new().expect("id"));
        assert!(!plugin.is_wired());
        assert_eq!(plugin.entry_count(), 0);

        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "check", "name": "io.example.bad", "module_sha256": DIGEST_A }),
            ))
            .expect("answers");
        assert_eq!(answer["condemned"], json!(false));
        assert_eq!(answer["wired"], json!(false));
        assert_eq!(answer["list_entries"], json!(0));

        // A host that wired an empty list is a different fact from one that forgot.
        let wired = initialised(BlacklistPlugin::with_list(Blacklist::new()).expect("id"));
        assert!(wired.is_wired());
    }

    #[test]
    fn a_blacklist_write_that_declares_kernel_authority_is_refused_as_unverifiable() {
        let mut plugin = initialised(BlacklistPlugin::new().expect("id"));
        let err = plugin
            .handle(&request(
                "kernel:policy:write",
                json!({ "op": "add", "entry": { "plugin_name": "io.example.rival" } }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(CODE_WRITE_UNVERIFIABLE), "{text}");
        assert!(text.contains("trust store"), "{text}");
        assert!(text.contains("with_list"), "{text}");
    }

    #[test]
    fn a_blacklist_write_that_does_not_declare_kernel_authority_is_refused_by_name() {
        let mut plugin = initialised(BlacklistPlugin::new().expect("id"));
        let err = plugin
            .handle(&request("plugin:message:send", json!({ "op": "add" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("kernel:policy:write"), "{text}");
        assert!(text.contains("plugin:message:send"), "{text}");
    }

    #[test]
    fn the_appeal_graph_is_the_kernels_and_an_illegal_appeal_is_an_answer_not_a_fault() {
        let mut plugin = initialised(BlacklistPlugin::new().expect("id"));
        for from in AppealStage::ALL {
            for to in AppealStage::ALL {
                let answer = plugin
                    .handle(&request(
                        "plugin:message:send",
                        json!({ "op": "appeal", "from": from.label(), "to": to.label() }),
                    ))
                    .expect("an appeal is always answered");
                match AppealOutcome::advance(from, to) {
                    AppealOutcome::Advanced(stage) => {
                        assert_eq!(answer["outcome"], json!("advanced"), "{from:?} -> {to:?}");
                        assert_eq!(answer["stage"], json!(stage.label()));
                        assert_eq!(answer["entry_removed"], json!(false));
                    }
                    AppealOutcome::Refused(why) => {
                        assert_eq!(answer["outcome"], json!("refused"), "{from:?} -> {to:?}");
                        assert_eq!(answer["reason"], json!(why));
                        assert_eq!(answer["entry_removed"], json!(false));
                    }
                }
            }
        }

        // The illegal move an operator tries first: skipping review entirely.
        let answer = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "appeal", "from": "appealed", "to": "lifted" }),
            ))
            .expect("answers");
        assert_eq!(answer["outcome"], json!("refused"));
        assert!(answer["reason"]
            .as_str()
            .expect("a reason")
            .contains("not an appeal edge"));
    }

    #[test]
    fn an_unknown_appeal_stage_is_refused_rather_than_defaulted() {
        let mut plugin = initialised(BlacklistPlugin::new().expect("id"));
        let err = plugin
            .handle(&request(
                "plugin:message:send",
                json!({ "op": "appeal", "from": "limbo", "to": "lifted" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(CODE_UNKNOWN_APPEAL_STAGE), "{text}");
        assert!(text.contains("grey_list"), "{text}");
    }

    #[test]
    fn an_unknown_operation_lists_the_vocabulary_this_door_implements() {
        let mut plugin = initialised(BlacklistPlugin::new().expect("id"));
        let err = plugin
            .handle(&request("plugin:message:send", json!({ "op": "purge" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("list, check, appeal, add"), "{text}");
    }

    #[test]
    fn the_list_operation_reports_the_kernels_entries_and_the_whole_appeal_graph() {
        let mut plugin = initialised(BlacklistPlugin::with_list(condemned_list()).expect("id"));
        let answer = plugin
            .handle(&request("plugin:message:send", json!({ "op": "list" })))
            .expect("answers");
        assert_eq!(answer["count"], json!(1));
        assert_eq!(answer["wired"], json!(true));
        assert_eq!(answer["entries"][0]["plugin_name"], json!("io.example.bad"));
        assert_eq!(answer["entries"][0]["reason"], json!("malware"));
        assert_eq!(answer["entries"][0]["condemns_every_build"], json!(false));

        let stages = answer["appeal_stages"].as_array().expect("an array");
        assert_eq!(stages.len(), AppealStage::ALL.len());
        for (rendered, stage) in stages.iter().zip(AppealStage::ALL) {
            assert_eq!(rendered["stage"], json!(stage.label()));
            assert_eq!(rendered["is_final"], json!(stage.is_final()));
            assert_eq!(
                rendered["next_stages"].as_array().expect("an array").len(),
                stage.next_stages().len()
            );
        }
    }
}
