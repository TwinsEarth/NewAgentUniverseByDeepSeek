//! `com.twinsearth.sys.arbiter` — the load pipeline's contract, as a door.
//!
//! # What is behind the door
//!
//! [`nau_plugin::arbiter`] turns a manifest into a running plugin, or into a typed
//! refusal with a full stage trace. Every step is *reportable* on purpose: when a
//! plugin does not load, the operator's question is never "did it fail" but "which
//! check refused it, and what would have to change", and the answer has to be the
//! same one the REST surface, the CLI and the tests give.
//!
//! This plugin is the door onto that contract:
//!
//! | `op` | Answer |
//! |---|---|
//! | `stages` | the pipeline in order, what each stage decides, and the refusal codes it can produce |
//! | `refusals` | the kernel's whole refusal vocabulary, with the stages that attribute each code and the codes no stage attributes |
//! | `tiers` | per tier: the ceiling `tier_ceiling` sets, the runtime `runtime_for_tier` requires, and whether that tier runs in process |
//!
//! All three require the request to declare `kernel:plugin:manage` — the same
//! capability the orchestrator's `check` requires. Loading is kernel authority, so a
//! non-system caller cannot even hold the capability the bus would check before
//! delivering a question about it.
//!
//! # Why it reports the pipeline instead of running it
//!
//! Running a load needs a [`Registry`](nau_plugin::registry::Registry) and a
//! [`Bus`](nau_plugin::bus::Bus), and [`HostContext`] carries neither: it carries a
//! token, an outbox and a log sink, and this plugin's constructor takes no port. That
//! is the framework's rule rather than an omission — a T0 plugin reaches the host
//! through the one door, and a plugin that could load plugins would be an ambient
//! plugin manager. So this door answers the *contract* the pipeline enforces, and a
//! caller that wants a load executed asks the host that owns the arbiter.
//!
//! # Why the table is trustworthy
//!
//! The kernel does not export a stage list — `LoadStep.step` is a `&'static str` set
//! inside `Arbiter::load`, and the refusal vocabulary is the `LoadRefusal` enum. A
//! hand-written copy of either could drift, so two tests in this file read the
//! kernel's source and fail if it does: every stage name must still appear as a
//! `LoadStep` literal in `nau-plugin/src/arbiter.rs`, and the vocabulary reported here
//! must equal, in both directions, the `LoadRefusal::X => "code"` pairs in
//! `nau-plugin/src/error.rs`. A stage renamed or a variant added in the kernel breaks
//! this door's tests rather than silently making it wrong.
//!
//! The `refusals` answer also reports the codes **no stage attributes** rather than
//! hiding them, because a vocabulary entry no stage can emit is a real fact about the
//! pipeline: `name_invalid` is never produced, because `refusal_of` collapses
//! `PluginError::Name` into `manifest_invalid`, and `capability_not_approved` is never
//! produced either, because `verify` maps every token-issue failure to
//! `capability_not_permitted`.

use nau_plugin::arbiter::{runtime_for_tier, tier_ceiling};
use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, LoadRefusal, PluginId, Result, Tier};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["stages", "refusals", "tiers"];

/// One stage of the kernel's load pipeline, as this door reports it.
struct Stage {
    /// The stage name the kernel's `LoadStep` carries.
    name: &'static str,
    /// The question the stage answers, in one clause.
    decides: &'static str,
    /// The refusal codes the stage can produce.
    refusals: &'static [LoadRefusal],
}

/// The pipeline, in the order `Arbiter::load` runs it.
///
/// Read off the kernel's own steps, one entry per `LoadStep` the trace can carry:
/// `parse`, `blacklist`, `verify`, `compat`, `limits`, `runtime`, `registry`, `bus`
/// and `lifecycle`. The two stages that can only ever pass are here too — `limits`
/// clamps and records rather than refusing, and a caller that cannot see it would not
/// know the clamping happened.
const STAGES: &[Stage] = &[
    Stage {
        name: "parse",
        decides: "is the document a well-formed, self-consistent manifest",
        refusals: &[LoadRefusal::ManifestInvalid, LoadRefusal::AbiIncompatible],
    },
    Stage {
        name: "blacklist",
        decides: "is this exact artefact quarantined, before any step with a side effect",
        refusals: &[LoadRefusal::Blacklisted],
    },
    Stage {
        name: "verify",
        decides: "name and tier, digest, publisher signature, counter-signature, module hash, capability ceiling",
        refusals: &[
            LoadRefusal::ManifestInvalid,
            LoadRefusal::SignatureInvalid,
            LoadRefusal::UntrustedPublisher,
            LoadRefusal::CounterSignatureMissing,
            LoadRefusal::ModuleDigestMismatch,
            LoadRefusal::CapabilityNotPermitted,
        ],
    },
    Stage {
        // Between authenticity and compatibility, and the position is the statement: a
        // manifest is first proven to be what its publisher signed, then asked what a review
        // approved, and only then considered for serving.
        name: "certification",
        decides: "does a review cover the capabilities this manifest asks for, and is a \
                  certification present at the tier that requires one",
        refusals: &[
            LoadRefusal::CertificationMissing,
            LoadRefusal::CapabilityNotPermitted,
        ],
    },
    Stage {
        name: "compat",
        decides: "can this host serve that ABI, directly or through a named adapter",
        refusals: &[LoadRefusal::AbiIncompatible, LoadRefusal::ManifestInvalid],
    },
    Stage {
        name: "limits",
        decides: "are the requested limits inside the tier ceiling (clamped and recorded, never refused)",
        refusals: &[],
    },
    Stage {
        name: "runtime",
        decides: "is a runtime registered for this tier, and can it enforce the boundaries the manifest did not waive",
        refusals: &[LoadRefusal::IsolationNotEnforceable],
    },
    Stage {
        name: "registry",
        decides: "does the entry insert, with its declared dependencies satisfied",
        refusals: &[LoadRefusal::DependencyUnsatisfied],
    },
    Stage {
        name: "bus",
        decides: "can the plugin's token be registered for delivery",
        refusals: &[LoadRefusal::ManifestInvalid],
    },
    Stage {
        name: "lifecycle",
        decides: "do the transitions to `running` all succeed through the one assignment site",
        refusals: &[LoadRefusal::ManifestInvalid],
    },
];

/// Every refusal code in the kernel's [`LoadRefusal`] vocabulary.
///
/// A drift-checked copy, not a second definition: a test parses
/// `nau-plugin/src/error.rs` and fails if this list and the kernel's `code()` impl
/// stop matching, in either direction.
const VOCABULARY: &[LoadRefusal] = &[
    LoadRefusal::NameInvalid,
    LoadRefusal::ManifestInvalid,
    LoadRefusal::SignatureInvalid,
    LoadRefusal::UntrustedPublisher,
    LoadRefusal::CounterSignatureMissing,
    // Added when the certification scope became a load-time check. A certified plugin that
    // no review covers is refused by this code rather than by `counter_signature_missing`,
    // because the counter-signature is present in that case, and the two send an operator
    // to different documents.
    LoadRefusal::CertificationMissing,
    LoadRefusal::ModuleDigestMismatch,
    LoadRefusal::Blacklisted,
    LoadRefusal::CapabilityNotPermitted,
    LoadRefusal::CapabilityNotApproved,
    LoadRefusal::IsolationNotEnforceable,
    LoadRefusal::DependencyUnsatisfied,
    LoadRefusal::AbiIncompatible,
];

/// The arbiter system plugin.
pub struct ArbiterPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl ArbiterPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.arbiter";

    /// The capabilities the plugin declares: the basic set plus
    /// `kernel:plugin:manage`.
    ///
    /// It declares the kernel capability because the pipeline is kernel authority:
    /// a caller must hold `kernel:plugin:manage` for the bus to deliver a question
    /// about loading, and only the system tier can hold it.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::KernelPluginManage,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`](nau_plugin::PluginError::Name) if [`ArbiterPlugin::ID`] is not a
    /// valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for ArbiterPlugin {
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
                "arbiter ready: {} stages, {} refusal codes, {} tiers",
                STAGES.len(),
                VOCABULARY.len(),
                Tier::ALL.len()
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "stages" => {
                self.grant
                    .require_operation(declared, Capability::KernelPluginManage)?;
                Ok(payload::answer(Self::ID, "stages", stages_json()))
            }
            "refusals" => {
                self.grant
                    .require_operation(declared, Capability::KernelPluginManage)?;
                Ok(payload::answer(Self::ID, "refusals", refusals_json()))
            }
            "tiers" => {
                self.grant
                    .require_operation(declared, Capability::KernelPluginManage)?;
                Ok(payload::answer(Self::ID, "tiers", tiers_json()))
            }
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

/// The pipeline, stage by stage.
fn stages_json() -> Value {
    let stages: Vec<Value> = STAGES
        .iter()
        .map(|stage| {
            json!({
                "stage": stage.name,
                "decides": stage.decides,
                "refusals": stage
                    .refusals
                    .iter()
                    .map(|refusal| refusal.code())
                    .collect::<Vec<&str>>(),
            })
        })
        .collect();
    let count = stages.len();
    json!({ "stages": stages, "count": count, "vocabulary_count": VOCABULARY.len() })
}

/// The refusal vocabulary, with the stages that attribute each code.
fn refusals_json() -> Value {
    let refusals: Vec<Value> = VOCABULARY
        .iter()
        .map(|refusal| {
            json!({
                "code": refusal.code(),
                "stages": stage_names_for(refusal),
            })
        })
        .collect();
    let unattributed: Vec<&str> = VOCABULARY
        .iter()
        .filter(|refusal| stage_names_for(refusal).is_empty())
        .map(|refusal| refusal.code())
        .collect();
    let count = refusals.len();
    json!({ "refusals": refusals, "unattributed": unattributed, "count": count })
}

/// Every stage that can refuse with `refusal`, in pipeline order.
fn stage_names_for(refusal: &LoadRefusal) -> Vec<&'static str> {
    STAGES
        .iter()
        .filter(|stage| stage.refusals.iter().any(|candidate| candidate == refusal))
        .map(|stage| stage.name)
        .collect()
}

/// The tier ceilings and runtimes, from the kernel's own two functions.
fn tiers_json() -> Value {
    let tiers: Vec<Value> = Tier::ALL
        .iter()
        .map(|tier| {
            let ceiling = tier_ceiling(*tier);
            json!({
                "tier": tier.label(),
                "runtime": runtime_for_tier(*tier).label(),
                "runs_in_process": tier.runs_in_process(),
                "ceiling": {
                    "memory_bytes": ceiling.memory_bytes,
                    "cpu_ms": ceiling.cpu_ms,
                    "disk_bytes": ceiling.disk_bytes,
                    "max_processes": ceiling.max_processes,
                    "max_output_bytes": ceiling.max_output_bytes,
                },
            })
        })
        .collect();
    let count = tiers.len();
    json!({ "tiers": tiers, "count": count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use crate::sign::{fixture_key, verified_system, FIXTURE_ISSUED_AT};
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::lifecycle::PluginState;
    use nau_plugin::runtime::RuntimeKind;
    use nau_plugin::CapabilityToken;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    const NOW: u64 = FIXTURE_ISSUED_AT;
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// The caller every fixture message comes from: a system plugin, because only the
    /// system tier can hold `kernel:plugin:manage`.
    const CALLER: &str = "com.twinsearth.sys.policy";

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse(CALLER).expect("a valid plugin name");
        PmbMessage::new(
            &id,
            Target::Plugin(ArbiterPlugin::ID.to_string()),
            Capability::parse(capability).expect("a known capability"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    /// Initialise a plugin exactly as the host would, without the host.
    fn initialised(mut plugin: ArbiterPlugin) -> ArbiterPlugin {
        let token = CapabilityToken::issue(
            ArbiterPlugin::ID,
            Tier::System,
            ArbiterPlugin::CAPABILITIES,
            DIGEST,
            NOW,
        )
        .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    /// Read a file from the kernel crate next door.
    ///
    /// A test that reads another crate's source is unusual, and it is deliberate
    /// here: the kernel exports neither a stage list nor a vocabulary list, so the
    /// only tie that can fail loudly when the kernel changes is its source. Test code
    /// is allowed to panic, which is what makes it a gate rather than a comment.
    fn kernel_file(relative: &str) -> String {
        let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("`{}` must be readable: {e}", path.display()))
    }

    /// The refusal codes the kernel's `LoadRefusal::code` impl names.
    fn kernel_refusal_codes() -> BTreeSet<String> {
        let source = kernel_file("../nau-plugin/src/error.rs");
        let mut codes = BTreeSet::new();
        for line in source.lines() {
            let Some(rest) = line.trim().strip_prefix("LoadRefusal::") else {
                continue;
            };
            let Some((_, after)) = rest.split_once("=>") else {
                continue;
            };
            let mut quoted = after.split('"');
            let _ = quoted.next();
            if let Some(code) = quoted.next() {
                codes.insert(code.to_string());
            }
        }
        codes
    }

    #[test]
    fn the_plugin_registers_reaches_running_and_only_then_answers() {
        let verified = verified_system(
            ArbiterPlugin::ID,
            ArbiterPlugin::CAPABILITIES,
            &fixture_key(3),
            &fixture_key(9),
        )
        .expect("a system manifest for this plugin verifies");
        let mut host =
            SystemPluginHost::new(HostLimits::default()).expect("the default limits are usable");
        host.register(
            Box::new(ArbiterPlugin::new().expect("the constant id parses")),
            &verified,
            NOW,
        )
        .expect("registers against its own manifest");
        assert_eq!(host.state(ArbiterPlugin::ID), Some(PluginState::Loaded));

        // Registered is not running: the host refuses before the plugin is asked.
        let err = host
            .handle(&request("kernel:plugin:manage", json!({ "op": "stages" })))
            .expect_err("a loaded plugin does not serve");
        assert!(err.to_string().contains("not running"), "{err}");

        host.init(ArbiterPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(ArbiterPlugin::ID), Some(PluginState::Running));
        assert!(host
            .handle(&request("kernel:plugin:manage", json!({ "op": "stages" })))
            .is_ok());
    }

    #[test]
    fn a_pipeline_query_is_answered_and_pinned_to_the_kernels_own_source() {
        let mut plugin = initialised(ArbiterPlugin::new().expect("id"));
        let answer = plugin
            .handle(&request("kernel:plugin:manage", json!({ "op": "stages" })))
            .expect("answers");
        let stages = answer["stages"].as_array().expect("an array");
        assert_eq!(answer["count"], json!(stages.len()));
        assert_eq!(answer["vocabulary_count"], json!(VOCABULARY.len()));

        let names: Vec<&str> = stages
            .iter()
            .map(|stage| stage["stage"].as_str().expect("a stage name"))
            .collect();
        assert_eq!(
            names,
            [
                "parse",
                "blacklist",
                "verify",
                "certification",
                "compat",
                "limits",
                "runtime",
                "registry",
                "bus",
                "lifecycle"
            ],
            "the order is the order the kernel runs the stages in"
        );
        for stage in stages {
            assert!(
                !stage["decides"]
                    .as_str()
                    .expect("a clause")
                    .trim()
                    .is_empty(),
                "{}",
                stage["stage"]
            );
        }

        // Every stage this door names must still be a stage literal in the kernel's
        // pipeline, so a rename there cannot leave a phantom stage here.
        let arbiter_source = kernel_file("../nau-plugin/src/arbiter.rs");
        for name in &names {
            let literal = format!("(\"{name}\"");
            assert!(
                arbiter_source.contains(&format!("LoadStep::ok{literal}"))
                    || arbiter_source.contains(&format!("LoadStep::refused{literal}")),
                "`{name}` is reported as a pipeline stage but appears in no `LoadStep` in \
                 nau-plugin/src/arbiter.rs"
            );
        }

        // The vocabulary is the kernel's own, in both directions.
        let reported: BTreeSet<String> = {
            let answer = plugin
                .handle(&request(
                    "kernel:plugin:manage",
                    json!({ "op": "refusals" }),
                ))
                .expect("answers");
            answer["refusals"]
                .as_array()
                .expect("an array")
                .iter()
                .map(|refusal| refusal["code"].as_str().expect("a code").to_string())
                .collect()
        };
        assert_eq!(
            reported,
            kernel_refusal_codes(),
            "the refusal vocabulary must be the kernel's, and a variant added there must be \
             covered here before this passes"
        );
    }

    #[test]
    fn the_refusal_answer_names_the_codes_no_stage_attributes() {
        let mut plugin = initialised(ArbiterPlugin::new().expect("id"));
        let answer = plugin
            .handle(&request(
                "kernel:plugin:manage",
                json!({ "op": "refusals" }),
            ))
            .expect("answers");
        let refusals = answer["refusals"].as_array().expect("an array");
        assert_eq!(answer["count"], json!(VOCABULARY.len()));

        // Every attributed code names stages that are in the table, and it names them
        // in pipeline order rather than in some order of its own.
        for refusal in refusals {
            let stages = refusal["stages"].as_array().expect("an array");
            let names: Vec<&str> = stages.iter().map(|s| s.as_str().expect("a name")).collect();
            let positions: Vec<usize> = names
                .iter()
                .map(|name| {
                    STAGES
                        .iter()
                        .position(|stage| stage.name == *name)
                        .unwrap_or_else(|| panic!("`{name}` is not a stage in the table"))
                })
                .collect();
            let mut ascending = positions.clone();
            ascending.sort_unstable();
            assert_eq!(
                positions, ascending,
                "{} is out of pipeline order",
                refusal["code"]
            );
        }

        // The two codes the kernel's vocabulary carries but its pipeline cannot emit
        // today. This is asserted rather than documented because it is a fact an operator
        // reading `refusals` will act on: a refusal code that no stage can produce is not a
        // thing to search the code for.
        assert_eq!(
            answer["unattributed"],
            json!(["name_invalid", "capability_not_approved"]),
            "`refusal_of` collapses `PluginError::Name` into `manifest_invalid`, and `verify` maps \
             every token-issue failure to `capability_not_permitted`"
        );
    }

    #[test]
    fn the_tier_ceilings_and_runtimes_are_the_kernels_own() {
        let mut plugin = initialised(ArbiterPlugin::new().expect("id"));
        let answer = plugin
            .handle(&request("kernel:plugin:manage", json!({ "op": "tiers" })))
            .expect("answers");
        let tiers = answer["tiers"].as_array().expect("an array");
        assert_eq!(tiers.len(), Tier::ALL.len());
        for (rendered, tier) in tiers.iter().zip(Tier::ALL) {
            assert_eq!(rendered["tier"], json!(tier.label()));
            assert_eq!(
                rendered["runtime"],
                json!(runtime_for_tier(tier).label()),
                "{tier}"
            );
            assert_eq!(rendered["runs_in_process"], json!(tier.runs_in_process()));
            let ceiling = tier_ceiling(tier);
            let rendered_ceiling = &rendered["ceiling"];
            assert_eq!(
                rendered_ceiling["memory_bytes"],
                json!(ceiling.memory_bytes)
            );
            assert_eq!(rendered_ceiling["cpu_ms"], json!(ceiling.cpu_ms));
            assert_eq!(rendered_ceiling["disk_bytes"], json!(ceiling.disk_bytes));
            assert_eq!(
                rendered_ceiling["max_processes"],
                json!(ceiling.max_processes)
            );
            assert_eq!(
                rendered_ceiling["max_output_bytes"],
                json!(ceiling.max_output_bytes)
            );
        }

        // The properties an operator relies on, read back through the door.
        assert_eq!(
            tiers
                .iter()
                .find(|t| t["tier"] == json!("sys"))
                .expect("the system tier")["runtime"],
            json!(RuntimeKind::Native.label())
        );
        assert_eq!(
            tiers
                .iter()
                .find(|t| t["tier"] == json!("official"))
                .expect("the official tier")["runtime"],
            json!(RuntimeKind::Process.label())
        );
    }

    #[test]
    fn an_operation_that_declares_the_wrong_capability_is_refused_by_name() {
        let mut plugin = initialised(ArbiterPlugin::new().expect("id"));
        let err = plugin
            .handle(&request("plugin:message:send", json!({ "op": "stages" })))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("kernel:plugin:manage"), "{text}");
        assert!(text.contains("plugin:message:send"), "{text}");
    }

    #[test]
    fn a_message_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let mut plugin = initialised(ArbiterPlugin::new().expect("id"));
        let err = plugin
            .handle(&request("net:dht:read", json!({ "op": "stages" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("net:dht:read"), "{err}");
    }

    #[test]
    fn an_unknown_operation_lists_the_vocabulary_this_door_implements() {
        let mut plugin = initialised(ArbiterPlugin::new().expect("id"));
        let err = plugin
            .handle(&request(
                "kernel:plugin:manage",
                json!({ "op": "load", "manifest": "{}" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains(payload::CODE_UNKNOWN_OPERATION), "{text}");
        assert!(text.contains("stages, refusals, tiers"), "{text}");
    }
}
