//! `com.twinsearth.sys.security.tribunal` — the body that writes policy and cannot move a plugin.
//!
//! # The split from the police, in both directions
//!
//! `tribunal` rules on violations, executes penalties and approves unsealing, and its results reach
//! the blacklist. It holds `kernel:policy:write` and **not** `kernel:plugin:manage`, and both halves
//! matter:
//!
//! * a tribunal that could **move plugins** would execute its own sentences without the police,
//!   which is a court with an army;
//! * and the police, symmetrically, cannot write the policy it enforces.
//!
//! # C-08's first criterion: a penalty is decided by a rule, not by the accused
//!
//! [`Penalty::of`] computes the penalty from the **reason** and the **violation count**, by a table
//! that lives here. A request may state the penalty it expects, and that statement is checked for
//! well-formedness — a guilty verdict must ask for something — but it **does not decide the
//! amount**. This is the shape upstream v2.8.2's finding F established for slashing, and the reason
//! is the same: a request that names its own punishment is a request to be judged by the accused.
//!
//! # C-08's second criterion: the real field names, and the ones that do not exist
//!
//! [`BLACKLIST_FIELDS`] is the field list of [`BlacklistEntry`] as this repository defines it. The
//! original design named `wasm_sha256` and `evidence_hash`; the real names are `module_sha256` and
//! `evidence_cid`.
//!
//! **This body's own first version got that wrong in a different way**: it answered with
//! `["did", "reason", "since", "evidence"]`, four names invented in the placeholder rather than
//! looked up. That is the same defect the criterion exists to prevent, committed while writing the
//! refusal of it — and it is why the list is now a `const` asserted against the struct, field by
//! field, in the tests below.
//!
//! # C-08's third criterion: unsealing needs an explicit approval, and not one's own
//!
//! A blacklist entry is the one state here meant to be hard to leave. So unsealing requires an
//! [`Approval`] **named in the request**, and [`Approval::Host`] is refused: the body that condemned
//! cannot release on its own authority, or the sentence would be advisory.

use nau_plugin::blacklist::{BlacklistEntry, BlacklistReason};
use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::{Approval, Capability};
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &[
    "capabilities",
    "penalties",
    "rule",
    "unseal",
    // E-09: the governance log's view and its replay -- and deliberately not a ballot.
    "governance",
];

/// The field names of [`BlacklistEntry`], as this repository defines it.
pub const BLACKLIST_FIELDS: [&str; 7] = [
    "plugin_name",
    "module_sha256",
    "reason",
    "blacklisted_at",
    "evidence_cid",
    "signer_key",
    "signature",
];

/// Names the original design used that exist nowhere in this repository.
pub const ABSENT_FIELDS: [&str; 2] = ["wasm_sha256", "evidence_hash"];

/// What a guilty verdict does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Penalty {
    /// Recorded, and the plugin keeps running.
    Reprimand,
    /// A blacklist entry against this build.
    CondemnBuild,
    /// A blacklist entry against every build of the name.
    CondemnName,
}

impl Penalty {
    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Penalty::Reprimand => "reprimand",
            Penalty::CondemnBuild => "condemn-build",
            Penalty::CondemnName => "condemn-name",
        }
    }

    /// Whether this penalty writes a blacklist entry.
    #[must_use]
    pub fn condemns(self) -> bool {
        !matches!(self, Penalty::Reprimand)
    }

    /// Whether it condemns every build.
    #[must_use]
    pub fn condemns_every_build(self) -> bool {
        matches!(self, Penalty::CondemnName)
    }

    /// **The rule.** The penalty follows from the reason and the count, and from nothing a caller
    /// said.
    ///
    /// The table, and why each row is what it is:
    ///
    /// * `Malware` condemns the name on the **first** verdict. A build that is malicious is not
    ///   evidence that the next build is safe, and the entry itself is what records that.
    /// * `KeyRevoked` likewise: the key is the identity, and a revoked key signs nothing anybody
    ///   should trust.
    /// * `PolicyViolation` starts at a reprimand and reaches a build condemnation on the **third**
    ///   verdict — the same threshold the kernel uses for quarantine, so an operator has one number
    ///   to remember rather than two.
    /// * `CommunityReport` never condemns the name on its own; reports are not findings, and a
    ///   tribunal that condemned every accused name on hearsay would be one nobody could appeal to.
    #[must_use]
    pub fn of(reason: BlacklistReason, violations: u32) -> Self {
        match reason {
            BlacklistReason::Malware | BlacklistReason::KeyRevoked => Penalty::CondemnName,
            BlacklistReason::PolicyViolation => {
                if violations >= nau_plugin::lifecycle::VIOLATION_THRESHOLD {
                    Penalty::CondemnBuild
                } else {
                    Penalty::Reprimand
                }
            }
            BlacklistReason::CommunityReport => Penalty::Reprimand,
        }
    }
}

/// The approval authorities that may unseal, and the one that may not.
///
/// [`Approval::Host`] is absent on purpose: the host is this node, and this node is the body that
/// condemned. An unsealing path that accepted its own approval would make every sentence advisory.
#[must_use]
pub fn may_unseal(approval: Approval) -> bool {
    !matches!(approval, Approval::Host)
}

/// The tribunal system plugin.
pub struct TribunalPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl TribunalPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.security.tribunal";

    /// The capabilities the plugin declares.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        // To write the blacklist. Not `KernelPluginManage`: see the module documentation.
        Capability::KernelPolicyWrite,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if the id is not a valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for TribunalPlugin {
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
            "security.tribunal ready; it writes policy, does not move plugins, and cannot unseal \
             on its own authority",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        // A self-description needs no authority beyond the read every plugin holds; everything else
        // here writes policy.
        let needed = match op {
            "capabilities" | "penalties" => Capability::LifecycleRead,
            _ => Capability::KernelPolicyWrite,
        };
        self.grant.require_operation(declared, needed)?;

        match op {
            "capabilities" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "declares": Self::CAPABILITIES.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "operations": OPERATIONS,
                    "may_not": ["kernel:plugin:manage"],
                    "why": "a court that could execute its own sentences without the police is a \
                            court with an army; the police, symmetrically, cannot write the policy \
                            it enforces",
                }),
            )),
            "penalties" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "rule": "a penalty is decided by server-side rules, never by the request body",
                    "why": "a request that names its own punishment is a request to be judged by \
                            the accused",
                    "blacklist_fields": BLACKLIST_FIELDS,
                    "original_design_fields": ABSENT_FIELDS,
                    "note": "the two names in the original design exist nowhere in this codebase; \
                             an entry carrying them could be written neither by this node nor read \
                             by it",
                    // The list is a `const` asserted against the struct field by field in the
                    // tests, because this body's own first version answered with four invented
                    // names -- the same defect the criterion exists to prevent.
                    "fields_are_asserted_against_the_struct": true,
                }),
            )),
            "rule" => {
                let reason: BlacklistReason =
                    serde_json::from_value(payload::field(&msg.payload, "reason")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "unknown_reason",
                                format!(
                                    "a ruling needs one of {:?} as its `reason`: {e}",
                                    BlacklistReason::ALL.map(BlacklistReason::label)
                                ),
                            )
                        })?;
                let violations = payload::optional_u64(&msg.payload, "violations")?.unwrap_or(0);
                let violations = u32::try_from(violations).unwrap_or(u32::MAX);

                // Criterion one, and the shape of the check is the point. A request MAY state the
                // penalty it expects; that statement is checked for well-formedness and does NOT
                // decide anything. A caller that asks for a lighter sentence than the rule gives is
                // told what the rule gives, and told that it was overruled.
                let asked = payload::optional_string(&msg.payload, "penalty")?;
                if let Some(requested) = asked.as_deref() {
                    if !["reprimand", "condemn-build", "condemn-name"].contains(&requested) {
                        return Err(payload::protocol(
                            "unknown_penalty",
                            format!(
                                "`{requested}` is not a penalty this body can impose; it imposes \
                                 reprimand, condemn-build and condemn-name"
                            ),
                        ));
                    }
                }
                let penalty = Penalty::of(reason, violations);
                let overruled = asked.as_deref().is_some_and(|r| r != penalty.label());
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "reason": reason.label(),
                        "violations": violations,
                        "penalty": penalty.label(),
                        "condemns": penalty.condemns(),
                        "condemns_every_build": penalty.condemns_every_build(),
                        "decided_by": "the rule in this body, not the request",
                        "request_asked_for": asked,
                        // Said explicitly rather than left to be inferred from the two fields: a
                        // caller whose request was overruled should not have to diff them.
                        "overruled": overruled,
                    }),
                ))
            }
            "unseal" => {
                let name = payload::string_field(&msg.payload, "plugin_name")?;
                // Criterion three: the approval is REQUIRED, and its absence is a refusal rather
                // than a default. A default would be an unsealing path nobody had to decide
                // anything to use.
                //
                // The presence is checked BEFORE the deserialisation, so that a request with no
                // approval gets `missing_approval` -- the name of the rule -- rather than whatever
                // the field reader says first. A caller reading the refusal should learn which rule
                // it broke, and "missing field `approval`" would leave it to guess whether the rule
                // is about approval at all.
                if msg.payload.get("approval").is_none() {
                    return Err(payload::protocol(
                        "missing_approval",
                        format!(
                            "unsealing is an approval, so it must name who approved it (one of \
                             {:?}); an unsealing path that defaulted would be one nobody had to \
                             decide anything to use",
                            Approval::ALL.map(Approval::label)
                        ),
                    ));
                }
                let approval: Approval =
                    serde_json::from_value(payload::field(&msg.payload, "approval")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "missing_approval",
                                format!(
                                    "`approval` must name an authority (one of {:?}): {e}",
                                    Approval::ALL.map(Approval::label)
                                ),
                            )
                        })?;
                if !may_unseal(approval) {
                    return Err(payload::protocol(
                        "self_approval",
                        format!(
                            "`{}` may not unseal: the host is this node, and this node is the body \
                             that condemned. An unsealing path that accepted its own approval would \
                             make every sentence advisory",
                            approval.label()
                        ),
                    ));
                }
                // The record such an unsealing would be written against, built from the REAL struct
                // with the real field names. Returned rather than written: this body holds no
                // `Blacklist` handle, and inventing one would be a second store.
                let entry_shape = BlacklistEntry {
                    plugin_name: name.to_string(),
                    module_sha256: payload::optional_string(&msg.payload, "module_sha256")?,
                    reason: BlacklistReason::PolicyViolation,
                    blacklisted_at: 0,
                    evidence_cid: String::new(),
                    signer_key: String::new(),
                    signature: String::new(),
                };
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "plugin_name": name,
                        "approved_by": approval.label(),
                        "approved": true,
                        "entry_fields": BLACKLIST_FIELDS,
                        "entry_shape": serde_json::to_value(&entry_shape).unwrap_or(Value::Null),
                        "note": "approved, not written: the blacklist is the kernel's store and this \
                                 body holds no handle to it",
                    }),
                ))
            }
            // E-09's third criterion, arriving as an operation that CANNOT execute. This body holds
            // `kernel:policy:write` and is where a governance decision would be applied -- but there is
            // no ballot operation here, because a court that could also vote would be one that decides
            // who sits on it.
            "governance" => {
                let log = crate::plugins::security::governance::GovernanceLog::new(1);
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "ballots_recorded": log.len(),
                        "revision": log.revision(),
                        "replay": log.replay(),
                        "this_body_cannot_vote": "there is no ballot operation here: this body \
                                                  applies a decided policy, and a court that could \
                                                  also vote would be one that decides who sits on \
                                                  it -- the same split v3.7.1 made between the \
                                                  police and this body, one level up",
                        "votes_cannot_execute": "the governance module tallies and produces a \
                                                 `PolicyChange`, which is DATA: applying it is this \
                                                 body's act, and there is no variant of its outcome \
                                                 meaning `and it is now in force`",
                        "on_chain_refused": "contracts/src/GovernanceToken.sol exists and is tested, \
                                             and nothing in crates/ can call it: no JSON-RPC client, \
                                             no ABI encoder, no EVM address type. A vote here is \
                                             recorded and replayable, and putting it on-chain is \
                                             refused for the same reason every other chain write in \
                                             this family is",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> BlacklistEntry {
        BlacklistEntry {
            plugin_name: "com.example.plugin".to_string(),
            module_sha256: Some("a".repeat(64)),
            reason: BlacklistReason::Malware,
            blacklisted_at: 1,
            evidence_cid: "bafyexample".to_string(),
            signer_key: "c".repeat(64),
            signature: "d".repeat(128),
        }
    }

    #[test]
    fn the_field_list_is_the_structs_own_fields_and_not_a_list_somebody_typed() {
        // C-08's second criterion, held the only way that keeps holding: by serialising a real
        // entry and comparing. A hand-written list drifts; this fails when a field is added,
        // renamed or removed.
        let value = serde_json::to_value(sample_entry()).expect("serialises");
        let object = value.as_object().expect("an entry is an object");

        let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut declared: Vec<&str> = BLACKLIST_FIELDS.to_vec();
        declared.sort_unstable();
        assert_eq!(
            declared, actual,
            "BLACKLIST_FIELDS must be exactly the fields of BlacklistEntry"
        );
    }

    #[test]
    fn the_names_the_original_design_used_are_not_fields_of_anything_here() {
        // The point of the criterion: `wasm_sha256` and `evidence_hash` exist nowhere, and an entry
        // written with them could be read by nobody.
        let value = serde_json::to_value(sample_entry()).expect("serialises");
        for absent in ABSENT_FIELDS {
            assert!(
                value.get(absent).is_none(),
                "`{absent}` is not a field of BlacklistEntry, and a list naming it would describe a \
                 struct that does not exist"
            );
            assert!(!BLACKLIST_FIELDS.contains(&absent));
        }
    }

    #[test]
    fn the_penalty_follows_the_reason_and_the_count_and_nothing_else() {
        // C-08's first criterion. Each row of the table, asserted where it is defined.
        assert_eq!(
            Penalty::of(BlacklistReason::Malware, 0),
            Penalty::CondemnName,
            "a malicious build is not evidence that the next one is safe"
        );
        assert_eq!(
            Penalty::of(BlacklistReason::KeyRevoked, 0),
            Penalty::CondemnName
        );
        assert_eq!(
            Penalty::of(BlacklistReason::PolicyViolation, 0),
            Penalty::Reprimand
        );
        assert_eq!(
            Penalty::of(BlacklistReason::PolicyViolation, 2),
            Penalty::Reprimand
        );
        assert_eq!(
            Penalty::of(BlacklistReason::PolicyViolation, 3),
            Penalty::CondemnBuild,
            "the third violation is the kernel's own threshold, so there is one number to remember"
        );
        assert_eq!(
            Penalty::of(BlacklistReason::CommunityReport, 99),
            Penalty::Reprimand,
            "reports are not findings, and a tribunal that condemned on hearsay could not be \
             appealed to"
        );
    }

    #[test]
    fn the_penalty_labels_are_distinct_and_classify_exactly_one_way() {
        let all = [
            Penalty::Reprimand,
            Penalty::CondemnBuild,
            Penalty::CondemnName,
        ];
        let mut labels: Vec<&str> = all.iter().map(|p| p.label()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count);

        assert!(!Penalty::Reprimand.condemns());
        assert!(Penalty::CondemnBuild.condemns());
        assert!(Penalty::CondemnName.condemns());
        assert!(!Penalty::CondemnBuild.condemns_every_build());
        assert!(Penalty::CondemnName.condemns_every_build());
    }

    #[test]
    fn the_tribunal_cannot_unseal_on_its_own_authority() {
        // C-08's third criterion. The host is this node and this node condemned, so its own
        // approval is refused; the other three are the authorities that may.
        assert!(!may_unseal(Approval::Host));
        assert!(may_unseal(Approval::VendorTeam));
        assert!(may_unseal(Approval::CertificationCommittee));
        assert!(may_unseal(Approval::Operator));
        // And the refused one is a real variant rather than a name that does not exist, so the
        // refusal is about authority rather than about spelling.
        assert!(Approval::ALL.contains(&Approval::Host));
    }

    #[test]
    fn it_may_write_policy_and_may_not_move_a_plugin() {
        assert!(TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite));
        assert!(
            !TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPluginManage),
            "a court that executes its own sentences is a court with an army"
        );
    }

    #[test]
    fn it_and_the_police_hold_complementary_authorities() {
        // A property of the pair, because the reason for the split is the relationship.
        let police = super::super::PolicePlugin::CAPABILITIES;
        assert!(police.contains(&Capability::KernelPluginManage));
        assert!(!police.contains(&Capability::KernelPolicyWrite));
        assert!(TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite));
        assert!(!TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPluginManage));
    }

    #[test]
    fn its_id_is_in_the_security_namespace() {
        assert!(TribunalPlugin::ID.starts_with("com.twinsearth.sys.security."));
        TribunalPlugin::new().expect("a valid id");
    }

    #[test]
    fn every_reason_has_a_row_in_the_table() {
        // A reason added to the kernel without a row here would fall into whichever arm a `match`
        // happened to reach. `Penalty::of` matches exhaustively, so what this really asserts is
        // that every reason produces a label rather than an empty one.
        for reason in BlacklistReason::ALL {
            let penalty = Penalty::of(reason, 0);
            assert!(
                !penalty.label().is_empty(),
                "{reason:?} produced a penalty with no label"
            );
        }
    }
}
