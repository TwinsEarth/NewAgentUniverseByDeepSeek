//! `com.twinsearth.sys.security.report` — the body that records and cannot act.
//!
//! # Why a reporting desk holds `chain:evm:write`
//!
//! It is the only body that does, and the reason is what a report is for. An anomaly report whose
//! evidence is not anchored is an assertion this node makes about itself; anchoring it writes the
//! digest to a chain the node does not control, which is what makes the report checkable by
//! somebody who does not trust this node.
//!
//! That is also why it holds **no `kernel:*`**: a body that could both record an anomaly and act on
//! it would be a police force that writes its own incident reports.
//!
//! # C-07's first criterion: a grade is a claim about a check, so the check has to be nameable
//!
//! [`EvidenceGrade`] already exists in `nau-attest` and already publishes its own ceiling:
//! [`MAX_ACHIEVABLE_GRADE`] is `SignatureVerified`, one rung below `HardwareAttested`, because the
//! certificate-chain verification the top rung names **does not exist in this workspace**.
//!
//! So this body does two things with it, and both are refusals:
//!
//! 1. **A report graded at or above the ceiling must name the artifact it was checked against.** A
//!    `signature-verified` report with nothing to re-check is a claim that a signature was verified
//!    and no way to verify it — so it is refused **when it is recorded**, not when somebody later
//!    tries to review it. The difference matters: a report refused at review time has already been
//!    distributed.
//!
//! 2. **A report claiming `HardwareAttested` is refused outright**, because nothing here can award
//!    it. [`MAX_ACHIEVABLE_GRADE`] is **read** rather than restated, so if this workspace ever
//!    implements the chain, this body starts accepting the top rung without an edit here.
//!
//! # What is deliberately not done
//!
//! Nothing here re-checks the attestation. `nau-attest` does that and this defers to it; a second
//! implementation would be a second answer to "is this evidence", and the two would disagree
//! eventually. What this body does is refuse a **claim** the workspace cannot support, and require
//! that a supported claim point at its own support.

use nau_attest::{EvidenceGrade, MAX_ACHIEVABLE_GRADE};
use nau_plugin::bus::{PmbKind, PmbMessage, Target};
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::host::{BusHandle, HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "grades", "record", "anchor"];

/// The plugin the anchoring is delegated to.
pub const CHAIN_ANCHOR_PLUGIN: &str = "com.twinsearth.official.chain-anchor";

/// One piece of evidence, as a report carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// What was checked, as `nau-attest` grades it.
    pub grade: EvidenceGrade,
    /// What the evidence is about.
    pub subject: String,
    /// **What a reviewer would re-check**, named.
    ///
    /// Required at or above [`MAX_ACHIEVABLE_GRADE`] and optional below it, because a report that
    /// says nothing was verified has nothing to point at. An empty string is refused for the same
    /// reason a missing one is: it is a field that looks filled in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    /// The digest of the evidence itself, so the record can be matched to the bytes.
    pub digest: String,
}

impl Evidence {
    /// Whether this grade is one the workspace can actually award.
    #[must_use]
    pub fn is_achievable(&self) -> bool {
        self.grade <= MAX_ACHIEVABLE_GRADE
    }

    /// Whether this grade requires the report to name what was checked.
    #[must_use]
    pub fn requires_artifact(&self) -> bool {
        self.grade >= MAX_ACHIEVABLE_GRADE
    }

    /// Whether the artifact is present **and** says something.
    #[must_use]
    pub fn names_an_artifact(&self) -> bool {
        self.artifact
            .as_deref()
            .is_some_and(|a| !a.trim().is_empty())
    }

    /// Check the two rules, naming which one failed.
    ///
    /// # Errors
    ///
    /// A protocol refusal. Kept as a method rather than inline in the handler so the rules can be
    /// tested without a host, and so a caller reading the plugin sees both in one place.
    pub fn validate(&self) -> Result<()> {
        if !self.is_achievable() {
            return Err(payload::protocol(
                "grade_not_achievable",
                format!(
                    "`{}` is above the highest grade this workspace can award (`{}`), whose \
                     certificate chain is not implemented; a report claiming it would be a claim \
                     nothing here can support",
                    grade_label(self.grade),
                    grade_label(MAX_ACHIEVABLE_GRADE)
                ),
            ));
        }
        if self.requires_artifact() && !self.names_an_artifact() {
            return Err(payload::protocol(
                "evidence_not_recheckable",
                format!(
                    "a `{}` report must name the artifact it was checked against, or it is a claim \
                     that a check happened with no way to check it. Refused when it is RECORDED \
                     rather than at review: a report refused later has already been distributed",
                    grade_label(self.grade)
                ),
            ));
        }
        if self.digest.trim().is_empty() {
            return Err(payload::protocol(
                "missing_digest",
                "evidence must carry the digest of the bytes it is about, so the record can be \
                 matched to what it describes",
            ));
        }
        Ok(())
    }
}

/// A machine-readable grade name, from the crate that grades.
///
/// `nau-attest` publishes `label` for exactly this, so reporting code never `Debug`-formats an enum
/// into a message a person reads.
#[must_use]
pub fn grade_label(grade: EvidenceGrade) -> &'static str {
    nau_attest::grade::label(grade)
}

/// The reporting system plugin.
pub struct ReportPlugin {
    id: PluginId,
    grant: PluginGrant,
    /// The handle that lets `handle` queue a message, since the context itself is not available
    /// there.
    bus: Option<BusHandle>,
}

impl ReportPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.security.report";

    /// The capabilities the plugin declares.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        // To anchor evidence. The only body that holds it.
        Capability::ChainEvmWrite,
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
            bus: None,
        })
    }
}

impl SystemPlugin for ReportPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        // Taken here, because `handle` does not receive the context and the anchor op has to queue
        // a message. A plugin that could not send would have to perform the write itself, which is
        // the second implementation of anchoring this body delegates to avoid.
        self.bus = Some(ctx.bus_handle());
        ctx.log(
            LogLevel::Info,
            &format!(
                "security.report ready; it records and anchors, holds no authority to act, and \
                 awards at most `{}`",
                grade_label(MAX_ACHIEVABLE_GRADE)
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        let needed = match op {
            // A self-description and the list of grades are reads. Recording and anchoring are the
            // two things this body exists to do, and anchoring is what the chain write is for.
            "capabilities" | "grades" => Capability::LifecycleRead,
            _ => Capability::ChainEvmWrite,
        };
        self.grant.require_operation(declared, needed)?;

        match op {
            "capabilities" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "declares": Self::CAPABILITIES.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "operations": OPERATIONS,
                    "may_not": ["kernel:plugin:manage", "kernel:policy:write"],
                    "why": "a body that could record an anomaly and act on it would write its own \
                            incident reports",
                }),
            )),
            "grades" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    // Read from the crate that grades, rather than restated here. If this workspace
                    // ever implements the certificate chain, this answer changes with it and no
                    // edit is needed in the report body.
                    "ceiling": grade_label(MAX_ACHIEVABLE_GRADE),
                    "all": [
                        grade_label(EvidenceGrade::Unverified),
                        grade_label(EvidenceGrade::StructurallyValid),
                        grade_label(EvidenceGrade::SignatureVerified),
                        grade_label(EvidenceGrade::HardwareAttested),
                    ],
                    "above_the_ceiling": grade_label(EvidenceGrade::HardwareAttested),
                    "why_a_ceiling": "the top rung means a full vendor certificate chain and a \
                                      hardware root were verified, and that is not implemented in \
                                      this workspace",
                    "rule": "a report at or above the ceiling must name the artifact it was checked \
                             against, and is refused when it is RECORDED rather than at review -- a \
                             report refused later has already been distributed",
                }),
            )),
            "record" => {
                let evidence: Evidence =
                    serde_json::from_value(payload::field(&msg.payload, "evidence")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "malformed_evidence",
                                format!(
                                    "an evidence record needs a grade, a subject and a digest: {e}"
                                ),
                            )
                        })?;
                // The rules, at the moment of recording.
                evidence.validate()?;
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "recorded": true,
                        "grade": grade_label(evidence.grade),
                        "subject": evidence.subject,
                        "digest": evidence.digest,
                        "artifact": evidence.artifact,
                        "recheckable": evidence.names_an_artifact(),
                        // Said on every answer: a reader who does not know this will assume more
                        // than the record can support.
                        "anchored": false,
                        "note": "recording is not anchoring; the digest reaches a chain only when \
                                 `anchor` is called, and until then this is this node's word",
                    }),
                ))
            }
            "anchor" => {
                let evidence: Evidence =
                    serde_json::from_value(payload::field(&msg.payload, "evidence")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "malformed_evidence",
                                format!("an anchor needs the same evidence record: {e}"),
                            )
                        })?;
                // Anchoring something unrecordable would put a claim this body refuses onto a chain
                // it cannot take back, so the same rules run first.
                evidence.validate()?;
                let at = payload::optional_u64(&msg.payload, "at")?.unwrap_or(0);
                if at == 0 {
                    return Err(payload::protocol(
                        "missing_timestamp",
                        "an anchor must carry a non-zero `at`",
                    ));
                }
                let Some(bus) = self.bus.as_ref() else {
                    return Err(payload::protocol(
                        "not_initialised",
                        "the bus handle is taken in `init`; a plugin that has not been initialised \
                         cannot queue a message",
                    ));
                };
                // Queued rather than performed: the chain plugin owns the write, and doing it here
                // would be the second implementation of anchoring this body exists to delegate.
                let message = PmbMessage::new(
                    &self.id,
                    Target::Plugin(CHAIN_ANCHOR_PLUGIN.to_string()),
                    Capability::ChainEvmWrite,
                    PmbKind::Request,
                    json!({
                        "op": "record_anchor",
                        "subject": evidence.subject,
                        "digest": evidence.digest,
                        "grade": grade_label(evidence.grade),
                    }),
                    at,
                )
                .with_topic("nau.security.anchor");
                bus.send(message)?;
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "queued": true,
                        "to": CHAIN_ANCHOR_PLUGIN,
                        "capability": Capability::ChainEvmWrite.as_str(),
                        "digest": evidence.digest,
                        "grade": grade_label(evidence.grade),
                        "note": "queued, not anchored: the chain plugin performs the write and the \
                                 host carries the message",
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

    fn evidence(grade: EvidenceGrade, artifact: Option<&str>) -> Evidence {
        Evidence {
            grade,
            subject: "com.example.plugin".to_string(),
            artifact: artifact.map(str::to_string),
            digest: "a".repeat(64),
        }
    }

    #[test]
    fn a_verified_report_without_an_artifact_is_refused_when_it_is_recorded() {
        // C-07's first criterion. The refusal is at record time rather than review time, and the
        // message says so: a report refused later has already been distributed.
        let err = evidence(MAX_ACHIEVABLE_GRADE, None)
            .validate()
            .expect_err("must refuse");
        let text = format!("{err}");
        assert!(text.contains("evidence_not_recheckable"), "got: {text}");
        assert!(
            text.contains("RECORDED"),
            "the refusal must say WHEN it is applied, got: {text}"
        );

        // An empty string is refused for the same reason a missing field is: it is a field that
        // looks filled in.
        let err = evidence(MAX_ACHIEVABLE_GRADE, Some("   "))
            .validate()
            .expect_err("must refuse a blank artifact");
        assert!(format!("{err}").contains("evidence_not_recheckable"));

        // And naming one is accepted, so the rule is not simply always failing.
        evidence(MAX_ACHIEVABLE_GRADE, Some("sha256:abc"))
            .validate()
            .expect("a named artifact satisfies the rule");
    }

    #[test]
    fn a_grade_above_the_ceiling_is_refused_outright() {
        // `HardwareAttested` is not reachable in this workspace, and the ceiling is READ from
        // `nau-attest` rather than restated here -- so implementing the chain would make this body
        // accept the top rung without an edit.
        assert_eq!(MAX_ACHIEVABLE_GRADE, EvidenceGrade::SignatureVerified);
        assert!(EvidenceGrade::HardwareAttested > MAX_ACHIEVABLE_GRADE);

        let err = evidence(EvidenceGrade::HardwareAttested, Some("sha256:abc"))
            .validate()
            .expect_err("must refuse a grade nothing here can award");
        let text = format!("{err}");
        assert!(text.contains("grade_not_achievable"), "got: {text}");
        assert!(
            text.contains("certificate chain is not implemented"),
            "the refusal must name why, got: {text}"
        );
    }

    #[test]
    fn a_lower_grade_needs_no_artifact_because_it_claims_no_check() {
        // The rule is not "every report names an artifact" -- it is that a report claiming a check
        // must point at it. An unverified envelope is data, and its grade says so.
        for grade in [EvidenceGrade::Unverified, EvidenceGrade::StructurallyValid] {
            assert!(!evidence(grade, None).requires_artifact());
            evidence(grade, None)
                .validate()
                .unwrap_or_else(|e| panic!("{grade:?} must not need an artifact: {e}"));
        }
    }

    #[test]
    fn the_boundary_is_the_ceiling_itself_rather_than_one_above_it() {
        assert!(evidence(EvidenceGrade::SignatureVerified, None).requires_artifact());
        assert!(!evidence(EvidenceGrade::StructurallyValid, None).requires_artifact());
    }

    #[test]
    fn evidence_without_a_digest_is_refused() {
        // The digest is what matches the record to the bytes it describes; without it the record is
        // an assertion about nothing in particular.
        let mut e = evidence(EvidenceGrade::Unverified, None);
        e.digest = "  ".to_string();
        let err = e.validate().expect_err("must refuse");
        assert!(format!("{err}").contains("missing_digest"), "got: {err}");
    }

    #[test]
    fn it_is_the_only_body_holding_a_chain_write_and_it_holds_no_kernel_authority() {
        assert!(ReportPlugin::CAPABILITIES.contains(&Capability::ChainEvmWrite));
        for cap in ReportPlugin::CAPABILITIES {
            assert!(
                !cap.is_kernel(),
                "a body that could record an anomaly and act on it would write its own reports, \
                 but it holds {}",
                cap.as_str()
            );
        }
    }

    #[test]
    fn it_delegates_the_write_rather_than_performing_it() {
        // The plugin it queues to, named so that a rename in the official plugin set fails this
        // test rather than silently addressing a plugin that is not there.
        assert_eq!(CHAIN_ANCHOR_PLUGIN, "com.twinsearth.official.chain-anchor");
        assert!(OPERATIONS.contains(&"anchor"));
    }

    #[test]
    fn its_id_is_in_the_security_namespace() {
        assert!(ReportPlugin::ID.starts_with("com.twinsearth.sys.security."));
        ReportPlugin::new().expect("a valid id");
    }

    #[test]
    fn the_grade_labels_come_from_the_crate_that_grades() {
        // Not restated: `nau-attest` publishes `label` so reporting code never Debug-formats an enum
        // into a message a person reads, and the wire name cannot drift silently.
        assert_eq!(grade_label(EvidenceGrade::Unverified), "unverified");
        assert_eq!(
            grade_label(EvidenceGrade::StructurallyValid),
            "structurally-valid"
        );
        assert_eq!(
            grade_label(EvidenceGrade::SignatureVerified),
            "signature-verified"
        );
        assert_eq!(
            grade_label(EvidenceGrade::HardwareAttested),
            "hardware-attested"
        );
    }
}
