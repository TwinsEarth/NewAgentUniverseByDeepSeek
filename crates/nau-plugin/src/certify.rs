//! Certification: the review a publisher goes through, and the scope that review grants.
//!
//! # The part that is actually a security control
//!
//! A review pipeline is a process; a **certification scope** is a control. So the
//! type that matters here is [`Certification`], and the assertion that matters is
//! this: *a certified plugin may not hold a capability outside the scope its review
//! granted*, even if the manifest asks for it and even if the vendor counter-signature
//! is valid.
//!
//! Without that, certification would be decoration: the counter-signature proves the
//! vendor saw *a* manifest, but nothing would tie the approval to the capability set
//! that was actually reviewed. A publisher could be certified for a plugin with two
//! benign capabilities, then ship a manifest asking for `economy:settle`, and the
//! counter-signature machinery would happily confirm it.
//!
//! # The flow, as a state machine
//!
//! ```text
//! Submitted ─► AutoScanned ─► ManualReview ─► GreyRun ─► Certified
//!      │             │              │            │
//!      └─────────────┴──────────────┴────────────┴──────► Rejected
//! ```
//!
//! Terminal states are terminal, a stage cannot be skipped, and every transition
//! carries a reason — the same three rules the plugin lifecycle uses, for the same
//! reason: a process whose steps can be skipped is not a process.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::error::{PluginError, Result};
use crate::manifest::{Manifest, TrustStore, VerifiedManifest};
use crate::tier::Tier;

/// Where a submission is in review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStage {
    /// The publisher has submitted a binary, a manifest and a signature.
    Submitted,
    /// Automatic scanning finished.
    AutoScanned,
    /// A human is reading the code.
    ManualReview,
    /// The plugin is running under supervision on the test network.
    GreyRun,
    /// Approved.
    Certified,
    /// Refused, with findings.
    Rejected,
}

impl ReviewStage {
    /// Every stage.
    ///
    /// Exhaustive, so a new stage breaks this array and the totality test.
    pub const ALL: [ReviewStage; 6] = [
        ReviewStage::Submitted,
        ReviewStage::AutoScanned,
        ReviewStage::ManualReview,
        ReviewStage::GreyRun,
        ReviewStage::Certified,
        ReviewStage::Rejected,
    ];

    /// The stages nothing leaves.
    pub const TERMINAL: [ReviewStage; 2] = [ReviewStage::Certified, ReviewStage::Rejected];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ReviewStage::Submitted => "submitted",
            ReviewStage::AutoScanned => "auto_scanned",
            ReviewStage::ManualReview => "manual_review",
            ReviewStage::GreyRun => "grey_run",
            ReviewStage::Certified => "certified",
            ReviewStage::Rejected => "rejected",
        }
    }

    /// Whether nothing leaves this stage.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        ReviewStage::TERMINAL.contains(&self)
    }

    /// The legal next stages. `Rejected` is always reachable: a review can fail at
    /// any point, and a process that could not fail early would be a rubber stamp.
    #[must_use]
    pub fn next_stages(self) -> Vec<ReviewStage> {
        use ReviewStage::{AutoScanned, Certified, GreyRun, ManualReview, Rejected, Submitted};
        match self {
            Submitted => vec![AutoScanned, Rejected],
            AutoScanned => vec![ManualReview, Rejected],
            ManualReview => vec![GreyRun, Rejected],
            GreyRun => vec![Certified, Rejected],
            Certified | Rejected => vec![],
        }
    }

    /// Whether `self -> next` is legal. A repeat is never an edge.
    #[must_use]
    pub fn can_transition_to(self, next: ReviewStage) -> bool {
        next != self && self.next_stages().contains(&next)
    }
}

impl fmt::Display for ReviewStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What one automatic check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    /// Nothing wrong.
    Clean,
    /// Worth a human's attention.
    Note,
    /// Must be fixed before certification.
    Blocker,
}

impl Finding {
    /// Every finding level.
    pub const ALL: [Finding; 3] = [Finding::Clean, Finding::Note, Finding::Blocker];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Finding::Clean => "clean",
            Finding::Note => "note",
            Finding::Blocker => "blocker",
        }
    }

    /// Whether this finding forbids certification.
    #[must_use]
    pub fn blocks_certification(self) -> bool {
        matches!(self, Finding::Blocker)
    }
}

/// One automatic check and what it found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport {
    /// The check's name.
    pub check: String,
    /// What it found.
    pub finding: Finding,
    /// One clause of detail.
    pub detail: String,
}

/// The report an automatic scan produces.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Every check, in the order it ran.
    pub checks: Vec<CheckReport>,
}

impl ScanReport {
    /// Add a check result.
    pub fn push(&mut self, check: &str, finding: Finding, detail: &str) {
        self.checks.push(CheckReport {
            check: check.to_string(),
            finding,
            detail: detail.to_string(),
        });
    }

    /// Whether any check forbade certification.
    #[must_use]
    pub fn has_blocker(&self) -> bool {
        self.checks.iter().any(|c| c.finding.blocks_certification())
    }

    /// The blockers, for the refusal message.
    #[must_use]
    pub fn blockers(&self) -> Vec<&CheckReport> {
        self.checks
            .iter()
            .filter(|c| c.finding.blocks_certification())
            .collect()
    }
}

/// One review, with its history.
#[derive(Debug, Clone)]
pub struct Review {
    /// The plugin under review.
    pub plugin: String,
    /// The publisher's DID.
    pub publisher: String,
    stage: ReviewStage,
    history: Vec<(ReviewStage, String, u64)>,
    scan: ScanReport,
}

impl Review {
    /// Open a review.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when the plugin name or publisher is blank: a review
    /// that cannot say what it is reviewing is not a record.
    pub fn open(plugin: &str, publisher: &str, submitted_at: u64) -> Result<Self> {
        if plugin.trim().is_empty() || publisher.trim().is_empty() {
            return Err(PluginError::Manifest(
                "a review needs a plugin name and a publisher".into(),
            ));
        }
        Ok(Self {
            plugin: plugin.to_string(),
            publisher: publisher.to_string(),
            stage: ReviewStage::Submitted,
            history: vec![(
                ReviewStage::Submitted,
                "publisher submitted".to_string(),
                submitted_at,
            )],
            scan: ScanReport::default(),
        })
    }

    /// The current stage.
    #[must_use]
    pub fn stage(&self) -> ReviewStage {
        self.stage
    }

    /// The history, oldest first.
    #[must_use]
    pub fn history(&self) -> &[(ReviewStage, String, u64)] {
        &self.history
    }

    /// The scan report.
    #[must_use]
    pub fn scan(&self) -> &ScanReport {
        &self.scan
    }

    /// Attach the scan report. Only legal before a decision.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when the review has already reached a terminal stage.
    pub fn record_scan(&mut self, scan: ScanReport) -> Result<()> {
        if self.stage.is_terminal() {
            return Err(PluginError::Manifest(format!(
                "{} is terminal: a scan recorded now could not change the decision",
                self.stage
            )));
        }
        self.scan = scan;
        Ok(())
    }

    /// Move to `next`.
    ///
    /// Advancing past `AutoScanned` is refused while an automatic check reports a
    /// blocker: the pipeline must not be able to walk past its own findings.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] naming the illegal edge, the terminal stage, or the
    /// blocker that stands in the way.
    pub fn advance(&mut self, next: ReviewStage, because: &str, at: u64) -> Result<ReviewStage> {
        if because.trim().is_empty() {
            return Err(PluginError::Manifest(
                "a review transition must state why".into(),
            ));
        }
        if self.stage.is_terminal() {
            return Err(PluginError::Manifest(format!(
                "{} is terminal; a refused submission is resubmitted as a new review",
                self.stage
            )));
        }
        if !self.stage.can_transition_to(next) {
            return Err(PluginError::Manifest(format!(
                "{} -> {} is not a review edge",
                self.stage, next
            )));
        }
        if next != ReviewStage::Rejected
            && self.stage == ReviewStage::AutoScanned
            && self.scan.has_blocker()
        {
            let blockers: Vec<String> = self
                .scan
                .blockers()
                .iter()
                .map(|c| format!("{} ({})", c.check, c.detail))
                .collect();
            return Err(PluginError::Manifest(format!(
                "the automatic scan reported {} blocker(s): {}",
                blockers.len(),
                blockers.join(", ")
            )));
        }
        self.stage = next;
        self.history.push((next, because.to_string(), at));
        Ok(next)
    }
}

/// What a successful review grants.
///
/// The scope is the control: see the module documentation for why a certification
/// without a scope would be decoration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certification {
    /// The plugin certified.
    pub plugin: String,
    /// The capabilities the review approved. A manifest asking for anything outside
    /// this set is refused **even though it carries a valid counter-signature**.
    pub scope: BTreeSet<Capability>,
    /// The vendor key that signed the certification.
    pub vendor_key: String,
    /// When.
    pub certified_at: u64,
    /// The review this came from.
    pub stage_history: Vec<(ReviewStage, String, u64)>,
}

impl Certification {
    /// Issue a certification from a finished review.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when the review is not at `Certified`, when the
    /// scope is empty (a certification for nothing is a mistake, not a policy), or
    /// when a scoped capability is above what the tier may hold.
    pub fn issue(
        review: &Review,
        scope: &[Capability],
        tier: Tier,
        vendor_key: &str,
        at: u64,
    ) -> Result<Self> {
        if review.stage() != ReviewStage::Certified {
            return Err(PluginError::Manifest(format!(
                "`{}` is at {} and cannot be certified",
                review.plugin,
                review.stage()
            )));
        }
        if scope.is_empty() {
            return Err(PluginError::Manifest(
                "a certification must grant a non-empty scope; an empty one would certify nothing \
                 and could not be told apart from a mistake"
                    .into(),
            ));
        }
        if at == 0 {
            return Err(PluginError::Manifest(
                "a certification must carry a timestamp".into(),
            ));
        }
        for cap in scope {
            if let crate::capability::Grant::Refused { reason } = cap.decision(tier) {
                return Err(PluginError::Capability(format!(
                    "`{}` cannot be in the certification scope for tier {tier}: {reason}",
                    cap.as_str()
                )));
            }
        }
        Ok(Self {
            plugin: review.plugin.clone(),
            scope: scope.iter().copied().collect(),
            vendor_key: vendor_key.to_string(),
            certified_at: at,
            stage_history: review.history().to_vec(),
        })
    }

    /// Refuse unless every capability the manifest asks for is inside the scope.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] naming the capabilities that are outside the
    /// reviewed scope — the ones a valid counter-signature alone would have let
    /// through.
    pub fn require_within_scope(&self, manifest: &Manifest) -> Result<()> {
        let requested = manifest.requested_capabilities()?;
        let outside: Vec<&str> = requested
            .iter()
            .filter(|cap| !self.scope.contains(cap))
            .map(|cap| cap.as_str())
            .collect();
        if outside.is_empty() {
            return Ok(());
        }
        Err(PluginError::Capability(format!(
            "`{}` asks for {} which the {} certification of {} did not review (scope: {})",
            manifest.plugin.name,
            outside.join(", "),
            self.vendor_key.chars().take(12).collect::<String>(),
            self.plugin,
            self.scope
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    /// Verify a manifest against *both* signatures and the scope.
    ///
    /// This is the full certification path: the four manifest checks, plus the scope
    /// check that a bare counter-signature does not give.
    ///
    /// # Errors
    ///
    /// Whatever [`Manifest::verify`] refuses, or [`PluginError::Capability`] when the
    /// manifest reaches outside the reviewed scope.
    pub fn verify(
        &self,
        manifest: &Manifest,
        module: &[u8],
        trust: &TrustStore,
        now: u64,
    ) -> Result<VerifiedManifest> {
        let verified = manifest.verify(module, trust, now)?;
        self.require_within_scope(manifest)?;
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_750_000_000;

    fn review_at_certified() -> Review {
        let mut r = Review::open(
            "com.twinsearth.certified.analytics",
            "did:nau:0011223344556677",
            NOW,
        )
        .expect("open");
        for (stage, why) in [
            (ReviewStage::AutoScanned, "scan finished"),
            (ReviewStage::ManualReview, "queued for a human"),
            (ReviewStage::GreyRun, "reviewed"),
            (ReviewStage::Certified, "72h grey run clean"),
        ] {
            r.advance(stage, why, NOW + 1).expect("legal");
        }
        r
    }

    #[test]
    fn the_review_graph_is_total_and_terminal_states_are_really_terminal() {
        assert_eq!(ReviewStage::ALL.len(), 6);
        assert_eq!(ReviewStage::TERMINAL.len(), 2);
        for stage in ReviewStage::ALL {
            for next in stage.next_stages() {
                assert!(!stage.is_terminal(), "{stage} is terminal but has edges");
                assert_ne!(next, stage, "{stage} must not have a self-edge");
                assert!(stage.can_transition_to(next), "{stage} -> {next}");
            }
            if stage.is_terminal() {
                assert!(stage.next_stages().is_empty(), "{stage}");
            }
        }
    }

    #[test]
    fn a_stage_cannot_be_skipped() {
        let mut r = Review::open("io.example.a", "did:nau:00", NOW).expect("open");
        let err = r
            .advance(ReviewStage::Certified, "looks fine", NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("is not a review edge"), "{err}");
        assert_eq!(r.stage(), ReviewStage::Submitted);
    }

    #[test]
    fn rejection_is_reachable_from_every_non_terminal_stage() {
        // A review that could only fail at the end would be a rubber stamp.
        for stage in [
            ReviewStage::Submitted,
            ReviewStage::AutoScanned,
            ReviewStage::ManualReview,
            ReviewStage::GreyRun,
        ] {
            assert!(
                stage.can_transition_to(ReviewStage::Rejected),
                "{stage} must be able to reject"
            );
        }
    }

    #[test]
    fn a_terminal_review_does_not_move() {
        let mut r = review_at_certified();
        let err = r
            .advance(ReviewStage::Rejected, "changed my mind", NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("terminal"), "{err}");
    }

    #[test]
    fn a_review_transition_needs_a_reason() {
        let mut r = Review::open("io.example.a", "did:nau:00", NOW).expect("open");
        assert!(r.advance(ReviewStage::AutoScanned, "  ", NOW).is_err());
        assert_eq!(r.stage(), ReviewStage::Submitted);
    }

    #[test]
    fn the_pipeline_cannot_walk_past_its_own_blockers() {
        let mut r = Review::open("io.example.a", "did:nau:00", NOW).expect("open");
        r.advance(ReviewStage::AutoScanned, "scan done", NOW)
            .expect("legal");
        let mut scan = ScanReport::default();
        scan.push(
            "dependency-audit",
            Finding::Blocker,
            "CVE-2026-0001 in a dependency",
        );
        scan.push("wasm-validate", Finding::Clean, "module is well formed");
        r.record_scan(scan).expect("recorded");

        let err = r
            .advance(ReviewStage::ManualReview, "queue it", NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("blocker"), "{err}");
        assert!(err.to_string().contains("dependency-audit"), "{err}");
        // Rejection is still reachable, which is what a blocker should lead to.
        r.advance(ReviewStage::Rejected, "blocker unfixed", NOW)
            .expect("legal");
    }

    #[test]
    fn notes_do_not_block_certification() {
        let mut r = Review::open("io.example.a", "did:nau:00", NOW).expect("open");
        r.advance(ReviewStage::AutoScanned, "scan done", NOW)
            .expect("legal");
        let mut scan = ScanReport::default();
        scan.push("style", Finding::Note, "unused import");
        r.record_scan(scan).expect("recorded");
        assert!(!r.scan().has_blocker());
        r.advance(ReviewStage::ManualReview, "queue it", NOW)
            .expect("legal");
    }

    #[test]
    fn a_scan_recorded_after_a_decision_is_refused() {
        let mut r = review_at_certified();
        let err = r
            .record_scan(ScanReport::default())
            .expect_err("must be refused");
        assert!(err.to_string().contains("terminal"), "{err}");
    }

    #[test]
    fn only_a_certified_review_can_issue_a_certification() {
        let mut r = Review::open("io.example.a", "did:nau:00", NOW).expect("open");
        let err = Certification::issue(&r, &[Capability::MessageSend], Tier::Certified, "key", NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("cannot be certified"), "{err}");

        r.advance(ReviewStage::AutoScanned, "scan", NOW)
            .expect("legal");
        r.advance(ReviewStage::ManualReview, "read", NOW)
            .expect("legal");
        r.advance(ReviewStage::GreyRun, "observing", NOW)
            .expect("legal");
        r.advance(ReviewStage::Certified, "clean", NOW)
            .expect("legal");
        assert!(
            Certification::issue(&r, &[Capability::MessageSend], Tier::Certified, "key", NOW)
                .is_ok()
        );
    }

    #[test]
    fn an_empty_scope_or_a_zero_timestamp_is_refused() {
        let r = review_at_certified();
        assert!(Certification::issue(&r, &[], Tier::Certified, "key", NOW).is_err());
        assert!(
            Certification::issue(&r, &[Capability::MessageSend], Tier::Certified, "key", 0)
                .is_err()
        );
    }

    #[test]
    fn a_scope_above_the_tier_is_refused_at_issue_time() {
        // The certification committee cannot grant what the tier may never hold.
        let r = review_at_certified();
        let err = Certification::issue(
            &r,
            &[Capability::KernelPolicyWrite],
            Tier::Certified,
            "key",
            NOW,
        )
        .expect_err("must be refused");
        assert!(err.to_string().contains("kernel:policy:write"), "{err}");
    }

    fn keypair(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A manifest for `name` signed by `publisher`, with a vendor counter-signature.
    fn signed_manifest(name: &str, caps: &[&str]) -> (Manifest, TrustStore) {
        let vendor = keypair(9);
        let publisher = keypair(7);
        let module = b"module".to_vec();
        let mut m = Manifest {
            plugin: crate::manifest::PluginSection {
                name: name.to_string(),
                // The plugin's own version, not the kernel's.
                version: "1.4.0".into(),
                abi: "2.2".into(),
                entry: "plugin.bin".into(),
                publisher: "did:nau:0011223344556677".into(),
                module_sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&module)),
            },
            capabilities: crate::manifest::CapabilitySection {
                grant: caps.iter().map(|s| (*s).to_string()).collect(),
            },
            limits: crate::manifest::Limits {
                memory_bytes: 64 * 1024 * 1024,
                cpu_ms: 5_000,
                disk_bytes: 8 * 1024 * 1024,
                max_processes: 2,
                max_output_bytes: 32 * 1024,
            },
            waivers: std::collections::BTreeMap::new(),
            dependencies: Vec::new(),
            // A-11: the class this manifest runs at. Stated explicitly here rather than
            // relying on serde's default, so that adding the field is a decision this
            // construction site made rather than a value it inherited.
            priority: crate::manifest::PriorityClass::LatencyTolerant,
            signature: crate::manifest::SignatureSection {
                publisher_key: hex::encode(publisher.verifying_key().to_bytes()),
                manifest_digest: String::new(),
                sig: String::new(),
                counter_sig: None,
                counter_key: None,
            },
        };
        m.signature.manifest_digest = m.digest_hex().expect("digest");
        let digest = m.signature.manifest_digest.clone();
        m.signature.sig = hex::encode(publisher.sign(digest.as_bytes()).to_bytes());
        m.signature.counter_sig = Some(hex::encode(vendor.sign(digest.as_bytes()).to_bytes()));
        m.signature.counter_key = Some(hex::encode(vendor.verifying_key().to_bytes()));
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(vendor.verifying_key().to_bytes()))
            .expect("trust");
        (m, trust)
    }

    #[test]
    fn a_valid_counter_signature_does_not_let_a_manifest_outgrow_its_reviewed_scope() {
        // The control this module exists for. The manifest below is perfectly signed
        // -- publisher AND vendor -- so every check in `Manifest::verify` passes. It
        // is refused anyway, because the review approved a narrower capability set.
        let r = review_at_certified();
        // The review approved ONE capability. The probe below asks for two, and both
        // are capabilities the tier holds unconditionally -- so every manifest-level
        // check passes and only the reviewed scope can refuse it. (An earlier version
        // of this test issued a scope equal to the probe's request, which made the
        // scope check unreachable and the test vacuous.)
        let certification = Certification::issue(
            &r,
            &[Capability::MessageSend],
            Tier::Certified,
            "vendor-key",
            NOW,
        )
        .expect("issuable");

        let (inside, trust) = signed_manifest(
            "com.twinsearth.certified.analytics",
            &["plugin:message:send"],
        );
        assert!(certification
            .verify(&inside, b"module", &trust, NOW)
            .is_ok());

        // The capability has to be one the tier CAN hold, or `Manifest::verify`
        // refuses it first and this test would be proving the wrong thing. The first
        // version of this test used `economy:settle`, which at tier Certified needs
        // committee approval -- so it never reached the scope check at all. A second
        // basic capability is the right probe: the tier holds it unconditionally, the
        // signature is valid, and only the reviewed scope stands in the way.
        let (outside, trust2) = signed_manifest(
            "com.twinsearth.certified.analytics",
            &["plugin:message:send", "plugin:storage:own"],
        );
        assert!(
            outside.verify(b"module", &trust2, NOW).is_ok(),
            "the probe manifest must pass every manifest-level check, or the scope check is \
             not what is being tested"
        );
        let err = certification
            .verify(&outside, b"module", &trust2, NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("plugin:storage:own"), "{err}");
        assert!(err.to_string().contains("did not review"), "{err}");
    }

    #[test]
    fn the_certified_tier_can_be_scoped_for_capabilities_the_third_party_tier_refuses() {
        // **Why the tier has to come from the plugin's name rather than be hardcoded.**
        //
        // A certification is scoped at a tier, and `issue` refuses any scope containing a
        // capability that tier refuses outright. The review flow used to hardcode
        // `Tier::ThirdParty` in its scan rules, in its per-capability decisions and in
        // `issue` -- so while the arbiter requires a certification for every
        // `com.twinsearth.certified.*` name, the only shipped producer of certifications
        // issued them at a ceiling that refuses, outright, every capability a certified
        // plugin exists to be certified for. The tier that exists to be certified had no way
        // to be certified by anything shipped.
        //
        // Both directions are asserted, because only the pair shows that the tier is what
        // decides: the same scope, the same review, two ceilings.
        let r = review_at_certified();
        let sensitive = Capability::DhtRead;
        assert!(
            matches!(
                sensitive.decision(Tier::ThirdParty),
                crate::capability::Grant::Refused { .. }
            ),
            "this test is about a capability the third-party tier refuses; {sensitive} is not one"
        );

        let scoped_at_t2 = Certification::issue(
            &r,
            &[Capability::MessageSend, sensitive],
            Tier::Certified,
            "k",
            NOW,
        )
        .expect("a certified plugin may be certified for what the certified tier permits");
        assert!(scoped_at_t2.scope.contains(&sensitive));

        let refused_at_t3 = Certification::issue(
            &r,
            &[Capability::MessageSend, sensitive],
            Tier::ThirdParty,
            "k",
            NOW,
        )
        .expect_err("the third-party tier refuses it outright, and no review can grant it");
        assert!(
            refused_at_t3.to_string().contains("third-party"),
            "the refusal must name the tier that cannot hold it: {refused_at_t3}"
        );
    }

    #[test]
    fn the_scope_check_reports_every_outside_capability_at_once() {
        let r = review_at_certified();
        let certification =
            Certification::issue(&r, &[Capability::MessageSend], Tier::Certified, "k", NOW)
                .expect("issuable");
        let (m, _) = signed_manifest(
            "com.twinsearth.certified.analytics",
            &["plugin:storage:own", "plugin:lifecycle:read"],
        );
        let err = certification.require_within_scope(&m).expect_err("refused");
        let text = err.to_string();
        assert!(text.contains("plugin:storage:own"), "{text}");
        assert!(text.contains("plugin:lifecycle:read"), "{text}");
    }

    #[test]
    fn the_certification_carries_the_review_history() {
        let r = review_at_certified();
        let c = Certification::issue(&r, &[Capability::MessageSend], Tier::Certified, "k", NOW)
            .expect("issuable");
        assert_eq!(c.stage_history.len(), 5, "submitted plus four advances");
        assert_eq!(c.stage_history[0].0, ReviewStage::Submitted);
        assert_eq!(c.stage_history[4].0, ReviewStage::Certified);
    }

    #[test]
    fn every_stage_and_finding_has_a_distinct_label() {
        let mut labels: Vec<&str> = ReviewStage::ALL.iter().map(|s| s.label()).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), before);

        let mut findings: Vec<&str> = Finding::ALL.iter().map(|f| f.label()).collect();
        findings.sort_unstable();
        let before = findings.len();
        findings.dedup();
        assert_eq!(findings.len(), before);
        assert!(Finding::Blocker.blocks_certification());
        assert!(!Finding::Note.blocks_certification());
        assert!(!Finding::Clean.blocks_certification());
    }
}
