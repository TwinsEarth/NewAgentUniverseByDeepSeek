//! Quarantine: fingerprint, evidence, appeal, and the emergency broadcast.
//!
//! # Why an entry must be signed
//!
//! A blacklist that anyone can append to is a denial-of-service tool: the first
//! peer to reach a node could ban its competitors. So an entry is only accepted when
//! it carries a signature from a **trusted vendor key** — the same
//! [`crate::manifest::TrustStore`] that counter-signs official plugins. That makes
//! the blacklist a distributed decision that a node can verify offline, rather than
//! a list it has to trust.
//!
//! # Why a quarantine is not a deletion
//!
//! [`BlacklistEntry::module_sha256`] pins the *exact* artefact that was condemned. A
//! plugin that fixes the problem and ships a new build has a new digest, and it does
//! not match the entry — which is what makes "publish a new version and go through
//! review again" a real path rather than a slogan. Deleting the entry would erase
//! the evidence; pinning the digest keeps the evidence while leaving the door open.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{LoadRefusal, PluginError, Result};
use crate::manifest::{TrustStore, DIGEST_HEX_CHARS, SIGNATURE_BYTES};

/// Why a plugin was condemned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlacklistReason {
    /// Malicious behaviour was observed.
    Malware,
    /// The plugin violated policy without being malicious.
    PolicyViolation,
    /// The publisher key was revoked.
    KeyRevoked,
    /// Community reports crossed the threshold.
    CommunityReport,
}

impl BlacklistReason {
    /// Every reason.
    pub const ALL: [BlacklistReason; 4] = [
        BlacklistReason::Malware,
        BlacklistReason::PolicyViolation,
        BlacklistReason::KeyRevoked,
        BlacklistReason::CommunityReport,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            BlacklistReason::Malware => "malware",
            BlacklistReason::PolicyViolation => "policy_violation",
            BlacklistReason::KeyRevoked => "key_revoked",
            BlacklistReason::CommunityReport => "community_report",
        }
    }

    /// Whether the reason is grave enough that a re-published build must be
    /// reviewed rather than auto-accepted.
    #[must_use]
    pub fn requires_review_on_republish(self) -> bool {
        // Everything except a revoked key (which is about the publisher, not the
        // code) means the code itself was condemned, so new code needs eyes on it.
        !matches!(self, BlacklistReason::KeyRevoked)
    }
}

/// One quarantined artefact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlacklistEntry {
    /// The plugin name, matched exactly.
    pub plugin_name: String,
    /// The exact module digest condemned. `None` condemns every build of the name,
    /// which is reserved for a revoked key or confirmed malware.
    pub module_sha256: Option<String>,
    /// Why.
    pub reason: BlacklistReason,
    /// When, in Unix seconds.
    pub blacklisted_at: u64,
    /// A content identifier for the evidence bundle.
    pub evidence_cid: String,
    /// The vendor key that signed this entry, lower-case hex.
    pub signer_key: String,
    /// Ed25519 signature over the canonical bytes of every field above.
    pub signature: String,
}

impl BlacklistEntry {
    /// The bytes the signature covers: every field except `signature` itself.
    ///
    /// Built by hand rather than by serialising the struct, because the struct
    /// contains the signature — serialising it and then removing the field is the
    /// mistake that makes a signature cover itself (see the V2.5.6 audit's
    /// `canonical_payload` note).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(&self.plugin_name);
        out.push('\u{1f}');
        out.push_str(self.module_sha256.as_deref().unwrap_or("*"));
        out.push('\u{1f}');
        out.push_str(self.reason.label());
        out.push('\u{1f}');
        out.push_str(&self.blacklisted_at.to_string());
        out.push('\u{1f}');
        out.push_str(&self.evidence_cid);
        out.push('\u{1f}');
        out.push_str(&self.signer_key);
        out.into_bytes()
    }

    /// Whether this entry condemns a specific artefact, or every build of the name.
    #[must_use]
    pub fn condemns_every_build(&self) -> bool {
        self.module_sha256.is_none()
    }
}

/// The blacklist.
///
/// Entries are keyed by plugin name, and a lookup additionally compares the module
/// digest. There is deliberately **no** "remove" method for an entry: the module
/// documents the appeal path instead, and an operator who could delete an entry
/// could also erase the evidence that justified it.
#[derive(Debug, Default)]
pub struct Blacklist {
    entries: BTreeMap<String, BlacklistEntry>,
}

impl Blacklist {
    /// An empty blacklist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many names are condemned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is condemned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add an entry, verifying its signature against the trust store.
    ///
    /// # Errors
    ///
    /// [`PluginError::Blacklist`] when the signer is untrusted, the signature does
    /// not verify, the digest is malformed, or the timestamp is zero. Each of these
    /// is a way an unsigned or forged entry could otherwise enter the list.
    pub fn add(&mut self, entry: BlacklistEntry, trust: &TrustStore) -> Result<()> {
        if entry.blacklisted_at == 0 {
            return Err(PluginError::Blacklist(
                "an entry must carry the time it was issued".into(),
            ));
        }
        if let Some(digest) = &entry.module_sha256 {
            if digest.len() != DIGEST_HEX_CHARS
                || digest != &digest.to_ascii_lowercase()
                || !digest.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(PluginError::Blacklist(format!(
                    "module_sha256 `{digest}` is not a lower-case 64-character hex digest"
                )));
            }
        }
        if !trust.is_trusted_vendor_key(&entry.signer_key) {
            return Err(PluginError::Blacklist(format!(
                "entry for `{}` is signed by {}, which is not a trusted vendor key; an \
                 unsigned or self-signed blacklist is a way to ban a competitor",
                entry.plugin_name,
                &entry.signer_key[..entry.signer_key.len().min(12)]
            )));
        }
        let key = parse_key(&entry.signer_key)?;
        let sig = parse_signature(&entry.signature)?;
        key.verify(&entry.signing_bytes(), &sig).map_err(|e| {
            PluginError::Blacklist(format!(
                "entry for `{}` does not verify: {e}",
                entry.plugin_name
            ))
        })?;
        self.entries.insert(entry.plugin_name.clone(), entry);
        Ok(())
    }

    /// Whether `name` at `module_sha256` is condemned.
    ///
    /// `module_sha256` may be `None` when the digest is not known yet, in which case
    /// only an entry that condemns every build matches — an entry pinned to a
    /// specific artefact deliberately does **not** block a different build.
    #[must_use]
    pub fn check(&self, name: &str, module_sha256: Option<&str>) -> Option<&BlacklistEntry> {
        let entry = self.entries.get(name)?;
        match (&entry.module_sha256, module_sha256) {
            (None, _) => Some(entry),
            (Some(pinned), Some(actual)) if pinned == actual => Some(entry),
            _ => None,
        }
    }

    /// Refuse unless `name` at `module_sha256` is not condemned.
    ///
    /// # Errors
    ///
    /// [`PluginError::Blacklist`] whose message begins with the
    /// [`LoadRefusal::Blacklisted`] code, so a caller can branch on it.
    pub fn require_allowed(&self, name: &str, module_sha256: Option<&str>) -> Result<()> {
        match self.check(name, module_sha256) {
            None => Ok(()),
            Some(entry) => Err(PluginError::Blacklist(format!(
                "{}: `{name}` is blacklisted for {} since {} (evidence {}); a quarantined \
                 artefact is never loaded, and the path back is a new build, not a state change",
                LoadRefusal::Blacklisted.code(),
                entry.reason.label(),
                entry.blacklisted_at,
                entry.evidence_cid
            ))),
        }
    }

    /// Every condemned name, in name order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    /// The entry for a name, condemned or not.
    #[must_use]
    pub fn entry(&self, name: &str) -> Option<&BlacklistEntry> {
        self.entries.get(name)
    }
}

/// Where an appeal has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStage {
    /// The publisher has asked for a review.
    Appealed,
    /// Security is looking at it.
    UnderReview,
    /// A fixed build is being trialled under supervision.
    GreyList,
    /// Lifted, because a new build passed review.
    Lifted,
    /// Refused, with reasons.
    Denied,
}

impl AppealStage {
    /// The stages in order.
    pub const ALL: [AppealStage; 5] = [
        AppealStage::Appealed,
        AppealStage::UnderReview,
        AppealStage::GreyList,
        AppealStage::Lifted,
        AppealStage::Denied,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            AppealStage::Appealed => "appealed",
            AppealStage::UnderReview => "under_review",
            AppealStage::GreyList => "grey_list",
            AppealStage::Lifted => "lifted",
            AppealStage::Denied => "denied",
        }
    }

    /// Whether no further stage follows.
    #[must_use]
    pub fn is_final(self) -> bool {
        matches!(self, AppealStage::Lifted | AppealStage::Denied)
    }

    /// The legal next stages.
    #[must_use]
    pub fn next_stages(self) -> Vec<AppealStage> {
        match self {
            AppealStage::Appealed => vec![AppealStage::UnderReview, AppealStage::Denied],
            AppealStage::UnderReview => vec![AppealStage::GreyList, AppealStage::Denied],
            AppealStage::GreyList => vec![AppealStage::Lifted, AppealStage::Denied],
            AppealStage::Lifted | AppealStage::Denied => vec![],
        }
    }
}

/// Why an appeal cannot move to a stage.
///
/// The important part is what this type *cannot* express: there is no path from an
/// appeal to "the entry is gone". Lifting an appeal means a **new build passed
/// review**, and the old entry stays on the list with its evidence intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppealOutcome {
    /// Advanced.
    Advanced(AppealStage),
    /// Rejected, with the reason.
    Refused(String),
}

impl AppealOutcome {
    /// Advance an appeal, refusing an illegal move.
    ///
    /// # Errors
    ///
    /// Never returns `Err`; an illegal move is a *value*, because "your appeal was
    /// denied" is an ordinary answer to an ordinary request and not a host fault.
    #[must_use]
    pub fn advance(from: AppealStage, to: AppealStage) -> AppealOutcome {
        if from.is_final() {
            return AppealOutcome::Refused(format!("{} is final", from.label()));
        }
        if !from.next_stages().contains(&to) {
            return AppealOutcome::Refused(format!(
                "{} -> {} is not an appeal edge",
                from.label(),
                to.label()
            ));
        }
        AppealOutcome::Advanced(to)
    }
}

/// Parse a hex Ed25519 key.
fn parse_key(hex_key: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_key)
        .map_err(|e| PluginError::Blacklist(format!("signer_key is not hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PluginError::Blacklist("signer_key is not 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| PluginError::Blacklist(format!("signer_key is not a valid key: {e}")))
}

/// Parse a hex Ed25519 signature.
fn parse_signature(hex_sig: &str) -> Result<Signature> {
    if hex_sig.len() != SIGNATURE_BYTES * 2 {
        return Err(PluginError::Blacklist(format!(
            "signature is {} hex characters; {} are required",
            hex_sig.len(),
            SIGNATURE_BYTES * 2
        )));
    }
    let bytes = hex::decode(hex_sig)
        .map_err(|e| PluginError::Blacklist(format!("signature is not hex: {e}")))?;
    let arr: [u8; SIGNATURE_BYTES] = bytes
        .try_into()
        .map_err(|_| PluginError::Blacklist("signature is not 64 bytes".into()))?;
    Ok(Signature::from_bytes(&arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn vendor() -> (SigningKey, TrustStore) {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&hex::encode(key.verifying_key().to_bytes()))
            .expect("trust");
        (key, trust)
    }

    fn entry(
        name: &str,
        digest: Option<&str>,
        reason: BlacklistReason,
        key: &SigningKey,
    ) -> BlacklistEntry {
        let mut e = BlacklistEntry {
            plugin_name: name.to_string(),
            module_sha256: digest.map(str::to_string),
            reason,
            blacklisted_at: 1_750_000_000,
            evidence_cid: "bafyevidence".into(),
            signer_key: hex::encode(key.verifying_key().to_bytes()),
            signature: String::new(),
        };
        let sig = key.sign(&e.signing_bytes());
        e.signature = hex::encode(sig.to_bytes());
        e
    }

    #[test]
    fn a_signed_entry_is_accepted_and_blocks_the_artefact() {
        let (key, trust) = vendor();
        let mut list = Blacklist::new();
        list.add(
            entry(
                "io.example.bad",
                Some(DIGEST_A),
                BlacklistReason::Malware,
                &key,
            ),
            &trust,
        )
        .expect("accepted");
        assert_eq!(list.len(), 1);
        assert!(list.check("io.example.bad", Some(DIGEST_A)).is_some());
        let err = list
            .require_allowed("io.example.bad", Some(DIGEST_A))
            .expect_err("must refuse");
        assert!(err.to_string().contains("blacklisted"), "{err}");
        assert!(err.to_string().contains("malware"), "{err}");
    }

    #[test]
    fn an_entry_signed_by_an_untrusted_key_is_refused() {
        // The denial-of-service this prevents: anyone appending competitors to the
        // list and every node believing it.
        let (_, trust) = vendor();
        let rogue = SigningKey::from_bytes(&[7u8; 32]);
        let mut list = Blacklist::new();
        let err = list
            .add(
                entry("io.example.rival", None, BlacklistReason::Malware, &rogue),
                &trust,
            )
            .expect_err("must be refused");
        assert!(
            err.to_string().contains("not a trusted vendor key"),
            "{err}"
        );
        assert!(list.is_empty(), "nothing may be added by a refused entry");
    }

    #[test]
    fn a_tampered_entry_fails_its_signature() {
        let (key, trust) = vendor();
        let mut e = entry(
            "io.example.bad",
            Some(DIGEST_A),
            BlacklistReason::PolicyViolation,
            &key,
        );
        // Change the reason after signing: the classic way to escalate a policy
        // violation into "malware" without the vendor's key.
        e.reason = BlacklistReason::Malware;
        let mut list = Blacklist::new();
        let err = list.add(e, &trust).expect_err("must be refused");
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn a_pinned_entry_does_not_condemn_a_different_build() {
        // This is what makes "publish a fixed build" a real path.
        let (key, trust) = vendor();
        let mut list = Blacklist::new();
        list.add(
            entry(
                "io.example.bad",
                Some(DIGEST_A),
                BlacklistReason::Malware,
                &key,
            ),
            &trust,
        )
        .expect("accepted");
        assert!(list.check("io.example.bad", Some(DIGEST_B)).is_none());
        assert!(list
            .require_allowed("io.example.bad", Some(DIGEST_B))
            .is_ok());
    }

    #[test]
    fn an_unpinned_entry_condemns_every_build() {
        let (key, trust) = vendor();
        let mut list = Blacklist::new();
        list.add(
            entry("io.example.bad", None, BlacklistReason::KeyRevoked, &key),
            &trust,
        )
        .expect("accepted");
        assert!(list
            .entry("io.example.bad")
            .expect("entry")
            .condemns_every_build());
        assert!(list.check("io.example.bad", Some(DIGEST_B)).is_some());
        assert!(list.check("io.example.bad", None).is_some());
    }

    #[test]
    fn an_unknown_digest_does_not_match_a_pinned_entry() {
        let (key, trust) = vendor();
        let mut list = Blacklist::new();
        list.add(
            entry(
                "io.example.bad",
                Some(DIGEST_A),
                BlacklistReason::Malware,
                &key,
            ),
            &trust,
        )
        .expect("accepted");
        // The digest is unknown, so a pinned entry cannot be shown to apply.
        assert!(list.check("io.example.bad", None).is_none());
    }

    #[test]
    fn a_zero_timestamp_or_malformed_digest_is_refused() {
        let (key, trust) = vendor();
        let mut list = Blacklist::new();

        let mut no_time = entry("io.example.a", None, BlacklistReason::Malware, &key);
        no_time.blacklisted_at = 0;
        assert!(list.add(no_time, &trust).is_err());

        let mut bad_digest = entry(
            "io.example.a",
            Some("short"),
            BlacklistReason::Malware,
            &key,
        );
        let sig = key.sign(&bad_digest.signing_bytes());
        bad_digest.signature = hex::encode(sig.to_bytes());
        let err = list.add(bad_digest, &trust).expect_err("must be refused");
        assert!(err.to_string().contains("hex digest"), "{err}");
        assert!(list.is_empty());
    }

    #[test]
    fn signing_bytes_exclude_the_signature() {
        let (key, _) = vendor();
        let mut e = entry("io.example.a", None, BlacklistReason::Malware, &key);
        let before = e.signing_bytes();
        e.signature = "00".repeat(64);
        assert_eq!(
            before,
            e.signing_bytes(),
            "the signature must not cover itself"
        );
    }

    #[test]
    fn key_revocation_is_the_only_reason_that_does_not_require_re_review() {
        for reason in BlacklistReason::ALL {
            let expected = reason != BlacklistReason::KeyRevoked;
            assert_eq!(
                reason.requires_review_on_republish(),
                expected,
                "{reason:?}"
            );
        }
        assert_eq!(BlacklistReason::ALL.len(), 4);
    }

    #[test]
    fn an_appeal_can_be_lifted_but_never_erases_the_entry() {
        // The appeal path advances stages; it has no operation that removes an entry,
        // which is the point.
        let mut stage = AppealStage::Appealed;
        for next in [
            AppealStage::UnderReview,
            AppealStage::GreyList,
            AppealStage::Lifted,
        ] {
            match AppealOutcome::advance(stage, next) {
                AppealOutcome::Advanced(to) => stage = to,
                AppealOutcome::Refused(why) => panic!("{stage:?} -> {next:?} refused: {why}"),
            }
        }
        assert!(stage.is_final());
        assert_eq!(stage, AppealStage::Lifted);
        assert_eq!(
            AppealOutcome::advance(stage, AppealStage::UnderReview),
            AppealOutcome::Refused("lifted is final".into())
        );
    }

    #[test]
    fn the_appeal_graph_refuses_skipping_review() {
        assert!(matches!(
            AppealOutcome::advance(AppealStage::Appealed, AppealStage::Lifted),
            AppealOutcome::Refused(_)
        ));
        assert!(matches!(
            AppealOutcome::advance(AppealStage::Denied, AppealStage::GreyList),
            AppealOutcome::Refused(_)
        ));
    }

    #[test]
    fn the_appeal_graph_is_total() {
        for stage in AppealStage::ALL {
            for next in stage.next_stages() {
                assert!(!stage.is_final(), "{stage:?} is final but has edges");
                assert!(
                    matches!(
                        AppealOutcome::advance(stage, next),
                        AppealOutcome::Advanced(_)
                    ),
                    "{stage:?} -> {next:?}"
                );
            }
        }
        assert_eq!(AppealStage::ALL.len(), 5);
    }
}
