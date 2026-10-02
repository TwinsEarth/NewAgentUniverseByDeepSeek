//! Findings: every semantic difference between upstream and this project.
//!
//! A migration that silently coerces is worse than one that refuses, because the
//! operator cannot tell the two apart afterwards. Every difference this tool
//! encounters therefore produces a [`Warning`] carrying
//!
//! * a stable machine-readable [`Finding`] code,
//! * the [`Severity`] (a note, a warning, or a **rejection** of that record),
//! * the source file (and `#<index>` when the record came from a root array),
//! * a human sentence that names the offending field and value.
//!
//! Records with `Severity::Rejection` are **never** imported; everything else is
//! imported with the difference recorded.

use std::fmt;

use serde::Serialize;

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Recorded for the operator's information; the record was migrated as-is.
    Info,
    /// The record was migrated, but a semantic difference had to be resolved in
    /// a documented way (or something upstream claimed does not reconcile).
    Warning,
    /// The record was **refused** and not imported.
    Rejection,
}

impl Severity {
    /// The stable label used in JSON and in human output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Rejection => "rejection",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A stable, machine-readable reason for a [`Warning`].
///
/// Names are `snake_case` in JSON and are never reused for a different meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    // ---- recorded differences (Severity::Info) -----------------------------
    /// The record's DID carries upstream's `did:aip:` prefix and was kept
    /// verbatim; this project mints `did:nau:` but accepts the legacy prefix on
    /// parse, so the identity and its signature survive unchanged.
    LegacyDidPrefix,
    /// Fields upstream does not carry were filled with this project's documented
    /// defaults (the list of fields is in the message).
    DefaultsFilled,
    /// The public key was not in the record and was taken from the `keys.json`
    /// registry, which models the out-of-band key transport upstream required
    /// (a DID is only a fingerprint of the key, so it cannot verify anything by
    /// itself).
    KeyFromRegistry,
    /// The imported card/task is stored **unsigned**. Its legacy signature covers
    /// upstream's canonical payload, which is not the payload of the converted
    /// record, and no private key is available in a migration, so the converted
    /// record cannot be made wire-valid here. The verified legacy signature is
    /// preserved in the plan.
    TargetNotWireValid,
    /// An upstream settlement reason was carried over verbatim, with a note where
    /// the audit records that variant as unreachable in upstream's own code path.
    UpstreamUnreachableReason,
    /// The journal entry kind was inferred from which parties are present, because
    /// the upstream reason did not name one.
    LedgerKindInferred,
    /// A reserved internal account (`__escrow__:` / `__stake__:`) was preserved
    /// verbatim; keeping locked funds in a namespaced account is upstream's good
    /// idea and this project keeps it.
    SystemAccountKept,
    /// Nothing recognisable was found in the source tree.
    NoSourceArtifacts,
    /// An upstream status spelling differed from this project's state name and was
    /// mapped by the documented table.
    StatusRemapped,
    /// A database file was found in the source tree. This crate reads JSON only:
    /// upstream's SQLite store (`storage/persist.rs`, four tables) had no ledger or
    /// balance table and nothing ever read it back, so there is nothing in it that
    /// is not better served by the JSON artifacts. Reading it is possible in
    /// principle and deliberately out of scope.
    DatabaseIgnored,

    // ---- recorded differences that need attention (Severity::Warning) ------
    /// An upstream balance claim does not reconcile exactly with the sum of the
    /// journal entries for that account. The re-derived value is used and the
    /// difference is reported (upstream compared with a `0.001` tolerance and never
    /// re-derived from its journal at all).
    BalanceDiscrepancy,
    /// Two source records claimed the same DID/task id. The later one wins and the
    /// earlier one is reported (upstream silently overwrote the map entry *and*
    /// deposited the stake a second time).
    DuplicateSourceRecord,
    /// An entry has only one party, so the journal is not closed: the sum of
    /// imported movements is not zero and the report says so instead of pretending
    /// the ledger is conserved.
    ExternalParty,
    /// A capability id was lowercased to satisfy this project's skill index.
    CapabilityNormalised,
    /// A field was present but this project has no counterpart for its value; the
    /// documented default was used and the discarded value is named.
    FieldNotMapped,

    // ---- rejections (Severity::Rejection) ---------------------------------
    /// The file (or one element of a root array) was not valid JSON.
    MalformedJson,
    /// A source file could not be read as UTF-8 text.
    UnreadableFile,
    /// A record's root value was not a JSON object.
    RecordNotAnObject,
    /// A record's root was an array where an object was required, or the reverse.
    UnexpectedRoot,
    /// The raw literal could not be recovered verbatim from the source text.
    RawLiteralUnavailable,
    /// A required field was missing.
    MissingField,
    /// A field was present with the wrong JSON type.
    InvalidFieldType,
    /// A field was present and well-typed but its value is not usable here.
    InvalidFieldValue,
    /// Two fields that must agree disagree.
    ConflictingFields,
    /// The DID string is not a `did:aip:`/`did:nau:` identifier with a 16-hex-digit
    /// fingerprint.
    InvalidDid,
    /// The task id is outside this project's safe identifier charset.
    InvalidTaskId,
    /// No public key was available for the record's DID.
    MissingPublicKey,
    /// The supplied public key does not fingerprint the record's DID.
    DidKeyMismatch,
    /// The legacy signature is not 64 bytes of hex.
    SignatureEncodingInvalid,
    /// The legacy signature did not verify over the record's canonical payload.
    SignatureInvalid,
    /// This project's canonical form refuses a float, and the legacy record's
    /// signed payload contains one. Upstream admitted floats into signed payloads
    /// (`100` and `100.0` differ between languages), so such a signature is not
    /// reproducible here and the record cannot be accepted.
    LegacyFloatInSignedPayload,
    /// Canonicalization failed for another reason (root not an object, nesting too
    /// deep, a number outside `i64`/`u64`).
    CanonicalizationRefused,
    /// The amount was not a decimal number.
    AmountNotANumber,
    /// The amount needs more than six decimal places.
    AmountNotExact,
    /// The amount is outside the range of `i64` minor units.
    AmountOutOfRange,
    /// The amount was zero or negative where a strictly positive amount is
    /// required (upstream accepted negative deposits and slashes and its tolerance
    /// check could not see them).
    NonPositiveAmount,
    /// The upstream task status has no counterpart in this project's state machine.
    UnsupportedStatus,
    /// The converted record failed this project's own validation; the record was
    /// not imported.
    TargetValidationFailed,
    /// The ledger account label is outside the charset this project's account
    /// identifier accepts.
    InvalidAccountLabel,
}

impl Finding {
    /// Every variant, so that tests can pin the JSON spelling of all of them.
    pub const ALL: &'static [Finding] = &[
        Finding::LegacyDidPrefix,
        Finding::DefaultsFilled,
        Finding::KeyFromRegistry,
        Finding::TargetNotWireValid,
        Finding::UpstreamUnreachableReason,
        Finding::LedgerKindInferred,
        Finding::SystemAccountKept,
        Finding::NoSourceArtifacts,
        Finding::StatusRemapped,
        Finding::DatabaseIgnored,
        Finding::BalanceDiscrepancy,
        Finding::DuplicateSourceRecord,
        Finding::ExternalParty,
        Finding::CapabilityNormalised,
        Finding::FieldNotMapped,
        Finding::MalformedJson,
        Finding::UnreadableFile,
        Finding::RecordNotAnObject,
        Finding::UnexpectedRoot,
        Finding::RawLiteralUnavailable,
        Finding::MissingField,
        Finding::InvalidFieldType,
        Finding::InvalidFieldValue,
        Finding::ConflictingFields,
        Finding::InvalidDid,
        Finding::InvalidTaskId,
        Finding::MissingPublicKey,
        Finding::DidKeyMismatch,
        Finding::SignatureEncodingInvalid,
        Finding::SignatureInvalid,
        Finding::LegacyFloatInSignedPayload,
        Finding::CanonicalizationRefused,
        Finding::AmountNotANumber,
        Finding::AmountNotExact,
        Finding::AmountOutOfRange,
        Finding::NonPositiveAmount,
        Finding::UnsupportedStatus,
        Finding::TargetValidationFailed,
        Finding::InvalidAccountLabel,
    ];

    /// The stable label used in JSON and in human output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Finding::LegacyDidPrefix => "legacy_did_prefix",
            Finding::DefaultsFilled => "defaults_filled",
            Finding::KeyFromRegistry => "key_from_registry",
            Finding::TargetNotWireValid => "target_not_wire_valid",
            Finding::UpstreamUnreachableReason => "upstream_unreachable_reason",
            Finding::LedgerKindInferred => "ledger_kind_inferred",
            Finding::SystemAccountKept => "system_account_kept",
            Finding::NoSourceArtifacts => "no_source_artifacts",
            Finding::StatusRemapped => "status_remapped",
            Finding::DatabaseIgnored => "database_ignored",
            Finding::BalanceDiscrepancy => "balance_discrepancy",
            Finding::DuplicateSourceRecord => "duplicate_source_record",
            Finding::ExternalParty => "external_party",
            Finding::CapabilityNormalised => "capability_normalised",
            Finding::FieldNotMapped => "field_not_mapped",
            Finding::MalformedJson => "malformed_json",
            Finding::UnreadableFile => "unreadable_file",
            Finding::RecordNotAnObject => "record_not_an_object",
            Finding::UnexpectedRoot => "unexpected_root",
            Finding::RawLiteralUnavailable => "raw_literal_unavailable",
            Finding::MissingField => "missing_field",
            Finding::InvalidFieldType => "invalid_field_type",
            Finding::InvalidFieldValue => "invalid_field_value",
            Finding::ConflictingFields => "conflicting_fields",
            Finding::InvalidDid => "invalid_did",
            Finding::InvalidTaskId => "invalid_task_id",
            Finding::MissingPublicKey => "missing_public_key",
            Finding::DidKeyMismatch => "did_key_mismatch",
            Finding::SignatureEncodingInvalid => "signature_encoding_invalid",
            Finding::SignatureInvalid => "signature_invalid",
            Finding::LegacyFloatInSignedPayload => "legacy_float_in_signed_payload",
            Finding::CanonicalizationRefused => "canonicalization_refused",
            Finding::AmountNotANumber => "amount_not_a_number",
            Finding::AmountNotExact => "amount_not_exact",
            Finding::AmountOutOfRange => "amount_out_of_range",
            Finding::NonPositiveAmount => "non_positive_amount",
            Finding::UnsupportedStatus => "unsupported_status",
            Finding::TargetValidationFailed => "target_validation_failed",
            Finding::InvalidAccountLabel => "invalid_account_label",
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One finding: a recorded difference, a warning, or a rejected record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    /// How serious this is.
    pub severity: Severity,
    /// Stable machine-readable code.
    pub code: Finding,
    /// Source file, `file#<index>` for an element of a root array, or `None` for a
    /// finding about the tree as a whole.
    pub source: Option<String>,
    /// Human sentence naming the offending field and value.
    pub detail: String,
}

impl Warning {
    /// A note.
    pub fn info(code: Finding, source: Option<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            code,
            source,
            detail: detail.into(),
        }
    }

    /// Something that was migrated but resolved in a documented way.
    pub fn warn(code: Finding, source: Option<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code,
            source,
            detail: detail.into(),
        }
    }

    /// A record that was refused.
    pub fn reject(code: Finding, source: Option<String>, detail: impl Into<String>) -> Self {
        Self {
            severity: Severity::Rejection,
            code,
            source,
            detail: detail.into(),
        }
    }

    /// True when this finding refused a record.
    pub fn is_rejection(&self) -> bool {
        self.severity == Severity::Rejection
    }

    /// True when this finding merely records a difference.
    pub fn is_info(&self) -> bool {
        self.severity == Severity::Info
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.severity, self.code)?;
        if let Some(source) = &self.source {
            write!(f, " [{source}]")?;
        }
        write!(f, ": {}", self.detail)
    }
}

/// Why one record was rejected, before it is attached to a source file.
///
/// Conversion routines return this so that a single bad record does not abort a
/// whole tree; [`crate::plan`] turns it into a [`Warning`] with
/// [`Severity::Rejection`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defect {
    /// Stable code.
    pub code: Finding,
    /// Human sentence.
    pub detail: String,
    /// Source file (and `#<index>`) the record came from.
    pub source: String,
}

impl Defect {
    /// Build a defect for a source location.
    pub fn new(code: Finding, source: &str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            source: source.to_string(),
        }
    }
}

impl From<Defect> for Warning {
    fn from(defect: Defect) -> Self {
        Warning::reject(defect.code, Some(defect.source), defect.detail)
    }
}

impl fmt::Display for Defect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_finding_lists_itself_once_and_spells_itself_the_same_way_in_json() {
        let mut seen = std::collections::BTreeSet::new();
        for finding in Finding::ALL {
            assert!(seen.insert(*finding), "{finding:?} is listed twice in ALL");
            let json = serde_json::to_value(finding).expect("finding serializes");
            assert_eq!(
                json,
                serde_json::json!(finding.as_str()),
                "{finding:?}: serde spelling and as_str() disagree"
            );
            assert_eq!(finding.as_str(), finding.to_string());
        }
        assert_eq!(Finding::ALL.len(), seen.len());
    }

    #[test]
    fn severities_are_ordered_so_the_worst_finding_can_be_reported() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Rejection);
        assert_eq!(Severity::Rejection.as_str(), "rejection");
    }

    #[test]
    fn a_defect_becomes_a_rejection_warning_with_its_source() {
        let defect = Defect::new(Finding::AmountNotExact, "ledger.jsonl", "boom");
        let warning: Warning = defect.into();
        assert!(warning.is_rejection());
        assert_eq!(warning.source.as_deref(), Some("ledger.jsonl"));
        assert!(warning.to_string().contains("amount_not_exact"));
        assert!(Warning::info(Finding::LegacyDidPrefix, None, "x").is_info());
    }
}
