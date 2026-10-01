//! The kernel's error taxonomy.
//!
//! Deliberately its own type rather than a variant of [`nau_core`]'s: that enum is
//! `#[non_exhaustive]`, so a crate outside `nau-core` cannot add to it, and
//! converting every plugin failure into a generic validation error would lose the
//! distinction that matters most here — *which kind of refusal this was*. A refused
//! capability, a forged manifest and a missing blacklist entry are three different
//! operational facts.

use serde::{Deserialize, Serialize};

/// What can go wrong while classifying, verifying, loading or routing a plugin.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// The plugin name is not a valid, classifiable name.
    #[error("plugin name: {0}")]
    Name(String),
    /// The manifest is malformed, incomplete, or inconsistent with itself.
    #[error("manifest: {0}")]
    Manifest(String),
    /// A signature, digest or key did not verify.
    #[error("signature: {0}")]
    Signature(String),
    /// A capability was requested, granted or used improperly.
    #[error("capability: {0}")]
    Capability(String),
    /// The tier rule refused the plugin.
    #[error("tier: {0}")]
    Tier(String),
    /// The lifecycle state machine refused the transition.
    #[error("lifecycle: {0}")]
    Lifecycle(String),
    /// The bus refused to deliver a message.
    #[error("bus: {0}")]
    Bus(String),
    /// The runtime refused to start, call or stop an instance.
    #[error("runtime: {0}")]
    Runtime(String),
    /// The blacklist store refused, or the plugin is on it.
    #[error("blacklist: {0}")]
    Blacklist(String),
    /// Filesystem or process I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON could not be encoded or decoded.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl PluginError {
    /// A stable machine-readable code, for logs, metrics and the REST surface.
    ///
    /// The project's rule from the market work applies here too: a status is a
    /// machine code, never prose that a caller has to pattern-match.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            PluginError::Name(_) => "plugin_name_invalid",
            PluginError::Manifest(_) => "manifest_invalid",
            PluginError::Signature(_) => "signature_invalid",
            PluginError::Capability(_) => "capability_refused",
            PluginError::Tier(_) => "tier_refused",
            PluginError::Lifecycle(_) => "lifecycle_refused",
            PluginError::Bus(_) => "bus_refused",
            PluginError::Runtime(_) => "runtime_refused",
            PluginError::Blacklist(_) => "blacklisted",
            PluginError::Io(_) => "io_error",
            PluginError::Json(_) => "json_error",
        }
    }

    /// Whether a caller may retry the same operation unchanged.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, PluginError::Io(_))
    }
}

/// The kernel's result alias.
pub type Result<T> = std::result::Result<T, PluginError>;

/// Why a plugin was not loaded, as a value rather than a string.
///
/// Produced by the load pipeline so the REST surface, the CLI and the tests all
/// agree on the same vocabulary. `Refused` is not an error path that "should not
/// happen": refusing is the ordinary outcome for a plugin that asks for a boundary
/// this build cannot enforce or a capability its tier may not hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadRefusal {
    /// The name is not classifiable.
    NameInvalid,
    /// The manifest failed validation.
    ManifestInvalid,
    /// The signature or digest did not verify.
    SignatureInvalid,
    /// The publisher key is not trusted for this tier.
    UntrustedPublisher,
    /// A required counter-signature is missing or invalid.
    CounterSignatureMissing,
    /// The module digest does not match the one the manifest signed.
    ModuleDigestMismatch,
    /// The plugin is on the blacklist.
    Blacklisted,
    /// The plugin asks for a capability its tier may not hold.
    CapabilityNotPermitted,
    /// A capability needs approval that has not been given.
    CapabilityNotApproved,
    /// The plugin asks for an isolation level no available runtime enforces.
    IsolationNotEnforceable,
    /// A declared dependency is absent or at an incompatible version.
    DependencyUnsatisfied,
    /// The ABI major version has no adapter in this host.
    AbiIncompatible,
}

impl LoadRefusal {
    /// A stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            LoadRefusal::NameInvalid => "name_invalid",
            LoadRefusal::ManifestInvalid => "manifest_invalid",
            LoadRefusal::SignatureInvalid => "signature_invalid",
            LoadRefusal::UntrustedPublisher => "untrusted_publisher",
            LoadRefusal::CounterSignatureMissing => "counter_signature_missing",
            LoadRefusal::ModuleDigestMismatch => "module_digest_mismatch",
            LoadRefusal::Blacklisted => "blacklisted",
            LoadRefusal::CapabilityNotPermitted => "capability_not_permitted",
            LoadRefusal::CapabilityNotApproved => "capability_not_approved",
            LoadRefusal::IsolationNotEnforceable => "isolation_not_enforceable",
            LoadRefusal::DependencyUnsatisfied => "dependency_unsatisfied",
            LoadRefusal::AbiIncompatible => "abi_incompatible",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_has_a_distinct_machine_code() {
        let errors = [
            PluginError::Name("x".into()),
            PluginError::Manifest("x".into()),
            PluginError::Signature("x".into()),
            PluginError::Capability("x".into()),
            PluginError::Tier("x".into()),
            PluginError::Lifecycle("x".into()),
            PluginError::Bus("x".into()),
            PluginError::Runtime("x".into()),
            PluginError::Blacklist("x".into()),
        ];
        let mut codes: Vec<&str> = errors.iter().map(PluginError::code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before, "two errors share a code: {codes:?}");
    }

    #[test]
    fn every_refusal_has_a_distinct_machine_code() {
        let refusals = [
            LoadRefusal::NameInvalid,
            LoadRefusal::ManifestInvalid,
            LoadRefusal::SignatureInvalid,
            LoadRefusal::UntrustedPublisher,
            LoadRefusal::CounterSignatureMissing,
            LoadRefusal::ModuleDigestMismatch,
            LoadRefusal::Blacklisted,
            LoadRefusal::CapabilityNotPermitted,
            LoadRefusal::CapabilityNotApproved,
            LoadRefusal::IsolationNotEnforceable,
            LoadRefusal::DependencyUnsatisfied,
            LoadRefusal::AbiIncompatible,
        ];
        let mut codes: Vec<&str> = refusals.iter().map(LoadRefusal::code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before, "two refusals share a code: {codes:?}");
    }

    #[test]
    fn only_io_is_retryable() {
        // A refusal is a decision, not a transient fault: retrying it unchanged must
        // not be advertised as sensible.
        assert!(PluginError::Io(std::io::Error::other("x")).is_retryable());
        for e in [
            PluginError::Manifest("x".into()),
            PluginError::Bus("x".into()),
            PluginError::Signature("x".into()),
        ] {
            assert!(!e.is_retryable(), "{e} must not be retryable");
        }
    }
}
