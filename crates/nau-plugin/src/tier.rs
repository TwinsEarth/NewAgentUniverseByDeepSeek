//! Trust tiers and the identification rule that derives them.
//!
//! # The rule this module exists to enforce
//!
//! A plugin's tier decides its isolation, its permission ceiling and its update
//! policy. So the tier must be derivable from something that **cannot be forged
//! independently of the signature**. It is derived from the manifest `name` alone,
//! because an extra "tier" field would be one more value a forger has to change —
//! and the name is inside the signed payload.
//!
//! | Tier | Prefix | Loadable |
//! |---|---|---|
//! | [`Tier::System`] | `com.twinsearth.sys.` | yes, in-process only |
//! | [`Tier::Official`] | `com.twinsearth.official.` | yes |
//! | [`Tier::Certified`] | `com.twinsearth.certified.` | yes |
//! | [`Tier::ThirdParty`] | any other reverse-domain name | yes |
//! | [`Tier::Blacklisted`] | exact match in the blacklist store | **never** |
//!
//! The vendor prefix `com.twinsearth.` is **reserved**: a third party that names
//! itself `com.twinsearth.official.market` is refused rather than classified, so a
//! name collision cannot be used to climb tiers. `Blacklisted` is not a trust level
//! a name can reach — it is a verdict produced by [`crate::blacklist`] and it
//! overrides whatever the prefix said.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{PluginError, Result};

/// The vendor namespace reserved for plugins published by this project.
pub const VENDOR_PREFIX: &str = "com.twinsearth.";

/// Prefix for [`Tier::System`] plugin names.
pub const SYSTEM_PREFIX: &str = "com.twinsearth.sys.";

/// Prefix for [`Tier::Official`] plugin names.
pub const OFFICIAL_PREFIX: &str = "com.twinsearth.official.";

/// Prefix for [`Tier::Certified`] plugin names.
pub const CERTIFIED_PREFIX: &str = "com.twinsearth.certified.";

/// Longest accepted plugin name, in bytes.
pub const MAX_NAME_BYTES: usize = 128;

/// Fewest dot-separated labels a third-party name must have.
///
/// Two is the minimum that can express a reverse-domain prefix (`example.com`
/// written as `com.example`), which is what makes impersonation visible to a reader.
pub const MIN_THIRD_PARTY_LABELS: usize = 2;

/// The five-level classification.
///
/// Four of these are trust tiers a plugin can be *loaded* at. The fifth,
/// [`Tier::Blacklisted`], is a verdict: [`Tier::from_name`] never returns it, and
/// [`Tier::is_loadable`] is false for it, so a blacklist hit cannot be smuggled in
/// through a manifest field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Ring 0. Ships with the kernel, runs in-process, cannot be hot-plugged.
    System,
    /// Ring 1. First-party, runs in an isolated process.
    Official,
    /// Ring 2. Third-party code that passed certification, double-signed.
    Certified,
    /// Ring 3. Uncertified community code, smallest permission set, strictest quotas.
    ThirdParty,
    /// Ring -1. A verdict, not a level: quarantined, never loadable.
    Blacklisted,
}

impl Tier {
    /// Every tier, in descending order of trust.
    ///
    /// Exhaustive on purpose: adding a variant to [`Tier`] breaks this array at
    /// compile time, so the tier matrix cannot silently gain a row that no test
    /// covers.
    pub const ALL: [Tier; 5] = [
        Tier::System,
        Tier::Official,
        Tier::Certified,
        Tier::ThirdParty,
        Tier::Blacklisted,
    ];

    /// The loadable tiers, which are the ones a manifest name can select.
    pub const LOADABLE: [Tier; 4] = [
        Tier::System,
        Tier::Official,
        Tier::Certified,
        Tier::ThirdParty,
    ];

    /// Derive the tier from a plugin name.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] when the name is empty, too long, reserved but not
    /// matched by a vendor prefix, or not a well-formed reverse-domain name.
    pub fn from_name(name: &str) -> Result<Tier> {
        validate_name_shape(name)?;
        if let Some(rest) = name.strip_prefix(SYSTEM_PREFIX) {
            require_label(rest, name)?;
            return Ok(Tier::System);
        }
        if let Some(rest) = name.strip_prefix(OFFICIAL_PREFIX) {
            require_label(rest, name)?;
            return Ok(Tier::Official);
        }
        if let Some(rest) = name.strip_prefix(CERTIFIED_PREFIX) {
            require_label(rest, name)?;
            return Ok(Tier::Certified);
        }
        // The vendor namespace is reserved. Without this branch a plugin named
        // `com.twinsearth.something` would fall through to ThirdParty and be
        // *loadable* while squatting on the vendor's namespace.
        if name.starts_with(VENDOR_PREFIX) {
            return Err(PluginError::Name(format!(
                "`{name}` is inside the reserved namespace `{VENDOR_PREFIX}` but matches no known \
                 tier prefix ({SYSTEM_PREFIX}*, {OFFICIAL_PREFIX}*, {CERTIFIED_PREFIX}*)"
            )));
        }
        if name.split('.').count() < MIN_THIRD_PARTY_LABELS {
            return Err(PluginError::Name(format!(
                "`{name}` is not a reverse-domain name: it needs at least \
                 {MIN_THIRD_PARTY_LABELS} dot-separated labels"
            )));
        }
        Ok(Tier::ThirdParty)
    }

    /// The tier's wire label, as used in manifests and logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Tier::System => "sys",
            Tier::Official => "official",
            Tier::Certified => "certified",
            Tier::ThirdParty => "3rd",
            Tier::Blacklisted => "blk",
        }
    }

    /// Parse a tier from a label.
    ///
    /// # Why the kernel owns this
    ///
    /// Every plugin that accepts a tier name out of a payload needs this mapping, and
    /// the first one to need it wrote its own. Two mappings of one vocabulary drift:
    /// one accepts `third-party`, the other does not, and a payload that works against
    /// one plugin is refused by the next for no stated reason. Accepting the short
    /// label, the serde name and the common spellings in a single place is what keeps
    /// the vocabulary single-sourced.
    ///
    /// # Errors
    ///
    /// [`PluginError::Tier`] listing the accepted spellings. An unknown tier is refused
    /// rather than defaulted, because a default would silently place a plugin at a tier
    /// nobody chose.
    pub fn from_label(label: &str) -> Result<Tier> {
        match label.trim().to_ascii_lowercase().as_str() {
            "sys" | "system" => Ok(Tier::System),
            "official" => Ok(Tier::Official),
            "certified" => Ok(Tier::Certified),
            "3rd" | "third_party" | "third-party" | "thirdparty" => Ok(Tier::ThirdParty),
            "blk" | "blacklisted" | "blacklist" => Ok(Tier::Blacklisted),
            other => Err(PluginError::Tier(format!(
                "`{other}` is not a tier; the accepted spellings are sys/system, official, \
                 certified, 3rd/third_party/third-party, blk/blacklisted"
            ))),
        }
    }

    /// Whether a plugin of this tier may be loaded at all.
    #[must_use]
    pub fn is_loadable(self) -> bool {
        !matches!(self, Tier::Blacklisted)
    }

    /// Whether plugins of this tier run inside the host's own address space.
    #[must_use]
    pub fn runs_in_process(self) -> bool {
        matches!(self, Tier::System)
    }

    /// Whether this tier may be hot-plugged once V3.0.0 lands.
    ///
    /// System plugins deliberately cannot: they are part of the kernel and are
    /// compiled into it, which is also why they are the only tier allowed in-process.
    #[must_use]
    pub fn is_hot_pluggable(self) -> bool {
        matches!(self, Tier::Official | Tier::Certified | Tier::ThirdParty)
    }

    /// Whether a publisher signature alone is enough, or a vendor counter-signature
    /// is also required.
    #[must_use]
    pub fn requires_counter_signature(self) -> bool {
        match self {
            Tier::System | Tier::Official | Tier::Certified => true,
            // A third-party plugin has no counter-signature, which is exactly why it
            // can never be granted a capability above the third-party ceiling.
            Tier::ThirdParty | Tier::Blacklisted => false,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A validated plugin name.
///
/// The only way to obtain one is [`PluginId::parse`], which applies
/// [`Tier::from_name`]'s shape rules, so a `PluginId` is always a name that the
/// tier rule was able to classify. This is the same "one validator, no second way
/// in" pattern the sandbox uses for path components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PluginId(String);

impl PluginId {
    /// Parse and validate a plugin name.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] when [`Tier::from_name`] rejects the name.
    pub fn parse(name: &str) -> Result<Self> {
        Tier::from_name(name)?;
        Ok(Self(name.to_string()))
    }

    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// This plugin's tier, recomputed from the name.
    ///
    /// # Errors
    ///
    /// Cannot fail for a value obtained from [`PluginId::parse`]; it returns a
    /// `Result` because the name is part of a signed payload that a caller may have
    /// deserialised from somewhere else — `serde` does not run the validator.
    pub fn tier(&self) -> Result<Tier> {
        Tier::from_name(&self.0)
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Check the parts of a name that are independent of the tier prefix.
fn validate_name_shape(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(PluginError::Name("a plugin name must not be empty".into()));
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(PluginError::Name(format!(
            "plugin name is {} bytes; the maximum is {MAX_NAME_BYTES}",
            name.len()
        )));
    }
    if name != name.to_ascii_lowercase() {
        return Err(PluginError::Name(format!(
            "`{name}` must be lower-case: an upper-case variant of a name is a second name"
        )));
    }
    if name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        return Err(PluginError::Name(format!(
            "`{name}` has an empty or leading/trailing label"
        )));
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(PluginError::Name(format!("`{name}` has an empty label")));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(PluginError::Name(format!(
                "`{name}` has a label `{label}` that starts or ends with `-`"
            )));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(PluginError::Name(format!(
                "`{name}` has a label `{label}` containing a character outside [a-z0-9-]"
            )));
        }
    }
    Ok(())
}

/// After a tier prefix, the remainder must itself be a usable name.
fn require_label(rest: &str, whole: &str) -> Result<()> {
    if rest.is_empty() {
        return Err(PluginError::Name(format!(
            "`{whole}` has a tier prefix but no plugin name after it"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_vendor_prefix_selects_its_tier() {
        assert_eq!(
            Tier::from_name("com.twinsearth.sys.identity").expect("system"),
            Tier::System
        );
        assert_eq!(
            Tier::from_name("com.twinsearth.official.market").expect("official"),
            Tier::Official
        );
        assert_eq!(
            Tier::from_name("com.twinsearth.certified.analytics").expect("certified"),
            Tier::Certified
        );
        assert_eq!(
            Tier::from_name("io.example.analytics").expect("third party"),
            Tier::ThirdParty
        );
    }

    #[test]
    fn a_third_party_cannot_squat_on_the_vendor_namespace() {
        // The failure mode this prevents: `com.twinsearth.not-a-known-tier` falling
        // through to ThirdParty and being loadable *inside the vendor's namespace*.
        let err = Tier::from_name("com.twinsearth.something").expect_err("must be refused");
        assert!(matches!(err, PluginError::Name(_)), "{err}");
        assert!(err.to_string().contains("reserved namespace"), "{err}");
    }

    #[test]
    fn a_tier_prefix_with_nothing_after_it_is_refused() {
        assert!(Tier::from_name("com.twinsearth.sys.").is_err());
        assert!(Tier::from_name("com.twinsearth.official.").is_err());
    }

    #[test]
    fn one_label_is_not_a_reverse_domain_name() {
        assert!(Tier::from_name("analytics").is_err());
        assert!(Tier::from_name("example").is_err());
        assert!(Tier::from_name("io.example").is_ok());
    }

    #[test]
    fn hostile_name_shapes_are_refused() {
        for bad in [
            "",
            ".",
            "..",
            ".io.example",
            "io.example.",
            "io..example",
            "IO.EXAMPLE",
            "io.Example",
            "-io.example",
            "io-.example",
            "io.exa mple",
            "io.exämple",
            "io.exa/mple",
        ] {
            assert!(
                Tier::from_name(bad).is_err(),
                "`{bad}` must be refused as a plugin name"
            );
        }
    }

    #[test]
    fn a_name_longer_than_the_cap_is_refused_before_it_is_stored() {
        let long = format!("io.{}", "a".repeat(MAX_NAME_BYTES));
        assert!(Tier::from_name(&long).is_err());
    }

    #[test]
    fn the_tier_matrix_is_total_over_the_five_levels() {
        // Every tier appears exactly once in ALL, and LOADABLE excludes only the
        // verdict. If a variant is added, ALL stops compiling.
        assert_eq!(Tier::ALL.len(), 5);
        for tier in Tier::ALL {
            assert_eq!(
                Tier::ALL.iter().filter(|t| **t == tier).count(),
                1,
                "{tier} appears more than once"
            );
        }
        assert_eq!(Tier::LOADABLE.len(), 4);
        assert!(!Tier::Blacklisted.is_loadable());
        for tier in Tier::LOADABLE {
            assert!(tier.is_loadable(), "{tier} must be loadable");
        }
    }

    #[test]
    fn only_the_system_tier_runs_in_process() {
        assert!(Tier::System.runs_in_process());
        for tier in [Tier::Official, Tier::Certified, Tier::ThirdParty] {
            assert!(
                !tier.runs_in_process(),
                "{tier} must run in an isolated process, not in the host"
            );
        }
    }

    #[test]
    fn hot_pluggability_excludes_the_kernel_and_the_quarantine() {
        assert!(
            !Tier::System.is_hot_pluggable(),
            "the kernel is not pluggable"
        );
        assert!(!Tier::Blacklisted.is_hot_pluggable());
        for tier in [Tier::Official, Tier::Certified, Tier::ThirdParty] {
            assert!(
                tier.is_hot_pluggable(),
                "{tier} should be hot-pluggable in V3.0.0"
            );
        }
    }

    #[test]
    fn the_counter_signature_rule_matches_the_permission_ceiling() {
        // The two must agree: a tier that cannot obtain a counter-signature must not
        // be able to reach the capabilities that require one. See `capability.rs`.
        assert!(Tier::Official.requires_counter_signature());
        assert!(Tier::Certified.requires_counter_signature());
        assert!(!Tier::ThirdParty.requires_counter_signature());
    }

    #[test]
    fn a_plugin_id_round_trips_and_reports_its_tier() {
        let id = PluginId::parse("com.twinsearth.official.market").expect("valid");
        assert_eq!(id.as_str(), "com.twinsearth.official.market");
        assert_eq!(id.tier().expect("tier"), Tier::Official);
        assert_eq!(id.to_string(), "com.twinsearth.official.market");
    }

    #[test]
    fn deserialising_a_plugin_id_does_not_skip_the_validator() {
        // `serde` can build a `PluginId` from any string, which is why `tier()`
        // re-validates instead of trusting the name it was given.
        let smuggled: PluginId = serde_json::from_str("\"NOT A NAME\"").expect("serde accepts it");
        assert!(smuggled.tier().is_err());
    }

    #[test]
    fn every_tier_round_trips_through_its_label() {
        // The kernel is now the only place this mapping lives, so it has to be total.
        for tier in Tier::ALL {
            assert_eq!(
                Tier::from_label(tier.label()).expect("its own label parses"),
                tier,
                "{tier} did not round-trip"
            );
        }
        assert_eq!(
            Tier::from_label("SYSTEM").expect("case-insensitive"),
            Tier::System
        );
        assert_eq!(
            Tier::from_label("  third-party  ").expect("trimmed"),
            Tier::ThirdParty
        );
        assert_eq!(
            Tier::from_label("blacklist").expect("spelling"),
            Tier::Blacklisted
        );
    }

    #[test]
    fn an_unknown_tier_label_is_refused_with_the_accepted_spellings() {
        let err = Tier::from_label("superuser").expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("superuser"), "{text}");
        assert!(
            text.contains("official"),
            "the refusal must list what is accepted: {text}"
        );
    }

    #[test]
    fn no_tier_label_parses_to_a_different_tier() {
        // A label that resolves twice, to different tiers, would make a payload's
        // meaning depend on which plugin read it.
        for tier in Tier::ALL {
            let label = tier.label();
            assert_eq!(Tier::from_label(label).expect("parses"), tier);
        }
        for alias in ["sys", "system", "official", "certified", "3rd", "blk"] {
            let parsed = Tier::from_label(alias).expect("an accepted spelling");
            let again = Tier::from_label(parsed.label()).expect("its canonical label");
            assert_eq!(parsed, again, "`{alias}` is not stable under round trip");
        }
    }
}
