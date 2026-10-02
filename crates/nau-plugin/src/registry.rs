//! The plugin registry: who is registered, at what version, depending on what.
//!
//! The registry holds **verified** manifests only. A manifest enters through
//! [`crate::manifest::Manifest::verify`], so nothing here has to re-check a
//! signature — and nothing here can be reached by a caller holding an unverified
//! manifest, because [`Registry::insert`] takes a
//! [`crate::manifest::VerifiedManifest`] rather than a `Manifest`. That is the
//! "make it structurally impossible" rule the V1.2.3 work kept applying: a check a
//! future caller can forget is not a check.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::{LoadRefusal, PluginError, Result};
use crate::lifecycle::{Lifecycle, PluginState};
use crate::manifest::VerifiedManifest;
use crate::tier::{PluginId, Tier};

/// Default cap on registered plugins.
pub const DEFAULT_CAPACITY: usize = 256;

/// A declared dependency on another plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    /// The dependency's plugin name.
    pub name: String,
    /// The minimum version, `major.minor.patch`.
    pub min_version: String,
}

impl Dependency {
    /// Whether a registered version satisfies this dependency.
    ///
    /// Compatibility is *same major, at least the requested minor.patch* — the rule
    /// the crate documents for plugin versions generally. It is deliberately not a
    /// range syntax: a range language is a second thing to get wrong, and the
    /// compatibility question here is only ever "may this plugin link against that
    /// one".
    #[must_use]
    pub fn satisfied_by(&self, available: &str) -> bool {
        match (parse_semver(&self.min_version), parse_semver(available)) {
            (
                Some((want_major, want_minor, want_patch)),
                Some((has_major, has_minor, has_patch)),
            ) => has_major == want_major && (has_minor, has_patch) >= (want_minor, want_patch),
            _ => false,
        }
    }
}

/// One registered plugin.
#[derive(Debug, Clone)]
pub struct PluginEntry {
    /// The verified manifest.
    pub verified: VerifiedManifest,
    /// Its lifecycle, with history.
    pub lifecycle: Lifecycle,
    /// What it declared it needs.
    pub dependencies: Vec<Dependency>,
}

impl PluginEntry {
    /// The plugin's name.
    #[must_use]
    pub fn id(&self) -> &PluginId {
        &self.verified.id
    }

    /// The plugin's tier.
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.verified.tier
    }

    /// The plugin's own version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.verified.manifest.plugin.version
    }

    /// Its current lifecycle state.
    #[must_use]
    pub fn state(&self) -> PluginState {
        self.lifecycle.state()
    }
}

/// The registry.
#[derive(Debug)]
pub struct Registry {
    entries: BTreeMap<String, PluginEntry>,
    capacity: usize,
}

impl Registry {
    /// A registry with the default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// A registry with an explicit capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            // A zero capacity would make every insert fail, which reads as a bug
            // rather than a policy; clamp to one and let the refusal be about size.
            capacity: capacity.max(1),
        }
    }

    /// How many plugins are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Look one up.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PluginEntry> {
        self.entries.get(name)
    }

    /// Look one up mutably, for lifecycle transitions.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut PluginEntry> {
        self.entries.get_mut(name)
    }

    /// Register a verified plugin.
    ///
    /// Replacing an existing entry is refused: an upgrade is a distinct operation
    /// that has to move the lifecycle and (in V3.0.0) swap the instance, and doing
    /// it by silently overwriting a map entry is how a running plugin's state
    /// disappears. Removing first is explicit.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] naming the reason: capacity reached, name already
    /// registered, or a declared dependency that is absent or unsatisfied.
    pub fn insert(
        &mut self,
        verified: VerifiedManifest,
        dependencies: Vec<Dependency>,
    ) -> Result<()> {
        let name = verified.id.as_str().to_string();
        if self.entries.contains_key(&name) {
            return Err(PluginError::Manifest(format!(
                "`{name}` is already registered at version {}; remove it before registering \
                 another version, so a running instance cannot be overwritten in place",
                self.entries[&name].version()
            )));
        }
        if self.entries.len() >= self.capacity {
            return Err(PluginError::Manifest(format!(
                "the registry is at capacity ({}); refusing to register `{name}`",
                self.capacity
            )));
        }
        for dep in &dependencies {
            let present = self.entries.get(&dep.name).ok_or_else(|| {
                PluginError::Manifest(format!(
                    "`{name}` depends on `{}` {}, which is not registered",
                    dep.name, dep.min_version
                ))
            })?;
            if !dep.satisfied_by(present.version()) {
                return Err(PluginError::Manifest(format!(
                    "`{name}` needs `{}` >= {}, but {} is registered",
                    dep.name,
                    dep.min_version,
                    present.version()
                )));
            }
        }
        self.entries.insert(
            name,
            PluginEntry {
                verified,
                lifecycle: Lifecycle::new(),
                dependencies,
            },
        );
        Ok(())
    }

    /// Remove a plugin, refusing while anything still depends on it.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] naming the dependents, or [`PluginError::Lifecycle`]
    /// when the plugin is not in a state where removal is meaningful.
    pub fn remove(&mut self, name: &str) -> Result<PluginEntry> {
        let dependents: Vec<String> = self
            .entries
            .values()
            .filter(|e| e.dependencies.iter().any(|d| d.name == name))
            .map(|e| e.id().as_str().to_string())
            .collect();
        if !dependents.is_empty() {
            return Err(PluginError::Manifest(format!(
                "`{name}` still has dependents: {}",
                dependents.join(", ")
            )));
        }
        self.entries
            .remove(name)
            .ok_or_else(|| PluginError::Manifest(format!("`{name}` is not registered")))
    }

    /// Dependency order, dependencies before dependents.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] with [`LoadRefusal::DependencyUnsatisfied`] when a
    /// cycle exists. A cycle is refused rather than broken arbitrarily: the load
    /// order would otherwise depend on map iteration, which is a bug that only shows
    /// up on some machines.
    pub fn load_order(&self) -> Result<Vec<String>> {
        let mut ordered: Vec<String> = Vec::with_capacity(self.entries.len());
        let mut done: BTreeSet<String> = BTreeSet::new();

        // Repeated passes; each one settles at least one more plugin or the graph has
        // a cycle. Quadratic in the worst case and bounded by the registry capacity,
        // which is 256 by default — the clarity is worth more than the asymptotics.
        while ordered.len() < self.entries.len() {
            let mut progressed = false;
            for (name, entry) in &self.entries {
                if done.contains(name) {
                    continue;
                }
                if entry.dependencies.iter().all(|d| done.contains(&d.name)) {
                    ordered.push(name.clone());
                    done.insert(name.clone());
                    progressed = true;
                }
            }
            if !progressed {
                let stuck: Vec<&str> = self
                    .entries
                    .keys()
                    .filter(|n| !done.contains(*n))
                    .map(String::as_str)
                    .collect();
                return Err(PluginError::Manifest(format!(
                    "{}: these plugins depend on each other in a cycle, so no load order exists: {}",
                    LoadRefusal::DependencyUnsatisfied.code(),
                    stuck.join(", ")
                )));
            }
        }
        Ok(ordered)
    }

    /// Names of every registered plugin, in name order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Record a policy violation against `name`, quarantining it on the third.
    ///
    /// # Why this exists
    ///
    /// The lifecycle has escalated "three violations → quarantined" since the first
    /// revision, and the bus has refused messages that exceed a plugin's authority
    /// since the first revision — but nothing joined the two, because
    /// [`crate::bus::Bus::send`] holds a shared registry and cannot move a lifecycle.
    /// The rule was therefore stated in the architecture document and enforced by
    /// nothing, which is the defect this project exists to refuse. This is the door
    /// that joins them, and [`crate::bus::Bus::send_checked`] is its production caller.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when the plugin is not registered: an unregistered
    /// plugin has no lifecycle to record against. A caller that sees this should keep
    /// the original refusal — the refusal stands either way, and the escalation is the
    /// secondary effect.
    pub fn record_violation(&mut self, name: &str, what: &str, at: u64) -> Result<PluginState> {
        let entry = self.entries.get_mut(name).ok_or_else(|| {
            PluginError::Manifest(format!(
                "`{name}` is not registered, so there is no lifecycle to record a violation against"
            ))
        })?;
        entry.lifecycle.violation(what, at)
    }

    /// How many plugins are in each state, for reporting.
    #[must_use]
    pub fn state_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for entry in self.entries.values() {
            *counts.entry(entry.state().label()).or_insert(0) += 1;
        }
        counts
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse `major.minor.patch`.
fn parse_semver(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_is_same_major_and_at_least_the_requested_minor() {
        let dep = Dependency {
            name: "com.twinsearth.sys.identity".into(),
            min_version: "2.1.0".into(),
        };
        assert!(dep.satisfied_by("2.1.0"));
        // A newer minor within the same major satisfies it. The sample must merely not
        // *be* the release version, or this test restates it and breaks on the next bump.
        assert!(dep.satisfied_by("2.7.3"));
        assert!(dep.satisfied_by("2.1.5"));
        // A different major is not compatible, even if numerically larger.
        assert!(!dep.satisfied_by("3.0.0"));
        // Older is not compatible.
        assert!(!dep.satisfied_by("2.0.9"));
        // Malformed versions satisfy nothing, rather than comparing as zero.
        assert!(!dep.satisfied_by("2.1"));
        assert!(!dep.satisfied_by("two.one.zero"));
    }

    #[test]
    fn a_fresh_registry_is_empty_and_bounded() {
        let registry = Registry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.capacity(), DEFAULT_CAPACITY);
        assert_eq!(
            Registry::with_capacity(0).capacity(),
            1,
            "zero is clamped to one"
        );
        assert!(registry.names().is_empty());
        assert!(registry.state_counts().is_empty());
    }

    #[test]
    fn a_malformed_version_is_not_treated_as_zero() {
        assert!(parse_semver("").is_none());
        assert!(parse_semver("1.2").is_none());
        assert!(parse_semver("1.2.3.4").is_none());
        assert!(parse_semver("1.2.x").is_none());
        assert_eq!(parse_semver("1.2.3"), Some((1, 2, 3)));
    }
}
