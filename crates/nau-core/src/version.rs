//! Compile-time and protocol constants.
//!
//! The project version has exactly one source of truth per language, and
//! `crates/nau-core/tests/version_consistency.rs` asserts that they agree:
//!
//! | Artifact | Declares the version |
//! |---|---|
//! | `VERSION` (repo root) | `1.0.1` — read by scripts, CI and both SDKs |
//! | `[workspace.package] version` | `1.0.1` — becomes [`VERSION`] below |
//!
//! Upstream v2.5.6 has no such check and its own release checklist
//! (`docs/version-checklist.md`) lists 14 places a human must edit by hand; the
//! audit found files still advertising older versions. Machine-checked
//! consistency replaces the manual checklist.

/// Cargo package version of the workspace, e.g. `"1.0.1"`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Human-facing project name.
pub const PROJECT: &str = "NewAgentUniverseByDeepSeek";

/// Wire-protocol / domain revision. Bump when the canonical payload rules or
/// any signed structure changes in a way that breaks byte compatibility.
pub const PROTOCOL_VERSION: &str = "nau/1";

/// The upstream open-source project this rewrite derives its domain model from,
/// kept for attribution (MIT).
pub const UPSTREAM_PROJECT: &str = "TwinsEarth/agent-universe";

/// The exact upstream release this rewrite was audited against.
pub const UPSTREAM_VERSION: &str = "2.5.6";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_pinned() {
        assert_eq!(PROTOCOL_VERSION, "nau/1");
    }

    #[test]
    fn attribution_is_present() {
        assert_eq!(UPSTREAM_PROJECT, "TwinsEarth/agent-universe");
        assert_eq!(UPSTREAM_VERSION, "2.5.6");
    }
}
