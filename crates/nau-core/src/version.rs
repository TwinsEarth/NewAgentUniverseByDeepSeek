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

/// The exact upstream release this rewrite was **ported from**.
///
/// # This is not the only upstream version this build names, and the two are not rivals
///
/// Two project-wide constants name an upstream release, and until now nothing said how they
/// relate — which made `nau --version` read as a single, quietly stale claim:
///
/// | Constant | What it answers |
/// |---|---|
/// | this one | the release the code was **ported from** (the fork's base) |
/// | [`nau_plugin::UPSTREAM_AUDITED`](https://docs.rs/nau-plugin) | the release whose **plugin architecture** this build answers |
///
/// They differ because they are different questions, and the build legitimately carries
/// per-module fix attributions to *several* releases (`// upstream v2.8.2 fix:` and
/// `// upstream v2.5.6 fix:` both appear). A single "based on" line could not say that, so the
/// CLI prints both and names what each means.
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
