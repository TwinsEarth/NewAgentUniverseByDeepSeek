//! Machine-checked version consistency.
//!
//! Upstream v2.5.6 keeps a hand-maintained registry of version declaration
//! points (`docs/version-checklist.md`) plus a `sed` script keyed to it, and the
//! audit found the registry had already drifted: six files still declared
//! `2.3.6`/`v2.3.4` (the Python SDK's `__init__.py`, `mcp_client.py`, `aca.py`,
//! both Tauri `index.html` shells and `desktop/README.md`) because they were
//! never registered. Its own rule — "new version constant ⇒ add a row" — was the
//! thing that was not followed.
//!
//! A checklist that a human must maintain cannot prevent drift. This test
//! replaces it with an assertion: the workspace version and the `VERSION` file
//! must agree, and SDK/CI declaration points are covered by the SDKs' own test
//! suites, which read the same `VERSION` file rather than restating the number.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

#[test]
fn version_file_and_cargo_package_version_agree() {
    let version_file = repo_root().join("VERSION");
    let text = std::fs::read_to_string(&version_file)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", version_file.display()));
    let from_file = text.trim();

    assert!(
        !from_file.is_empty(),
        "VERSION must not be empty (it is the single source of truth)"
    );
    assert_eq!(
        from_file,
        env!("CARGO_PKG_VERSION"),
        "VERSION says `{from_file}` but [workspace.package] version is `{}`; \
         these are the two machine-readable version sources and they must agree",
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(from_file, nau_core::VERSION);
}

#[test]
fn version_is_well_formed_semver() {
    let v = nau_core::VERSION;
    let parts: Vec<&str> = v.split('.').collect();
    assert_eq!(parts.len(), 3, "VERSION `{v}` must be MAJOR.MINOR.PATCH");
    for part in &parts {
        assert!(
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
            "VERSION `{v}` has a non-numeric component `{part}`"
        );
    }
    // This release is NewAgentUniverseByDeepSeek V1.0.1.
    assert_eq!(v, "3.8.7", "unexpected release version");
}

#[test]
fn the_workspace_members_declare_a_shared_version() {
    // Every crate must take its version from the workspace, so there is exactly
    // one place to bump. A crate with a literal version is a future drift bug.
    let crates_dir = repo_root().join("crates");
    let entries = std::fs::read_dir(&crates_dir).expect("crates/ must exist");
    let mut checked = 0;
    for entry in entries {
        let path = entry.expect("readable dir entry").path();
        let manifest = path.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&manifest).expect("crate manifest readable");
        // Only the [package] section matters; [dependencies] legitimately pin
        // third-party versions.
        let package_section = text.split("[dependencies]").next().unwrap_or(&text);
        if package_section.contains("version = \"") && package_section.contains("[package]") {
            panic!(
                "{} declares a literal version; use `version.workspace = true`",
                manifest.display()
            );
        }
        assert!(
            package_section.contains("version.workspace = true"),
            "{} must declare `version.workspace = true`",
            manifest.display()
        );
        checked += 1;
    }
    assert!(checked > 0, "no crate manifests were checked");
}

#[test]
fn sdk_packages_read_the_version_instead_of_restating_it() {
    // The rewrite's answer to upstream's drift: the SDKs and CI read VERSION
    // rather than duplicating the number, so there is nothing to keep in sync.
    // This test asserts the loader exists in each SDK.
    let root = repo_root();
    let py = root
        .join("sdks")
        .join("python")
        .join("nau_sdk")
        .join("version.py");
    let js = root.join("sdks").join("js").join("lib").join("version.js");
    for path in [&py, &js] {
        assert!(
            path.is_file(),
            "{} must exist so the SDK does not restate the version",
            path.display()
        );
        let text = std::fs::read_to_string(path).expect("readable");
        assert!(
            text.contains("VERSION"),
            "{} must load the shared VERSION file",
            path.display()
        );
    }
}
