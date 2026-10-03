//! `nau plugin` — end to end, against the real binary.
//!
//! # Why this spawns a process instead of calling the functions
//!
//! The unit tests in `src/plugin_cli.rs` cover the flag parsing. What they cannot
//! cover is the thing an operator actually experiences: a plugin directory on disk, a
//! real Ed25519 signature, the pipeline's verdict, the exit code and the words on the
//! terminal. So this test builds a signed plugin directory, runs
//! `env!("CARGO_BIN_EXE_nau")` against it, and reads what came out.
//!
//! # The two verdicts that both have to work
//!
//! `ACCEPTED` is the easy half. `REFUSED` is the half that matters: a refusal has to
//! name the check that refused it and print the stages that passed before it, or an
//! operator cannot tell a policy decision from a broken tool. Both are asserted, and
//! the tampered fixture asserts the *refusal code*, not merely a non-zero exit.

use std::path::{Path, PathBuf};
use std::process::Command;

use ed25519_dalek::{Signer, SigningKey};
use nau_plugin::manifest::{CapabilitySection, Limits, Manifest, PluginSection, SignatureSection};
use sha2::{Digest, Sha256};

/// The vendor key that counter-signs official plugins in these fixtures.
fn vendor() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

/// The publisher key.
fn publisher() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn hex_key(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

const MODULE: &[u8] = b"#!/bin/sh\nexit 0\n";

/// The ABI a current plugin declares.
///
/// Read from the kernel rather than written down: a fixture pinned to a literal would
/// have to be edited on every ABI bump, and the one time it was not is exactly how these
/// tests went red when the host moved to 3.2.
fn host_abi() -> String {
    format!("{}.{}", nau_plugin::ABI_MAJOR, nau_plugin::ABI_MINOR)
}

fn limits() -> Limits {
    Limits {
        memory_bytes: 128 * 1024 * 1024,
        cpu_ms: 10_000,
        disk_bytes: 16 * 1024 * 1024,
        max_processes: 4,
        max_output_bytes: 64 * 1024,
    }
}

/// The boundaries the process runtime cannot enforce on this platform. A plugin that
/// does not waive them is refused, which is itself asserted below.
///
/// Derived from the runtime's own declaration rather than listed literally. This was the
/// third copy of the same five keys; when A-02 added four boundaries, all three copies
/// went stale together and seven end-to-end tests here failed while the CLI was correct.
/// Asking the runtime what it lacks cannot go stale.
fn waivers() -> std::collections::BTreeMap<String, String> {
    use nau_plugin::runtime::PluginRuntime;
    nau_plugin::runtime::ProcessRuntime::new()
        .declares()
        .unenforced()
        .into_iter()
        .map(|(boundary, _why)| {
            (
                boundary.waiver_key().to_string(),
                "test fixture: accepted here, this boundary is not under test".to_string(),
            )
        })
        .collect()
}

/// Build a fully signed official manifest.
fn signed_manifest(name: &str, caps: &[&str], waive: bool) -> Manifest {
    let publisher = publisher();
    let vendor = vendor();
    let mut m = Manifest {
        plugin: PluginSection {
            name: name.to_string(),
            // The plugin's own version, deliberately not the kernel's: a fixture tied to
            // the release version makes every routine bump rewrite it.
            version: "1.4.0".into(),
            abi: host_abi(),
            entry: "plugin.bin".into(),
            publisher: "did:nau:0011223344556677".into(),
            module_sha256: hex::encode(Sha256::digest(MODULE)),
        },
        capabilities: CapabilitySection {
            grant: caps.iter().map(|s| (*s).to_string()).collect(),
        },
        limits: limits(),
        waivers: if waive {
            waivers()
        } else {
            std::collections::BTreeMap::new()
        },
        dependencies: Vec::new(),
        signature: SignatureSection {
            publisher_key: hex_key(&publisher),
            manifest_digest: String::new(),
            sig: String::new(),
            counter_sig: None,
            counter_key: None,
        },
    };
    m.signature.manifest_digest = m.digest_hex().expect("canonical manifest should hash");
    let digest = m.signature.manifest_digest.clone();
    m.signature.sig = hex::encode(publisher.sign(digest.as_bytes()).to_bytes());
    m.signature.counter_sig = Some(hex::encode(vendor.sign(digest.as_bytes()).to_bytes()));
    m.signature.counter_key = Some(hex_key(&vendor));
    m
}

/// A directory holding `plugin.json` and the entry artefact it names.
struct PluginDir {
    path: PathBuf,
}

impl PluginDir {
    fn create(tag: &str, manifest: Option<&Manifest>) -> Self {
        let path = std::env::temp_dir().join(format!(
            "nau-plugin-cli-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        if let Some(m) = manifest {
            let json = serde_json::to_string_pretty(m).expect("manifest serialises");
            std::fs::write(path.join("plugin.json"), json).expect("manifest written");
            std::fs::write(path.join("plugin.bin"), MODULE).expect("entry written");
        }
        Self { path }
    }

    fn as_str(&self) -> &str {
        self.path.to_str().expect("temp path is utf-8")
    }
}

impl Drop for PluginDir {
    fn drop(&mut self) {
        // Best effort: a leftover temp directory must not fail the test that made it.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Run the CLI and return `(exit code, stdout, stderr)`.
fn nau(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_nau"))
        .args(args)
        .output()
        .expect("the nau binary should be runnable");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn tiers_prints_the_matrix_it_generates_and_marks_kernel_authority() {
    let (code, stdout, _) = nau(&["plugin", "tiers"]);
    assert_eq!(code, 0, "tiers should succeed");
    // Every capability is listed, because the command walks `Capability::ALL`.
    for cap in nau_plugin::Capability::ALL {
        assert!(
            stdout.contains(cap.as_str()),
            "matrix omitted {}",
            cap.as_str()
        );
    }
    // And the two claims that carry the security model are stated in the output.
    assert!(
        stdout.contains("REFUSED"),
        "the refusal cells must be visible"
    );
    assert!(
        stdout.contains("no approval path"),
        "the kernel-authority rule must be stated, not implied"
    );
}

#[test]
fn runtimes_reports_what_is_not_enforced_rather_than_omitting_it() {
    let (code, stdout, _) = nau(&["plugin", "runtimes"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("native"),
        "the native backend must be listed"
    );
    assert!(
        stdout.contains("process"),
        "the process backend must be listed"
    );
    // The honest part: the boundaries nothing enforces are printed with their reasons.
    assert!(
        stdout.contains("NOT network_deny"),
        "egress must be reported as unenforced"
    );
    assert!(
        stdout.contains("NOT disk_quota"),
        "the disk quota must be reported as unenforced"
    );
    assert!(
        stdout.contains("NOT"),
        "unenforced boundaries must be visible"
    );
    // And the typed-refusal rule, not a silent downgrade.
    assert!(
        stdout.contains("typed refusal"),
        "the refusal rule must be stated"
    );
}

#[test]
fn a_fully_signed_plugin_is_accepted_and_the_stages_are_shown() {
    let dir = PluginDir::create(
        "accepted",
        Some(&signed_manifest(
            "com.twinsearth.official.market",
            &["plugin:message:send", "plugin:storage:own"],
            true,
        )),
    );
    let vendor_key = hex_key(&vendor());
    let (code, stdout, stderr) = nau(&["plugin", "verify", dir.as_str(), "--vendor", &vendor_key]);

    assert_eq!(
        code, 0,
        "a valid plugin should verify; stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(stdout.contains("ACCEPTED"), "{stdout}");
    for stage in [
        "parse",
        "blacklist",
        "verify",
        "limits",
        "runtime",
        "lifecycle",
    ] {
        assert!(
            stdout.contains(stage),
            "stage `{stage}` missing from the trace:\n{stdout}"
        );
    }
    // The limit of this command is stated where the operator reads the result, not
    // only in the source.
    assert!(
        stdout.contains("NOT executed"),
        "the command must not imply it ran the plugin:\n{stdout}"
    );
}

#[test]
fn a_plugin_that_waived_nothing_is_refused_with_the_boundary_names() {
    // The tier is official and the signature is valid; only the waivers are missing.
    let dir = PluginDir::create(
        "no-waivers",
        Some(&signed_manifest(
            "com.twinsearth.official.market",
            &["plugin:message:send"],
            false,
        )),
    );
    let vendor_key = hex_key(&vendor());
    let (code, stdout, _) = nau(&["plugin", "verify", dir.as_str(), "--vendor", &vendor_key]);

    assert_eq!(code, 1, "an unwaived boundary must be refused");
    assert!(stdout.contains("REFUSED"), "{stdout}");
    assert!(stdout.contains("isolation_not_enforceable"), "{stdout}");
    assert!(
        stdout.contains("network_deny"),
        "the boundary must be named:\n{stdout}"
    );
    assert!(
        stdout.contains("disk_quota"),
        "every unhandled boundary must be named:\n{stdout}"
    );
}

#[test]
fn a_tampered_manifest_is_refused_at_the_digest_check() {
    let mut manifest = signed_manifest(
        "com.twinsearth.official.market",
        &["plugin:message:send"],
        true,
    );
    // Edit a signed field after signing, exactly as a forger would.
    manifest
        .capabilities
        .grant
        .push("kernel:policy:write".into());
    let dir = PluginDir::create("tampered", Some(&manifest));
    let vendor_key = hex_key(&vendor());
    let (code, stdout, _) = nau(&["plugin", "verify", dir.as_str(), "--vendor", &vendor_key]);

    assert_eq!(code, 1);
    assert!(stdout.contains("REFUSED"), "{stdout}");
    assert!(
        stdout.contains("manifest_invalid"),
        "the refusal must name the failed check:\n{stdout}"
    );
    // And the stages before it are shown, so the refusal is attributable.
    assert!(stdout.contains("parse"), "{stdout}");
}

#[test]
fn an_untrusted_host_refuses_a_third_party_plugin_by_default() {
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let module_digest = hex::encode(Sha256::digest(MODULE));
    let mut m = Manifest {
        plugin: PluginSection {
            name: "io.example.analytics".into(),
            version: "1.4.0".into(),
            abi: host_abi(),
            entry: "plugin.bin".into(),
            publisher: "did:nau:0011223344556677".into(),
            module_sha256: module_digest,
        },
        capabilities: CapabilitySection {
            grant: vec!["plugin:message:send".into()],
        },
        limits: limits(),
        waivers: waivers(),
        dependencies: Vec::new(),
        signature: SignatureSection {
            publisher_key: hex_key(&key),
            manifest_digest: String::new(),
            sig: String::new(),
            counter_sig: None,
            counter_key: None,
        },
    };
    m.signature.manifest_digest = m.digest_hex().expect("digest");
    let digest = m.signature.manifest_digest.clone();
    m.signature.sig = hex::encode(key.sign(digest.as_bytes()).to_bytes());

    let dir = PluginDir::create("untrusted", Some(&m));

    // With no key configured, the fail-closed default refuses it.
    let (code, stdout, _) = nau(&["plugin", "verify", dir.as_str()]);
    assert_eq!(
        code, 1,
        "an unconfigured host must refuse a third-party plugin"
    );
    assert!(stdout.contains("untrusted_publisher"), "{stdout}");

    // Once the operator trusts the key explicitly, it loads.
    let (code, stdout, stderr) = nau(&[
        "plugin",
        "verify",
        dir.as_str(),
        &format!("--trust={}", hex_key(&key)),
    ]);
    assert_eq!(
        code, 0,
        "a trusted third-party plugin should verify; {stderr}\n{stdout}"
    );
    assert!(stdout.contains("ACCEPTED"), "{stdout}");
}

#[test]
fn a_directory_without_a_manifest_is_a_tool_error_not_a_plugin_refusal() {
    // Exit 2 means "the tool could not do its job"; exit 1 means "the plugin was
    // refused". Collapsing the two would make a broken invocation look like a policy
    // decision, which is the confusion this distinction exists to prevent.
    let dir = PluginDir::create("empty", None);
    let (code, _, stderr) = nau(&["plugin", "verify", dir.as_str()]);
    assert_eq!(code, 2, "a missing manifest is a usage error");
    assert!(stderr.contains("cannot read"), "{stderr}");
}

#[test]
fn the_blacklist_command_refuses_to_run_without_a_trusted_key() {
    let dir = PluginDir::create("blacklist", None);
    let file = dir.path.join("blacklist.json");
    std::fs::write(&file, "[]").expect("written");
    let (code, _, stderr) = nau(&["plugin", "blacklist", file.to_str().expect("utf-8")]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("fail-closed"),
        "the refusal must explain that this is the default, not a bug:\n{stderr}"
    );
}

#[test]
fn the_usage_lists_every_subcommand_it_implements() {
    let (code, stdout, _) = nau(&["plugin"]);
    assert_eq!(code, 0);
    for sub in ["tiers", "runtimes", "verify", "run", "blacklist", "system"] {
        assert!(stdout.contains(sub), "usage omits `{sub}`:\n{stdout}");
    }
}

#[test]
fn the_system_plugins_boot_to_running_and_are_actually_called() {
    // This test exists because the first version of the boot registered the four T0
    // plugins and never called `init`, so they sat in `loaded` and every dispatch came
    // back "not running". Listing registrations would not have caught it; calling them
    // does.
    let dir = PluginDir::create("system", None);
    let (code, stdout, stderr) = nau(&["plugin", "system", "--data-dir", dir.as_str()]);
    assert_eq!(code, 0, "system boot should succeed; {stderr}\n{stdout}");

    // Every shipped plugin reaches Running -- not merely registered. Counted from the
    // declarations rather than from a literal: this assertion said "4" while four existed
    // and went red when ten more were wired, which is the test working, but the durable
    // form is the one that cannot go stale.
    let declared = nau_plugins::host::standard_declarations().len();
    assert_eq!(
        stdout.matches("state  running").count(),
        declared,
        "all {declared} shipped system plugins must reach Running:\n{stdout}"
    );
    for (name, _) in nau_plugins::host::standard_declarations() {
        assert!(
            stdout.contains(name),
            "`{name}` is missing from the boot report"
        );
    }
    assert!(
        !stdout.contains("state  loaded"),
        "a plugin left in `loaded` cannot be called:\n{stdout}"
    );

    // And a real call is answered.
    assert!(
        stdout.contains("policy.matrix") && stdout.contains("answered"),
        "the policy plugin must actually answer:\n{stdout}"
    );

    // The over-reach is refused by the token, naming the capability.
    assert!(stdout.contains("identity.overreach"), "{stdout}");
    assert!(stdout.contains("refused:"), "{stdout}");
    assert!(stdout.contains("kernel:policy:write"), "{stdout}");
    assert!(
        !stdout.contains("must never happen"),
        "a T0 plugin obtained a capability its token does not grant:\n{stdout}"
    );

    // The command must not claim to have run anything it did not.
    assert!(
        stdout.contains("No downloaded code ran"),
        "the command must state what it executed:\n{stdout}"
    );
}

#[test]
fn an_unknown_subcommand_is_reported_as_an_error_and_not_ignored() {
    let (code, _, stderr) = nau(&["plugin", "frobnicate"]);
    assert_ne!(code, 0, "an unknown subcommand must not exit 0");
    assert!(stderr.contains("frobnicate"), "{stderr}");
}

/// The fixture generator itself has to be right, or every assertion above is vacuous.
#[test]
fn the_fixture_signs_what_it_claims_to_sign() {
    let m = signed_manifest(
        "com.twinsearth.official.market",
        &["plugin:message:send"],
        true,
    );
    let trust = {
        let mut t = nau_plugin::TrustStore::deny_all();
        t.trust_vendor_key(&hex_key(&vendor())).expect("vendor key");
        t
    };
    let verified = m
        .verify(MODULE, &trust, 1_750_000_000)
        .expect("the fixture must verify, or the acceptance test proves nothing");
    assert_eq!(verified.tier, nau_plugin::Tier::Official);
    assert!(verified.token.allows(nau_plugin::Capability::MessageSend));
}

/// A guard against the fixture silently drifting from the directory layout.
#[test]
fn the_fixture_writes_a_directory_the_tool_can_read() {
    let dir = PluginDir::create(
        "layout",
        Some(&signed_manifest(
            "com.twinsearth.official.market",
            &[],
            true,
        )),
    );
    assert!(Path::new(dir.as_str()).join("plugin.json").is_file());
    assert!(Path::new(dir.as_str()).join("plugin.bin").is_file());
}

/// The certification scope, enforced by the loader, through the real binary.
///
/// # The defect this pins
///
/// `Certification::require_within_scope` was written, unit-tested, and called by **nothing
/// but its own tests** — so a certification was a record no loader read, and the review CLI
/// printed "the loader enforces this scope" at the operator. That is worse than a missing
/// check: it was a false statement in user-facing output.
///
/// All three outcomes are asserted, because "it refuses when the scope is wrong" alone would
/// pass on a check that refuses everything, which is not enforcement.
#[test]
fn a_certified_plugin_needs_a_certification_and_its_scope_is_enforced() {
    let name = "com.twinsearth.certified.analytics";
    let dir = PluginDir::create(
        "certified-scope",
        Some(&signed_manifest(name, &["plugin:message:send"], true)),
    );
    let scratch = PluginDir::create("certified-cert", None);
    let cert_path = Path::new(scratch.as_str()).join("certification.json");

    // 1. No certification at all. The counter-signature is present and valid, and that is
    //    exactly the point: the tier's requirement is the *review*, not the signature, and
    //    the refusal code has to say so rather than send an operator to the wrong document.
    let (code, out, err) = nau(&[
        "plugin",
        "verify",
        dir.as_str(),
        "--vendor",
        &hex_key(&vendor()),
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 1,
        "a certified plugin with no certification must be refused: {combined}"
    );
    assert!(
        combined.contains("certification_missing"),
        "the refusal must be its own code, not `counter_signature_missing`: {combined}"
    );

    // A certification naming a scope that does **not** cover what the manifest asks for.
    let wrong_scope = serde_json::json!({
        "plugin": name,
        "scope": ["plugin:lifecycle:read"],
        "vendor_key": hex_key(&vendor()),
        "certified_at": 1_750_000_010,
        "stage_history": [
            { "stage": "submitted", "because": "publisher submitted", "at": 1_750_000_000 },
            { "stage": "certified", "because": "approved", "at": 1_750_000_004 }
        ]
    });
    std::fs::write(
        &cert_path,
        serde_json::to_string_pretty(&wrong_scope).expect("serialises"),
    )
    .expect("certification written");

    let (code, out, err) = nau(&[
        "plugin",
        "verify",
        dir.as_str(),
        "--vendor",
        &hex_key(&vendor()),
        "--certification",
        cert_path.to_str().expect("utf-8 path"),
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 1,
        "a capability outside the certified scope must be refused: {combined}"
    );
    assert!(
        combined.contains("plugin:message:send"),
        "the refusal must name the capability the review did not cover: {combined}"
    );
    assert!(
        combined.contains("did not review"),
        "the refusal must say the review is what is missing: {combined}"
    );

    // And the covering scope loads. Without this the test would pass on a check that simply
    // refuses every certified plugin.
    let covering = serde_json::json!({
        "plugin": name,
        "scope": ["plugin:message:send"],
        "vendor_key": hex_key(&vendor()),
        "certified_at": 1_750_000_010,
        "stage_history": [
            { "stage": "submitted", "because": "publisher submitted", "at": 1_750_000_000 },
            { "stage": "certified", "because": "approved", "at": 1_750_000_004 }
        ]
    });
    std::fs::write(
        &cert_path,
        serde_json::to_string_pretty(&covering).expect("serialises"),
    )
    .expect("certification written");

    let (code, out, err) = nau(&[
        "plugin",
        "verify",
        dir.as_str(),
        "--vendor",
        &hex_key(&vendor()),
        "--certification",
        cert_path.to_str().expect("utf-8 path"),
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 0,
        "a manifest inside its certified scope must load: {combined}"
    );
    assert!(
        combined.contains("certification"),
        "the trace must show the certification stage: {combined}"
    );
}

/// A certification file that has been edited into something meaningless is refused.
///
/// The artefact is how a granted scope reaches the loader, so a file that does not describe
/// a review must not become one by default. Each field is checked rather than defaulted:
/// an invented scope is a grant nobody made.
#[test]
fn a_malformed_certification_is_refused_rather_than_defaulted() {
    let scratch = PluginDir::create("bad-cert", None);
    let cert_path = Path::new(scratch.as_str()).join("certification.json");
    let empty_scope = serde_json::json!({
        "plugin": "com.twinsearth.certified.analytics",
        "scope": [],
        "vendor_key": hex_key(&vendor()),
        "certified_at": 1_750_000_010,
        "stage_history": [
            { "stage": "submitted", "because": "s", "at": 1 },
            { "stage": "certified", "because": "a", "at": 4 }
        ]
    });
    std::fs::write(
        &cert_path,
        serde_json::to_string_pretty(&empty_scope).expect("serialises"),
    )
    .expect("written");

    let dir = PluginDir::create(
        "bad-cert-plugin",
        Some(&signed_manifest(
            "com.twinsearth.certified.analytics",
            &["plugin:message:send"],
            true,
        )),
    );
    let (code, out, err) = nau(&[
        "plugin",
        "verify",
        dir.as_str(),
        "--vendor",
        &hex_key(&vendor()),
        "--certification",
        cert_path.to_str().expect("utf-8 path"),
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 1,
        "an empty certification scope must be refused: {combined}"
    );
    assert!(
        combined.contains("certifies nothing") || combined.contains("certification_refused"),
        "the refusal must say what was wrong with the artefact: {combined}"
    );
}

/// `nau plugin run` starts the plugin and returns its answer.
///
/// # The command that had no predecessor
///
/// `verify` runs every check that can refuse a plugin and then says, in as many words, that the
/// plugin was **not executed**. That was accurate for the whole build: `ProcessPluginHost` —
/// the only thing that can start a process plugin — was constructed **only by its own tests**,
/// so the T1/T2/T3 tiers could be loaded, reviewed and certified and **nothing an operator has
/// ever ran one**. A whole set of tiers that pass every gate and still never run is the
/// "written but not wired" shape at its largest scale here.
///
/// The entry is the **real echo binary** rather than the shell stub the other fixtures use,
/// and that difference is the point: the stub passes the pipeline and cannot answer a frame, so
/// it can prove a load and not an execution.
#[test]
fn run_starts_a_verified_plugin_and_returns_its_answer() {
    let mut profile = std::env::current_exe().expect("the test binary has a path");
    profile.pop(); // deps/
    profile.pop(); // <profile>/
    let mut echo = profile.join("nau-plugin-echo");
    if cfg!(windows) {
        echo.set_extension("exe");
    }
    assert!(
        echo.exists(),
        "the echo plugin must have been built for this test: {}",
        echo.display()
    );
    let module = std::fs::read(&echo).expect("the echo binary is readable");

    let entry_name = if cfg!(windows) {
        "plugin.exe"
    } else {
        "plugin.bin"
    };
    let name = "io.example.echo";
    let publisher = publisher();
    let vendor = vendor();
    let mut manifest = signed_manifest(name, &[], true);
    manifest.plugin.entry = entry_name.to_string();
    manifest.plugin.module_sha256 = hex::encode(Sha256::digest(&module));
    // Re-signed after the edits: the digest covers the entry name, so changing it without
    // re-signing would make this test pass a manifest the kernel should refuse.
    manifest.signature.manifest_digest = manifest
        .digest_hex()
        .expect("canonical manifest should hash");
    let digest = manifest.signature.manifest_digest.clone();
    manifest.signature.sig = hex::encode(publisher.sign(digest.as_bytes()).to_bytes());
    manifest.signature.counter_sig = Some(hex::encode(vendor.sign(digest.as_bytes()).to_bytes()));
    manifest.signature.counter_key = Some(hex_key(&vendor));

    let dir = std::env::temp_dir().join(format!(
        "nau-plugin-cli-run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    // **`copy`, not `read` + `write`.** On Unix `fs::write` creates the file without the
    // executable bit, so the plugin loaded, passed every gate, and then could not be started --
    // and the failure appeared only on Linux and macOS, where Windows had been green. A
    // fixture that cannot run the thing it is a fixture for proves the wrong half; `fs::copy`
    // carries the permission bits across, which is what makes the entry an artefact the host
    // can actually exec.
    std::fs::copy(&echo, dir.join(entry_name)).expect("entry copied");
    // Pinned rather than assumed: on Unix the difference between a plugin that runs and one
    // that silently cannot be started is one permission bit, and this assertion is where that
    // becomes a sentence instead of a mystery. The first version of this test used
    // `fs::write`, passed on Windows, and failed on Linux and macOS for exactly this reason.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join(entry_name))
            .expect("the entry exists")
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "the entry must be executable or the host cannot start it: mode {mode:o}"
        );
    }
    std::fs::write(
        dir.join("plugin.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest serialises"),
    )
    .expect("manifest written");

    let (code, out, err) = nau(&[
        "plugin",
        "run",
        dir.to_str().expect("utf-8 path"),
        "--trust",
        &hex_key(&publisher),
        "--op",
        "echo",
        "--payload",
        r#"{"hello":"world"}"#,
    ]);
    let combined = format!("{out}{err}");
    assert!(
        combined.contains("EXECUTING"),
        "the command must say it is executing rather than only verifying: {combined}"
    );
    if cfg!(target_os = "macos") {
        // **macOS cannot do this, and the test asserts the refusal rather than skipping.**
        //
        // The sandbox backend on this platform refuses with `EINVAL` (`os error 22`), which is
        // a documented hard limit of this build rather than a defect in the command: the plugin
        // loads and passes every gate, and cannot be started because the kernel primitive the
        // sandbox needs is not available. A `#[cfg]` that removed this test on macOS would make
        // the platform look like one where the command was simply never tried; asserting the
        // refusal keeps the limit visible and keeps "it loaded" and "it ran" from being
        // conflated on the one platform where they differ.
        assert_eq!(
            code, 1,
            "macOS must refuse to start, not fail silently: {combined}"
        );
        assert!(
            combined.contains("call_refused"),
            "the refusal must be the call stage's own: {combined}"
        );
        assert!(
            combined.contains("os error 22") || combined.contains("Invalid argument"),
            "the refusal must name the platform error honestly: {combined}"
        );
        assert!(
            !combined.contains("NOT executed"),
            "`run` must not print the note that says the plugin was not executed: {combined}"
        );
    } else {
        assert_eq!(
            code, 0,
            "a plugin that verifies must run and answer: {combined}"
        );
        assert!(
            combined.contains("hello") && combined.contains("world"),
            "the plugin's own answer must come back: {combined}"
        );
        assert!(
            !combined.contains("NOT executed"),
            "`run` must not print the note that says the plugin was not executed: {combined}"
        );
    }

    if !cfg!(target_os = "macos") {
        // An op the plugin does not implement is a refusal with the plugin's own code, not a
        // crash and not a success. Not asserted on macOS, where the plugin cannot be started at
        // all -- the two failure modes would be indistinguishable there.
        let (code, out, err) = nau(&[
            "plugin",
            "run",
            dir.to_str().expect("utf-8 path"),
            "--trust",
            &hex_key(&publisher),
            "--op",
            "definitely-not-an-op",
        ]);
        let combined = format!("{out}{err}");
        assert_eq!(code, 1, "an unknown op must exit 1: {combined}");
        assert!(
            combined.contains("abi_unknown_operation"),
            "the plugin's own code must be reported: {combined}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A process plugin can ask the host to deliver a message, and the host is the one that decides.
///
/// # The gap this closes
///
/// A process plugin here is a child that answers one frame and exits. It holds no capability
/// token, no bus handle and no session key, so before this it could not communicate at all: its
/// answer was the whole of what it could do. `agent-universe` v3.5.0's §B2 closes the same gap
/// for Python process plugins by having them write `outbox.jsonl` in a sandbox; ours return a
/// frame already, so the declaration travels in the frame.
///
/// # What is asserted, and why the refusals are the point
///
/// A check that only showed a message being delivered would leave the interesting question open:
/// **can a plugin widen its own authority by declaring a capability it does not hold?** It cannot
/// — the host presents the plugin's own token and the bus decides — and the second case below is
/// what says so. The first case shows the attempt reaching the bus at all.
#[test]
fn a_process_plugin_can_declare_a_message_for_the_host_to_deliver() {
    let mut profile = std::env::current_exe().expect("the test binary has a path");
    profile.pop();
    profile.pop();
    let mut echo = profile.join("nau-plugin-echo");
    if cfg!(windows) {
        echo.set_extension("exe");
    }
    assert!(
        echo.exists(),
        "the echo plugin must have been built for this test: {}",
        echo.display()
    );
    let module = std::fs::read(&echo).expect("the echo binary is readable");

    let entry_name = if cfg!(windows) {
        "plugin.exe"
    } else {
        "plugin.bin"
    };
    let name = "io.example.echo";
    let publisher = publisher();
    let vendor = vendor();
    let mut manifest = signed_manifest(name, &[], true);
    manifest.plugin.entry = entry_name.to_string();
    manifest.plugin.module_sha256 = hex::encode(Sha256::digest(&module));
    manifest.signature.manifest_digest = manifest
        .digest_hex()
        .expect("canonical manifest should hash");
    let digest = manifest.signature.manifest_digest.clone();
    manifest.signature.sig = hex::encode(publisher.sign(digest.as_bytes()).to_bytes());
    manifest.signature.counter_sig = Some(hex::encode(vendor.sign(digest.as_bytes()).to_bytes()));
    manifest.signature.counter_key = Some(hex_key(&vendor));

    let dir = std::env::temp_dir().join(format!(
        "nau-plugin-cli-b2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::copy(&echo, dir.join(entry_name)).expect("entry copied");
    std::fs::write(
        dir.join("plugin.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest serialises"),
    )
    .expect("manifest written");

    if cfg!(target_os = "macos") {
        // macOS cannot start a process plugin at all (the sandbox backend refuses with EINVAL),
        // so the declaration path is unreachable there. Said here rather than skipped, for the
        // same reason as the test above: the platform's limit stays visible.
        let (code, out, err) = nau(&[
            "plugin",
            "run",
            dir.to_str().expect("utf-8 path"),
            "--trust",
            &hex_key(&publisher),
            "--op",
            "announce",
        ]);
        let combined = format!("{out}{err}");
        assert_eq!(code, 1, "macOS must refuse to start: {combined}");
        assert!(combined.contains("call_refused"), "{combined}");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    // 1. The declaration reaches the bus. The target is not registered in this one-shot run, so
    //    the bus refuses -- and that refusal **is** the proof: the host took the plugin's words,
    //    built a real PMB message and handed it to the one component allowed to judge it.
    let (code, out, err) = nau(&[
        "plugin",
        "run",
        dir.to_str().expect("utf-8 path"),
        "--trust",
        &hex_key(&publisher),
        "--op",
        "announce",
        "--payload",
        r#"{"to":"com.twinsearth.sys.identity"}"#,
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(code, 0, "the call itself succeeds: {combined}");
    assert!(
        combined.contains("declared 1 message(s)"),
        "the host must report the declaration: {combined}"
    );
    assert!(
        combined.contains("refused by the bus"),
        "an unregistered recipient must be refused by the bus, not dropped: {combined}"
    );

    // 2. **A plugin cannot widen its own authority by writing a word in a frame.** The plugin
    //    holds nothing beyond the basic set, so a declaration naming a privileged capability is
    //    refused by the bus even though the plugin asked for it by name.
    let (code, out, err) = nau(&[
        "plugin",
        "run",
        dir.to_str().expect("utf-8 path"),
        "--trust",
        &hex_key(&publisher),
        "--op",
        "announce",
        "--payload",
        r#"{"to":"com.twinsearth.sys.identity","capability":"kernel:plugin:manage"}"#,
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(code, 0, "the call still succeeds: {combined}");
    assert!(
        combined.contains("declared 1 message(s)"),
        "the host must still report the declaration: {combined}"
    );
    assert!(
        combined.contains("refused by the bus"),
        "a capability the plugin does not hold must be refused by the bus: {combined}"
    );
    assert!(
        combined.contains("kernel:plugin:manage"),
        "the refusal must name the capability that was claimed: {combined}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A third-party plugin loads, and then the quarantine stops it.
///
/// # What this ties together
///
/// The third-party tier is what the whole registration-and-review flow was built for: a
/// publisher submits, nobody counter-signs, the tier holds the basic capability set and
/// nothing above it. It is also the tier a **blacklist entry** is meant to stop, and until
/// now there was no third-party plugin object to stop — so the blacklist driver's work and
/// the tier's purpose had never met.
///
/// Both halves are asserted against the **same** directory with the **same** manifest and
/// the **same** trust: the only thing that changes between them is the quarantine, so a
/// refusal in the second half cannot be anything else.
#[test]
fn a_third_party_plugin_loads_until_the_quarantine_condemns_it() {
    use nau_plugin::blacklist::{BlacklistEntry, BlacklistReason};

    let name = "com.example.reputation";
    let plugin = PluginDir::create("t3", Some(&signed_manifest(name, &[], true)));
    let scratch = PluginDir::create("t3-quarantine", None);
    let publisher_hex = hex_key(&publisher());

    // 1. It loads. Third-party names need no certification, and none is supplied.
    let (code, out, err) = nau(&[
        "plugin",
        "verify",
        plugin.as_str(),
        "--trust",
        &publisher_hex,
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 0,
        "a third-party plugin the operator trusts must load: {combined}"
    );
    assert!(
        combined.contains("tier 3rd"),
        "the trace must say which tier it classified as: {combined}"
    );

    // 2. A signed quarantine entry condemning this exact plugin.
    let signer = vendor();
    let mut entry = BlacklistEntry {
        plugin_name: name.to_string(),
        module_sha256: None,
        reason: BlacklistReason::Malware,
        blacklisted_at: 1_750_000_000,
        evidence_cid: "bafyevidence".to_string(),
        signer_key: hex_key(&signer),
        signature: String::new(),
    };
    entry.signature = hex::encode(signer.sign(&entry.signing_bytes()).to_bytes());
    let list = Path::new(scratch.as_str()).join("blacklist.json");
    std::fs::write(
        &list,
        serde_json::to_string(&vec![entry]).expect("serialises"),
    )
    .expect("written");

    // 3. The same command, the same trust, plus the quarantine: refused, and by the
    //    blacklist stage rather than by anything else.
    let (code, out, err) = nau(&[
        "plugin",
        "verify",
        plugin.as_str(),
        "--trust",
        &publisher_hex,
        "--vendor",
        &hex_key(&signer),
        "--blacklist",
        list.to_str().expect("utf-8 path"),
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 1,
        "a quarantined third-party plugin must be refused: {combined}"
    );
    assert!(
        combined.contains("blacklisted"),
        "the refusal must be the blacklist stage's own: {combined}"
    );
    assert!(
        combined.contains(name),
        "the refusal must name the plugin: {combined}"
    );
}

/// The whole arc a certified (T2) plugin walks, through the real binary.
///
/// # Why this is the test that says the certified tier works
///
/// Four rounds of work met here, and each of them was a check refusing something it existed
/// to permit: the tier was hardcoded to third-party in the review flow; an approval-gated
/// capability was recorded as a blocker by the flow that grants the approval; the scan's
/// trust held only the publisher key, so the vendor counter-signature the tier **requires**
/// could never verify; and the load path demanded a certification while the only shipped
/// producer issued them at a ceiling that refuses what the tier exists for.
///
/// So this drives the whole thing in one go, the way an operator would: submit a
/// `com.twinsearth.certified.*` manifest asking for `swarm:consensus` -- committee-gated at
/// this tier and refused outright at the third-party one -- review it, certify it with that
/// capability in scope, and load it.
#[test]
fn a_certified_plugin_can_be_reviewed_certified_and_loaded_and_its_scope_is_enforced() {
    let name = "com.twinsearth.certified.swarm";
    let plugin = PluginDir::create(
        "t2-arc",
        Some(&signed_manifest(
            name,
            &["plugin:message:send", "swarm:consensus"],
            true,
        )),
    );
    let work = PluginDir::create("t2-arc-review", None);
    let manifest = Path::new(plugin.as_str()).join("plugin.json");
    let manifest = manifest.to_str().expect("utf-8 path");
    let vendor_hex = hex_key(&vendor());

    // 1. Open and scan. The vendor key is what verifies the counter-signature this tier
    //    requires, so without it the tier's own defining condition reads as a blocker.
    let (code, out, err) = nau(&[
        "plugin",
        "review",
        "open",
        "--dir",
        work.as_str(),
        "--manifest",
        manifest,
        "--publisher",
        "did:nau:0011223344556677",
        "--at",
        "1750000000",
    ]);
    assert_eq!(code, 0, "open: {out}{err}");

    let (code, out, err) = nau(&[
        "plugin",
        "review",
        "scan",
        "--dir",
        work.as_str(),
        "--manifest",
        manifest,
        "--vendor",
        &vendor_hex,
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 0,
        "a certified submission asking for an approval-gated capability must scan clean: \
         {combined}"
    );
    assert!(
        combined.contains("swarm:consensus"),
        "the scan must have looked at the gated capability: {combined}"
    );

    // 2. Walk the stages and certify with the gated capability in scope.
    for (to, because) in [
        ("auto_scanned", "scanned"),
        ("manual_review", "read"),
        ("grey_run", "trialled"),
        ("certified", "approved"),
    ] {
        let (code, out, err) = nau(&[
            "plugin",
            "review",
            "advance",
            "--dir",
            work.as_str(),
            "--to",
            to,
            "--because",
            because,
        ]);
        assert_eq!(code, 0, "advance to {to}: {out}{err}");
    }
    let (code, out, err) = nau(&[
        "plugin",
        "review",
        "certify",
        "--dir",
        work.as_str(),
        "--scope",
        "plugin:message:send,swarm:consensus",
        "--vendor-key",
        &vendor_hex,
        "--at",
        "1750000010",
    ]);
    assert_eq!(code, 0, "certify: {out}{err}");

    let artifact = Path::new(work.as_str()).join("certification.json");
    assert!(
        artifact.is_file(),
        "certify must write the artefact a loader is handed"
    );

    // 3. Load it with that certification. The approval that lets the token carry
    //    `swarm:consensus` comes from the scope, so this also proves the two are one decision.
    let (code, out, err) = nau(&[
        "plugin",
        "verify",
        plugin.as_str(),
        "--vendor",
        &vendor_hex,
        "--certification",
        artifact.to_str().expect("utf-8 path"),
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 0,
        "a certified plugin inside its certified scope must load: {combined}"
    );
    assert!(
        combined.contains("certification"),
        "the trace must name the certification stage: {combined}"
    );

    // 4. And the scope is what bounds it. Overwrite the artefact with one that omits the
    //    gated capability: the manifest is unchanged, the counter-signature is still valid,
    //    and the load must now refuse -- naming the capability the review did not cover.
    let narrow = serde_json::json!({
        "plugin": name,
        "scope": ["plugin:message:send"],
        "vendor_key": vendor_hex,
        "certified_at": 1_750_000_010,
        "stage_history": [
            { "stage": "submitted", "because": "submitted", "at": 1_750_000_000 },
            { "stage": "certified", "because": "approved", "at": 1_750_000_004 }
        ]
    });
    std::fs::write(
        &artifact,
        serde_json::to_string_pretty(&narrow).expect("serialises"),
    )
    .expect("written");

    let (code, out, err) = nau(&[
        "plugin",
        "verify",
        plugin.as_str(),
        "--vendor",
        &vendor_hex,
        "--certification",
        artifact.to_str().expect("utf-8 path"),
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 1,
        "a capability outside the certified scope must be refused: {combined}"
    );
    assert!(
        combined.contains("swarm:consensus"),
        "the refusal must name the capability the review did not cover: {combined}"
    );
}

/// The property the review flow exists for, across two modules, through the real binary.
///
/// # Why this specific test
///
/// `nau plugin review scan` is only worth having if **"passes review" means "can be
/// loaded"**. The version of `scan` that ran against `Blacklist::new()` — an empty list —
/// broke exactly that: it would approve a submission the load pipeline refuses as
/// quarantined, which is a review people would trust and should not. Two modules were
/// involved (`review` scanned, `blacklist` maintained the list) and neither one's own tests
/// could see the gap, because each was correct about its own half.
///
/// So the test drives the whole thing the way an operator would: maintain a quarantine with
/// `nau plugin blacklist add`, then scan a submission the quarantine condemns, and require
/// the refusal to be the **arbiter's own** blacklist stage rather than anything the review
/// driver composed.
#[test]
fn a_review_scan_refuses_a_submission_the_stored_quarantine_condemns() {
    use nau_plugin::blacklist::{BlacklistEntry, BlacklistReason};

    let name = "io.example.analytics";
    let plugin = PluginDir::create("review-quarantine", Some(&signed_manifest(name, &[], true)));
    let work = PluginDir::create("review-work", None);
    let manifest = Path::new(plugin.as_str()).join("plugin.json");
    let manifest = manifest.to_str().expect("utf-8 path");

    // 1. Open the review. Nothing is quarantined yet.
    let (code, out, err) = nau(&[
        "plugin",
        "review",
        "open",
        "--dir",
        work.as_str(),
        "--manifest",
        manifest,
        "--publisher",
        "did:nau:0011223344556677",
        "--at",
        "1750000000",
    ]);
    assert_eq!(code, 0, "open should succeed: {out}{err}");

    // 2. A signed quarantine entry condemning this plugin, every build of it.
    let signer = vendor();
    let mut entry = BlacklistEntry {
        plugin_name: name.to_string(),
        module_sha256: None,
        reason: BlacklistReason::Malware,
        blacklisted_at: 1_750_000_000,
        evidence_cid: "bafyevidence".to_string(),
        signer_key: hex_key(&signer),
        signature: String::new(),
    };
    entry.signature = hex::encode(signer.sign(&entry.signing_bytes()).to_bytes());
    let entry_path = Path::new(work.as_str()).join("quarantine-entry.json");
    // `--entry` takes **one** signed entry; the stored list is the array form.
    std::fs::write(
        &entry_path,
        serde_json::to_string(&entry).expect("entry serialises"),
    )
    .expect("entry written");

    // The list file the review reads is the one this operation writes, which is the
    // coupling the test is about.
    let (code, out, err) = nau(&[
        "plugin",
        "blacklist",
        "add",
        "--dir",
        work.as_str(),
        "--entry",
        entry_path.to_str().expect("utf-8 path"),
        "--vendor",
        &hex_key(&signer),
    ]);
    assert_eq!(code, 0, "the signed entry should be accepted: {out}{err}");

    // 3. Scan. The verdict must be the load pipeline's own blacklist stage.
    let (code, out, err) = nau(&[
        "plugin",
        "review",
        "scan",
        "--dir",
        work.as_str(),
        "--manifest",
        manifest,
        "--vendor",
        &hex_key(&signer),
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 1,
        "a scan must refuse a quarantined submission, not approve it: {combined}"
    );
    assert!(
        combined.contains("load:blacklist"),
        "the refusal must come from the arbiter's own blacklist stage, not from a sentence \
         the review driver composed: {combined}"
    );
    assert!(
        combined.contains(name),
        "the refusal must name the plugin: {combined}"
    );

    // 4. And the scan says which list it consulted, so "no entries" cannot be mistaken for
    //    "not consulted" — the ambiguity that hid the original gap.
    assert!(
        combined.contains("blacklist.json"),
        "the scan must say which quarantine it consulted: {combined}"
    );

    // 5. `check` agrees, through the same stored file.
    let (code, out, err) = nau(&[
        "plugin",
        "blacklist",
        "check",
        "--dir",
        work.as_str(),
        "--name",
        name,
    ]);
    assert_eq!(code, 1, "check should condemn it: {out}{err}");
}

/// A quarantine that cannot be verified is a refusal, never an empty list.
///
/// The distinction matters more than it looks: an empty list permits everything, and a
/// caller that cannot tell "I checked and there is nothing" from "I could not check" has no
/// quarantine at all. `nau plugin verify` says out loud when it ran with none.
#[test]
fn a_hand_edited_quarantine_is_refused_by_every_reader_and_not_treated_as_empty() {
    use nau_plugin::blacklist::{BlacklistEntry, BlacklistReason};

    let work = PluginDir::create("quarantine-tamper", None);
    let signer = vendor();
    let mut entry = BlacklistEntry {
        plugin_name: "io.example.tampered".to_string(),
        module_sha256: None,
        reason: BlacklistReason::Malware,
        blacklisted_at: 1_750_000_000,
        evidence_cid: "bafyevidence".to_string(),
        signer_key: hex_key(&signer),
        signature: String::new(),
    };
    entry.signature = hex::encode(signer.sign(&entry.signing_bytes()).to_bytes());
    let entry_path = Path::new(work.as_str()).join("entry.json");
    std::fs::write(
        &entry_path,
        serde_json::to_string(&entry).expect("serialises"),
    )
    .expect("written");
    let (code, _, err) = nau(&[
        "plugin",
        "blacklist",
        "add",
        "--dir",
        work.as_str(),
        "--entry",
        entry_path.to_str().expect("utf-8 path"),
        "--vendor",
        &hex_key(&signer),
    ]);
    assert_eq!(code, 0, "the entry should be accepted first: {err}");

    // Edit the entry after it was signed. The signature no longer covers the contents.
    let list = Path::new(work.as_str()).join("blacklist.json");
    let text = std::fs::read_to_string(&list).expect("the list was written");
    let edited = text.replace("io.example.tampered", "io.example.someone.else");
    assert_ne!(text, edited, "the fixture must actually change the file");
    std::fs::write(&list, edited).expect("edited list written");

    let (code, out, err) = nau(&[
        "plugin",
        "blacklist",
        "list",
        "--dir",
        work.as_str(),
        "--vendor",
        &hex_key(&signer),
    ]);
    let combined = format!("{out}{err}");
    assert_eq!(
        code, 1,
        "a hand-edited entry must be refused, not read as a list: {combined}"
    );
    assert!(
        combined.contains("does not verify") || combined.contains("entry-refused"),
        "the refusal must say the entry failed verification: {combined}"
    );

    // And the entry that was edited does not silently disappear along with it: reading the
    // file at all is refused, so no caller can act on a partially trusted list.
    assert!(
        !combined.contains("the blacklist is empty"),
        "a refusal must not be reported as an empty list: {combined}"
    );
}
