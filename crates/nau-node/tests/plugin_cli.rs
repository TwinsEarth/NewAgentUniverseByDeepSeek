//! `nau plugin …` end to end, against the real binary.
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
fn waivers() -> std::collections::BTreeMap<String, String> {
    [
        ("network", "test fixture: loopback host"),
        (
            "filesystem_confinement",
            "test fixture: no confinement primitive",
        ),
        ("disk_bytes", "test fixture: no quota primitive"),
        ("cpu_ms", "test fixture: no cpu primitive"),
        ("max_open_files", "test fixture: no handle cap"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
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
            abi: "2.2".into(),
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
            abi: "2.2".into(),
            entry: "plugin.bin".into(),
            publisher: "did:nau:0011223344556677".into(),
            module_sha256: module_digest,
        },
        capabilities: CapabilitySection {
            grant: vec!["plugin:message:send".into()],
        },
        limits: limits(),
        waivers: waivers(),
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
    for sub in ["tiers", "runtimes", "verify", "blacklist", "system"] {
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

    // All four reach Running -- not merely registered.
    assert_eq!(
        stdout.matches("state  running").count(),
        4,
        "every shipped system plugin must reach Running:\n{stdout}"
    );
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
