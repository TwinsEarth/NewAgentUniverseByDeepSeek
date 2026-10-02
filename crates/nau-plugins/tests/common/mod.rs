#![allow(dead_code)]
//! Shared builders for the `nau-plugins` integration tests.
//!
//! The fixture definitions live here rather than in one test file because three
//! suites use them: `manifest_fixtures.rs` asserts their outcomes and regenerates
//! the files on disk, `system_plugins.rs` registers T0 plugins against system
//! manifests built the same way, and `end_to_end.rs` runs a T1 plugin's message
//! through the bus into a T0 plugin. `#![allow(dead_code)]` is here because each
//! integration test is its own crate: every binary compiles the whole module, and
//! none of them uses all of it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use nau_plugin::lifecycle::PluginState;
use nau_plugin::registry::Registry;
use nau_plugin::runtime::{Boundary, PluginRuntime, ProcessRuntime};
use nau_plugin::{Capability, Manifest, PluginError, Result, Tier, TrustStore, VerifiedManifest};
use nau_plugins::sign;

/// The issue time every fixture is verified at, and the time every lifecycle
/// transition in these tests carries.
pub const NOW: u64 = sign::FIXTURE_ISSUED_AT;

/// [`NOW`] in milliseconds, which is the unit the bus takes.
pub const NOW_MS: u64 = NOW * 1_000;

// ---------------------------------------------------------------------------
// Keys. One byte per seed, documented in `tests/fixtures/README.md` so that a
// reader can recompute every fixture from this file alone.
// ---------------------------------------------------------------------------

/// Seed of the host's own T0 publisher key.
pub const HOST_SEED: u8 = 3;
/// Seed of the official market publisher.
pub const PUBLISHER_SEED: u8 = 7;
/// Seed of the trusted vendor key that counter-signs official and certified.
pub const VENDOR_SEED: u8 = 9;
/// Seed of the certified analytics publisher.
pub const CERTIFIED_SEED: u8 = 11;
/// Seed of the third-party publisher (`io.example.analytics`).
pub const THIRD_PARTY_SEED: u8 = 5;
/// Seed of a publisher the operator's trust store does **not** list.
pub const STRANGER_SEED: u8 = 13;
/// Seed of a vendor key the trust store does **not** list.
pub const ROGUE_VENDOR_SEED: u8 = 21;

/// The host's own publisher key for T0 manifests.
#[must_use]
pub fn host_key() -> SigningKey {
    sign::fixture_key(HOST_SEED)
}

/// The trusted vendor key.
#[must_use]
pub fn vendor_key() -> SigningKey {
    sign::fixture_key(VENDOR_SEED)
}

/// The official market publisher key.
#[must_use]
pub fn publisher_key() -> SigningKey {
    sign::fixture_key(PUBLISHER_SEED)
}

/// The certified analytics publisher key.
#[must_use]
pub fn certified_key() -> SigningKey {
    sign::fixture_key(CERTIFIED_SEED)
}

/// The third-party publisher key.
#[must_use]
pub fn third_party_key() -> SigningKey {
    sign::fixture_key(THIRD_PARTY_SEED)
}

/// A publisher key no trust store in these tests lists.
#[must_use]
pub fn stranger_key() -> SigningKey {
    sign::fixture_key(STRANGER_SEED)
}

/// The trust store an operator would configure for these fixtures: the vendor key
/// may counter-sign, and the third-party publisher has been explicitly trusted.
///
/// # Errors
///
/// [`PluginError::Manifest`] when a key is malformed, which the kernel decides.
pub fn trust() -> Result<TrustStore> {
    sign::trust_store(&[&vendor_key()], &[&third_party_key()])
}

/// The reason the fixture manifests give for waiving the boundaries this build
/// cannot enforce.
#[must_use]
pub fn fixture_waivers() -> BTreeMap<String, String> {
    sign::process_waivers(sign::FIXTURE_WAIVER_REASON)
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// What verifying a fixture must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expected {
    /// Verification succeeds, at this tier, with exactly this capability set.
    Verified {
        /// The tier the name classifies as.
        tier: Tier,
        /// The capabilities the token must hold.
        capabilities: &'static [Capability],
    },
    /// Verification fails, and the error must contain this exact refusal code.
    Refused(&'static str),
}

/// One manifest fixture: the artefact, the module bytes it is checked against, the
/// trust store it is checked with, and what must happen.
pub struct Fixture {
    /// File name under `tests/fixtures/`.
    pub file: &'static str,
    /// What this fixture is for, in one line.
    pub case: &'static str,
    /// The signed manifest.
    pub manifest: Manifest,
    /// The bytes handed to `verify` as the entry artefact.
    pub module: Vec<u8>,
    /// The trust store it is verified with.
    pub trust: TrustStore,
    /// The required outcome.
    pub expected: Expected,
}

impl Fixture {
    /// The plugin name the fixture declares.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.manifest.plugin.name
    }

    /// Verify the fixture, returning the outcome as a `Result`.
    ///
    /// # Errors
    ///
    /// Whatever [`Manifest::verify`] reports.
    pub fn verify(&self) -> Result<VerifiedManifest> {
        self.manifest.verify(&self.module, &self.trust, NOW)
    }
}

/// The official market plugin's unconditional capability set.
///
/// The task's market set is `plugin:message:send`, `plugin:storage:own`,
/// `agent:card:create` and `economy:settle`. At the Official tier **every**
/// non-basic capability resolves through `Grant::RequiresApproval`, and
/// `CapabilityToken::issue` has no parameter that can carry an approval — so the
/// set a market plugin "needs" is refused by the kernel, and the set it can hold
/// unconditionally is the basic one. Both are fixtures:
/// [`fixtures`] carries the refusal, `official-market.json` the loadable manifest.
pub const MARKET_ASKED: &[Capability] = &[
    Capability::MessageSend,
    Capability::StorageOwn,
    Capability::AgentCardCreate,
    Capability::EconomySettle,
];

/// The directory the fixture files live in.
#[must_use]
pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Every fixture, in file order.
///
/// # Errors
///
/// Whatever drafting or signing reports.
pub fn fixtures() -> Result<Vec<Fixture>> {
    Ok(vec![
        market_fixture()?,
        market_full_set_fixture()?,
        market_settle_fixture()?,
        certified_fixture()?,
        third_party_fixture()?,
        third_party_dht_fixture()?,
        module_mismatch_fixture()?,
        capabilities_edited_fixture()?,
        no_counter_signature_fixture()?,
        untrusted_publisher_fixture()?,
        future_abi_fixture()?,
    ])
}

/// Fixture 1: a loadable official plugin, publisher-signed and vendor counter-signed,
/// holding the basic set.
fn market_fixture() -> Result<Fixture> {
    Ok(Fixture {
        file: "official-market.json",
        case: "loadable official plugin, double-signed, basic capabilities",
        manifest: sign::signed(
            "com.twinsearth.official.market",
            "market.bin",
            &sign::module("market.bin"),
            &Capability::BASIC,
            &publisher_key(),
            &vendor_key(),
            fixture_waivers(),
        )?,
        module: sign::module("market.bin"),
        trust: trust()?,
        expected: Expected::Verified {
            tier: Tier::Official,
            capabilities: &Capability::BASIC,
        },
    })
}

/// Fixture 2: the same plugin asking for the capability set a market plugin needs,
/// refused because at Official every non-basic capability needs the vendor team's
/// approval and this load carries none.
///
/// The code is `capability_not_approved` rather than `capability_not_permitted`: the
/// capability is permitted at this tier, it simply has not been approved, and the two
/// send an operator to different places. The kernel gained a door that *does* carry an
/// approval into a token (`Manifest::verify_with_approvals`), so this fixture is now
/// specifically the "nobody approved it" case rather than "no such mechanism exists".
fn market_full_set_fixture() -> Result<Fixture> {
    Ok(Fixture {
        file: "official-market-full-set.json",
        case:
            "official plugin asking for agent:card:create and economy:settle, which need approval",
        manifest: sign::signed(
            "com.twinsearth.official.market",
            "market.bin",
            &sign::module("market.bin"),
            MARKET_ASKED,
            &publisher_key(),
            &vendor_key(),
            fixture_waivers(),
        )?,
        module: sign::module("market.bin"),
        trust: trust()?,
        expected: Expected::Refused("capability_not_approved"),
    })
}

/// Fixture 3: the `economy:settle` case on its own, so the `RequiresApproval` path has
/// one unambiguous fixture rather than being a detail of the one above.
///
/// Refused `capability_not_approved`, for the same reason as fixture 2: at Official the
/// capability is permitted conditional on the vendor team's approval, and no approval was
/// supplied.
fn market_settle_fixture() -> Result<Fixture> {
    Ok(Fixture {
        file: "official-market-settle.json",
        case: "official plugin asking only for economy:settle, which the vendor team must approve",
        manifest: sign::signed(
            "com.twinsearth.official.market",
            "market.bin",
            &sign::module("market.bin"),
            &[
                Capability::LifecycleRead,
                Capability::MessageSend,
                Capability::StorageOwn,
                Capability::EconomySettle,
            ],
            &publisher_key(),
            &vendor_key(),
            fixture_waivers(),
        )?,
        module: sign::module("market.bin"),
        trust: trust()?,
        expected: Expected::Refused("capability_not_approved"),
    })
}

/// 4. Certified, double-signed, basic capabilities only.
fn certified_fixture() -> Result<Fixture> {
    Ok(Fixture {
        file: "certified-analytics.json",
        case: "loadable certified plugin, publisher signature plus vendor counter-signature",
        manifest: sign::signed(
            "com.twinsearth.certified.analytics",
            "analytics.bin",
            &sign::module("analytics.bin"),
            &Capability::BASIC,
            &certified_key(),
            &vendor_key(),
            fixture_waivers(),
        )?,
        module: sign::module("analytics.bin"),
        trust: trust()?,
        expected: Expected::Verified {
            tier: Tier::Certified,
            capabilities: &Capability::BASIC,
        },
    })
}

/// 5. Third party, publisher-signed only, trusted explicitly by the operator.
fn third_party_fixture() -> Result<Fixture> {
    Ok(Fixture {
        file: "thirdparty-analytics.json",
        case: "loadable third-party plugin, publisher-signed, key trusted by the operator",
        manifest: third_party_manifest(&Capability::BASIC)?,
        module: sign::module("analytics.bin"),
        trust: trust()?,
        expected: Expected::Verified {
            tier: Tier::ThirdParty,
            capabilities: &Capability::BASIC,
        },
    })
}

/// 6. The negative capability fixture: a third-party plugin asking for the DHT.
fn third_party_dht_fixture() -> Result<Fixture> {
    Ok(Fixture {
        file: "thirdparty-dht-overreach.json",
        case: "third-party plugin asking for net:dht:read",
        manifest: third_party_manifest(&[
            Capability::LifecycleRead,
            Capability::MessageSend,
            Capability::StorageOwn,
            Capability::DhtRead,
        ])?,
        module: sign::module("analytics.bin"),
        trust: trust()?,
        expected: Expected::Refused("capability_not_permitted"),
    })
}

/// 7. Hostile: the module bytes do not hash to what the manifest signed.
fn module_mismatch_fixture() -> Result<Fixture> {
    Ok(Fixture {
        file: "hostile-module-mismatch.json",
        case: "manifest whose module_sha256 covers hostile.bin but is checked against market.bin",
        manifest: sign::signed(
            "com.twinsearth.official.market",
            "hostile.bin",
            &sign::module("hostile.bin"),
            &Capability::BASIC,
            &publisher_key(),
            &vendor_key(),
            fixture_waivers(),
        )?,
        // Deliberately the wrong artefact for this manifest.
        module: sign::module("market.bin"),
        trust: trust()?,
        expected: Expected::Refused("module_digest_mismatch"),
    })
}

/// 8. Hostile: capabilities edited after signing.
fn capabilities_edited_fixture() -> Result<Fixture> {
    let mut edited = sign::signed(
        "com.twinsearth.official.market",
        "market.bin",
        &sign::module("market.bin"),
        &Capability::BASIC,
        &publisher_key(),
        &vendor_key(),
        fixture_waivers(),
    )?;
    edited
        .capabilities
        .grant
        .push(Capability::KernelPolicyWrite.as_str().to_string());
    Ok(Fixture {
        file: "hostile-capabilities-edited.json",
        case: "kernel:policy:write added to the grant list after the manifest was signed",
        manifest: edited,
        module: sign::module("market.bin"),
        trust: trust()?,
        expected: Expected::Refused("manifest_invalid"),
    })
}

/// 9. Hostile: an official manifest with the vendor counter-signature stripped.
fn no_counter_signature_fixture() -> Result<Fixture> {
    let mut stripped = sign::draft(
        "com.twinsearth.official.market",
        "market.bin",
        &sign::module("market.bin"),
        &Capability::BASIC,
        &publisher_key(),
        fixture_waivers(),
    )?;
    sign::sign(&mut stripped, &publisher_key())?;
    Ok(Fixture {
        file: "hostile-no-counter-signature.json",
        case: "official manifest with counter_sig and counter_key removed",
        manifest: stripped,
        module: sign::module("market.bin"),
        trust: trust()?,
        expected: Expected::Refused("counter_signature_missing"),
    })
}

/// 10. Hostile: signed by a key the operator's trust store does not list.
fn untrusted_publisher_fixture() -> Result<Fixture> {
    let mut stranger = sign::draft(
        "io.example.analytics",
        "analytics.bin",
        &sign::module("analytics.bin"),
        &Capability::BASIC,
        &stranger_key(),
        fixture_waivers(),
    )?;
    sign::sign(&mut stranger, &stranger_key())?;
    Ok(Fixture {
        file: "hostile-untrusted-publisher.json",
        case: "third-party manifest signed by a publisher key the trust store does not list",
        manifest: stranger,
        module: sign::module("analytics.bin"),
        trust: trust()?,
        expected: Expected::Refused("untrusted_publisher"),
    })
}

/// 11. Hostile: a future ABI minor.
fn future_abi_fixture() -> Result<Fixture> {
    let mut future = sign::draft_with_abi(
        "io.example.analytics",
        "4.0",
        "analytics.bin",
        &sign::module("analytics.bin"),
        &Capability::BASIC,
        &third_party_key(),
        fixture_waivers(),
    )?;
    sign::sign(&mut future, &third_party_key())?;
    Ok(Fixture {
        file: "hostile-future-abi.json",
        case: "plugin built against ABI 2.9, newer than this host's 2.2",
        manifest: future,
        module: sign::module("analytics.bin"),
        trust: trust()?,
        expected: Expected::Refused("abi_incompatible"),
    })
}

/// One third-party manifest over `analytics.bin`, publisher-signed only.
fn third_party_manifest(capabilities: &[Capability]) -> Result<Manifest> {
    let mut manifest = sign::draft(
        "io.example.analytics",
        "analytics.bin",
        &sign::module("analytics.bin"),
        capabilities,
        &third_party_key(),
        fixture_waivers(),
    )?;
    sign::sign(&mut manifest, &third_party_key())?;
    Ok(manifest)
}

/// Write every fixture to `tests/fixtures/`, pretty-printed.
///
/// # Errors
///
/// [`PluginError::Io`] when a file cannot be written, and [`PluginError::Json`] when
/// a manifest cannot be encoded.
pub fn write_fixtures(fixtures: &[Fixture]) -> Result<()> {
    std::fs::create_dir_all(fixture_dir())?;
    for fixture in fixtures {
        let path = fixture_dir().join(fixture.file);
        let mut json = serde_json::to_string_pretty(&fixture.manifest)?;
        json.push('\n');
        std::fs::write(&path, json)?;
    }
    Ok(())
}

/// Read a fixture back from disk, **without** validating it.
///
/// [`Manifest::parse`] also validates, and one fixture
/// (`hostile-future-abi.json`) is deliberately invalid — that is what it is for. The
/// JSON is decoded directly so the drift check can compare every fixture, hostile
/// ones included; a test that wants the validation step calls
/// `Manifest::parse` on the file itself.
///
/// # Errors
///
/// [`PluginError::Io`] when the file cannot be read, [`PluginError::Json`] when it is
/// not a manifest.
pub fn read_fixture(file: &str) -> Result<Manifest> {
    let path = fixture_dir().join(file);
    let text = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&text)?)
}

/// Read a fixture through the validating parser.
///
/// # Errors
///
/// [`PluginError::Io`] when the file cannot be read, and whatever
/// [`Manifest::parse`] refuses.
pub fn parse_fixture(file: &str) -> Result<Manifest> {
    let path = fixture_dir().join(file);
    Manifest::parse(&std::fs::read_to_string(&path)?)
}

// ---------------------------------------------------------------------------
// Frameworks.
// ---------------------------------------------------------------------------

/// A verified system manifest for a T0 plugin.
///
/// # Errors
///
/// Whatever signing or verification reports.
pub fn system_manifest(name: &str, capabilities: &[Capability]) -> Result<VerifiedManifest> {
    sign::verified_system(name, capabilities, &host_key(), &vendor_key())
}

/// Insert a verified manifest into the registry and move it to `Running`.
///
/// # Errors
///
/// [`PluginError::Manifest`] when the insert is refused, [`PluginError::Lifecycle`]
/// when a transition is illegal.
pub fn activate(registry: &mut Registry, verified: &VerifiedManifest) -> Result<()> {
    registry.insert(verified.clone(), Vec::new())?;
    let name = verified.id.as_str().to_string();
    let entry = registry
        .get_mut(&name)
        .ok_or_else(|| PluginError::Manifest(format!("`{name}` was inserted and is not there")))?;
    for state in [
        PluginState::Verified,
        PluginState::Loaded,
        PluginState::Running,
    ] {
        entry
            .lifecycle
            .transition(state, "test: activated for the pipeline", NOW)?;
    }
    Ok(())
}

/// The sandbox boundaries `ProcessRuntime` cannot enforce for a plugin.
#[must_use]
pub fn unenforced_boundaries() -> Vec<Boundary> {
    ProcessRuntime::new()
        .declares()
        .unenforced()
        .into_iter()
        .map(|(boundary, _why)| boundary)
        .collect()
}

/// A fresh directory under the system temp directory, named for the test that asked.
#[must_use]
pub fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("nau-plugins-{tag}-{}-{nanos}", std::process::id()))
}

/// An `Arc` of the registry, usable both as `&Registry` and as the orchestrator's
/// [`LoadOrderSource`](nau_plugins::LoadOrderSource).
#[must_use]
pub fn shared(registry: Registry) -> Arc<Registry> {
    Arc::new(registry)
}
