//! Manifest signing: the vendor-side helper this crate ships for its fixtures.
//!
//! # Why this is not behind a feature
//!
//! The alternative was `#[cfg(feature = "sign")]`. It is not gated, deliberately:
//! the signed manifest fixtures under `tests/fixtures/` are *generated* by this
//! module and *asserted* by the default test run, and the isolation tests another
//! agent writes need to mint a manifest with a valid signature to get past the
//! kernel's first three checks. A non-default feature would mean the required
//! command (`cargo test -p nau-plugins --locked`) never exercises any of that — the
//! fixtures would be verified only by whoever remembered to pass `--features sign`,
//! which is precisely the "documented but unenforced" shape this project exists to
//! refuse.
//!
//! The kernel never calls this module. It produces [`Manifest`] values; only
//! [`Manifest::verify`] decides whether one is loadable, and this module cannot make
//! it say yes.
//!
//! # What it does and does not do
//!
//! * It signs the **canonical** digest of the manifest, computed by
//!   [`Manifest::digest_hex`] — so the bytes covered are the same bytes the kernel
//!   recomputes, rather than a second canonicalisation written here.
//! * It derives a publisher's DID with `nau-core`'s identity module rather than
//!   formatting one, so a fixture's `plugin.publisher` really is the fingerprint of
//!   the key that signed it.
//! * It does not create, store or protect production keys. [`fixture_key`] takes a
//!   one-byte seed and exists so a fixture is reproducible; a one-byte seed space is
//!   trivially enumerable and must never be used for a real publisher or vendor key.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use nau_core::identity::Keypair;
use nau_plugin::manifest::{CapabilitySection, PluginSection, SignatureSection};
use nau_plugin::{Capability, Limits, Manifest, PluginError, Result, TrustStore, VerifiedManifest};

/// The version every fixture manifest declares.
///
/// Deliberately **not** the release version. A plugin versions independently of the
/// kernel -- the architecture document says so, and the manifest's `version` field is
/// the plugin's own -- so tying this constant to the release version was wrong twice
/// over: it made every fixture restate a version it has nothing to do with, and it
/// meant a routine version bump silently rewrote every fixture digest. The version
/// gate caught it the moment the release moved to 2.2.2, which is the gate working.
pub const FIXTURE_VERSION: &str = "1.4.0";

/// The issue time every fixture is verified at (2025-06-15T14:26:40Z).
pub const FIXTURE_ISSUED_AT: u64 = 1_750_000_000;

/// A deterministic key from a one-byte seed.
///
/// Fixtures only. See the module documentation: the seed space is 256 values, so
/// this is a reproducible test key and nothing else.
#[must_use]
pub fn fixture_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The lower-case hex public key of `key`, as a manifest carries it.
#[must_use]
pub fn key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// The `did:nau:` identifier `key` fingerprints, derived by `nau-core`.
#[must_use]
pub fn did_of(key: &SigningKey) -> String {
    Keypair::from_seed(&key.to_bytes()).did().to_string()
}

/// The module bytes a fixture manifest covers.
///
/// Deterministic and printable on purpose: a reader of `tests/fixtures/README.md`
/// can reconstruct the exact bytes from the entry name, so the `module_sha256` in a
/// fixture is checkable by hand.
#[must_use]
pub fn module(entry: &str) -> Vec<u8> {
    format!("nau-plugins fixture module for {entry}\n").into_bytes()
}

/// SHA-256 of `bytes`, lower-case hex.
#[must_use]
pub fn module_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// The limits every fixture declares: non-zero in every dimension, because the
/// kernel refuses zero rather than reading it as "unlimited".
#[must_use]
pub fn limits() -> Limits {
    Limits {
        memory_bytes: 256 * 1024 * 1024,
        cpu_ms: 20_000,
        disk_bytes: 64 * 1024 * 1024,
        max_processes: 4,
        max_output_bytes: 256 * 1024,
    }
}

/// A manifest with a module digest and a publisher, but no signature yet.
///
/// `version` is [`FIXTURE_VERSION`] and `abi` is the ABI this kernel speaks, so a
/// fixture cannot accidentally declare an ABI the host would refuse for the wrong
/// reason. Use [`draft_with_abi`] when the fixture is *about* the version fields.
///
/// `waivers` is part of the **signed** payload, so it is set here rather than after
/// signing: see [`process_waivers`].
///
/// # Errors
///
/// [`PluginError::Manifest`] when the manifest cannot be canonicalised for its
/// digest, which cannot happen for this schema but is returned rather than assumed.
pub fn draft(
    name: &str,
    entry: &str,
    module_bytes: &[u8],
    capabilities: &[Capability],
    publisher: &SigningKey,
    waivers: BTreeMap<String, String>,
) -> Result<Manifest> {
    draft_with_abi(
        name,
        &crate::frame::abi_version(),
        entry,
        module_bytes,
        capabilities,
        publisher,
        waivers,
    )
}

/// [`draft`] with the ABI spelled out, for the `abi_incompatible` fixture.
///
/// # Errors
///
/// As [`draft`].
pub fn draft_with_abi(
    name: &str,
    abi: &str,
    entry: &str,
    module_bytes: &[u8],
    capabilities: &[Capability],
    publisher: &SigningKey,
    waivers: BTreeMap<String, String>,
) -> Result<Manifest> {
    Ok(Manifest {
        plugin: PluginSection {
            name: name.to_string(),
            version: FIXTURE_VERSION.to_string(),
            abi: abi.to_string(),
            entry: entry.to_string(),
            publisher: did_of(publisher),
            module_sha256: module_digest(module_bytes),
        },
        capabilities: CapabilitySection {
            grant: capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
        },
        limits: limits(),
        waivers,
        dependencies: Vec::new(),
        // A-11: the class this manifest runs at. Stated explicitly here rather than
        // relying on serde's default, so that adding the field is a decision this
        // construction site made rather than a value it inherited.
        priority: nau_plugin::PriorityClass::LatencyTolerant,
        signature: SignatureSection {
            publisher_key: key_hex(publisher),
            manifest_digest: String::new(),
            sig: String::new(),
            counter_sig: None,
            counter_key: None,
        },
    })
}

/// The waivers a plugin needs to start under
/// [`ProcessRuntime`](nau_plugin::runtime::ProcessRuntime), with one reason.
///
/// Derived from the runtime's own declaration rather than written out here, so the
/// list cannot drift from what the runtime admits it cannot enforce: on this build
/// that is egress denial, filesystem confinement, disk quota, CPU time and open-file
/// caps, none of which has a primitive behind a plain child process.
///
/// A manifest that omits these is refused with `isolation_not_enforceable` before
/// the runtime stage, which is the correct answer and a *different* test from the
/// ones the fixtures exist for.
#[must_use]
pub fn process_waivers(reason: &str) -> BTreeMap<String, String> {
    use nau_plugin::runtime::{PluginRuntime, ProcessRuntime};
    ProcessRuntime::new()
        .declares()
        .unenforced()
        .into_iter()
        .map(|(boundary, _why)| (boundary.waiver_key().to_string(), reason.to_string()))
        .collect()
}

/// Sign `manifest` in place with the publisher key.
///
/// The digest is recomputed here and stored in the manifest, then signed. Signing is
/// over the digest's ASCII bytes — the kernel's `verify_over_digest` verifies exactly
/// that, and a helper that signed the manifest bytes instead would produce fixtures
/// that fail with `signature_invalid` and look like a kernel bug.
///
/// # Errors
///
/// As [`Manifest::digest_hex`].
pub fn sign(manifest: &mut Manifest, publisher: &SigningKey) -> Result<()> {
    let digest = manifest.digest_hex()?;
    manifest.signature.publisher_key = key_hex(publisher);
    manifest.signature.sig = hex::encode(publisher.sign(digest.as_bytes()).to_bytes());
    manifest.signature.manifest_digest = digest;
    Ok(())
}

/// Counter-sign `manifest` in place with a vendor key.
///
/// The digest signed here is the one already recorded by [`sign`]: a counter-signature
/// covers the same bytes as the publisher's, which is what makes it a statement about
/// *this* manifest rather than about a different one.
///
/// # Errors
///
/// [`PluginError::Manifest`] when the manifest has not been signed yet, because a
/// counter-signature over an empty digest would be a signature over nothing.
pub fn counter_sign(manifest: &mut Manifest, vendor: &SigningKey) -> Result<()> {
    if manifest.signature.manifest_digest.is_empty() {
        return Err(PluginError::Manifest(
            "counter-signing a manifest that has not been signed: there is no digest to cover"
                .into(),
        ));
    }
    let digest = manifest.signature.manifest_digest.clone();
    manifest.signature.counter_sig = Some(hex::encode(vendor.sign(digest.as_bytes()).to_bytes()));
    manifest.signature.counter_key = Some(key_hex(vendor));
    Ok(())
}

/// Draft, sign and counter-sign in one call.
///
/// # Errors
///
/// As [`draft`], [`sign`] and [`counter_sign`].
pub fn signed(
    name: &str,
    entry: &str,
    module_bytes: &[u8],
    capabilities: &[Capability],
    publisher: &SigningKey,
    vendor: &SigningKey,
    waivers: BTreeMap<String, String>,
) -> Result<Manifest> {
    let mut manifest = draft(name, entry, module_bytes, capabilities, publisher, waivers)?;
    sign(&mut manifest, publisher)?;
    counter_sign(&mut manifest, vendor)?;
    Ok(manifest)
}

/// A trust store that trusts exactly the keys given.
///
/// # Errors
///
/// [`PluginError::Manifest`] when a key is not a valid key, which the kernel's
/// `TrustStore` decides.
pub fn trust_store(vendors: &[&SigningKey], third_parties: &[&SigningKey]) -> Result<TrustStore> {
    let mut trust = TrustStore::deny_all();
    for key in vendors {
        trust.trust_vendor_key(&key_hex(key))?;
    }
    for key in third_parties {
        trust.trust_third_party_key(&key_hex(key))?;
    }
    Ok(trust)
}

/// The entry name a [`verified_third_party`] manifest declares.
pub const HELPER_ENTRY: &str = "plugin.bin";

/// The reason fixture manifests give for waiving the boundaries this build cannot
/// enforce.
pub const FIXTURE_WAIVER_REASON: &str = "fixture: this build has no primitive for egress \
     denial, filesystem confinement, disk quota, CPU time or an open-file cap behind a child \
     process; accepted so the load pipeline can be exercised past the runtime gate";

/// A verified system manifest: publisher-signed by the host's own key and
/// counter-signed by the vendor key, which is what [`Tier::System`] requires.
///
/// This is how a T0 plugin's token is minted — it goes through
/// [`Manifest::verify`] like every other tier, so a system plugin cannot reach
/// [`crate::host::SystemPluginHost::register`] with a token that no check produced.
/// No waivers: a T0 plugin runs natively, and [`NativeRuntime`] asks for none.
///
/// # Errors
///
/// Whatever signing or verification reports.
///
/// [`Tier::System`]: nau_plugin::Tier::System
/// [`NativeRuntime`]: nau_plugin::runtime::NativeRuntime
pub fn verified_system(
    name: &str,
    capabilities: &[Capability],
    host: &SigningKey,
    vendor: &SigningKey,
) -> Result<VerifiedManifest> {
    let bytes = module(HELPER_ENTRY);
    let manifest = signed(
        name,
        HELPER_ENTRY,
        &bytes,
        capabilities,
        host,
        vendor,
        BTreeMap::new(),
    )?;
    let trust = trust_store(&[vendor], &[])?;
    manifest.verify(&bytes, &trust, FIXTURE_ISSUED_AT)
}

/// A verified third-party manifest with the capabilities given, signed by
/// `publisher` and trusted by a store that trusts exactly that key.
///
/// # Errors
///
/// Whatever signing or verification reports — including the kernel's refusals, which
/// is the point: a capability a third-party plugin may not hold makes this fail
/// rather than produce a manifest that loads.
pub fn verified_third_party(
    name: &str,
    capabilities: &[Capability],
    publisher: &SigningKey,
) -> Result<VerifiedManifest> {
    let bytes = module(HELPER_ENTRY);
    let mut manifest = draft(
        name,
        HELPER_ENTRY,
        &bytes,
        capabilities,
        publisher,
        process_waivers(FIXTURE_WAIVER_REASON),
    )?;
    sign(&mut manifest, publisher)?;
    let trust = trust_store(&[], &[publisher])?;
    manifest.verify(&bytes, &trust, FIXTURE_ISSUED_AT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_plugin::Tier;

    const NOW: u64 = 1_750_000_000;

    fn official_caps() -> [Capability; 3] {
        [
            Capability::MessageSend,
            Capability::StorageOwn,
            Capability::LifecycleRead,
        ]
    }

    #[test]
    fn a_signed_official_manifest_verifies_and_the_counter_signature_is_load_bearing() {
        let publisher = fixture_key(7);
        let vendor = fixture_key(9);
        let bytes = module("market.bin");
        let manifest = signed(
            "com.twinsearth.official.market",
            "market.bin",
            &bytes,
            &official_caps(),
            &publisher,
            &vendor,
            process_waivers(FIXTURE_WAIVER_REASON),
        )
        .expect("signs");

        let trust = trust_store(&[&vendor], &[]).expect("trust");
        let verified = manifest.verify(&bytes, &trust, NOW).expect("verifies");
        assert_eq!(verified.tier, Tier::Official);
        assert!(verified.token.allows(Capability::MessageSend));

        // The waivers are part of the signed payload, so they survived verification
        // rather than being re-derived at load time.
        assert_eq!(
            verified.manifest.waivers.len(),
            process_waivers("x").len(),
            "every waiver the runtime cannot enforce is declared and covered by the signature"
        );

        // The same manifest without the vendor key does not verify: the
        // counter-signature is what authorises the tier.
        let empty = TrustStore::deny_all();
        assert!(manifest.verify(&bytes, &empty, NOW).is_err());
    }

    #[test]
    fn adding_a_waiver_after_signing_invalidates_the_manifest() {
        // `waivers` is inside the signed payload; this pins that it really is, which
        // is what stops a plugin from waiving a boundary after review.
        let vendor = fixture_key(9);
        let bytes = module("market.bin");
        let mut manifest = signed(
            "com.twinsearth.official.market",
            "market.bin",
            &bytes,
            &official_caps(),
            &fixture_key(7),
            &vendor,
            BTreeMap::new(),
        )
        .expect("signs");
        manifest.waivers.insert(
            "network".to_string(),
            "added after the signature".to_string(),
        );
        let trust = trust_store(&[&vendor], &[]).expect("trust");
        let err = manifest
            .verify(&bytes, &trust, NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("manifest_invalid"), "{err}");
    }

    #[test]
    fn the_publisher_did_really_is_the_fingerprint_of_the_signing_key() {
        let key = fixture_key(7);
        // The conformance vector `nau-core` pins for seed [1u8; 32].
        assert_eq!(
            did_of(&fixture_key(1)),
            "did:nau:34750f98bd59fcfc",
            "the DID must come from nau-core's derivation, not from a local format"
        );
        let did = nau_core::identity::Did::parse(&did_of(&key)).expect("parses");
        let public = nau_core::identity::PublicKey::from_hex(&key_hex(&key)).expect("parses");
        assert!(did.matches_public_key(&public));
    }

    #[test]
    fn signing_is_deterministic_so_a_fixture_file_is_reproducible() {
        let publisher = fixture_key(7);
        let bytes = module("market.bin");
        let build = || {
            signed(
                "com.twinsearth.official.market",
                "market.bin",
                &bytes,
                &[Capability::MessageSend],
                &publisher,
                &fixture_key(9),
                process_waivers(FIXTURE_WAIVER_REASON),
            )
            .expect("signs")
        };
        let first = build();
        let second = build();
        assert_eq!(first, second);
        assert_eq!(
            first.digest_hex().expect("digest"),
            second.digest_hex().expect("digest")
        );
    }

    #[test]
    fn the_module_bytes_are_reconstructible_from_the_entry_name() {
        assert_eq!(
            module("market.bin"),
            b"nau-plugins fixture module for market.bin\n".to_vec()
        );
        assert_eq!(
            module_digest(b"nau-plugins fixture module for market.bin\n"),
            module_digest(&module("market.bin"))
        );
    }

    #[test]
    fn the_process_waivers_are_exactly_what_the_runtime_cannot_enforce() {
        use nau_plugin::runtime::{PluginRuntime, ProcessRuntime};
        let runtime = ProcessRuntime::new();
        let waivers = process_waivers("why");
        for (boundary, _why) in runtime.declares().unenforced() {
            assert!(
                waivers.contains_key(boundary.waiver_key()),
                "{boundary:?} must be waived"
            );
            assert_eq!(
                waivers.get(boundary.waiver_key()).map(String::as_str),
                Some("why")
            );
        }
        assert_eq!(waivers.len(), runtime.declares().unenforced().len());
        // And the runtime accepts them, which is the whole point of the helper.
        assert!(runtime
            .declares()
            .require(
                &runtime
                    .declares()
                    .unenforced()
                    .into_iter()
                    .map(|(b, _)| b)
                    .collect::<Vec<_>>(),
                &waivers
            )
            .is_ok());
    }

    #[test]
    fn counter_signing_an_unsigned_manifest_is_refused() {
        let mut manifest = draft(
            "com.twinsearth.official.market",
            "market.bin",
            &module("market.bin"),
            &[Capability::MessageSend],
            &fixture_key(7),
            BTreeMap::new(),
        )
        .expect("drafts");
        let err = counter_sign(&mut manifest, &fixture_key(9)).expect_err("refused");
        assert!(err.to_string().contains("not been signed"), "{err}");
    }

    #[test]
    fn a_manifest_whose_capabilities_were_edited_after_signing_is_refused() {
        let publisher = fixture_key(7);
        let vendor = fixture_key(9);
        let bytes = module("market.bin");
        let mut manifest = signed(
            "com.twinsearth.official.market",
            "market.bin",
            &bytes,
            &[Capability::MessageSend],
            &publisher,
            &vendor,
            BTreeMap::new(),
        )
        .expect("signs");
        manifest
            .capabilities
            .grant
            .push(Capability::KernelPolicyWrite.as_str().to_string());
        let trust = trust_store(&[&vendor], &[]).expect("trust");
        let err = manifest
            .verify(&bytes, &trust, NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("manifest_invalid"), "{err}");
    }

    #[test]
    fn an_older_abi_verifies_and_a_future_one_is_refused() {
        // This test used to be called `a_draft_can_declare_an_abi_this_host_refuses` and
        // asserted that `verify` refuses a `2.9` manifest. From V3.2.1 that is wrong in a
        // way worth spelling out: `2.9` is an **older major**, it is authentic, and it is
        // precisely what the shipped adapter exists to serve. Keeping the old assertion
        // would have left this fixture green while the compatibility feature was dead.
        let trust = trust_store(&[], &[&fixture_key(5)]).expect("trust");

        let mut older = draft_with_abi(
            "io.example.a",
            "2.9",
            "plugin.bin",
            &module("plugin.bin"),
            &Capability::BASIC,
            &fixture_key(5),
            BTreeMap::new(),
        )
        .expect("drafts");
        assert_eq!(older.plugin.abi, "2.9");
        sign(&mut older, &fixture_key(5)).expect("signs");
        assert!(
            older.verify(&module("plugin.bin"), &trust, NOW).is_ok(),
            "an older major must verify: whether this host can *serve* it is the arbiter's \
             question, answered through an adapter"
        );

        // What `verify` does refuse is an ABI from the future: no adapter can translate
        // downwards, so there is no later stage that could accept it.
        let mut future = draft_with_abi(
            "io.example.a",
            "4.0",
            "plugin.bin",
            &module("plugin.bin"),
            &Capability::BASIC,
            &fixture_key(5),
            BTreeMap::new(),
        )
        .expect("drafts");
        sign(&mut future, &fixture_key(5)).expect("signs");
        let err = future
            .verify(&module("plugin.bin"), &trust, NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("abi_incompatible"), "{err}");
        assert!(
            err.to_string().contains("cannot be adapted downwards"),
            "{err}"
        );
    }
}
