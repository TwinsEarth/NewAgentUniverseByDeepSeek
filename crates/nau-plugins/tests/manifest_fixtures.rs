//! The signed manifest fixtures: three loadable plugins and eight refusals.
//!
//! Every fixture under `tests/fixtures/` is generated deterministically by
//! [`nau_plugins::sign`] from the one-byte key seeds documented in
//! `tests/fixtures/README.md`, and this file asserts two things about each:
//!
//! * verifying it produces the *exact* outcome it documents — for the hostile ones,
//!   the exact refusal code, because a gate that re-checks these needs the code and
//!   not a prose match;
//! * the file on disk is still the artefact this build produces, so a fixture cannot
//!   drift away from the code that generated it.
//!
//! Regeneration is explicit:
//!
//! ```text
//! NAU_PLUGIN_WRITE_FIXTURES=1 cargo test -p nau-plugins --test manifest_fixtures
//! ```
//!
//! Without the variable the writer returns immediately, so an ordinary test run
//! never touches the source tree.

mod common;

use std::collections::BTreeSet;

use nau_plugin::{Capability, LoadRefusal, Tier};
use nau_plugins::sign;

/// The literal codes these fixtures assert, pinned here so a rename in the kernel
/// breaks this test rather than silently weakening it.
#[test]
fn the_refusal_codes_this_suite_asserts_are_the_kernels() {
    assert_eq!(LoadRefusal::ManifestInvalid.code(), "manifest_invalid");
    assert_eq!(
        LoadRefusal::ModuleDigestMismatch.code(),
        "module_digest_mismatch"
    );
    assert_eq!(
        LoadRefusal::CounterSignatureMissing.code(),
        "counter_signature_missing"
    );
    assert_eq!(
        LoadRefusal::UntrustedPublisher.code(),
        "untrusted_publisher"
    );
    assert_eq!(LoadRefusal::AbiIncompatible.code(), "abi_incompatible");
    assert_eq!(
        LoadRefusal::CapabilityNotPermitted.code(),
        "capability_not_permitted"
    );
    assert_eq!(
        LoadRefusal::CapabilityNotApproved.code(),
        "capability_not_approved"
    );
    assert_eq!(LoadRefusal::NameInvalid.code(), "name_invalid");
}

#[test]
fn every_fixture_has_the_outcome_it_documents() {
    for fixture in common::fixtures().expect("fixtures build") {
        match &fixture.expected {
            common::Expected::Verified { tier, capabilities } => {
                let verified = fixture
                    .verify()
                    .unwrap_or_else(|e| panic!("`{}` must verify, but: {e}", fixture.file));
                assert_eq!(&verified.tier, tier, "{}", fixture.file);
                assert_eq!(verified.id.as_str(), fixture.name(), "{}", fixture.file);
                for capability in *capabilities {
                    assert!(
                        verified.token.allows(*capability),
                        "{} must hold {capability}",
                        fixture.file
                    );
                }
                assert_eq!(
                    verified.token.granted().len(),
                    capabilities.len(),
                    "{} must hold exactly what it documents",
                    fixture.file
                );
            }
            common::Expected::Refused(code) => {
                let err = fixture
                    .verify()
                    .err()
                    .unwrap_or_else(|| panic!("`{}` must be refused", fixture.file));
                assert!(
                    err.to_string().contains(code),
                    "`{}` must be refused with `{code}`, got: {err}",
                    fixture.file
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The loadable fixtures, named individually so a reader can find them.
// ---------------------------------------------------------------------------

#[test]
fn the_official_market_fixture_is_double_signed_and_holds_the_basic_set() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "official-market.json")
        .expect("the fixture exists");
    let verified = fixture.verify().expect("verifies");

    assert_eq!(verified.tier, Tier::Official);
    assert_eq!(verified.id.as_str(), "com.twinsearth.official.market");
    // Double-signed: the publisher's key AND a trusted vendor's counter-signature.
    assert_eq!(
        fixture.manifest.signature.publisher_key,
        sign::key_hex(&common::publisher_key())
    );
    assert_eq!(
        fixture.manifest.signature.counter_key.as_deref(),
        Some(sign::key_hex(&common::vendor_key()).as_str())
    );
    assert!(fixture.manifest.signature.counter_sig.is_some());
    // The waivers are inside the signed payload, so they survived verification.
    assert_eq!(
        fixture.manifest.waivers.len(),
        common::fixture_waivers().len()
    );

    // Verifying without the vendor key is a refusal, which is what the
    // counter-signature is for.
    let err = fixture
        .manifest
        .verify(
            &fixture.module,
            &nau_plugin::TrustStore::deny_all(),
            common::NOW,
        )
        .expect_err("an unconfigured trust store must refuse");
    assert!(err.to_string().contains("untrusted_publisher"), "{err}");
}

#[test]
fn the_market_capability_set_a_market_plugin_needs_is_refused_and_says_who_must_approve() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "official-market-full-set.json")
        .expect("the fixture exists");
    assert_eq!(
        fixture
            .manifest
            .requested_capabilities()
            .expect("parses")
            .len(),
        4
    );

    let err = fixture.verify().expect_err("must be refused");
    let text = err.to_string();
    // `capability_not_approved`, not `capability_not_permitted`. The capability *is*
    // permitted at the official tier; it has simply not been approved yet, and the two
    // outcomes send an operator to different places -- one to the authority named in the
    // message, the other to a dead end. They used to share a code, which also left
    // `capability_not_approved` in the vocabulary with nothing able to emit it.
    assert!(text.contains("capability_not_approved"), "{text}");
    assert!(text.contains("agent:card:create"), "{text}");
    assert!(text.contains("vendor-team"), "{text}");
}

#[test]
fn economy_settle_resolves_through_requires_approval_and_the_kernel_refuses_it() {
    // The fixture, first.
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "official-market-settle.json")
        .expect("the fixture exists");
    let err = fixture.verify().expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains("capability_not_approved"), "{text}");
    assert!(text.contains("economy:settle"), "{text}");
    assert!(text.contains("vendor-team"), "{text}");

    // And the kernel directly, so the refusal is attributed to the decision matrix
    // rather than to anything this crate does.
    assert_eq!(
        Capability::EconomySettle.decision(Tier::Official),
        nau_plugin::Grant::RequiresApproval(nau_plugin::Approval::VendorTeam)
    );
    let err = nau_plugin::CapabilityToken::issue(
        "com.twinsearth.official.market",
        Tier::Official,
        &[Capability::EconomySettle],
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        common::NOW,
    )
    .expect_err("`issue` has no way to carry an approval, so it refuses");
    let text = err.to_string();
    assert!(
        text.contains("needs approval from the vendor-team"),
        "{text}"
    );
}

#[test]
fn the_certified_fixture_is_double_signed_with_basic_capabilities_only() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "certified-analytics.json")
        .expect("the fixture exists");
    let verified = fixture.verify().expect("verifies");
    assert_eq!(verified.tier, Tier::Certified);
    assert!(fixture.manifest.signature.counter_sig.is_some());
    for capability in Capability::ALL {
        if !capability.is_basic() {
            assert!(
                !verified.token.allows(capability),
                "a certified fixture with {capability} would be a different fixture"
            );
        }
    }
}

#[test]
fn the_third_party_fixture_verifies_only_because_the_operator_trusted_its_key() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "thirdparty-analytics.json")
        .expect("the fixture exists");
    let verified = fixture.verify().expect("verifies");
    assert_eq!(verified.tier, Tier::ThirdParty);
    assert!(
        fixture.manifest.signature.counter_sig.is_none(),
        "a third-party manifest has no counter-signature to carry"
    );

    // An unconfigured host trusts nobody, so the same manifest is refused.
    let err = fixture
        .manifest
        .verify(
            &fixture.module,
            &nau_plugin::TrustStore::deny_all(),
            common::NOW,
        )
        .expect_err("must be refused");
    assert!(err.to_string().contains("untrusted_publisher"), "{err}");
}

#[test]
fn the_third_party_plugin_asking_for_the_dht_is_refused_with_capability_not_permitted() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "thirdparty-dht-overreach.json")
        .expect("the fixture exists");
    let err = fixture.verify().expect_err("must be refused");
    let text = err.to_string();
    assert!(
        text.contains(LoadRefusal::CapabilityNotPermitted.code()),
        "{text}"
    );
    assert!(text.contains("net:dht:read"), "{text}");
    assert!(text.contains("3rd"), "{text}");
}

// ---------------------------------------------------------------------------
// The hostile fixtures, one test each, because a future gate re-checks these.
// ---------------------------------------------------------------------------

#[test]
fn a_module_that_does_not_match_its_digest_is_refused_with_module_digest_mismatch() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "hostile-module-mismatch.json")
        .expect("the fixture exists");
    // The manifest itself is genuinely signed: with its own artefact it verifies,
    // which is what makes this fixture about the *module* rather than a forgery.
    let own = sign::module("hostile.bin");
    assert!(fixture
        .manifest
        .verify(&own, &fixture.trust, common::NOW)
        .is_ok());

    let err = fixture.verify().expect_err("must be refused");
    let text = err.to_string();
    assert!(
        text.contains(LoadRefusal::ModuleDigestMismatch.code()),
        "{text}"
    );
    assert!(text.contains("entry artefact"), "{text}");
}

#[test]
fn capabilities_edited_after_signing_are_refused_with_manifest_invalid() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "hostile-capabilities-edited.json")
        .expect("the fixture exists");
    assert!(
        fixture
            .manifest
            .capabilities
            .grant
            .contains(&"kernel:policy:write".to_string()),
        "the edit is what the fixture is for"
    );
    let err = fixture.verify().expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains(LoadRefusal::ManifestInvalid.code()), "{text}");
    assert!(text.contains("digest mismatch"), "{text}");
}

#[test]
fn an_official_manifest_without_a_counter_signature_is_refused() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "hostile-no-counter-signature.json")
        .expect("the fixture exists");
    assert!(fixture.manifest.signature.counter_sig.is_none());
    assert!(fixture.manifest.signature.counter_key.is_none());
    let err = fixture.verify().expect_err("must be refused");
    let text = err.to_string();
    assert!(
        text.contains(LoadRefusal::CounterSignatureMissing.code()),
        "{text}"
    );
    assert!(
        text.contains("requires a vendor counter-signature"),
        "{text}"
    );
}

#[test]
fn a_publisher_the_trust_store_does_not_list_is_refused() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "hostile-untrusted-publisher.json")
        .expect("the fixture exists");
    // The signature is real: signed by the stranger's own key, and the DID in the
    // manifest is that key's fingerprint.
    assert_eq!(
        fixture.manifest.signature.publisher_key,
        sign::key_hex(&common::stranger_key())
    );
    assert_eq!(
        fixture.manifest.plugin.publisher,
        sign::did_of(&common::stranger_key())
    );

    let err = fixture.verify().expect_err("must be refused");
    let text = err.to_string();
    assert!(
        text.contains(LoadRefusal::UntrustedPublisher.code()),
        "{text}"
    );
    assert!(text.contains("trusted key list"), "{text}");

    // Trusting the key explicitly is what changes the answer.
    let mut trust = common::trust().expect("trust");
    trust
        .trust_third_party_key(&sign::key_hex(&common::stranger_key()))
        .expect("trusts");
    assert!(fixture
        .manifest
        .verify(&fixture.module, &trust, common::NOW)
        .is_ok());
}

#[test]
fn a_future_abi_minor_is_refused_with_abi_incompatible() {
    let fixture = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .find(|f| f.file == "hostile-future-abi.json")
        .expect("the fixture exists");
    assert_eq!(fixture.manifest.plugin.abi, "4.0");
    let err = fixture.verify().expect_err("must be refused");
    let text = err.to_string();
    assert!(text.contains(LoadRefusal::AbiIncompatible.code()), "{text}");
    assert!(text.contains("newer than this host"), "{text}");

    // The same refusal arrives one step earlier if the file is read through the
    // validating parser, which is the path a host would take.
    let err = common::parse_fixture("hostile-future-abi.json").expect_err("must be refused");
    assert!(err.to_string().contains("abi_incompatible"), "{err}");
}

// ---------------------------------------------------------------------------
// The files themselves.
// ---------------------------------------------------------------------------

#[test]
fn every_fixture_file_on_disk_is_exactly_what_this_build_produces() {
    for fixture in common::fixtures().expect("fixtures build") {
        let on_disk = common::read_fixture(fixture.file)
            .unwrap_or_else(|e| panic!("`{}` must exist and parse: {e}", fixture.file));
        assert_eq!(
            on_disk, fixture.manifest,
            "`{}` has drifted from the manifest this build produces; regenerate with \
             NAU_PLUGIN_WRITE_FIXTURES=1",
            fixture.file
        );
        // Equal manifests have equal digests by definition, so this also proves the
        // signature on disk covers the same bytes.
        assert_eq!(
            on_disk.digest_hex().expect("digest"),
            fixture.manifest.digest_hex().expect("digest"),
            "`{}`",
            fixture.file
        );
    }
}

#[test]
fn the_fixture_directory_holds_no_stale_manifest() {
    let expected: BTreeSet<String> = common::fixtures()
        .expect("fixtures build")
        .into_iter()
        .map(|f| f.file.to_string())
        .collect();
    let mut actual: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(common::fixture_dir()).expect("the directory exists") {
        let path = entry.expect("readable").path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                actual.insert(name.to_string());
            }
        }
    }
    assert_eq!(
        actual, expected,
        "the fixture directory and the fixture list disagree; a stale manifest is a fixture that \
         no test asserts"
    );
}

#[test]
fn fixtures_are_written_only_when_the_environment_asks_for_it() {
    let asked = std::env::var("NAU_PLUGIN_WRITE_FIXTURES").unwrap_or_default();
    if asked != "1" {
        // The ordinary path: this test asserts nothing was written by accident.
        return;
    }
    let fixtures = common::fixtures().expect("fixtures build");
    common::write_fixtures(&fixtures).expect("writes");
    for fixture in &fixtures {
        let reread = common::read_fixture(fixture.file).expect("re-reads");
        assert_eq!(&reread, &fixture.manifest, "{}", fixture.file);
    }
}

/// The key material `tests/fixtures/README.md` documents, pinned here.
///
/// A seed that changes silently would change every signature in the directory and
/// the README with it; this test makes that a failure instead. Regenerate the table
/// with `NAU_PLUGIN_WRITE_FIXTURES=1` and the same command that regenerates the
/// fixtures.
#[test]
fn the_documented_fixture_keys_are_the_ones_the_fixtures_use() {
    let documented: [(u8, &str, &str); 6] = [
        (
            common::HOST_SEED,
            "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
            "did:nau:b62e867fa2f33afe",
        ),
        (
            common::PUBLISHER_SEED,
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
            "did:nau:fe812c12f3ab4ce6",
        ),
        (
            common::VENDOR_SEED,
            "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
            "did:nau:dbc298251c51321b",
        ),
        (
            common::CERTIFIED_SEED,
            "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a",
            "did:nau:fdf72a088f18f739",
        ),
        (
            common::THIRD_PARTY_SEED,
            "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1",
            "did:nau:7599776c3085e3f9",
        ),
        (
            common::STRANGER_SEED,
            "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a",
            "did:nau:defe6330f78fcc11",
        ),
    ];
    for (seed, key_hex, did) in documented {
        let key = sign::fixture_key(seed);
        assert_eq!(sign::key_hex(&key), key_hex, "seed {seed}");
        assert_eq!(sign::did_of(&key), did, "seed {seed}");
    }
}

/// The manifest digests `tests/fixtures/README.md` documents, pinned here.
///
/// These are recomputed from the canonical form on every run, so a change to the
/// canonicaliser or to the manifest schema shows up as a digest change rather than as
/// a silently different fixture.
#[test]
fn the_documented_manifest_digests_are_the_ones_the_fixtures_have() {
    let documented: [(&str, &str); 4] = [
        (
            "official-market.json",
            "34be10c63b40f9fc129a35e7ea1483e21b7b5d0abff438c676a7ccaf888ee2a2",
        ),
        (
            "official-market-settle.json",
            "8a0aa13e6d65dabe72d1ef0066eb9550a047252c19789eb546feac480d298701",
        ),
        (
            "certified-analytics.json",
            "4ce1d7fabd47a3b1bac64e86d51328eed468e030e6cd98079cdb4d8770028558",
        ),
        (
            "thirdparty-analytics.json",
            "482f00bdb4063de12b496c04e82f987f4312496b8938f9aad5007073f6404b01",
        ),
    ];
    // Every drifted fixture is reported in one run rather than one per attempt: when the
    // manifest schema gains a field, all of them move at once, and a test that stops at
    // the first turns a single schema change into four rounds of editing.
    let mut wrong: Vec<String> = Vec::new();
    for (file, digest) in documented {
        let manifest = common::read_fixture(file).expect("reads");
        let actual = manifest.digest_hex().expect("digest");
        if actual != digest {
            wrong.push(format!("{file}: documented {digest}, actual {actual}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} fixture(s) have a different canonical digest from the documented one -- a change \
         to the manifest schema, to the canonicaliser, or to a signed field shows up here:\n  {}",
        wrong.len(),
        wrong.join("\n  ")
    );
}
