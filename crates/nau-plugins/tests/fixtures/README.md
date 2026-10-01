# Signed manifest fixtures

Eleven `plugin.json` manifests, generated deterministically by
[`nau_plugins::sign`](../../src/sign.rs) and asserted by
[`tests/manifest_fixtures.rs`](../manifest_fixtures.rs). Three load, eight are
refused — the refusals carry the exact `LoadRefusal` code in their message, because
the gate that re-checks them branches on the code and not on prose.

They exist so that the load pipeline, the isolation tests and the certification work
have real signed artefacts to point at instead of hand-written JSON that no signature
covers.

## Regenerating

```text
$env:NAU_PLUGIN_WRITE_FIXTURES="1"; cargo +1.85.0 test -p nau-plugins --locked --test manifest_fixtures -- --test-threads=1
cargo +1.85.0 test -p nau-plugins --locked --test manifest_fixtures
```

The writer only runs when `NAU_PLUGIN_WRITE_FIXTURES=1`; an ordinary test run never
touches the source tree, and `every_fixture_file_on_disk_is_exactly_what_this_build_produces`
fails if a file has drifted from the manifest this build produces. `--test-threads=1`
is for the writer only: the reader tests must not run while files are being replaced.

Ed25519 (RFC 8032) is deterministic, so the same seed and the same manifest always
produce byte-identical signatures: regeneration is a no-op unless something really
changed.

## Keys

Every key is `SigningKey::from_bytes(&[seed; 32])` — a one-byte seed, printed here so
a reader can recompute any fixture from the crate alone. **These are fixture keys.**
A 256-value seed space is trivially enumerable and none of these may ever sign
anything real.

| Role | Seed | Public key (hex) | DID |
|---|---|---|---|
| host (T0 publisher) | `3` | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` | `did:nau:b62e867fa2f33afe` |
| market publisher | `7` | `ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c` | `did:nau:fe812c12f3ab4ce6` |
| vendor (counter-signer) | `9` | `fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618` | `did:nau:dbc298251c51321b` |
| certified publisher | `11` | `66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a` | `did:nau:fdf72a088f18f739` |
| third-party publisher | `5` | `6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1` | `did:nau:7599776c3085e3f9` |
| stranger publisher | `13` | `91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a` | `did:nau:defe6330f78fcc11` |

The DIDs are derived by `nau-core` (`did:nau:` + the first 8 bytes of SHA-256 of the
raw key, lower-case hex), not formatted here, so a fixture's `plugin.publisher` really
is the fingerprint of the key that signed it.

## The trust store

Unless a fixture's row says otherwise, verify with the store an operator would
configure:

* vendor keys: the vendor key (seed `9`) — it may counter-sign official and certified
  plugins;
* third-party keys: the third-party publisher (seed `5`), trusted explicitly.

```rust
let trust = nau_plugins::sign::trust_store(&[&vendor], &[&third_party_publisher])?;
```

## Module bytes

A manifest covers `plugin.module_sha256`, and verification hashes the artefact it is
handed. No binary is committed, so the covered bytes are one printable line:

```text
nau-plugins fixture module for <entry>\n
```

`nau_plugins::sign::module("<entry>")` produces exactly that, and
`sign::module_digest(bytes)` is the SHA-256 that must appear in `module_sha256`. The
one exception is `hostile-module-mismatch.json`, whose row names the wrong artefact to
hand it.

## The fixtures

| File | Plugin | Entry | Outcome | Module sha256 |
|---|---|---|---|---|
| `official-market.json` | `com.twinsearth.official.market` | `market.bin` | **verifies**, tier Official, basic set | `568075ba…acf3` |
| `official-market-full-set.json` | `com.twinsearth.official.market` | `market.bin` | refused `capability_not_permitted` (`agent:card:create`, `vendor-team`) | `568075ba…acf3` |
| `official-market-settle.json` | `com.twinsearth.official.market` | `market.bin` | refused `capability_not_permitted` (`economy:settle`, `vendor-team`) | `568075ba…acf3` |
| `certified-analytics.json` | `com.twinsearth.certified.analytics` | `analytics.bin` | **verifies**, tier Certified, basic set | `28070cc9…d8b6` |
| `thirdparty-analytics.json` | `io.example.analytics` | `analytics.bin` | **verifies**, tier ThirdParty, basic set | `28070cc9…d8b6` |
| `thirdparty-dht-overreach.json` | `io.example.analytics` | `analytics.bin` | refused `capability_not_permitted` (`net:dht:read`) | `28070cc9…d8b6` |
| `hostile-module-mismatch.json` | `com.twinsearth.official.market` | `hostile.bin` | refused `module_digest_mismatch` | `6cbf61bd…00f1` |
| `hostile-capabilities-edited.json` | `com.twinsearth.official.market` | `market.bin` | refused `manifest_invalid` | `568075ba…acf3` |
| `hostile-no-counter-signature.json` | `com.twinsearth.official.market` | `market.bin` | refused `counter_signature_missing` | `568075ba…acf3` |
| `hostile-untrusted-publisher.json` | `io.example.analytics` | `analytics.bin` | refused `untrusted_publisher` | `28070cc9…d8b6` |
| `hostile-future-abi.json` | `io.example.analytics` | `analytics.bin` | refused `abi_incompatible` | `28070cc9…d8b6` |

Per fixture, in the order the kernel checks them:

1. **`official-market.json`** — publisher-signed by seed `7` and counter-signed by the
   trusted vendor (seed `9`). Capabilities: `plugin:lifecycle:read`,
   `plugin:message:send`, `plugin:storage:own`. Manifest digest
   `34e194fb…eda65`. The task's market capability set also includes
   `agent:card:create` and `economy:settle`; see the next two rows for why this
   fixture does not carry them.
2. **`official-market-full-set.json`** — the same plugin asking for the set a market
   plugin *needs*: the basic three plus `agent:card:create` and `economy:settle`. At
   the Official tier every non-basic capability resolves through
   `Grant::RequiresApproval(Approval::VendorTeam)`, and `CapabilityToken::issue` takes
   no approvals — so the kernel refuses the whole request, all-or-nothing, naming
   `agent:card:create` (the first one it reaches) and `vendor-team`. This is the
   kernel working correctly, and it is why the loadable market fixture carries the set
   the tier holds unconditionally.
3. **`official-market-settle.json`** — isolates `economy:settle`, so the
   `RequiresApproval` path has one unambiguous fixture. Digest
   `a19c3532…b58f`.
4. **`certified-analytics.json`** — double-signed, basic capabilities only, so it
   verifies. Digest `c9c64463…a3ab`.
5. **`thirdparty-analytics.json`** — publisher-signed only, no counter-signature, and
   it verifies **only** because the operator's trust store lists seed `5`. Against
   `TrustStore::deny_all()` it is refused with `untrusted_publisher`. Digest
   `774cd1b4…1771`.
6. **`thirdparty-dht-overreach.json`** — the negative capability fixture: the same
   third-party plugin asking for `net:dht:read`. Refused with
   `capability_not_permitted`, naming `net:dht:read` and the tier.
7. **`hostile-module-mismatch.json`** — genuinely signed, and it verifies against its
   *own* artefact (`sign::module("hostile.bin")`). Hand it
   `sign::module("market.bin")` and the digest check refuses with
   `module_digest_mismatch`. This is the "manifest is legal but the payload was
   swapped" case.
8. **`hostile-capabilities-edited.json`** — `kernel:policy:write` appended to
   `capabilities.grant` *after* signing. The recomputed digest no longer matches the
   signed one, so it is refused with `manifest_invalid` before any signature is even
   checked. This is the fixture that proves the capability list is inside the signed
   payload.
9. **`hostile-no-counter-signature.json`** — an official manifest with a valid
   publisher signature and `counter_sig`/`counter_key` removed: refused with
   `counter_signature_missing`. A publisher key alone cannot authorise a
   counter-signature tier.
10. **`hostile-untrusted-publisher.json`** — a real signature by seed `13`, a key no
    trust store here lists: refused with `untrusted_publisher`. Adding
    `trust.trust_third_party_key(...)` for seed `13` makes the same bytes verify,
    which is asserted in the test.
11. **`hostile-future-abi.json`** — `plugin.abi = "4.0"`, newer than this host's
    `3.2`: refused with `abi_incompatible`. Reading it through the validating parser
    (`Manifest::parse`) refuses one step earlier with the same code.

## Waivers

Every fixture declares the five waivers `ProcessRuntime` cannot enforce on this build
(`network`, `filesystem_confinement`, `disk_bytes`, `cpu_ms`, `max_open_files`),
generated by `sign::process_waivers(...)` from the runtime's own declaration rather
than written out by hand. `waivers` is part of the **signed** payload, so a fixture
cannot have one added after review — `adding_a_waiver_after_signing_invalidates_the_manifest`
in `src/sign.rs` pins that.

They are there so the load pipeline can be exercised past the runtime gate. A fixture
without them is refused with `isolation_not_enforceable` before anything interesting
happens, which is a different test from the ones these fixtures exist for.

## What these fixtures do not cover

* **A blacklist refusal.** `blacklist` is keyed on a name and a module digest and is
  checked by the load pipeline, not by `Manifest::verify`; a manifest cannot carry its
  own condemnation. `nau-plugin`'s own tests cover `Blacklist::require_allowed`.
* **A wasm runtime request.** There is no `runtime` field in the V2.2.2 manifest
  schema: `WasmRuntime` refuses every start regardless of what a manifest says, so a
  fixture could not demonstrate anything the kernel does not already refuse.
* **A real process-escape attempt.** The hostile fixtures here are hostile *manifests*.
  A hostile *plugin* needs a binary, and the only process plugin this crate ships is
  the echoing one in `src/bin/`.
