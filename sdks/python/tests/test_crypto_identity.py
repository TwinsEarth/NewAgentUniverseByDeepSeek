"""Identity, Ed25519 and the cross-language conformance fixture.

The point of this file is that the Ed25519 implementation is *proved* against
signatures produced by Node/OpenSSL -- an implementation that shares no code with
this SDK.  Nothing here is skipped: upstream's Python suite guarded its crypto
tests with a module-level ``skipif``, so 11 of its 17 tests never ran in CI and
its flagship cross-language guarantee was never exercised.
"""

from __future__ import annotations

import hashlib
import json
import unittest

try:  # discovered as a package by run_tests.py
    from ._support import CONFORMANCE_SEED, load_repo_version, load_vectors
except ImportError:  # pragma: no cover - run as a plain script
    from _support import CONFORMANCE_SEED, load_repo_version, load_vectors

from nau_sdk import (
    DID_PREFIX,
    DID_PREFIX_LEGACY,
    Did,
    DidError,
    Identity,
    Keypair,
    SignatureError,
    VERSION,
    canonical_json,
    did_from_public_key,
    public_key_from_hex,
    verify_payload,
    verify_payload_bound,
)
from nau_sdk import _ed25519

MD = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"


class TestVersion(unittest.TestCase):
    def test_version_is_read_from_the_repository_version_file(self) -> None:
        # The value is not hardcoded anywhere in the SDK; it is read at import.
        self.assertEqual(VERSION, load_repo_version())

    def test_version_file_is_found(self) -> None:
        from nau_sdk import VERSION_FILE

        self.assertIsNotNone(VERSION_FILE)
        self.assertTrue(str(VERSION_FILE).endswith("VERSION"))

    def test_no_hardcoded_version_literal_in_the_package(self) -> None:
        """Grep-style check: the release version must not be restated as a literal.

        Upstream v2.5.6 restated it in four Python files and all four drifted to
        ``2.3.6`` while the package claimed ``2.5.6``.  Only *string literals*
        shaped like a release (``"1.2.3"``) count -- prose that discusses the
        drift, RFC section numbers and ``127.0.0.1`` are not version claims.
        """
        import os
        import re

        package_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "nau_sdk"
        )
        literal = re.compile(r"['\"]\d+\.\d+\.\d+['\"]")
        rfc_section = re.compile(r"section\s+\d+\.\d+\.\d+", re.IGNORECASE)
        offenders = []
        for root, _dirs, files in os.walk(package_dir):
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                with open(path, "r", encoding="utf-8") as handle:
                    for lineno, line in enumerate(handle, 1):
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        if not literal.search(line):
                            continue
                        if rfc_section.search(line):
                            continue
                        if "127.0.0.1" in line or "0.0.0" in line:
                            # Host/port and the deliberate not-a-release sentinel.
                            continue
                        offenders.append(f"{name}:{lineno}: {stripped}")
        self.assertEqual(
            offenders,
            [],
            "the version must live only in the repository VERSION file; found: "
            + "; ".join(offenders),
        )
        # Sanity: the check really would catch a hardcoded release number.
        self.assertTrue(literal.search('VERSION = "1.0.1"'))


class TestKeyDerivationAgainstTheFixture(unittest.TestCase):
    def test_derived_public_key_and_dids_match_the_fixture(self) -> None:
        vectors = load_vectors()
        seed = bytes.fromhex(vectors["seed_hex"])
        keypair = Keypair.from_seed(seed)

        self.assertEqual(keypair.public_key.hex(), vectors["identity"]["public_key_hex"])
        self.assertEqual(keypair.public_key.hex(), MD)
        self.assertEqual(keypair.did.as_str(), vectors["identity"]["did_nau"])
        self.assertEqual(keypair.legacy_did.as_str(), vectors["identity"]["did_legacy"])
        self.assertEqual(
            did_from_public_key(keypair.public_key), vectors["identity"]["did_nau"]
        )
        self.assertEqual(
            did_from_public_key(keypair.public_key, DID_PREFIX_LEGACY),
            vectors["identity"]["did_legacy"],
        )
        self.assertEqual(
            keypair.did.fingerprint,
            hashlib.sha256(keypair.public_key).hexdigest()[:16],
        )

    def test_the_seed_is_the_fixture_seed(self) -> None:
        self.assertEqual(CONFORMANCE_SEED.hex(), load_vectors()["seed_hex"])

    def test_legacy_did_binds_to_the_same_key(self) -> None:
        legacy = Did.parse(load_vectors()["identity"]["did_legacy"])
        self.assertTrue(legacy.matches_public_key(bytes.fromhex(MD)))
        self.assertEqual(legacy.prefix, DID_PREFIX_LEGACY)
        self.assertEqual(legacy.as_str(), "did:aip:34750f98bd59fcfc")


class TestEd25519Primitives(unittest.TestCase):
    def test_public_key_derivation_is_deterministic(self) -> None:
        self.assertEqual(
            Keypair.from_seed(CONFORMANCE_SEED).public_key,
            Keypair.from_seed(CONFORMANCE_SEED).public_key,
        )

    def test_signing_is_deterministic_and_verifies(self) -> None:
        keypair = Keypair.from_seed(CONFORMANCE_SEED)
        message = b"hello"
        first = keypair.sign(message)
        second = keypair.sign(message)
        self.assertEqual(first, second, "Ed25519 must be deterministic")
        self.assertEqual(len(first), 64)
        self.assertTrue(keypair.verify(message, first))

    def test_a_tampered_message_or_signature_fails(self) -> None:
        keypair = Keypair.from_seed(CONFORMANCE_SEED)
        signature = keypair.sign(b"hello")
        self.assertFalse(keypair.verify(b"hellp", signature))
        self.assertFalse(keypair.verify(b"hello", bytes([signature[0] ^ 1]) + signature[1:]))
        self.assertFalse(keypair.verify(b"hello", signature[:63]))
        self.assertFalse(keypair.verify(b"hello", b""))

    def test_a_signature_from_a_different_key_fails(self) -> None:
        other = Keypair.from_seed(bytes([2] * 32))
        self.assertFalse(other.verify(b"hello", Keypair.from_seed(CONFORMANCE_SEED).sign(b"hello")))

    def test_unreduced_s_is_rejected_to_prevent_malleability(self) -> None:
        keypair = Keypair.from_seed(CONFORMANCE_SEED)
        signature = keypair.sign(b"malleable")
        s = int.from_bytes(signature[32:], "little")
        malleable = signature[:32] + (s + _ed25519.L).to_bytes(32, "little")
        self.assertFalse(
            keypair.verify(b"malleable", malleable),
            "S + L must not verify: otherwise signatures are malleable",
        )

    def test_the_base_point_has_order_l(self) -> None:
        self.assertTrue(
            _ed25519._point_equal(
                _ed25519._point_mul(_ed25519.L, _ed25519._B), _ed25519._IDENTITY
            )
        )

    def test_the_cofactor_times_a_small_order_point_is_the_identity(self) -> None:
        # The all-zero encoding is the identity point, which is small-order.
        self.assertTrue(_ed25519.is_weak_public_key(bytes(32)))
        self.assertFalse(_ed25519.is_weak_public_key(bytes.fromhex(MD)))

    def test_seeds_and_public_keys_reject_wrong_lengths(self) -> None:
        with self.assertRaises(DidError):
            Keypair.from_seed(b"\x01" * 31)
        with self.assertRaises(_ed25519.InvalidKeyError):
            _ed25519.public_key_from_seed(b"\x01" * 31)
        with self.assertRaises(DidError):
            public_key_from_hex("00")
        with self.assertRaises(DidError):
            public_key_from_hex("zz" * 32)


class TestConformanceFixture(unittest.TestCase):
    """The whole fixture: identity, canonical bytes, verify *and* re-sign.

    Re-signing is the strongest available check: Ed25519 is deterministic, so the
    64 bytes produced here must equal the bytes OpenSSL produced.  If they do
    not, this implementation is wrong -- the test must not be weakened.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = load_vectors()
        cls.seed = bytes.fromhex(cls.vectors["seed_hex"])
        cls.keypair = Keypair.from_seed(cls.seed)
        cls.public_key = cls.keypair.public_key

    def test_identity_matches(self) -> None:
        self.assertEqual(
            self.public_key.hex(), self.vectors["identity"]["public_key_hex"]
        )
        self.assertEqual(self.keypair.did.as_str(), self.vectors["identity"]["did_nau"])

    def test_every_payload_canonicalizes_verifies_and_resigns(self) -> None:
        payloads = self.vectors["payloads"]
        self.assertGreaterEqual(len(payloads), 10, "the fixture must be complete")
        ids = []
        for entry in payloads:
            ids.append(entry["id"])
            with self.subTest(entry=entry["id"]):
                parsed = json.loads(entry["input_json"])
                canonical = canonical_json(parsed)
                canonical_bytes = canonical.encode("utf-8")

                # 1. canonical bytes are byte-for-byte the fixture's.
                self.assertEqual(canonical, entry["canonical"])
                self.assertEqual(canonical_bytes.hex(), entry["canonical_hex"])

                signature = bytes.fromhex(entry["signature_hex"])
                self.assertEqual(len(signature), 64)

                # 2. the Node/OpenSSL signature verifies under this verifier.
                self.assertTrue(
                    _ed25519.verify(self.public_key, signature, canonical_bytes),
                    "a signature produced by OpenSSL must verify here",
                )
                self.assertTrue(self.keypair.verify(canonical_bytes, signature))

                # 3. signing the same bytes reproduces the same 64 bytes.
                self.assertEqual(
                    self.keypair.sign(canonical_bytes).hex(),
                    entry["signature_hex"],
                    "deterministic signing must reproduce the fixture signature",
                )

                # 4. the high-level API accepts the object that still carries its
                #    signature field, because canonicalization strips it.
                identity = Identity.from_seed(self.seed)
                signed = dict(parsed)
                signed["signature"] = entry["signature_hex"]
                identity.verify_payload(signed, entry["signature_hex"])
                verify_payload(signed, entry["signature_hex"], self.public_key)
                verify_payload_bound(
                    signed, entry["signature_hex"], self.public_key, identity.did.as_str()
                )

        self.assertIn("upstream-v2.5.6-compat", ids)
        self.assertIn("astral-plane-key-ordering", ids)
        self.assertIn("uint64-max", ids)

    def test_the_upstream_vector_is_byte_identical_including_the_signature(self) -> None:
        entry = next(
            p
            for p in self.vectors["payloads"]
            if p["id"] == "upstream-v2.5.6-compat"
        )
        self.assertEqual(
            entry["canonical"],
            '{"capabilities":["text-generation","mcp"],"did":"did:aip:34750f98bd59fcfc",'
            '"name":"CrossLang","stake":100}',
        )
        self.assertEqual(
            entry["signature_hex"],
            "e14d3f9e8204ea185ea4ba32a8117f262095ab9dac1352e1a7964ce36d3355c2"
            "88dd6804ffa7daeb5f6eba9f30428f52702a75fd3efbb6a62555a7f24665da0e",
            "must equal the signature upstream's own Rust test pins",
        )
        canonical = entry["canonical"].encode("utf-8")
        self.assertEqual(self.keypair.sign(canonical).hex(), entry["signature_hex"])

    def test_every_rejection_raises(self) -> None:
        from nau_sdk import CanonicalError

        for entry in self.vectors["rejections"]:
            with self.subTest(entry=entry["id"]):
                parsed = json.loads(entry["input_json"])
                with self.assertRaises(CanonicalError):
                    canonical_json(parsed)

    def test_tampering_with_any_byte_breaks_verification(self) -> None:
        for entry in self.vectors["payloads"]:
            with self.subTest(entry=entry["id"]):
                canonical = entry["canonical"].encode("utf-8")
                signature = bytes.fromhex(entry["signature_hex"])
                tampered = bytearray(canonical)
                tampered[-1] ^= 0x01
                self.assertFalse(
                    _ed25519.verify(self.public_key, signature, bytes(tampered))
                )
                self.assertFalse(
                    _ed25519.verify(self.public_key, signature, canonical[:-1])
                )


class TestHighLevelIdentityApi(unittest.TestCase):
    def test_sign_and_verify_a_payload(self) -> None:
        identity = Identity.from_seed(CONFORMANCE_SEED)
        card = {
            "did": identity.did.as_str(),
            "name": "CrossLang",
            "capabilities": ["text-generation", "mcp"],
            "stake": 100,
            "signature": "",
        }
        signature = identity.sign_payload(card)
        card["signature"] = signature
        identity.verify_payload(card, signature)

    def test_a_wrong_signature_raises_signature_error(self) -> None:
        identity = Identity.from_seed(CONFORMANCE_SEED)
        with self.assertRaises(SignatureError):
            identity.verify_payload({"a": 1}, "00" * 64)
        with self.assertRaises(SignatureError):
            identity.verify_payload({"a": 1}, "")
        with self.assertRaises(SignatureError):
            identity.verify_payload({"a": 1}, "zz" * 64)

    def test_a_payload_that_cannot_canonicalize_never_gets_signed(self) -> None:
        from nau_sdk import NonIntegerNumber, RootNotObject

        identity = Identity.from_seed(CONFORMANCE_SEED)
        with self.assertRaises(NonIntegerNumber):
            identity.sign_payload({"amount": 1.5})
        with self.assertRaises(RootNotObject):
            identity.sign_payload([1, 2, 3])

    def test_tampering_is_detected(self) -> None:
        identity = Identity.from_seed(CONFORMANCE_SEED)
        signed = {"did": identity.did.as_str(), "name": "CrossLang", "signature": ""}
        signed["signature"] = identity.sign_payload(signed)
        tampered = dict(signed, name="Tampered")
        with self.assertRaises(SignatureError):
            identity.verify_payload(tampered, signed["signature"])

    def test_a_signature_cannot_be_attributed_to_another_did(self) -> None:
        me = Identity.from_seed(CONFORMANCE_SEED)
        other = Identity.from_seed(bytes([2] * 32))
        signed = {"n": 1, "signature": ""}
        signature = me.sign_payload(signed)
        signed["signature"] = signature

        with self.assertRaises(DidError):
            verify_payload_bound(signed, signature, me.public_key, other.did)
        # The bare verifier does not care about the DID, only the key.
        verify_payload(signed, signature, me.public_key)

    def test_raw_signing_round_trips(self) -> None:
        identity = Identity.from_seed(CONFORMANCE_SEED)
        signature = identity.sign_raw(b"raw bytes")
        identity.verify_raw(b"raw bytes", signature)
        with self.assertRaises(SignatureError):
            identity.verify_raw(b"other bytes", signature)

    def test_generate_produces_a_usable_identity(self) -> None:
        identity = Identity.generate()
        self.assertNotEqual(identity.did, Identity.generate().did)
        signed = {"x": 1, "signature": ""}
        signed["signature"] = identity.sign_payload(signed)
        identity.verify_payload(signed, signed["signature"])


class TestDidParsing(unittest.TestCase):
    def test_accepts_both_prefixes(self) -> None:
        self.assertEqual(
            Did.parse("did:nau:34750f98bd59fcfc").as_str(), "did:nau:34750f98bd59fcfc"
        )
        parsed = Did.parse("did:aip:34750f98bd59fcfc")
        self.assertEqual(parsed.prefix, DID_PREFIX_LEGACY)
        self.assertEqual(parsed.fingerprint, "34750f98bd59fcfc")

    def test_rejects_wrong_length(self) -> None:
        for text in (
            "did:nau:short",
            "did:nau:34750f98bd59fcf",
            "did:nau:34750f98bd59fcfc1",
            "did:nau:",
        ):
            with self.subTest(text=text):
                with self.assertRaises(DidError):
                    Did.parse(text)

    def test_rejects_uppercase_hex(self) -> None:
        with self.assertRaises(DidError):
            Did.parse("did:nau:34750F98BD59FCFC")

    def test_rejects_a_wrong_or_missing_prefix(self) -> None:
        for text in (
            "did:key:34750f98bd59fcfc",
            "34750f98bd59fcfc",
            "nau:34750f98bd59fcfc",
            "",
        ):
            with self.subTest(text=text):
                with self.assertRaises(DidError):
                    Did.parse(text)

    def test_rejects_non_hex_fingerprints(self) -> None:
        for text in ("did:nau:34750f98bd59fcfg", "did:nau:34750f98bd59fcf!", "did:nau:" + "z" * 16):
            with self.subTest(text=text):
                with self.assertRaises(DidError):
                    Did.parse(text)

    def test_matches_public_key_ignores_the_prefix(self) -> None:
        key = bytes.fromhex(MD)
        self.assertTrue(Did.parse("did:nau:34750f98bd59fcfc").matches_public_key(key))
        self.assertTrue(Did.parse("did:aip:34750f98bd59fcfc").matches_public_key(key))
        self.assertFalse(Did.parse("did:nau:0000000000000000").matches_public_key(key))

    def test_matches_public_key_is_false_for_a_bad_key_length(self) -> None:
        self.assertFalse(Did.parse("did:nau:34750f98bd59fcfc").matches_public_key(b"x"))

    def test_equality_and_hash(self) -> None:
        a = Did.parse("did:nau:34750f98bd59fcfc")
        b = Did.parse("did:nau:34750f98bd59fcfc")
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertEqual(len({a, b}), 1)

    def test_public_key_hex_round_trip(self) -> None:
        self.assertEqual(public_key_from_hex(MD), bytes.fromhex(MD))

    def test_the_all_zero_key_is_refused_as_a_weak_point(self) -> None:
        with self.assertRaises(DidError):
            public_key_from_hex("00" * 32)

    def test_the_live_prefix_is_nau(self) -> None:
        self.assertEqual(DID_PREFIX, "did:nau:")
        self.assertEqual(DID_PREFIX_LEGACY, "did:aip:")


if __name__ == "__main__":
    unittest.main()
