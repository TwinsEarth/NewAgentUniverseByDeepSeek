"""Canonicalization tests, including every rejection the fixture pins."""

from __future__ import annotations

import json
import unittest

try:  # discovered as a package by run_tests.py
    from ._support import load_vectors
except ImportError:  # pragma: no cover - run as a plain script
    from _support import load_vectors

from nau_sdk import (
    MAX_DEPTH,
    CanonicalError,
    NonIntegerNumber,
    NumberOutOfRange,
    RootNotObject,
    SerializeError,
    TooDeep,
    canonical_json,
    canonical_payload,
    canonical_string,
)


class TestCanonicalRules(unittest.TestCase):
    def test_keys_are_sorted_and_whitespace_is_absent(self) -> None:
        self.assertEqual(canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')
        self.assertEqual(canonical_json({}), "{}")

    def test_signature_is_dropped_at_every_depth(self) -> None:
        value = {
            "outer": 1,
            "signature": "deadbeef",
            "nested": {"inner": True, "signature": "cafe"},
            "list": [{"signature": "x", "kept": 1}],
        }
        self.assertEqual(
            canonical_json(value),
            '{"list":[{"kept":1}],"nested":{"inner":true},"outer":1}',
        )

    def test_only_the_exact_key_name_signature_is_dropped(self) -> None:
        self.assertEqual(
            canonical_json({"signature2": 1, "Signature": 2, "sig": 3}),
            '{"Signature":2,"sig":3,"signature2":1}',
        )

    def test_non_ascii_is_raw_utf8_and_controls_are_minimally_escaped(self) -> None:
        self.assertEqual(canonical_json({"zh": "智能体宇宙"}), '{"zh":"智能体宇宙"}')
        self.assertEqual(
            canonical_json({"s": 'a"b\\c\nd\te\x01f\x1f'}),
            '{"s":"a\\"b\\\\c\\nd\\te\\u0001f\\u001f"}',
        )
        # The seven short escapes, and only those, are used.
        self.assertEqual(
            canonical_json({"s": "\b\t\n\f\r"}),
            '{"s":"\\b\\t\\n\\f\\r"}',
        )
        # 0x7f and 0x80 are NOT control characters for JSON escaping purposes.
        self.assertEqual(canonical_json({"s": "\x7f"}), '{"s":"\x7f"}')

    def test_keys_are_ordered_by_code_point_not_utf16_code_unit(self) -> None:
        value = {"\U0001f600": "astral", "\ue000": "bmp-private-use", "a": "ascii"}
        # U+0061 < U+E000 < U+1F600. A default JS sort would put U+1F600 first.
        self.assertEqual(
            canonical_json(value),
            '{"a":"ascii","\ue000":"bmp-private-use","\U0001f600":"astral"}',
        )

    def test_prefix_ordering_shorter_key_first(self) -> None:
        self.assertEqual(
            canonical_json({"zero": 0, "z": None}), '{"z":null,"zero":0}'
        )

    def test_integers_across_the_full_range(self) -> None:
        self.assertEqual(canonical_json({"n": -(2**63)}), '{"n":-9223372036854775808}')
        self.assertEqual(canonical_json({"n": 2**63 - 1}), '{"n":9223372036854775807}')
        self.assertEqual(canonical_json({"n": 2**64 - 1}), '{"n":18446744073709551615}')

    def test_out_of_range_integers_are_refused(self) -> None:
        with self.assertRaises(NumberOutOfRange):
            canonical_json({"n": 2**64})
        with self.assertRaises(NumberOutOfRange):
            canonical_json({"n": -(2**63) - 1})

    def test_booleans_are_not_integers(self) -> None:
        self.assertEqual(canonical_json({"a": True, "b": False}), '{"a":true,"b":false}')

    def test_root_must_be_an_object(self) -> None:
        for value in ([1, 2, 3], "hello", 1, None, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(CanonicalError) as ctx:
                    canonical_json(value)
                if isinstance(value, float):
                    self.assertIsInstance(ctx.exception, NonIntegerNumber)
                else:
                    self.assertIsInstance(ctx.exception, RootNotObject)

    def test_canonical_string_allows_a_non_object_root(self) -> None:
        # Used for hashing sub-structures, so it has no root rule.
        self.assertEqual(canonical_string([1, {"a": None}]), '[1,{"a":null}]')
        self.assertEqual(canonical_string("hi"), '"hi"')

    def test_canonical_payload_is_utf8_bytes(self) -> None:
        payload = canonical_payload({"zh": "中"})
        self.assertIsInstance(payload, bytes)
        self.assertEqual(payload, '{"zh":"中"}'.encode("utf-8"))


class TestFloatsAreRejectedEverywhere(unittest.TestCase):
    """Floats are the single most important cross-language fix."""

    def test_top_level_nested_and_in_arrays(self) -> None:
        cases = [
            {"amount": 1.0},
            {"amount": 1.5},
            {"a": {"b": 2.5}},
            {"a": [1, 2.5]},
            {"a": [{"b": -0.0}]},
            {"a": [[[0.25]]]},
        ]
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(NonIntegerNumber):
                    canonical_json(case)

    def test_exponent_notation_parsed_as_a_float_is_refused(self) -> None:
        for text in ('{"amount":1e2}', '{"amount":1E2}', '{"amount":-1.5e-3}'):
            with self.subTest(text=text):
                with self.assertRaises(NonIntegerNumber):
                    canonical_json(json.loads(text))

    def test_nan_and_infinity_are_refused(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(NonIntegerNumber):
                    canonical_json({"a": value})

    def test_an_integral_float_is_still_a_float(self) -> None:
        # 100 == 100.0 in Python, but they must not canonicalize to the same
        # bytes, so the *type* is what is checked.
        with self.assertRaises(NonIntegerNumber):
            canonical_json({"n": 100.0})

    def test_money_like_decimals_from_json_are_refused(self) -> None:
        with self.assertRaises(NonIntegerNumber):
            canonical_json({"price": json.loads("12.50")})


class TestDepthCap(unittest.TestCase):
    def test_the_cap_is_64(self) -> None:
        self.assertEqual(MAX_DEPTH, 64)

    @staticmethod
    def _nest(depth: int) -> dict:
        value: object = 1
        for _ in range(depth):
            value = {"n": value}
        return value  # type: ignore[return-value]

    def test_within_the_cap_is_accepted(self) -> None:
        canonical_json(self._nest(1))
        canonical_json(self._nest(32))

    def test_beyond_the_cap_is_refused(self) -> None:
        with self.assertRaises(TooDeep):
            canonical_json(self._nest(MAX_DEPTH + 10))

    def test_a_deep_array_is_refused_too(self) -> None:
        value: object = 1
        for _ in range(MAX_DEPTH + 10):
            value = [value]
        with self.assertRaises(TooDeep):
            canonical_json({"a": value})

    def test_hostile_nesting_does_not_overflow_the_stack(self) -> None:
        # 5000 levels would blow a naive recursive serializer; it must be a
        # clean error instead.
        with self.assertRaises(TooDeep):
            canonical_json(self._nest(5000))


class TestSerializationFailureIsLoud(unittest.TestCase):
    def test_unknown_types_raise_instead_of_signing_null(self) -> None:
        class Boom:
            pass

        with self.assertRaises(SerializeError):
            canonical_json({"a": Boom()})

    def test_sets_and_bytes_are_not_silently_coerced(self) -> None:
        with self.assertRaises(SerializeError):
            canonical_json({"a": {1, 2}})
        with self.assertRaises(SerializeError):
            canonical_json({"a": b"bytes"})

    def test_non_string_keys_are_refused(self) -> None:
        with self.assertRaises(SerializeError):
            canonical_json({1: "x"})

    def test_a_failing_to_json_hook_raises(self) -> None:
        class Boom:
            def to_json(self) -> dict:
                raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            canonical_json(Boom())

    def test_the_error_hierarchy_is_catchable_as_value_error(self) -> None:
        for exc in (NonIntegerNumber(1.0), NumberOutOfRange(2**64), TooDeep(), SerializeError("x")):
            with self.subTest(exc=type(exc).__name__):
                self.assertIsInstance(exc, CanonicalError)
                self.assertIsInstance(exc, ValueError)


class TestFixturePayloads(unittest.TestCase):
    """Every fixture payload must canonicalize to the pinned bytes."""

    def test_every_payload_matches_canonical_and_canonical_hex(self) -> None:
        vectors = load_vectors()
        self.assertTrue(vectors["payloads"])
        for entry in vectors["payloads"]:
            with self.subTest(entry=entry["id"]):
                parsed = json.loads(entry["input_json"])
                derived = canonical_json(parsed)
                self.assertEqual(derived, entry["canonical"])
                self.assertEqual(derived.encode("utf-8").hex(), entry["canonical_hex"])
                self.assertEqual(canonical_payload(parsed).hex(), entry["canonical_hex"])


class TestFixtureRejections(unittest.TestCase):
    """Every entry in ``rejections`` must raise the matching error type.

    ``vectors.json`` is the contract, so the mapping is written out here rather
    than inferred: an unknown error name fails the test instead of silently
    passing.
    """

    EXPECTED = {
        "non_integer_number": NonIntegerNumber,
        "root_not_object": RootNotObject,
        "too_deep": TooDeep,
        "number_out_of_range": NumberOutOfRange,
        "serialize": SerializeError,
    }

    def test_every_rejection_raises_the_matching_error(self) -> None:
        vectors = load_vectors()
        rejections = vectors["rejections"]
        self.assertTrue(rejections)
        seen = set()
        for entry in rejections:
            with self.subTest(entry=entry["id"]):
                kind = entry["error"]
                self.assertIn(
                    kind,
                    self.EXPECTED,
                    f"vectors.json names an error this suite does not know: {kind}",
                )
                parsed = json.loads(entry["input_json"])
                with self.assertRaises(self.EXPECTED[kind]):
                    canonical_json(parsed)
                seen.add(entry["id"])
        # The three float cases and both root cases are required by the contract.
        self.assertIn("float-value", seen)
        self.assertIn("root-is-array", seen)


if __name__ == "__main__":
    unittest.main()
