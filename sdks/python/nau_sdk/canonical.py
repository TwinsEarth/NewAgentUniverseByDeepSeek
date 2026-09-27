"""Canonical JSON payloads -- the byte-level contract between Rust, Python and
JavaScript.

The rules implemented here are the ones pinned by
``conformance/vectors.json`` and by
``crates/nau-core/src/identity/canonical.rs``:

1. The value must be a JSON **object** at the root.
2. Every object key named ``signature`` is dropped, **at every depth**.
3. Object keys are emitted in ascending **Unicode code point** order.
   (``sorted()`` on ``str`` is already code-point order; a byte or locale sort
   would disagree, and JavaScript's default ``Array.prototype.sort()`` compares
   UTF-16 code units, which disagrees for astral-plane characters.)
4. No whitespace: separators are exactly ``,`` and ``:``.
5. Strings are emitted as raw UTF-8.  Only ``"``, ``\\`` and the seven control
   characters with short escapes are escaped; every other control character uses
   a lowercase ``\\u00xx`` escape.  Nothing else is escaped.
6. Numbers must be **integers**.  Floats are refused with
   :class:`NonIntegerNumber` rather than silently reformatted: ``100``,
   ``100.0`` and ``1e2`` print differently in Rust, Python and JavaScript, so a
   signed payload containing a float cannot be reproduced byte for byte.  Money
   therefore travels as integer minor units.
7. Nesting is bounded to :data:`MAX_DEPTH` levels, so a hostile document cannot
   overflow the stack during signing.

Why not ``json.dumps``?  Its output happens to match rules 3-5, but rule 6
cannot be enforced through it (``json.dumps`` happily renders ``1.0`` as
``1.0``), rule 2 has no hook, and rule 7 is unchecked.  Building the bytes here
means every rule is checked on the way out and a failure **raises** -- upstream's
``unwrap_or(Value::Null)`` signed the literal payload ``null`` instead.
"""

from __future__ import annotations

import math
from typing import Any

__all__ = [
    "MAX_DEPTH",
    "SIGNATURE_FIELD",
    "CanonicalError",
    "NonIntegerNumber",
    "NumberOutOfRange",
    "RootNotObject",
    "SerializeError",
    "TooDeep",
    "canonical_json",
    "canonical_payload",
    "canonical_string",
]

#: The object key removed at every depth before signing/verifying.
SIGNATURE_FIELD = "signature"

#: Maximum object/array nesting accepted while canonicalizing.
MAX_DEPTH = 64


class CanonicalError(ValueError):
    """Base class for every canonicalization failure.

    Subclasses :class:`ValueError` so that callers who only want "this payload
    is not signable" can catch one ordinary built-in exception.
    """


class RootNotObject(CanonicalError):
    """The root of a signing payload was not a JSON object."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__(
            f"canonical payload root must be a JSON object, found {kind}"
        )


class NonIntegerNumber(CanonicalError):
    """A float (or exponent-form) number appeared in a signing payload."""

    def __init__(self, value: Any) -> None:
        self.value = value
        super().__init__(
            f"non-integer number `{_render_number(value)}` in canonical payload: "
            "signing payloads admit integers only (carry money as integer minor "
            "units, never as a float)"
        )


class NumberOutOfRange(CanonicalError):
    """An integer did not fit in ``i64``/``u64``."""

    def __init__(self, value: Any) -> None:
        self.value = value
        super().__init__(
            f"number `{_render_number(value)}` does not fit in i64 or u64, which "
            "canonical payloads require"
        )


class TooDeep(CanonicalError):
    """The value nested deeper than :data:`MAX_DEPTH`."""

    def __init__(self) -> None:
        super().__init__(f"canonical payload nests deeper than {MAX_DEPTH} levels")


class SerializeError(CanonicalError):
    """The value could not be serialized to JSON at all.

    Raised instead of the upstream behaviour of signing the four bytes ``null``.
    """


def _render_number(value: Any) -> str:
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "inf" if value > 0 else "-inf"
    return repr(value)


def _kind_of(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


# ``int`` in Python is unbounded; the wire format is not.  Accept exactly the
# union of i64 and u64, matching the Rust implementation, so that a value that
# canonicalizes here also canonicalizes there.
_I64_MIN = -(2**63)
_U64_MAX = 2**64 - 1

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _coerce_object(value: Any) -> Any:
    """Turn model objects into plain JSON values, or return the value unchanged.

    The domain models in :mod:`nau_sdk.models` expose ``to_json()``; honouring it
    here means ``canonical_payload(card)`` works without the caller remembering
    to convert first.  Tuples become arrays (JSON has no tuple).
    """
    hook = getattr(value, "to_json", None)
    if callable(hook):
        return hook()
    if isinstance(value, tuple):
        return list(value)
    return value


def _write_string(out: list[str], s: str) -> None:
    out.append('"')
    for ch in s:
        escaped = _SHORT_ESCAPES.get(ch)
        if escaped is not None:
            out.append(escaped)
        elif ch < "\x20":
            out.append("\\u%04x" % ord(ch))
        else:
            # Raw, including every non-ASCII character: rule 5.
            out.append(ch)
    out.append('"')


def _write_value(out: list[str], value: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise TooDeep()
    value = _coerce_object(value)
    if value is None:
        out.append("null")
        return
    if value is True:
        out.append("true")
        return
    if value is False:
        out.append("false")
        return
    # NOTE: ``bool`` is a subclass of ``int``, so the bool checks come first.
    if isinstance(value, int):
        if value < _I64_MIN or value > _U64_MAX:
            raise NumberOutOfRange(value)
        out.append(str(value))
        return
    if isinstance(value, float):
        # No float is ever accepted: even an integral one would have to be
        # re-rendered, and ``100`` and ``100.0`` format differently per language.
        raise NonIntegerNumber(value)
    if isinstance(value, str):
        _write_string(out, value)
        return
    if isinstance(value, dict):
        out.append("{")
        keys = [k for k in value.keys() if k != SIGNATURE_FIELD]
        for key in keys:
            if not isinstance(key, str):
                raise SerializeError(
                    f"object keys must be strings, found {_kind_of(key)}: {key!r}"
                )
        # ``sorted`` over ``str`` compares by Unicode code point: rule 3.
        keys.sort()
        for i, key in enumerate(keys):
            if i:
                out.append(",")
            _write_string(out, key)
            out.append(":")
            _write_value(out, value[key], depth + 1)
        out.append("}")
        return
    if isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write_value(out, item, depth + 1)
        out.append("]")
        return
    raise SerializeError(
        f"cannot canonicalize a value of type {_kind_of(value)}: {value!r}"
    )


def canonical_string(obj: Any) -> str:
    """Canonicalize any value (no root-object requirement).

    Useful for hashing sub-structures.  Signing should use
    :func:`canonical_json` / :func:`canonical_payload`, which also enforce the
    root-object rule.
    """
    out: list[str] = []
    _write_value(out, obj, 0)
    return "".join(out)


def canonical_json(obj: Any) -> str:
    """Canonicalize a signing payload, enforcing every rule including rule 1.

    Raises a :class:`CanonicalError` subclass on any violation; it never returns
    a fallback.
    """
    if isinstance(obj, float):
        # A float is never a valid root, but the reason it is refused is that it
        # is not an integer -- reporting ``RootNotObject`` here would bury the
        # more specific rule behind the structural one.
        raise NonIntegerNumber(obj)
    if not hasattr(obj, "keys"):
        # ``to_json()`` may still produce an object, so coerce once before the
        # root check to keep ``canonical_json(card)`` working.
        coerced = _coerce_object(obj)
        if not isinstance(coerced, dict):
            raise RootNotObject(_kind_of(obj))
        obj = coerced
    return canonical_string(obj)


def canonical_payload(obj: Any) -> bytes:
    """The exact bytes to be signed for ``obj``: rule 1 applied, UTF-8 encoded."""
    return canonical_json(obj).encode("utf-8")
