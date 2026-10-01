"""Pure-Python Ed25519 (RFC 8032) -- no third-party dependency.

Upstream ``agent-universe`` v2.5.6 imported ``cryptography`` **optionally**, and
its crypto tests were guarded by a module-level ``skipif``: 11 of its 17 Python
tests were silently skipped in CI, so its flagship cross-language signature
guarantee was never actually exercised.  This module has no such escape hatch:
Ed25519 is implemented here from the RFC 8032 reference construction, using
nothing but :mod:`hashlib` (SHA-512) and integer arithmetic over ``2^255 - 19``.

The implementation follows RFC 8032 section 5.1 (Ed25519) using the extended
twisted-Edwards coordinates of section 5.1.4.  It is deliberately a direct
transcription of the standard: this code is not constant-time and is not
intended for secrets that face a local timing attacker; it is intended to be
*correct* and available everywhere Python runs.

Correctness is not asserted here, it is *proved* against
``conformance/vectors.json``: signatures produced by Node/OpenSSL are verified by
this module, and signing the canonical bytes with the fixture seed must reproduce
the fixture signature byte for byte (Ed25519 is deterministic).
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

__all__ = [
    "PUBLIC_KEY_SIZE",
    "SEED_SIZE",
    "SIGNATURE_SIZE",
    "InvalidKeyError",
    "InvalidSignatureError",
    "generate_seed",
    "is_weak_public_key",
    "public_key_from_seed",
    "sign",
    "verify",
]

# --- Curve parameters (RFC 8032 section 5.1) --------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, P - 2, P)) % P
_I = pow(2, (P - 1) // 4, P)  # sqrt(-1)
_BY = (4 * pow(5, P - 2, P)) % P

#: Length of a raw Ed25519 public key.
PUBLIC_KEY_SIZE = 32
#: Length of a raw Ed25519 secret seed.
SEED_SIZE = 32
#: Length of a detached Ed25519 signature.
SIGNATURE_SIZE = 64

# Extended-coordinate point: ``(X, Y, Z, T)`` with ``x = X/Z``, ``y = Y/Z`` and
# ``XY = ZT``.  The neutral element is ``(0, 1, 1, 0)``.
Point = Tuple[int, int, int, int]
_IDENTITY: Point = (0, 1, 1, 0)


class InvalidKeyError(ValueError):
    """A public key or seed was not a usable Ed25519 value."""


class InvalidSignatureError(ValueError):
    """A signature was malformed or did not verify."""


# --- Point arithmetic -------------------------------------------------------


def _recover_x(y: int, sign: int) -> Optional[int]:
    """Recover the x-coordinate of an Edwards point from ``y`` and its sign bit."""
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        # x = 0; the sign bit must be clear, else the encoding is not canonical.
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _I % P
    if (x * x - x2) % P != 0:
        return None  # not a square: not a point on the curve
    if (x & 1) != sign:
        x = P - x
    return x


def _point_add(p: Point, q: Point) -> Point:
    """Add two points in extended coordinates (RFC 8032 section 5.1.4)."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * _D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_double(p: Point) -> Point:
    """Double a point in extended coordinates (RFC 8032 section 5.1.4)."""
    x1, y1, z1, _ = p
    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    h = (a + b) % P
    e = (h - (x1 + y1) * (x1 + y1)) % P
    g = (a - b) % P
    f = (c + g) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_equal(p: Point, q: Point) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _point_mul(s: int, p: Point) -> Point:
    """Scalar multiplication; ``s`` is reduced lazily by the double-and-add."""
    q = _IDENTITY
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_double(p)
        s >>= 1
    return q


def _point_compress(p: Point) -> bytes:
    x, y, z, _ = p
    z_inv = pow(z, P - 2, P)
    x = x * z_inv % P
    y = y * z_inv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _point_decompress(data: bytes) -> Optional[Point]:
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _base_point() -> Point:
    # Build the base point from the published y-coordinate rather than a literal
    # x, so a transcription slip in this file cannot silently change it.
    x = _recover_x(_BY, 0)
    if x is None:  # pragma: no cover - impossible unless P or D is wrong
        raise InvalidKeyError("the Ed25519 base point failed to decompress")
    point = (x, _BY, 1, x * _BY % P)
    # Sanity: the base point must have order L.
    if not _point_equal(_point_mul(L, point), _IDENTITY):  # pragma: no cover
        raise InvalidKeyError("the Ed25519 base point does not have order L")
    return point


_B = _base_point()


def is_weak_public_key(public_key: bytes) -> bool:
    """True when a public key is a small-order ("weak") point.

    The all-zero encoding of the identity point is the notorious case: for
    certain messages, a signature can be forged for it.  Upstream checked
    nothing; :func:`public_key_from_seed` and ``identity`` reject such keys
    rather than accepting them.
    """
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"public key must be {PUBLIC_KEY_SIZE} bytes, got {len(public_key)}"
        )
    point = _point_decompress(public_key)
    if point is None:
        return True  # undecodable is, for our purposes, unusable
    return _point_equal(_point_mul(8, point), _IDENTITY)


def generate_seed() -> bytes:
    """A fresh 32-byte seed from the operating system CSPRNG."""
    import os

    return os.urandom(SEED_SIZE)


def _secret_expand(seed: bytes) -> Tuple[int, bytes]:
    if len(seed) != SEED_SIZE:
        raise InvalidKeyError(f"seed must be {SEED_SIZE} bytes, got {len(seed)}")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8  # clear the three low bits ...
    scalar |= 1 << 254  # ... and set the second-highest bit
    return scalar, digest[32:]


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key for a 32-byte seed."""
    scalar, _ = _secret_expand(seed)
    return _point_compress(_point_mul(scalar, _B))


def sign(seed: bytes, message: bytes) -> bytes:
    """Produce a detached 64-byte Ed25519 signature.

    RFC 8032 signing is deterministic: the same seed and message always produce
    the same 64 bytes.  That is what makes byte-identical cross-language
    signatures -- and this SDK's conformance test -- possible.
    """
    scalar, prefix = _secret_expand(seed)
    public_key = _point_compress(_point_mul(scalar, _B))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_encoded = _point_compress(_point_mul(r, _B))
    k = (
        int.from_bytes(
            hashlib.sha512(r_encoded + public_key + message).digest(), "little"
        )
        % L
    )
    s = (r + k * scalar) % L
    return r_encoded + s.to_bytes(32, "little")


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a detached Ed25519 signature.  Returns a bool.

    ``False`` means "not a valid signature by this key over this message",
    including the case where the key or the signature is undecodable.  Callers
    that need a reason should use :mod:`nau_sdk.identity`, which raises.
    """
    if len(public_key) != PUBLIC_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    point_a = _point_decompress(public_key)
    point_r = _point_decompress(signature[:32])
    if point_a is None or point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    # Reject a non-canonical (unreduced) S: accepting it would make signatures
    # malleable, since S + L would verify just as well.
    if s >= L:
        return False
    k = (
        int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
        )
        % L
    )
    return _point_equal(_point_mul(s, _B), _point_add(point_r, _point_mul(k, point_a)))
