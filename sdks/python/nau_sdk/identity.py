"""Identity: Ed25519 key material, ``did:nau:`` derivation and canonical signing.

DID derivation
--------------

.. code-block:: text

   did:nau:<first 8 bytes of SHA-256(raw 32-byte Ed25519 public key), lowercase hex>

That is 16 hex characters, the same construction upstream v2.5.6 uses with the
prefix ``did:aip:``.  :data:`DID_PREFIX_LEGACY` is accepted on **parse** so that
identities minted by upstream can still be read after migration, but this SDK
only ever mints ``did:nau:``.

A DID is a *fingerprint*, and SHA-256 is not invertible, so a DID alone can
never verify a signature: the verifier needs the public key, transported
separately, and must check that the key actually hashes to the DID.  That
binding check is :meth:`Did.matches_public_key`, and
:func:`verify_payload_bound` performs it as part of verification.  Upstream
checked the DID by convention only.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Optional

from . import _ed25519
from .canonical import canonical_payload
from .errors import AuthorizationError, DidError, SignatureError

__all__ = [
    "DID_PREFIX",
    "DID_PREFIX_LEGACY",
    "DID_FINGERPRINT_BYTES",
    "PUBLIC_KEY_BYTES",
    "SIGNATURE_BYTES",
    "Did",
    "Keypair",
    "Identity",
    "did_from_public_key",
    "public_key_from_hex",
    "verify_payload",
    "verify_payload_bound",
]

#: Prefix minted for new identities.
DID_PREFIX = "did:nau:"
#: Prefix minted by upstream ``agent-universe``; accepted when parsing.
DID_PREFIX_LEGACY = "did:aip:"
#: Number of SHA-256 bytes retained for the DID fingerprint.
DID_FINGERPRINT_BYTES = 8
#: Raw Ed25519 public key length.
PUBLIC_KEY_BYTES = 32
#: Raw Ed25519 signature length.
SIGNATURE_BYTES = 64

_HEX_DIGITS = set("0123456789abcdef")


def _fingerprint(public_key: bytes) -> str:
    if len(public_key) != PUBLIC_KEY_BYTES:
        raise DidError(
            f"public key must be {PUBLIC_KEY_BYTES} raw bytes, got {len(public_key)}"
        )
    return hashlib.sha256(public_key).hexdigest()[: DID_FINGERPRINT_BYTES * 2]


def did_from_public_key(pub: bytes, prefix: str = DID_PREFIX) -> str:
    """Derive a DID string from a raw 32-byte public key."""
    return f"{prefix}{_fingerprint(pub)}"


def public_key_from_hex(text: str) -> bytes:
    """Decode a 64-character lowercase-hex public key, rejecting weak keys."""
    if not isinstance(text, str):
        raise DidError(f"public key must be a hex string, got {type(text).__name__}")
    if len(text) != PUBLIC_KEY_BYTES * 2:
        raise DidError(
            f"public key must be {PUBLIC_KEY_BYTES * 2} hex characters, got {len(text)}"
        )
    if any(ch not in _HEX_DIGITS for ch in text):
        raise DidError("public key hex must be lowercase [0-9a-f]")
    raw = bytes.fromhex(text)
    # Hardening beyond upstream: an all-zero (identity) key is a small-order
    # point, and signatures are forgeable for it.  Refuse it at parse time.
    if _ed25519.is_weak_public_key(raw):
        raise DidError(
            "public key is a small-order (weak) point and is not usable"
        )
    return raw


def _signature_from_hex(text: str) -> bytes:
    if not isinstance(text, str):
        raise SignatureError(
            f"signature must be a hex string, got {type(text).__name__}"
        )
    if len(text) != SIGNATURE_BYTES * 2:
        raise SignatureError(
            f"signature must be {SIGNATURE_BYTES * 2} hex characters, got {len(text)}"
        )
    if any(ch not in _HEX_DIGITS for ch in text):
        raise SignatureError("signature hex must be lowercase [0-9a-f]")
    return bytes.fromhex(text)


class Did:
    """A decentralized identifier, e.g. ``did:nau:34750f98bd59fcfc``.

    Use :meth:`parse`; the constructor is not part of the public contract.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    @staticmethod
    def parse(text: str) -> "Did":
        """Parse and validate a DID string.

        Accepts both ``did:nau:`` and the legacy ``did:aip:``.  Rejects anything
        whose fingerprint is not exactly 16 lowercase hex characters, so a typo
        cannot silently become a distinct identity.
        """
        if not isinstance(text, str):
            raise DidError(f"DID must be a string, got {type(text).__name__}")
        rest: Optional[str] = None
        for prefix in (DID_PREFIX, DID_PREFIX_LEGACY):
            if text.startswith(prefix):
                rest = text[len(prefix) :]
                break
        if rest is None:
            raise DidError(
                f"`{text}` must start with `{DID_PREFIX}` or `{DID_PREFIX_LEGACY}`"
            )
        if len(rest) != DID_FINGERPRINT_BYTES * 2 or any(
            ch not in _HEX_DIGITS for ch in rest
        ):
            raise DidError(
                f"`{text}` must carry exactly {DID_FINGERPRINT_BYTES * 2} lowercase "
                "hex characters after the prefix"
            )
        return Did(text)

    @staticmethod
    def from_public_key(public_key: bytes, prefix: str = DID_PREFIX) -> "Did":
        """The DID a raw 32-byte public key fingerprints."""
        return Did(did_from_public_key(public_key, prefix))

    @staticmethod
    def from_fingerprint_hex(prefix: str, fingerprint_hex: str) -> "Did":
        return Did.parse(f"{prefix}{fingerprint_hex}")

    @property
    def prefix(self) -> str:
        """The method prefix (``did:nau:`` or ``did:aip:``)."""
        if self._value.startswith(DID_PREFIX_LEGACY):
            return DID_PREFIX_LEGACY
        return DID_PREFIX

    @property
    def fingerprint(self) -> str:
        """The 16-character fingerprint."""
        return self._value[len(self.prefix) :]

    def matches_public_key(self, public_key: bytes) -> bool:
        """True when this DID is the fingerprint of ``public_key``.

        This is the binding check that makes "verify with this DID" meaningful.
        The prefix is intentionally irrelevant, so a migrated ``did:aip:``
        identity still binds to its key.
        """
        try:
            expected = _fingerprint(public_key)
        except DidError:
            return False
        return hmac.compare_digest(self.fingerprint, expected)

    def as_str(self) -> str:
        """The DID as a string."""
        return self._value

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"Did({self._value})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Did):
            return self._value == other._value
        if isinstance(other, str):
            return self._value == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)


class Keypair:
    """An Ed25519 keypair.

    ``seed`` is exposed because the conformance fixture needs it; treat it as a
    secret.  The derived signing scalar is never stored beyond a single call.
    """

    __slots__ = ("_seed", "_public_key")

    def __init__(self, seed: bytes) -> None:
        if len(seed) != _ed25519.SEED_SIZE:
            raise DidError(
                f"seed must be {_ed25519.SEED_SIZE} bytes, got {len(seed)}"
            )
        self._seed = bytes(seed)
        self._public_key = _ed25519.public_key_from_seed(self._seed)

    @classmethod
    def generate(cls) -> "Keypair":
        """A keypair from operating-system entropy."""
        return cls(_ed25519.generate_seed())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Keypair":
        """Deterministically derive a keypair from a 32-byte seed.

        This is the constructor the cross-language conformance vectors use.
        """
        if not isinstance(seed, (bytes, bytearray, memoryview)):
            raise DidError(f"seed must be bytes, got {type(seed).__name__}")
        return cls(bytes(seed))

    @classmethod
    def from_seed_hex(cls, text: str) -> "Keypair":
        if not isinstance(text, str) or len(text) != 64 or any(
            ch not in _HEX_DIGITS for ch in text
        ):
            raise DidError("seed hex must be 64 lowercase hex characters")
        return cls(bytes.fromhex(text))

    @property
    def seed(self) -> bytes:
        """The 32-byte secret seed.  Handle with care."""
        return self._seed

    @property
    def seed_hex(self) -> str:
        """The 64-character hex secret seed."""
        return self._seed.hex()

    @property
    def public_key(self) -> bytes:
        """The raw 32-byte public key."""
        return self._public_key

    @property
    def public_key_hex(self) -> str:
        """The 64-character hex public key."""
        return self._public_key.hex()

    @property
    def did(self) -> Did:
        """The self-certifying DID for this keypair."""
        return Did.from_public_key(self._public_key)

    @property
    def legacy_did(self) -> Did:
        """The upstream-compatible (``did:aip:``) DID, for migration."""
        return Did.from_public_key(self._public_key, DID_PREFIX_LEGACY)

    def sign(self, message: bytes) -> bytes:
        """Sign raw bytes, returning a detached 64-byte signature."""
        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise SignatureError(
                f"message must be bytes, got {type(message).__name__}"
            )
        return _ed25519.sign(self._seed, bytes(message))

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a raw signature against raw bytes."""
        return _ed25519.verify(self._public_key, bytes(signature), bytes(message))

    def __repr__(self) -> str:
        # Never print the secret.
        return f"Keypair({self.did})"


class Identity:
    """A keypair together with the signing helpers built on canonical payloads."""

    __slots__ = ("_keypair",)

    def __init__(self, keypair: Keypair) -> None:
        if not isinstance(keypair, Keypair):
            raise DidError("Identity requires a Keypair")
        self._keypair = keypair

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Keypair.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Identity":
        return cls(Keypair.from_seed(seed))

    @classmethod
    def from_seed_hex(cls, text: str) -> "Identity":
        return cls(Keypair.from_seed_hex(text))

    @property
    def keypair(self) -> Keypair:
        return self._keypair

    @property
    def did(self) -> Did:
        return self._keypair.did

    @property
    def public_key(self) -> bytes:
        """The raw 32-byte public key (see also :attr:`public_key_hex`)."""
        return self._keypair.public_key

    @property
    def public_key_hex(self) -> str:
        return self._keypair.public_key_hex

    @property
    def seed(self) -> bytes:
        return self._keypair.seed

    # -- canonical payload signing ------------------------------------------

    def sign_payload(self, obj: Any) -> str:
        """Sign the canonical payload of ``obj``, returning hex.

        Raises whatever :func:`nau_sdk.canonical_payload` raises -- never signs a
        fallback payload.
        """
        payload = canonical_payload(obj)
        return self._keypair.sign(payload).hex()

    def verify_payload(self, obj: Any, signature_hex: str) -> None:
        """Verify a hex signature over the canonical payload of ``obj``.

        ``obj`` must still contain its ``signature`` field; canonicalization
        removes it.  The DID-to-key binding is checked too.  Raises on failure.
        """
        verify_payload_bound(obj, signature_hex, self._keypair.public_key, self.did)

    def sign_raw(self, message: bytes) -> str:
        """Sign raw bytes (no canonicalization), returning hex."""
        return self._keypair.sign(message).hex()

    def verify_raw(self, message: bytes, signature_hex: str) -> None:
        """Verify a hex signature over raw bytes.  Raises on failure."""
        signature = _signature_from_hex(signature_hex)
        if not self._keypair.verify(message, signature):
            raise SignatureError("raw signature did not verify")

    def sign_as(self, obj: Any, expected_did: Did) -> str:
        """Sign ``obj`` only if it is addressed to this identity.

        Refuses to act as somebody else, which is the check upstream only
        performed at the domain layer (and only sometimes).
        """
        if Did(str(expected_did)) != self.did:
            raise AuthorizationError(
                f"{self.did} may not sign for {expected_did}"
            )
        return self.sign_payload(obj)

    def __repr__(self) -> str:
        return f"Identity({self.did})"


def verify_payload(obj: Any, sig_hex: str, public_key: bytes) -> None:
    """Verify a hex signature over the canonical payload of ``obj``.

    Raises :class:`SignatureError` on any failure; returns ``None`` on success so
    that a caller cannot accidentally ignore a boolean.
    """
    if not sig_hex:
        raise SignatureError("signature is empty")
    signature = _signature_from_hex(sig_hex)
    payload = canonical_payload(obj)
    if not _ed25519.verify(public_key, signature, payload):
        raise SignatureError(
            "signature did not verify over the canonical payload"
        )


def verify_payload_bound(
    obj: Any, sig_hex: str, public_key: bytes, did: Any
) -> None:
    """Verify a signature **and** that ``did`` is the fingerprint of ``public_key``.

    This is the check to use when an identity arrives from the network: verifying
    against an attacker-supplied key while trusting a different DID is the
    classic impersonation bug.
    """
    parsed = Did.parse(did) if isinstance(did, str) else did
    if not isinstance(parsed, Did):
        raise DidError(f"expected a Did or DID string, got {type(did).__name__}")
    if not parsed.matches_public_key(public_key):
        raise DidError(
            f"DID {parsed} is not the fingerprint of the supplied public key"
        )
    verify_payload(obj, sig_hex, public_key)
