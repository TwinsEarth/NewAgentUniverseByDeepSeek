"""One error taxonomy for the whole SDK.

Every failure mode the SDK can report is a distinct type, so a caller can never
mistake "the signature is invalid" for "the payload could not be serialized" --
the defect upstream v2.5.6 had when a serialization failure produced a signature
over the literal payload ``null``.

The canonicalization errors live in :mod:`nau_sdk.canonical` (they are part of
the byte-format contract); this module holds everything else.
"""

from __future__ import annotations

from typing import Optional

__all__ = [
    "SDKError",
    "ValidationError",
    "AmountError",
    "OverflowError",
    "DidError",
    "SignatureError",
    "AuthorizationError",
    "TransitionError",
    "MarketError",
    "McpError",
]


class SDKError(Exception):
    """Base class for every ``nau_sdk`` failure that is not a :class:`ValueError`."""


class ValidationError(SDKError, ValueError):
    """A structure failed its own invariants (a model was constructed wrong)."""


class AmountError(SDKError, ValueError):
    """A monetary amount could not be parsed or would lose precision."""


class OverflowError(AmountError):  # noqa: A001 - deliberate shadow of the builtin
    """A checked arithmetic operation would overflow ``i64``."""


class DidError(SDKError, ValueError):
    """A decentralized identifier was malformed, or did not bind to a key."""


class SignatureError(SDKError, ValueError):
    """A signature was malformed, or did not verify."""


class AuthorizationError(SDKError, ValueError):
    """A signer tried to act for an identity that is not theirs."""


class TransitionError(SDKError, ValueError):
    """A task state transition is not permitted by the state machine."""


class MarketError(SDKError):
    """The market daemon refused a request.

    Carries the HTTP status and a human-readable message.  ``status`` is ``0``
    when the failure happened before a response arrived (a connection error or a
    timeout), so callers can distinguish "the daemon said no" from "there was no
    daemon".
    """

    def __init__(self, status: int, message: str, *, method: str = "", path: str = "") -> None:
        self.status = int(status)
        self.message = str(message)
        self.method = method
        self.path = path
        where = f" {method} {path}" if method or path else ""
        super().__init__(f"market error [{self.status}]{where}: {self.message}")


class McpError(SDKError):
    """The MCP endpoint returned a JSON-RPC error or an unusable response."""

    def __init__(
        self,
        message: str,
        *,
        code: Optional[int] = None,
        data: Optional[object] = None,
        status: int = 0,
    ) -> None:
        self.code = code
        self.data = data
        self.status = status
        detail = f" (code {code})" if code is not None else ""
        super().__init__(f"MCP error{detail}: {message}")
