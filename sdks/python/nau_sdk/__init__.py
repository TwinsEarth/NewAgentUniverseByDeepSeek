"""``nau_sdk`` -- the Python SDK for the nau/1 protocol.

A clean-room implementation of the shared contract in ``conformance/vectors.json``.
Two properties are worth stating up front, because upstream v2.5.6 got both
wrong and this SDK is tested on them:

* **No third-party dependencies.**  Ed25519 is implemented in pure Python (RFC
  8032), so the cross-language signature guarantee is exercised on every run.
  Upstream's ``cryptography`` import was optional, so 11 of its 17 Python tests
  were silently skipped in CI and that guarantee was never actually checked.
* **One source of truth for the version.**  :data:`nau_sdk.VERSION` is read from
  the repository ``VERSION`` file at import time.  Upstream restated its version
  as a literal in four Python files and all four drifted.

Quick start::

    from nau_sdk import Identity, canonical_json

    me = Identity.generate()
    signed = {"did": me.did.as_str(), "name": "Translator", "signature": ""}
    signed["signature"] = me.sign_payload(signed)
    me.verify_payload(signed, signed["signature"])   # raises on failure
"""

from __future__ import annotations

from .canonical import (
    MAX_DEPTH,
    SIGNATURE_FIELD,
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
from .errors import (
    AmountError,
    AuthorizationError,
    DidError,
    MarketError,
    McpError,
    OverflowError,
    SDKError,
    SignatureError,
    TransitionError,
    ValidationError,
)
from .identity import (
    DID_FINGERPRINT_BYTES,
    DID_PREFIX,
    DID_PREFIX_LEGACY,
    PUBLIC_KEY_BYTES,
    SIGNATURE_BYTES,
    Did,
    Identity,
    Keypair,
    did_from_public_key,
    public_key_from_hex,
    verify_payload,
    verify_payload_bound,
)
from .ledger import GENESIS_HASH, Ledger, LedgerEntry
from .market import DEFAULT_BASE_URL, DEFAULT_PATHS, DEFAULT_TIMEOUT, MarketClient
from .mcp import MCP_PROTOCOL_VERSION, McpHttpClient
from .models import (
    CURRENCY,
    DECIMALS,
    MINOR_UNITS_PER_MAJOR,
    SIX_FIELDS,
    AgentCard,
    AgentCategory,
    Bid,
    Dispute,
    DisputeOutcome,
    EvidenceGrade,
    Money,
    Pricing,
    PricingModel,
    PricingUnit,
    ResultEnvelope,
    Skill,
    Sla,
    TASK_STATES,
    Task,
    TaskId,
    TaskSpec,
    TaskState,
    VerificationPolicy,
    classify_task_state,
    major,
)
from .version import VERSION, VERSION_FILE

__all__ = [
    # version
    "VERSION",
    "VERSION_FILE",
    # canonicalization
    "CanonicalError",
    "NonIntegerNumber",
    "NumberOutOfRange",
    "RootNotObject",
    "SerializeError",
    "TooDeep",
    "canonical_json",
    "canonical_payload",
    "canonical_string",
    "MAX_DEPTH",
    "SIGNATURE_FIELD",
    # identity
    "Did",
    "Keypair",
    "Identity",
    "did_from_public_key",
    "public_key_from_hex",
    "verify_payload",
    "verify_payload_bound",
    "DID_PREFIX",
    "DID_PREFIX_LEGACY",
    "DID_FINGERPRINT_BYTES",
    "PUBLIC_KEY_BYTES",
    "SIGNATURE_BYTES",
    # errors
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
    # models
    "Money",
    "major",
    "CURRENCY",
    "DECIMALS",
    "MINOR_UNITS_PER_MAJOR",
    "SIX_FIELDS",
    "AgentCard",
    "AgentCategory",
    "Bid",
    "Dispute",
    "DisputeOutcome",
    "EvidenceGrade",
    "Pricing",
    "PricingModel",
    "PricingUnit",
    "ResultEnvelope",
    "Skill",
    "Sla",
    "Task",
    "TaskId",
    "TaskSpec",
    "TaskState",
    "TASK_STATES",
    "VerificationPolicy",
    "classify_task_state",
    # ledger
    "Ledger",
    "LedgerEntry",
    "GENESIS_HASH",
    # clients
    "MarketClient",
    "McpHttpClient",
    "MCP_PROTOCOL_VERSION",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "DEFAULT_PATHS",
]

__version__ = VERSION
