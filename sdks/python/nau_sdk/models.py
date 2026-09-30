"""The shared domain vocabulary: money, agents, tasks, bids, results, disputes.

Contrast with upstream v2.5.6:

* money was ``f64`` everywhere, and conservation was asserted with a tolerance
  (``(balance_sum - expected_sum).abs() < 0.001``).  A ledger that is only
  "conserved to within 0.001" is not conserved: the error is real money and it
  grows without bound.  :class:`Money` is an exact ``i64`` count of minor units
  (10^-6), and every operation is checked.
* signed structures carried no public key, no nonce and no timestamp, so replay
  and impersonation were both undetectable.  Every structure here carries
  ``*_key``, ``nonce`` and ``signed_at`` and is self-verifying.
* its Python ``TaskStatus`` had 7 states and **no transition validation at all**,
  while its JavaScript SDK had 12 states and a real table -- the two could not
  interoperate.  :class:`TaskState` has the twelve states and the full table.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional, Sequence, Set

from .errors import (
    AmountError,
    AuthorizationError,
    DidError,
    TransitionError,
    ValidationError,
    OverflowError as MoneyOverflowError,
)
from .identity import Did, Identity, verify_payload_bound

__all__ = [
    "MINOR_UNITS_PER_MAJOR",
    "DECIMALS",
    "CURRENCY",
    "MAX_ID_LEN",
    "MAX_TEXT_LEN",
    "SIX_FIELDS",
    "Money",
    "major",
    "TaskState",
    "classify_task_state",
    "TASK_STATES",
    "VerificationPolicy",
    "EvidenceGrade",
    "Skill",
    "PricingModel",
    "PricingUnit",
    "Pricing",
    "Sla",
    "AgentCategory",
    "AgentCard",
    "TaskId",
    "TaskSpec",
    "Task",
    "Bid",
    "ResultEnvelope",
    "Dispute",
    "DisputeOutcome",
]

#: Minor units per major unit: six decimal places.
MINOR_UNITS_PER_MAJOR = 1_000_000
#: Number of decimal digits in the minor-unit scale.
DECIMALS = 6
#: Currency ticker used by the settlement ledger.
CURRENCY = "NAU"
#: Maximum length accepted for any identifier (task id, skill id).
MAX_ID_LEN = 64
#: Maximum length accepted for free-text fields.
MAX_TEXT_LEN = 16_384
#: The six fields that define a well-formed task specification.
SIX_FIELDS = ("goal", "context", "done", "todo", "trace", "owner")

_I64_MIN = -(2**63)
_I64_MAX = 2**63 - 1

_DIGITS = frozenset("0123456789")


# ===========================================================================
# Money
# ===========================================================================


class Money(int):
    """An exact amount, counted in minor units (10^-6).

    ``Money`` deliberately *is* an ``int`` so that the canonical layer sees a
    JSON integer -- rule 6 of the canonical format rejects floats outright, and
    a float that survives into a signed payload cannot be reproduced byte for
    byte in another language.  Because it is an integer subtype there is no
    ``__float__`` shortcut anywhere in this class, and no arithmetic silently
    produces a float.

    ``+`` and ``-`` are intentionally *not* overridden: their results are plain
    ``int`` and cannot silently wrap.  Callers who want an overflow check must
    say so with :meth:`checked_add` / :meth:`checked_sub`.
    """

    __slots__ = ()

    def __new__(cls, minor: int = 0) -> "Money":
        if isinstance(minor, bool) or not isinstance(minor, int):
            raise AmountError(
                f"Money minor units must be an integer, got {type(minor).__name__}"
            )
        if minor < _I64_MIN or minor > _I64_MAX:
            raise MoneyOverflowError(
                f"Money minor units {minor} do not fit in i64"
            )
        return super().__new__(cls, minor)

    # -- constructors -------------------------------------------------------

    @staticmethod
    def from_minor(minor: int) -> "Money":
        """Wrap a raw minor-unit count."""
        return Money(minor)

    @staticmethod
    def zero() -> "Money":
        return Money(0)

    @staticmethod
    def max() -> "Money":
        return Money(_I64_MAX)

    @staticmethod
    def parse(text: str) -> "Money":
        """Parse a decimal string such as ``"12.5"``, ``"-0.000001"``, ``"1000"``.

        Parsing is textual -- the string never passes through ``float`` -- so
        ``"0.1"`` is exactly 100000 minor units and ``"0.1" + "0.2"`` is exactly
        ``"0.3"``.  Exponent notation, thousands separators, ``NaN``, ``inf`` and
        anything with more than six decimal places are rejected.
        """
        if not isinstance(text, str):
            raise AmountError(f"amount must be a string, got {type(text).__name__}")
        s = text.strip()
        if not s:
            raise AmountError("empty string")
        negative = False
        if s.startswith("-"):
            negative, rest = True, s[1:]
        elif s.startswith("+"):
            rest = s[1:]
        else:
            rest = s
        if not rest:
            raise AmountError(f"`{s}` has no digits")
        if rest.count(".") > 1:
            raise AmountError(f"`{s}` has more than one decimal point")
        if "." in rest:
            int_part, frac_part = rest.split(".", 1)
        else:
            int_part, frac_part = rest, ""
        if not int_part and not frac_part:
            raise AmountError(f"`{s}` has no digits")
        if any(ch not in _DIGITS for ch in int_part):
            raise AmountError(f"`{s}` has a non-digit in the integer part")
        if any(ch not in _DIGITS for ch in frac_part):
            raise AmountError(f"`{s}` has a non-digit in the fractional part")
        if len(frac_part) > DECIMALS:
            raise AmountError(
                f"`{s}` has more than {DECIMALS} decimal places; the smallest unit "
                f"is 1e-{DECIMALS}"
            )
        int_value = int(int_part) if int_part else 0
        padded = frac_part + "0" * (DECIMALS - len(frac_part))
        frac_value = int(padded) if padded else 0
        magnitude = int_value * MINOR_UNITS_PER_MAJOR + frac_value
        if magnitude > _I64_MAX:
            raise MoneyOverflowError(f"`{s}` does not fit in i64 minor units")
        return Money(-magnitude if negative else magnitude)

    @staticmethod
    def from_major_units(units: int) -> "Money":
        """Build from whole major units."""
        return Money(units * MINOR_UNITS_PER_MAJOR)

    # -- accessors ----------------------------------------------------------

    @property
    def minor(self) -> int:
        """The raw minor-unit count."""
        return int(self)

    def is_zero(self) -> bool:
        return int(self) == 0

    def is_positive(self) -> bool:
        return int(self) > 0

    def is_negative(self) -> bool:
        return int(self) < 0

    def abs_minor(self) -> int:
        """The magnitude, saturating (never raises, even for ``i64::MIN``)."""
        value = int(self)
        if value == _I64_MIN:
            return _I64_MAX
        return abs(value)

    def to_decimal_string(self) -> str:
        """Render as a decimal string, trimming trailing zeros in the fraction.

        ``Money.parse(m.to_decimal_string()) == m`` for every ``m``.
        """
        value = int(self)
        negative = value < 0
        magnitude = -value if negative else value
        int_part, frac_part = divmod(magnitude, MINOR_UNITS_PER_MAJOR)
        out = "-" if negative else ""
        out += str(int_part)
        if frac_part:
            frac = f"{frac_part:0{DECIMALS}d}".rstrip("0")
            out += "." + frac
        return out

    def to_json(self) -> int:
        """Wire form: a **JSON integer** of minor units, never a float."""
        return int(self)

    # -- checked arithmetic -------------------------------------------------

    def checked_add(self, other: "Money | int") -> "Money":
        total = int(self) + int(other)
        if total < _I64_MIN or total > _I64_MAX:
            raise MoneyOverflowError("Money.checked_add overflowed i64")
        return Money(total)

    def checked_sub(self, other: "Money | int") -> "Money":
        total = int(self) - int(other)
        if total < _I64_MIN or total > _I64_MAX:
            raise MoneyOverflowError("Money.checked_sub overflowed i64")
        return Money(total)

    def checked_neg(self) -> "Money":
        value = int(self)
        if value == _I64_MIN:
            raise MoneyOverflowError("Money.checked_neg overflowed i64")
        return Money(-value)

    def checked_mul_int(self, factor: int) -> "Money":
        if isinstance(factor, bool) or not isinstance(factor, int):
            raise AmountError(
                f"factor must be an integer, got {type(factor).__name__}"
            )
        product = int(self) * factor
        if product < _I64_MIN or product > _I64_MAX:
            raise MoneyOverflowError("Money.checked_mul_int overflowed i64")
        return Money(product)

    def split(self, parts: int) -> "tuple[Money, Money]":
        """Split into ``parts`` equal shares plus an explicit remainder.

        ``share * parts + remainder == self``.  Integer division never invents or
        destroys value the way ``f64 / n`` does, and the remainder is handed back
        so the caller must decide where it goes.
        """
        if isinstance(parts, bool) or not isinstance(parts, int) or parts <= 0:
            raise AmountError("cannot split into zero parts")
        share = int(self) // parts
        return Money(share), Money(int(self) - share * parts)

    def __str__(self) -> str:
        return f"{self.to_decimal_string()} {CURRENCY}"

    def __repr__(self) -> str:
        return f"Money({int(self)} minor = {self.to_decimal_string()})"


def major(units: int) -> Money:
    """Build a :class:`Money` from whole major units (tests, defaults)."""
    return Money.from_major_units(units)


# ===========================================================================
# JSON serialization helper
# ===========================================================================


def to_json(value: Any) -> Any:
    """Recursively convert SDK values into plain JSON-compatible values.

    ``Did`` becomes its string, ``Money`` stays an integer, raw keys become
    lowercase hex, dataclasses become dicts, and ``None`` is preserved (the
    caller decides whether an optional field is omitted).  The result contains no
    floats, by construction.
    """
    hook = getattr(value, "to_json", None)
    if callable(hook):
        return hook()
    if isinstance(value, Did):
        return value.as_str()
    if isinstance(value, Money):
        return int(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        # Raw public keys travel as lowercase hex, exactly as the Rust core
        # serializes them.
        return bytes(value).hex()
    if isinstance(value, str):
        return value
    if value is None:
        return None
    if isinstance(value, dict):
        return {str(k): to_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_json(v) for v in value]
    raise ValidationError(
        f"cannot serialize a value of type {type(value).__name__} to JSON"
    )


def _field_json(obj: Any, *, drop_none: bool = True) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for f in fields(obj):
        value = getattr(obj, f.name)
        if drop_none and value is None:
            continue
        out[f.name] = to_json(value)
    return out


# ===========================================================================
# Task state machine
# ===========================================================================


class TaskState(str):
    """Task lifecycle state -- exactly the twelve the Rust core defines.

    Upstream's Python SDK had seven states and no transition validation at all,
    while its JavaScript SDK had twelve and a real table, so the two could not
    interoperate.  This is the union: a total, tested table including the two
    recovery edges upstream lacks:

    * ``no_quorum -> open`` -- the "view change" upstream's docs promised but
      whose state was absorbing.
    * ``rework -> running`` -- the documented rework loop.

    The twelve states are attributes of this class (``TaskState.OPEN`` and so
    on) *and* valid values in their own right, because they are ``TaskState``
    instances -- a plain ``str`` assigned as a class attribute would be rebound
    to ``str`` by :func:`str.__set_name__` and would lose every method.
    """

    __slots__ = ()

    @staticmethod
    def parse(value: str) -> "TaskState":
        if not isinstance(value, str):
            raise ValidationError(
                f"task state must be a string, got {type(value).__name__}"
            )
        normalized = value.strip().lower()
        if normalized not in _TRANSITIONS:
            raise ValidationError(
                f"`{value}` is not one of the twelve task states: "
                + ", ".join(sorted(_TRANSITIONS))
            )
        return TaskState(normalized)

    def is_terminal(self) -> bool:
        """True when no further transition is possible."""
        return self in (TaskState.SETTLED, TaskState.SLASHED, TaskState.CANCELLED)

    def can_transition_to(self, next_state: "TaskState | str") -> bool:
        """True when the transition table permits ``self -> next_state``."""
        if not isinstance(next_state, TaskState):
            next_state = TaskState.parse(next_state)
        return str(next_state) in _TRANSITIONS[str(self)]

    def transition(self, next_state: "TaskState | str", task_id: str = "") -> "TaskState":
        """Apply a transition, or raise :class:`TransitionError`.

        Re-applying the current state is a no-op, not an error.
        """
        if not isinstance(next_state, TaskState):
            next_state = TaskState.parse(next_state)
        if str(self) == str(next_state):
            return self
        if not self.can_transition_to(next_state):
            where = f" for task `{task_id}`" if task_id else ""
            raise TransitionError(
                f"illegal task transition{where}: {self} -> {next_state}"
            )
        return next_state

    def to_json(self) -> str:
        return str(self)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"TaskState({str(self)!r})"


# The twelve states are bound *after* the class body: a plain ``str`` in the body
# would be silently re-wrapped by ``str.__set_name__``, and the resulting attribute
# would have none of the methods above.
for _state_name in (
    "OPEN",
    "MATCHED",
    "RUNNING",
    "SUBMITTED",
    "VERIFYING",
    "ACCEPTED",
    "REWORK",
    "SETTLED",
    "DISPUTED",
    "SLASHED",
    "CANCELLED",
    "NO_QUORUM",
):
    setattr(TaskState, _state_name, TaskState(_state_name.lower()))
del _state_name


#: The complete transition table.  Terminal states map to the empty set.
_TRANSITIONS: Dict[str, Set[str]] = {
    TaskState.OPEN: {TaskState.MATCHED, TaskState.CANCELLED, TaskState.NO_QUORUM},
    TaskState.MATCHED: {
        TaskState.RUNNING,
        TaskState.OPEN,
        TaskState.CANCELLED,
        TaskState.DISPUTED,
    },
    TaskState.RUNNING: {
        TaskState.SUBMITTED,
        TaskState.DISPUTED,
        TaskState.CANCELLED,
    },
    TaskState.SUBMITTED: {TaskState.VERIFYING, TaskState.DISPUTED},
    TaskState.VERIFYING: {
        TaskState.ACCEPTED,
        TaskState.REWORK,
        TaskState.NO_QUORUM,
        TaskState.DISPUTED,
    },
    TaskState.REWORK: {TaskState.RUNNING, TaskState.OPEN, TaskState.CANCELLED},
    TaskState.ACCEPTED: {TaskState.SETTLED, TaskState.DISPUTED},
    TaskState.DISPUTED: {
        TaskState.SETTLED,
        TaskState.SLASHED,
        TaskState.ACCEPTED,
        TaskState.CANCELLED,
    },
    TaskState.NO_QUORUM: {TaskState.OPEN, TaskState.CANCELLED},
    TaskState.SETTLED: set(),
    TaskState.SLASHED: set(),
    TaskState.CANCELLED: set(),
}

#: Every task state, in lifecycle order (the twelve the Rust core declares).
TASK_STATES: Sequence[TaskState] = tuple(
    TaskState(name)
    for name in (
        "open",
        "matched",
        "running",
        "submitted",
        "verifying",
        "accepted",
        "rework",
        "settled",
        "disputed",
        "slashed",
        "cancelled",
        "no_quorum",
    )
)


def classify_task_state(value: Any) -> TaskState:
    """Normalize a string or :class:`TaskState` into a validated state."""
    if isinstance(value, TaskState):
        return value
    return TaskState.parse(value)


# ===========================================================================
# Verification policy
# ===========================================================================


class VerificationPolicy:
    """How a task's result is to be verified."""

    __slots__ = ("kind", "n", "f")

    def __init__(self, kind: str = "requester_only", n: int = 0, f: int = 0) -> None:
        kind = str(kind).strip().lower()
        if kind not in ("committee", "requester_only"):
            raise ValidationError(
                f"verification kind must be `committee` or `requester_only`, got `{kind}`"
            )
        self.kind = kind
        self.n = int(n)
        self.f = int(f)
        if kind == "committee":
            self.validate()

    @staticmethod
    def committee(n: int, f: int) -> "VerificationPolicy":
        return VerificationPolicy("committee", n, f)

    @staticmethod
    def requester_only() -> "VerificationPolicy":
        return VerificationPolicy("requester_only")

    def validate(self) -> None:
        """Check the BFT relation ``n >= 3f + 1`` without overflowing."""
        if self.kind != "committee":
            return
        if self.n <= 0:
            raise ValidationError("committee size must be > 0")
        minimum = 3 * self.f + 1
        if self.n < minimum:
            raise ValidationError(
                f"BFT-lite requires n >= 3f+1, got n={self.n}, f={self.f} "
                f"(need n >= {minimum})"
            )

    def quorum(self) -> int:
        """The quorum ``2f + 1``, or ``1`` when the requester alone decides."""
        if self.kind == "requester_only":
            return 1
        return 2 * self.f + 1

    def to_json(self) -> Dict[str, Any]:
        if self.kind == "committee":
            return {"kind": "committee", "n": self.n, "f": self.f}
        return {"kind": "requester_only"}

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VerificationPolicy):
            return NotImplemented
        return (self.kind, self.n, self.f) == (other.kind, other.n, other.f)

    def __repr__(self) -> str:
        if self.kind == "committee":
            return f"VerificationPolicy(committee, n={self.n}, f={self.f})"
        return "VerificationPolicy(requester_only)"


class EvidenceGrade(str):
    """How trustworthy the evidence accompanying a result is.

    Ordered from most to least trustworthy.  The default is ``unverified``, i.e.
    fail-closed: a result that does not say otherwise is not treated as evidence.
    Upstream defined ``is_trustworthy()`` "for the settlement gate" and then
    never called it, so an unverified result settled at full budget.

    As with :class:`TaskState`, the grades are bound after the class body so the
    class attributes are real ``EvidenceGrade`` values.
    """

    __slots__ = ()

    @staticmethod
    def parse(value: str) -> "EvidenceGrade":
        normalized = str(value).strip().lower().replace("-", "_")
        if normalized not in _EVIDENCE_GRADES:
            raise ValidationError(
                f"`{value}` is not an evidence grade; expected one of "
                + ", ".join(sorted(_EVIDENCE_GRADES))
            )
        return EvidenceGrade(normalized)

    def label(self) -> str:
        """Machine-readable label (``cpu-proto`` uses a hyphen, as upstream)."""
        return "cpu-proto" if str(self) == EvidenceGrade.CPU_PROTO else str(self)

    def is_settlement_grade(self) -> bool:
        """Whether this grade is strong enough to release payment."""
        return str(self) in (EvidenceGrade.VERIFIED, EvidenceGrade.CPU_PROTO)

    def to_json(self) -> str:
        return str(self)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"EvidenceGrade({str(self)!r})"


_EVIDENCE_GRADES: Set[str] = {"verified", "cpu_proto", "unverified"}

for _grade_name, _grade_value in (
    ("VERIFIED", "verified"),
    ("CPU_PROTO", "cpu_proto"),
    ("UNVERIFIED", "unverified"),
):
    setattr(EvidenceGrade, _grade_name, EvidenceGrade(_grade_value))
del _grade_name, _grade_value


# ===========================================================================
# Agent cards
# ===========================================================================


class PricingModel(str):
    """How an agent charges."""

    __slots__ = ()
    FIXED = "fixed"
    PER_UNIT = "per_unit"
    AUCTION = "auction"

    @staticmethod
    def parse(value: str) -> "PricingModel":
        normalized = str(value).strip().lower()
        if normalized not in ("fixed", "per_unit", "auction"):
            raise ValidationError(f"`{value}` is not a pricing model")
        return PricingModel(normalized)


class PricingUnit(str):
    """What a per-unit price is counted in."""

    __slots__ = ()
    TASK = "task"
    KILO_TOKEN = "kilo_token"
    SECOND = "second"
    MEBIBYTE = "mebibyte"

    @staticmethod
    def parse(value: str) -> "PricingUnit":
        normalized = str(value).strip().lower()
        if normalized not in ("task", "kilo_token", "second", "mebibyte"):
            raise ValidationError(f"`{value}` is not a pricing unit")
        return PricingUnit(normalized)


class AgentCategory(str):
    """Coarse category, used for discovery grouping."""

    __slots__ = ()
    GENERAL = "general"
    LANGUAGE = "language"
    VISION = "vision"
    CODE = "code"
    DATA = "data"
    INFRASTRUCTURE = "infrastructure"
    RESEARCH = "research"
    OTHER = "other"

    @staticmethod
    def parse(value: str) -> "AgentCategory":
        normalized = str(value).strip().lower()
        if normalized not in (
            "general",
            "language",
            "vision",
            "code",
            "data",
            "infrastructure",
            "research",
            "other",
        ):
            raise ValidationError(f"`{value}` is not an agent category")
        return AgentCategory(normalized)


@dataclass
class Skill:
    """A capability the agent claims, with a version."""

    id: str
    version: int = 1
    description: Optional[str] = None

    @staticmethod
    def new(skill_id: str, version: int = 1) -> "Skill":
        """Build a skill; the id is lowercased on insert, as upstream did."""
        return Skill(id=str(skill_id).lower(), version=int(version))

    def with_description(self, description: str) -> "Skill":
        self.description = description
        return self

    def validate(self) -> None:
        if not self.id or not str(self.id).strip():
            raise ValidationError("skill id must not be empty")
        if len(self.id) > MAX_ID_LEN:
            raise ValidationError(
                f"skill id `{self.id}` is longer than {MAX_ID_LEN} characters"
            )
        if self.id != self.id.lower():
            raise ValidationError(
                f"skill id `{self.id}` must be lowercase (skill lookup lowercases "
                "queries)"
            )
        if self.version < 0:
            raise ValidationError("skill version must not be negative")

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self)


@dataclass
class Pricing:
    """An advertised price."""

    model: PricingModel = PricingModel.AUCTION
    unit_price: Money = Money(0)
    unit: PricingUnit = PricingUnit.TASK

    def __post_init__(self) -> None:
        self.model = PricingModel.parse(self.model)
        self.unit = PricingUnit.parse(self.unit)
        if not isinstance(self.unit_price, Money):
            self.unit_price = Money(self.unit_price)

    def validate(self) -> None:
        if self.unit_price.is_negative():
            raise AmountError(
                f"unit_price {self.unit_price.to_decimal_string()} must not be negative"
            )

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self)


@dataclass
class Sla:
    """Advertised service level."""

    latency_p95_ms: int = 2_000
    availability_bps: int = 9_500
    max_concurrency: int = 10

    def validate(self) -> None:
        if self.availability_bps > 10_000:
            raise ValidationError(
                f"availability_bps {self.availability_bps} exceeds 10000"
            )
        if self.max_concurrency == 0:
            raise ValidationError(
                "max_concurrency must be at least 1 (a node that accepts nothing "
                "cannot be matched)"
            )

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self)


@dataclass
class AgentCard:
    """A published agent identity card.

    The card carries ``owner_key``, so :meth:`verify` can check the signature
    *and* that the key fingerprints ``owner`` without any out-of-band lookup.
    """

    owner: Did
    owner_key: bytes
    name: str
    skills: List[Skill]
    stake: Money
    signed_at: int
    nonce: int
    category: AgentCategory = AgentCategory.GENERAL
    description: Optional[str] = None
    pricing: Pricing = field(default_factory=Pricing)
    sla: Sla = field(default_factory=Sla)
    endpoints: List[str] = field(default_factory=list)
    expires_at: Optional[int] = None
    signature: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.owner, str):
            self.owner = Did.parse(self.owner)
        if isinstance(self.owner_key, str):
            self.owner_key = bytes.fromhex(self.owner_key)
        self.category = AgentCategory.parse(self.category)
        if not isinstance(self.stake, Money):
            self.stake = Money(self.stake)
        self.skills = [
            s if isinstance(s, Skill) else Skill(**s) for s in (self.skills or [])
        ]

    @staticmethod
    def draft(
        identity: Identity,
        name: str,
        skills: Sequence[Skill],
        stake: Money,
        signed_at: int,
        nonce: int,
    ) -> "AgentCard":
        """A minimal card owned by ``identity``, with no signature yet."""
        return AgentCard(
            owner=identity.did,
            owner_key=identity.public_key,
            name=name,
            skills=list(skills),
            stake=stake,
            signed_at=signed_at,
            nonce=nonce,
        )

    def validate(self) -> None:
        """Check every structural invariant.  Raises on the first failure."""
        if not self.name or not self.name.strip():
            raise ValidationError("agent name must not be empty")
        if len(self.name) > 128:
            raise ValidationError("agent name must be at most 128 characters")
        if not self.skills:
            raise ValidationError(
                "an agent must declare at least one skill to be discoverable"
            )
        for skill in self.skills:
            skill.validate()
        seen: Set[str] = set()
        for skill in self.skills:
            if skill.id in seen:
                raise ValidationError(f"duplicate skill `{skill.id}` in one card")
            seen.add(skill.id)
        self.pricing.validate()
        self.sla.validate()
        if not self.stake.is_positive():
            raise AmountError(
                "stake must be greater than zero for a card to be admissible"
            )
        if not self.owner.matches_public_key(self.owner_key):
            raise DidError(
                f"DID {self.owner} is not the fingerprint of the card's owner_key"
            )
        if self.expires_at is not None and self.expires_at <= self.signed_at:
            raise ValidationError(
                f"expires_at {self.expires_at} must be after signed_at {self.signed_at}"
            )

    def sign(self, identity: Identity) -> str:
        """Sign the card as ``identity`` and store the hex signature."""
        if identity.did != self.owner:
            raise AuthorizationError(
                f"{identity.did} may not sign a card owned by {self.owner}"
            )
        if identity.public_key != self.owner_key:
            raise AuthorizationError(
                "the signing identity's key does not match the card's owner_key"
            )
        self.signature = identity.sign_payload(self)
        return self.signature

    def verify(self) -> None:
        """Verify the stored signature against ``owner``/``owner_key``."""
        verify_payload_bound(self, self.signature, self.owner_key, self.owner)

    def validate_and_verify(self) -> None:
        self.validate()
        self.verify()

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self, drop_none=False)

    def __getitem__(self, key: str) -> Any:
        """Read a field as if the card were a mapping (handy in tests/scripts)."""
        if not isinstance(key, str):
            raise TypeError("an AgentCard is keyed by field name")
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key) from None

    def to_dict(self) -> Dict[str, Any]:
        return self.to_json()


# ===========================================================================
# Tasks
# ===========================================================================


class TaskId(str):
    """A validated task identifier: ASCII letters, digits, ``-`` and ``_``."""

    __slots__ = ()

    @staticmethod
    def parse(value: str) -> "TaskId":
        if not isinstance(value, str):
            raise ValidationError("task id must be a string")
        if not value:
            raise ValidationError("task id must not be empty")
        if len(value) > MAX_ID_LEN:
            raise ValidationError(
                f"task id is longer than {MAX_ID_LEN} characters"
            )
        if not all(ch.isascii() and (ch.isalnum() or ch in "-_") for ch in value):
            raise ValidationError(
                f"task id `{value}` may only contain ASCII letters, digits, `-` and `_`"
            )
        return TaskId(value)

    @staticmethod
    def generate() -> "TaskId":
        return TaskId("task-" + os.urandom(8).hex())


@dataclass
class TaskSpec:
    """The six-field task specification: goal / context / done / todo / trace / owner.

    Upstream documented those six fields and then validated ``budget``,
    ``required_skills`` and ``requester`` instead -- never ``done``, ``trace`` or
    ``owner``.  :meth:`gaps` checks the six documented fields; the fields that
    belong to a *task* (budget, skills) live on :class:`Task`.
    """

    goal: str
    context: str
    done: List[str]
    todo: List[str]
    owner: Did
    trace: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.owner, str):
            self.owner = Did.parse(self.owner)
        self.done = list(self.done or [])
        self.todo = list(self.todo or [])

    def gaps(self) -> List[str]:
        """Every missing or invalid field, as human-readable strings."""
        gaps: List[str] = []
        if not self.goal or not self.goal.strip():
            gaps.append("goal must not be empty")
        if not self.context or not self.context.strip():
            gaps.append("context must not be empty")
        if not self.done or all(not d.strip() for d in self.done):
            gaps.append(
                "done must contain at least one non-empty acceptance criterion"
            )
        if not self.todo or all(not t.strip() for t in self.todo):
            gaps.append("todo must contain at least one non-empty step")
        if len(self.goal.encode()) > MAX_TEXT_LEN or len(self.context.encode()) > MAX_TEXT_LEN:
            gaps.append(f"goal/context must be at most {MAX_TEXT_LEN} bytes")
        if len(self.done) > 256 or len(self.todo) > 256:
            gaps.append("done/todo may contain at most 256 entries")
        if self.trace is not None and len(self.trace.encode()) > MAX_TEXT_LEN:
            gaps.append(f"trace must be at most {MAX_TEXT_LEN} bytes")
        return gaps

    def validate(self) -> None:
        gaps = self.gaps()
        if gaps:
            raise ValidationError("; ".join(gaps))

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self, drop_none=False)


@dataclass
class Task:
    """A published task."""

    id: TaskId
    spec: TaskSpec
    required_skills: List[str]
    budget: Money
    requester_key: bytes
    signed_at: int
    nonce: int
    state: TaskState = TaskState.OPEN
    deadline: Optional[int] = None
    verification: VerificationPolicy = field(
        default_factory=VerificationPolicy.requester_only
    )
    assigned_to: Optional[Did] = None
    signature: str = ""

    def __post_init__(self) -> None:
        self.id = TaskId.parse(self.id) if not isinstance(self.id, TaskId) else self.id
        if isinstance(self.requester_key, str):
            self.requester_key = bytes.fromhex(self.requester_key)
        self.state = classify_task_state(self.state)
        if isinstance(self.assigned_to, str):
            self.assigned_to = Did.parse(self.assigned_to)
        if not isinstance(self.budget, Money):
            self.budget = Money(self.budget)
        self.required_skills = list(self.required_skills or [])

    @staticmethod
    def draft(
        task_id: TaskId,
        spec: TaskSpec,
        required_skills: Sequence[str],
        budget: Money,
        requester_key: bytes,
        signed_at: int,
        nonce: int,
        deadline: Optional[int] = None,
        verification: Optional[VerificationPolicy] = None,
    ) -> "Task":
        """Build an unsigned draft in the ``open`` state."""
        return Task(
            id=task_id,
            spec=spec,
            required_skills=list(required_skills),
            budget=budget,
            requester_key=requester_key,
            signed_at=signed_at,
            nonce=nonce,
            deadline=deadline,
            verification=verification or VerificationPolicy.requester_only(),
        )

    def validate(self) -> None:
        self.spec.validate()
        if not self.required_skills:
            raise ValidationError("required_skills must name at least one skill")
        for skill in self.required_skills:
            if not skill.strip() or len(skill) > MAX_ID_LEN:
                raise ValidationError(
                    f"required skill `{skill}` must be 1..={MAX_ID_LEN} characters"
                )
        if not self.budget.is_positive():
            raise AmountError(
                "budget must be greater than zero; a task with no budget cannot pay anyone"
            )
        self.verification.validate()
        if not self.spec.owner.matches_public_key(self.requester_key):
            raise DidError(
                f"DID {self.spec.owner} is not the fingerprint of requester_key"
            )
        if self.deadline is not None and self.deadline <= self.signed_at:
            raise ValidationError(
                f"deadline {self.deadline} must be after signed_at {self.signed_at}"
            )

    def is_expired(self, now: int) -> bool:
        """True when ``now`` is past the deadline (upstream stored it and never read it)."""
        return self.deadline is not None and now > self.deadline

    def sign(self, identity: Identity) -> str:
        if identity.did != self.spec.owner:
            raise AuthorizationError(
                f"{identity.did} may not sign a task owned by {self.spec.owner}"
            )
        self.signature = identity.sign_payload(self)
        return self.signature

    def verify(self) -> None:
        verify_payload_bound(self, self.signature, self.requester_key, self.spec.owner)

    def validate_and_verify(self) -> None:
        """Structural validation, then the signature, then advance the state?  No.

        Validation only -- use :meth:`transition` for state changes.
        """
        self.validate()
        self.verify()

    def transition(self, next_state: "TaskState | str") -> TaskState:
        """Move to ``next_state`` if the table permits it."""
        self.state = self.state.transition(next_state, str(self.id))
        return self.state

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self, drop_none=False)


# ===========================================================================
# Bids, results, disputes
# ===========================================================================


@dataclass
class Bid:
    """An offer to execute a task.

    Upstream accepted a negative or zero price and, because its scoring formula
    degraded to `reputation` when ``price <= 0.0``, a bid of ``0`` won selection
    *and* was then paid the full task budget.  A non-positive price is refused
    here.
    """

    task_id: TaskId
    bidder: Did
    bidder_key: bytes
    price: Money
    eta_secs: int
    confidence_bps: int
    signed_at: int
    nonce: int
    expires_at: Optional[int] = None
    signature: str = ""

    def __post_init__(self) -> None:
        self.task_id = (
            self.task_id
            if isinstance(self.task_id, TaskId)
            else TaskId.parse(self.task_id)
        )
        if isinstance(self.bidder, str):
            self.bidder = Did.parse(self.bidder)
        if isinstance(self.bidder_key, str):
            self.bidder_key = bytes.fromhex(self.bidder_key)
        if not isinstance(self.price, Money):
            self.price = Money(self.price)

    def validate_for(self, task: Task) -> None:
        """Validate the bid against the task it targets."""
        if str(self.task_id) != str(task.id):
            raise ValidationError(
                f"bid targets task `{self.task_id}` but was checked against `{task.id}`"
            )
        if not self.price.is_positive():
            raise AmountError("bid price must be greater than zero")
        if self.price > task.budget:
            raise AmountError(
                f"bid price {self.price.to_decimal_string()} exceeds the task budget "
                f"{task.budget.to_decimal_string()}"
            )
        if self.eta_secs <= 0:
            raise ValidationError("bid eta_secs must be greater than zero")
        if self.confidence_bps > 10_000:
            raise ValidationError(
                f"confidence_bps {self.confidence_bps} exceeds 10000"
            )
        if not self.bidder.matches_public_key(self.bidder_key):
            raise DidError(
                f"DID {self.bidder} is not the fingerprint of the bid's bidder_key"
            )

    def sign(self, identity: Identity) -> str:
        if identity.did != self.bidder:
            raise AuthorizationError(
                f"{identity.did} may not sign a bid from {self.bidder}"
            )
        self.signature = identity.sign_payload(self)
        return self.signature

    def verify(self) -> None:
        verify_payload_bound(self, self.signature, self.bidder_key, self.bidder)

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self, drop_none=False)


@dataclass
class ResultEnvelope:
    """A delivered result.

    Carries a digest rather than the output itself, so the envelope stays small
    and the payload can live in content-addressed storage.
    """

    task_id: TaskId
    agent: Did
    agent_key: bytes
    output_digest: str
    summary: str
    signed_at: int
    nonce: int
    evidence: EvidenceGrade = EvidenceGrade.UNVERIFIED
    output_uri: Optional[str] = None
    latency_ms: int = 0
    signature: str = ""

    def __post_init__(self) -> None:
        self.task_id = (
            self.task_id
            if isinstance(self.task_id, TaskId)
            else TaskId.parse(self.task_id)
        )
        if isinstance(self.agent, str):
            self.agent = Did.parse(self.agent)
        if isinstance(self.agent_key, str):
            self.agent_key = bytes.fromhex(self.agent_key)
        self.evidence = EvidenceGrade.parse(self.evidence)

    @staticmethod
    def digest_output(output: bytes) -> str:
        """The hex SHA-256 of an output blob, as the envelope expects."""
        import hashlib

        return hashlib.sha256(output).hexdigest()

    def validate(self) -> None:
        if len(self.output_digest) != 64 or any(
            ch not in "0123456789abcdef" for ch in self.output_digest
        ):
            raise ValidationError(
                "output_digest must be 64 lowercase hex characters (SHA-256)"
            )
        if len(self.summary.encode()) > MAX_TEXT_LEN:
            raise ValidationError(
                f"summary must be at most {MAX_TEXT_LEN} bytes"
            )
        if not self.agent.matches_public_key(self.agent_key):
            raise DidError(
                f"DID {self.agent} is not the fingerprint of the result's agent_key"
            )

    def sign(self, identity: Identity) -> str:
        if identity.did != self.agent:
            raise AuthorizationError(
                f"{identity.did} may not sign a result from {self.agent}"
            )
        self.signature = identity.sign_payload(self)
        return self.signature

    def verify(self) -> None:
        verify_payload_bound(self, self.signature, self.agent_key, self.agent)

    def validate_for_settlement(self) -> None:
        """Validate, verify, and require a settlement-grade evidence label."""
        self.validate()
        self.verify()
        if not self.evidence.is_settlement_grade():
            raise ValidationError(
                f"evidence grade `{self.evidence.label()}` is not sufficient to "
                "release payment"
            )

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self, drop_none=False)


@dataclass
class Dispute:
    """A raised dispute."""

    id: str
    task_id: TaskId
    complainant: Did
    complainant_key: bytes
    respondent: Did
    reason: str
    signed_at: int
    nonce: int
    evidence_digest: Optional[str] = None
    signature: str = ""

    def __post_init__(self) -> None:
        self.task_id = (
            self.task_id
            if isinstance(self.task_id, TaskId)
            else TaskId.parse(self.task_id)
        )
        for name in ("complainant", "respondent"):
            value = getattr(self, name)
            if isinstance(value, str):
                setattr(self, name, Did.parse(value))
        if isinstance(self.complainant_key, str):
            self.complainant_key = bytes.fromhex(self.complainant_key)

    def validate(self) -> None:
        if not self.id.strip() or len(self.id) > MAX_ID_LEN:
            raise ValidationError(f"dispute id must be 1..={MAX_ID_LEN} characters")
        if not self.reason.strip():
            raise ValidationError("dispute reason must not be empty")
        if len(self.reason.encode()) > MAX_TEXT_LEN:
            raise ValidationError(
                f"dispute reason must be at most {MAX_TEXT_LEN} bytes"
            )
        if self.complainant == self.respondent:
            raise ValidationError("a party cannot dispute itself")
        if not self.complainant.matches_public_key(self.complainant_key):
            raise DidError(
                f"DID {self.complainant} is not the fingerprint of the dispute's key"
            )
        if self.evidence_digest is not None and (
            len(self.evidence_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in self.evidence_digest)
        ):
            raise ValidationError("evidence_digest must be 64 lowercase hex characters")

    def sign(self, identity: Identity) -> str:
        if identity.did != self.complainant:
            raise AuthorizationError(
                f"{identity.did} may not sign a dispute raised by {self.complainant}"
            )
        self.signature = identity.sign_payload(self)
        return self.signature

    def verify(self) -> None:
        verify_payload_bound(
            self, self.signature, self.complainant_key, self.complainant
        )

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self, drop_none=False)


@dataclass
class DisputeOutcome:
    """The outcome of arbitrating a dispute.

    A guilty verdict with a zero slash is rejected.  Upstream gated slashing on
    ``slash_amount > 0.0`` and therefore returned a "guilty" verdict that
    penalised nobody.
    """

    dispute_id: str
    task_id: TaskId
    guilty: bool
    slash_amount: Money
    ruling: str
    arbitrator: Did
    arbitrator_key: bytes
    signed_at: int
    nonce: int
    signature: str = ""

    def __post_init__(self) -> None:
        self.task_id = (
            self.task_id
            if isinstance(self.task_id, TaskId)
            else TaskId.parse(self.task_id)
        )
        if isinstance(self.arbitrator, str):
            self.arbitrator = Did.parse(self.arbitrator)
        if isinstance(self.arbitrator_key, str):
            self.arbitrator_key = bytes.fromhex(self.arbitrator_key)
        if not isinstance(self.slash_amount, Money):
            self.slash_amount = Money(self.slash_amount)
        self.guilty = bool(self.guilty)

    def validate(self) -> None:
        if self.guilty and not self.slash_amount.is_positive():
            raise ValidationError("a guilty verdict must slash a positive amount")
        if not self.guilty and not self.slash_amount.is_zero():
            raise ValidationError("a not-guilty verdict must not slash anything")
        if not self.arbitrator.matches_public_key(self.arbitrator_key):
            raise DidError(
                f"DID {self.arbitrator} is not the fingerprint of the arbitrator_key"
            )

    def sign(self, identity: Identity) -> str:
        self.signature = identity.sign_payload(self)
        return self.signature

    def verify(self) -> None:
        verify_payload_bound(
            self, self.signature, self.arbitrator_key, self.arbitrator
        )

    def to_json(self) -> Dict[str, Any]:
        return _field_json(self, drop_none=False)
