"""An append-only, integer-only settlement ledger.

Upstream's ledger kept every balance in an ``f64`` and asserted conservation with
a tolerance::

    let conserved = (self.balance_sum - expected_sum).abs() < 0.001

A ledger that is only "conserved to within 0.001" is not conserved.  The error is
real money, it grows without bound, and a participant who understands the drift
can steer it.  Here every amount is a :class:`~nau_sdk.models.Money` (an exact
integer count of minor units) and conservation is an *equality* over integers.

Every entry is chained: each one carries the SHA-256 of the previous entry, so
the history cannot be edited in place without breaking the chain.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

from .canonical import canonical_payload
from .errors import AmountError, ValidationError
from .identity import Did
from .models import CURRENCY, Money

__all__ = ["GENESIS_HASH", "LedgerEntry", "Ledger"]

#: The ``prev_hash`` of the first entry in a ledger.
GENESIS_HASH = "0" * 64


@dataclass
class LedgerEntry:
    """One immutable, hash-chained movement of value."""

    index: int
    kind: str
    account: str
    amount: Money
    balance_after: Money
    prev_hash: str
    hash: str = ""
    memo: str = ""
    task_id: Optional[str] = None
    signed_at: int = 0

    def payload(self) -> Dict[str, Any]:
        """The canonical body that :attr:`hash` commits to."""
        return {
            "index": self.index,
            "kind": self.kind,
            "account": self.account,
            "amount": int(self.amount),
            "balance_after": int(self.balance_after),
            "prev_hash": self.prev_hash,
            "memo": self.memo,
            "task_id": self.task_id,
            "signed_at": self.signed_at,
        }

    def compute_hash(self) -> str:
        """SHA-256 over the canonical payload (no floats can enter it)."""
        return hashlib.sha256(canonical_payload(self.payload())).hexdigest()

    def to_json(self) -> Dict[str, Any]:
        out = self.payload()
        out["hash"] = self.hash
        return out


class Ledger:
    """An in-memory double-entry ledger over exact integer amounts.

    The ledger tracks *external* funds (deposits and withdrawals) and balances;
    internal movements never change the total, which is what conservation means.
    """

    def __init__(self) -> None:
        self._balances: Dict[str, Money] = {}
        self._entries: List[LedgerEntry] = []
        self._external: Money = Money(0)

    # -- balances -----------------------------------------------------------

    def balance(self, account: str) -> Money:
        """The balance of ``account``; zero for an account never seen."""
        self._check_account(account)
        return self._balances.get(account, Money(0))

    def accounts(self) -> List[str]:
        return sorted(self._balances)

    def total(self) -> Money:
        """The sum of every balance."""
        return Money(sum(int(v) for v in self._balances.values()))

    def external_total(self) -> Money:
        """Deposits minus withdrawals -- the only way value enters or leaves."""
        return self._external

    @staticmethod
    def _check_account(account: str) -> None:
        if not isinstance(account, str) or not account.strip():
            raise ValidationError("an account name must be a non-empty string")

    # -- movements ----------------------------------------------------------

    def _record(
        self,
        kind: str,
        account: str,
        amount: Money,
        *,
        memo: str = "",
        task_id: Optional[str] = None,
        signed_at: int = 0,
    ) -> LedgerEntry:
        self._check_account(account)
        previous = self._balances.get(account, Money(0))
        balance_after = previous.checked_add(amount)
        entry = LedgerEntry(
            index=len(self._entries),
            kind=kind,
            account=account,
            amount=amount,
            balance_after=balance_after,
            prev_hash=self._entries[-1].hash if self._entries else GENESIS_HASH,
            memo=memo,
            task_id=task_id,
            signed_at=signed_at,
        )
        entry.hash = entry.compute_hash()
        self._balances[account] = balance_after
        self._entries.append(entry)
        return entry

    def deposit(
        self,
        account: str,
        amount: Money,
        *,
        memo: str = "",
        signed_at: int = 0,
    ) -> LedgerEntry:
        """Bring value in from outside the ledger."""
        amount = self._as_money(amount)
        if amount.is_negative():
            raise AmountError("a deposit must not be negative")
        self._external = self._external.checked_add(amount)
        return self._record(
            "deposit", account, amount, memo=memo, signed_at=signed_at
        )

    def withdraw(
        self,
        account: str,
        amount: Money,
        *,
        memo: str = "",
        signed_at: int = 0,
    ) -> LedgerEntry:
        """Take value out of the ledger (a pure balance move, checked)."""
        amount = self._as_money(amount)
        if amount.is_negative():
            raise AmountError("a withdrawal must not be negative")
        if self.balance(account) < amount:
            raise AmountError(
                f"account `{account}` holds {self.balance(account).to_decimal_string()} "
                f"but {amount.to_decimal_string()} was requested"
            )
        return self._record(
            "withdraw", account, amount.checked_neg(), memo=memo, signed_at=signed_at
        )

    def credit(
        self,
        account: str,
        amount: Money,
        *,
        memo: str = "",
        task_id: Optional[str] = None,
        signed_at: int = 0,
    ) -> LedgerEntry:
        """Move value *within* the ledger: the total is unchanged."""
        amount = self._as_money(amount)
        if amount.is_negative():
            raise AmountError("a credit must not be negative")
        return self._record(
            "credit", account, amount, memo=memo, task_id=task_id, signed_at=signed_at
        )

    def debit(
        self,
        account: str,
        amount: Money,
        *,
        memo: str = "",
        task_id: Optional[str] = None,
        signed_at: int = 0,
    ) -> LedgerEntry:
        """Move value *within* the ledger: the total is unchanged, and it is checked."""
        amount = self._as_money(amount)
        if amount.is_negative():
            raise AmountError("a debit must not be negative")
        if self.balance(account) < amount:
            raise AmountError(
                f"account `{account}` holds {self.balance(account).to_decimal_string()} "
                f"but {amount.to_decimal_string()} was requested"
            )
        return self._record(
            "debit", account, amount.checked_neg(), memo=memo, task_id=task_id,
            signed_at=signed_at,
        )

    def transfer(
        self,
        source: str,
        destination: str,
        amount: Money,
        *,
        memo: str = "",
        task_id: Optional[str] = None,
        signed_at: int = 0,
    ) -> "tuple[LedgerEntry, LedgerEntry]":
        """Atomically debit ``source`` and credit ``destination``."""
        if source == destination:
            raise ValidationError("a transfer needs two distinct accounts")
        amount = self._as_money(amount)
        if not amount.is_positive():
            raise AmountError("a transfer must be strictly positive")
        # Check both sides *before* mutating anything, so a failure cannot leave
        # half a transfer behind.
        self.balance(source).checked_sub(amount)
        debit = self.debit(
            source, amount, memo=memo, task_id=task_id, signed_at=signed_at
        )
        credit = self.credit(
            destination, amount, memo=memo, task_id=task_id, signed_at=signed_at
        )
        return debit, credit

    def slash(
        self,
        account: str,
        amount: Money,
        *,
        memo: str = "",
        task_id: Optional[str] = None,
        signed_at: int = 0,
    ) -> LedgerEntry:
        """Confiscate stake: the value leaves the ledger, so ``external`` shrinks."""
        amount = self._as_money(amount)
        if amount.is_negative():
            raise AmountError("a slash must not be negative")
        if self.balance(account) < amount:
            raise AmountError(
                f"account `{account}` holds {self.balance(account).to_decimal_string()} "
                f"but {amount.to_decimal_string()} was requested"
            )
        self._external = self._external.checked_sub(amount)
        return self._record(
            "slash", account, amount.checked_neg(), memo=memo, task_id=task_id,
            signed_at=signed_at,
        )

    # -- conservation -------------------------------------------------------

    def conserved(self) -> bool:
        """True when the sum of balances equals the external total exactly.

        This is an integer equality.  There is no tolerance, and there is
        nothing to tune: if it returns ``False``, value was created or destroyed.
        """
        return int(self.total()) == int(self._external)

    def assert_conserved(self) -> None:
        """Raise :class:`AmountError` unless :meth:`conserved` holds."""
        if not self.conserved():
            difference = int(self.total()) - int(self._external)
            raise AmountError(
                "ledger is not conserved: balances total "
                f"{self.total().to_decimal_string()} but external flow is "
                f"{self._external.to_decimal_string()} (difference "
                f"{Money(abs(difference)).to_decimal_string()})"
            )

    def verify_chain(self) -> None:
        """Recompute every hash and link; raise on the first inconsistency."""
        previous = GENESIS_HASH
        for position, entry in enumerate(self._entries):
            if entry.index != position:
                raise ValidationError(
                    f"entry {position} claims index {entry.index}"
                )
            if entry.prev_hash != previous:
                raise ValidationError(
                    f"entry {position} does not link to its predecessor"
                )
            if entry.compute_hash() != entry.hash:
                raise ValidationError(f"entry {position} has been tampered with")
            previous = entry.hash

    # -- accessors ----------------------------------------------------------

    def entries(self) -> "tuple[LedgerEntry, ...]":
        return tuple(self._entries)

    def entries_for(self, account: str) -> "tuple[LedgerEntry, ...]":
        return tuple(e for e in self._entries if e.account == account)

    def head_hash(self) -> str:
        return self._entries[-1].hash if self._entries else GENESIS_HASH

    def conservation_report(self) -> Dict[str, Any]:
        """A JSON-safe summary, used by ``MarketClient.conservation``."""
        return {
            "currency": CURRENCY,
            "balances_total_minor": int(self.total()),
            "external_total_minor": int(self._external),
            "balanced": self.conserved(),
            "entries": len(self._entries),
            "head_hash": self.head_hash(),
            "accounts": len(self._balances),
        }

    def leaderboard(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Accounts ranked by balance, descending."""
        if limit <= 0:
            raise ValidationError("leaderboard limit must be positive")
        ranked = sorted(
            self._balances.items(), key=lambda kv: (-int(kv[1]), kv[0])
        )
        return [
            {"account": account, "balance_minor": int(balance)}
            for account, balance in ranked[:limit]
        ]

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _as_money(amount: Any) -> Money:
        if isinstance(amount, Money):
            return amount
        if isinstance(amount, int) and not isinstance(amount, bool):
            return Money(amount)
        if isinstance(amount, str):
            return Money.parse(amount)
        raise AmountError(
            f"amount must be Money, int minor units or a decimal string, got "
            f"{type(amount).__name__}"
        )

    @staticmethod
    def account_did(identity_or_did: Any) -> str:
        """Accept a DID, an ``Identity`` or a plain string as an account name."""
        if isinstance(identity_or_did, Did):
            return identity_or_did.as_str()
        if isinstance(identity_or_did, str):
            return identity_or_did
        did = getattr(identity_or_did, "did", None)
        if isinstance(did, Did):
            return did.as_str()
        raise ValidationError(
            f"cannot use {type(identity_or_did).__name__} as a ledger account"
        )

    def __iter__(self) -> Iterator[LedgerEntry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return (
            f"Ledger(entries={len(self._entries)}, accounts={len(self._balances)}, "
            f"conserved={self.conserved()})"
        )
