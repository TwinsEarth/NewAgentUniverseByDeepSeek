"""The market client: JSON over HTTP to a ``naudd`` daemon.

Upstream v2.5.6 shipped two clients -- a Python one and a JavaScript one -- and
**neither had a single test**.  This module's tests run a real ``http.server``
stub on ``127.0.0.1:0`` so the error mapping and the request shapes are actually
exercised, not assumed.

Only the standard library is used (:mod:`urllib.request`, :mod:`json`).  An HTTP
status of 400 or above is mapped to :class:`~nau_sdk.errors.MarketError` carrying
the status, and a non-JSON error body is reported as text rather than crashing
the client.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Mapping, Optional

from .errors import MarketError
from .models import to_json

__all__ = ["DEFAULT_BASE_URL", "DEFAULT_TIMEOUT", "DEFAULT_PATHS", "MarketClient"]

DEFAULT_BASE_URL = "http://127.0.0.1:4002"
DEFAULT_TIMEOUT = 10.0

#: Characters left unescaped inside a path segment.  ``:`` is included because a
#: DID contains colons and the daemon routes on the literal ``did:nau:<fp>`` form.
_PATH_SAFE = ":-_.~"

#: Default routes, relative to ``base_url``.  They can be overridden per client
#: (``MarketClient(paths={...})``) so that the SDK can follow a daemon that
#: mounts the API elsewhere without needing a new release.
DEFAULT_PATHS: Dict[str, str] = {
    "health": "/api/v1/health",
    "deposit": "/api/v1/ledger/deposit",
    "balance": "/api/v1/ledger/balance/{account}",
    "register_agent": "/api/v1/agents",
    "get_agent": "/api/v1/agents/{did}",
    "discover": "/api/v1/discover",
    "search": "/api/v1/search",
    "publish_task": "/api/v1/tasks",
    "get_task": "/api/v1/tasks/{task_id}",
    "list_tasks": "/api/v1/tasks",
    "submit_bid": "/api/v1/tasks/{task_id}/bids",
    "match_task": "/api/v1/tasks/{task_id}/match",
    "submit_result": "/api/v1/tasks/{task_id}/result",
    "verify_result": "/api/v1/tasks/{task_id}/verify",
    "settle_task": "/api/v1/tasks/{task_id}/settle",
    "open_dispute": "/api/v1/disputes",
    "arbitrate": "/api/v1/disputes/{dispute_id}/arbitrate",
    "conservation": "/api/v1/ledger/conservation",
    "leaderboard": "/api/v1/ledger/leaderboard",
    "stats": "/api/v1/stats",
}


class MarketClient:
    """A thin, typed-ish client for the market daemon's HTTP API.

    ``base_url`` defaults to the local daemon.  ``timeout`` is in seconds.
    Every method returns decoded JSON (usually a ``dict``) or raises
    :class:`~nau_sdk.errors.MarketError`.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        *,
        paths: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise MarketError(0, "base_url must be a non-empty string")
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self.paths: Dict[str, str] = dict(DEFAULT_PATHS)
        if paths:
            self.paths.update(dict(paths))
        self.headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "nau-sdk-python",
        }
        if headers:
            self.headers.update(dict(headers))

    # -- plumbing -----------------------------------------------------------

    def url_for(self, route: str, **parameters: Any) -> str:
        """Build an absolute URL for a named route, substituting placeholders."""
        try:
            template = self.paths[route]
        except KeyError:
            raise MarketError(0, f"unknown API route `{route}`") from None
        quoted = {
            k: urllib.parse.quote(str(v), safe=_PATH_SAFE) for k, v in parameters.items()
        }
        try:
            path = template.format(**quoted)
        except KeyError as missing:
            raise MarketError(
                0, f"route `{route}` needs parameter {missing}"
            ) from None
        return self.base_url + path

    def request(
        self,
        method: str,
        url: str,
        payload: Any = None,
        query: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        """Perform one HTTP request and decode the JSON body.

        Raises :class:`MarketError` on any HTTP error, connection failure, or
        timeout.  A non-JSON *error* body is embedded in the message instead of
        escaping as a decoder crash.
        """
        if query:
            encoded = urllib.parse.urlencode(
                {k: v for k, v in query.items() if v is not None}
            )
            if encoded:
                url = f"{url}?{encoded}"
        body: Optional[bytes] = None
        headers = dict(self.headers)
        if payload is not None:
            body = json.dumps(to_json(payload)).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raw = b""
            try:
                raw = exc.read()
            except Exception:  # pragma: no cover - unreadable error body
                pass
            raise MarketError(
                exc.code, _describe_body(raw, exc.reason), method=method, path=url
            ) from None
        except urllib.error.URLError as exc:
            raise MarketError(
                0, f"cannot reach the market daemon: {exc.reason}",
                method=method, path=url,
            ) from None
        except (TimeoutError, OSError) as exc:
            raise MarketError(
                0, f"request failed: {exc}", method=method, path=url
            ) from None
        if not raw:
            return None
        return _decode_json(raw, method=method, path=url)

    def _get(self, route: str, **parameters: Any) -> Any:
        """GET a named route.

        ``_query`` is pulled out and encoded as a query string; every other
        keyword is substituted into the path template.  DIDs and task ids are
        percent-encoded, but ``:`` is left alone because it is the delimiter of a
        DID and the daemon routes on the unencoded form.
        """
        parameters = dict(parameters)
        query = parameters.pop("_query", None)
        return self.request("GET", self.url_for(route, **parameters), query=query)

    def _post(self, route: str, payload: Any = None, **parameters: Any) -> Any:
        return self.request("POST", self.url_for(route, **parameters), payload)

    # -- health and ledger --------------------------------------------------

    def health(self) -> Any:
        """Liveness/version probe."""
        return self._get("health")

    def deposit(self, account: Any, amount: Any) -> Any:
        """Deposit ``amount`` into ``account``.

        ``amount`` is integer minor units (or a :class:`~nau_sdk.models.Money` /
        decimal string) and is sent as a **JSON integer**; floats never leave
        this client.
        """
        return self._post(
            "deposit", {"account": _account(account), "amount": _minor(amount)}
        )

    def balance(self, account: Any) -> Any:
        """The balance of ``account``, in integer minor units."""
        return self._get("balance", account=_account(account))

    def conservation(self) -> Any:
        """The ledger's conservation report (integer equality, no tolerance)."""
        return self._get("conservation")

    def leaderboard(self, limit: int = 10) -> Any:
        """The top ``limit`` accounts by balance."""
        return self._get("leaderboard", _query={"limit": int(limit)})

    # -- agents -------------------------------------------------------------

    def register_agent(self, card: Any) -> Any:
        """Publish (and thereby register) an agent card."""
        return self._post("register_agent", card)

    def get_agent(self, did: Any) -> Any:
        """Look up an agent card by DID."""
        return self._get("get_agent", did=_account(did))

    def discover(self, skill: Any) -> Any:
        """Agents advertising ``skill``."""
        return self._get("discover", _query={"skill": str(skill)})

    def search(self, q: Any) -> Any:
        """Free-text search across agent cards."""
        return self._get("search", _query={"q": str(q)})

    # -- tasks --------------------------------------------------------------

    def publish_task(self, task: Any) -> Any:
        """Publish a task (its budget is escrowed from ``spec.owner``)."""
        return self._post("publish_task", task)

    def get_task(self, task_id: Any) -> Any:
        return self._get("get_task", task_id=str(task_id))

    def list_tasks(self) -> Any:
        return self._get("list_tasks")

    def submit_bid(self, task_id: Any, bid: Any) -> Any:
        return self._post("submit_bid", bid, task_id=str(task_id))

    def match_task(self, task_id: Any) -> Any:
        return self._post("match_task", None, task_id=str(task_id))

    def submit_result(self, task_id: Any, envelope: Any) -> Any:
        return self._post("submit_result", envelope, task_id=str(task_id))

    def verify_result(self, task_id: Any) -> Any:
        return self._post("verify_result", None, task_id=str(task_id))

    def settle_task(self, task_id: Any) -> Any:
        return self._post("settle_task", None, task_id=str(task_id))

    # -- disputes -----------------------------------------------------------

    def open_dispute(self, dispute: Any) -> Any:
        return self._post("open_dispute", dispute)

    def arbitrate(self, dispute_id: Any, guilty: bool, slash_amount: Any) -> Any:
        """Rule on a dispute.

        A guilty verdict must slash a positive amount; the daemon enforces it,
        and this client refuses to send the contradictory combination at all.
        """
        if guilty and int(_minor(slash_amount)) <= 0:
            raise MarketError(
                0, "a guilty verdict must slash a positive amount"
            )
        if not guilty and int(_minor(slash_amount)) != 0:
            raise MarketError(0, "a not-guilty verdict must not slash anything")
        return self._post(
            "arbitrate",
            {"guilty": bool(guilty), "slash_amount": _minor(slash_amount)},
            dispute_id=str(dispute_id),
        )

    # -- misc ---------------------------------------------------------------

    def stats(self) -> Any:
        return self._get("stats")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self.base_url!r}, timeout={self.timeout})"


# -- helpers ----------------------------------------------------------------


def _decode_json(raw: bytes, *, method: str, path: str) -> Any:
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except (ValueError, UnicodeError):
        raise MarketError(
            0,
            f"response was not JSON: {text[:200]!r}",
            method=method,
            path=path,
        ) from None


def _describe_body(raw: bytes, reason: Any) -> str:
    """Turn an error body into a message, tolerating non-JSON."""
    if not raw:
        return str(reason or "no response body")
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return str(reason or "empty response body")
    try:
        decoded = json.loads(text)
    except (ValueError, UnicodeError):
        return text[:500]
    if isinstance(decoded, dict):
        for key in ("error", "message", "detail", "reason"):
            value = decoded.get(key)
            if isinstance(value, str) and value:
                return value
        return json.dumps(decoded, sort_keys=True)[:500]
    return str(decoded)[:500]


def _account(account: Any) -> str:
    from .identity import Did

    if isinstance(account, Did):
        return account.as_str()
    if isinstance(account, str) and account.strip():
        return account
    did = getattr(account, "did", None)
    if isinstance(did, Did):
        return did.as_str()
    raise MarketError(0, f"invalid account: {account!r}")


def _minor(amount: Any) -> int:
    """Coerce an amount to integer minor units, refusing floats outright."""
    from .models import Money

    if isinstance(amount, Money):
        return int(amount)
    if isinstance(amount, bool):
        raise MarketError(0, "amount must be an integer number of minor units")
    if isinstance(amount, int):
        return int(amount)
    if isinstance(amount, str):
        return int(Money.parse(amount))
    if isinstance(amount, float):
        raise MarketError(
            0,
            f"amount {amount!r} is a float; money travels as integer minor units",
        )
    raise MarketError(0, f"invalid amount: {amount!r}")
