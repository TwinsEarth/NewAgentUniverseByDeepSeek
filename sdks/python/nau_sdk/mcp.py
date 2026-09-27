"""A minimal MCP (Model Context Protocol) client over HTTP.

The handshake is the part everybody gets wrong, so it is stated explicitly here:

1. ``initialize`` -- a JSON-RPC request, awaited.  The server answers with its
   protocol version, capabilities and server info.
2. ``notifications/initialized`` -- a JSON-RPC **notification**: it has no ``id``
   and the server sends *no response*.  Sending it as a request and waiting for a
   reply deadlocks, which is why this client posts it without awaiting anything.
3. Normal calls -- ``tools/list`` and ``tools/call``.

The protocol revision is pinned in :data:`MCP_PROTOCOL_VERSION`.  Upstream's
Python MCP client restated its protocol string inline and had no tests at all;
the handshake below is covered against a real ``http.server`` stub.
"""

from __future__ import annotations

import itertools
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Mapping, Optional

from .errors import McpError
from .market import DEFAULT_BASE_URL, DEFAULT_TIMEOUT
from .models import to_json

__all__ = ["MCP_PROTOCOL_VERSION", "DEFAULT_MCP_PATH", "McpHttpClient"]

#: The MCP protocol revision this client speaks.
MCP_PROTOCOL_VERSION = "2024-11-05"

#: Default MCP endpoint path, relative to ``base_url``.
DEFAULT_MCP_PATH = "/api/v1/mcp"

_JSONRPC_VERSION = "2.0"


class McpHttpClient:
    """JSON-RPC 2.0 over HTTP, following the MCP initialize handshake."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        path: str = DEFAULT_MCP_PATH,
        timeout: float = DEFAULT_TIMEOUT,
        *,
        client_name: str = "nau-sdk-python",
        client_version: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        auto_initialize: bool = False,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise McpError("base_url must be a non-empty string")
        self.base_url = base_url.rstrip("/")
        self.path = path if path.startswith("/") else "/" + path
        self.timeout = float(timeout)
        self.client_name = client_name
        if client_version is None:
            # Read the one source of truth rather than restating it inline.
            from .version import VERSION

            client_version = VERSION
        self.client_version = client_version
        self.headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "nau-sdk-python",
        }
        if headers:
            self.headers.update(dict(headers))
        self._ids = itertools.count(1)
        self._initialized = False
        self._notifications_sent = 0
        self._last_initialize_result: Optional[Dict[str, Any]] = None
        if auto_initialize:
            self.initialize()

    # -- plumbing -----------------------------------------------------------

    @property
    def endpoint(self) -> str:
        return self.base_url + self.path

    def _post_raw(
        self, message: Dict[str, Any], *, allow_empty: bool = False
    ) -> Optional[Dict[str, Any]]:
        """POST one JSON-RPC message.

        Returns ``None`` when the server sends no body.  That is a protocol
        violation for a *request* (the caller turns it into an error) and the
        normal outcome for a *notification* (``allow_empty=True``).
        """
        body = json.dumps(message).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint, data=body, headers=dict(self.headers), method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            if allow_empty and exc.code in (200, 202, 204):
                return None
            text = ""
            try:
                text = exc.read().decode("utf-8", errors="replace")
            except Exception:  # pragma: no cover - unreadable error body
                pass
            raise McpError(
                f"HTTP {exc.code} from the MCP endpoint: {text[:300] or exc.reason}",
                status=exc.code,
            ) from None
        except urllib.error.URLError as exc:
            raise McpError(f"cannot reach the MCP endpoint: {exc.reason}") from None
        except (TimeoutError, OSError) as exc:
            raise McpError(f"MCP request failed: {exc}") from None
        if not raw or not raw.strip():
            return None
        try:
            decoded = json.loads(raw.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeError):
            raise McpError(
                f"the MCP endpoint did not return JSON: {raw[:200]!r}"
            ) from None
        if not isinstance(decoded, dict):
            raise McpError(f"expected a JSON-RPC object, got {type(decoded).__name__}")
        return decoded

    def _call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        request_id = next(self._ids)
        message: Dict[str, Any] = {
            "jsonrpc": _JSONRPC_VERSION,
            "id": request_id,
            "method": method,
        }
        if params is not None:
            message["params"] = to_json(params)
        response = self._post_raw(message)
        if response is None:
            raise McpError(
                f"the MCP endpoint returned no response to `{method}` "
                f"(request id {request_id})"
            )
        error = response.get("error")
        if isinstance(error, dict):
            raise McpError(
                str(error.get("message") or "JSON-RPC error"),
                code=error.get("code"),
                data=error.get("data"),
            )
        if error is not None:
            raise McpError(f"malformed JSON-RPC error member: {error!r}")
        if response.get("id") not in (request_id, None):
            raise McpError(
                f"response id {response.get('id')!r} does not match request id "
                f"{request_id}"
            )
        return response.get("result")

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        """Send a JSON-RPC notification: no ``id``, and **no reply is awaited**.

        The server is not obliged to answer -- a bare 202 with an empty body is
        the expected response -- so the body is drained and discarded rather than
        parsed, and an empty body is not an error.  Transport failures still
        raise, because "the server is unreachable" is never a valid handshake.
        Waiting for a reply here is the deadlock this method exists to avoid.
        """
        message: Dict[str, Any] = {"jsonrpc": _JSONRPC_VERSION, "method": method}
        if params is not None:
            message["params"] = to_json(params)
        self._post_raw(message, allow_empty=True)
        self._notifications_sent += 1

    # -- the handshake ------------------------------------------------------

    def initialize(self) -> Dict[str, Any]:
        """Perform ``initialize`` then ``notifications/initialized``.

        Returns the server's ``initialize`` result.  Idempotent: calling it twice
        does not re-handshake.
        """
        if self._initialized and self._last_initialize_result is not None:
            return self._last_initialize_result
        result = self._call(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": self.client_name,
                    "version": self.client_version,
                },
            },
        )
        if not isinstance(result, dict):
            raise McpError("initialize did not return an object")
        negotiated = result.get("protocolVersion")
        if isinstance(negotiated, str) and negotiated != MCP_PROTOCOL_VERSION:
            # A different revision is not fatal, but the caller must know.
            result.setdefault("negotiatedProtocolVersion", negotiated)
        self._last_initialize_result = result
        self._initialized = True
        self._notify("notifications/initialized")
        return result

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self.initialize()

    # -- MCP surface --------------------------------------------------------

    def list_tools(self) -> List[Dict[str, Any]]:
        """The tools the server advertises."""
        self._ensure_initialized()
        result = self._call("tools/list", {})
        if isinstance(result, dict):
            tools = result.get("tools")
        else:
            tools = result
        if tools is None:
            return []
        if not isinstance(tools, list):
            raise McpError(f"tools/list returned {type(tools).__name__}, expected a list")
        return tools

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Invoke a tool by name and return its (unwrapped) result."""
        if not isinstance(name, str) or not name:
            raise McpError("a tool name is required")
        self._ensure_initialized()
        result = self._call(
            "tools/call", {"name": name, "arguments": dict(arguments or {})}
        )
        if isinstance(result, dict) and result.get("isError") is True:
            raise McpError(f"tool `{name}` reported an error: {result.get('content')!r}")
        return result

    # -- introspection ------------------------------------------------------

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def server_info(self) -> Optional[Dict[str, Any]]:
        return self._last_initialize_result

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(endpoint={self.endpoint!r}, "
            f"initialized={self._initialized})"
        )
