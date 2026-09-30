"""Shared test helpers: paths, fixture loading and HTTP stub servers.

Everything here is standard library only.  ``pytest`` is not used and not
required; the suite runs with ``unittest`` through ``run_tests.py``.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

# Make `import nau_sdk` work when tests are run from anywhere.
_HERE = os.path.dirname(os.path.abspath(__file__))
_SDK_ROOT = os.path.dirname(_HERE)
_REPO_ROOT = os.path.dirname(os.path.dirname(_SDK_ROOT))
if _SDK_ROOT not in sys.path:
    sys.path.insert(0, _SDK_ROOT)

VECTORS_PATH = os.path.join(_REPO_ROOT, "conformance", "vectors.json")
VERSION_PATH = os.path.join(_REPO_ROOT, "VERSION")

#: The fixed seed every conformance vector in every language uses.
CONFORMANCE_SEED = bytes([1] * 32)


def load_vectors() -> Dict[str, Any]:
    """Load the shared conformance fixture."""
    with open(VECTORS_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_repo_version() -> str:
    """The repository VERSION file's contents, stripped."""
    with open(VERSION_PATH, "r", encoding="utf-8") as handle:
        return handle.read().strip()


class StubHandler(BaseHTTPRequestHandler):
    """A configurable HTTP stub.

    Subclasses (or the ``routes`` mapping on the server) decide what to answer.
    ``requests`` records every request as ``(method, path, body_text)`` so tests
    can assert on what the client actually sent.

    Logging is disabled: the default handler writes to stderr, which would bury
    the test output.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    # -- dispatch -----------------------------------------------------------

    def _record(self, body: bytes) -> Tuple[str, str, str]:
        entry = (self.command, self.path, body.decode("utf-8", errors="replace"))
        self.server.requests.append(entry)  # type: ignore[attr-defined]
        return entry

    def _handler(self) -> Optional[Callable[..., Any]]:
        routes = getattr(self.server, "routes", {})  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        if path in routes:
            return routes[path]
        default = getattr(self.server, "default", None)  # type: ignore[attr-defined]
        return default

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _dispatch(self) -> None:
        body = self._read_body()
        self._record(body)
        handler = self._handler()
        if handler is None:
            self._send_json(404, {"error": "no such route"})
            return
        try:
            handler(self, body)
        except BrokenPipeError:  # pragma: no cover - client hung up
            pass

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_DELETE = _dispatch

    # -- response helpers, usable from a route handler ----------------------

    def _send_raw(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _send_json(self, status: int, obj: Any) -> None:
        self._send_raw(status, json.dumps(obj).encode("utf-8"), "application/json")

    def _send_empty(self, status: int = 202) -> None:
        self._send_raw(status, b"", "application/json")


class StubServer:
    """A ``ThreadingHTTPServer`` on ``127.0.0.1:0`` in a background thread.

    Binds an ephemeral port, so tests never collide with a real daemon and never
    need a fixed port.
    """

    def __init__(
        self,
        routes: Optional[Dict[str, Callable[..., Any]]] = None,
        default: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), StubHandler)
        self.httpd.daemon_threads = True
        self.httpd.requests = []  # type: ignore[attr-defined]
        self.httpd.routes = dict(routes or {})  # type: ignore[attr-defined]
        self.httpd.default = default  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def requests(self) -> List[Tuple[str, str, str]]:
        return self.httpd.requests  # type: ignore[attr-defined]

    def route(self, path: str, handler: Callable[..., Any]) -> None:
        self.httpd.routes[path] = handler  # type: ignore[attr-defined]

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def __enter__(self) -> "StubServer":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def json_route(obj: Any, status: int = 200) -> Callable[..., Any]:
    """A route handler that always answers with ``obj`` as JSON."""

    def handler(request: StubHandler, body: bytes) -> None:
        request._send_json(status, obj)

    return handler


def text_route(text: str, status: int = 200, content_type: str = "text/plain") -> Callable[..., Any]:
    """A route handler that answers with a non-JSON body (for error mapping)."""

    def handler(request: StubHandler, body: bytes) -> None:
        request._send_raw(status, text.encode("utf-8"), content_type)

    return handler


def echo_route(status: int = 200) -> Callable[..., Any]:
    """A route handler that returns the parsed request body it received."""

    def handler(request: StubHandler, body: bytes) -> None:
        try:
            parsed = json.loads(body.decode("utf-8")) if body else None
        except ValueError:
            parsed = {"raw": body.decode("utf-8", errors="replace")}
        request._send_json(status, {"received": parsed})

    return handler
