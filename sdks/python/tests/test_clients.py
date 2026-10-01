"""Client tests against a real ``http.server`` stub.

Upstream v2.5.6 shipped a Python market client and a Python MCP client and had
**zero tests for either**.  Each test here starts a ``ThreadingHTTPServer`` on
``127.0.0.1:0`` in a background thread, so the request shapes, the error mapping
and the MCP handshake are actually exercised.
"""

from __future__ import annotations

import json
import unittest

try:  # discovered as a package by run_tests.py
    from ._support import StubHandler, StubServer, echo_route, json_route, text_route
except ImportError:  # pragma: no cover - run as a plain script
    from _support import StubHandler, StubServer, echo_route, json_route, text_route

from nau_sdk import (
    MCP_PROTOCOL_VERSION,
    AgentCard,
    Did,
    Identity,
    MarketClient,
    MarketError,
    McpError,
    McpHttpClient,
    Money,
    Skill,
    TaskSpec,
    VerificationPolicy,
    major,
)
from nau_sdk.version import VERSION


class TestMarketClient(unittest.TestCase):
    def setUp(self) -> None:
        self.server = StubServer()
        self.addCleanup(self.server.close)
        self.client = MarketClient(base_url=self.server.base_url, timeout=5.0)

    def last_request(self) -> tuple:
        self.assertTrue(self.server.requests, "the stub received no request")
        return self.server.requests[-1]

    # -- transport ----------------------------------------------------------

    def test_health_gets_the_health_route(self) -> None:
        self.server.route("/api/v1/health", json_route({"status": "ok", "version": "1.0.1"}))
        self.assertEqual(self.client.health()["status"], "ok")
        method, path, _body = self.last_request()
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/api/v1/health")

    def test_deposit_posts_integer_minor_units(self) -> None:
        self.server.route("/api/v1/ledger/deposit", echo_route())
        result = self.client.deposit("alice", Money.parse("0.1"))
        self.assertEqual(result["received"], {"account": "alice", "amount": 100000})
        method, _path, body = self.last_request()
        self.assertEqual(method, "POST")
        # The wire form must be a JSON integer, never 0.1.
        self.assertNotIn("0.1", body)
        self.assertIn('"amount": 100000', body)

    def test_a_float_amount_is_refused_before_it_reaches_the_wire(self) -> None:
        with self.assertRaises(MarketError):
            self.client.deposit("alice", 0.1)
        self.assertEqual(self.server.requests, [])

    def test_balance_quotes_the_account_in_the_path(self) -> None:
        self.server.route(
            "/api/v1/ledger/balance/alice", json_route({"account": "alice", "balance_minor": 5})
        )
        self.assertEqual(self.client.balance("alice")["balance_minor"], 5)
        self.assertEqual(self.last_request()[1], "/api/v1/ledger/balance/alice")

    def test_balance_accepts_a_did_or_an_identity(self) -> None:
        account = Did.parse("did:nau:34750f98bd59fcfc")
        path = "/api/v1/ledger/balance/" + account.as_str()
        self.server.route(path, json_route({"ok": True}))
        self.client.balance(account)
        self.assertEqual(self.last_request()[1], path)

        identity = Identity.from_seed(bytes([4] * 32))
        did_path = "/api/v1/ledger/balance/" + identity.did.as_str()
        self.server.route(did_path, json_route({"ok": True}))
        self.client.balance(identity)
        self.assertEqual(self.last_request()[1], did_path)

    # -- error mapping ------------------------------------------------------

    def test_a_json_error_maps_to_market_error_with_the_status(self) -> None:
        self.server.route(
            "/api/v1/ledger/balance/bob",
            json_route({"error": "no such account"}, status=404),
        )
        with self.assertRaises(MarketError) as ctx:
            self.client.balance("bob")
        self.assertEqual(ctx.exception.status, 404)
        self.assertIn("no such account", str(ctx.exception))

    def test_a_non_json_error_body_does_not_crash_the_client(self) -> None:
        self.server.route(
            "/api/v1/ledger/balance/bob",
            text_route("<html><body>502 Bad Gateway</body></html>", status=502),
        )
        with self.assertRaises(MarketError) as ctx:
            self.client.balance("bob")
        self.assertEqual(ctx.exception.status, 502)
        self.assertIn("502 Bad Gateway", str(ctx.exception))

    def test_an_empty_error_body_is_still_a_market_error(self) -> None:
        def empty(request: StubHandler, body: bytes) -> None:
            request._send_raw(500, b"", "text/plain")

        self.server.route("/api/v1/stats", empty)
        with self.assertRaises(MarketError) as ctx:
            self.client.stats()
        self.assertEqual(ctx.exception.status, 500)

    def test_a_non_json_success_body_is_reported_not_crashed(self) -> None:
        self.server.route("/api/v1/stats", text_route("not json at all"))
        with self.assertRaises(MarketError):
            self.client.stats()

    def test_an_unreachable_daemon_is_a_market_error_with_status_zero(self) -> None:
        client = MarketClient(base_url="http://127.0.0.1:1", timeout=1.0)
        with self.assertRaises(MarketError) as ctx:
            client.health()
        self.assertEqual(ctx.exception.status, 0)

    def test_a_204_with_no_body_returns_none(self) -> None:
        def no_content(request: StubHandler, body: bytes) -> None:
            request._send_raw(204, b"", "application/json")

        self.server.route("/api/v1/stats", no_content)
        self.assertIsNone(self.client.stats())

    # -- request shapes -----------------------------------------------------

    def test_every_documented_method_reaches_its_route(self) -> None:
        """One case per route, so a typo in a path cannot hide."""
        identity = Identity.from_seed(bytes([7] * 32))
        task = {
            "id": "task-abc",
            "spec": TaskSpec(
                goal="g",
                context="c",
                done=["d"],
                todo=["t"],
                owner=identity.did,
            ),
            "required_skills": ["translation"],
            "budget": 10_000_000,
            "requester_key": identity.public_key_hex,
            "state": "open",
            "verification": VerificationPolicy.requester_only(),
            "signed_at": 1,
            "nonce": 1,
            "signature": "",
        }
        card = AgentCard.draft(
            identity, "Translator", [Skill.new("translation")], major(1), 1, 1
        )
        calls = [
            ("POST", "/api/v1/agents", lambda: self.client.register_agent(card)),
            ("GET", "/api/v1/agents/" + identity.did.as_str(), lambda: self.client.get_agent(identity.did.as_str())),
            ("GET", "/api/v1/discover?skill=translation", lambda: self.client.discover("translation")),
            ("GET", "/api/v1/search?q=trans", lambda: self.client.search("trans")),
            ("POST", "/api/v1/tasks", lambda: self.client.publish_task(task)),
            ("GET", "/api/v1/tasks/task-abc", lambda: self.client.get_task("task-abc")),
            ("GET", "/api/v1/tasks", lambda: self.client.list_tasks()),
            ("POST", "/api/v1/tasks/task-abc/bids", lambda: self.client.submit_bid("task-abc", {"price": 1})),
            ("POST", "/api/v1/tasks/task-abc/match", lambda: self.client.match_task("task-abc")),
            ("POST", "/api/v1/tasks/task-abc/result", lambda: self.client.submit_result("task-abc", {"x": 1})),
            ("POST", "/api/v1/tasks/task-abc/verify", lambda: self.client.verify_result("task-abc")),
            ("POST", "/api/v1/tasks/task-abc/settle", lambda: self.client.settle_task("task-abc")),
            ("POST", "/api/v1/disputes", lambda: self.client.open_dispute({"id": "d1"})),
            ("GET", "/api/v1/ledger/conservation", lambda: self.client.conservation()),
            ("GET", "/api/v1/ledger/leaderboard?limit=5", lambda: self.client.leaderboard(5)),
            ("GET", "/api/v1/stats", lambda: self.client.stats()),
        ]
        for method, path, call in calls:
            with self.subTest(path=path):
                self.server.route(path.split("?")[0], json_route({"ok": True}))
                self.assertIsInstance(call(), dict)
                seen_method, seen_path, _body = self.last_request()
                self.assertEqual(seen_method, method)
                self.assertEqual(seen_path, path)

    def test_arbitrate_refuses_a_contradictory_verdict(self) -> None:
        with self.assertRaises(MarketError):
            self.client.arbitrate("d1", True, Money(0))
        with self.assertRaises(MarketError):
            self.client.arbitrate("d1", False, major(1))
        self.assertEqual(self.server.requests, [])

    def test_arbitrate_sends_the_amount_as_minor_units(self) -> None:
        self.server.route("/api/v1/disputes/d1/arbitrate", echo_route())
        result = self.client.arbitrate("d1", True, major(10))
        self.assertEqual(result["received"], {"guilty": True, "slash_amount": 10_000_000})

    def test_model_objects_are_serialized_without_floats(self) -> None:
        self.server.route("/api/v1/agents", echo_route())
        identity = Identity.from_seed(bytes([8] * 32))
        card = AgentCard.draft(identity, "T", [Skill.new("translation")], major(1), 5, 1)
        card.sign(identity)
        result = self.client.register_agent(card)
        received = result["received"]
        self.assertEqual(received["owner"], identity.did.as_str())
        self.assertEqual(received["stake"], 1_000_000)
        self.assertIsInstance(received["stake"], int)
        self.assertEqual(received["skills"][0]["id"], "translation")
        self.assertIn("signature", received)
        # Round-trips as valid JSON with no float anywhere.
        self.assertNotIn(".", json.dumps(received))

    def test_unknown_routes_are_refused_locally(self) -> None:
        with self.assertRaises(MarketError):
            self.client.url_for("no_such_route")

    def test_paths_can_be_overridden_per_client(self) -> None:
        self.server.route("/custom/health", json_route({"status": "ok"}))
        client = MarketClient(
            base_url=self.server.base_url,
            timeout=5.0,
            paths={"health": "/custom/health"},
        )
        self.assertEqual(client.health()["status"], "ok")
        self.assertEqual(self.last_request()[1], "/custom/health")

    def test_an_empty_base_url_is_refused(self) -> None:
        with self.assertRaises(MarketError):
            MarketClient(base_url="")

    def test_a_bad_query_parameter_is_url_encoded(self) -> None:
        self.server.route("/api/v1/search", json_route({"ok": True}))
        self.client.search("a b&c=d")
        self.assertEqual(self.last_request()[1], "/api/v1/search?q=a+b%26c%3Dd")

    def test_every_method_returns_the_decoded_body(self) -> None:
        self.server.route("/api/v1/stats", json_route({"agents": 3, "tasks": 4}))
        self.assertEqual(self.client.stats(), {"agents": 3, "tasks": 4})


class TestMcpHttpClient(unittest.TestCase):
    def setUp(self) -> None:
        self.initialized_notifications = 0
        self.server = StubServer()
        self.addCleanup(self.server.close)
        self.server.route("/api/v1/mcp", self._mcp)
        self.client = McpHttpClient(base_url=self.server.base_url, timeout=5.0)

    def _mcp(self, request: StubHandler, body: bytes) -> None:
        """A minimal, conformant MCP server.

        ``notifications/initialized`` is answered with a bare 202 and an empty
        body -- exactly what deadlocks a client that awaits a reply.
        """
        message = json.loads(body.decode("utf-8"))
        method = message.get("method")
        if "id" not in message:
            self.initialized_notifications += 1
            request._send_empty(202)
            return
        if method == "initialize":
            request._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "stub", "version": "0"},
                    },
                },
            )
        elif method == "tools/list":
            request._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {"tools": [{"name": "echo", "description": "echoes"}]},
                },
            )
        elif method == "tools/call":
            name = message["params"]["name"]
            if name == "explode":
                request._send_json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {"code": -32601, "message": "no such tool"},
                    },
                )
            else:
                request._send_json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": "ok"}],
                            "arguments": message["params"]["arguments"],
                        },
                    },
                )
        else:
            request._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": -32601, "message": f"unknown method {method}"},
                },
            )

    def methods(self) -> list:
        return [
            json.loads(body)["method"]
            for _m, _p, body in self.server.requests
            if body
        ]

    # -- handshake ----------------------------------------------------------

    def test_initialize_performs_the_full_handshake(self) -> None:
        result = self.client.initialize()
        self.assertEqual(result["serverInfo"]["name"], "stub")
        self.assertEqual(result["protocolVersion"], MCP_PROTOCOL_VERSION)
        # initialize, then the notification -- and the notification is sent
        # without an id, so the server cannot reply to it.
        self.assertEqual(self.methods(), ["initialize", "notifications/initialized"])
        payloads = [json.loads(b) for _m, _p, b in self.server.requests if b]
        self.assertIn("id", payloads[0])
        self.assertNotIn("id", payloads[1], "a notification must not carry an id")
        self.assertEqual(payloads[1]["jsonrpc"], "2.0")
        self.assertEqual(self.initialized_notifications, 1)

    def test_the_client_pins_the_protocol_version(self) -> None:
        self.client.initialize()
        sent = json.loads(self.server.requests[0][2])
        self.assertEqual(sent["params"]["protocolVersion"], MCP_PROTOCOL_VERSION)
        self.assertEqual(MCP_PROTOCOL_VERSION, "2024-11-05")

    def test_the_client_reports_its_own_version_from_the_version_file(self) -> None:
        self.client.initialize()
        sent = json.loads(self.server.requests[0][2])
        self.assertEqual(sent["params"]["clientInfo"]["version"], VERSION)

    def test_initialize_is_idempotent(self) -> None:
        self.client.initialize()
        self.client.initialize()
        self.assertEqual(self.methods().count("initialize"), 1)
        self.assertEqual(self.initialized_notifications, 1)

    def test_the_handshake_completes_against_an_empty_notification_response(self) -> None:
        # The stub answers the notification with 202 and no body; a client that
        # awaited a reply here would hang or raise.
        self.client.initialize()
        self.assertTrue(self.client.initialized)

    def test_normal_calls_trigger_the_handshake_first(self) -> None:
        tools = self.client.list_tools()
        self.assertEqual(tools[0]["name"], "echo")
        self.assertEqual(self.methods()[:2], ["initialize", "notifications/initialized"])
        self.assertIn("tools/list", self.methods())

    # -- calls --------------------------------------------------------------

    def test_call_tool_returns_the_result(self) -> None:
        result = self.client.call_tool("echo", {"text": "hi"})
        self.assertEqual(result["arguments"], {"text": "hi"})
        sent = json.loads(self.server.requests[-1][2])
        self.assertEqual(sent["method"], "tools/call")
        self.assertEqual(sent["params"], {"name": "echo", "arguments": {"text": "hi"}})

    def test_call_tool_defaults_to_empty_arguments(self) -> None:
        self.client.call_tool("echo")
        sent = json.loads(self.server.requests[-1][2])
        self.assertEqual(sent["params"]["arguments"], {})

    def test_a_json_rpc_error_becomes_an_mcp_error_with_the_code(self) -> None:
        with self.assertRaises(McpError) as ctx:
            self.client.call_tool("explode")
        self.assertEqual(ctx.exception.code, -32601)
        self.assertIn("no such tool", str(ctx.exception))

    def test_a_tool_level_error_is_reported(self) -> None:
        self.server.route("/api/v1/mcp", self._error_tool)
        with self.assertRaises(McpError):
            self.client.call_tool("bad")

    def _error_tool(self, request: StubHandler, body: bytes) -> None:
        message = json.loads(body.decode("utf-8"))
        if "id" not in message:
            request._send_empty(202)
            return
        if message["method"] == "initialize":
            request._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {"protocolVersion": MCP_PROTOCOL_VERSION},
                },
            )
        else:
            request._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {"isError": True, "content": [{"type": "text", "text": "bad"}]},
                },
            )

    def test_a_missing_tool_name_is_refused_locally(self) -> None:
        with self.assertRaises(McpError):
            self.client.call_tool("")
        self.assertEqual(self.server.requests, [])

    # -- failure modes ------------------------------------------------------

    def test_an_http_error_becomes_an_mcp_error(self) -> None:
        self.server.route("/api/v1/mcp", text_route("nope", status=503))
        with self.assertRaises(McpError) as ctx:
            self.client.initialize()
        self.assertEqual(ctx.exception.status, 503)

    def test_a_non_json_response_becomes_an_mcp_error(self) -> None:
        self.server.route("/api/v1/mcp", text_route("this is not json"))
        with self.assertRaises(McpError):
            self.client.initialize()

    def test_an_empty_response_to_a_request_is_an_mcp_error(self) -> None:
        def empty(request: StubHandler, body: bytes) -> None:
            request._send_empty(200)

        self.server.route("/api/v1/mcp", empty)
        with self.assertRaises(McpError):
            self.client.initialize()

    def test_a_mismatched_response_id_is_refused(self) -> None:
        def wrong_id(request: StubHandler, body: bytes) -> None:
            message = json.loads(body.decode("utf-8"))
            if "id" not in message:
                request._send_empty(202)
                return
            request._send_json(
                200, {"jsonrpc": "2.0", "id": 999_999, "result": {"protocolVersion": MCP_PROTOCOL_VERSION}}
            )

        self.server.route("/api/v1/mcp", wrong_id)
        with self.assertRaises(McpError):
            self.client.initialize()

    def test_an_unreachable_endpoint_is_an_mcp_error(self) -> None:
        client = McpHttpClient(base_url="http://127.0.0.1:1", timeout=1.0)
        with self.assertRaises(McpError):
            client.initialize()

    def test_an_empty_base_url_is_refused(self) -> None:
        with self.assertRaises(McpError):
            McpHttpClient(base_url="")

    def test_the_endpoint_joins_base_url_and_path(self) -> None:
        client = McpHttpClient(base_url="http://127.0.0.1:4002/", path="api/v1/mcp")
        self.assertEqual(client.endpoint, "http://127.0.0.1:4002/api/v1/mcp")

    def test_auto_initialize_runs_the_handshake_at_construction(self) -> None:
        client = McpHttpClient(
            base_url=self.server.base_url, timeout=5.0, auto_initialize=True
        )
        self.assertTrue(client.initialized)
        self.assertEqual(self.initialized_notifications, 1)

    def test_server_info_is_exposed_after_the_handshake(self) -> None:
        self.client.initialize()
        self.assertEqual(self.client.server_info["serverInfo"]["name"], "stub")


if __name__ == "__main__":
    unittest.main()
