from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

from fastmcp import FastMCP
from ida_mcp.proxy.http_server import _SessionStickyMiddleware as ProxySessionStickyMiddleware
from ida_mcp.registry_server import _SessionStickyMiddleware as GatewaySessionStickyMiddleware


def _load_utils_module():
    repo_root = Path(__file__).resolve().parents[1]
    utils_path = repo_root / "ida_mcp" / "utils.py"
    spec = importlib.util.spec_from_file_location("ida_mcp_utils_only", utils_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_get_streamable_http_session_manager():
    utils = _load_utils_module()

    mcp = FastMCP("cleanup-test")
    app = mcp.http_app(path="/mcp")

    session_manager = utils.get_streamable_http_session_manager(app)
    assert session_manager is not None
    assert hasattr(session_manager, "_server_instances")


def test_prune_terminated_streamable_http_sessions():
    utils = _load_utils_module()

    class FakeTransport:
        def __init__(self, is_terminated: bool):
            self.is_terminated = is_terminated

    class FakeSessionManager:
        def __init__(self):
            self._server_instances = {
                "dead-a": FakeTransport(True),
                "alive-b": FakeTransport(False),
                "dead-c": FakeTransport(True),
            }

    session_manager = FakeSessionManager()
    removed = utils.prune_terminated_streamable_http_sessions(session_manager)

    assert removed == 2
    assert list(session_manager._server_instances.keys()) == ["alive-b"]

class _FakeSessionRecoveringApp:
    def __init__(self):
        self.calls = []

    async def __call__(self, scope, receive, send):
        headers = list(scope.get("headers", []))
        self.calls.append(headers)

        while True:
            message = await receive()
            if message.get("type") != "http.request" or not message.get("more_body", False):
                break

        header_map = {key.lower(): value for key, value in headers}
        if header_map.get(b"mcp-session-id") == b"stale-session":
            await send(
                {
                    "type": "http.response.start",
                    "status": 404,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"jsonrpc":"2.0","error":{"code":-32600,"message":"Session not found"}}',
                    "more_body": False,
                }
            )
            return

        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"mcp-session-id", b"fresh-session"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b'{"ok":true}', "more_body": False})


def _run_http_app(app, headers=None):
    sent_messages = []
    request_messages = [{"type": "http.request", "body": b"", "more_body": False}]

    async def _receive():
        if request_messages:
            return request_messages.pop(0)
        return {"type": "http.disconnect"}

    async def _send(message):
        sent_messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "headers": headers or [],
    }

    asyncio.run(app(scope, _receive, _send))
    return sent_messages


def _find_header(headers, name: bytes):
    for key, value in headers:
        if key.lower() == name.lower():
            return value
    return None


def test_session_sticky_middleware_retries_cached_stale_session():
    app = _FakeSessionRecoveringApp()
    middleware = ProxySessionStickyMiddleware(app)
    middleware._session_id = "stale-session"

    sent_messages = _run_http_app(middleware)

    assert len(app.calls) == 2
    assert _find_header(app.calls[0], b"mcp-session-id") == b"stale-session"
    assert _find_header(app.calls[1], b"mcp-session-id") is None
    assert sent_messages[0]["type"] == "http.response.start"
    assert sent_messages[0]["status"] == 200
    assert _find_header(sent_messages[0]["headers"], b"mcp-session-id") == b"fresh-session"
    assert middleware._session_id == "fresh-session"


def test_session_sticky_middleware_retries_client_supplied_stale_session():
    app = _FakeSessionRecoveringApp()
    middleware = ProxySessionStickyMiddleware(app)

    sent_messages = _run_http_app(middleware, headers=[(b"mcp-session-id", b"stale-session")])

    assert len(app.calls) == 2
    assert _find_header(app.calls[0], b"mcp-session-id") == b"stale-session"
    assert _find_header(app.calls[1], b"mcp-session-id") is None
    assert sent_messages[0]["type"] == "http.response.start"
    assert sent_messages[0]["status"] == 200
    assert _find_header(sent_messages[0]["headers"], b"mcp-session-id") == b"fresh-session"
    assert middleware._session_id == "fresh-session"


def test_gateway_session_sticky_middleware_retries_cached_stale_session():
    app = _FakeSessionRecoveringApp()
    middleware = GatewaySessionStickyMiddleware(app)
    middleware._session_id = "stale-session"

    sent_messages = _run_http_app(middleware)

    assert len(app.calls) == 2
    assert _find_header(app.calls[0], b"mcp-session-id") == b"stale-session"
    assert _find_header(app.calls[1], b"mcp-session-id") is None
    assert sent_messages[0]["type"] == "http.response.start"
    assert sent_messages[0]["status"] == 200
    assert _find_header(sent_messages[0]["headers"], b"mcp-session-id") == b"fresh-session"
    assert middleware._session_id == "fresh-session"

