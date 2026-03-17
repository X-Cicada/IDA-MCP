"""Standalone single-port gateway for instance registration, routing, and MCP proxying."""
from __future__ import annotations

import asyncio
import json
import pathlib
import socket
import sys
import threading
import time
import traceback
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

if __package__ in {None, ""}:
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from ida_mcp.config import get_http_bind_host, get_http_connect_host, get_http_path, get_http_port, get_request_timeout
    from ida_mcp.proxy._server import server as proxy_server
else:
    from .config import get_http_bind_host, get_http_connect_host, get_http_path, get_http_port, get_request_timeout
    from .proxy._server import server as proxy_server

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route


LOCALHOST = "127.0.0.1"
GATEWAY_BIND_HOST = get_http_bind_host()
GATEWAY_CONNECT_HOST = get_http_connect_host()
GATEWAY_PORT = get_http_port()
MCP_PATH = get_http_path()
REQUEST_TIMEOUT = get_request_timeout()

DEBUG_ENABLED = False
DEBUG_MAX_LEN = 1000

_instances: List[Dict[str, Any]] = []
_lock = threading.RLock()
_current_instance_port: Optional[int] = None
_call_locks: Dict[int, asyncio.Lock] = {}
_proxy_ready = False
_proxy_last_error: Optional[str] = None
_gateway_started_at = time.time()
_uvicorn_server = None


class _SessionStickyMiddleware:
    """Reuse the same MCP session across concurrent HTTP requests."""

    def __init__(self, app):
        self.app = app
        self._session_id: Optional[str] = None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_headers = list(scope.get("headers", []))
        has_session = any(key.lower() == b"mcp-session-id" for key, _ in raw_headers)
        if not has_session and self._session_id is not None:
            raw_headers.append((b"mcp-session-id", self._session_id.encode("ascii")))
            scope = {**scope, "headers": raw_headers}

        middleware_self = self

        async def _capture_send(message):
            if message.get("type") == "http.response.start":
                for key, value in message.get("headers", []):
                    if key.lower() == b"mcp-session-id":
                        middleware_self._session_id = value.decode("ascii")
                        break
                if int(message.get("status") or 0) >= 400:
                    middleware_self._session_id = None
            await send(message)

        await self.app(scope, receive, _capture_send)


def _short(v: Any) -> str:
    try:
        s = json.dumps(v, ensure_ascii=False)
    except Exception:
        s = str(v)
    if len(s) > DEBUG_MAX_LEN:
        return s[:DEBUG_MAX_LEN] + "..."
    return s


def _debug_log(event: str, **fields: Any) -> None:  # pragma: no cover
    if not DEBUG_ENABLED:
        return
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    kv = " ".join(f"{k}={_short(v)}" for k, v in fields.items())
    print(f"[{ts}] [gateway] {event} {kv}", flush=True)


def set_debug(enable: bool) -> None:
    global DEBUG_ENABLED
    DEBUG_ENABLED = bool(enable)


def _proxy_status() -> Dict[str, Any]:
    return {
        "enabled": True,
        "running": _proxy_ready,
        "url": f"http://{GATEWAY_CONNECT_HOST}:{GATEWAY_PORT}{MCP_PATH}",
        "host": GATEWAY_CONNECT_HOST,
        "bind_host": GATEWAY_BIND_HOST,
        "port": GATEWAY_PORT,
        "path": MCP_PATH,
        "last_error": None if _proxy_ready else (_proxy_last_error or "gateway MCP route not ready"),
    }


async def _healthz(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "gateway": True,
            "proxy": _proxy_status(),
            "instance_count": len(_instances),
            "started_at": _gateway_started_at,
        }
    )


async def _instances_handler(_: Request) -> JSONResponse:
    with _lock:
        return JSONResponse(_instances)


async def _current_instance_handler(_: Request) -> JSONResponse:
    with _lock:
        return JSONResponse({"port": _current_instance_port})


async def _debug_get(_: Request) -> JSONResponse:
    return JSONResponse({"enabled": DEBUG_ENABLED})


async def _debug_post(request: Request) -> JSONResponse:
    payload = await request.json()
    enable = bool(payload.get("enable") if "enable" in payload else payload.get("enabled", False))
    set_debug(enable)
    return JSONResponse({"status": "ok", "enabled": DEBUG_ENABLED})


async def _proxy_status_handler(_: Request) -> JSONResponse:
    return JSONResponse(_proxy_status())


async def _ensure_proxy_handler(_: Request) -> JSONResponse:
    return JSONResponse(_proxy_status())


def _signal_gateway_shutdown() -> None:
    global _uvicorn_server
    if _uvicorn_server is not None:
        try:
            if hasattr(_uvicorn_server, "trigger_exit"):
                _uvicorn_server.trigger_exit()
            else:
                _uvicorn_server.should_exit = True
        except Exception:
            pass


async def _shutdown_handler(request: Request) -> JSONResponse:
    payload = await request.json() if request.method == "POST" else {}
    force = bool(payload.get("force", False))
    with _lock:
        instance_count = len(_instances)
    if instance_count > 0 and not force:
        return JSONResponse(
            {
                "error": "Gateway shutdown refused while IDA instances are still registered",
                "instance_count": instance_count,
            },
            status_code=409,
        )

    threading.Timer(0.05, _signal_gateway_shutdown).start()
    return JSONResponse(
        {
            "status": "ok",
            "message": "Gateway shutdown requested",
            "forced": force,
            "instance_count": instance_count,
        }
    )


async def _register_handler(request: Request) -> JSONResponse:
    payload = await request.json()
    if not {"pid", "port"}.issubset(payload):
        return JSONResponse({"error": "missing fields"}, status_code=400)
    with _lock:
        pid = payload["pid"]
        existing = [e for e in _instances if e.get("pid") != pid]
        _instances.clear()
        _instances.extend(existing)
        _instances.append(payload)
    _debug_log("REGISTER", pid=payload.get("pid"), port=payload.get("port"))
    return JSONResponse({"status": "ok"})


async def _deregister_handler(request: Request) -> JSONResponse:
    global _current_instance_port
    payload = await request.json()
    pid = payload.get("pid")
    if pid is None:
        return JSONResponse({"error": "missing pid"}, status_code=400)
    with _lock:
        remaining = [e for e in _instances if e.get("pid") != pid]
        if _current_instance_port and not any(e.get("port") == _current_instance_port for e in remaining):
            _current_instance_port = None
        _instances.clear()
        _instances.extend(remaining)
    _debug_log("DEREGISTER", pid=pid, remaining=len(_instances))
    return JSONResponse({"status": "ok"})


async def _select_instance_handler(request: Request) -> JSONResponse:
    global _current_instance_port
    payload = await request.json()
    port = payload.get("port")
    with _lock:
        if port is None:
            if not _instances:
                return JSONResponse({"error": "No instances to select from"}, status_code=404)
            sorted_instances = sorted(
                _instances,
                key=lambda x: (x.get("port") != 10000, x.get("started", float("inf"))),
            )
            _current_instance_port = sorted_instances[0].get("port")
        else:
            if not any(e.get("port") == port for e in _instances):
                return JSONResponse({"error": f"Instance with port {port} not found"}, status_code=404)
            _current_instance_port = port
    return JSONResponse({"status": "ok", "selected_port": _current_instance_port})


async def _call_handler(request: Request) -> JSONResponse:
    payload = await request.json()
    target_pid = payload.get("pid")
    target_port = payload.get("port")
    tool = payload.get("tool")
    params = payload.get("params") or {}
    if not tool:
        return JSONResponse({"error": "missing tool"}, status_code=400)

    with _lock:
        target = None
        if target_pid is not None:
            for entry in _instances:
                if entry.get("pid") == target_pid:
                    target = entry
                    break
        elif target_port is not None:
            for entry in _instances:
                if entry.get("port") == target_port:
                    target = entry
                    break
    if target is None:
        return JSONResponse({"error": "instance not found"}, status_code=404)

    port = target.get("port")
    if not isinstance(port, int):
        return JSONResponse({"error": "bad target port"}, status_code=500)

    req_timeout = payload.get("timeout")
    try:
        effective_timeout = int(req_timeout) if req_timeout and int(req_timeout) > 0 else REQUEST_TIMEOUT
    except (ValueError, TypeError):
        effective_timeout = REQUEST_TIMEOUT

    try:
        with socket.create_connection((LOCALHOST, port), timeout=1.0):
            pass
    except (ConnectionRefusedError, OSError, socket.timeout) as exc:
        return JSONResponse({"error": f"Port {port} not reachable: {type(exc).__name__}: {exc}"}, status_code=500)

    if port not in _call_locks:
        _call_locks[port] = asyncio.Lock()
    call_lock = _call_locks[port]

    try:
        await asyncio.wait_for(call_lock.acquire(), timeout=effective_timeout + 5)
    except TimeoutError:
        return JSONResponse({"error": f"Timed out waiting for call lock on port {port}"}, status_code=503)

    try:
        from mcp import ClientSession  # type: ignore
        from mcp.client.streamable_http import streamable_http_client  # type: ignore
        import httpx  # type: ignore

        mcp_url = f"http://{LOCALHOST}:{port}/mcp"
        http_timeout = httpx.Timeout(effective_timeout + 15)
        client_limits = httpx.Limits(max_connections=4, max_keepalive_connections=0)
        async with httpx.AsyncClient(timeout=http_timeout, limits=client_limits) as http_client:
            async with streamable_http_client(mcp_url, http_client=http_client) as (read, write, _get_sid):
                async with ClientSession(read, write) as session:
                    await asyncio.wait_for(session.initialize(), timeout=effective_timeout)
                    resp = await asyncio.wait_for(
                        session.call_tool(tool, arguments=params or {}),
                        timeout=effective_timeout,
                    )
                    data = None
                    if hasattr(resp, "content") and resp.content:
                        for item in resp.content:
                            text = getattr(item, "text", None)
                            if text:
                                try:
                                    data = json.loads(text)
                                    break
                                except (json.JSONDecodeError, TypeError):
                                    continue
                    if data is None and hasattr(resp, "data") and resp.data is not None:
                        def norm(x: Any) -> Any:
                            if isinstance(x, list):
                                return [norm(i) for i in x]
                            if isinstance(x, dict):
                                return {k: norm(v) for k, v in x.items()}
                            if hasattr(x, "model_dump"):
                                return x.model_dump()
                            if hasattr(x, "__dict__") and x.__dict__:
                                return norm(vars(x))
                            return x
                        data = norm(resp.data)
        return JSONResponse({"tool": tool, "data": data})
    except BaseException as exc:  # pragma: no cover  # BaseException catches ExceptionGroup on 3.11+
        if hasattr(exc, "exceptions"):
            err_detail = f"{type(exc).__name__}: [" + "; ".join(f"{type(se).__name__}: {se}" for se in exc.exceptions) + "]"
        else:
            err_detail = f"{type(exc).__name__}: {exc}"
        _debug_log("CALL_FAIL", tool=tool, target_port=port, error=err_detail, traceback=traceback.format_exc())
        return JSONResponse({"error": f"call failed: {err_detail}"}, status_code=500)
    finally:
        call_lock.release()




def _build_internal_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            Route("/instances", _instances_handler, methods=["GET"]),
            Route("/current_instance", _current_instance_handler, methods=["GET"]),
            Route("/debug", _debug_get, methods=["GET"]),
            Route("/debug", _debug_post, methods=["POST"]),
            Route("/proxy_status", _proxy_status_handler, methods=["GET"]),
            Route("/ensure_proxy", _ensure_proxy_handler, methods=["POST"]),
            Route("/shutdown", _shutdown_handler, methods=["POST"]),
            Route("/register", _register_handler, methods=["POST"]),
            Route("/deregister", _deregister_handler, methods=["POST"]),
            Route("/select_instance", _select_instance_handler, methods=["POST"]),
            Route("/call", _call_handler, methods=["POST"]),
        ]
    )


def _build_app() -> Starlette:
    from ida_mcp.utils import (
        StreamableHTTPSessionCleanupMiddleware,
        get_streamable_http_session_manager,
    )

    mcp_app = proxy_server.http_app(path=MCP_PATH)  # type: ignore[attr-defined]
    session_manager = get_streamable_http_session_manager(mcp_app)
    if session_manager is not None and hasattr(mcp_app, "add_middleware"):
        mcp_app.add_middleware(
            StreamableHTTPSessionCleanupMiddleware,
            session_manager=session_manager,
        )
    mcp_app = _SessionStickyMiddleware(mcp_app)

    @asynccontextmanager
    async def gateway_lifespan(app: Starlette):
        global _proxy_last_error, _proxy_ready

        _proxy_ready = False
        _proxy_last_error = None
        try:
            # FastMCP's Streamable HTTP session manager must run in the parent
            # Starlette lifespan so request scopes inherit the initialized state.
            if hasattr(mcp_app, "lifespan"):
                async with mcp_app.lifespan(app):
                    _proxy_ready = True
                    yield
            else:
                _proxy_ready = True
                yield
        except Exception as exc:
            _proxy_last_error = str(exc)
            raise
        finally:
            _proxy_ready = False

    return Starlette(
        routes=[
            Mount("/internal", app=_build_internal_app()),
            Mount("/", app=mcp_app),
        ],
        lifespan=gateway_lifespan,
    )


def serve_forever(host: str = GATEWAY_BIND_HOST, port: int = GATEWAY_PORT) -> None:
    import uvicorn
    from ida_mcp.utils import create_event_driven_server

    global _uvicorn_server
    app = _build_app()
    print(f"[IDA-MCP-Gateway] listening on http://{host}:{port}", flush=True)
    print(f"[IDA-MCP-Gateway] MCP available at http://{GATEWAY_CONNECT_HOST}:{port}{MCP_PATH}", flush=True)
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
        timeout_keep_alive=86400,
    )
    _uvicorn_server = create_event_driven_server(config)
    _uvicorn_server.run()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IDA MCP standalone gateway")
    parser.add_argument("--host", default=GATEWAY_BIND_HOST, help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=GATEWAY_PORT, help="Port to bind (default: 11338)")
    args = parser.parse_args()
    serve_forever(args.host, args.port)
