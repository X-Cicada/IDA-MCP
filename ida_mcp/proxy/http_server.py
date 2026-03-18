"""IDA MCP HTTP proxy transport entrypoint."""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
from typing import Any, Optional

from ._server import server


class _SessionStickyMiddleware:
    """Reuse the same MCP session across concurrent HTTP requests.

    If a cached or client-provided session becomes stale, retry once without
    the session header so FastMCP can issue a fresh session.
    """

    _SESSION_HEADER = b"mcp-session-id"
    _SESSION_NOT_FOUND_MARKER = b"session not found"

    def __init__(self, app):
        self.app = app
        self._session_id: Optional[str] = None
        self._session_lock = threading.Lock()

    def __getattr__(self, name: str):
        return getattr(self.app, name)

    def _get_cached_session_id(self) -> Optional[str]:
        with self._session_lock:
            return self._session_id

    def _clear_cached_session(self) -> None:
        with self._session_lock:
            self._session_id = None

    def _store_response_session(self, session_id: Optional[str], status_code: int) -> None:
        with self._session_lock:
            if status_code >= 400:
                self._session_id = None
            elif session_id is not None:
                self._session_id = session_id

    @classmethod
    def _has_session_header(cls, headers) -> bool:
        return any(key.lower() == cls._SESSION_HEADER for key, _ in headers)

    @classmethod
    def _strip_session_headers(cls, headers):
        return [(key, value) for key, value in headers if key.lower() != cls._SESSION_HEADER]

    @classmethod
    def _extract_response_session_id(cls, message) -> Optional[str]:
        for key, value in message.get("headers", []):
            if key.lower() == cls._SESSION_HEADER:
                return value.decode("ascii")
        return None

    @classmethod
    def _is_session_not_found(cls, status_code: int, body_chunks: list[bytes]) -> bool:
        if status_code != 404:
            return False
        return cls._SESSION_NOT_FOUND_MARKER in b"".join(body_chunks).lower()

    @staticmethod
    async def _buffer_request(receive):
        messages = []
        while True:
            message = await receive()
            messages.append(message)
            if message.get("type") == "http.disconnect":
                break
            if message.get("type") == "http.request" and not message.get("more_body", False):
                break
        return messages

    @staticmethod
    def _make_replay_receive(messages, fallback_receive):
        replay_messages = [dict(message) for message in messages]
        index = 0

        async def _receive():
            nonlocal index
            if index < len(replay_messages):
                message = replay_messages[index]
                index += 1
                return message
            return await fallback_receive()

        return _receive

    def _scope_with_cached_session(self, scope):
        raw_headers = list(scope.get("headers", []))
        cached_session = self._get_cached_session_id()
        if not self._has_session_header(raw_headers) and cached_session is not None:
            raw_headers.append((self._SESSION_HEADER, cached_session.encode("ascii")))
            return {**scope, "headers": raw_headers}
        return scope

    async def _dispatch(self, scope, request_messages, receive, send, allow_retry: bool) -> None:
        status_code = 0
        response_session_id: Optional[str] = None
        delay_response = False
        pending_messages = []
        body_chunks: list[bytes] = []

        async def _capture_send(message):
            nonlocal status_code, response_session_id, delay_response

            if message.get("type") == "http.response.start":
                status_code = int(message.get("status") or 0)
                response_session_id = self._extract_response_session_id(message)
                delay_response = status_code == 404
                if delay_response:
                    pending_messages.append(message)
                    return

                self._store_response_session(response_session_id, status_code)
                await send(message)
                return

            if delay_response:
                pending_messages.append(message)
                if message.get("type") == "http.response.body":
                    body_chunks.append(message.get("body", b""))
                return

            await send(message)

        await self.app(scope, self._make_replay_receive(request_messages, receive), _capture_send)

        if not delay_response:
            return

        if allow_retry and self._is_session_not_found(status_code, body_chunks):
            self._clear_cached_session()
            retry_scope = {**scope, "headers": self._strip_session_headers(scope.get("headers", []))}
            await self._dispatch(retry_scope, request_messages, receive, send, allow_retry=False)
            return

        self._store_response_session(response_session_id, status_code)
        for message in pending_messages:
            await send(message)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_messages = await self._buffer_request(receive)
        await self._dispatch(self._scope_with_cached_session(scope), request_messages, receive, send, allow_retry=True)


_http_thread: Optional[threading.Thread] = None
_http_server: Any = None
_http_port: Optional[int] = None
_http_host: Optional[str] = None
_http_path: Optional[str] = None
_http_last_error: Optional[str] = None
_stop_lock = threading.Lock()


def _is_http_proxy_listening(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def start_http_proxy(host: str = "127.0.0.1", port: int = 11338, path: str = "/mcp", startup_timeout: float = 5.0) -> bool:
    """Start the HTTP MCP proxy server."""
    global _http_thread, _http_server, _http_port, _http_host, _http_path, _http_last_error

    with _stop_lock:
        if _http_thread is not None and _http_thread.is_alive():
            if _is_http_proxy_listening(host, port):
                _http_last_error = None
                return True

        def worker():
            global _http_server, _http_last_error
            try:
                if os.name == "nt":
                    try:
                        import asyncio

                        if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
                            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                    except Exception:
                        pass

                app = server.http_app(path=path)
                ready = threading.Event()

                import asyncio
                import uvicorn
                from ida_mcp.utils import (
                    StreamableHTTPSessionCleanupMiddleware,
                    create_event_driven_server,
                    get_streamable_http_session_manager,
                )

                session_manager = get_streamable_http_session_manager(app)
                if session_manager is not None and hasattr(app, "add_middleware"):
                    app.add_middleware(
                        StreamableHTTPSessionCleanupMiddleware,
                        session_manager=session_manager,
                    )
                app = _SessionStickyMiddleware(app)

                config = uvicorn.Config(
                    app,
                    host=host,
                    port=port,
                    log_level="warning",
                    access_log=False,
                    timeout_keep_alive=86400,
                )
                _http_server = create_event_driven_server(config)
                _http_last_error = None

                def _exception_handler(loop, context):
                    exc = context.get("exception")
                    if exc is not None:
                        winerr = getattr(exc, "winerror", None)
                        if winerr == 10054 and isinstance(exc, (ConnectionResetError, OSError)):
                            return
                    msg = str(context.get("message") or "")
                    if "10054" in msg and "ConnectionResetError" in msg:
                        return
                    loop.default_exception_handler(context)

                def _wait_started():
                    try:
                        for _ in range(100):
                            if getattr(_http_server, "started", False):
                                ready.set()
                                return
                            if getattr(_http_server, "should_exit", False):
                                return
                            time.sleep(0.05)
                    except Exception:
                        return

                loop = asyncio.new_event_loop()
                try:
                    asyncio.set_event_loop(loop)
                    loop.set_exception_handler(_exception_handler)
                    threading.Thread(target=_wait_started, name="IDA-MCP-HTTP-Ready", daemon=True).start()
                    if hasattr(_http_server, "serve"):
                        loop.run_until_complete(_http_server.serve())
                    else:
                        _http_server.run()
                finally:
                    try:
                        loop.run_until_complete(loop.shutdown_asyncgens())
                    except Exception:
                        pass
                    try:
                        loop.run_until_complete(loop.shutdown_default_executor())
                    except Exception:
                        pass
                    try:
                        loop.close()
                    except Exception:
                        pass
            except Exception as exc:
                _http_last_error = f"{type(exc).__name__}: {exc}"
                print(f"[IDA-MCP-HTTP][ERROR] Server failed: {exc}")
            finally:
                _http_server = None

        _http_thread = threading.Thread(target=worker, name="IDA-MCP-HTTP-Proxy", daemon=True)
        _http_thread.start()
        _http_host = host
        _http_port = port
        _http_path = path

        deadline = time.monotonic() + max(startup_timeout, 0.5)
        while time.monotonic() < deadline:
            if _is_http_proxy_listening(host, port):
                _http_last_error = None
                return True
            if _http_thread is None or not _http_thread.is_alive():
                break
            time.sleep(0.1)
        if _http_last_error is None:
            _http_last_error = "proxy did not become reachable in time"
        return False


def stop_http_proxy() -> None:
    """Stop the HTTP MCP proxy server."""
    global _http_thread, _http_server, _http_port, _http_host, _http_path

    with _stop_lock:
        if _http_server is not None:
            try:
                if hasattr(_http_server, "trigger_exit"):
                    _http_server.trigger_exit()
                else:
                    _http_server.should_exit = True
            except Exception:
                pass

        if _http_thread is not None:
            _http_thread.join(timeout=5)

        _http_thread = None
        _http_server = None
        _http_port = None
        _http_host = None
        _http_path = None


def is_http_proxy_running() -> bool:
    if _http_thread is None or not _http_thread.is_alive() or _http_port is None:
        return False
    host = _http_host or "127.0.0.1"
    return _is_http_proxy_listening(host, _http_port)


def get_http_url() -> Optional[str]:
    if _http_port is None:
        return None

    host = _http_host or "127.0.0.1"
    path = _http_path or "/mcp"

    return f"http://{host}:{_http_port}{path}"


def get_http_proxy_status() -> dict:
    return {
        "running": is_http_proxy_running(),
        "url": get_http_url(),
        "host": _http_host,
        "port": _http_port,
        "path": _http_path,
        "last_error": _http_last_error,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IDA MCP HTTP Proxy Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=11338, help="Port to bind (default: 11338)")
    parser.add_argument("--path", default="/mcp", help="MCP endpoint path (default: /mcp)")
    args = parser.parse_args()

    print(f"[IDA-MCP-HTTP] Starting HTTP proxy at http://{args.host}:{args.port}{args.path}")
    print("[IDA-MCP-HTTP] Reusing shared server from proxy/_server.py")

    if start_http_proxy(args.host, args.port, args.path):
        print("[IDA-MCP-HTTP] Server started successfully")
        try:
            while is_http_proxy_running():
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[IDA-MCP-HTTP] Shutting down...")
            stop_http_proxy()
    else:
        print("[IDA-MCP-HTTP] Failed to start server")
        sys.exit(1)
