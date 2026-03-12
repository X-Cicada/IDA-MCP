"""Runtime helpers that coordinate optional transports around the registry."""
from __future__ import annotations


def start_http_proxy_if_coordinator() -> str | None:
    """Start the client-facing HTTP proxy when the current instance owns the coordinator."""
    try:
        from . import registry
        from .config import get_http_host, get_http_path, get_http_port, is_http_enabled
        from .proxy.http_server import get_http_url, start_http_proxy

        if not registry.is_coordinator() or not is_http_enabled():
            return None

        host = get_http_host()
        port = get_http_port()
        path = get_http_path()

        if start_http_proxy(host, port, path):
            return get_http_url()
    except Exception:
        return None

    return None
