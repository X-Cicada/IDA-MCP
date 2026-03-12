from __future__ import annotations

import importlib.util
from pathlib import Path

from fastmcp import FastMCP


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
