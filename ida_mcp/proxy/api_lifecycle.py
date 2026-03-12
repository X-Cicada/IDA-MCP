"""Lifecycle API for proxy-side launch and shutdown operations."""
from __future__ import annotations

import os
import subprocess
import sys
from typing import List, Optional

from ..config import get_ida_path
from ..platform import normalize_subprocess_cwd, wsl_to_win_path
from ._state import forward


def open_in_ida(
    file_path: str,
    extra_args: Optional[List[str]] = None,
) -> dict:
    """Launch IDA and request plugin auto-start."""
    try:
        target_ida = get_ida_path()
        if not target_ida:
            return {"error": "IDA path not configured. Please set IDA_PATH environment variable or 'ida_path' in config.conf."}
        if not os.path.exists(target_ida):
            return {"error": f"IDA executable not found at: {target_ida}"}
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        final_file_path = wsl_to_win_path(os.path.abspath(file_path))
        cmd = [target_ida]
        launch_args = list(extra_args or [])
        if not any(arg.upper() == "-A" for arg in launch_args):
            launch_args.insert(0, "-A")
        if launch_args:
            cmd.extend(launch_args)
        cmd.append(final_file_path)

        env = os.environ.copy()
        env["IDA_MCP_AUTO_START"] = "1"
        cwd = normalize_subprocess_cwd(os.path.dirname(target_ida))
        subprocess.Popen(cmd, cwd=cwd, env=env, close_fds=True if sys.platform != "win32" else False)
        return {"status": "ok", "message": f"Launched IDA: {' '.join(cmd)}"}
    except Exception as e:
        return {"error": f"Failed to launch IDA: {e}"}


def close_ida(
    save: bool = True,
    port: Optional[int] = None,
    timeout: Optional[int] = None,
) -> dict:
    """Forward the instance shutdown request to the selected IDA backend."""
    return forward("close_ida", {"save": save}, port, timeout=timeout)
