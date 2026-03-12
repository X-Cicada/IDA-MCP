"""Cross-platform path helpers shared by runtime and tooling."""
from __future__ import annotations

import os
import subprocess


def is_wsl() -> bool:
    if not os.path.exists("/proc/version"):
        return False
    try:
        with open("/proc/version", "r", encoding="utf-8") as handle:
            return "microsoft" in handle.read().lower()
    except Exception:
        return False


def win_to_wsl_path(path: str) -> str:
    if not path or not is_wsl():
        return path
    try:
        result = subprocess.check_output(["wslpath", "-u", path], stderr=subprocess.DEVNULL)
        return result.decode().strip()
    except Exception:
        return path


def wsl_to_win_path(path: str) -> str:
    if not path or not is_wsl():
        return path
    try:
        result = subprocess.check_output(["wslpath", "-w", path], stderr=subprocess.DEVNULL)
        return result.decode().strip()
    except Exception:
        return path


def normalize_subprocess_cwd(path: str | None) -> str | None:
    if path is None:
        return None
    if is_wsl() and ":" in path and "\\" in path:
        return win_to_wsl_path(path)
    return path
