"""
core/red_mode/platform.py

Cross-platform OS detection for Red Mode.
Import IS_WINDOWS / IS_WSL / IS_LINUX instead of sprinkling os.name checks.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _detect_wsl() -> bool:
    """Return True when running inside Windows Subsystem for Linux."""
    try:
        return Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
    except OSError:
        return False


IS_WINDOWS: bool = os.name == "nt"
IS_WSL: bool = not IS_WINDOWS and _detect_wsl()
IS_LINUX: bool = sys.platform == "linux" and not IS_WSL and not IS_WINDOWS
