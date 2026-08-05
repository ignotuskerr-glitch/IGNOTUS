from __future__ import annotations

import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class PowerShellProbeError(RuntimeError):
    pass


def _run_script(script: Path, *arguments: str, timeout: int = 120) -> str:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            *arguments,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        detail = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or "probe returned no data"
        )
        raise PowerShellProbeError(detail)
    return completed.stdout.strip()


def collect_windows_snapshot() -> dict:
    output = _run_script(
        PROJECT_ROOT / "scripts" / "red_mode_snapshot.ps1", timeout=180
    )
    return json.loads(output)


def collect_native_probe() -> list[dict]:
    output = _run_script(
        PROJECT_ROOT / "scripts" / "red_mode_native_probe.ps1",
        "-SourcePath",
        str(PROJECT_ROOT / "tools" / "redprobe" / "RedProbe.cs"),
        timeout=90,
    )
    payload = json.loads(output)
    return payload if isinstance(payload, list) else [payload]
