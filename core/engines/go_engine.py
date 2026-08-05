"""JSONL adapter for the optional Ignotus Go preflight engine."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.config import BASE_DIR

_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


def _is_wsl() -> bool:
    """Return True when the process is running inside Windows Subsystem for Linux."""
    try:
        return Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
    except OSError:
        return False


_WSL = _is_wsl()


class GoEngineError(RuntimeError):
    """The Go engine could not start or returned invalid output."""


@dataclass(slots=True)
class PreflightResult:
    host: str
    ips: list[str] = field(default_factory=list)
    cname: str | None = None
    ports: list[tuple[int, str]] = field(default_factory=list)
    http: dict | None = None
    error: str | None = None
    duration_ms: int = 0


class GoEngine:
    def __init__(self, binary: str | os.PathLike[str] | None = None) -> None:
        configured = os.getenv("IGNOTUS_GO_ENGINE")
        if binary or configured:
            self.binary = Path(binary or configured)
        else:
            bin_dir = Path(BASE_DIR) / "bin"
            if os.name == "nt":
                # Native Windows (PowerShell, cmd)
                self.binary = bin_dir / "ignotus-engine.exe"
            elif _WSL:
                # WSL: prefer native Linux binary, fall back to .exe via interop
                native = bin_dir / "ignotus-engine"
                win_exe = bin_dir / "ignotus-engine.exe"
                self.binary = native if native.is_file() else win_exe
            else:
                # Pure Linux / macOS
                self.binary = bin_dir / "ignotus-engine"

    @property
    def available(self) -> bool:
        return self.binary.is_file()

    def scan_many(
        self,
        hosts: list[str],
        ports: list[int],
        *,
        workers: int,
        rate_limit: float,
        timeout_seconds: float,
    ) -> dict[str, PreflightResult]:
        if not self.available:
            raise GoEngineError(f"motor Go não encontrado: {self.binary}")

        requests = []
        for index, host in enumerate(hosts):
            if not _SAFE_HOST.fullmatch(host):
                raise GoEngineError(f"host inválido para o motor Go: {host!r}")
            requests.append(
                json.dumps(
                    {
                        "id": str(index),
                        "host": host,
                        "ports": ports,
                        "timeout_ms": min(10_000, max(250, int(timeout_seconds * 1000))),
                    },
                    separators=(",", ":"),
                )
            )

        command = [
            str(self.binary),
            "--workers",
            str(workers),
            "--rate",
            str(rate_limit),
        ]
        try:
            completed = subprocess.run(
                command,
                input="\n".join(requests) + "\n",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(5.0, timeout_seconds),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GoEngineError(str(exc)) from exc

        if completed.returncode != 0:
            detail = completed.stderr.strip() or f"exit {completed.returncode}"
            raise GoEngineError(detail)

        results: dict[str, PreflightResult] = {}
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                host = str(item["host"])
                results[host] = PreflightResult(
                    host=host,
                    ips=[str(ip) for ip in item.get("ips", [])],
                    cname=item.get("cname"),
                    ports=[
                        (int(port["port"]), str(port.get("banner", "")))
                        for port in item.get("ports", [])
                        if port.get("open")
                    ],
                    http=item.get("http"),
                    error=item.get("error"),
                    duration_ms=int(item.get("duration_ms", 0)),
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise GoEngineError(f"resposta JSONL inválida: {line[:160]}") from exc
        return results
