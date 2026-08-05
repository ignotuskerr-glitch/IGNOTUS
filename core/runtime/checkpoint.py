"""Atomic checkpoints for resumable scans."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import (
    ASNInfo,
    DNSInfo,
    EmailSecurityInfo,
    HostResult,
    HTTPInfo,
    Impact,
    ServiceExposure,
    TLSInfo,
)

SCHEMA_VERSION = 3


def _known_values(model: type, data: dict[str, Any] | None) -> dict[str, Any]:
    allowed = {field.name for field in fields(model)}
    return {key: value for key, value in (data or {}).items() if key in allowed}


def host_result_from_dict(data: dict[str, Any]) -> HostResult:
    """Rehydrate a sanitized HostResult produced by ``to_dict``."""
    http_data = _known_values(HTTPInfo, data.get("http"))
    http_data.pop("body", None)
    result = HostResult(
        host=str(data["host"]),
        dns=DNSInfo(**_known_values(DNSInfo, data.get("dns"))),
        http=HTTPInfo(**http_data),
        ports=[(int(port), str(banner)) for port, banner in data.get("ports", [])],
        leaks=[(str(ip), str(message)) for ip, message in data.get("leaks", [])],
        tls=TLSInfo(**_known_values(TLSInfo, data.get("tls")))
        if data.get("tls")
        else None,
        asn=ASNInfo(**_known_values(ASNInfo, data.get("asn")))
        if data.get("asn")
        else None,
        reverse_dns=data.get("reverse_dns"),
        classification=str(data.get("classification", "UNKNOWN")),
        confidence=int(data.get("confidence", 0)),
        time_elapsed=str(data.get("time_elapsed", "0.00s")),
        impacts=[Impact(**_known_values(Impact, item)) for item in data.get("impacts", [])],
        services=[
            ServiceExposure(**_known_values(ServiceExposure, item))
            for item in data.get("services", [])
        ],
        email_security=EmailSecurityInfo(
            **_known_values(EmailSecurityInfo, data.get("email_security"))
        )
        if data.get("email_security")
        else None,
    )
    return result


class CheckpointStore:
    """Persist each completed host without storing response bodies or auth data."""

    def __init__(self, path: str | os.PathLike[str], target: str) -> None:
        self.path = Path(path).resolve()
        self.target = target.lower().strip()
        self._lock = threading.Lock()
        self._results: dict[str, HostResult] = {}
        self._complete = False

    def load(self) -> dict[str, HostResult]:
        if not self.path.is_file():
            return {}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if payload.get("schema") != SCHEMA_VERSION:
            raise ValueError("checkpoint incompatível")
        if str(payload.get("target", "")).lower() != self.target:
            raise ValueError("checkpoint pertence a outro alvo")
        loaded = {
            host: host_result_from_dict(item)
            for host, item in payload.get("results", {}).items()
        }
        with self._lock:
            self._results = loaded
            self._complete = bool(payload.get("complete", False))
        return dict(loaded)

    def record(self, result: HostResult) -> None:
        with self._lock:
            self._results[result.host] = result
            self._write_locked()

    def finalize(self) -> None:
        with self._lock:
            self._complete = True
            self._write_locked()

    def _write_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": SCHEMA_VERSION,
            "target": self.target,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "complete": self._complete,
            "results": {host: result.to_dict() for host, result in self._results.items()},
        }
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(temporary, self.path)
