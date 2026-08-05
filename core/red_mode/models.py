from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RedCheck:
    id: str
    category: str
    status: str
    title: str
    detail: str
    recommendation: str = ""
    attack_id: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RedRun:
    profile: str
    generated_at: str
    checks: list[RedCheck]
    snapshot: dict[str, Any]
    native_probe: list[dict[str, Any]]
    canaries: dict[str, Any]
    impact: dict[str, Any] = field(default_factory=dict)
    drift: list[dict[str, Any]] = field(default_factory=list)
    baseline_path: str | None = None
    json_path: str = ""
    markdown_path: str = ""

    @property
    def summary(self) -> dict[str, Any]:
        counts = {
            status: sum(check.status == status for check in self.checks)
            for status in ("PASS", "WARN", "FAIL", "INFO")
        }
        scored = [check for check in self.checks if check.status != "INFO"]
        points = sum(
            1 if check.status == "PASS" else 0.5 if check.status == "WARN" else 0
            for check in scored
        )
        score = round(100 * points / len(scored)) if scored else 0
        return {**counts, "total": len(self.checks), "score": score}
