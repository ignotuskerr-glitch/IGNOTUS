"""Finding normalization and deterministic risk ordering."""

from __future__ import annotations

from core.config import SEVERITY_ORDER
from core.models import Impact


def deduplicate_impacts(impacts: list[Impact]) -> list[Impact]:
    unique: dict[tuple[str, str, str], Impact] = {}
    for impact in impacts:
        severity = impact.severity.upper()
        key = (
            severity,
            " ".join(impact.description.casefold().split()),
            " ".join(impact.evidence.casefold().split())[:240],
        )
        existing = unique.get(key)
        if existing is None or impact.cvss_score > existing.cvss_score:
            impact.severity = severity
            unique[key] = impact
    return sorted(
        unique.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity.upper(), 99),
            -item.cvss_score,
            item.description.casefold(),
        ),
    )
