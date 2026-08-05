"""Strict evidence primitives shared by advanced validators.

The legacy corpus showed that pattern matches were frequently promoted to
impact without proving ownership, reachability, or use.  This module keeps
those decisions explicit and redacts material that must never enter a report.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any


PLACEHOLDER_RE = re.compile(
    r"(?:example|sample|placeholder|changeme|your[_-]?|replace[_-]?me|"
    r"<[^>]+>|\btest\b|\bdummy\b|xxxxx+|undefined|null|no[_-]?token)",
    re.IGNORECASE,
)


def redact_value(value: Any, keep: int = 4) -> str:
    """Return a stable, non-secret representation suitable for evidence."""
    text = str(value or "")
    if not text:
        return "<empty>"
    digest = hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:12]
    if len(text) <= keep * 2:
        return f"<redacted sha256:{digest}>"
    return f"{text[:keep]}…{text[-keep:]} <sha256:{digest}>"


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RE.search(value or ""))


def classify_secret_evidence(
    secret_type: str,
    value: str,
    source_path: str,
    validation_note: str | None = None,
) -> dict[str, Any]:
    """Grade a secret observation without claiming exploitability.

    ``CONFIRMED`` is reserved for a validator that observed a provider-side
    permission result.  A format match alone is only ``SUPPORTED`` and must
    not be shown as a confirmed vulnerability.
    """
    note = (validation_note or "").casefold()
    source = (source_path or "").casefold()
    strong_type = any(
        marker in secret_type.casefold()
        for marker in ("private key", "database connection", "aws access", "aws secret", "stripe secret", "github token")
    )
    provider_confirmed = any(
        marker in note
        for marker in ("exploitável", "exploitable", "permission denied: false", "public read", "unauthenticated access")
    )
    if is_placeholder(value):
        status = "REJECTED"
        rationale = "placeholder_or_test_value"
    elif provider_confirmed:
        status = "CONFIRMED"
        rationale = "provider_permission_or_behavior_validated"
    elif strong_type and "node_modules" not in source and "vendor" not in source:
        status = "SUPPORTED"
        rationale = "high_confidence_format_in_first_party_source;_validation_required"
    else:
        status = "UNVERIFIED"
        rationale = "pattern_match_without_provider_validation"
    return {
        "status": status,
        "rationale": rationale,
        "validation_required": status not in {"CONFIRMED", "REJECTED"},
        "value_fingerprint": redact_value(value),
    }


def source_class(source_path: str) -> str:
    """Classify reconstructed source as first-party or dependency noise."""
    normalized = (source_path or "").replace("\\", "/").casefold()
    third_party_markers = (
        "/node_modules/", "/.pnpm/", "/vendor/", "webpack:///node_modules/",
        "webpack:///_n_e/node_modules/", "/bower_components/",
    )
    return "third_party" if any(marker in normalized for marker in third_party_markers) else "first_party"


# Public edge ranges used only to avoid calling a CDN edge an origin.  The
# check is deliberately conservative: an unknown address is still probed,
# while a known edge can never be reported as an origin without corroboration.
KNOWN_EDGE_NETWORKS = {
    "cloudflare": ("173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32"),
    "vercel": ("76.76.21.0/24", "64.29.17.0/24", "66.33.60.0/24", "2606:4700:10::/48"),
    "fastly": ("23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "146.75.0.0/16", "151.101.0.0/16", "199.232.0.0/16", "2a04:4e42::/32"),
}


def is_known_edge_ip(address: str, providers: list[str] | None = None) -> bool:
    try:
        candidate = ipaddress.ip_address(address)
    except ValueError:
        return False
    selected = {name.casefold() for name in (providers or KNOWN_EDGE_NETWORKS)}
    return any(
        candidate in ipaddress.ip_network(network)
        for name, networks in KNOWN_EDGE_NETWORKS.items()
        if name in selected
        for network in networks
    )
