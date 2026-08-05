"""
ingotus/core/evidence.py

Saves raw recon artefacts (PoC files) organised by host.

Directory structure created per host:
  evidence/
  └── {target_domain}/
        └── {hostname}/
              ├── request.txt    — HTTP request headers sent
              ├── response.txt   — HTTP response headers + body snippet
              ├── tls.json       — TLS certificate details
              ├── dns.txt        — DNS resolution record
              ├── impacts.txt    — Impact / finding summary
              └── bypass_poc.txt — WAF bypass PoC (only when CRITICAL bypass confirmed)
"""

import os
import re
import json
import textwrap
from datetime import datetime, timezone

from core.config import (
    EVIDENCE_DIR,
    USER_AGENT,
    RESPONSE_SNIPPET_SIZE,
    REPORT_SEPARATOR_WIDTH,
    EVIDENCE_WRAP_WIDTH,
)
from core.models import HostResult
from core.redaction import redact_headers, redact_text


def _host_dir(host: str, target_label: str = "") -> str:
    """
    Return (and create) a dedicated evidence directory for this host,
    grouped under the target domain folder.
    Structure: evidence/{target_domain}/{hostname}/
    """
    safe_target = target_label.replace(":", "_").replace("*", "").strip(".") if target_label else "general"
    safe_host   = host.replace(":", "_")
    host_path   = os.path.join(EVIDENCE_DIR, safe_target, safe_host)
    os.makedirs(host_path, exist_ok=True)
    return host_path


def _write(path: str, content: str) -> None:
    """Atomic-ish file write; silently ignores I/O errors."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    except Exception:
        pass


def _write_poc(path: str, content: str) -> None:
    """Write a PoC file with UTF-8 BOM so Windows tools display it correctly."""
    try:
        with open(path, "w", encoding="utf-8-sig") as fh:
            fh.write(content)
    except Exception:
        pass


# ── Evidence writers ───────────────────────────────────────────────────────────

def _save_http_request(host_path: str, host: str) -> None:
    """Saves the HTTP request that was sent, using the canonical USER_AGENT."""
    content = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"   # always matches the real UA used in http.py
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    _write(os.path.join(host_path, "request.txt"), content)


def _save_http_response(host_path: str, result: HostResult) -> None:
    lines = [f"HTTP/1.1 {result.http.status}"]
    for header, val in redact_headers(result.http.headers).items():
        lines.append(f"{header.title()}: {val}")
    lines.append("")
    if result.http.response_snippet:
        lines.append(redact_text(result.http.response_snippet[:RESPONSE_SNIPPET_SIZE]))
    _write(os.path.join(host_path, "response.txt"), "\r\n".join(lines))


def _save_tls(host_path: str, result: HostResult) -> None:
    try:
        data = result.tls.to_dict()
    except Exception:
        data = {
            "valid":      result.tls.valid,
            "issuer":     result.tls.issuer,
            "expiration": result.tls.expiration,
        }
    _write(
        os.path.join(host_path, "tls.json"),
        json.dumps(data, indent=2, ensure_ascii=False),
    )


def _save_dns(host_path: str, result: HostResult) -> None:
    lines = [
        f"Timestamp : {datetime.now(timezone.utc).isoformat()}",
        f"Host      : {result.host}",
        f"CNAME     : {result.dns.cname or '(none)'}",
        f"IPs       : {', '.join(result.dns.ips) if result.dns.ips else '(none)'}",
    ]
    if result.asn:
        lines += [
            f"ASN       : {result.asn.number or 'N/A'}",
            f"Org       : {result.asn.organization or 'N/A'}",
        ]
    if result.reverse_dns:
        lines.append(f"rDNS      : {result.reverse_dns}")
    _write(os.path.join(host_path, "dns.txt"), "\n".join(lines) + "\n")


def _save_impacts(host_path: str, result: HostResult) -> None:
    sep = "=" * REPORT_SEPARATOR_WIDTH
    ts  = datetime.now(timezone.utc).isoformat()
    lines = [
        sep,
        f"  IMPACT REPORT  —  {result.host}",
        f"  Generated     : {ts}",
        f"  Classification: {result.classification}",
        f"  Confidence    : {result.confidence}%",
        sep,
        "",
    ]
    for idx, imp in enumerate(result.impacts, start=1):
        lines += [
            f"[{idx:02d}] Severity    : {imp.severity}",
            f"     Description : {imp.description}",
        ]
        if hasattr(imp, "evidence") and imp.evidence:
            wrapped = textwrap.fill(
                redact_text(imp.evidence),
                width=EVIDENCE_WRAP_WIDTH,
                initial_indent="     Evidence   : ",
                subsequent_indent="                  ",
            )
            lines.append(wrapped)
        lines.append("")

    _write(os.path.join(host_path, "impacts.txt"), "\n".join(lines))


def _save_services(host_path: str, result: HostResult) -> None:
    """Persist bounded protocol evidence without credentials or response bodies."""
    _write(
        os.path.join(host_path, "services.json"),
        json.dumps(
            [service.to_dict() for service in result.services],
            indent=2,
            ensure_ascii=False,
        ),
    )


def _save_bypass_poc(host_path: str, result: HostResult) -> None:
    """Writes bypass_poc.txt when a WAF bypass was confirmed for this host."""
    bypass_impacts = [
        imp for imp in result.impacts
        if imp.severity == "CRITICAL" and "Bypass de WAF/CDN confirmado" in imp.description
    ]
    if not bypass_impacts:
        return

    lines = [
        "=" * 72,
        "  PROOF OF CONCEPT  —  WAF/CDN Bypass via Origin IP",
        f"  Host      : {result.host}",
        f"  Generated : {datetime.now(timezone.utc).isoformat()}",
        "=" * 72,
        "",
    ]

    for imp in bypass_impacts:
        # Extract IP from description e.g. "Bypass de WAF/CDN confirmado via IP de origem (1.2.3.4)"
        match = re.search(r"\(([\d.]+)\)", imp.description)
        ip = match.group(1) if match else "(unknown IP)"

        lines += [
            f"  Target IP : {ip}",
            f"  Hostname  : {result.host}",
            "",
            "  PoC Command:",
            f"    curl -sk https://{ip} -H 'Host: {result.host}' -o /dev/null -w '%{{http_code}}\\n'",
            "",
            "  Evidence:",
        ]
        for eline in imp.evidence.splitlines():
            lines.append(f"    {eline}")
        lines.append("")

    _write_poc(os.path.join(host_path, "bypass_poc.txt"), "\n".join(lines))


# ── Public API ─────────────────────────────────────────────────────────────────

def save_evidence(result: HostResult, target_label: str = "") -> None:
    """Save all available evidence for a host into its target domain folder."""
    has_data = (
        (result.http and result.http.status)
        or result.tls
        or result.dns.ips
        or result.impacts
        or result.services
    )
    if not has_data:
        return

    host_path = _host_dir(result.host, target_label=target_label)

    if result.http and result.http.status:
        _save_http_request(host_path, result.host)
        _save_http_response(host_path, result)

    if result.tls:
        _save_tls(host_path, result)

    if result.services:
        _save_services(host_path, result)

    if result.dns.ips or result.impacts:
        _save_dns(host_path, result)

    if result.impacts:
        _save_impacts(host_path, result)
        _save_bypass_poc(host_path, result)
