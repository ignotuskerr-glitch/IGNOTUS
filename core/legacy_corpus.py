"""Offline audit of legacy Ignotus logs and reconstructed source trees.

This command is intentionally local-only.  It emits counts, hashes and rule
quality metrics; it never copies URLs with credentials, cookies, tokens or
source snippets into the report.

Usage:
    python -m core.legacy_corpus --logs PATH --sourcemaps PATH --output DIR
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from core.impact_gate import source_class
from core.sourcemap_analyzer import analyze_file


LOG_PATTERNS = {
    "critical_labels": re.compile(r"\bCRITICAL\b", re.IGNORECASE),
    "high_labels": re.compile(r"\bHIGH\b", re.IGNORECASE),
    "medium_labels": re.compile(r"\bMEDIUM\b", re.IGNORECASE),
    "low_labels": re.compile(r"\bLOW\b", re.IGNORECASE),
    "takeover_labels": re.compile(r"takeover", re.IGNORECASE),
    "source_map_mentions": re.compile(r"source\s*\.?\s*map|\.map", re.IGNORECASE),
    "email_policy_mentions": re.compile(r"SPF|DMARC", re.IGNORECASE),
    "waf_mentions": re.compile(r"WAF|bypass|origem", re.IGNORECASE),
    "cookie_mentions": re.compile(r"cookie|HttpOnly|SameSite", re.IGNORECASE),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_logs(log_root: Path) -> dict:
    counts = Counter()
    files = 0
    lines = 0
    for path in sorted(log_root.glob("*.log")) if log_root.is_dir() else []:
        files += 1
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    lines += 1
                    for name, pattern in LOG_PATTERNS.items():
                        if pattern.search(line):
                            counts[name] += 1
        except OSError:
            counts["unreadable_files"] += 1
    return {
        "files": files,
        "lines": lines,
        "pattern_counts": dict(sorted(counts.items())),
    }


def audit_sources(root: Path, max_files: int = 50000) -> dict:
    counts = Counter()
    files_seen = 0
    files_analyzed = 0
    findings = Counter()
    source_hashes: list[str] = []
    if not root.exists():
        return {"exists": False, "files_seen": 0, "files_analyzed": 0, "classes": {}, "finding_counts": {}}

    for directory, dirnames, filenames in os.walk(root):
        # Dependency trees are noise for impact claims and can be enormous.
        dirnames[:] = [name for name in dirnames if name not in {"node_modules", ".pnpm", "vendor"}]
        for name in filenames:
            if files_seen >= max_files:
                break
            path = Path(directory) / name
            if path.suffix.casefold() not in {".js", ".ts", ".tsx", ".jsx", ".vue", ".svelte"}:
                continue
            files_seen += 1
            counts[source_class(str(path))] += 1
            try:
                result = analyze_file(path)
            except OSError:
                counts["unreadable"] += 1
                continue
            files_analyzed += 1
            for key, values in result.items():
                findings[key] += len(values)
            if result.get("potential_secrets"):
                source_hashes.append(_sha256(path)[:16])
        if files_seen >= max_files:
            break
    return {
        "exists": True,
        "files_seen": files_seen,
        "files_analyzed": files_analyzed,
        "classes": dict(sorted(counts.items())),
        "finding_counts": dict(sorted(findings.items())),
        "secret_file_fingerprints": source_hashes[:100],
        "truncated": files_seen >= max_files,
    }


def build_report(log_root: Path, source_root: Path, max_files: int = 5000) -> dict:
    return {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_policy": "strict-impact-v2",
        "scope": {"logs": str(log_root), "sourcemaps": str(source_root)},
        "logs": audit_logs(log_root),
        "sourcemaps": audit_sources(source_root, max_files=max_files),
        "legacy_quality_findings": [
            {
                "id": "LEGACY-CDN-EDGE-PROMOTION",
                "status": "corrected",
                "impact": "Old WAF/origin labels require provider-edge exclusion and differential proof.",
            },
            {
                "id": "LEGACY-SECRET-RAW-OUTPUT",
                "status": "corrected",
                "impact": "Source-map and JavaScript evidence is now redacted and fingerprinted.",
            },
            {
                "id": "LEGACY-DEPENDENCY-NOISE",
                "status": "corrected",
                "impact": "node_modules/vendor trees are excluded from first-party impact claims.",
            },
            {
                "id": "LEGACY-UNVALIDATED-SEVERITY",
                "status": "corrected",
                "impact": "Pattern matches are SUPPORTED/UNVERIFIED until provider permission or behavior is observed.",
            },
        ],
    }


def markdown(report: dict) -> str:
    log = report["logs"]
    src = report["sourcemaps"]
    lines = [
        "# Ignotus — auditoria offline do corpus legado",
        "",
        f"- Política: `{report['evidence_policy']}`",
        f"- Logs: {log['files']} arquivos / {log['lines']} linhas",
        f"- Fontes: {src.get('files_analyzed', 0)} analisadas / {src.get('files_seen', 0)} encontradas",
        "",
        "## Métricas de qualidade",
        "",
        "| Regra | Estado | Resultado |",
        "|---|---|---|",
    ]
    for item in report["legacy_quality_findings"]:
        lines.append(f"| {item['id']} | {item['status']} | {item['impact']} |")
    lines += ["", "## Contagens de log (sem conteúdo sensível)", ""]
    for key, value in log["pattern_counts"].items():
        lines.append(f"- `{key}`: {value}")
    lines += ["", "## Contagens de fontes (primeira parte)", ""]
    for key, value in src.get("finding_counts", {}).items():
        lines.append(f"- `{key}`: {value}")
    lines += ["", "Nenhum token, cookie, segredo ou trecho de código foi incluído.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Auditoria offline estrita do corpus legado Ignotus")
    parser.add_argument("--logs", required=True, type=Path)
    parser.add_argument("--sourcemaps", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-files", type=int, default=5000, help="limite de fontes de primeira parte analisadas (default: 5000)")
    args = parser.parse_args()
    report = build_report(args.logs, args.sourcemaps, max_files=max(1, args.max_files))
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "legacy_corpus_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (args.output / "legacy_corpus_report.md").write_text(markdown(report), encoding="utf-8")
    print(json.dumps({"json": str((args.output / 'legacy_corpus_report.json').resolve()), "markdown": str((args.output / 'legacy_corpus_report.md').resolve()), "evidence_policy": report["evidence_policy"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
