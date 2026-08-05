"""
ingotus/core/sourcemap_auditor.py

Analisa o conteúdo de source maps (.map) em busca de segredos hardcoded:
  - Chaves de API (Amplitude, Firebase, Stripe, SendGrid, etc.)
  - Tokens de autenticação (Bearer, JWT iniciais)
  - Credenciais de banco de dados / URLs de conexão
  - DSNs de monitoramento (Sentry, Datadog, Rollbar)
  - Variáveis de ambiente com padrão KEY=VALUE
  - Endpoints internos / URLs privadas

Uso:
    from core.sourcemap_auditor import audit_sourcemap_content
    findings = audit_sourcemap_content(map_url, sources_content_list)
"""

import re
import json
import hashlib
import requests
from typing import List, Dict, Optional, Any
from core.config import PROBE_TIMEOUT, USER_AGENT
from core.impact_gate import classify_secret_evidence, redact_value, source_class


# ── Secret patterns ────────────────────────────────────────────────────────────
# Each tuple: (name, regex, severity, description)

SECRET_PATTERNS: List[tuple] = [
    # --- Analytics Keys ---
    (
        "Amplitude API Key",
        re.compile(r"(?:amplitudeApiKey|amplitude[_\-]?api[_\-]?key)\s*[=:]\s*['\"]([a-f0-9]{32})['\"]", re.IGNORECASE),
        "HIGH",
        "Chave de API do Amplitude hardcoded — permite injetar eventos falsos em dashboards de produto",
    ),
    (
        "Google Analytics / Tag Manager",
        re.compile(r"['\"]?(G-[A-Z0-9]{8,}|UA-\d{6,}-\d|GTM-[A-Z0-9]{5,})['\"]?"),
        "LOW",
        "ID de rastreamento Google Analytics/GTM exposto",
    ),
    # --- Sentry / Error tracking ---
    (
        "Sentry DSN",
        re.compile(r"https://[a-f0-9]{32}@[^/]+/\d+", re.IGNORECASE),
        "MEDIUM",
        "DSN do Sentry exposto — permite enviar eventos falsos ao sistema de error tracking",
    ),
    (
        "Datadog RUM Token",
        re.compile(r"(?:datadogRumToken|DD_RUM|clientToken)\s*[=:]\s*['\"]([a-zA-Z0-9]{32,})['\"]", re.IGNORECASE),
        "MEDIUM",
        "Token do Datadog RUM exposto",
    ),
    # --- Cloud Provider Keys ---
    (
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        "CRITICAL",
        "AWS Access Key ID hardcoded — permite acesso à conta AWS do alvo",
    ),
    (
        "AWS Secret Key",
        re.compile(r"aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", re.IGNORECASE),
        "CRITICAL",
        "AWS Secret Access Key hardcoded",
    ),
    (
        "Google Cloud API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "HIGH",
        "Chave de API do Google Cloud hardcoded",
    ),
    (
        "Firebase Config",
        re.compile(r"apiKey\s*:\s*['\"]AIza[0-9A-Za-z\-_]{35}['\"]", re.IGNORECASE),
        "HIGH",
        "Configuração Firebase com apiKey hardcoded — possível acesso a banco Firestore público",
    ),
    # --- Payment Processors ---
    (
        "Stripe Secret Key",
        re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),
        "CRITICAL",
        "Chave secreta do Stripe hardcoded — permite cobranças e acesso a dados de pagamento",
    ),
    (
        "Stripe Publishable Key",
        re.compile(r"pk_(?:live|test)_[0-9a-zA-Z]{24,}"),
        "LOW",
        "Chave pública do Stripe exposta (risco limitado, mas indica ambiente de produção)",
    ),
    # --- Auth & Tokens ---
    (
        "Generic Bearer Token",
        re.compile(r"[Bb]earer\s+([A-Za-z0-9\-_]{20,}\.?[A-Za-z0-9\-_]*\.?[A-Za-z0-9\-_]*)"),
        "HIGH",
        "Token Bearer hardcoded no código-fonte",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        "HIGH",
        "JWT token hardcoded no código-fonte — pode conter claims de usuário e ser reutilizado",
    ),
    (
        "GitHub Token",
        re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
        "CRITICAL",
        "GitHub Personal Access Token hardcoded",
    ),
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,48}"),
        "HIGH",
        "Token do Slack hardcoded — possível acesso a workspaces corporativos",
    ),
    (
        "Twilio API Key",
        re.compile(r"SK[0-9a-fA-F]{32}"),
        "HIGH",
        "Chave de API do Twilio hardcoded",
    ),
    (
        "SendGrid API Key",
        re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
        "HIGH",
        "Chave de API do SendGrid hardcoded — permite envio de e-mails como o alvo",
    ),
    # --- Database URLs ---
    (
        "Database Connection URL",
        re.compile(
            r"(?:postgres|mysql|mongodb|redis|sqlite|mssql)(?:\+\w+)?://[^@\s\"']+:[^@\s\"']+@[^\s\"']+",
            re.IGNORECASE,
        ),
        "CRITICAL",
        "URL de conexão de banco de dados com credenciais hardcoded",
    ),
    # --- Generic Secrets (low noise, high yield) ---
    (
        "Private Key (RSA/EC/PGP)",
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "CRITICAL",
        "Chave privada criptográfica hardcoded no código-fonte",
    ),
    (
        "Generic API Key variable",
        re.compile(
            r"""(?:api_key|apiKey|api_secret|secret_key|secretKey|auth_token|authToken|access_token)\s*[=:]\s*['"]((?!undefined|null|your|<|{)[A-Za-z0-9\-_]{16,})['"']""",
            re.IGNORECASE,
        ),
        "HIGH",
        "Variável com padrão de chave/segredo hardcoded detectada",
    ),
    (
        "Internal Staging URL",
        re.compile(r"https?://[a-zA-Z0-9\-]+\.(?:internal|staging|dev|nonprod|preprod|test)\.[a-zA-Z0-9.\-]+"),
        "MEDIUM",
        "URL de ambiente interno/staging hardcoded — revela infraestrutura não-pública",
    ),
    (
        "IP Address (Private range)",
        re.compile(r"https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"),
        "MEDIUM",
        "URL com IP privado hardcoded — aponta para infraestrutura interna",
    ),
]

# Minimum character overlap to avoid duplicate findings per file
_SEEN_THRESHOLD = 10


def _scan_content(source_path: str, content: str) -> List[Dict[str, Any]]:
    """Scan a single source file's content for secret patterns."""
    findings = []
    seen_values: set = set()

    for name, pattern, severity, description in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            raw_value = match.group(0)
            value = raw_value[:120]  # cap only before redaction/fingerprinting

            # Skip obvious placeholders
            if any(p in value.lower() for p in ["your_", "example", "placeholder", "xxxxxxxxx", "undefined", "null"]):
                continue

            # Deduplicate by value fingerprint within the same file
            fingerprint = value[:_SEEN_THRESHOLD].lower()
            if fingerprint in seen_values:
                continue
            seen_values.add(fingerprint)

            # Compute line number
            line_num = content[:match.start()].count("\n") + 1
            context_start = max(0, match.start() - 80)
            context_end   = min(len(content), match.end() + 80)
            context_snippet = content[context_start:context_end].replace("\n", " ").strip()

            findings.append({
                "secret_type":   name,
                "severity":      severity,
                "description":   description,
                "file":          source_path,
                "line":          line_num,
                "source_class":  source_class(source_path),
                "value_preview": redact_value(value),
                "value_sha256":  hashlib.sha256(raw_value.encode("utf-8", "ignore")).hexdigest(),
                "context":       _redact_context(context_snippet, raw_value),
                "evidence":      classify_secret_evidence(name, raw_value, source_path),
            })

    return findings


def _redact_context(context: str, known_value: str = "") -> str:
    """Remove assignment values and bearer-like material from source context."""
    if known_value:
        context = context.replace(known_value, redact_value(known_value))
    context = re.sub(
        r"((?:secret|token|password|passwd|api[_-]?key|authorization|bearer)\s*[=:]\s*)([^,;\s}]+)",
        lambda m: f"{m.group(1)}{redact_value(m.group(2))}",
        context,
        flags=re.IGNORECASE,
    )
    context = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]{12,}", "Bearer <redacted>", context, flags=re.IGNORECASE)
    return context


def audit_sourcemap_content(
    map_url: str,
    sources: Optional[List[str]] = None,
    sources_content: Optional[List[Optional[str]]] = None,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main entry point. Given a source map URL:
      1. If sources/sources_content are passed, use them directly
      2. Otherwise, download the map and extract them

    Returns:
        {
            "map_url": str,
            "total_files_scanned": int,
            "secrets_found": int,
            "findings": [{ secret_type, severity, file, line, value_preview, context }],
            "highest_severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"NONE",
        }
    """
    result: Dict[str, Any] = {
        "map_url":             map_url,
        "total_files_scanned": 0,
        "secrets_found":       0,
        "findings":            [],
        "highest_severity":    "NONE",
        "evidence_policy":     "strict-impact-v2",
        "first_party_files":   0,
        "third_party_files":   0,
        "confirmed_findings":  0,
        "supported_findings":  0,
        "unverified_findings": 0,
        "error":               None,
    }

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 99}

    # ── Download map if content not already supplied ──────────────────────────
    if sources is None or sources_content is None:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        try:
            r = requests.get(
                map_url,
                headers={"User-Agent": USER_AGENT},
                timeout=PROBE_TIMEOUT * 3,
                verify=False,
                proxies=proxies,
            )
            if r.status_code != 200:
                result["error"] = f"HTTP {r.status_code} ao acessar {map_url}"
                return result

            data = r.json()
            sources         = data.get("sources", [])
            sources_content = data.get("sourcesContent", [])
        except requests.exceptions.Timeout:
            result["error"] = "Timeout ao baixar source map"
            return result
        except Exception as exc:
            result["error"] = f"Erro ao baixar/parsear source map: {exc}"
            return result

    if not sources:
        result["error"] = "Source map não contém 'sources'"
        return result

    # ── Scan each source file's content ──────────────────────────────────────
    all_findings: List[Dict] = []

    for idx, src_path in enumerate(sources):
        content = sources_content[idx] if sources_content and idx < len(sources_content) else None
        if not content:
            continue

        result["total_files_scanned"] += 1
        if source_class(src_path) == "third_party":
            result["third_party_files"] += 1
            continue
        result["first_party_files"] += 1
        file_findings = _scan_content(src_path, content)
        all_findings.extend(file_findings)

    # ── Rank and summarise ────────────────────────────────────────────────────
    result["findings"]       = all_findings
    result["secrets_found"]  = len(all_findings)
    for item in all_findings:
        status = (item.get("evidence") or {}).get("status", "UNVERIFIED")
        if status == "CONFIRMED":
            result["confirmed_findings"] += 1
        elif status == "SUPPORTED":
            result["supported_findings"] += 1
        else:
            result["unverified_findings"] += 1

    if all_findings:
        best = min(all_findings, key=lambda f: sev_order.get(f["severity"], 99))
        result["highest_severity"] = best["severity"]

    return result


def format_findings_as_evidence(audit_result: Dict[str, Any]) -> str:
    """
    Format audit_result into a human-readable evidence block
    suitable for Impact.evidence field in the classifier.
    """
    if not audit_result.get("findings"):
        return "Nenhum segredo detectado no source map."

    lines = [
        f"Source Map URL: {audit_result['map_url']}",
        f"Arquivos analisados: {audit_result['total_files_scanned']}",
        f"Primeira parte: {audit_result.get('first_party_files', 0)}; dependências excluídas: {audit_result.get('third_party_files', 0)}",
        f"Observações: {audit_result['secrets_found']} (confirmadas: {audit_result.get('confirmed_findings', 0)}; suportadas: {audit_result.get('supported_findings', 0)}; não verificadas: {audit_result.get('unverified_findings', 0)})",
        f"Severidade máxima: {audit_result['highest_severity']}",
        "",
        "═══ SEGREDOS DETECTADOS ═══",
    ]

    for f in audit_result["findings"]:
        lines.append(f"")
        lines.append(f"[{f['severity']}] {f['secret_type']}")
        lines.append(f"  Arquivo : {f['file']} (linha {f['line']})")
        lines.append(f"  Valor   : {f['value_preview']}")
        lines.append(f"  Contexto: ...{f['context']}...")
        evidence = f.get("evidence") or {}
        lines.append(f"  Evidência: {evidence.get('status', 'UNVERIFIED')} — {evidence.get('rationale', 'validation_required')}")
        lines.append(f"  Impacto : {f['description']}")

    lines.append("")
    lines.append("PoC de Validação:")
    lines.append(f"  curl -s '{audit_result['map_url']}' | python3 -c \"")
    lines.append("  import sys,json; d=json.load(sys.stdin)")
    lines.append("  [print(d['sourcesContent'][i][:2000])")
    lines.append("   for i,s in enumerate(d.get('sources',[])) if 'analytic' in s.lower() or 'config' in s.lower()]")
    lines.append("  \"")

    return "\n".join(lines)
