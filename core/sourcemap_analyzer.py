"""
ingotus/core/sourcemap_analyzer.py

Analisador automático de source maps extraídos.

Funcionalidades:
  1. Extrai todos os endpoints de API mencionados no código-fonte
  2. Lista todas as variáveis de ambiente referenciadas (process.env.*)
  3. Detecta padrões sensíveis: keys, tokens, URLs de infra, staging
  4. Gera wordlist de paths para fuzzing
  5. Gera relatório JSON/Markdown consolidado

Uso:
    python -m core.sourcemap_analyzer <dir_extraido> [--output report.json]
"""

import os
import re
import json
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Optional
from datetime import datetime
from core.impact_gate import classify_secret_evidence, redact_value, source_class

# ─── Padrões de Busca ────────────────────────────────────────────────────────

PATTERNS = {
    "env_vars": re.compile(
        r'process\.env\.([A-Z0-9_]+)|import\.meta\.env\.([A-Z0-9_]+)',
        re.IGNORECASE,
    ),
    "api_endpoints": re.compile(
        r"""[`"'](?:https?://[^"'`\s]+)?(/(?:api|v\d|graphql|rest|rpc|internal|auth|session|user|admin)[^"'`\s]*)[`"']""",
        re.IGNORECASE,
    ),
    "hardcoded_urls": re.compile(
        r"""https?://[a-zA-Z0-9._\-]+\.[a-zA-Z]{2,}(?:/[^\s"'`]*)?""",
        re.IGNORECASE,
    ),
    "aws_resources": re.compile(
        r"""https?://[a-z0-9\-]+\.(?:execute-api\.[a-z0-9\-]+\.amazonaws\.com|s3\.amazonaws\.com|cognito-idp\.[a-z0-9\-]+\.amazonaws\.com)(?:/[^\s"'`]*)?""",
        re.IGNORECASE,
    ),
    "firebase_config": re.compile(
        r"""(?:apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId|measurementId)\s*:\s*["']([^"']+)["']""",
        re.IGNORECASE,
    ),
    "potential_secrets": re.compile(
        r"""(?:secret|password|passwd|api_key|apikey|token|bearer|private_key|client_secret|access_key|auth_token)\s*[=:]\s*["']([^"'\s]{12,})["']""",
        re.IGNORECASE,
    ),
    "graphql_queries": re.compile(
        r"""gql\s*`([^`]+)`|query\s+(\w+)\s*\{""",
        re.DOTALL,
    ),
    "internal_hosts": re.compile(
        r"""https?://(?:internal|staging|dev|test|qa|preprod|sandbox|stg|uat)\.[a-zA-Z0-9._\-]+""",
        re.IGNORECASE,
    ),
    "jwt_decode": re.compile(
        r"""(?:jwt|jwtDecode|jwtVerify|parseJwt|decodeToken)\s*\(""",
        re.IGNORECASE,
    ),
    "error_messages": re.compile(
        r"""(?:error|err|message)\s*[=:]\s*["']([^"']{10,})["']""",
        re.IGNORECASE,
    ),
}

SENSITIVE_NOISE_WORDS = {
    "example", "placeholder", "your_", "my_key", "xxx", "test_key",
    "changeme", "replace_me", "insert_", "enter_", ".data-api",
    "no-api-key", "no-token", "_token", "GOOGLE_DEV_MODE",
    "user_token", "encodedtoken", "subscribe-no", "update-no",
    "use-sw-after", "use-vapid", "data-api",
}

EXTENSION_WHITELIST = {".js", ".ts", ".tsx", ".jsx", ".vue", ".svelte"}

# ─── Funções de Análise ───────────────────────────────────────────────────────

def is_noise(value: str) -> bool:
    v = value.lower()
    return any(noise in v for noise in SENSITIVE_NOISE_WORDS)


def collect_files(base_dir: Path, skip_node_modules: bool = True) -> list[Path]:
    files = []
    for f in base_dir.rglob("*"):
        if f.is_file() and f.suffix in EXTENSION_WHITELIST:
            if skip_node_modules and "node_modules" in f.parts:
                continue
            files.append(f)
    return files


def analyze_file(filepath: Path) -> dict:
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}

    result = defaultdict(list)

    # Env vars
    for m in PATTERNS["env_vars"].finditer(content):
        var = m.group(1) or m.group(2)
        if var:
            result["env_vars"].append(var)

    # API endpoints (path-based)
    for m in PATTERNS["api_endpoints"].finditer(content):
        path = m.group(1)
        if path and len(path) > 2:
            result["api_endpoints"].append(path)

    # Hardcoded URLs
    for m in PATTERNS["hardcoded_urls"].finditer(content):
        url = m.group(0)
        # Skip common CDNs / public resources
        skip_domains = {"fonts.googleapis", "cdn.jsdelivr", "unpkg.com", "cdnjs.cloudflare",
                        "stackoverflow.com", "github.com", "npmjs.com", "emberjs.com",
                        "developer.mozilla", "w3.org", "schema.org"}
        if not any(d in url for d in skip_domains):
            result["hardcoded_urls"].append(url)

    # AWS resources
    for m in PATTERNS["aws_resources"].finditer(content):
        result["aws_resources"].append(m.group(0))

    # Firebase config blocks
    for m in PATTERNS["firebase_config"].finditer(content):
        result["firebase_config"].append(m.group(0)[:80])

    # Potential secrets
    for m in PATTERNS["potential_secrets"].finditer(content):
        val = m.group(1)
        if not is_noise(val):
            line = content[:m.start()].count(chr(10)) + 1
            result["potential_secrets"].append(
                {
                    "line": line,
                    "fingerprint": redact_value(val),
                    "evidence": classify_secret_evidence("Generic source-map secret", val, str(filepath)),
                }
            )

    # Internal hosts
    for m in PATTERNS["internal_hosts"].finditer(content):
        result["internal_hosts"].append(m.group(0))

    # JWT usage
    if PATTERNS["jwt_decode"].search(content):
        result["jwt_usage"].append("JWT decode/verify detected")

    # Error messages exposing logic
    errors = []
    for m in PATTERNS["error_messages"].finditer(content):
        msg = m.group(1)
        if any(k in msg.lower() for k in ["invalid", "unauthorized", "forbidden", "error", "failed"]):
            errors.append(msg[:100])
    if errors:
        result["exposed_errors"] = list(set(errors))[:10]

    # Deduplicate scalar and structured evidence without using a dict as a key.
    normalized = {}
    for key, values in result.items():
        unique = []
        seen = set()
        for value in values:
            marker = json.dumps(value, sort_keys=True, ensure_ascii=False) if isinstance(value, dict) else str(value)
            if marker not in seen:
                seen.add(marker)
                unique.append(value)
        normalized[key] = unique
    return normalized


def analyze_directory(base_dir: Path, verbose: bool = False) -> dict:
    files = collect_files(base_dir)
    
    report = {
        "meta": {
            "base_dir": str(base_dir),
            "files_analyzed": len(files),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
        "summary": defaultdict(set),
        "by_file": {},
        "all_env_vars": set(),
        "all_endpoints": set(),
        "all_aws_resources": set(),
        "all_internal_hosts": set(),
        "all_potential_secrets": [],
        "all_firebase_configs": [],
        "all_hardcoded_urls": set(),
    }

    for filepath in files:
        rel = str(filepath.relative_to(base_dir))
        findings = analyze_file(filepath)

        if not findings:
            continue

        report["by_file"][rel] = findings

        for env in findings.get("env_vars", []):
            report["all_env_vars"].add(env)
        for ep in findings.get("api_endpoints", []):
            report["all_endpoints"].add(ep)
        for aws in findings.get("aws_resources", []):
            report["all_aws_resources"].add(aws)
        for host in findings.get("internal_hosts", []):
            report["all_internal_hosts"].add(host)
        for secret in findings.get("potential_secrets", []):
            report["all_potential_secrets"].append({"file": rel, "match": secret})
        for fb in findings.get("firebase_config", []):
            report["all_firebase_configs"].append({"file": rel, "config": fb})
        for url in findings.get("hardcoded_urls", []):
            report["all_hardcoded_urls"].add(url)

        if verbose:
            if findings.get("potential_secrets") or findings.get("aws_resources"):
                print(f"  [!] {rel}: {len(findings.get('potential_secrets', []))} secrets, {len(findings.get('aws_resources', []))} AWS")

    # Convert sets to sorted lists for JSON serialization
    report["all_env_vars"] = sorted(report["all_env_vars"])
    report["all_endpoints"] = sorted(report["all_endpoints"])
    report["all_aws_resources"] = sorted(report["all_aws_resources"])
    report["all_internal_hosts"] = sorted(report["all_internal_hosts"])
    report["all_hardcoded_urls"] = sorted(report["all_hardcoded_urls"])
    del report["summary"]

    return report


def generate_markdown(report: dict) -> str:
    lines = [
        f"# Source Map Analysis Report",
        f"**Directory:** `{report['meta']['base_dir']}`",
        f"**Files Analyzed:** {report['meta']['files_analyzed']}",
        f"**Generated:** {report['meta']['timestamp']}",
        "",
    ]

    if report["all_env_vars"]:
        lines += ["## 🔧 Environment Variables Referenced", "```"]
        lines += sorted(report["all_env_vars"])
        lines += ["```", ""]

    if report["all_endpoints"]:
        lines += ["## 🌐 API Endpoints Discovered", "```"]
        lines += sorted(set(report["all_endpoints"]))[:100]
        lines += ["```", ""]

    if report["all_aws_resources"]:
        lines += ["## ☁️ AWS Resources Exposed", ""]
        for url in report["all_aws_resources"]:
            lines.append(f"- `{url}`")
        lines.append("")

    if report["all_internal_hosts"]:
        lines += ["## 🔴 Internal/Staging Hosts Found", ""]
        for host in report["all_internal_hosts"]:
            lines.append(f"- `{host}`")
        lines.append("")

    if report["all_firebase_configs"]:
        lines += ["## 🔥 Firebase Config Blocks", ""]
        for item in report["all_firebase_configs"][:20]:
            lines.append(f"- `{item['file']}`: `{item['config']}`")
        lines.append("")

    if report["all_potential_secrets"]:
        lines += ["## 🚨 Potential Secrets (REVIEW MANUALLY)", ""]
        for item in report["all_potential_secrets"][:30]:
            lines.append(f"- **{item['file']}**")
            lines.append(f"  ```{item['match']}```")
        lines.append("")

    if report["all_hardcoded_urls"]:
        lines += ["## 🔗 Hardcoded URLs (sample)", "```"]
        lines += sorted(report["all_hardcoded_urls"])[:50]
        lines += ["```", ""]

    return "\n".join(lines)


def generate_wordlist(report: dict) -> str:
    """Gera wordlist de paths para uso com ffuf/gobuster/feroxbuster."""
    paths = set()
    for ep in report["all_endpoints"]:
        # Normalize path
        clean = ep.split("?")[0].split("#")[0]
        # Add path itself
        paths.add(clean)
        # Add path segments progressively
        parts = [p for p in clean.split("/") if p]
        for i in range(1, len(parts)+1):
            paths.add("/" + "/".join(parts[:i]))
    return "\n".join(sorted(paths))


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ingotus — Source Map Analyzer")
    parser.add_argument("directory", help="Diretório com source maps extraídos")
    parser.add_argument("--output", "-o", default=None, help="Arquivo de saída JSON")
    parser.add_argument("--markdown", "-m", default=None, help="Arquivo de saída Markdown")
    parser.add_argument("--wordlist", "-w", default=None, help="Gerar wordlist de endpoints")
    parser.add_argument("--verbose", "-v", action="store_true", help="Saída verbosa")
    args = parser.parse_args()

    base_dir = Path(args.directory)
    if not base_dir.exists():
        print(f"[ERRO] Diretório não encontrado: {base_dir}")
        return

    print(f"[*] Analisando: {base_dir}")
    report = analyze_directory(base_dir, verbose=args.verbose)

    # Estatísticas
    print(f"\n{'='*60}")
    print(f"  Arquivos analisados  : {report['meta']['files_analyzed']}")
    print(f"  Env vars encontradas : {len(report['all_env_vars'])}")
    print(f"  Endpoints de API     : {len(report['all_endpoints'])}")
    print(f"  Recursos AWS         : {len(report['all_aws_resources'])}")
    print(f"  Hosts internos       : {len(report['all_internal_hosts'])}")
    print(f"  Firebase configs     : {len(report['all_firebase_configs'])}")
    print(f"  Secrets potenciais   : {len(report['all_potential_secrets'])}")
    print(f"  URLs hardcoded       : {len(report['all_hardcoded_urls'])}")
    print(f"{'='*60}\n")

    # Mostra highlights
    if report["all_aws_resources"]:
        print("[!] AWS Resources:")
        for url in report["all_aws_resources"]:
            print(f"    {url}")

    if report["all_internal_hosts"]:
        print("[!] Internal Hosts:")
        for host in report["all_internal_hosts"]:
            print(f"    {host}")

    if report["all_potential_secrets"]:
        print(f"[!!] {len(report['all_potential_secrets'])} potential secrets found — review manually!")

    # Salva JSON
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] JSON salvo em: {args.output}")

    # Salva Markdown
    if args.markdown:
        md = generate_markdown(report)
        Path(args.markdown).write_text(md, encoding="utf-8")
        print(f"[+] Markdown salvo em: {args.markdown}")

    # Gera Wordlist
    if args.wordlist:
        wl = generate_wordlist(report)
        Path(args.wordlist).write_text(wl, encoding="utf-8")
        print(f"[+] Wordlist salva em: {args.wordlist}")


if __name__ == "__main__":
    main()
