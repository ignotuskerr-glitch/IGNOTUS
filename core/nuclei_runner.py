"""
ingotus/core/nuclei_runner.py

Nuclei YAML Template Engine — roda templates de detecção de vulnerabilidades.

Estratégia dual:
  1. Se o binário 'nuclei' estiver no PATH → invoca via subprocess com templates bundled
  2. Se não estiver → usa engine própria em Python (subconjunto Nuclei-compatible)

Subconjunto suportado:
  - requests[].method   (GET, POST)
  - requests[].paths[]  com {{BaseURL}} e {{Hostname}}
  - requests[].headers{}
  - requests[].body
  - requests[].matchers[].type: status, word, regex
  - requests[].matchers-condition: and | or
"""

import os
import re
import json
import shutil
import subprocess
import requests as req_lib
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from core.config import PROBE_TIMEOUT, USER_AGENT

# ── Template directory ─────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(BASE_DIR, "data", "templates")


def _nuclei_binary_available() -> Optional[str]:
    """Locate Nuclei in PATH or in the project-managed tools directory."""
    candidates = [
        shutil.which("nuclei"),
        os.path.join(BASE_DIR, "tools", "bin", "nuclei.exe"),
        os.path.join(BASE_DIR, "tools", "bin", "nuclei"),
    ]
    return next((path for path in candidates if path and os.path.isfile(path)), None)


# ── YAML Engine ────────────────────────────────────────────────────────────────

def _load_template(path: str) -> Optional[Dict]:
    """Load and parse a Nuclei YAML template."""
    if not YAML_AVAILABLE:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _resolve_variables(s: str, base_url: str) -> str:
    """Replace {{BaseURL}} and {{Hostname}} in template strings."""
    parsed   = urlparse(base_url)
    hostname = parsed.hostname or ""
    s = s.replace("{{BaseURL}}", base_url.rstrip("/"))
    s = s.replace("{{Hostname}}", hostname)
    return s


def _execute_request(req_block: Dict, base_url: str, proxy: Optional[str] = None) -> List[Dict]:
    """Execute all paths in a request block and return response objects."""
    method  = req_block.get("method", "GET").upper()
    paths   = req_block.get("paths", [base_url])
    headers = {"User-Agent": USER_AGENT}
    headers.update({
        k: _resolve_variables(str(v), base_url)
        for k, v in req_block.get("headers", {}).items()
    })
    body    = req_block.get("body", None)
    if body:
        body = _resolve_variables(str(body), base_url)

    proxies = {"http": proxy, "https": proxy} if proxy else None
    results = []

    for path_tpl in paths:
        url = _resolve_variables(path_tpl, base_url)
        try:
            r = req_lib.request(
                method, url,
                headers=headers,
                data=body,
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=True,
                proxies=proxies,
            )
            results.append({
                "url":     url,
                "status":  r.status_code,
                "body":    r.text[:4000],
                "headers": dict(r.headers),
            })
        except Exception:
            results.append({"url": url, "status": 0, "body": "", "headers": {}})

    return results


def _apply_matchers(resp: Dict, matchers: List[Dict], condition: str = "and") -> bool:
    """Evaluate matchers against a single response. Returns True if matched."""
    results = []
    for m in matchers:
        t      = m.get("type", "")
        ci     = m.get("case-insensitive", False)
        m_cond = m.get("condition", "or")
        hit    = False

        if t == "status":
            hit = resp["status"] in m.get("status", [])

        elif t == "word":
            body  = resp["body"]
            words = m.get("words", [])
            if ci:
                body  = body.lower()
                words = [w.lower() for w in words]
            hits = [w in body for w in words]
            hit  = all(hits) if m_cond == "and" else any(hits)

        elif t == "regex":
            body     = resp["body"]
            flags    = re.IGNORECASE if ci else 0
            patterns = m.get("regex", [])
            hits     = [bool(re.search(p, body, flags)) for p in patterns]
            hit      = all(hits) if m_cond == "and" else any(hits)

        results.append(hit)

    if not results:
        return False
    return all(results) if condition == "and" else any(results)


def _run_template(template: Dict, base_url: str, proxy: Optional[str] = None) -> Optional[Dict]:
    """Run a single template against a URL. Returns finding dict or None."""
    info = template.get("info", {})

    for req_block in template.get("requests", []):
        condition = req_block.get("matchers-condition", "and")
        matchers  = req_block.get("matchers", [])
        responses = _execute_request(req_block, base_url, proxy=proxy)

        for resp in responses:
            if resp["status"] == 0:
                continue
            if _apply_matchers(resp, matchers, condition):
                severity = info.get("severity", "medium").upper()
                tags     = info.get("tags", [])
                return {
                    "template_id": template.get("id", "unknown"),
                    "name":        info.get("name", "Unknown"),
                    "severity":    severity,
                    "description": str(info.get("description", "")).strip(),
                    "tags":        tags,
                    "matched_url": resp["url"],
                    "status_code": resp["status"],
                    "evidence": (
                        f"Template  : {template.get('id', '?')} — {info.get('name', '')}\n"
                        f"URL       : {resp['url']}\n"
                        f"Status    : HTTP {resp['status']}\n"
                        f"Tags      : {', '.join(tags)}\n"
                        f"Descrição : {str(info.get('description', '')).strip()}\n\n"
                        f"PoC cURL:\n"
                        f"  curl -sk '{resp['url']}'\n\n"
                        f"Referência: https://nuclei.projectdiscovery.io/"
                    ),
                }
    return None


# ── Subprocess Nuclei ──────────────────────────────────────────────────────────

def _parse_partial_nuclei_jsonl(output: str | bytes, target_url: str) -> List[Dict]:
    """Preserve complete records already emitted when Nuclei reaches its deadline."""
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    findings = []
    for line in output.splitlines():
        try:
            result = json.loads(line.strip())
        except (json.JSONDecodeError, TypeError):
            continue
        info = result.get("info", {})
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        matched = result.get("matched-at", target_url)
        findings.append({
            "template_id": result.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", "medium").upper(),
            "description": str(info.get("description", "")).strip(),
            "tags": tags,
            "matched_url": matched,
            "status_code": 0,
            "evidence": f"Template: {result.get('template-id', '')}\nURL: {matched}\nTags: {', '.join(tags)}",
        })
    return findings


def _run_nuclei_subprocess(binary: str, target_url: str, proxy: Optional[str] = None) -> List[Dict]:
    """Invoke official Nuclei templates with conservative, non-DoS settings."""
    findings = []
    cmd = [
        binary, "-u", target_url,
        "-jsonl", "-silent", "-no-color",
        "-tags", "nginx,ssl,misconfig,exposure,tech",
        "-exclude-tags", "dos,fuzz,intrusive,bruteforce",
        "-severity", "info,low,medium,high,critical",
        "-rate-limit", "5", "-concurrency", "2", "-bulk-size", "1",
        "-timeout", "8", "-retries", "1",
    ]
    if proxy:
        cmd += ["-proxy", proxy]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result    = json.loads(line)
                info      = result.get("info", {})
                severity  = info.get("severity", "medium").upper()
                matched   = result.get("matched-at", target_url)
                findings.append({
                    "template_id": result.get("template-id", ""),
                    "name":        info.get("name", ""),
                    "severity":    severity,
                    "description": str(info.get("description", "")).strip(),
                    "tags":        info.get("tags", []),
                    "matched_url": matched,
                    "status_code": 0,
                    "evidence": (
                        f"Template: {result.get('template-id', '')} — {info.get('name', '')}\n"
                        f"URL: {matched}\n"
                        f"Tags: {', '.join(info.get('tags', []))}\n\n"
                        f"PoC cURL:\n  curl -sk '{matched}'"
                    ),
                })
            except json.JSONDecodeError:
                continue
    except subprocess.TimeoutExpired as exc:
        findings.extend(_parse_partial_nuclei_jsonl(exc.stdout or "", target_url))
    except (FileNotFoundError, OSError):
        pass

    return findings


# ── Main Entry Point ───────────────────────────────────────────────────────────

def run_nuclei_templates(
    target_url:    str,
    templates_dir: Optional[str] = None,
    proxy:         Optional[str] = None,
    max_workers:   int = 8,
) -> List[Dict[str, Any]]:
    """
    Run all bundled YAML templates against target_url.
    Uses nuclei binary if available, else built-in engine.
    Returns list of finding dicts (severity, description, evidence).
    """
    if templates_dir is None:
        templates_dir = TEMPLATES_DIR

    # ── Try nuclei binary ──────────────────────────────────────────────────────
    nuclei_bin = _nuclei_binary_available()
    if nuclei_bin:
        return _run_nuclei_subprocess(nuclei_bin, target_url, proxy=proxy)

    # ── Fall back to built-in YAML engine ──────────────────────────────────────
    if not YAML_AVAILABLE:
        return []

    templates = []
    if os.path.isdir(templates_dir):
        for fname in sorted(os.listdir(templates_dir)):
            if fname.endswith((".yaml", ".yml")):
                t = _load_template(os.path.join(templates_dir, fname))
                if t:
                    templates.append(t)

    if not templates:
        return []

    findings = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_run_template, t, target_url, proxy): t for t in templates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    return findings
