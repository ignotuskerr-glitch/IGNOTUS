"""
ingotus/core/js_scraper.py

Scrapes external JavaScript files referenced in HTML responses.
Extracts:
  1. High-value secrets & API keys (AWS, Stripe, Firebase, Google, JWTs).
  2. Hidden API endpoints & administrative routes.
"""

import re
import requests
import urllib3
from typing import List, Tuple, Dict, Set, Optional
from core.config import PROBE_TIMEOUT, USER_AGENT
from core.impact_gate import classify_secret_evidence, redact_value

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# High-entropy secret patterns
SECRET_PATTERNS: Dict[str, Tuple[str, str]] = {
    "AWS Access Key": (r"\b(AKIA[0-9A-Z]{16})\b", "CRITICAL"),
    "Google API Key": (r"\b(AIzaSy[A-Za-z0-9_-]{35})\b", "HIGH"),
    "Stripe API Key": (r"\b(sk_live_[0-9a-zA-Z]{24,34})\b", "CRITICAL"),
    "Firebase Config URL": (r"https://[a-z0-9-]+\.firebaseio\.com", "HIGH"),
    "RSA Private Key": (r"-----BEGIN (RSA|EC|PRIVATE) KEY-----", "CRITICAL"),
    "Generic Bearer/JWT Token": (r"\bBearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b", "HIGH"),
    "Slack Webhook": (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "HIGH"),
}

# API Route extraction pattern
ROUTE_PATTERN = re.compile(
    r"""["'](/(?:api|v1|v2|v3|admin|auth|user|internal|graphql|service|config)/[a-zA-Z0-9_/-]+)["']""",
    re.IGNORECASE
)

SCRIPT_SRC_PATTERN = re.compile(r"""<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']""", re.IGNORECASE)


def extract_js_urls(base_url: str, html_body: str) -> List[str]:
    """Extracts absolute JS URLs from HTML script tags."""
    if not html_body:
        return []

    js_urls = []
    matches = SCRIPT_SRC_PATTERN.findall(html_body)

    for src in matches[:10]:  # Limit to top 10 scripts per page to avoid performance degradation
        if src.startswith("//"):
            js_urls.append(f"https:{src}")
        elif src.startswith("http://") or src.startswith("https://"):
            js_urls.append(src)
        elif src.startswith("/"):
            # Construct absolute URL
            domain_base = "/".join(base_url.split("/")[:3])
            js_urls.append(f"{domain_base}{src}")
        else:
            domain_base = "/".join(base_url.split("/")[:3])
            js_urls.append(f"{domain_base}/{src}")

    return list(set(js_urls))


def validate_secret(secret_type: str, value: str) -> Tuple[bool, str, str]:
    """
    Actively tests if an extracted secret/key is accessible or unauthenticated.
    Returns:
        (is_exploitable, status_summary, poc_curl_command)
    """
    if secret_type == "Firebase Config URL":
        target_url = f"{value.rstrip('/')}/.json"
        try:
            r = requests.get(target_url, timeout=2.5, verify=False)
            if r.status_code == 200 and not any(kw in r.text.lower() for kw in ("permission_denied", "error", "<html")):
                return True, "EXPLOITABLE (Firebase DB com Leitura Pública Ativa!)", f"curl -sk '{target_url}'"
            return False, "INFO (Firebase DB protegido com regras de segurança)", f"curl -sk '{target_url}'"
        except Exception:
            return False, "INFO (Não foi possível conectar ao Firebase DB)", f"curl -sk '{target_url}'"

    elif secret_type == "Google API Key":
        target_url = f"https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key={value}"
        try:
            r = requests.get(target_url, timeout=2.5, verify=False)
            if r.status_code == 200 and r.json().get("status") == "OK":
                return True, "EXPLOITABLE (Google Geocoding API pública sem restrições!)", f"curl -sk '{target_url}'"
            return False, "INFO (Chave com restrição de API/Domínio)", f"curl -sk '{target_url}'"
        except Exception:
            return False, "INFO (Falha na verificação da chave Google)", f"curl -sk '{target_url}'"

    elif secret_type == "Slack Webhook":
        return True, "EXPLOITABLE (Slack Webhook exposto — permite envio de mensagens não autorizadas)", f"curl -X POST -H 'Content-type: application/json' --data '{{\"text\":\"Security Audit Test\"}}' '{value}'"

    return False, "UNVERIFIED (Sem validador automatizado para este tipo)", ""


def check_sourcemap(js_url: str, proxy: Optional[str] = None) -> Optional[Dict[str, str]]:
    """
    Checks if a JavaScript Source Map (.map) is publicly accessible,
    allowing reconstruction of the original uncompiled frontend source code.
    """
    map_url = f"{js_url}.map"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        r = requests.get(
            map_url,
            headers={"User-Agent": USER_AGENT},
            timeout=2.5,
            verify=False,
            allow_redirects=True,
            proxies=proxies,
        )
        if r.status_code == 200 and r.text and '"sources"' in r.text and '"version"' in r.text:
            return {
                "type": "Exposição de JavaScript Source Map (.map)",
                "value": map_url,
                "severity": "INFO",
                "source": js_url,
                "status_note": "EXPLOITABLE (Source Map público permite reconstruir o código-fonte original completo!)",
                "poc_curl": f"curl -sk '{map_url}'",
                "evidence_status": "OBSERVED",
            }
    except Exception:
        pass
    return None


def analyze_js_file(js_url: str, proxy: Optional[str] = None) -> Tuple[List[Dict[str, str]], List[str]]:
    """
    Downloads a JS file, checks for .map sourcemaps, extracts secrets, actively validates them, and extracts hidden API endpoints.
    Returns:
        (found_secrets, found_routes)
    """
    found_secrets: List[Dict[str, str]] = []
    found_routes: Set[str] = set()
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Check for Source Map exposure (.js.map)
    map_secret = check_sourcemap(js_url, proxy=proxy)
    if map_secret:
        # A fetched map proves source exposure only; it does not prove that a
        # secret or privileged route is exploitable.
        map_secret["status_note"] = "OBSERVED (source map público acessível; impacto requer validação de primeira parte)"
        map_secret["severity"] = "INFO"
        found_secrets.append(map_secret)

    try:
        r = requests.get(
            js_url,
            headers={"User-Agent": USER_AGENT},
            timeout=PROBE_TIMEOUT,
            verify=False,
            allow_redirects=True,
            proxies=proxies,
        )
        if r.status_code != 200 or not r.text:
            return found_secrets, []

        content = r.text

        # 1. Search for Secrets & Actively Validate
        for secret_name, (pattern, default_severity) in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                for match in set(matches):
                    val = match if isinstance(match, str) else match[0]
                    is_exploitable, status_note, poc_cmd = validate_secret(secret_name, val)
                    
                    final_severity = "CRITICAL" if is_exploitable else ("LOW" if "protegido" in status_note.lower() else default_severity)
                    
                    evidence = classify_secret_evidence(secret_name, val, js_url, status_note)
                    found_secrets.append({
                        "type": secret_name,
                        "value": redact_value(val),
                        "severity": final_severity if evidence["status"] == "CONFIRMED" else min_severity(final_severity),
                        "source": js_url,
                        "status_note": status_note,
                        "poc_curl": redact_poc(poc_cmd, val),
                        "evidence_status": evidence["status"],
                        "evidence_rationale": evidence["rationale"],
                        "value_fingerprint": evidence["value_fingerprint"],
                    })

        # 2. Search for API Routes
        routes = ROUTE_PATTERN.findall(content)
        for route in set(routes):
            if len(route) < 100:
                found_routes.add(route)

    except Exception:
        pass

    return found_secrets, sorted(list(found_routes))


def min_severity(severity: str) -> str:
    """Unvalidated client-side observations cannot be CRITICAL/HIGH impacts."""
    return {"CRITICAL": "MEDIUM", "HIGH": "MEDIUM"}.get(severity, severity)


def redact_poc(command: str, secret: str) -> str:
    if not command:
        return ""
    return command.replace(secret, "<redacted>")
