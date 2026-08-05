"""
ingotus/core/cors_credentials.py

Deep CORS Credential Exploiter.
Tests advanced reflection technique with Access-Control-Allow-Credentials: true
and inspects if sensitive JWT tokens, session cookies, or PII are exposed in the response.
"""

import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from core.config import PROBE_TIMEOUT, USER_AGENT
from core.jwt_analyzer import extract_and_analyze_jwts

def audit_cors_credentials(base_url: str, proxy: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Audits CORS configuration specifically looking for exploitation via credentials reflection.
    """
    findings: List[Dict[str, Any]] = []
    proxies = {"http": proxy, "https": proxy} if proxy else None

    parsed = urlparse(base_url)
    clean_host = parsed.netloc

    test_origins = [
        ("https://evil-attacker.com", "Arbitrary External Origin"),
        (f"https://attacker.{clean_host}", "Subdomain Bypass"),
        (f"https://{clean_host}.evil-attacker.com", "Pre-Domain Bypass"),
        ("null", "Null Origin (Sandboxed Iframe)"),
    ]

    for origin, label in test_origins:
        headers = {
            "User-Agent": USER_AGENT,
            "Origin": origin
        }
        try:
            r = requests.get(base_url, headers=headers, timeout=PROBE_TIMEOUT, verify=False, proxies=proxies, allow_redirects=False)
            
            allow_origin = r.headers.get("access-control-allow-origin", "").strip()
            allow_creds = r.headers.get("access-control-allow-credentials", "").strip().lower()

            is_reflected = (allow_origin == origin) or (origin == "null" and allow_origin == "null")
            has_credentials = (allow_creds == "true")

            if is_reflected and has_credentials:
                # Inspect body/headers for JWT or sensitive data
                jwts = extract_and_analyze_jwts(r.text + str(r.headers))
                
                sev = "CRITICAL" if jwts else "HIGH"
                jwt_note = f"\n[!] ATENÇÃO: {len(jwts)} JWT Token(s) exposto(s) na resposta vulnerável!" if jwts else ""

                findings.append({
                    "severity": sev,
                    "desc": f"CORS Crítico: Credenciais Habilitadas com Origem Refletida ({label})",
                    "evidence": (
                        f"Target URL: {base_url}\n"
                        f"Origin Enviada: {origin} ({label})\n"
                        f"Header Resposta: Access-Control-Allow-Origin: {allow_origin}\n"
                        f"Header Resposta: Access-Control-Allow-Credentials: {allow_creds}"
                        f"{jwt_note}\n\n"
                        f"PoC Exploit JavaScript:\n"
                        f"  fetch('{base_url}', {{\n"
                        f"    credentials: 'include',\n"
                        f"    headers: {{ 'Origin': '{origin}' }}\n"
                        f"  }}).then(r => r.text()).then(data => alert(data));"
                    ),
                    "poc": f"curl -sk '{base_url}' -H 'Origin: {origin}' -v"
                })
        except Exception:
            continue

    return findings
