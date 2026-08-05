"""
ingotus/core/cors.py

Advanced CORS misconfiguration tester.
Testa:
  1. Reflexo de Origin arbitrário com credentials (evil-attacker.com)
  2. Origin: null com credentials (iframe sandboxed exploit)
  3. Subdomain bypass (attacker.target.com)
  4. Pre-domain bypass (target.com.evil.com)
  5. Wildcard (*) com credentials (configuração inválida mas reportável)
  6. HTTP downgrade (http:// em alvo HTTPS)
"""

import requests
from typing import Optional, Tuple, List, Dict
from core.config import PROBE_TIMEOUT, USER_AGENT


def _make_origins(target_host: str) -> List[Tuple[str, str]]:
    """
    Gera lista de origens de teste com labels para o report.
    """
    # Remove port e schema do host
    clean_host = (
        target_host.replace("https://", "").replace("http://", "").split("/")[0]
    )
    return [
        ("https://evil-attacker.com", "origin_arbitrary"),
        ("null", "origin_null"),
        (f"https://attacker.{clean_host}", "subdomain_of_target"),
        (f"https://{clean_host}.evil.com", "pre_domain_bypass"),
        (f"http://{clean_host}", "http_downgrade"),
        ("https://evil-attacker.com\r\n", "crlf_origin_injection"),
    ]


def probe_cors(
    url: str,
    proxy: Optional[str] = None,
    target_host: Optional[str] = None,
) -> Tuple[bool, bool, Optional[str]]:
    """
    Interface compatível com o código existente no classifier.py.

    Returns:
        (is_reflected, allows_credentials, test_origin_used)
    """
    results = probe_cors_full(url, proxy=proxy, target_host=target_host)
    if results:
        top = results[0]
        reflected = top.get("allow_origin") != "*"
        return reflected, top.get("allows_credentials", False), top.get("origin_tested")
    return False, False, None


def probe_cors_full(
    url: str,
    proxy: Optional[str] = None,
    target_host: Optional[str] = None,
) -> List[Dict]:
    """
    Testa múltiplas variantes de bypass de CORS.

    Returns:
        Lista de findings com detalhes de cada bypass encontrado.
    """
    findings: List[Dict] = []
    proxies = {"http": proxy, "https": proxy} if proxy else None

    if not target_host:
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        target_host = f"{parsed.scheme}://{parsed.netloc}"

    origins_to_test = _make_origins(target_host)

    for origin, origin_label in origins_to_test:
        headers = {
            "User-Agent": USER_AGENT,
            "Origin": origin,
        }
        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )

            if r.status_code in (301, 302, 303, 307, 308):
                continue

            allow_origin = r.headers.get("access-control-allow-origin", "").strip()
            allow_creds = (
                r.headers.get("access-control-allow-credentials", "").strip().lower()
            )
            allow_methods = r.headers.get("access-control-allow-methods", "")

            is_reflected = (
                allow_origin == origin
                or (origin == "null" and allow_origin == "null")
                or allow_origin == "*"
            )

            if not is_reflected:
                continue

            is_creds_true = allow_creds == "true"

            # Analisar se a resposta expoe JWT Tokens sensiveis no corpo ou cabeçalhos
            from core.jwt_analyzer import extract_and_analyze_jwts

            jwt_findings = extract_and_analyze_jwts(r.text + str(r.headers))
            jwt_note = ""
            if jwt_findings:
                jwt_note = f"\n[!] ATENÇÃO: A resposta vulnerável a CORS expõe {len(jwt_findings)} JWT Token(s)!"

            # Wildcard + credentials é configuração inválida (browsers ignoram)
            # mas alguns proxies/frameworks ainda aceitam
            if allow_origin == "*" and is_creds_true:
                severity = "HIGH"
                desc = "CORS: Wildcard (*) com Access-Control-Allow-Credentials: true — configuração inválida exploitável em alguns proxies"
            elif is_creds_true:
                severity = "CRITICAL" if jwt_findings else "HIGH"
                desc = f"CORS: Origin refletida ({origin_label}) com credentials — exploitável para roubo de sessão autenticada"
            else:
                severity = "MEDIUM"
                desc = f"CORS: Origin refletida ({origin_label}) sem credentials — informational mas verificar impacto"

            findings.append(
                {
                    "severity": severity,
                    "origin_label": origin_label,
                    "origin_tested": origin,
                    "allow_origin": allow_origin,
                    "allows_credentials": is_creds_true,
                    "allow_methods": allow_methods,
                    "desc": desc,
                    "evidence": (
                        f"GET {url}\n"
                        f"Origin: {origin}\n"
                        f"→ Access-Control-Allow-Origin: {allow_origin}\n"
                        f"→ Access-Control-Allow-Credentials: {allow_creds}"
                        f"{jwt_note}"
                    ),
                    "poc": (
                        f'fetch("{url}", {{\n'
                        f'  credentials: "include",\n'
                        f'  headers: {{ "Origin": "{origin}" }}\n'
                        f"}}).then(r => r.text()).then(console.log)"
                    ),
                }
            )

        except Exception:
            continue

    return findings
