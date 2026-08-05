"""
ingotus/core/ssrf_probe.py

SSRF detector com integração ao Interactsh (interact.sh) para validação OOB.
Usa o servidor público oast.fun ou servidor customizado via INTERACTSH_SERVER env var.

Fluxo:
  1. Registra um único token com interact.sh → obtém subdomínio único
  2. Descobre parâmetros GET/POST suspeitos no alvo
  3. Injeta URL callback nos parâmetros
  4. Aguarda N segundos e consulta interact.sh por interações DNS/HTTP
  5. Confirma SSRF com evidência se detectar callback

Referências:
  - https://github.com/projectdiscovery/interactsh
  - https://portswigger.net/web-security/ssrf
"""

import os
import re
import time
import uuid
import json
import base64
import requests
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin
from core.config import PROBE_TIMEOUT, USER_AGENT


# ── Configuration ──────────────────────────────────────────────────────────────
INTERACTSH_SERVER  = os.getenv("INTERACTSH_SERVER", "oast.fun")
INTERACTSH_API     = os.getenv("INTERACTSH_API_URL", f"https://interact.sh")
POLL_WAIT_SECONDS  = int(os.getenv("INTERACTSH_POLL_WAIT", "8"))

# Parameters most commonly vulnerable to SSRF
SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "redirect_to", "redirect_url", "next", "next_url",
    "target", "redir", "go", "out", "view", "from", "return",
    "return_to", "return_url", "back", "back_url",
    "proxy", "proxy_url", "webhook", "webhook_url", "callback",
    "callback_url", "endpoint", "api", "api_url", "host",
    "fetch", "load", "image", "img", "avatar", "photo",
    "file", "document", "attachment", "resource",
]

# Common paths that often have URL parameters
SSRF_PATHS = [
    "/api/webhook",
    "/api/fetch",
    "/api/proxy",
    "/redirect",
    "/out",
    "/fetch",
    "/image/proxy",
    "/avatar",
    "/api/v1/webhook",
    "/api/v2/webhook",
]


class InteractshClient:
    """Lightweight Interactsh client for OOB interaction detection."""

    def __init__(self):
        self.token       = str(uuid.uuid4()).replace("-", "")[:20]
        self.domain      = None
        self.registered  = False
        self._interactions: List[Dict] = []

    def register(self) -> Optional[str]:
        """
        Register with interactsh server and get a unique OOB domain.
        Falls back to a static pattern if registration fails.
        """
        # Try to register with interact.sh API
        try:
            r = requests.post(
                f"{INTERACTSH_API}/register",
                json={"public-key": self.token, "secret-key": self.token},
                headers={"User-Agent": USER_AGENT},
                timeout=5,
                verify=False,
            )
            if r.status_code == 200:
                data = r.json()
                self.domain    = data.get("domain", f"{self.token}.{INTERACTSH_SERVER}")
                self.registered = True
                return self.domain
        except Exception:
            pass

        # Fallback: use predictable subdomain pattern (works even without registration)
        self.domain    = f"{self.token}.{INTERACTSH_SERVER}"
        self.registered = True
        return self.domain

    def poll(self) -> List[Dict]:
        """Poll interact.sh for any recorded interactions."""
        if not self.domain:
            return []
        try:
            r = requests.get(
                f"{INTERACTSH_API}/poll",
                params={"id": self.token, "secret": self.token},
                headers={"User-Agent": USER_AGENT},
                timeout=5,
                verify=False,
            )
            if r.status_code == 200:
                data = r.json()
                return data.get("data", []) or []
        except Exception:
            pass
        return []

    def get_callback_url(self, path: str = "") -> str:
        """Returns an HTTP callback URL pointing to the OOB server."""
        return f"http://{self.domain}/{path}"

    def get_callback_https(self, path: str = "") -> str:
        return f"https://{self.domain}/{path}"


def _extract_params_from_url(url: str) -> List[str]:
    """Extract GET parameter names from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return list(params.keys())


def _inject_param(url: str, param: str, value: str) -> str:
    """Replace or add a parameter value in a URL."""
    from urllib.parse import quote
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    # Build query string manually to avoid double-encoding the injected value
    pairs = []
    for k, v_list in params.items():
        pairs.append(f"{quote(k, safe='')}={quote(v_list[0], safe=':/?#[]@!$&\'()*+,;=')}")
    new_qs = "&".join(pairs)
    return urlunparse(parsed._replace(query=new_qs))



def _find_ssrf_candidates(base_url: str, proxy: Optional[str] = None) -> List[Tuple[str, str]]:
    """
    Discover SSRF injection points on the target:
    1. Scan current URL params
    2. Try common SSRF paths with common param names

    Returns list of (url_template, param_name) tuples.
    """
    candidates = []
    proxies    = {"http": proxy, "https": proxy} if proxy else None
    headers    = {"User-Agent": USER_AGENT}

    # Current URL params
    existing_params = _extract_params_from_url(base_url)
    for p in existing_params:
        if p.lower() in SSRF_PARAM_NAMES:
            candidates.append((base_url, p))

    # Try common paths
    parsed = urlparse(base_url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    for path in SSRF_PATHS:
        test_url = base + path
        try:
            r = requests.get(test_url, headers=headers, timeout=PROBE_TIMEOUT,
                             verify=False, proxies=proxies, allow_redirects=False)
            if r.status_code in (200, 302, 400, 405, 422):
                # Path exists — add all SSRF param candidates for it
                for p in SSRF_PARAM_NAMES[:8]:
                    candidates.append((test_url, p))
        except Exception:
            continue

    return candidates


def probe_ssrf(
    base_url: str,
    proxy:    Optional[str] = None,
    timeout:  int = POLL_WAIT_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Main SSRF probe function.
    1. Initialise OOB client
    2. Find candidate URLs/parameters
    3. Inject callback URLs
    4. Wait and poll for interactions
    5. Return confirmed/attempted findings
    """
    findings      = []
    client        = InteractshClient()
    callback_host = client.register()

    if not callback_host:
        return []

    proxies  = {"http": proxy, "https": proxy} if proxy else None
    headers  = {"User-Agent": USER_AGENT}
    injected = []

    candidates = _find_ssrf_candidates(base_url, proxy=proxy)

    # Limit to avoid hammering; take top unique (url, param) pairs
    seen_params = set()
    for url_tpl, param in candidates:
        key = f"{urlparse(url_tpl).path}::{param}"
        if key in seen_params or len(injected) >= 10:
            continue
        seen_params.add(key)

        callback = client.get_callback_url(f"ssrf-{param}")
        injected_url = _inject_param(url_tpl, param, callback)

        try:
            requests.get(
                injected_url,
                headers=headers,
                timeout=PROBE_TIMEOUT,
                verify=False,
                proxies=proxies,
                allow_redirects=True,
            )
            injected.append({
                "url":       injected_url,
                "param":     param,
                "callback":  callback,
                "oob_host":  callback_host,
            })
        except Exception:
            pass

    if not injected:
        return []

    # Wait for OOB interactions
    time.sleep(timeout)

    # Poll interactsh
    interactions = client.poll()
    confirmed    = len(interactions) > 0

    for attempt in injected:
        severity   = "CRITICAL" if confirmed else "MEDIUM"
        confidence = "CONFIRMADO via OOB callback" if confirmed else "TENTATIVA (sem callback confirmado — verifique manualmente)"

        poc_url = attempt["url"]
        poc_cmd = f'curl -sk "{poc_url}"'

        findings.append({
            "severity":    severity,
            "technique":   "SSRF",
            "confidence":  confidence,
            "oob_host":    attempt["oob_host"],
            "param":       attempt["param"],
            "confirmed":   confirmed,
            "interactions": interactions,
            "evidence": (
                f"Técnica: Server-Side Request Forgery (SSRF)\n"
                f"Parâmetro injetado: {attempt['param']}\n"
                f"URL testada: {attempt['url']}\n"
                f"OOB Callback URL: {attempt['callback']}\n"
                f"Servidor OOB: {attempt['oob_host']}\n"
                f"Status: {confidence}\n"
                f"Interações recebidas: {len(interactions)}\n"
                + (f"Dados da interação: {json.dumps(interactions[0], indent=2)}\n" if interactions else "")
                + f"\n"
                f"Impacto: SSRF permite ao servidor fazer requisições para recursos internos,\n"
                f"metadados de cloud (AWS IMDS: 169.254.169.254), serviços internos (Redis, Elasticsearch),\n"
                f"ou ser usado como proxy para atacar redes internas.\n\n"
                f"PoC cURL:\n"
                f"  {poc_cmd}\n\n"
                f"  # Teste com AWS IMDS:\n"
                f"  curl -sk '{_inject_param(attempt['url'], attempt['param'], 'http://169.254.169.254/latest/meta-data/')}'\n\n"
                f"  # Verificar OOB:\n"
                f"  curl -sk 'https://interact.sh/poll?id={client.token}&secret={client.token}'"
            ),
        })

    return findings
