"""
ingotus/providers/github_dork.py

Queries GitHub Code Search API to discover:
1. Subdomains mentioned in public GitHub code/repositories
2. Exposed credentials, secrets, or configuration files linked to the domain

Supports GITHUB_TOKEN environment variable if available for higher rate limits.
"""

import os
import re
import requests
from typing import List, Dict, Any
from core.config import TIMEOUT, USER_AGENT


def _get_headers() -> Dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github.v3+json",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def get_subdomains(domain: str) -> List[str]:
    """Queries GitHub Code Search for subdomains of the target domain."""
    subdomains: set = set()
    url = f"https://api.github.com/search/code?q={domain}&per_page=50"

    try:
        r = requests.get(url, headers=_get_headers(), timeout=TIMEOUT * 2)
        if r.status_code == 200:
            data = r.json()
            items = data.get("items", [])
            
            # Subdomain regex matching target domain
            sub_pattern = re.compile(
                r"([a-zA-Z0-9\-_]+\." + re.escape(domain) + r")",
                re.IGNORECASE
            )

            for item in items:
                # Check repo name / path
                repo_name = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                
                for match in sub_pattern.findall(f"{repo_name} {path}"):
                    sub = match.lower().strip()
                    if not sub.startswith("*."):
                        subdomains.add(sub)
    except Exception:
        pass

    return list(subdomains)


def audit_github_dorks(domain: str) -> List[Dict[str, Any]]:
    """
    Performs GitHub Dorking search for high-risk sensitive patterns.
    Queries:
      - '<domain> filename:.env'
      - '<domain> password'
      - '<domain> aws_secret_access_key'
      - '<domain> id_rsa'

    Returns list of findings with repo URL, file path, and snippet.
    """
    findings = []
    dorks = [
        (f'"{domain}" filename:.env', "Arquivo .env Público no GitHub", "CRITICAL"),
        (f'"{domain}" "password=" OR "DB_PASSWORD"', "Senha Hardcoded no GitHub", "HIGH"),
        (f'"{domain}" "aws_secret_access_key"', "Chave AWS exposta no GitHub", "CRITICAL"),
        (f'"{domain}" "BEGIN RSA PRIVATE KEY"', "Chave Privada exposta no GitHub", "CRITICAL"),
    ]

    for query, desc, severity in dorks:
        url = f"https://api.github.com/search/code?q={query}&per_page=5"
        try:
            r = requests.get(url, headers=_get_headers(), timeout=TIMEOUT * 2)
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items:
                    repo_url = item.get("html_url", "")
                    path = item.get("path", "")
                    repo_name = item.get("repository", {}).get("full_name", "")

                    findings.append({
                        "category": "github_dork",
                        "severity": severity,
                        "desc": desc,
                        "evidence": (
                            f"Repositório Público: {repo_name}\n"
                            f"Arquivo: {path}\n"
                            f"URL no GitHub: {repo_url}\n"
                            f"Consulta Dork: {query}\n"
                            f"Impacto: Credenciais ou configurações do domínio {domain} expostas em código público."
                        ),
                        "url": repo_url,
                    })
        except Exception:
            pass

    return findings
