"""
ingotus/core/github_dorker.py

GitHub Code Search & Secret Dorker.
Queries GitHub API for target orgs/domains searching for exposed secrets, .env files, and credentials.
"""

import urllib.parse
import requests
from typing import List, Dict, Optional

GITHUB_API_URL = "https://api.github.com/search/code"

DEFAULT_DORKS = [
    "filename:.env",
    "filename:config.json secret",
    "filename:docker-compose.yml password",
    "\"AKIA\" OR \"aws_secret_access_key\"",
    "\"sk-\" OR \"api_key\"",
    "\"DB_PASSWORD\" OR \"DATABASE_URL\"",
]


def dork_github(target_domain: str, token: Optional[str] = None, limit: int = 5) -> List[Dict[str, str]]:
    """
    Executes GitHub Code Search dorks for the given target domain.
    Returns list of findings with repo, file path, and URL.
    """
    clean_domain = target_domain.lstrip("*.").strip()
    findings = []

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "IngotusRecon/2.0",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    for dork in DEFAULT_DORKS[:limit]:
        query = f'"{clean_domain}" {dork}'
        params = {"q": query, "per_page": 5}

        try:
            resp = requests.get(GITHUB_API_URL, params=params, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("items", []):
                    findings.append({
                        "dork": dork,
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "path": item.get("path", ""),
                        "html_url": item.get("html_url", ""),
                        "severity": "high" if ".env" in item.get("path", "").lower() else "medium"
                    })
            elif resp.status_code == 403:
                # Rate limit hit
                break
        except Exception:
            continue

    return findings
