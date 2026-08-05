"""
ingotus/providers/securitytrails_free.py

Passive subdomain discovery via SecurityTrails API (requires free API key).
Set environment variable: SECURITYTRAILS_API_KEY=your_key_here
"""
import os
import requests
from typing import List
from core.config import TIMEOUT, USER_AGENT


def get_subdomains(domain: str) -> List[str]:
    """Queries SecurityTrails API for subdomains of domain."""
    api_key = os.getenv("SECURITYTRAILS_API_KEY", "")
    if not api_key:
        return []

    subdomains: set = set()
    headers = {
        "User-Agent": USER_AGENT,
        "APIKEY": api_key,
        "Accept": "application/json",
    }
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT * 15)
        if r.status_code == 200:
            data = r.json()
            for sub in data.get("subdomains", []):
                sub = sub.strip().lower()
                if sub and not sub.startswith("*."):
                    full = f"{sub}.{domain}"
                    subdomains.add(full)
    except Exception:
        pass
    return list(subdomains)
