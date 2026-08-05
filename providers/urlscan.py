"""
ingotus/providers/urlscan.py

Passive subdomain discovery via urlscan.io public API.
No API key required for basic searches.
"""
import requests
from typing import List
from core.config import TIMEOUT, USER_AGENT


def get_subdomains(domain: str) -> List[str]:
    """Queries urlscan.io public API for subdomains of domain."""
    subdomains: set = set()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT * 15)
        if r.status_code == 200:
            data = r.json()
            for result in data.get("results", []):
                sub = result.get("page", {}).get("domain", "").strip().lower()
                if sub and (sub.endswith(f".{domain}") or sub == domain) and not sub.startswith("*."):
                    subdomains.add(sub)
    except Exception:
        pass
    return list(subdomains)
