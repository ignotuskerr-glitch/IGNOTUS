"""
ingotus/providers/anubis.py

Passive subdomain discovery via Anubis-DB (free, no API key required).
Source: https://jonlu.ca/anubis/subdomains/{domain}
"""
import requests
from typing import List
from core.config import TIMEOUT, USER_AGENT


def get_subdomains(domain: str) -> List[str]:
    """Queries Anubis-DB free API for subdomains of domain."""
    subdomains: set = set()
    headers = {"User-Agent": USER_AGENT}
    url = f"https://jonlu.ca/anubis/subdomains/{domain}"
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT * 15)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                for sub in data:
                    sub = sub.strip().lower()
                    if sub and (sub.endswith(f".{domain}") or sub == domain) and not sub.startswith("*."):
                        subdomains.add(sub)
    except Exception:
        pass
    return list(subdomains)
