"""
ingotus/providers/shodan_dns.py

Passive subdomain discovery via Shodan DNS API (requires free API key).
Set environment variable: SHODAN_API_KEY=your_key_here
"""
import os
import requests
from typing import List
from core.config import TIMEOUT, USER_AGENT


def get_subdomains(domain: str) -> List[str]:
    """Queries Shodan DNS API for subdomains of domain."""
    api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key:
        return []

    subdomains: set = set()
    headers = {"User-Agent": USER_AGENT}
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
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
