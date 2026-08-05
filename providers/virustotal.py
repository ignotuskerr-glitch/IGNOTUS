"""
ingotus/providers/virustotal.py

Passive subdomain discovery via VirusTotal API v3 (requires free API key).
Set environment variable: VT_API_KEY=your_key_here
"""
import os
import requests
from typing import List
from core.config import TIMEOUT, USER_AGENT


def get_subdomains(domain: str) -> List[str]:
    """Queries VirusTotal API v3 for subdomains of domain."""
    api_key = os.getenv("VT_API_KEY", "")
    if not api_key:
        return []

    subdomains: set = set()
    headers = {
        "User-Agent": USER_AGENT,
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT * 15)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("data", []):
                sub = item.get("id", "").strip().lower()
                if sub and (sub.endswith(f".{domain}") or sub == domain) and not sub.startswith("*."):
                    subdomains.add(sub)
    except Exception:
        pass
    return list(subdomains)
