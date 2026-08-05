import requests
from typing import List
from core.config import TIMEOUT, USER_AGENT
from core.fingerprint import fingerprint_engine


def get_subdomains(domain: str) -> List[str]:
    """Queries AlienVault OTX Passive DNS API for subdomains."""
    subdomains: set = set()
    cfg     = fingerprint_engine.providers["alienvault"]
    url     = cfg["url"].replace("{domain}", domain)
    timeout = TIMEOUT * cfg.get("timeout_multiplier", 2)
    headers = {"User-Agent": USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            for record in data.get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if hostname.endswith(domain) and not hostname.startswith("*."):
                    subdomains.add(hostname)
    except Exception:
        pass

    return list(subdomains)
