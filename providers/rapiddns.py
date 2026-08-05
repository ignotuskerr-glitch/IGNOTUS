import requests
import re
from typing import List
from core.config import TIMEOUT, USER_AGENT
from core.fingerprint import fingerprint_engine


def get_subdomains(domain: str) -> List[str]:
    """Queries RapidDNS.io for subdomains via HTML scraping (regex from JSON config)."""
    subdomains: set = set()
    cfg     = fingerprint_engine.providers["rapiddns"]
    url     = cfg["url"].replace("{domain}", domain)
    timeout = TIMEOUT * cfg.get("timeout_multiplier", 3)
    headers = {"User-Agent": USER_AGENT}

    # Regex pattern is stored in JSON so it can be updated without touching code.
    raw_pattern = cfg.get("regex", r"([a-z0-9][a-z0-9.-]+\.{domain})")
    pattern = re.compile(
        raw_pattern.replace("{domain}", re.escape(domain)),
        re.IGNORECASE,
    )

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            for match in pattern.findall(response.text):
                sub = match.lower().strip()
                if not sub.startswith("*."):
                    subdomains.add(sub)
    except Exception:
        pass

    return list(subdomains)
