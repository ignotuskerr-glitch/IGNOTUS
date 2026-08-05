import requests
from typing import List
from core.config import TIMEOUT, USER_AGENT
from core.fingerprint import fingerprint_engine


def get_subdomains(domain: str) -> List[str]:
    """Queries HackerTarget Host Search API for subdomains."""
    subdomains: set = set()
    cfg     = fingerprint_engine.providers["hackertarget"]
    url     = cfg["url"].replace("{domain}", domain)
    timeout = TIMEOUT * cfg.get("timeout_multiplier", 2)
    headers = {"User-Agent": USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            for line in response.text.split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub.endswith(domain) and not sub.startswith("*."):
                        subdomains.add(sub)
    except Exception:
        pass

    return list(subdomains)
