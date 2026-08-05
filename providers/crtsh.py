import requests
import json
import time
from typing import List
from core.config import TIMEOUT, USER_AGENT
from core.fingerprint import fingerprint_engine


def get_subdomains(domain: str) -> List[str]:
    """Queries crt.sh certificate transparency database for subdomains with retries."""
    subdomains: set = set()
    cfg     = fingerprint_engine.providers["crtsh"]
    timeout = TIMEOUT * cfg.get("timeout_multiplier", 20)
    headers = {"User-Agent": USER_AGENT}

    # Try both URL-encoded wildcard and standard query formats
    queries = [f"%25.{domain}", f"%.{domain}", domain]

    for q in queries:
        url = f"https://crt.sh/?q={q}&output=json"
        for attempt in range(1, 4):
            try:
                response = requests.get(url, headers=headers, timeout=timeout)
                if response.status_code == 200 and response.text.strip():
                    try:
                        data = response.json()
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if (sub.endswith(f".{domain}") or sub == domain) and not sub.startswith("*."):
                                    subdomains.add(sub)
                        if subdomains:
                            return list(subdomains)
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass
            time.sleep(attempt * 1.5)

    return list(subdomains)

