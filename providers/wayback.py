"""
ingotus/providers/wayback.py

Queries Wayback Machine (web.archive.org) CDX API for historical subdomains.
This passive source discovers historical hosts, staging endpoints, and legacy subdomains
that may not appear in current DNS or certificate transparency logs.
"""

import requests
import json
from typing import List
from core.config import TIMEOUT, USER_AGENT


def get_subdomains(domain: str) -> List[str]:
    """Queries Wayback Machine CDX API for unique subdomains of target domain."""
    subdomains: set = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
    headers = {"User-Agent": USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT * 3)
        if response.status_code == 200 and response.text.strip():
            try:
                data = response.json()
                # First item is header ["original"], rest are rows
                if len(data) > 1:
                    for row in data[1:]:
                        if not row:
                            continue
                        orig_url = row[0]
                        # Extract hostname from URL
                        from urllib.parse import urlparse
                        parsed = urlparse(orig_url)
                        host = parsed.netloc.split(":")[0].lower().strip()

                        if (host.endswith(f".{domain}") or host == domain) and not host.startswith("*."):
                            subdomains.add(host)
            except (json.JSONDecodeError, IndexError, ValueError):
                pass
    except Exception:
        pass

    return list(subdomains)
