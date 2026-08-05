"""
ingotus/core/wayback_harvester.py

Wayback Machine / CDX Historical URL & Subdomain Harvester.
Fetches historical URLs for a target domain from archive.org CDX API.
Extracts interesting parameters (SSRF, Open Redirect, SQLi, LFI targets) and historical subdomains.
"""

import re
import urllib.parse
import requests
from typing import List, Dict, Set, Optional

WAYBACK_CDX_URL = "http://web.archive.org/cdx/search/cdx"

INTERESTING_PARAMS = {
    "ssrf": {"url", "dest", "redirect", "uri", "path", "continue", "to", "out", "view", "site", "domain", "host", "link"},
    "sqli": {"id", "select", "query", "search", "category", "filter", "order", "sort", "type", "view", "page"},
    "lfi": {"file", "filename", "doc", "document", "folder", "root", "pg", "template"},
    "redirect": {"next", "redirect_to", "return", "return_url", "checkout_url", "goto", "r"},
}


def fetch_wayback_urls(domain: str, limit: int = 5000, timeout: int = 15) -> List[str]:
    """
    Queries Wayback Machine CDX API for URLs matching *.domain/*
    """
    clean_domain = domain.lstrip("*.").strip()
    params = {
        "url": f"*.{clean_domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(limit),
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) IngotusRecon/2.0"
    }

    try:
        resp = requests.get(WAYBACK_CDX_URL, params=params, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                # First element is header ["original"]
                urls = [row[0] for row in data[1:] if len(row) > 0]
                return urls
    except Exception:
        pass

    return []


def analyze_wayback_urls(urls: List[str]) -> Dict[str, Set[str]]:
    """
    Categorizes URLs by potential vulnerability vectors and extracts historical subdomains.
    """
    results = {
        "subdomains": set(),
        "ssrf_targets": set(),
        "redirect_targets": set(),
        "sqli_targets": set(),
        "lfi_targets": set(),
        "sensitive_files": set(),
    }

    sensitive_extensions = {".env", ".git", ".bak", ".sql", ".zip", ".tar.gz", ".config", ".json", ".xml", ".yml", ".yaml"}

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname:
            results["subdomains"].add(parsed.hostname.lower())

        # Extension check
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in sensitive_extensions):
            results["sensitive_files"].add(url)

        # Query param check
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        param_names = {k.lower() for k in query.keys()}

        if param_names.intersection(INTERESTING_PARAMS["ssrf"]):
            results["ssrf_targets"].add(url)
        if param_names.intersection(INTERESTING_PARAMS["redirect"]):
            results["redirect_targets"].add(url)
        if param_names.intersection(INTERESTING_PARAMS["sqli"]):
            results["sqli_targets"].add(url)
        if param_names.intersection(INTERESTING_PARAMS["lfi"]):
            results["lfi_targets"].add(url)

    return results
