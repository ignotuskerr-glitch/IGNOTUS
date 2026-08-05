"""
ingotus/core/cve_lookup.py

Correlates detected software versions against public CVE databases.

Strategy:
  - Only queries when a concrete version string is identified (e.g. "nginx/1.18.0").
    Without a version there is nothing to pin a CVE to — querying by product name
    alone produces thousands of false positives.
  - Primary source: CIRCL CVE Search API (https://cve.circl.lu) — no API key required.
  - Fallback source: NVD 2.0 API (https://services.nvd.nist.gov) — used if CIRCL
    returns no results or is unreachable.
  - Only CVEs with CVSS v3.1 base score >= 7.0 (HIGH/CRITICAL) are returned.
    Lower-severity CVEs add noise without actionable red-team value.
  - Results are cached in-process for the lifetime of one scan run to avoid
    hammering external APIs when multiple subdomains run the same software.
"""

from __future__ import annotations

import re
import time
import logging
from typing import List, Dict, Optional, Tuple
from functools import lru_cache

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

# Minimum CVSS 3.x base score to include in results (0.0 = inclui TODOS os CVEs registrados)
MIN_CVSS_SCORE: float = 0.0

# Request timeouts — keep short; CVE lookup is best-effort, not blocking
CIRCL_TIMEOUT: float  = 4.0
NVD_TIMEOUT:   float  = 5.0

# CIRCL CVE Search API
CIRCL_BASE = "https://cve.circl.lu/api"

# NVD 2.0 API
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Minimum delay between successive external calls (be a polite client)
_CALL_DELAY: float = 0.3

# ── Version extraction ────────────────────────────────────────────────────────

_VERSION_RE = re.compile(
    r"(?P<vendor>[A-Za-z0-9_\-\.]+)"
    r"[/\s]"
    r"(?P<version>\d+(?:\.\d+){1,4}(?:[a-z0-9\-\.]+)?)",
    re.IGNORECASE,
)


def parse_versioned_tech(raw: str) -> Optional[Tuple[str, str]]:
    """
    Extract (product, version) from a raw server/tech string.

    Examples:
      "nginx/1.18.0"           -> ("nginx", "1.18.0")
      "Apache/2.4.51 (Ubuntu)" -> ("apache", "2.4.51")
      "Microsoft-IIS/10.0"     -> ("microsoft-iis", "10.0")
      "cloudflare"             -> None   (no version)
      ""                       -> None
    """
    if not raw:
        return None
    m = _VERSION_RE.search(raw)
    if not m:
        return None
    product = m.group("vendor").lower().replace("-", "_")
    version = m.group("version")
    # Skip obviously wrong matches like "v1.0" vendor names from generic strings
    if len(product) < 2:
        return None
    return product, version


# ── CIRCL API ─────────────────────────────────────────────────────────────────

def _query_circl(product: str, version: str) -> List[Dict]:
    """
    Query CIRCL CVE Search API.

    CIRCL's /api/search endpoint accepts {vendor}/{product} only — no version
    in the URL.  We fetch all CVEs for the product and then filter client-side
    by checking whether our version appears in the CPE strings attached to each
    CVE entry.  This keeps false-positives low without needing a second round-
    trip per CVE.
    """
    url = f"{CIRCL_BASE}/search/{product}/{product}"
    try:
        resp = requests.get(url, timeout=CIRCL_TIMEOUT, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        raw_list: List[Dict] = []
        if isinstance(data, dict):
            raw_list = data.get("results", [])
        elif isinstance(data, list):
            raw_list = data

        # Filter: keep only entries whose CPE strings mention our version
        filtered: List[Dict] = []
        for entry in raw_list:
            cpes: List[str] = entry.get("vulnerable_product", []) or entry.get("cpe", [])
            if not cpes:
                # No CPE data — skip to avoid false-positives
                continue
            version_hit = any(f":{version}:" in cpe or f":{version}" == cpe[-len(version)-1:]
                              for cpe in cpes)
            if version_hit:
                filtered.append(entry)
        return filtered
    except Exception as exc:
        logger.debug("[cve_lookup] CIRCL request failed for %s/%s: %s", product, version, exc)
    return []


def _parse_circl_cve(raw: Dict) -> Optional[Dict]:
    """
    Normalise a raw CIRCL CVE record into a compact dict.
    Returns None when the CVE doesn't meet the minimum score threshold.
    """
    cve_id = raw.get("id") or raw.get("cve_id", "")
    summary = raw.get("summary") or raw.get("description", "No description available.")

    # CIRCL may embed CVSS v3 score directly or inside a nested dict
    score_v3: float = 0.0
    vector_v3: str  = ""

    cvss3 = raw.get("cvss3") or raw.get("cvss-v3") or {}
    if isinstance(cvss3, dict):
        score_v3  = float(cvss3.get("baseScore", 0.0) or cvss3.get("score", 0.0))
        vector_v3 = cvss3.get("vectorString", "") or cvss3.get("vector", "")
    elif isinstance(cvss3, (int, float)):
        score_v3 = float(cvss3)

    # Fallback: CIRCL sometimes puts score in top-level "cvss"
    if score_v3 == 0.0:
        cvss_raw = raw.get("cvss")
        if cvss_raw:
            try:
                score_v3 = float(cvss_raw)
            except (TypeError, ValueError):
                pass

    if score_v3 < MIN_CVSS_SCORE:
        return None

    return {
        "cve_id":     cve_id,
        "score":      score_v3,
        "vector":     vector_v3,
        "summary":    summary[:300],
        "references": (raw.get("references") or [])[:3],
        "source":     "CIRCL",
    }


# ── NVD primary API ───────────────────────────────────────────────────────────

# Common CPE vendor aliases (NVD uses specific vendor names in CPE 2.3 URIs)
_CPE_VENDOR_MAP: dict = {
    "nginx":           "nginx",
    "apache":          "apache",
    "microsoft_iis":   "microsoft",
    "openssl":         "openssl",
    "tomcat":          "apache",
    "jetty":           "eclipse",
    "lighttpd":        "lighttpd",
    "openresty":       "openresty",
    "php":             "php",
    "wordpress":       "wordpress",
    "drupal":          "drupal",
    "joomla":          "joomla",
    "django":          "djangoproject",
    "flask":           "palletsprojects",
    "spring":          "vmware",
    "struts":          "apache",
    "jquery":          "jquery",
}

# CPE product name overrides where NVD's CPE product ID differs from the
# colloquial product name we parse from the Server header.
_CPE_PRODUCT_MAP: dict = {
    "apache":         "http_server",           # Apache HTTPD — NVD CPE uses http_server
    "microsoft_iis":  "internet_information_services",
    "tomcat":         "tomcat",
    "struts":         "struts",
    "openresty":      "openresty",
    "nginx":          "nginx",
    "lighttpd":       "lighttpd",
    "openssl":        "openssl",
    "php":            "php",
    "wordpress":      "wordpress",
    "drupal":         "drupal",
    "joomla":         "joomla",
    "jquery":         "jquery",
}


def _query_nvd(product: str, version: str) -> List[Dict]:
    """
    Query NVD 2.0 API using two passes:

    Pass 1 — cpeName exact match: constructs a CPE 2.3 URI and queries
    NVD's cpeName parameter. Most precise; returns only CVEs that explicitly
    reference that product+version combination in their CPE configuration.

    Pass 2 — keywordSearch fallback: used when the CPE query returns nothing
    or the product is not in the alias map. Broader but still useful.
    """
    found: List[Dict] = []

    # Pass 1: CPE-name query
    vendor  = _CPE_VENDOR_MAP.get(product, product)
    prod_id = _CPE_PRODUCT_MAP.get(product, product)
    cpe_uri = f"cpe:2.3:a:{vendor}:{prod_id}:{version}:*:*:*:*:*:*:*"
    try:
        resp = requests.get(
            NVD_BASE,
            params={"cpeName": cpe_uri, "resultsPerPage": 15},
            timeout=NVD_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            found = resp.json().get("vulnerabilities", [])
    except Exception as exc:
        logger.debug("[cve_lookup] NVD CPE query failed for %s: %s", cpe_uri, exc)

    # Pass 2: keyword fallback when CPE returned nothing
    if not found:
        try:
            resp = requests.get(
                NVD_BASE,
                params={
                    "keywordSearch":  f"{product} {version}",
                    "resultsPerPage": 10,
                },
                timeout=NVD_TIMEOUT,
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                found = resp.json().get("vulnerabilities", [])
        except Exception as exc:
            logger.debug("[cve_lookup] NVD keyword query failed for %s/%s: %s", product, version, exc)

    return found


def _parse_nvd_cve(raw: Dict, product: str, version: str) -> Optional[Dict]:
    """
    Normalise a raw NVD 2.0 vulnerability record.
    Validates that the affected version range actually covers our version.
    """
    cve_node = raw.get("cve", {})
    if not _nvd_affects_version(cve_node.get("configurations", []), product, version):
        return None
    cve_id   = cve_node.get("id", "")
    descs    = cve_node.get("descriptions", [])
    summary  = next((d["value"] for d in descs if d.get("lang") == "en"), "No description.")

    # Extract CVSS v3.x score
    score_v3:  float = 0.0
    vector_v3: str   = ""
    metrics = cve_node.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score_v3  = float(cvss_data.get("baseScore", 0.0))
            vector_v3 = cvss_data.get("vectorString", "")
            break

    if score_v3 < MIN_CVSS_SCORE:
        return None

    refs = [
        r["url"] for r in cve_node.get("references", [])[:3]
    ]

    return {
        "cve_id":     cve_id,
        "score":      score_v3,
        "vector":     vector_v3,
        "summary":    summary[:300],
        "references": refs,
        "source":     "NVD",
    }


def _version_key(value: str) -> tuple:
    """Build a comparable key for common dotted software versions."""
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token.casefold())
        for token in re.findall(r"\d+|[A-Za-z]+", value)
    )


def _version_in_cpe_match(match: Dict, version: str) -> bool:
    criteria = str(match.get("criteria", ""))
    parts = criteria.split(":")
    exact_version = parts[5] if len(parts) > 5 else "*"
    if exact_version not in ("", "*", "-") and exact_version != version:
        return False

    candidate = _version_key(version)
    lower_inclusive = match.get("versionStartIncluding")
    lower_exclusive = match.get("versionStartExcluding")
    upper_inclusive = match.get("versionEndIncluding")
    upper_exclusive = match.get("versionEndExcluding")
    if lower_inclusive and candidate < _version_key(str(lower_inclusive)):
        return False
    if lower_exclusive and candidate <= _version_key(str(lower_exclusive)):
        return False
    if upper_inclusive and candidate > _version_key(str(upper_inclusive)):
        return False
    if upper_exclusive and candidate >= _version_key(str(upper_exclusive)):
        return False
    return bool(match.get("vulnerable", False))


def _nvd_affects_version(configurations: list, product: str, version: str) -> bool:
    """Require a vulnerable CPE/range that contains the detected version."""
    product_id = _CPE_PRODUCT_MAP.get(product, product).replace("_", "-")

    def walk(nodes):
        for node in nodes or []:
            for match in node.get("cpeMatch", []):
                criteria = str(match.get("criteria", "")).casefold()
                normalized = criteria.replace("_", "-")
                if f":{product_id}:" in normalized and _version_in_cpe_match(match, version):
                    return True
            if walk(node.get("nodes", [])):
                return True
            if walk(node.get("children", [])):
                return True
        return False

    return walk(configurations)


# ── Public interface ──────────────────────────────────────────────────────────

@lru_cache(maxsize=256)
def fetch_cves_for_tech(raw_tech_string: str) -> List[Dict]:
    """
    Main entry point.  Given a raw tech/server banner string, attempt to
    correlate it with known CVEs.

    Returns a list of normalised CVE dicts, sorted descending by score.
    Returns an empty list when:
      - No version can be parsed from the string.
      - No CVEs above the minimum score threshold are found.
      - External APIs are unreachable (best-effort, never raises).

    This function is safe to call from threaded scan workers.  Results are
    cached by input string for the lifetime of the Python process.
    """
    if not _HAS_REQUESTS:
        logger.debug("[cve_lookup] requests library not available — CVE lookup disabled")
        return []

    parsed = parse_versioned_tech(raw_tech_string)
    if not parsed:
        return []

    product, version = parsed
    results: List[Dict] = []

    # 1. NVD first — verified to work, returns version-accurate results
    time.sleep(_CALL_DELAY)
    raw_nvd = _query_nvd(product, version)
    for item in raw_nvd:
        normalised = _parse_nvd_cve(item, product, version)
        if normalised:
            results.append(normalised)

    # 2. CIRCL supplement — adds any CVEs NVD missed (uses CPE version filtering)
    if len(results) < 10:
        time.sleep(_CALL_DELAY)
        raw_circl = _query_circl(product, version)
        for item in raw_circl:
            normalised = _parse_circl_cve(item)
            if normalised:
                results.append(normalised)

    # Deduplicate by CVE ID and sort by score descending
    seen: set = set()
    unique: List[Dict] = []
    for r in results:
        if r["cve_id"] and r["cve_id"] not in seen:
            seen.add(r["cve_id"])
            unique.append(r)

    unique.sort(key=lambda x: x["score"], reverse=True)

    if unique:
        logger.debug(
            "[cve_lookup] %s/%s -> %d CVE(s) found (>= %.1f)",
            product, version, len(unique), MIN_CVSS_SCORE,
        )

    return unique


def severity_from_score(score: float) -> str:
    """Map a CVSS base score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"
