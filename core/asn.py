import requests
from typing import Optional
from core.config import TIMEOUT, USER_AGENT, PRIVATE_IP_PREFIXES
from core.models import ASNInfo
from core.cache import asn_cache
from core.fingerprint import fingerprint_engine


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP should be skipped (loopback, RFC-1918, unspecified)."""
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


def lookup_asn(ip: str) -> Optional[ASNInfo]:
    """
    Look up the ASN number and organisation for a public IP using the provider
    URL defined in fingerprints.json (asn_provider_url).
    Results are cached to respect the provider's rate limit.
    """
    if not ip or _is_private_ip(ip):
        return None

    cached = asn_cache.get(ip)
    if cached:
        return cached

    url     = fingerprint_engine.asn_provider_url.replace("{ip}", ip)
    headers = {"User-Agent": USER_AGENT}

    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                asn_info = ASNInfo()
                as_field = data.get("as", "")   # e.g. "AS15169 Google LLC"
                org_field = data.get("org", "")

                if as_field:
                    parts = as_field.split(" ", 1)
                    asn_info.number       = parts[0]
                    asn_info.organization = org_field or (parts[1] if len(parts) > 1 else "")
                else:
                    asn_info.organization = org_field

                asn_cache.set(ip, asn_info)
                return asn_info
    except Exception:
        pass

    return None
