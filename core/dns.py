"""
ingotus/core/dns.py

DNS resolution (A, AAAA, CNAME), wildcard detection, and email security
analysis (SPF / DMARC / DKIM) for the root domain.
"""

import re
import random
import string
import dns.resolver
from typing import List, Optional
from core.config import TIMEOUT, WILDCARD_CHECK_PREFIX, WILDCARD_RAND_LEN
from core.cache import dns_cache
from core.models import DNSInfo, EmailSecurityInfo


# ── Common DKIM selector names to probe ───────────────────────────────────────
# Only used for informational detection — we do NOT flag missing selectors as
# a vulnerability; DKIM key locations are private.
_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "mail",
    "k1", "dkim", "s1", "s2", "mandrill", "mailchimp",
]


def resolve_dns(subdomain: str) -> DNSInfo:
    """
    Resolve A, AAAA, and CNAME records for a subdomain.
    Resolver nameservers are read from fingerprints.json so they can be
    swapped without touching Python code. Results are cached per run.
    """
    cached = dns_cache.get(subdomain)
    if cached:
        return cached

    dns_info = DNSInfo()

    # If subdomain is already an IP address, bypass DNS query
    import socket
    is_ip = False
    for af in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(af, subdomain)
            is_ip = True
            break
        except socket.error:
            continue

    if is_ip:
        dns_info.ips.append(subdomain)
        dns_cache.set(subdomain, dns_info)
        return dns_info

    # Import here to avoid circular imports at module load time
    from core.fingerprint import fingerprint_engine

    resolver             = dns.resolver.Resolver(configure=False)
    resolver.nameservers = fingerprint_engine.dns_resolvers
    resolver.timeout     = TIMEOUT
    resolver.lifetime    = TIMEOUT

    # CNAME
    try:
        for rdata in resolver.resolve(subdomain, "CNAME"):
            dns_info.cname = str(rdata.target).rstrip(".")
            break
    except Exception:
        pass

    # A records (IPv4)
    try:
        for rdata in resolver.resolve(subdomain, "A"):
            dns_info.ips.append(str(rdata.address))
    except Exception:
        pass

    # AAAA records (IPv6)
    try:
        for rdata in resolver.resolve(subdomain, "AAAA"):
            dns_info.ips.append(str(rdata.address))
    except Exception:
        pass

    dns_cache.set(subdomain, dns_info)
    return dns_info


def check_wildcard_dns(domain: str) -> List[str]:
    """
    Detect wildcard / catch-all DNS by resolving a guaranteed-nonexistent subdomain.
    Returns the list of wildcard IPs if catch-all is active, or an empty list.
    """
    rand_suffix = "".join(
        random.choices(string.ascii_lowercase + string.digits, k=WILDCARD_RAND_LEN)
    )
    test_sub = f"{WILDCARD_CHECK_PREFIX}{rand_suffix}.{domain}"

    try:
        res = resolve_dns(test_sub)
        if res.ips:
            return res.ips
    except Exception:
        pass

    return []


# ── Email Security (SPF / DMARC / DKIM) ─────────────────────────────────────

def _query_txt(fqdn: str) -> List[str]:
    """Return all TXT record strings for *fqdn*, or [] on any error."""
    from core.fingerprint import fingerprint_engine
    try:
        resolver             = dns.resolver.Resolver(configure=False)
        resolver.nameservers = fingerprint_engine.dns_resolvers
        resolver.timeout     = TIMEOUT
        resolver.lifetime    = TIMEOUT
        answers = resolver.resolve(fqdn, "TXT")
        results = []
        for rdata in answers:
            # Each TXT record may be split across multiple strings; join them.
            txt = "".join(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                          for s in rdata.strings)
            results.append(txt)
        return results
    except Exception:
        return []


def _extract_dmarc_policy(record: str) -> Optional[str]:
    """Parse p= tag from a DMARC record string."""
    m = re.search(r"\bp=(\w+)", record, re.IGNORECASE)
    return m.group(1).lower() if m else None


def check_email_security(domain: str) -> EmailSecurityInfo:
    """
    Check SPF, DMARC, and DKIM for the given root domain.

    SPF  — TXT record on the domain itself containing 'v=spf1'
    DMARC — TXT record on _dmarc.<domain> containing 'v=DMARC1'
    DKIM  — probe common selectors at <selector>._domainkey.<domain>

    Only the root domain should be passed here; checking every subdomain
    would be redundant and expensive.
    """
    info = EmailSecurityInfo()

    # ── SPF ───────────────────────────────────────────────────────────────────
    for txt in _query_txt(domain):
        if txt.lower().startswith("v=spf1"):
            info.spf       = txt
            info.spf_valid = True
            break
    if not info.spf_valid:
        info.spf_valid = False

    # ── DMARC ─────────────────────────────────────────────────────────────────
    dmarc_fqdn = f"_dmarc.{domain}"
    for txt in _query_txt(dmarc_fqdn):
        if "v=dmarc1" in txt.lower():
            info.dmarc        = txt
            info.dmarc_policy = _extract_dmarc_policy(txt)
            break

    # ── DKIM (informational probe of common selectors) ─────────────────────
    info.dkim_checked = True
    for selector in _DKIM_SELECTORS:
        fqdn = f"{selector}._domainkey.{domain}"
        txts = _query_txt(fqdn)
        if any("v=dkim1" in t.lower() or "p=" in t for t in txts):
            # DKIM found — record the selector name for evidence
            info.dkim_checked = True
            break

    return info
