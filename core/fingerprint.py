"""
ingotus/core/fingerprint.py

Central engine that loads ALL configuration from data/fingerprints.json.
No inline fallback data — if the JSON is missing or corrupt the engine raises
immediately so the operator knows the installation is broken, rather than
silently scanning with stale hardcoded data.
"""

import json
import re
import os
from typing import Dict, Any, List, Optional

from core.config import FINGERPRINTS_JSON_PATH


class FingerprintEngine:
    """
    Loads signature data and configuration from fingerprints.json and exposes
    typed properties for every module that needs them.
    """

    def __init__(self):
        self.signatures: Dict[str, Any] = {}
        self._load()

    # ── Loader ─────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Load fingerprints.json. Raises FileNotFoundError / ValueError on failure."""
        if not os.path.exists(FINGERPRINTS_JSON_PATH):
            raise FileNotFoundError(
                f"fingerprints.json not found at: {FINGERPRINTS_JSON_PATH}\n"
                "The file is required for Ignotus to operate. "
                "Restore it from the repository or reinstall."
            )
        try:
            with open(FINGERPRINTS_JSON_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"fingerprints.json is malformed (JSON parse error): {exc}\n"
                "Fix the JSON syntax and restart."
            ) from exc

        if not data:
            raise ValueError("fingerprints.json loaded but is empty.")

        self.signatures = data

    def reload(self) -> None:
        """Hot-reload signatures at runtime (useful for long-running daemons)."""
        self._load()

    # ── Detection data properties ───────────────────────────────────────────────

    @property
    def load_balancers(self) -> List[str]:
        return self.signatures["load_balancers"]

    @property
    def hosting_keywords(self) -> List[str]:
        return self.signatures["hosting_keywords"]

    @property
    def sensitive_ports(self) -> Dict[int, Dict[str, str]]:
        """Returns {port_int: {service, severity}} — keys are always integers."""
        return {int(k): v for k, v in self.signatures["sensitive_ports"].items()}

    @property
    def common_ports(self) -> List[int]:
        return self.signatures["common_ports"]

    @property
    def banner_probes(self) -> List[Dict[str, Any]]:
        return self.signatures["banner_probes"]

    @property
    def dns_resolvers(self) -> List[str]:
        return self.signatures["dns_resolvers"]

    @property
    def tech_signatures(self) -> List[Dict[str, Any]]:
        return self.signatures.get("tech_signatures", [])

    @property
    def required_security_headers(self) -> List[Dict[str, Any]]:
        return self.signatures.get("required_security_headers", [])

    @property
    def sensitive_paths(self) -> List[Dict[str, str]]:
        """Returns list of {path, severity} objects."""
        return self.signatures["sensitive_paths"]

    @property
    def confidence_scores(self) -> Dict[str, int]:
        return self.signatures["confidence_scores"]

    @property
    def providers(self) -> Dict[str, Dict[str, Any]]:
        return self.signatures["providers"]

    @property
    def asn_provider_url(self) -> str:
        return self.signatures["asn_provider_url"]

    @property
    def user_agent(self) -> str:
        return self.signatures.get("user_agent", "")

    # ── Detection methods ───────────────────────────────────────────────────────

    def detect_tech(self, headers: Dict[str, str], body: Optional[str]) -> List[str]:
        """Detect CMS / frameworks from response headers and body signatures."""
        detected = []
        body_text = (body or "").lower()

        for sig in self.tech_signatures:
            matched = False

            for h_name, pat in sig.get("headers", {}).items():
                h_val = headers.get(h_name.lower())
                if h_val and re.search(pat, h_val, re.IGNORECASE):
                    matched = True
                    break

            if not matched and body_text:
                for b_pat in sig.get("body", []):
                    if b_pat.lower() in body_text:
                        matched = True
                        break

            if matched:
                detected.append(sig["name"])

        return list(set(detected))

    def detect_cdn(
        self,
        cname: Optional[str],
        headers: Dict[str, str],
        asn_number: Optional[str],
        ips: Optional[List[str]] = None,
    ) -> List[str]:
        """Detect CDN providers from CNAME, response headers, ASN, and IP prefixes."""
        detected = []
        ips = ips or []

        for cdn in self.signatures.get("cdns", []):
            # 1. CNAME match
            if cname and any(pat in cname.lower() for pat in cdn.get("cnames", [])):
                detected.append(cdn["name"])
                continue

            # 2. ASN match
            if asn_number and asn_number in cdn.get("asns", []):
                detected.append(cdn["name"])
                continue

            # 3. IP prefix match (catches CDN nodes whose CNAME/ASN lookup fails)
            ip_prefixes = cdn.get("ip_prefixes", [])
            if ip_prefixes and ips:
                for ip in ips:
                    if any(ip.startswith(pfx) for pfx in ip_prefixes):
                        detected.append(cdn["name"])
                        break
                if cdn["name"] in detected:
                    continue

            # 4. Response header match
            for header_name, pattern in cdn.get("headers", {}).items():
                h_val = headers.get(header_name.lower())
                if h_val and re.search(pattern, h_val, re.IGNORECASE):
                    detected.append(cdn["name"])
                    break

        return list(set(detected))

    def detect_waf(self, headers: Dict[str, str]) -> List[str]:
        """Detect WAF products from response headers."""
        detected = []

        for waf in self.signatures.get("wafs", []):
            for header_name, pattern in waf.get("headers", {}).items():
                h_val = headers.get(header_name.lower())
                if h_val and re.search(pattern, h_val, re.IGNORECASE):
                    detected.append(waf["name"])
                    break

        return list(set(detected))

    def detect_cloud(
        self, cname: Optional[str], asn_org: Optional[str]
    ) -> Optional[str]:
        """Detect cloud provider from CNAME suffix or ASN organisation name."""
        for cloud in self.signatures.get("clouds", []):
            if cname and any(pat in cname.lower() for pat in cloud.get("cnames", [])):
                return cloud["name"]

            if asn_org and cloud.get("asns_patterns"):
                if any(
                    re.search(pat, asn_org, re.IGNORECASE)
                    for pat in cloud["asns_patterns"]
                ):
                    return cloud["name"]

        return None

    def check_takeover(
        self, cname: Optional[str], body: Optional[str]
    ) -> Optional[str]:
        """Return service name if subdomain shows signs of takeover, else None."""
        if not cname or not body:
            return None

        for to in self.signatures.get("takeovers", []):
            if any(pat in cname.lower() for pat in to.get("cnames", [])):
                if any(sig.lower() in body.lower() for sig in to.get("fingerprints", [])):
                    return to["service"]

        return None


# ── Global singleton ───────────────────────────────────────────────────────────
fingerprint_engine = FingerprintEngine()
