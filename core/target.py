"""
ingotus/core/target.py

Intelligent target parser and normalizer for Ingotus Recon.
Handles domain wildcards (*.domain.com), URLs (http/https), IPv4, IPv6,
and targets with custom ports (e.g. host:8080 or [ipv6]:8080).
"""

import re
import urllib.parse
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Optional


class TargetType:
    DOMAIN         = "DOMAIN"          # e.g. example.com, *.example.com, sub.example.com
    IPV4           = "IPV4"            # e.g. 192.168.1.1
    IPV6           = "IPV6"            # e.g. 2800:3f0:4001:83b::2004
    HOST_WITH_PORT = "HOST_WITH_PORT"  # e.g. example.com:8080, 192.168.1.1:8443


class ParsedTarget:
    """
    Parses and normalizes any user-supplied target input.

    Attributes:
        raw (str): Original input string (e.g. "*.googel.com", "http://192.168.1.1:8080/")
        host (str): Clean hostname or IP address without wildcards/protocols/ports
        custom_port (Optional[int]): Port integer if target specified one, else None
        target_type (str): TargetType constant
        clean_target (str): Safe filesystem/reporting target label
        is_passive_eligible (bool): True if target is a domain suitable for passive recon
    """

    def __init__(self, raw_input: str):
        self.raw: str                 = raw_input.strip()
        self.host: str                = ""
        self.custom_port: Optional[int] = None
        self.target_type: str         = TargetType.DOMAIN
        self.clean_target: str        = ""
        self.is_passive_eligible: bool = True

        self._parse()

    def _parse(self) -> None:
        s = self.raw.strip().lower()

        # 1. Strip protocol scheme if present (e.g. http://, https://)
        if "://" in s:
            try:
                parsed_url = urllib.parse.urlparse(s)
                s = parsed_url.netloc or parsed_url.path
            except Exception:
                s = s.split("://", 1)[-1]

        # Strip URL paths, query parameters, trailing slashes
        s = s.split("/")[0].split("?")[0].split("#")[0]

        # 2. Strip wildcard patterns — suporta todos os formatos:
        #    *.example.com        → example.com
        #    *.example.*          → example  (tratado abaixo com fallback de TLD)
        #    *.example.com.*      → example.com
        #    *example.com         → example.com
        #    example.com/*        → example.com  (já tratado pelo split("/") acima)

        # Remove wildcard do início: *.foo -> foo
        s = re.sub(r'^\*\.+', '', s)
        s = re.sub(r'^\*+', '', s)

        # Remove wildcard do final: foo.* ou foo.com.* -> remove o .* final
        # Faz isso em loop para cobrir foo.*.* e similares
        while re.search(r'\.\*+$', s):
            s = re.sub(r'\.\*+$', '', s)

        # Remove wildcards no meio: foo.*.bar -> foo.bar
        s = re.sub(r'\.\*+\.', '.', s)

        # 3. Handle bracketed IPv6 with port: [2800:3f0:4001:83b::2004]:8080
        m_v6_port = re.match(r"^\[([a-f0-9:]+)\]:(\d+)$", s)
        if m_v6_port:
            self.host                = m_v6_port.group(1)
            self.custom_port         = int(m_v6_port.group(2))
            self.target_type         = TargetType.HOST_WITH_PORT
            self.clean_target        = f"{self.host.replace(':', '_')}_{self.custom_port}"
            self.is_passive_eligible = False
            return

        # 4. Handle raw IPv6 address without port: 2800:3f0:4001:83b::2004
        try:
            ip_obj = ip_address(s)
            if isinstance(ip_obj, IPv6Address):
                self.host                = str(ip_obj)
                self.target_type         = TargetType.IPV6
                self.clean_target        = self.host.replace(":", "_")
                self.is_passive_eligible = False
                return
            elif isinstance(ip_obj, IPv4Address):
                self.host                = str(ip_obj)
                self.target_type         = TargetType.IPV4
                self.clean_target        = self.host
                self.is_passive_eligible = False
                return
        except ValueError:
            pass

        # 5. Handle host:port or ipv4:port (e.g. example.com:8080 or 192.168.1.1:8080)
        if ":" in s and not s.endswith(":"):
            parts = s.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                self.host                = parts[0]
                self.custom_port         = int(parts[1])
                self.target_type         = TargetType.HOST_WITH_PORT
                self.clean_target        = f"{self.host}_{self.custom_port}"
                self.is_passive_eligible = False
                return

        # 6. Regular Domain / Subdomain (e.g. example.com or sub.example.com)
        self.host                = s
        self.clean_target        = s.replace("*", "").strip(".")
        self.target_type         = TargetType.DOMAIN
        self.is_passive_eligible = True

    def __repr__(self) -> str:
        return (
            f"ParsedTarget(raw='{self.raw}', host='{self.host}', "
            f"type='{self.target_type}', port={self.custom_port}, "
            f"passive={self.is_passive_eligible})"
        )
