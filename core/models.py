from dataclasses import dataclass, field, asdict
from typing import List, Tuple, Optional, Dict, Any


@dataclass
class DNSInfo:
    ips: List[str] = field(default_factory=list)
    cname: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EmailSecurityInfo:
    """SPF, DMARC, and DKIM status for the root domain."""
    spf: Optional[str] = None         # full SPF record or None
    spf_valid: Optional[bool] = None  # True = present, False = absent
    dmarc: Optional[str] = None       # full DMARC record or None
    dmarc_policy: Optional[str] = None  # 'none' | 'quarantine' | 'reject' | None
    dkim_checked: bool = False        # True when at least one selector was probed

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HTTPInfo:
    url: Optional[str] = None
    body: Optional[str] = None
    status: Optional[int] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    cdn: List[str] = field(default_factory=list)
    redirects_to: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    sensitive_paths: List[Tuple[str, int]] = field(default_factory=list)
    # New fields for enhanced pentest checks
    cookie_issues: List[str] = field(default_factory=list)   # missing Secure/HttpOnly/SameSite
    http_methods: List[str] = field(default_factory=list)    # dangerous methods confirmed open
    is_api_endpoint: bool = False                             # True when response is JSON/API
    js_secrets: List[Dict[str, str]] = field(default_factory=list)  # Secrets found in JS
    js_routes: List[str] = field(default_factory=list)              # Routes found in JS
    api_endpoints: List[Dict[str, str]] = field(default_factory=list) # Swagger/GraphQL endpoints
    # OAuth / session analysis
    flask_session_data: Optional[Dict[str, Any]] = None      # Decoded Flask session contents
    oauth_endpoints: List[Dict[str, str]] = field(default_factory=list)  # OAuth paths found + status
    werkzeug_dos_confirmed: bool = False                     # CVE-2023-46136 DoS trigger confirmed

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("body", None)
        d.pop("headers", None)
        d.pop("response_snippet", None)
        return d


@dataclass
class TLSInfo:
    issuer: Optional[str] = None
    organization: Optional[str] = None
    valid: Optional[bool] = None
    san: List[str] = field(default_factory=list)
    expiration: Optional[str] = None
    version: Optional[str] = None     # e.g. "TLSv1.3", "TLSv1.1"
    cipher: Optional[str] = None      # negotiated cipher suite name

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ASNInfo:
    number: Optional[str] = None
    organization: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Impact:
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str
    evidence: str
    cvss_score: float = 0.0
    cvss_vector: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceExposure:
    """Protocol-aware evidence collected from an externally reachable port."""

    port: int
    kind: str
    protocol: Optional[str] = None
    reachable: bool = True
    status: Optional[int] = None
    server: Optional[str] = None
    tls_supported: Optional[bool] = None
    auth_required: Optional[bool] = None
    auth_method: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HostResult:
    host: str
    dns: DNSInfo = field(default_factory=DNSInfo)
    http: HTTPInfo = field(default_factory=HTTPInfo)
    ports: List[Tuple[int, str]] = field(default_factory=list)
    leaks: List[Tuple[str, str]] = field(default_factory=list)  # (ip, message)
    tls: Optional[TLSInfo] = None
    asn: Optional[ASNInfo] = None
    reverse_dns: Optional[str] = None
    classification: str = "UNKNOWN"
    confidence: int = 0
    time_elapsed: str = "0.00s"
    impacts: List[Impact] = field(default_factory=list)
    services: List[ServiceExposure] = field(default_factory=list)
    # Domain-level email security (populated only for root domains)
    email_security: Optional[EmailSecurityInfo] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "dns": self.dns.to_dict(),
            "http": self.http.to_dict(),
            "ports": self.ports,
            "leaks": self.leaks,
            "time_elapsed": self.time_elapsed,
            "tls": self.tls.to_dict() if self.tls else None,
            "asn": self.asn.to_dict() if self.asn else None,
            "reverse_dns": self.reverse_dns,
            "classification": self.classification,
            "confidence": self.confidence,
            "impacts": [i.to_dict() for i in self.impacts],
            "services": [service.to_dict() for service in self.services],
            "email_security": self.email_security.to_dict() if self.email_security else None,
        }
