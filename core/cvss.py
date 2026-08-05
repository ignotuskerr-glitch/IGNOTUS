"""
ingotus/core/cvss.py

Calculates CVSS 3.1 base score and vector string for identified security impacts.
Allows bug bounty reports to include standardized CVSS metrics.
"""

from typing import Tuple, Dict

# CVSS 3.1 Base Metrics Mappings per Impact Category
# Format: (Score, VectorString)
CVSS_LOOKUP: Dict[str, Tuple[float, str]] = {
    # Subdomain Takeover
    "SUBDOMAIN_TAKEOVER": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N"),
    
    # WAF / Origin IP Exposure
    "WAF_BYPASS_CRITICAL": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "ORIGIN_IP_HIGH": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    
    # CORS
    "CORS_REFLECTED_CREDENTIALS": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "CORS_REFLECTED_NO_CREDS": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    
    # Secrets / Data Exposure
    "SECRET_CRITICAL": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SECRET_HIGH": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "SENSITIVE_FILE_EXPOSURE": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    
    # API Discovery
    "GRAPHQL_INTROSPECTION": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "SWAGGER_EXPOSED": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    
    # HTTP Methods & Session Security
    "HTTP_TRACE_ENABLED": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "HTTP_DANGEROUS_METHOD": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    "COOKIE_MISSING_FLAGS": (5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    
    # Ports & TLS
    "CRITICAL_PORT_OPEN": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "TLS_DEPRECATED": (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "SSL_INVALID": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    
    # Email Security
    "EMAIL_NO_SPF": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    "EMAIL_NO_DMARC": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    "EMAIL_DMARC_NONE": (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),

    # OAuth / Session
    "FLASK_SESSION_EXPOSED":  (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "OAUTH_CALLBACK_CRASH":   (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L"),

    # CVEs
    "CVE_2023_46136":         (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
}


def get_cvss(impact_key: str) -> Tuple[float, str]:
    """
    Returns (score, vector_string) for a given impact key.
    Defaults to (0.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N') if unknown.
    """
    return CVSS_LOOKUP.get(
        impact_key,
        (0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    )
