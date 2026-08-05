"""
ingotus/core/tls.py

TLS/SSL certificate analysis + protocol version and cipher detection.
"""

import socket
import ssl
from datetime import datetime
from typing import Optional, Tuple

from core.config import TIMEOUT, TLS_DEFAULT_PORT, TLS_CERT_DATE_FORMAT, TLS_UNKNOWN_ISSUER
from core.models import TLSInfo


def _parse_cert_field(field_tuples, target_key: str) -> Optional[str]:
    """Extract a named field (e.g. CN, O) from a certificate subject/issuer tuple."""
    try:
        for item in field_tuples:
            for key, value in item:
                if key == target_key:
                    return value
    except Exception:
        pass
    return None


def _connect_tls(
    hostname: str,
    port: int,
    ctx: ssl.SSLContext,
) -> Tuple[Optional[ssl.SSLSocket], bool]:
    """
    Attempt a TLS connection and return (ssock, success).
    Caller is responsible for closing ssock inside a context manager.
    """
    try:
        raw = socket.create_connection((hostname, port), timeout=TIMEOUT)
        ssock = ctx.wrap_socket(raw, server_hostname=hostname)
        return ssock, True
    except Exception:
        return None, False


def analyze_tls(hostname: str, port: int = TLS_DEFAULT_PORT) -> Optional[TLSInfo]:
    """
    Connect to the host and retrieve TLS/SSL certificate details plus the
    negotiated protocol version and cipher suite.

    Strategy:
      1. Verified connection (checks cert validity).
      2. If that fails, fall back to an unverified connection so we can still
         capture the protocol version even for self-signed / mismatched certs.
    """
    tls_info = TLSInfo()

    # ── Attempt 1: Verified connection ────────────────────────────────────────
    try:
        ctx         = ssl.create_default_context()
        ctx.timeout = TIMEOUT

        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_info.valid   = True
                tls_info.version = ssock.version()
                cipher           = ssock.cipher()
                tls_info.cipher  = cipher[0] if cipher else None

                if cert:
                    tls_info.issuer       = _parse_cert_field(cert.get("issuer", ()), "commonName")
                    tls_info.organization = _parse_cert_field(cert.get("subject", ()), "organizationName")
                    tls_info.expiration   = cert.get("notAfter")

                    tls_info.san = [
                        san_val
                        for san_type, san_val in cert.get("subjectAltName", ())
                        if san_type == "DNS"
                    ]

                    # Validate expiration date using the format from config
                    if tls_info.expiration:
                        try:
                            exp_date = datetime.strptime(tls_info.expiration, TLS_CERT_DATE_FORMAT)
                            if exp_date < datetime.utcnow():
                                tls_info.valid = False
                        except Exception:
                            pass

                return tls_info

    except Exception:
        pass

    # ── Attempt 2: Unverified connection (self-signed / wrong hostname) ───────
    tls_info.valid = False
    try:
        unverified_ctx                = ssl.create_default_context()
        unverified_ctx.check_hostname = False
        unverified_ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_info.issuer  = TLS_UNKNOWN_ISSUER
                tls_info.version = ssock.version()
                cipher           = ssock.cipher()
                tls_info.cipher  = cipher[0] if cipher else None
                return tls_info

    except Exception:
        return None
