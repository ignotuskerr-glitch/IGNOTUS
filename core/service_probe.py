"""Safe protocol-aware probes for services exposed on non-standard ports."""

from __future__ import annotations

import socket
import ssl
import struct
from collections.abc import Iterable

import requests

from core.config import PROBE_TIMEOUT, USER_AGENT
from core.models import ServiceExposure

ALTERNATE_WEB_PORTS = frozenset({3000, 3001, 3005, 5000, 8000, 8080, 8443, 8888})

_PG_AUTH_METHODS = {
    0: "trust/accepted",
    2: "kerberos-v5",
    3: "cleartext-password",
    5: "md5-password",
    6: "scm-credential",
    7: "gss",
    9: "sspi",
    10: "sasl/scram",
    11: "sasl-continue",
    12: "sasl-final",
}


def probe_alternate_http(
    host: str,
    port: int,
    *,
    proxy: str | None = None,
) -> ServiceExposure | None:
    """Try HTTPS and HTTP with one bounded GET and no redirect following."""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    for protocol in ("https", "http"):
        try:
            response = requests.get(
                f"{protocol}://{host}:{port}/",
                headers={"User-Agent": USER_AGENT},
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
                stream=True,
            )
            headers = {key.lower(): value for key, value in response.headers.items()}
            exposure = ServiceExposure(
                port=port,
                kind="http",
                protocol=protocol,
                status=response.status_code,
                server=headers.get("server"),
                tls_supported=protocol == "https",
                headers=headers,
                detail=f"{protocol}://{host}:{port}/ returned HTTP {response.status_code}",
            )
            response.close()
            return exposure
        except requests.RequestException:
            continue
    return None


def _postgres_startup(user: str = "postgres", database: str = "postgres") -> bytes:
    parameters = (
        b"user\x00" + user.encode("utf-8") + b"\x00"
        b"database\x00" + database.encode("utf-8") + b"\x00"
        b"application_name\x00ignotus-probe\x00\x00"
    )
    return struct.pack("!II", len(parameters) + 8, 196608) + parameters


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


def probe_postgresql(host: str, port: int = 5432) -> ServiceExposure | None:
    """Identify PostgreSQL TLS/auth posture without submitting a password."""
    try:
        connection = socket.create_connection((host, port), timeout=PROBE_TIMEOUT)
    except OSError:
        return None

    connection.settimeout(PROBE_TIMEOUT)
    tls_supported = False
    try:
        connection.sendall(struct.pack("!II", 8, 80877103))
        ssl_response = _recv_exact(connection, 1)
        if ssl_response == b"S":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = context.wrap_socket(connection, server_hostname=host)
            connection.settimeout(PROBE_TIMEOUT)
            tls_supported = True
        elif ssl_response != b"N":
            return ServiceExposure(
                port=port,
                kind="postgresql",
                protocol="postgresql",
                tls_supported=False,
                detail="TCP reachable; unexpected PostgreSQL SSL negotiation response",
            )

        connection.sendall(_postgres_startup())
        message_type = _recv_exact(connection, 1)
        message_length = struct.unpack("!I", _recv_exact(connection, 4))[0]
        if message_length < 4 or message_length > 1_048_576:
            raise ValueError("invalid PostgreSQL message length")
        payload = _recv_exact(connection, message_length - 4)

        if message_type == b"R" and len(payload) >= 4:
            auth_code = struct.unpack("!I", payload[:4])[0]
            return ServiceExposure(
                port=port,
                kind="postgresql",
                protocol="postgresql",
                tls_supported=tls_supported,
                auth_required=auth_code != 0,
                auth_method=_PG_AUTH_METHODS.get(auth_code, f"method-{auth_code}"),
                detail="Authentication request observed; no password was submitted",
            )
        if message_type == b"E":
            return ServiceExposure(
                port=port,
                kind="postgresql",
                protocol="postgresql",
                tls_supported=tls_supported,
                auth_required=True,
                auth_method="hba-rejected",
                detail="PostgreSQL rejected the startup request before authentication",
            )
        return ServiceExposure(
            port=port,
            kind="postgresql",
            protocol="postgresql",
            tls_supported=tls_supported,
            auth_required=None,
            detail=f"PostgreSQL message type {message_type!r} observed",
        )
    except (OSError, ValueError, ConnectionError, ssl.SSLError):
        return ServiceExposure(
            port=port,
            kind="postgresql",
            protocol="postgresql",
            tls_supported=tls_supported,
            detail="TCP reachable; protocol probe did not complete",
        )
    finally:
        try:
            connection.close()
        except OSError:
            pass


def probe_service_exposures(
    host: str,
    open_ports: Iterable[tuple[int, str]],
    *,
    proxy: str | None = None,
) -> list[ServiceExposure]:
    """Probe only recognized service ports already confirmed open."""
    port_numbers = {port for port, _banner in open_ports}
    exposures: list[ServiceExposure] = []
    if 5432 in port_numbers:
        postgres = probe_postgresql(host)
        if postgres:
            exposures.append(postgres)
    for port in sorted(port_numbers & ALTERNATE_WEB_PORTS):
        web = probe_alternate_http(host, port, proxy=proxy)
        if web:
            exposures.append(web)
    return exposures
