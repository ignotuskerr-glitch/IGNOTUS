import socket
from typing import List, Tuple
from core.config import BANNER_GRAB_TIMEOUT, BANNER_RECV_SIZE, BANNER_TRUNCATE_LEN, PORT_CONNECT_TIMEOUT
from core.fingerprint import fingerprint_engine


def grab_banner(s: socket.socket, port: int) -> str:
    """
    Attempt to grab a service banner on an already-connected socket.
    Probe behaviour (payload, action) is loaded from fingerprints.json.
    """
    try:
        s.settimeout(BANNER_GRAB_TIMEOUT)
        probes = fingerprint_engine.banner_probes

        for probe in probes:
            if port not in probe.get("ports", []):
                continue

            action       = probe.get("action", "")
            send_payload = probe.get("send", "")

            if action == "static":
                return probe.get("static_banner", "Active")

            if send_payload:
                s.sendall(send_payload.encode("utf-8", errors="ignore"))

            if action == "first_line":
                data = s.recv(BANNER_RECV_SIZE)
                return data.decode("utf-8", errors="ignore").split("\r\n")[0].strip()

            if action == "recv_immediate":
                data = s.recv(BANNER_RECV_SIZE)
                return data.decode("utf-8", errors="ignore").strip()

            # Default: read and return
            data = s.recv(BANNER_RECV_SIZE)
            return data.decode("utf-8", errors="ignore").strip()[:BANNER_TRUNCATE_LEN]

        # Generic fallback probe — sends CRLF and reads whatever the service sends back
        s.sendall(b"\r\n")
        data = s.recv(BANNER_RECV_SIZE)
        return data.decode("utf-8", errors="ignore").strip()[:BANNER_TRUNCATE_LEN]

    except Exception:
        return ""


def scan_ports(host: str, ports: List[int]) -> List[Tuple[int, str]]:
    """
    TCP connect scan on a list of ports.
    Returns [(port, banner), ...] for open ports only.
    """
    open_ports: List[Tuple[int, str]] = []

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return []

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PORT_CONNECT_TIMEOUT)
        try:
            if s.connect_ex((ip, port)) == 0:
                banner = grab_banner(s, port)
                open_ports.append((port, banner))
        except Exception:
            pass
        finally:
            s.close()

    # ── Port Spoofing / Catch-All / SOCKS Proxy Fake Connection Mitigation ─────
    # Real servers rarely expose FTP, SSH, Telnet, SMTP, POP3, MySQL, Postgres,
    # Redis, MongoDB, and Elasticsearch all open on the same IP. If a firewall or
    # local proxy intercepts outbound connections and returns synthetic SYN-ACKs,
    # we filter out silent sensitive ports to prevent critical false positives.
    sensitive_ports = fingerprint_engine.sensitive_ports
    open_sensitive   = [p for p in open_ports if p[0] in sensitive_ports]

    if len(open_sensitive) > 3:
        # Check how many of the open sensitive ports returned no banner
        silent_sensitive = [p for p in open_sensitive if not p[1] or p[1].strip() in ("", "—")]
        # If > 70% of open sensitive ports are completely silent, treat as port spoofing
        if len(silent_sensitive) / len(open_sensitive) > 0.7:
            # Discard silent sensitive ports; keep only the ones that returned a real banner
            silent_port_numbers = {s[0] for s in silent_sensitive}
            open_ports = [p for p in open_ports if p[0] not in silent_port_numbers]

    return open_ports
