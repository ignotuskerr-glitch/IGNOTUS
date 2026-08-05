"""Adapters for real, non-destructive validators installed in Kali WSL."""

from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from core.models import Impact

_SAFE_HOST = re.compile(r"^[A-Za-z0-9._:-]+$")


def _wsl_available() -> bool:
    return shutil.which("wsl.exe") is not None


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["wsl.exe", "-d", "kali-linux", "--", *command],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _script_output(root: ET.Element, script_id: str) -> str:
    values = []
    for script in root.findall(f".//script[@id='{script_id}']"):
        values.append(script.attrib.get("output", ""))
        values.extend(element.attrib.get("key", "") for element in script.iter())
        values.extend((element.text or "") for element in script.iter())
    return "\n".join(value for value in values if value)


def _parse_nmap(xml_text: str, host: str, port: int) -> list[Impact]:
    root = ET.fromstring(xml_text)
    findings = []
    tls_output = _script_output(root, "ssl-enum-ciphers")
    header_output = _script_output(root, "http-security-headers")
    methods_output = _script_output(root, "http-methods")
    ssh_output = _script_output(root, "ssh2-enum-algos")

    deprecated = [version for version in ("TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3") if version in tls_output]
    if deprecated:
        findings.append(Impact(
            severity="HIGH" if any(item.startswith("SSL") for item in deprecated) else "MEDIUM",
            description="Protocolo criptográfico obsoleto confirmado por Nmap",
            evidence=f"Alvo: {host}:{port}\nProtocolos: {', '.join(deprecated)}\nValidador: Nmap ssl-enum-ciphers",
        ))

    if port in (443, 8443) and "HSTS not configured" in header_output:
        findings.append(Impact(
            severity="LOW",
            description="HSTS ausente confirmado por validador externo",
            evidence=f"Alvo: {host}:{port}\nValidador: Nmap http-security-headers\nResultado: HSTS not configured",
        ))

    dangerous = [method for method in ("TRACE", "PUT", "DELETE", "CONNECT") if re.search(rf"\b{method}\b", methods_output)]
    if dangerous:
        findings.append(Impact(
            severity="MEDIUM",
            description="Métodos HTTP potencialmente perigosos anunciados",
            evidence=f"Alvo: {host}:{port}\nMétodos: {', '.join(dangerous)}\nValidador: Nmap http-methods",
        ))

    weak_ssh = [
        algorithm
        for algorithm in (
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "ssh-dss",
            "3des-cbc",
            "aes128-cbc",
            "aes256-cbc",
            "hmac-md5",
        )
        if algorithm in ssh_output
    ]
    if weak_ssh:
        findings.append(Impact(
            severity="MEDIUM",
            description="Algoritmos SSH legados confirmados externamente",
            evidence=f"Alvo: {host}:{port}\nAlgoritmos: {', '.join(weak_ssh)}\nValidador: Nmap ssh2-enum-algos",
        ))
    return findings


def _parse_sslscan(output: str, host: str, port: int) -> list[Impact]:
    findings = []
    weak = []
    for label in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
        if re.search(rf"{re.escape(label)}\s+enabled", output, re.IGNORECASE):
            weak.append(label)
    if weak:
        findings.append(Impact(
            severity="HIGH" if any(item.startswith("SSL") for item in weak) else "MEDIUM",
            description="Protocolo criptográfico obsoleto confirmado por sslscan",
            evidence=f"Alvo: {host}:{port}\nProtocolos: {', '.join(weak)}\nValidador: sslscan",
        ))
    return findings


def run_external_audit(host: str, port: int) -> list[Impact]:
    """Run Nmap and sslscan through WSL at a conservative request rate."""
    if not _wsl_available() or not _SAFE_HOST.fullmatch(host) or not 1 <= port <= 65535:
        return []

    findings = []
    try:
        if port == 22:
            scripts = "banner,ssh2-enum-algos,ssh-auth-methods"
        else:
            scripts = "http-methods,http-security-headers,ssl-cert,ssl-enum-ciphers"
        command = [
            "nmap", "-Pn", "-sT", "-sV", "-T3", "--max-retries", "2",
            "-p", str(port), "--script", scripts,
        ]
        if port != 22:
            command.extend(["--script-args", f"http.host={host}"])
        command.extend(["-oX", "-", host])
        nmap = _run(
            command,
            timeout=240,
        )
        if nmap.returncode == 0 and nmap.stdout.lstrip().startswith("<?xml"):
            findings.extend(_parse_nmap(nmap.stdout, host, port))
    except (OSError, subprocess.TimeoutExpired, ET.ParseError):
        pass

    if port in (443, 8443):
        try:
            sslscan = _run(["sslscan", "--no-colour", f"{host}:{port}"], timeout=180)
            findings.extend(_parse_sslscan(sslscan.stdout + sslscan.stderr, host, port))
        except (OSError, subprocess.TimeoutExpired):
            pass

    unique = {}
    for finding in findings:
        unique[(finding.description, finding.evidence)] = finding
    return list(unique.values())
