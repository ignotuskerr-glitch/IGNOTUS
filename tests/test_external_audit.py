from core.external_audit import _parse_nmap, _parse_sslscan


def test_nmap_parser_reports_confirmed_hsts_and_deprecated_tls():
    xml = """<?xml version='1.0'?>
    <nmaprun><host><ports><port protocol='tcp' portid='443'>
      <script id='http-security-headers' output='HSTS not configured in HTTPS Server'/>
      <script id='ssl-enum-ciphers' output='TLSv1.0: enabled&#10;TLSv1.2: enabled'/>
    </port></ports></host></nmaprun>"""

    findings = _parse_nmap(xml, "example.test", 443)

    assert any("HSTS" in item.description for item in findings)
    assert any("obsoleto" in item.description for item in findings)


def test_sslscan_disabled_protocol_is_not_a_finding():
    assert _parse_sslscan("TLSv1.0 disabled\nTLSv1.2 enabled", "example.test", 443) == []


def test_nmap_parser_reports_legacy_ssh_algorithms():
    xml = """<?xml version='1.0'?>
    <nmaprun><host><ports><port protocol='tcp' portid='22'>
      <script id='ssh2-enum-algos' output='kex_algorithms: diffie-hellman-group1-sha1'/>
    </port></ports></host></nmaprun>"""

    findings = _parse_nmap(xml, "203.0.113.10", 22)

    assert len(findings) == 1
    assert "SSH" in findings[0].description
