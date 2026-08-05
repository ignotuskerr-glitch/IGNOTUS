from core import classifier
from core.models import ASNInfo, DNSInfo, HostResult, TLSInfo


def test_cdn_dns_edges_are_not_reported_as_unconfirmed_origin(monkeypatch):
    result = HostResult(
        host="example.vercel.app",
        dns=DNSInfo(ips=["203.0.113.10"]),
        asn=ASNInfo(number="AS64500", organization="Ambiguous Transit Provider"),
    )
    result.http.status = 200
    result.http.headers = {"server": "Vercel"}

    monkeypatch.setattr(
        classifier.fingerprint_engine, "detect_cdn", lambda *a: ["Vercel"]
    )
    monkeypatch.setattr(classifier.fingerprint_engine, "detect_waf", lambda *a: [])
    monkeypatch.setattr(classifier.fingerprint_engine, "detect_cloud", lambda *a: None)
    monkeypatch.setattr(
        classifier.fingerprint_engine, "check_takeover", lambda *a: None
    )
    monkeypatch.setattr(
        classifier,
        "probe_origin_bypass",
        lambda *a, **k: (False, None, None, False, ""),
    )
    monkeypatch.setattr(classifier, "fetch_cves_for_tech", lambda *a, **k: [])
    monkeypatch.setattr("core.cloud_storage.audit_cloud_storage", lambda *a, **k: [])

    classifier.classify_and_validate(result)

    assert result.classification == "CDN"
    assert not result.leaks
    assert not any(
        "origem" in impact.description.casefold() for impact in result.impacts
    )


def test_known_cdn_edge_is_never_promoted_to_origin(monkeypatch):
    result = HostResult(
        host="edge.example",
        dns=DNSInfo(ips=["104.16.10.20"]),
        asn=ASNInfo(organization="Cloudflare, Inc."),
    )
    result.http.status = 200
    result.http.headers = {"server": "cloudflare"}

    monkeypatch.setattr(
        classifier.fingerprint_engine, "detect_cdn", lambda *a: ["Cloudflare"]
    )
    monkeypatch.setattr(classifier.fingerprint_engine, "detect_waf", lambda *a: [])
    monkeypatch.setattr(classifier.fingerprint_engine, "detect_cloud", lambda *a: None)
    monkeypatch.setattr(classifier.fingerprint_engine, "check_takeover", lambda *a: None)
    monkeypatch.setattr(
        classifier,
        "probe_origin_bypass",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("edge must not be probed")),
    )
    monkeypatch.setattr(classifier, "fetch_cves_for_tech", lambda *a, **k: [])
    monkeypatch.setattr("core.cloud_storage.audit_cloud_storage", lambda *a, **k: [])

    classifier.classify_and_validate(result)

    assert not result.leaks
    assert not any("bypass" in impact.description.casefold() for impact in result.impacts)


def test_ip_inventory_does_not_claim_domain_or_tls_findings(monkeypatch):
    result = HostResult(
        host="203.0.113.10",
        dns=DNSInfo(ips=["203.0.113.10"]),
        tls=TLSInfo(valid=False),
        ports=[(22, "SSH-2.0-OpenSSH_8.4"), (80, "")],
    )
    result.http.status = 502

    monkeypatch.setattr(classifier.fingerprint_engine, "detect_cdn", lambda *a: [])
    monkeypatch.setattr(classifier.fingerprint_engine, "detect_waf", lambda *a: [])
    monkeypatch.setattr(classifier.fingerprint_engine, "detect_cloud", lambda *a: None)
    monkeypatch.setattr(
        classifier.fingerprint_engine, "check_takeover", lambda *a: None
    )
    monkeypatch.setattr(
        classifier,
        "probe_origin_bypass",
        lambda *a, **k: (False, None, None, False, ""),
    )
    monkeypatch.setattr(classifier, "fetch_cves_for_tech", lambda *a, **k: [])
    monkeypatch.setattr("core.cloud_storage.audit_cloud_storage", lambda *a, **k: [])

    classifier.classify_and_validate(result)

    descriptions = [impact.description.casefold() for impact in result.impacts]
    assert not any("certificado" in description for description in descriptions)
    assert not any(
        "tráfego http inseguro" in description for description in descriptions
    )
    ssh = next(impact for impact in result.impacts if "22" in impact.description)
    assert ssh.severity == "INFO"
    assert ssh.cvss_score == 0.0
    assert ssh.cvss_vector == ""
    availability = next(
        impact
        for impact in result.impacts
        if "upstream" in impact.description.casefold()
    )
    assert availability.severity == "LOW"
    assert availability.cvss_score == 0.0
