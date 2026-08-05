from core import classifier
from core.models import DNSInfo, HostResult


def _neutralize_external_checks(monkeypatch):
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
    monkeypatch.setattr(classifier, "probe_cors", lambda *a, **k: (False, False, None))
    monkeypatch.setattr("core.cloud_storage.audit_cloud_storage", lambda *a, **k: [])


def test_cors_wildcard_without_credentials_is_informational(monkeypatch):
    _neutralize_external_checks(monkeypatch)
    result = HostResult(host="public.example", dns=DNSInfo(ips=["203.0.113.10"]))
    result.http.status = 200
    result.http.headers = {"access-control-allow-origin": "*"}

    classifier.classify_and_validate(result)

    cors = next(impact for impact in result.impacts if "CORS" in impact.description)
    assert cors.severity == "INFO"
    assert cors.cvss_score == 0.0
