import struct
from types import SimpleNamespace

from core import service_probe
from core.models import ASNInfo, DNSInfo, HostResult, ServiceExposure
from core import classifier


class _FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []

    def settimeout(self, _timeout):
        pass

    def sendall(self, payload):
        self.sent.append(payload)

    def recv(self, _size):
        return self.chunks.pop(0)

    def close(self):
        pass


def test_postgresql_probe_confirms_scram_without_sending_password(monkeypatch):
    connection = _FakeSocket(
        [b"S", b"R", struct.pack("!I", 8), struct.pack("!I", 10)]
    )
    monkeypatch.setattr(
        service_probe.socket,
        "create_connection",
        lambda *args, **kwargs: connection,
    )
    context = SimpleNamespace(check_hostname=True, verify_mode=None)
    context.wrap_socket = lambda sock, server_hostname: sock
    monkeypatch.setattr(service_probe.ssl, "create_default_context", lambda: context)

    result = service_probe.probe_postgresql("203.0.113.10")

    assert result is not None
    assert result.reachable
    assert result.tls_supported
    assert result.auth_required
    assert result.auth_method == "sasl/scram"
    assert len(connection.sent) == 2
    assert b"password" not in b"".join(connection.sent).lower()


def test_alternate_https_probe_captures_status_and_rate_limit(monkeypatch):
    response = SimpleNamespace(
        status_code=404,
        headers={"Server": "node", "RateLimit-Policy": "200;w=900"},
        close=lambda: None,
    )
    monkeypatch.setattr(service_probe.requests, "get", lambda *a, **k: response)

    result = service_probe.probe_alternate_http("203.0.113.10", 3005)

    assert result is not None
    assert result.protocol == "https"
    assert result.status == 404
    assert result.headers["ratelimit-policy"] == "200;w=900"


def test_classifier_correlates_failed_proxy_with_alternate_service(monkeypatch):
    result = HostResult(
        host="203.0.113.10",
        dns=DNSInfo(ips=["203.0.113.10"]),
        asn=ASNInfo(number="AS64500", organization="Example"),
        ports=[(3005, ""), (5432, "")],
        services=[
            ServiceExposure(
                port=3005,
                kind="http",
                protocol="https",
                status=404,
                tls_supported=True,
                headers={"ratelimit-policy": "200;w=900"},
            ),
            ServiceExposure(
                port=5432,
                kind="postgresql",
                protocol="postgresql",
                tls_supported=True,
                auth_required=True,
                auth_method="sasl/scram",
            ),
        ],
    )
    result.http.status = 502
    monkeypatch.setattr(classifier.fingerprint_engine, "detect_cdn", lambda *a: [])
    monkeypatch.setattr(classifier.fingerprint_engine, "detect_waf", lambda *a: [])
    monkeypatch.setattr(classifier.fingerprint_engine, "detect_cloud", lambda *a: None)
    monkeypatch.setattr(classifier.fingerprint_engine, "check_takeover", lambda *a: None)
    monkeypatch.setattr(
        classifier,
        "probe_origin_bypass",
        lambda *a, **k: (False, None, None, False, ""),
    )
    monkeypatch.setattr(classifier, "fetch_cves_for_tech", lambda *a, **k: [])
    monkeypatch.setattr("core.cloud_storage.audit_cloud_storage", lambda *a, **k: [])

    classifier.classify_and_validate(result)

    descriptions = {impact.description: impact for impact in result.impacts}
    assert descriptions["PostgreSQL acessível publicamente"].severity == "MEDIUM"
    proxy = descriptions[
        "Serviço de aplicação acessível fora do reverse proxy enquanto o upstream principal falha"
    ]
    assert proxy.severity == "MEDIUM"
    assert "200;w=900" in proxy.evidence


def test_host_result_serializes_protocol_aware_services():
    result = HostResult(
        host="example.com",
        services=[ServiceExposure(port=5432, kind="postgresql", auth_required=True)],
    )
    assert result.to_dict()["services"][0]["auth_required"] is True
