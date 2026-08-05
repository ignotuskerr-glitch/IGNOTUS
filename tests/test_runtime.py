import json
from types import SimpleNamespace

from core.engines.go_engine import GoEngine
from core.models import ASNInfo, DNSInfo, HostResult, Impact, ServiceExposure
from core.reporting import build_asset_graph, deduplicate_impacts
from core.runtime import CancellationToken, CheckpointStore, RateLimiter, ScanCancelled


def test_cancellation_token_stops_cooperatively():
    token = CancellationToken(60)
    token.cancel()

    assert token.cancelled
    try:
        token.raise_if_cancelled()
    except ScanCancelled:
        pass
    else:
        raise AssertionError("expected ScanCancelled")


def test_rate_limiter_honors_cancelled_token():
    limiter = RateLimiter(1)
    token = CancellationToken(60)
    limiter.wait(token)
    token.cancel()

    try:
        limiter.wait(token)
    except ScanCancelled:
        pass
    else:
        raise AssertionError("expected ScanCancelled")


def test_checkpoint_round_trip_is_sanitized(tmp_path):
    path = tmp_path / "checkpoint.json"
    result = HostResult(
        host="example.com",
        dns=DNSInfo(ips=["203.0.113.10"]),
        impacts=[Impact("HIGH", "Example", "Evidence", 8.0, "vector")],
        services=[
            ServiceExposure(
                port=5432,
                kind="postgresql",
                auth_required=True,
                auth_method="sasl/scram",
            )
        ],
    )
    result.http.body = "must not be persisted"
    result.http.headers = {"Authorization": "secret"}

    store = CheckpointStore(path, "example.com")
    store.record(result)
    restored = CheckpointStore(path, "example.com").load()

    assert restored["example.com"].dns.ips == ["203.0.113.10"]
    assert restored["example.com"].http.body is None
    assert restored["example.com"].services[0].auth_method == "sasl/scram"
    payload = path.read_text(encoding="utf-8")
    assert "must not be persisted" not in payload
    assert '"Authorization"' not in payload
    assert '"secret"' not in payload


def test_graph_and_deduplication_are_deterministic():
    result = HostResult(
        host="example.com",
        dns=DNSInfo(ips=["203.0.113.10"]),
        asn=ASNInfo(number="AS64500", organization="Example"),
        impacts=[
            Impact("low", "Header missing", "x"),
            Impact("LOW", "Header   missing", "x"),
        ],
    )
    result.impacts = deduplicate_impacts(result.impacts)
    graph = build_asset_graph({result.host: result})

    assert len(result.impacts) == 1
    assert result.impacts[0].severity == "LOW"
    assert {node["kind"] for node in graph["nodes"]} == {"host", "ip", "asn"}


def test_go_engine_parses_jsonl(monkeypatch, tmp_path):
    binary = tmp_path / "ignotus-engine.exe"
    binary.write_bytes(b"placeholder")
    response = {
        "id": "0",
        "host": "example.com",
        "ips": ["203.0.113.10"],
        "cname": "edge.example.net",
        "ports": [{"port": 443, "open": True}],
        "http": {"url": "https://example.com/", "status": 200},
        "duration_ms": 12,
    }

    monkeypatch.setattr(
        "core.engines.go_engine.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(response) + "\n",
            stderr="",
        ),
    )

    results = GoEngine(binary).scan_many(
        ["example.com"],
        [80, 443],
        workers=2,
        rate_limit=5,
        timeout_seconds=30,
    )

    assert results["example.com"].ports == [(443, "")]
    assert results["example.com"].cname == "edge.example.net"
