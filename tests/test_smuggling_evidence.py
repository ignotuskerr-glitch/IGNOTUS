from core import smuggling


def test_http_errors_without_timing_anomaly_are_not_findings(monkeypatch):
    timestamps = iter([value for _ in range(4) for value in (0.0, 0.45)])
    monkeypatch.setattr(smuggling, "_measure_baseline", lambda *a: 0.45)
    monkeypatch.setattr(
        smuggling,
        "_raw_send",
        lambda *a, **k: b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
    )
    monkeypatch.setattr(smuggling.time, "time", lambda: next(timestamps))

    assert smuggling.detect_smuggling("example.test", port=443) == []


def test_timing_anomaly_must_repeat(monkeypatch):
    timestamps = iter([0.0, 5.0, 10.0, 10.2, 20.0, 20.2, 30.0, 30.2, 40.0, 40.2])
    monkeypatch.setattr(smuggling, "_measure_baseline", lambda *a: 0.5)
    monkeypatch.setattr(
        smuggling,
        "_raw_send",
        lambda *a, **k: b"HTTP/1.1 400 Bad Request\r\n\r\n",
    )
    monkeypatch.setattr(smuggling.time, "time", lambda: next(timestamps))

    assert smuggling.detect_smuggling("example.test", port=443) == []
