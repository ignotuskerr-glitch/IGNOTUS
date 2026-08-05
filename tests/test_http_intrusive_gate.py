from core import http


class _FakeResponse:
    status_code = 204
    headers = {}
    text = ""
    history = []

    def __init__(self, url):
        self.url = url


def test_werkzeug_probe_is_not_called_without_authorization(monkeypatch):
    called = False

    def fake_probe(*args, **kwargs):
        nonlocal called
        called = True
        return True

    monkeypatch.setattr(http, "probe_werkzeug_dos", fake_probe)

    result = http._probe_werkzeug_dos_if_authorized(
        False,
        "https://example.com",
        {"User-Agent": "test"},
        ["/callback"],
    )

    assert result is False
    assert called is False


def test_werkzeug_probe_runs_when_explicitly_authorized(monkeypatch):
    calls = []

    def fake_probe(base_url, headers, post_paths, cookies, proxies):
        calls.append((base_url, headers, post_paths, cookies, proxies))
        return True

    monkeypatch.setattr(http, "probe_werkzeug_dos", fake_probe)

    result = http._probe_werkzeug_dos_if_authorized(
        True,
        "https://example.com",
        {"User-Agent": "test"},
        ["/callback"],
        cookies={"session": "authorized"},
        proxies={"https": "http://127.0.0.1:8080"},
    )

    assert result is True
    assert calls == [
        (
            "https://example.com",
            {"User-Agent": "test"},
            ["/callback"],
            {"session": "authorized"},
            {"https": "http://127.0.0.1:8080"},
        )
    ]


def test_authenticated_context_reaches_http_and_api_probes(monkeypatch):
    request_kwargs = []
    api_calls = []

    def fake_get(url, **kwargs):
        request_kwargs.append(kwargs)
        return _FakeResponse(url)

    def fake_graphql(base_url, **kwargs):
        api_calls.append(("graphql", kwargs))
        return None

    def fake_swagger(base_url, **kwargs):
        api_calls.append(("swagger", kwargs))
        return []

    monkeypatch.setattr(http.requests, "get", fake_get)
    monkeypatch.setattr(http, "probe_graphql_introspection", fake_graphql)
    monkeypatch.setattr(http, "probe_swagger_endpoints", fake_swagger)
    monkeypatch.setattr(http, "probe_http_methods", lambda *args, **kwargs: [])

    cookies = {"session": "authorized"}
    headers = {"Authorization": "Bearer authorized"}
    result = http.get_http_info(
        "example.com",
        auth_cookies=cookies,
        auth_headers=headers,
    )

    assert result.status == 204
    assert request_kwargs
    assert all(call["cookies"] == cookies for call in request_kwargs)
    assert all(call["headers"]["Authorization"] == headers["Authorization"] for call in request_kwargs)
    assert api_calls == [
        (
            "graphql",
            {"proxy": None, "auth_cookies": cookies, "auth_headers": headers},
        ),
        (
            "swagger",
            {"proxy": None, "auth_cookies": cookies, "auth_headers": headers},
        ),
    ]
