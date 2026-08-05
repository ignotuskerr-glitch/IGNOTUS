from core.redaction import REDACTED, redact_headers, redact_text


def test_redacts_sensitive_headers():
    result = redact_headers({
        "Authorization": "Bearer top-secret",
        "Set-Cookie": "session=abc",
        "Server": "nginx",
    })
    assert result["Authorization"] == REDACTED
    assert result["Set-Cookie"] == REDACTED
    assert result["Server"] == "nginx"


def test_redacts_common_assignments_and_aws_keys():
    text = "password=supersecret123 api_key='abcdef1234567890' AKIAABCDEFGHIJKLMNOP"
    result = redact_text(text)
    assert "supersecret123" not in result
    assert "abcdef1234567890" not in result
    assert "AKIAABCDEFGHIJKLMNOP" not in result
