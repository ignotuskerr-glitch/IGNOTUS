"""Central redaction for logs, evidence and reports."""

import re
from typing import Mapping


REDACTED = "[REDACTED]"
_SENSITIVE_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token",
}
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
    r"(\s*[=:]\s*)(['\"]?)([^\s,'\";]{6,})(['\"]?)"
)


def redact_text(value: object) -> str:
    text = str(value)
    text = _JWT.sub(REDACTED, text)
    text = _AWS_ACCESS_KEY.sub(REDACTED, text)
    return _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


def redact_headers(headers: Mapping[str, object]) -> dict[str, str]:
    return {
        str(name): REDACTED if str(name).lower() in _SENSITIVE_HEADER_NAMES else redact_text(value)
        for name, value in headers.items()
    }
