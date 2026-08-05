"""Operational asset exposure catalog.

The catalog data lives in ``config/assets/asset_catalog.json`` so the scanner
logic stays small and the path inventory can be reviewed/versioned separately.
Only safe GET-oriented discovery paths are accepted; response validators decide
whether a 200 response is a real asset and never treat a route name alone as
impact.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Any

from core.impact_gate import is_placeholder


CATALOG_PATH = Path(__file__).resolve().parent.parent / "config" / "assets" / "asset_catalog.json"
ALLOWED_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _text(value: str) -> str:
    return value if isinstance(value, str) else ""


def _has_any(text: str, needles: tuple[str, ...], casefold: bool = True) -> bool:
    value = text.casefold() if casefold else text
    return any(needle.casefold() in value for needle in needles)


def _validate_none(_text_value: str) -> bool:
    return True


def _validate_git(text: str) -> bool:
    return _has_any(text, ("ref:", "[core]", "gitdir", "HEAD"))


def _validate_env(text: str) -> bool:
    return _has_any(text, ("SECRET", "KEY", "TOKEN", "PASSWORD", "DATABASE", "API_"))


def _validate_api_schema(text: str) -> bool:
    return _has_any(text, ("swagger", "openapi", '"paths"', "__schema", "queryType"))


def _validate_database_dump(text: str) -> bool:
    return _has_any(text, ("create table", "insert into", "postgresql", "mysql", "sqlite"))


def _validate_private_key(text: str) -> bool:
    return _has_any(text, ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN CERTIFICATE"), casefold=False)


def _validate_source_map(text: str) -> bool:
    return '"version"' in text and '"sources"' in text


def _validate_cloud(text: str) -> bool:
    return _has_any(text, ("aws_access_key_id", "aws_secret_access_key", "AKIA", "BEGIN"))


def _validate_cloud_bucket(text: str) -> bool:
    return _has_any(text, ("<ListBucketResult>", "ListBucketResult", "BucketName", "Contents"))


def _validate_graphql(text: str) -> bool:
    return _has_any(text, ("graphiql", "graphql playground", "altair", "__schema"))


VALIDATORS: dict[str, Callable[[str], bool]] = {
    "none": _validate_none,
    "git": _validate_git,
    "env": _validate_env,
    "api_schema": _validate_api_schema,
    "database_dump": _validate_database_dump,
    "private_key": _validate_private_key,
    "source_map": _validate_source_map,
    "cloud": _validate_cloud,
    "cloud_bucket": _validate_cloud_bucket,
    "graphql": _validate_graphql,
}


def _safe_path(value: Any) -> str | None:
    path = _text(value).strip()
    if not path or not path.startswith("/") or _CONTROL.search(path):
        return None
    if ".." in path.replace("?", "/").split("/"):
        return None
    # Placeholder-looking paths have no value in a production inventory.
    if is_placeholder(path) and path not in {"/.env", "/.env.local", "/.env.production"}:
        return None
    return path


def load_asset_categories(path: Path = CATALOG_PATH) -> dict[str, dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 2 or payload.get("policy") != "strict-impact-v2":
        raise ValueError("asset catalog schema/policy is not strict-impact-v2")
    categories: dict[str, dict] = {}
    for raw in payload.get("categories", []):
        name = _text(raw.get("name")).strip()
        severity = _text(raw.get("severity")).upper()
        validator_name = _text(raw.get("validator", "none"))
        if not name or severity not in ALLOWED_SEVERITIES or validator_name not in VALIDATORS:
            raise ValueError(f"invalid asset category: {name or '<unnamed>'}")
        paths: list[str] = []
        for item in raw.get("paths", []):
            safe = _safe_path(item)
            if safe and safe not in paths:
                paths.append(safe)
        if not paths:
            continue
        categories[name] = {
            "severity": severity,
            "desc": _text(raw.get("desc")) or name,
            "paths": paths,
            "validators": [VALIDATORS[validator_name]],
            "validator_name": validator_name,
            "catalog_schema": payload["schema_version"],
        }
    if len(categories) < 10 or sum(len(item["paths"]) for item in categories.values()) < 1000:
        raise ValueError("asset catalog is unexpectedly small")
    return categories


ASSET_CATEGORIES = load_asset_categories()

