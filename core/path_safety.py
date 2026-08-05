"""Helpers for safely writing untrusted source-map paths."""

import re
from pathlib import Path, PurePosixPath
from typing import Optional


_SCHEME_PREFIX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?://)?")
_WINDOWS_DRIVE = re.compile(r"^[a-zA-Z]:")


def safe_output_path(output_dir: str, untrusted_path: str) -> Optional[Path]:
    """Return a path confined to output_dir, or None when it is unsafe."""
    if not isinstance(untrusted_path, str) or not untrusted_path.strip():
        return None

    value = untrusted_path.strip().replace("\\", "/")
    value = re.sub(r"^(webpack|vite|parcel|turbopack):///?", "", value)
    value = value.split("?", 1)[0].split("#", 1)[0]
    if value.startswith(("/", "//")) or _WINDOWS_DRIVE.match(value):
        return None
    if _SCHEME_PREFIX.match(value):
        return None

    parts = PurePosixPath(value).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        return None

    root = Path(output_dir).resolve()
    candidate = root.joinpath(*parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate
