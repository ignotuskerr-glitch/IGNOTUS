import os
import json

# ── Base paths ─────────────────────────────────────────────────────────────────
BASE_DIR               = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── File and directory paths ───────────────────────────────────────────────────
SQLITE_DB_PATH         = os.path.join(BASE_DIR, "database", "ingotus.db")
EVIDENCE_DIR           = os.path.join(BASE_DIR, "evidence")
FINGERPRINTS_JSON_PATH = os.path.join(BASE_DIR, "data", "fingerprints.json")
OUTPUT_DIR             = os.path.join(BASE_DIR, "output")
LOG_DIR                = os.path.join(BASE_DIR, "output", "logs")

# ── Versioning ─────────────────────────────────────────────────────────────────
VERSION            = "2.1"
EDITION            = "Bug Bounty Edition"
BANNER_DISCLAIMER  = "Autorização obrigatória. Use com responsabilidade."

# ── Network ────────────────────────────────────────────────────────────────────
TIMEOUT              = float(os.getenv("INGOTUS_TIMEOUT", "5.0"))
DEFAULT_WORKERS      = int(os.getenv("INGOTUS_WORKERS", "40"))
WEB_PORTS            = [80, 443, 3000, 3001, 3005, 5000, 8000, 8080, 8443, 8888]
DEFAULT_HTTP_PORTS   = [80, 443]
PRIVATE_IP_PREFIXES  = ["127.", "10.", "192.168.", "172.", "::1", "0.0.0.0"]

# ── Scan timeouts (distinct from the global connection timeout) ────────────────
PROBE_TIMEOUT        = float(os.getenv("INGOTUS_PROBE_TIMEOUT",   "2.0"))   # sensitive-path probe
BANNER_GRAB_TIMEOUT  = float(os.getenv("INGOTUS_BANNER_TIMEOUT",  "1.5"))   # banner recv
PORT_CONNECT_TIMEOUT = float(os.getenv("INGOTUS_PORT_TIMEOUT",    "1.0"))   # TCP connect

# ── Anti-False-Positive: Infrastructure host patterns ─────────────────────────
# Hosts matching any of these patterns are load balancers / GSLB / crawler infra.
# Security-header impact checks are suppressed for these hosts.
INFRA_HOST_PATTERNS = [
    ".gslb.",       # Global Server Load Balancer (Pinterest, Akamai, etc.)
    "-lb.",         # load balancer hostname convention
    ".lb.",
    "crawl-",       # named crawler IPs (e.g. crawl-54-236-1-101.pinterest.com)
    "crawler-",
    ".lb-",
    "traffic-manager",
]

# ── Anti-False-Positive: API endpoint detection ───────────────────────────────
# When a response has one of these Content-Type values, we treat the endpoint
# as an API. UI-only headers (CSP, X-Frame-Options) are NOT required for APIs.
API_CONTENT_TYPES = [
    "application/json",
    "application/graphql",
    "application/grpc",
    "text/event-stream",
    "application/ld+json",
]

# ── TLS version severity thresholds ───────────────────────────────────────────
DEPRECATED_TLS_VERSIONS = {"TLSv1": "HIGH", "TLSv1.1": "MEDIUM"}

# ── HTTP method enumeration ────────────────────────────────────────────────────
DANGEROUS_HTTP_METHODS = ["TRACE", "PUT", "DELETE", "CONNECT"]

# ── TLS ────────────────────────────────────────────────────────────────────────
TLS_DEFAULT_PORT     = 443
TLS_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"
TLS_UNKNOWN_ISSUER   = "Unknown (Invalid or Self-Signed SSL)"

# ── Buffer / snippet sizes ─────────────────────────────────────────────────────
RESPONSE_SNIPPET_SIZE = 2000   # bytes of HTTP response body stored
BANNER_RECV_SIZE      = 1024   # socket recv() buffer for port banners
BANNER_TRUNCATE_LEN   = 50     # max chars shown for generic port banners

# ── Display / terminal formatting ─────────────────────────────────────────────
DISPLAY_KEY_WIDTH      = 9     # key column width in host tree (keeps values aligned)
DISPLAY_URL_MAX_LEN    = 80    # redirect URL truncation in terminal output
DISPLAY_BANNER_MAX_LEN = 60    # port banner truncation in terminal output
PROGRESS_BAR_WIDTH     = 38    # Rich progress bar width (columns)
REPORT_SEPARATOR_WIDTH = 60    # "=" separator line width in impact files
EVIDENCE_WRAP_WIDTH    = 72    # textwrap width for evidence text

# ── Wildcard DNS probe ─────────────────────────────────────────────────────────
WILDCARD_CHECK_PREFIX = "ingotus-wildcard-check-"
WILDCARD_RAND_LEN     = 16

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_LEVEL     = os.getenv("INGOTUS_LOG_LEVEL", "DEBUG")
LOG_ROTATION  = "1 day"
LOG_RETENTION = "14 days"
LOG_FORMAT    = "{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {message}"

# ── Severity ordering — single source of truth ────────────────────────────────
# Imported by both logger.py and exporter.py to avoid duplication.
SEVERITY_ORDER: dict = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_TAGS: dict  = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]", "INFO": "[INFO]"}

# ── Common ports — loaded from fingerprints.json (Python list is the fallback) ─
# The fingerprints.json value always wins; this list is only used if JSON is missing.
COMMON_PORTS = [21, 22, 25, 53, 80, 443, 3000, 3001, 3005, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 8888]
if os.path.exists(FINGERPRINTS_JSON_PATH):
    try:
        with open(FINGERPRINTS_JSON_PATH, "r", encoding="utf-8") as _f:
            _fp = json.load(_f)
            if "common_ports" in _fp:
                COMMON_PORTS = _fp["common_ports"]
            # Load USER_AGENT from JSON if present (overrides the Python default below)
            _UA_FROM_JSON = _fp.get("user_agent")
    except Exception:
        _UA_FROM_JSON = None
else:
    _UA_FROM_JSON = None

# ── User-Agent ─────────────────────────────────────────────────────────────────
# Canonical UA used across http.py, evidence.py, and all providers.
# Value from fingerprints.json takes precedence so it can be changed without
# touching Python code.
USER_AGENT = (
    _UA_FROM_JSON
    or f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       f"AppleWebKit/537.36 (KHTML, like Gecko) "
       f"Chrome/124.0.0.0 Safari/537.36 "
       f"IgnotusRecon/{VERSION}"
)


# ── Directory bootstrap ────────────────────────────────────────────────────────
def setup_directories() -> None:
    """Create project output directories if they do not exist."""
    for d in [
        os.path.join(BASE_DIR, "database"),
        EVIDENCE_DIR,
        os.path.join(OUTPUT_DIR, "json"),
        os.path.join(OUTPUT_DIR, "markdown"),
        LOG_DIR,
    ]:
        os.makedirs(d, exist_ok=True)
