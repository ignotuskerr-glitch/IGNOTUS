"""
ingotus/core/logger.py

Flat, minimal terminal output — clean indented text with Rich.
Dual output: terminal (Rich / colors) + file (Loguru / plain, rotated).

Thread-safety: each host block is assembled as a rich.console.Group and
printed in ONE console.print() call so the progress spinner never interleaves
with data lines.
"""

import os
import re
import threading
from collections import defaultdict
from typing import Any

from loguru import logger as _loguru
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from core.config import (
    BANNER_DISCLAIMER,
    DISPLAY_BANNER_MAX_LEN,
    DISPLAY_KEY_WIDTH,
    DISPLAY_URL_MAX_LEN,
    EDITION,
    LOG_DIR,
    LOG_FORMAT,
    LOG_LEVEL,
    LOG_RETENTION,
    LOG_ROTATION,
    SEVERITY_ORDER,
    VERSION,
)

# ── File logger ────────────────────────────────────────────────────────────────

_LOG_FILE = os.path.join(LOG_DIR, "ingotus_{time:YYYY-MM-DD}.log")


def _init_loguru() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    _loguru.remove()
    _loguru.add(
        _LOG_FILE,
        rotation=LOG_ROTATION,
        retention=LOG_RETENTION,
        compression="gz",
        level=LOG_LEVEL,
        format=LOG_FORMAT,
        enqueue=True,
    )


_init_loguru()


# ── Severity styles ────────────────────────────────────────────────────────────
# Single source of truth for badge and text styles across all printers.

SEVERITY: dict[str, dict[str, str]] = {
    "CRITICAL": {"badge": "bold white on dark_red",       "text": "bold red"},
    "HIGH":     {"badge": "bold white on red3",           "text": "red"},
    "MEDIUM":   {"badge": "bold black on dark_goldenrod", "text": "yellow"},
    "LOW":      {"badge": "bold white on cyan4",          "text": "cyan"},
    "INFO":     {"badge": "bold white on steel_blue",     "text": "white"},
}

# Classification → terminal colour
CLASS_COLOR: dict[str, str] = {
    "CDN":           "green",
    "WAF":           "blue",
    "LOAD BALANCER": "cyan",
    "CLOUD ORIGIN":  "yellow",
    "ORIGIN":        "yellow",
    "UNKNOWN":       "dim white",
}


# ── Console & print lock ───────────────────────────────────────────────────────

console     = Console(force_terminal=True, highlight=False)
_PRINT_LOCK = threading.Lock()

try:
    # Unsupported terminal glyphs are presentation issues, never scan failures.
    console.file.reconfigure(errors="replace")
except (AttributeError, OSError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _plain(msg: str) -> str:
    """Strip Rich markup tags for plain-text loguru output."""
    return re.sub(r"\[/?[^\[\]]*\]", "", msg)


# ── Log-line helpers ───────────────────────────────────────────────────────────

def log_info(msg: str) -> None:
    console.print(f"[bold cyan] * [/bold cyan] {msg}")
    _loguru.info(_plain(msg))


def log_success(msg: str) -> None:
    console.print(f"[bold green] + [/bold green] {msg}")
    _loguru.success(_plain(msg))


def log_warning(msg: str) -> None:
    console.print(f"[bold yellow] ! [/bold yellow] {msg}")
    _loguru.warning(_plain(msg))


def log_error(msg: str) -> None:
    console.print(f"[bold red] - [/bold red] {msg}")
    _loguru.error(_plain(msg))


# ── Banner ─────────────────────────────────────────────────────────────────────

_RED_TEAM_LOGO = """ ██▓     ▄████     ███▄    █     ▒█████     ▄▄▄█████▓    █    ██      ██████
▓██▒    ██▒ ▀█▒    ██ ▀█   █    ▒██▒  ██▒   ▓  ██▒ ▓▒    ██  ▓██▒   ▒██    ▒
▒██▒   ▒██░▄▄▄░   ▓██  ▀█ ██▒   ▒██░  ██▒   ▒ ▓██░ ▒░   ▓██  ▒██░   ░ ▓██▄
░██░   ░▓█  ██▓   ▓██▒  ▐▌██▒   ▒██   ██░   ░ ▓██▓ ░    ▓▓█  ░██░     ▒   ██▒
░██░   ░▒▓███▀▒   ▒██░   ▓██░   ░ ████▓▒░     ▒██▒ ░    ▒▒█████▓    ▒██████▒▒
░▓      ░▒   ▒    ░ ▒░   ▒ ▒    ░ ▒░▒░▒░      ▒ ░░      ░▒▓▒ ▒ ▒    ▒ ▒▓▒ ▒ ░
 ▒ ░     ░   ░    ░ ░░   ░ ▒░     ░ ▒ ▒░        ░       ░░▒░ ░ ░    ░ ░▒  ░ ░
 ▒ ░   ░ ░   ░       ░   ░ ░    ░ ░ ░ ▒       ░          ░░░ ░ ░    ░  ░  ░
 ░           ░             ░        ░ ░                    ░              ░"""

_ASCII_LOGO = """ ___   ____  _   _  ___ _____ _   _ ____
|_ _| / ___|| \\ | |/ _ \\_   _| | | / ___|
 | | | |  _|  \\| | | | || | | | | \\___ \\
 | | | |_| | |\\  | |_| || | | |_| |___) |
|___| \\____|_| \\_|\\___/ |_|  \\___/|____/"""


def _select_banner_logo() -> str:
    """Return the full logo when the active console encoding can render it."""
    if not console_supports(_RED_TEAM_LOGO):
        return _ASCII_LOGO
    return _RED_TEAM_LOGO


def console_supports(value: str) -> bool:
    """Return whether the active output encoding can render ``value``."""
    encoding = getattr(console.file, "encoding", None) or "utf-8"
    try:
        value.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False
    return True


def print_banner() -> None:
    """Print the Red Team themed I G N O T U S terminal identity."""
    logo = Text(_select_banner_logo(), style="bold bright_red")

    details = Text(justify="center")
    details.append("I  G  N  O  T  U  S", style="bold white")
    details.append("\nR E D   T E A M   R E C O N", style="bold red")
    details.append(f"\n\nv{VERSION}  |  {EDITION}", style="bright_white")
    details.append(f"\n{BANNER_DISCLAIMER}", style="dim")

    console.print()
    # The supplied logo is exactly terminal-width on common 80-column shells.
    # Render it without a surrounding panel so Rich never folds its lines.
    console.print(logo, soft_wrap=True)
    console.print()
    console.print(
        Panel.fit(
            details,
            title="[bold bright_red] OFFENSIVE SECURITY FRAMEWORK [/bold bright_red]",
            subtitle="[bold red] RECON  |  VALIDATE  |  DOCUMENT [/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print()


def print_amsi_banner() -> None:
    """Print the dedicated defensive AMSI mode identity entirely in red."""
    logo = Text(_select_banner_logo(), style="bold red")
    details = Text(justify="center", style="red")
    details.append("I  G  N  O  T  U  S", style="bold bright_red")
    details.append("\nA M S I   D E F E N S I V E   V A L I D A T O R", style="bold red")
    details.append("\n\nNATIVE API  |  PROVIDERS  |  DEFENDER  |  TELEMETRY", style="bright_red")
    details.append("\nNo bypass. No malware. Evidence-based validation.", style="dim red")

    console.print()
    console.print(logo, soft_wrap=True)
    console.print()
    console.print(
        Panel.fit(
            details,
            title="[bold red] ADVANCED AMSI AUDIT [/bold red]",
            subtitle="[bold red] VERIFY  |  DETECT  |  REPORT [/bold red]",
            border_style="bright_red",
            padding=(1, 2),
        )
    )
    console.print()


def print_red_mode_banner() -> None:
    """Print the all-red defensive endpoint validation identity."""
    logo = Text(_select_banner_logo(), style="bold bright_red")
    details = Text(justify="center", style="red")
    details.append("I  G  N  O  T  U  S", style="bold bright_red")
    details.append("\nA D V A N C E D   D E F E N S I V E   R E D   M O D E", style="bold red")
    details.append("\n\nAMSI/ETW  |  DEFENDER  |  IMPACT  |  TELEMETRY  |  BASELINE", style="bright_red")
    details.append("\nLocal validation. Benign canaries. Evidence and drift.", style="dim red")

    console.print()
    console.print(logo, soft_wrap=True)
    console.print()
    console.print(
        Panel.fit(
            details,
            title="[bold bright_red] ENDPOINT SECURITY VALIDATOR [/bold bright_red]",
            subtitle="[bold red] VERIFY  |  MEASURE  |  IMPROVE [/bold red]",
            border_style="bright_red",
            padding=(1, 2),
        )
    )
    console.print()


# ── Host block builder ─────────────────────────────────────────────────────────

def _line(
    key: str = "",
    val: str = "",
    key_style: str = "dim white",
    val_style: str = "white",
    indent: int = 2,
) -> Text:
    """Build one key=value Text line (not yet printed)."""
    t = Text()
    t.append(" " * indent)
    t.append(f"{key:<{DISPLAY_KEY_WIDTH}}", style=key_style)
    if val:
        t.append("  ")
        t.append(val, style=val_style)
    return t


# ── Impact grouping helper ───────────────────────────────────────────────────────────────

# Impact types considered "header noise" — group these when there are 3+
_GROUPABLE_KEYWORDS = [
    "cabeçalho",
    "HSTS",
    "Referrer-Policy",
    "Permissions-Policy",
    "CSP",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def _group_impacts(impacts):
    """
    Groups similar LOW security-header impacts into a single summary line.
    Returns (grouped_singles, grouped_summary) where grouped_summary is a
    list of (severity, summary_text) tuples for collapsed groups.
    """
    grouped: dict[str, list] = defaultdict(list)
    singles = []

    for imp in impacts:
        is_groupable = (
            imp.severity in ("LOW", "INFO")
            and any(kw.lower() in imp.description.lower() for kw in _GROUPABLE_KEYWORDS)
        )
        if is_groupable:
            grouped[imp.severity].append(imp)
        else:
            singles.append(imp)

    summaries = []
    for sev, group in grouped.items():
        if len(group) == 1:
            singles.append(group[0])
        else:
            # Extract short names for each finding
            names = []
            for imp in group:
                # Pull out the header name between quotes or from keywords
                m = re.search(r"'([^']+)'|\b(HSTS|CSP|CORS|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy)\b", imp.description)
                names.append(m.group(1) or m.group(2) if m else imp.description[:30])
            summaries.append((sev, f"{len(group)} cabeçalhos de segurança ausentes: {', '.join(names)}", group[0].evidence[:120]))

    return singles, summaries


def _build_host_lines(result) -> list:
    """
    Build the complete host report as a list of Rich renderables.
    Wrapped in a Group and printed atomically.
    """
    col     = CLASS_COLOR.get(result.classification, "magenta")
    elapsed = getattr(result, "time_elapsed", "")
    conf    = result.confidence

    lines: list = []

    # Header
    header = Text()
    header.append(result.host,           style="bold white")
    header.append(" · ",                 style="dim white")
    header.append(result.classification, style=f"bold {col}")
    if conf:
        header.append(f" · conf {conf}%", style="dim white")
    if elapsed:
        header.append(f" · {elapsed}",   style="dim white")
    lines.append(Text(""))
    lines.append(header)

    # DNS
    lines.append(Text(""))
    lines.append(Text("DNS", style="bold white"))
    lines.append(_line("CNAME", result.dns.cname or "—", val_style="yellow"))
    for ip in result.dns.ips:
        lines.append(_line("IP", ip))

    # HTTP
    if result.http and result.http.status:
        sc     = result.http.status
        sc_col = "green" if sc < 400 else ("yellow" if sc < 500 else "red")
        lines.append(Text(""))
        lines.append(Text("HTTP", style="bold white"))
        lines.append(_line("status",  str(sc),                    sc_col))
        lines.append(_line("server",  result.http.server or "—"))
        if result.http.powered_by:
            lines.append(_line("powered", result.http.powered_by))
        if result.http.redirects_to:
            redir = result.http.redirects_to
            lines.append(_line(
                "redirect",
                redir[:DISPLAY_URL_MAX_LEN] + ("…" if len(redir) > DISPLAY_URL_MAX_LEN else ""),
                val_style="dim white",
            ))
        if result.http.cdn:
            cdn_str = (
                ", ".join(result.http.cdn)
                if isinstance(result.http.cdn, list)
                else result.http.cdn
            )
            lines.append(_line("cdn", cdn_str, val_style="green"))
        if result.http.is_api_endpoint:
            lines.append(_line("type", "API endpoint (JSON)", val_style="dim cyan"))
        if result.http.tech_stack:
            lines.append(_line("tech", ", ".join(result.http.tech_stack), val_style="bold cyan"))
        if result.http.http_methods:
            lines.append(_line("methods", ", ".join(result.http.http_methods), val_style="bold red"))
        if result.http.sensitive_paths:
            sp_str = ", ".join(f"{p} ({s})" for p, s in result.http.sensitive_paths)
            lines.append(_line("paths", sp_str, val_style="bold red"))

    # Ports
    if result.ports:
        lines.append(Text(""))
        lines.append(Text("PORTS", style="bold white"))
        for port, banner in result.ports:
            b = banner[:DISPLAY_BANNER_MAX_LEN] if banner else "—"
            lines.append(_line(str(port), b, val_style="dim white"))

    if result.services:
        lines.append(Text(""))
        lines.append(Text("SERVICES", style="bold white"))
        for service in result.services:
            if service.status is not None:
                state = f"{service.protocol} · HTTP {service.status}"
            elif service.auth_required is True:
                state = f"{service.protocol} · auth {service.auth_method}"
            elif service.auth_required is False:
                state = f"{service.protocol} · NO AUTH"
            else:
                state = service.protocol or service.kind
            style = "bold red" if service.auth_required is False else "cyan"
            lines.append(_line(str(service.port), state, val_style=style))

    # ASN
    if result.asn and result.asn.number:
        lines.append(Text(""))
        lines.append(Text("ASN", style="bold white"))
        lines.append(_line("number", result.asn.number, "yellow"))
        lines.append(_line("org",    result.asn.organization or "N/A"))
        if result.reverse_dns:
            lines.append(_line("rdns", result.reverse_dns, val_style="dim white"))

    # TLS
    if result.tls:
        valid_label = "VALID"     if result.tls.valid else "INVALID"
        tls_col     = "bold green" if result.tls.valid else "bold red"
        lines.append(Text(""))
        lines.append(Text("TLS", style="bold white"))
        lines.append(_line("status",  valid_label, val_style=tls_col))
        lines.append(_line("issuer",  result.tls.issuer or "N/A"))
        if result.tls.organization:
            lines.append(_line("org", result.tls.organization))
        if result.tls.expiration:
            lines.append(_line("expires", result.tls.expiration, val_style="yellow"))
        if result.tls.version:
            # Colour deprecated versions red, modern ones green
            ver_col = "bold red" if result.tls.version in ("TLSv1", "TLSv1.1") else "green"
            lines.append(_line("version", result.tls.version, val_style=ver_col))
        if result.tls.cipher:
            lines.append(_line("cipher", result.tls.cipher, val_style="dim white"))

    # Email security (only shown on root-domain hosts)
    if result.email_security:
        em = result.email_security
        lines.append(Text(""))
        lines.append(Text("EMAIL SEC", style="bold white"))
        spf_col = "green" if em.spf_valid else "bold red"
        spf_val = (em.spf[:60] + "…" if em.spf and len(em.spf) > 60 else em.spf) if em.spf else "—"
        lines.append(_line("SPF",   spf_val, val_style=spf_col))
        if em.dmarc:
            pol     = em.dmarc_policy or "?"
            pol_col = "green" if pol == "reject" else ("yellow" if pol == "quarantine" else "bold red")
            lines.append(_line("DMARC", f"p={pol}", val_style=pol_col))
        else:
            lines.append(_line("DMARC", "— (ausente)", val_style="bold red"))

    # Impacts — group LOWs to reduce noise
    if result.impacts:
        singles, summaries = _group_impacts(result.impacts)
        lines.append(Text(""))

        # Print grouped summaries first (less severe, compacted)
        for sev, summary_text, evidence in summaries:
            cfg = SEVERITY.get(sev, {"badge": "bold white", "text": "white"})
            row = Text()
            row.append("  [!] ", style="bold yellow")
            row.append(sev,          style=cfg["text"])
            row.append(" · ",        style="dim white")
            row.append(summary_text, style="white")
            lines.append(row)
            if evidence:
                ev_lines = [ev.strip() for ev in evidence.splitlines() if ev.strip()]
                for ev_line in ev_lines[:3]:
                    ev_t = Text()
                    ev_t.append(
                        "      ↳ " if console_supports("↳") else "      -> ",
                        style="dim cyan",
                    )
                    ev_t.append(ev_line[:120], style="dim white")
                    lines.append(ev_t)

        # Print individual impacts (high/critical + ungroupable)
        for imp in sorted(singles, key=lambda i: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(i.severity) if i.severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 9):
            cfg = SEVERITY.get(imp.severity, {"badge": "bold white", "text": "white"})
            row = Text()
            row.append("  [!] ", style="bold yellow")
            row.append(imp.severity,     style=cfg["text"])
            row.append(" · ",            style="dim white")
            row.append(imp.description,  style="white")
            lines.append(row)
            if imp.evidence:
                ev_lines = [ev.strip() for ev in imp.evidence.splitlines() if ev.strip()]
                for ev_line in ev_lines[:3]:
                    ev_t = Text()
                    ev_t.append(
                        "      ↳ " if console_supports("↳") else "      -> ",
                        style="dim cyan",
                    )
                    ev_t.append(ev_line[:120], style="dim white")
                    lines.append(ev_t)

    lines.append(Text(""))
    lines.append(Rule(style="dim white"))

    return lines


# ── Public printer ─────────────────────────────────────────────────────────────

def print_realtime_host_tree(result) -> None:
    """Print the host block atomically (one console.print call via Group)."""
    renderables = _build_host_lines(result)
    with _PRINT_LOCK:
        try:
            console.print(Group(*renderables))
        except UnicodeEncodeError:
            # Presentation must never invalidate a completed scan result.
            console.file.write(f"\n{result.host} - output contains unsupported glyphs\n")

    elapsed = getattr(result, "time_elapsed", "")
    _loguru.info(
        f"HOST={result.host} CLASS={result.classification} "
        f"CONF={result.confidence}% IMPACTS={len(result.impacts)} TIME={elapsed}"
    )
    for imp in result.impacts:
        _loguru.warning(f"  [{imp.severity}] {result.host} : {imp.description}")


# ── Summary table ──────────────────────────────────────────────────────────────

def print_summary_table(results: dict[str, Any]) -> None:
    from rich.table import Table

    console.print()
    console.print(Rule("[bold white]SCAN SUMMARY[/bold white]", style="dim white"))
    console.print()

    tbl = Table(
        border_style="dim white",
        header_style="bold white on grey23",
        show_lines=True,
        expand=True,
        padding=(0, 1),
    )
    tbl.add_column("Host",     style="white",   no_wrap=False, ratio=5)
    tbl.add_column("Class",    style="magenta", justify="center", ratio=2)
    tbl.add_column("IPs",      justify="center", ratio=1)
    tbl.add_column("HTTP",     justify="center", ratio=1)
    tbl.add_column("#",        justify="center", ratio=1)
    tbl.add_column("Severity", justify="center", ratio=2)
    tbl.add_column("Time",     justify="right",  style="dim", ratio=1)

    def _sort(item):
        _, r = item
        best = min(
            (SEVERITY_ORDER.get(i.severity, 9) for i in r.impacts),
            default=999,
        )
        return (best, item[0])

    for host, res in sorted(results.items(), key=_sort):
        n_imp   = len(res.impacts)
        max_sev = (
            min(res.impacts, key=lambda i: SEVERITY_ORDER.get(i.severity, 9), default=None)
            if res.impacts else None
        )

        sc     = res.http.status if res.http and res.http.status else None
        sc_col = (
            "green"    if sc and sc < 400 else
            "yellow"   if sc and sc < 500 else
            "red"      if sc else "dim white"
        )
        sc_cell  = Text(str(sc) if sc else "--", style=sc_col)
        ip_n     = len(res.dns.ips) if res.dns and res.dns.ips else 0
        imp_cell = Text(str(n_imp), style="bold red") if n_imp > 0 else Text("0", style="dim white")

        if max_sev:
            cfg      = SEVERITY.get(max_sev.severity, {"badge": "bold white"})
            sev_cell = Text(f" {max_sev.severity:<8}", style=cfg["badge"])
        else:
            sev_cell = Text("--", style="dim white")

        tbl.add_row(
            host,
            res.classification,
            str(ip_n) if ip_n else Text("--", style="dim"),
            sc_cell,
            imp_cell,
            sev_cell,
            getattr(res, "time_elapsed", "--"),
        )

    console.print(tbl)

    # Totals
    total  = len(results)
    w_imp  = sum(1 for r in results.values() if r.impacts)
    counts = {
        severity: sum(
            1
            for result in results.values()
            for impact in result.impacts
            if impact.severity == severity
        )
        for severity in SEVERITY_ORDER
    }

    console.print()
    parts = [
        f"[dim white]hosts[/dim white] [bold white]{total}[/bold white]",
        f"[dim white]with impacts[/dim white] [bold white]{w_imp}[/bold white]",
    ]
    for sev, cnt in counts.items():
        cfg = SEVERITY.get(sev, {"badge": "bold white"})
        parts.append(f"[{cfg['badge']}] {sev} {cnt} [/{cfg['badge']}]")
    console.print("  " + "  ·  ".join(parts))
    console.print()

    _loguru.info(
        f"SUMMARY total={total} impacts={w_imp} "
        + " ".join(f"{k}={v}" for k, v in counts.items())
    )
