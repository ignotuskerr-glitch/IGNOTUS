"""
ingotus/main.py
Entry point for the Ignotus Recon tool.
Orchestrates target parsing, passive discovery, active scanning, export, and reporting.
"""

# ── Providers Dynamic Loader ──────────────────────────────────────────────────
import importlib
import os
import pkgutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address
from typing import Dict, Optional

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule

import providers
from core.asn import lookup_asn
from core.asset_hunter import hunt_assets, hunt_sourcemaps_deep
from core.classifier import classify_and_validate
from core.cli import parse_cli_args

# ── Core Modules ───────────────────────────────────────────────────────────────
from core.config import (
    COMMON_PORTS,
    DEFAULT_HTTP_PORTS,
    OUTPUT_DIR,
    PROGRESS_BAR_WIDTH,
    SQLITE_DB_PATH,
    WEB_PORTS,
    setup_directories,
)
from core.dns import check_email_security, resolve_dns
from core.engines import GoEngine, GoEngineError, PreflightResult
from core.evidence import save_evidence
from core.exporter import export_json, export_markdown_report
from core.github_dorker import dork_github
from core.html_exporter import export_html_report
from core.http import get_http_info
from core.logger import (
    console,
    console_supports,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_amsi_banner,
    print_banner,
    print_realtime_host_tree,
    print_red_mode_banner,
    print_summary_table,
)
from core.models import DNSInfo, HostResult
from core.open_redirect import probe_open_redirect
from core.portscan import scan_ports
from core.reporting import deduplicate_impacts, export_asset_graph
from core.reverse import reverse_dns
from core.runtime import CancellationToken, CheckpointStore, RateLimiter, ScanCancelled
from core.scan_diff import calculate_scan_diff
from core.scope_checker import ScopeChecker, load_scope_file
from core.service_probe import probe_service_exposures
from core.target import ParsedTarget
from core.tls import analyze_tls
from core.unpack_map import unpack_sourcemap_url
from core.utils import init_db, save_scan_results
from core.wayback_harvester import analyze_wayback_urls, fetch_wayback_urls

# ── Thread-safe scan counters ─────────────────────────────────────────────────
_lock  = threading.Lock()
_stats = {
    "done": 0,
    "impacts": 0,
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
}


# ── PHASE 1: Passive Discovery ────────────────────────────────────────────────

def _run_provider(provider_module, domain: str, name: str) -> list:
    """Runs a single passive provider and returns its subdomains."""
    log_info(f"[PROVIDER] [yellow]{name:<18}[/yellow]  starting...")
    try:
        subs = provider_module.get_subdomains(domain)
        log_success(f"[PROVIDER] [yellow]{name:<18}[/yellow]  {len(subs):>4} subdomains returned")
        return subs
    except Exception as exc:
        log_error(f"[PROVIDER] [yellow]{name:<18}[/yellow]  error: {exc}")
        return []


def discover_subdomains(target: ParsedTarget) -> list:
    """Queries passive providers if eligible, else returns target host directly."""
    if not target.is_passive_eligible:
        log_info(f"Target is a single host/IP ({target.target_type}). Skipping passive discovery.")
        return [target.host]

    domain = target.host
    console.print("")
    console.print(Rule("[bold yellow]PHASE 1  —  PASSIVE SUBDOMAIN DISCOVERY[/bold yellow]", style="yellow"))
    console.print("")

    # Dynamically load all providers in the providers directory
    providers_found = []
    for finder, name, ispkg in pkgutil.iter_modules(providers.__path__):
        try:
            mod = importlib.import_module(f"providers.{name}")
            if hasattr(mod, "get_subdomains"):
                label = name.replace("_", "").title()
                providers_found.append((mod, label))
        except Exception as exc:
            log_error(f"Failed to load provider module {name}: {exc}")

    if not providers_found:
        log_warning("No passive providers loaded from providers/ directory.")
        return [domain]

    subdomains: set = set()

    with ThreadPoolExecutor(max_workers=len(providers_found)) as executor:
        futures = {
            executor.submit(_run_provider, mod, domain, label): label
            for mod, label in providers_found
        }
        for future in as_completed(futures):
            subdomains.update(future.result())

    subdomains.add(domain)  # always include the root domain

    console.print("")
    log_success(
        f"Discovery complete  >>  [bold green]{len(subdomains)}[/bold green] unique subdomains"
    )
    console.print("")

    return sorted(subdomains)


# ── PHASE 2: Active Host Scanning ─────────────────────────────────────────────

def scan_host(
    subdomain: str,
    do_portscan: bool,
    progress,
    task_id,
    only_impacts: bool = False,
    proxy: Optional[str] = None,
    custom_port: Optional[int] = None,
    target_label: str = "",
    hunt_assets_flag: bool = False,
    auth_cookies: Optional[Dict[str, str]] = None,
    auth_headers: Optional[Dict[str, str]] = None,
    download_dir: Optional[str] = None,
    smuggling_flag: bool = False,
    ssrf_flag: bool = False,
    nuclei_flag: bool = False,
    fuzz_files_flag: bool = False,
    test_api_flag: bool = False,
    screenshot_flag: bool = False,
    werkzeug_dos_flag: bool = False,
    external_audit_flag: bool = False,
    preflight: PreflightResult | None = None,
    rate_limiter: RateLimiter | None = None,
    cancellation: CancellationToken | None = None,
) -> HostResult:
    """
    Full recon pipeline for a single subdomain or host/IP:
      1. DNS resolution
      2. Port scan (optional or custom port)
      3. HTTP banner grab & Tech stack detection
      4. TLS certificate analysis
      5. ASN + rDNS lookup
      6. Impact classification
      7. Evidence saving
    """
    start = time.time()
    result = HostResult(host=subdomain)

    try:
        if rate_limiter is not None:
            rate_limiter.wait(cancellation)
        if cancellation is not None:
            cancellation.raise_if_cancelled()

        # 1 — DNS
        if preflight is not None and not preflight.error:
            result.dns = DNSInfo(ips=preflight.ips, cname=preflight.cname)
        else:
            result.dns = resolve_dns(subdomain)

        if result.dns.ips:
            # 2 — Ports
            if preflight is not None and not preflight.error:
                result.ports = preflight.ports
            elif custom_port:
                result.ports = scan_ports(subdomain, [custom_port])
            elif do_portscan:
                result.ports = scan_ports(subdomain, COMMON_PORTS)
            else:
                result.ports = [(p, "") for p in DEFAULT_HTTP_PORTS]

            # 3 — HTTP
            has_web = any(p[0] in WEB_PORTS for p in result.ports) or (custom_port is not None)
            if has_web or not do_portscan:
                result.http = get_http_info(
                    subdomain,
                    proxy=proxy,
                    custom_port=custom_port,
                    auth_cookies=auth_cookies,
                    auth_headers=auth_headers,
                    enable_werkzeug_dos=werkzeug_dos_flag,
                )

            # Protocol-aware validation for services exposed outside the
            # standard reverse-proxy ports (for example HTTPS on 3005) and
            # PostgreSQL authentication/TLS posture on 5432.
            result.services = probe_service_exposures(
                subdomain,
                result.ports,
                proxy=proxy,
            )

            # 4 — TLS
            tls_port = custom_port if custom_port else 443
            if any(p[0] == tls_port for p in result.ports) or custom_port:
                result.tls = analyze_tls(subdomain, port=tls_port)

            # 5 — ASN / rDNS
            primary_ip       = result.dns.ips[0]
            result.asn       = lookup_asn(primary_ip)
            result.reverse_dns = reverse_dns(primary_ip)

        elif result.dns.cname:
            result.http = get_http_info(
                subdomain,
                proxy=proxy,
                custom_port=custom_port,
                auth_cookies=auth_cookies,
                auth_headers=auth_headers,
                enable_werkzeug_dos=werkzeug_dos_flag,
            )

        if cancellation is not None:
            cancellation.raise_if_cancelled()

        # 5.1 — Root Domain Email Security Check (SPF / DMARC)
        if (
            target_label
            and subdomain.lower() == target_label.lower()
            and _is_domain_name(subdomain)
        ):
            result.email_security = check_email_security(subdomain)

        # 5.1b ── Subdomain Takeover Check ───────────────────────────────────
        # Roda sempre que o subdomínio tem CNAME (passamos ele direto para evitar
        # um segundo lookup DNS). Também testa subdomínios sem IPs (NXDOMAIN +
        # CNAME pendente = caso clássico de takeover).
        try:
            from core.models import Impact
            from core.takeover_checker import check_cname_takeover
            cname_hint = result.dns.cname if result.dns else None
            takeover = check_cname_takeover(subdomain, cname_target=cname_hint, proxy=proxy)
            if takeover:
                result.impacts.append(Impact(
                    severity=takeover["severity"],
                    description=takeover["desc"],
                    evidence=takeover["evidence"],
                ))
                log_warning(f"TAKEOVER [{takeover['severity']}] {subdomain} -> {takeover['service']} ({takeover['cname']})")
        except Exception:
            pass


        # 5.2 — Asset Hunting (source maps, .env, .git, configs, etc.)
        if hunt_assets_flag and result.http and result.http.url:
            base_url = result.http.url
            asset_findings = hunt_assets(base_url, proxy=proxy, download_dir=download_dir)
            for af in asset_findings:
                from core.models import Impact
                result.impacts.append(Impact(
                    severity=af["severity"],
                    description=af["desc"],
                    evidence=af.get("evidence", "") + ("\n\n[Conteúdo]\n" + af.get("content_preview", "") if af.get("content_preview") else ""),
                ))

            # Source map deep discovery from HTML
            if result.http.body:
                sm_findings = hunt_sourcemaps_deep(
                    base_url, result.http.body,
                    proxy=proxy, download_dir=download_dir
                )
                for sf in sm_findings:
                    from core.models import Impact
                    result.impacts.append(Impact(
                        severity=sf["severity"],
                        description=sf["desc"],
                        evidence=sf.get("evidence", ""),
                    ))

            # Source map auto-analysis: if maps were extracted, analyze them
            if download_dir:
                from datetime import datetime
                date_folder = datetime.now().strftime("%d%m%Y")
                host_netloc = subdomain.replace(":", "_")
                
                parts = host_netloc.split(".")
                if len(parts) >= 2:
                    if len(parts) >= 3 and parts[-2] in ("gov", "com", "net", "org", "edu", "co", "me"):
                        target_group = ".".join(parts[-3:])
                    else:
                        target_group = ".".join(parts[-2:])
                else:
                    target_group = host_netloc
                target_group = target_group.replace("*", "").replace(":", "_").strip(".")

                # ── Analisa APENAS o subdir do host atual dentro do seu grupo do dominio ──
                sm_extract_dir = os.path.join(download_dir, "sourcemaps", date_folder, target_group, host_netloc)
                if os.path.isdir(sm_extract_dir):
                    try:
                        from pathlib import Path

                        from core.models import Impact
                        from core.sourcemap_analyzer import analyze_directory
                        sm_report = analyze_directory(Path(sm_extract_dir), verbose=False)

                        if sm_report.get("all_aws_resources"):
                            result.impacts.append(Impact(
                                severity="medium",
                                description=f"Source Map: {len(sm_report['all_aws_resources'])} recurso(s) AWS expostos no código-fonte",
                                evidence="\n".join(sm_report["all_aws_resources"][:5]),
                            ))
                        if sm_report.get("all_internal_hosts"):
                            result.impacts.append(Impact(
                                severity="medium",
                                description=f"Source Map: {len(sm_report['all_internal_hosts'])} host(s) internos/staging expostos",
                                evidence="\n".join(sm_report["all_internal_hosts"]),
                            ))
                        if sm_report.get("all_potential_secrets"):
                            result.impacts.append(Impact(
                                severity="high",
                                description=f"Source Map: {len(sm_report['all_potential_secrets'])} possível(is) segredo(s) no código-fonte",
                                evidence="\n".join(
                                    f"{s['file']}: {s['match'][:80]}"
                                    for s in sm_report["all_potential_secrets"][:5]
                                ),
                            ))
                        if sm_report.get("all_endpoints"):
                            # ── Wordlists organizadas na pasta dedicada output/sourcemaps/wordlists/ ──
                            from core.sourcemap_analyzer import generate_wordlist
                            wl_dir = os.path.join(download_dir, "sourcemaps", "wordlists")
                            os.makedirs(wl_dir, exist_ok=True)

                            safe = subdomain.replace(".", "_").replace(":", "_")
                            wl_path = os.path.join(wl_dir, f"wordlist_{safe}.txt")
                            # Deduplica: não regera se wordlist já existe e tem conteúdo
                            if not os.path.exists(wl_path) or os.path.getsize(wl_path) == 0:
                                with open(wl_path, "w", encoding="utf-8") as wlf:
                                    wlf.write(generate_wordlist(sm_report))
                                log_info(f"Wordlist de endpoints gerada: {wl_path} ({len(sm_report['all_endpoints'])} paths)")
                            else:
                                log_info(f"Wordlist já existe, pulando: {wl_path}")

                            # ── Probe dos endpoints descobertos nos sourcemaps ──
                            from core.api_discovery import probe_discovered_endpoints
                            active_eps = probe_discovered_endpoints(base_url, sm_report["all_endpoints"], proxy=proxy)
                            for aep in active_eps:
                                result.impacts.append(Impact(
                                    severity=aep["severity"],
                                    description=aep["desc"],
                                    evidence=aep["evidence"] + f"\n\nPoC:\n  {aep['poc']}",
                                ))
                            if active_eps:
                                log_success(f"Endpoints de Source Map ativos encontrados: {len(active_eps)}")

                        if sm_report.get("all_env_vars"):
                            log_info(f"Env vars encontradas em source maps: {', '.join(sm_report['all_env_vars'][:10])}")
                    except Exception as e:
                        log_warning(f"Sourcemap analyzer falhou: {e}")


        # 5.3 — Open Redirect
        if result.http and result.http.url:
            redirect_findings = probe_open_redirect(result.http.url, proxy=proxy)
            for rf in redirect_findings:
                from core.models import Impact
                result.impacts.append(Impact(
                    severity=rf["severity"],
                    description=rf.get("desc", rf.get("description", "Open Redirect detectado")),
                    evidence=rf.get("poc", rf.get("evidence", "")),
                ))

        # 5.4 — HTTP Request Smuggling (optional)
        if smuggling_flag and result.dns.ips:
            try:
                from core.models import Impact
                from core.smuggling import detect_smuggling
                sm_port = custom_port or (443 if result.tls else 80)
                for sf in detect_smuggling(subdomain, port=sm_port):
                    result.impacts.append(Impact(
                        severity=sf["severity"],
                        description=f"HTTP Request Smuggling [{sf['technique']}] — {sf['confidence']}",
                        evidence=sf["evidence"],
                    ))
            except Exception:
                pass

        # 5.5 — SSRF Probe with Interactsh (optional)
        if ssrf_flag and result.http and result.http.url:
            try:
                from core.models import Impact
                from core.ssrf_probe import probe_ssrf
                for sf in probe_ssrf(result.http.url, proxy=proxy):
                    result.impacts.append(Impact(
                        severity=sf["severity"],
                        description=f"SSRF detectado no parâmetro '{sf['param']}' [{sf['confidence']}]",
                        evidence=sf["evidence"],
                    ))
            except Exception:
                pass

        # 5.6 — Nuclei Template Scan (optional)
        if nuclei_flag and result.http and result.http.url:
            try:
                from core.models import Impact
                from core.nuclei_runner import run_nuclei_templates
                for nf in run_nuclei_templates(result.http.url, proxy=proxy):
                    result.impacts.append(Impact(
                        severity=nf["severity"],
                        description=f"[Nuclei] {nf['name']}",
                        evidence=nf["evidence"],
                    ))
            except Exception:
                pass

        # 5.6b — Independent validation orchestrated by Ignotus through Kali WSL
        if external_audit_flag and result.dns.ips:
            try:
                from core.external_audit import run_external_audit

                if custom_port:
                    audit_ports = [custom_port]
                else:
                    audit_ports = [
                        port for port, _banner in result.ports
                        if port in (22, 80, 443, 8080, 8443)
                    ]
                for audit_port in audit_ports:
                    result.impacts.extend(run_external_audit(subdomain, audit_port))
            except Exception as exc:
                log_warning(f"Validação externa falhou para {subdomain}: {exc}")

        # 5.7 — Swagger / OpenAPI Auto-Explorer (optional)
        if test_api_flag and result.http and result.http.url:
            try:
                from core.models import Impact
                from core.swagger_tester import audit_swagger_endpoints
                for sf in audit_swagger_endpoints(result.http.url, proxy=proxy):
                    result.impacts.append(Impact(
                        severity=sf["severity"],
                        description=sf["desc"],
                        evidence=sf["evidence"],
                    ))
            except Exception:
                pass

        # 5.8 — Sensitive & Backup Files Fuzzer (automatic check for web hosts if enabled or full scan)
        if result.http and result.http.url and (fuzz_files_flag or hunt_assets_flag):
            try:
                from core.models import Impact
                from core.sensitive_files import audit_sensitive_files
                for ff in audit_sensitive_files(result.http.url, proxy=proxy):
                    result.impacts.append(Impact(
                        severity=ff["severity"],
                        description=ff["desc"],
                        evidence=ff["evidence"],
                    ))
            except Exception:
                pass

        # 5.9 — Deep CORS Credential Auditor (automatic check if web host)
        if result.http and result.http.url:
            try:
                from core.cors_credentials import audit_cors_credentials
                from core.models import Impact
                for cf in audit_cors_credentials(result.http.url, proxy=proxy):
                    result.impacts.append(Impact(
                        severity=cf["severity"],
                        description=cf["desc"],
                        evidence=cf["evidence"],
                    ))
            except Exception:
                pass

        # 5.9b — Automatic JWT Token Auditor
        if result.http and (result.http.headers or result.http.body):
            try:
                from core.jwt_analyzer import extract_and_analyze_jwts
                from core.models import Impact
                
                # Check both response headers (Set-Cookie / Auth) and body for JWTs
                sample_data = str(result.http.headers) + "\n" + str(result.http.body[:2000])
                jwt_findings = extract_and_analyze_jwts(sample_data)
                
                for jf in jwt_findings:
                    if jf.get("issues"):
                        result.impacts.append(Impact(
                            severity=jf["severity"],
                            description=f"JWT Token Vulnerável Detectado ({', '.join(jf['issues'])})",
                            evidence=f"Token: {jf['token']}\nHeader: {jf['header']}\nPayload: {jf['payload']}\nProblemas: {jf['issues']}",
                        ))
            except Exception:
                pass

        # 5.10 — Visual Screenshot Capturer (optional)
        if screenshot_flag and result.http and result.http.url:
            try:
                from core.screenshooter import capture_screenshot
                target_slug = target_label.replace("*", "").replace(":", "_").strip(".")
                shot_path = os.path.join(OUTPUT_DIR, "screenshots", target_slug, f"{subdomain}.png")
                if capture_screenshot(result.http.url, shot_path):
                    log_success(f"[SCREENSHOT] Capturado para [bold white]{subdomain}[/bold white]")
            except Exception:
                pass

        # 6 — Classification
        classify_and_validate(result)
        result.impacts = deduplicate_impacts(result.impacts)

        # 7 — Evidence
        save_evidence(result, target_label=target_label)

    except ScanCancelled:
        log_warning(f"[SCAN] [bold]{subdomain}[/bold] cancelado")
    except Exception as exc:
        log_error(f"[SCAN] [bold]{subdomain}[/bold]  error: {exc}")

    result.time_elapsed = f"{time.time() - start:.2f}s"

    # Update thread-safe counters
    with _lock:
        _stats["done"] += 1
        _stats["impacts"] += len(result.impacts)
        for imp in result.impacts:
            sev = imp.severity.upper()
            if sev in _stats:
                _stats[sev] += 1

    # Advance progress bar BEFORE printing so Rich can redraw cleanly
    progress.advance(task_id)

    # Print host block — skip silent/unresolved hosts
    # When --only-impacts is set, skip hosts with no impacts
    is_active = result.dns.ips or (result.http and result.http.status) or result.impacts
    has_impact = bool(result.impacts)

    if is_active and (not only_impacts or has_impact):
        print_realtime_host_tree(result)

    return result


# ── PHASE 3: Export ───────────────────────────────────────────────────────────

def export_results(target_label: str, results: dict):
    """Saves SQLite records, JSON and Markdown outputs."""

    console.print(Rule("[bold cyan]PHASE 3  —  EXPORT[/bold cyan]", style="cyan"))
    console.print("")

    safe_label = target_label.replace("*", "").replace(":", "_").strip(".")

    # SQLite
    init_db(SQLITE_DB_PATH)
    save_scan_results(SQLITE_DB_PATH, target_label, results)
    log_success(f"SQLite saved          [yellow]{SQLITE_DB_PATH}[/yellow]")

    # Diff calculation
    raw_results = [r.to_dict() if hasattr(r, 'to_dict') else r for r in results.values()]
    diff = calculate_scan_diff(raw_results, SQLITE_DB_PATH, target_label)
    if not diff.get("is_first_scan"):
        log_info("[bold cyan]── SCAN DIFF (Comparações com histórico) ──[/bold cyan]")
        if diff["new_subdomains"]:
            log_warning(f"  Novos Subdomínios   : [bold red]+{len(diff['new_subdomains'])}[/bold red] ({', '.join(diff['new_subdomains'][:5])})")
        if diff["new_open_ports"]:
            log_warning(f"  Novas Portas Abertas: [bold red]+{len(diff['new_open_ports'])}[/bold red] hosts")
        if diff["new_vulnerabilities"]:
            log_warning(f"  Novas Vulns Impacto : [bold red]+{len(diff['new_vulnerabilities'])}[/bold red]")
        if not (diff["new_subdomains"] or diff["new_open_ports"] or diff["new_vulnerabilities"]):
            log_success("  Nenhuma alteração detectada em relação ao último scan.")

    # JSON
    json_path = os.path.join(OUTPUT_DIR, "json", f"{safe_label}_results.json")
    export_json(results, json_path)
    log_success(f"JSON exported         [yellow]{json_path}[/yellow]")

    graph_path = os.path.join(OUTPUT_DIR, "json", f"{safe_label}_asset_graph.json")
    export_asset_graph(results, graph_path)
    log_success(f"Asset graph exported  [yellow]{graph_path}[/yellow]")

    # Markdown
    md_path = os.path.join(OUTPUT_DIR, "markdown", f"report_{safe_label}.md")
    export_markdown_report(target_label, results, md_path)
    log_success(f"Markdown report       [yellow]{md_path}[/yellow]")

    # HTML Dashboard (gerado automaticamente)
    html_path = os.path.join(OUTPUT_DIR, "markdown", f"report_{safe_label}.html")
    export_html_report(target_label, results, html_path)
    log_success(f"HTML dashboard        [yellow]{html_path}[/yellow]")

    console.print("")


# ── Entry Point ───────────────────────────────────────────────────────────────

def _checkpoint_store(args, target_label: str) -> CheckpointStore | None:
    if args.no_checkpoint:
        return None
    safe_label = target_label.replace("*", "").replace(":", "_").strip(".")
    path = args.checkpoint_file or os.path.join(
        OUTPUT_DIR,
        "checkpoints",
        f"{safe_label}.json",
    )
    return CheckpointStore(path, target_label)


def _is_domain_name(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return True
    return False


def _run_go_preflight(args, hosts: list[str], custom_port: int | None):
    if args.engine == "python" or not hosts:
        return {}

    engine = GoEngine()
    if not engine.available:
        if args.engine == "go":
            raise GoEngineError(
                "motor Go solicitado, mas bin/ignotus-engine não foi encontrado"
            )
        log_warning("Motor Go indisponível; usando fallback Python.")
        return {}

    ports = [custom_port] if custom_port else (
        [] if args.no_portscan else list(COMMON_PORTS)
    )
    log_info(
        f"Motor Go      [bold green]ENABLED[/bold green] "
        f"({len(hosts)} hosts, {len(ports)} portas)"
    )
    return engine.scan_many(
        hosts,
        ports,
        workers=args.workers,
        rate_limit=args.rate_limit,
        timeout_seconds=args.scan_timeout,
    )


def main():
    args, parser = parse_cli_args()
    # The terminal-first launcher already rendered the product identity. Direct
    # CLI invocations keep their dedicated banner.
    if not getattr(args, "compact_ui", False):
        if args.red_mode:
            print_red_mode_banner()
        elif args.amsi_audit:
            print_amsi_banner()
        else:
            print_banner()
    setup_directories()

    if args.red_mode:
        from core.red_mode import run_red_mode

        console.print(Rule("[bold red]RED MODE — DEFENSIVE ENDPOINT VALIDATION[/bold red]", style="red"))
        run = run_red_mode(
            target=args.target,
            profile=args.red_profile,
            output_dir=args.red_output,
            detections_file=args.red_detections,
            save_baseline_requested=args.red_save_baseline,
            compare_baseline_path=args.red_compare_baseline,
        )
        styles = {"PASS": "green", "WARN": "yellow", "FAIL": "bold red", "INFO": "cyan"}
        current_category = None
        for check in run.checks:
            if check.category != current_category:
                current_category = check.category
                console.print(f"\n [bold red]{current_category.upper()}[/bold red]")
            style = styles.get(check.status, "white")
            console.print(f" [{style}]{check.status:4}[/{style}] {check.id} · {check.detail}")
        summary = run.summary
        console.print("")
        log_info(
            f"Posture score: [bold white]{summary['score']}/100[/bold white] · "
            f"{summary['PASS']} PASS · {summary['WARN']} WARN · "
            f"{summary['FAIL']} FAIL · {summary['INFO']} INFO"
        )
        if run.drift:
            log_warning(f"Baseline drift: {len(run.drift)} stable changes")
        elif args.red_compare_baseline:
            log_success("Baseline drift: no stable changes")
        if run.impact:
            impact_summary = run.impact.get("summary") or {}
            log_info(
                f"Impact coverage: [bold white]{impact_summary.get('effective_coverage_percent', 0)}%[/bold white] · "
                f"BLOCKED {impact_summary.get('BLOCKED', 0)} · "
                f"DETECTED {impact_summary.get('DETECTED', 0)} · "
                f"MISSED {impact_summary.get('MISSED', 0)} · "
                f"NOT_OBSERVABLE {impact_summary.get('NOT_OBSERVABLE', 0)}"
            )
        if run.baseline_path:
            log_info(f"Baseline: {run.baseline_path}")
        log_info(f"JSON: {run.json_path}")
        log_info(f"Markdown: {run.markdown_path}")
        return

    if args.amsi_audit:
        from core.amsi_audit import run_amsi_audit

        console.print(Rule("[bold red]AMSI — NATIVE DEFENSIVE VALIDATION[/bold red]", style="red"))
        report = run_amsi_audit(args.amsi_output)
        for check in report["checks"]:
            style = "green" if check["status"] == "PASS" else "yellow" if check["status"] == "WARN" else "red"
            console.print(f" [{style}]{check['status']}[/{style}] {check['id']} · {check['detail']}")
        console.print("")
        log_info(f"Resultado: {report['summary']['passed']} PASS · {report['summary']['warnings']} WARN · {report['summary']['failed']} FAIL")
        log_info(f"JSON: {report['json_path']}")
        log_info(f"Markdown: {report['markdown_path']}")
        return

    if args.purple_team:
        from core.purple_team import run_purple_team

        console.print(Rule("[bold magenta]PURPLE TEAM — SAFE LOCAL SIMULATION[/bold magenta]", style="magenta"))
        run = run_purple_team(
            profile=args.purple_profile,
            detections_file=args.purple_detections,
            output_dir=args.purple_output,
        )
        for result in run.results:
            marker = "+" if result.execution == "passed" else "!"
            console.print(
                f" {marker} {result.simulation_id} · {result.attack_id} · "
                f"execução={result.execution} · detecção={result.detection}"
            )
        console.print("")
        log_success(f"Simulações benignas: {run.passed}/{len(run.results)}")
        log_info(f"Cobertura validada: {run.covered}/{len(run.results)}")
        log_info(f"JSON: {run.json_path}")
        log_info(f"Markdown: {run.markdown_path}")
        return


    # Processar --source-map diretamente (modo standalone)
    if args.source_map:
        console.print(Rule("[bold yellow]SOURCE MAP — EXTRAÇÃO DIRETA[/bold yellow]", style="yellow"))
        console.print("")
        log_info(f"Baixando e extraindo: [bold]{args.source_map}[/bold]")
        out = args.download_dir or "output/sourcemaps/direct"
        os.makedirs(out, exist_ok=True)
        result = unpack_sourcemap_url(args.source_map, out)
        log_success(f"Arquivos extraídos : [bold green]{result.get('files_extracted', 0)}[/bold green]")
        log_info(f"Diretório de saída  : [yellow]{result.get('output_dir', out)}[/yellow]")
        if result.get('external_sources'):
            log_info(f"Fontes externas    : {len(result['external_sources'])} tentadas")
        if result.get('nested_maps'):
            log_info(f"Mapas aninhados    : {len(result['nested_maps'])} detectados")
        sys.exit(0)

    # Parsear auth_cookie e auth_header
    auth_cookies: Optional[Dict[str, str]] = None
    auth_headers: Optional[Dict[str, str]] = None
    if args.auth_cookie:
        try:
            k, v = args.auth_cookie.split("=", 1)
            auth_cookies = {k.strip(): v.strip()}
        except ValueError:
            log_warning("--auth-cookie inválido: use o formato NAME=VALUE")
    if args.auth_header:
        try:
            k, v = args.auth_header.split(":", 1)
            auth_headers = {k.strip(): v.strip()}
        except ValueError:
            log_warning("--auth-header inválido: use o formato NAME:VALUE")

    # Parse and normalize input target
    target = ParsedTarget(args.target)

    # ── Session header ─────────────────────────────────────────────────
    compact_ui = getattr(args, "compact_ui", False)
    console.print(Rule("[bold white]SCAN ARMED[/bold white]" if compact_ui else "[bold white]SESSION CONFIG[/bold white]", style="dim white"))
    console.print("")
    if compact_ui:
        profile = "FULL" if args.full else "IMPACT"
        log_info(f"Target  [bold white]{target.host}[/bold white]  ·  Type [bold yellow]{target.target_type}[/bold yellow]")
        log_info(
            f"Profile [bold bright_red]{profile}[/bold bright_red]  ·  "
            f"Engine [bold white]{args.engine.upper()}[/bold white]  ·  "
            f"Workers [bold white]{args.workers}[/bold white]  ·  "
            f"Ports [bold white]{'OFF' if args.no_portscan else 'ON'}[/bold white]"
        )
    else:
        log_info(f"Target Input [bold white]{target.raw}[/bold white]")
        log_info(f"Parsed Host  [bold white]{target.host}[/bold white]")
        log_info(f"Target Type  [bold yellow]{target.target_type}[/bold yellow]")
        if target.custom_port:
            log_info(f"Custom Port  [bold yellow]{target.custom_port}[/bold yellow]")
        log_info(f"Workers      [bold white]{args.workers}[/bold white]")
        log_info(f"Port Scan    [bold white]{not args.no_portscan}[/bold white]")
        log_info(f"Only Impacts [bold white]{args.only_impacts}[/bold white]")
    module_labels = {
        "hunt_assets": "assets",
        "fuzz_files": "files",
        "test_api": "api",
        "smuggling": "smuggling",
        "ssrf": "ssrf",
        "nuclei": "nuclei",
        "screenshot": "screenshots",
        "external_audit": "wsl-audit",
    }
    enabled_modules = [
        label for attr, label in module_labels.items() if getattr(args, attr, False)
    ]
    if compact_ui and enabled_modules:
        log_info(f"Modules [bold green]{', '.join(enabled_modules)}[/bold green]")
    elif not compact_ui:
        for attr, label in module_labels.items():
            if getattr(args, attr, False):
                style = "bold red" if attr in {"smuggling", "ssrf", "nuclei"} else "bold green"
                log_info(f"{label:<13}[{style}]ENABLED[/{style}]")
    if args.proxy:
        log_info(f"Proxy        [bold yellow]{args.proxy}[/bold yellow]")
    console.print("")

    # ── Phase 1: Passive Discovery ─────────────────────────────────────
    subdomains = discover_subdomains(target)

    # 1.0 — Certificate Transparency Logs (crt.sh)
    if target.is_passive_eligible:
        try:
            from core.ct_harvester import fetch_ct_subdomains
            ct_subs = fetch_ct_subdomains(target.clean_target)
            new_ct_subs = [s for s in ct_subs if s not in subdomains]
            if new_ct_subs:
                subdomains.extend(new_ct_subs)
                log_success(f"Cert Transparency  [bold green]+{len(new_ct_subs)} subdomínios[/bold green] via crt.sh")
        except Exception:
            pass

    # 1.1 — Wayback Machine Historical Harvester
    if getattr(args, 'wayback', False) and target.is_passive_eligible:
        log_info(f"Consultando Wayback Machine (CDX API) para [bold]{target.clean_target}[/bold]...")
        wb_urls = fetch_wayback_urls(target.clean_target)
        if wb_urls:
            wb_data = analyze_wayback_urls(wb_urls)
            wb_subs = list(wb_data["subdomains"])
            new_wb_subs = [s for s in wb_subs if s not in subdomains]
            subdomains.extend(new_wb_subs)
            log_success(f"Wayback Machine    [bold green]+{len(wb_urls)} URLs[/bold green] ({len(new_wb_subs)} novos subdomínios)")
            if wb_data["sensitive_files"]:
                log_warning(f"Wayback Sensive    [bold yellow]{len(wb_data['sensitive_files'])} arquivos sensíveis históricos[/bold yellow]")

    # 1.2 — GitHub Secret Dorker
    if getattr(args, 'github_dork', False):
        log_info(f"Executando GitHub Secret Dorker para [bold]{target.clean_target}[/bold]...")
        gh_results = dork_github(target.clean_target, token=getattr(args, 'github_token', None))
        if gh_results:
            log_warning(f"GitHub Dorks       [bold red]{len(gh_results)} achados públicos detectados![/bold red]")
            for ghr in gh_results:
                log_info(f"  [{ghr['severity'].upper()}] {ghr['repo']}/{ghr['path']} -> {ghr['html_url']}")

    # 1.3 — Scope Filtering
    if getattr(args, 'scope_file', None):
        in_s, out_s = load_scope_file(args.scope_file)
        if not in_s:
            parser.error("arquivo de escopo ausente, inválido ou sem regras in-scope")
        sc = ScopeChecker(in_scope_rules=in_s, out_scope_rules=out_s)
        before_count = len(subdomains)
        subdomains = [s for s in subdomains if sc.is_in_scope(s)]
        log_info(f"Escopo Aplicado    [bold yellow]{len(subdomains)}/{before_count}[/bold yellow] hosts mantidos dentro do escopo")

    if not subdomains:
        log_warning("No targets found. Aborting.")
        sys.exit(0)

    # Check Wildcard DNS only for eligible domain targets
    if target.is_passive_eligible:
        from core.dns import check_wildcard_dns
        wildcard_ips = check_wildcard_dns(target.host)
        if wildcard_ips:
            log_warning(f"Wildcard DNS detected for {target.host} (Catch-all IPs: {', '.join(wildcard_ips)})")

    # ── Phase 2: Active Scan ───────────────────────────────────────────
    console.print(Rule("[bold red]PHASE 2  —  ACTIVE SCAN[/bold red]", style="red"))
    console.print("")
    log_info(
        f"Scanning [bold green]{len(subdomains)}[/bold green] hosts"
        f"  |  [bold white]{args.workers}[/bold white] workers"
        f"  |  port scan=[bold white]{not args.no_portscan}[/bold white]"
    )
    console.print("")

    checkpoint = _checkpoint_store(args, target.clean_target)
    results: dict = {}
    if args.resume and checkpoint is not None:
        try:
            results.update(checkpoint.load())
            results = {host: result for host, result in results.items() if host in subdomains}
            if results:
                log_success(f"Checkpoint retomado  [bold green]{len(results)} hosts[/bold green]")
        except (OSError, ValueError) as exc:
            parser.error(f"checkpoint inválido: {exc}")

    pending_hosts = [host for host in subdomains if host not in results]
    cancellation = CancellationToken(args.scan_timeout)
    rate_limiter = RateLimiter(args.rate_limit)
    try:
        preflight = _run_go_preflight(args, pending_hosts, target.custom_port)
    except GoEngineError as exc:
        parser.error(f"falha no motor Go: {exc}")

    progress_columns = [
        SpinnerColumn(
            spinner_name="dots" if console_supports("⠋") else "line",
            style="bold cyan",
        ),
        TextColumn("[bold white]{task.description}"),
    ]
    if console_supports("━"):
        progress_columns.append(
            BarColumn(
                bar_width=PROGRESS_BAR_WIDTH,
                style="cyan",
                complete_style="green",
            )
        )
    progress_columns.extend(
        [
            MofNCompleteColumn(),
            TextColumn("|"),
            TimeElapsedColumn(),
            TextColumn("| [red]impactos {task.fields[impacts]}[/red]"),
        ]
    )

    with Progress(
        *progress_columns,
        console=console,
        transient=False,
        disable=not console_supports("⠋"),
    ) as progress:
        task_id = progress.add_task(
            f"[cyan]{target.clean_target}[/cyan]",
            total=len(pending_hosts),
            impacts=sum(len(result.impacts) for result in results.values()),
        )

        try:
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(
                        scan_host, sub, not args.no_portscan,
                        progress, task_id, args.only_impacts, args.proxy,
                        target.custom_port, target.clean_target,
                        getattr(args, 'hunt_assets', False),
                        auth_cookies, auth_headers,
                        getattr(args, 'download_dir', 'output/sourcemaps'),
                        getattr(args, 'smuggling', False),
                        getattr(args, 'ssrf', False),
                        getattr(args, 'nuclei', False),
                        getattr(args, 'fuzz_files', False),
                        getattr(args, 'test_api', False),
                        getattr(args, 'screenshot', False),
                        getattr(args, 'werkzeug_dos', False),
                        getattr(args, 'external_audit', False),
                        preflight.get(sub),
                        rate_limiter,
                        cancellation,
                    ): sub
                    for sub in pending_hosts
                }
                for future in as_completed(futures):
                    sub = futures[future]
                    try:
                        result = future.result()
                        results[sub] = result
                        if checkpoint is not None:
                            checkpoint.record(result)
                        progress.update(
                            task_id,
                            impacts=sum(len(item.impacts) for item in results.values()),
                        )
                    except Exception as exc:
                        log_error(f"[THREAD] [bold]{sub}[/bold]  error: {exc}")

        except KeyboardInterrupt:
            cancellation.cancel()
            for future in futures:
                future.cancel()
            log_warning("Scan interrupted by user — saving partial results...")

    if checkpoint is not None and len(results) == len(subdomains):
        checkpoint.finalize()

    console.print("")

    # ── Phase 3: Recon Delta & Export ──────────────────────────────────
    from core.exporter import compare_recon_delta, save_scan_history
    delta = compare_recon_delta(target.clean_target, results)
    
    if any(delta.values()):
        console.print(Rule("[bold yellow]RECON DELTA — ALTERAÇÕES EM RELAÇÃO AO SCAN ANTERIOR[/bold yellow]", style="yellow"))
        console.print("")
        if delta["new_hosts"]:
            log_warning(f"[NOVO HOST DETECTADO] {len(delta['new_hosts'])} novos subdomínios descobertos:")
            for nh in delta["new_hosts"][:10]:
                console.print(f"   -> [bold green]+ {nh}[/bold green]")
        if delta["new_ports"]:
            log_warning("[NOVA PORTA ABERTA] Novas portas identificadas:")
            for np in delta["new_ports"]:
                console.print(f"   -> [bold red]+ {np}[/bold red]")
        if delta["status_changes"]:
            log_info("[MUDANÇA DE STATUS HTTP]:")
            for sc in delta["status_changes"]:
                console.print(f"   -> [bold cyan]~ {sc}[/bold cyan]")
        console.print("")

    export_results(target.clean_target, results)
    save_scan_history(target.clean_target, results)

    # ── Phase 4: Summary Table ─────────────────────────────────────────
    console.print(Rule("[bold green]PHASE 4  —  SUMMARY[/bold green]", style="green"))
    print_summary_table(results)

    # ── Phase 5: Impact Breakdown (re-print flagged hosts) ────────────
    flagged = {h: r for h, r in results.items() if r.impacts}
    if flagged:
        console.print(Rule("[bold red]PHASE 5  —  HOSTS WITH IMPACTS[/bold red]", style="red"))
        console.print("")
        for host, res in flagged.items():
            print_realtime_host_tree(res)
    else:
        log_success("No security impacts identified across all scanned hosts.")
        console.print("")


if __name__ == "__main__":
    main()
