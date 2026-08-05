import os
import json
from typing import Dict
from core.config import OUTPUT_DIR, SEVERITY_ORDER, SEVERITY_TAGS
from core.models import HostResult


def export_json(results: Dict[str, HostResult], filepath: str) -> None:
    """Export HostResult objects to a structured JSON file."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                {host: res.to_dict() for host, res in results.items()},
                f,
                indent=2,
                ensure_ascii=False,
            )
    except Exception:
        pass


def _deduplicate_impacts(all_impacts):
    """
    Group repetitive LOW severity findings (e.g. 300x Permissions-Policy missing on subdomains).
    Returns (deduped_impacts_for_table_and_poc, total_original_counts).
    """
    deduped = []
    low_groups = {}  # desc -> list of (host, imp)

    for host, imp in all_impacts:
        if imp.severity == "LOW":
            desc_key = imp.description
            if desc_key not in low_groups:
                low_groups[desc_key] = []
            low_groups[desc_key].append((host, imp))
        else:
            deduped.append((host, imp))

    # Process grouped LOWs
    for desc_key, items in low_groups.items():
        if len(items) <= 3:
            deduped.extend(items)
        else:
            # Keep first 3 as representative, combine the rest
            first_three = items[:3]
            deduped.extend(first_three)

            total_count = len(items)
            extra_count = total_count - 3
            representative_host = items[0][0]
            base_imp = items[0][1]

            summary_imp_desc = f"{desc_key} (afeta +{extra_count} outros subdomínios semelhantes)"
            combined_hosts_str = ", ".join([h for h, _ in items[3:]])
            summary_evidence = (
                f"Este impacto de baixa severidade foi identificado em um total de {total_count} hosts.\n"
                f"Primeiros 3 hosts listados acima ({', '.join([h for h, _ in first_three])}).\n\n"
                f"Outros {extra_count} subdomínios afetados:\n{combined_hosts_str}\n\n"
                f"Evidência de referência ({representative_host}):\n{base_imp.evidence}"
            )

            from core.models import Impact
            grouped_imp = Impact(
                severity="LOW",
                description=summary_imp_desc,
                evidence=summary_evidence,
                cvss_score=base_imp.cvss_score,
                cvss_vector=base_imp.cvss_vector,
            )
            deduped.append((f"+{extra_count} hosts", grouped_imp))

    return deduped


def export_markdown_report(
    domain: str,
    results: Dict[str, HostResult],
    filepath: str,
) -> None:
    """
    Generate a structured Markdown recon + security impact report.
    Severity ordering and emoji badges are read from config.py constants
    (SEVERITY_ORDER, SEVERITY_EMOJI) — no hardcoded values in this file.
    """
    # ── 1. Aggregate stats ──────────────────────────────────────────────────────
    total_hosts             = len(results)
    active_hosts            = sum(1 for r in results.values() if r.dns.ips or r.http.status)
    all_impacts             = []
    origin_leaks_count      = 0
    subdomain_takeovers_count = 0
    open_ports_count        = 0
    cdn_count               = 0
    waf_count               = 0

    for res in results.values():
        if "CDN" in res.classification:
            cdn_count += 1
        elif "WAF" in res.classification:
            waf_count += 1

        origin_leaks_count += len(res.leaks)
        open_ports_count   += len(res.ports)

        for imp in res.impacts:
            if "Takeover" in imp.description:
                subdomain_takeovers_count += 1
            all_impacts.append((res.host, imp))

    all_impacts.sort(key=lambda x: SEVERITY_ORDER.get(x[1].severity, 99))

    # Apply LOW finding deduplication
    display_impacts = _deduplicate_impacts(all_impacts)
    display_impacts.sort(key=lambda x: SEVERITY_ORDER.get(x[1].severity, 99))


    # ── 2. Build Markdown ───────────────────────────────────────────────────────
    md = []

    md.append(f"# Relatório de Reconhecimento & Impacto de Segurança: {domain}")
    md.append("*Gerado automaticamente pelo Ignotus Recon*")
    md.append("")
    md.append("## 1. Resumo Executivo")
    md.append("")
    md.append(
        "Este relatório documenta a análise de superfície de ataque e levantamento de "
        "ativos para o domínio alvo. Os dados são estruturados para facilitar a elaboração "
        "manual de relatórios de pentest e avaliação de riscos."
    )
    md.append("")

    # Summary table
    md.append("| Métrica | Total |")
    md.append("| :--- | :--- |")
    md.append(f"| Subdomínios Mapeados | **{total_hosts}** |")
    md.append(f"| Hosts Ativos | **{active_hosts}** |")
    md.append(f"| Subdomínios Vulneráveis a Takeover | **{subdomain_takeovers_count}** |")
    md.append(f"| IPs de Origem Expostos (Direct Exposure) | **{origin_leaks_count}** |")
    md.append(f"| Total de Portas Abertas Identificadas | **{open_ports_count}** |")
    md.append(f"| Hosts atrás de CDN | **{cdn_count}** |")
    md.append(f"| Hosts atrás de WAF | **{waf_count}** |")
    md.append("")

    # Impact counts — derived from SEVERITY_ORDER keys (no hardcoded list)
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for _, imp in all_impacts:
        counts[imp.severity] = counts.get(imp.severity, 0) + 1

    md.append("### Severidade dos Impactos Validados")
    md.append("")
    sev_labels = {
        "CRITICAL": "Crítico",
        "HIGH":     "Alto",
        "MEDIUM":   "Médio",
        "LOW":      "Baixo",
        "INFO":     "Informativo",
    }
    for sev in SEVERITY_ORDER:
        label = sev_labels.get(sev, sev)
        md.append(f"- **{label} ({sev}):** {counts.get(sev, 0)}")
    md.append("")
    md.append("---")
    md.append("")

    # ── Section 2: Impact table ─────────────────────────────────────────────────
    md.append("## 2. Tabela de Impactos Validados")
    md.append("")
    if not display_impacts:
        md.append("*Nenhum impacto de segurança com risco validado foi identificado.*")
    else:
        md.append("| Severidade | CVSS 3.1 | Host | Descrição |")
        md.append("| :--- | :--- | :--- | :--- |")
        for host, imp in display_impacts:
            tag      = SEVERITY_TAGS.get(imp.severity, f"[{imp.severity}]")
            sev_str  = f"**{tag}**"
            cvss_str = f"`{imp.cvss_score:.1f}`" if imp.cvss_score > 0 else "*N/A*"
            md.append(f"| {sev_str} | {cvss_str} | `{host}` | {imp.description} |")
    md.append("")
    md.append("---")
    md.append("")

    # ── Section 3: Detailed PoC & Steps to Reproduce ────────────────────────────
    md.append("## 3. Detalhamento de Impactos e Provas de Conceito (PoC)")
    md.append("")
    if not display_impacts:
        md.append("*Nenhum detalhamento disponível.*")
    else:
        for idx, (host, imp) in enumerate(display_impacts, 1):
            host_res = results.get(host)
            ip_info = ", ".join(host_res.dns.ips) if (host_res and host_res.dns and host_res.dns.ips) else "N/A"
            cname_info = host_res.dns.cname if (host_res and host_res.dns and host_res.dns.cname) else "Nenhum"
            server_info = host_res.http.server if (host_res and host_res.http and host_res.http.server) else "N/A"

            md.append(f"### 3.{idx} [{imp.severity}] {imp.description} — `{host}`")
            md.append("")
            md.append(f"- **Alvo / Subdomínio:** `{host}`")
            md.append(f"- **IP(s) Resolvido(s):** `{ip_info}`")
            md.append(f"- **CNAME:** `{cname_info}`")
            md.append(f"- **Servidor Web / Fingerprint:** `{server_info}`")
            md.append(f"- **Nível de Severidade:** **[{imp.severity}]**")
            if imp.cvss_score > 0:
                md.append(f"- **Pontuação CVSS 3.1:** `{imp.cvss_score:.1f}` (`{imp.cvss_vector}`)")
            md.append("")

            md.append("#### Passos para Reproduzir (Pronto para Bug Bounty):")
            md.append(f"1. Envie uma requisição HTTP para o host `{host}` (`{ip_info}`).")
            md.append("2. Utilize o comando de teste validado abaixo no terminal:")
            
            # Extract PoC cURL command if present in evidence or build a default one
            poc_cmd = f"curl -i -k -s 'https://{host}/'"
            if "PostgreSQL" in imp.description:
                poc_cmd = f"pg_isready -h {host} -p 5432"
            elif "porta alternativa" in imp.description or "reverse proxy" in imp.description:
                matching_service = next(
                    (service for service in (host_res.services if host_res else []) if service.kind == "http"),
                    None,
                )
                if matching_service:
                    poc_cmd = (
                        f"curl -i -k -s '{matching_service.protocol}://"
                        f"{host}:{matching_service.port}/'"
                    )
            for line in imp.evidence.splitlines():
                if line.strip().startswith("curl "):
                    poc_cmd = line.strip()
                    break
            
            md.append("```bash")
            md.append(poc_cmd)
            md.append("```")
            md.append("3. Observe a resposta da aplicação e a evidência capturada abaixo.")
            md.append("")
            md.append("#### Evidência Técnica / Logs de Execução:")
            md.append("```text")
            md.append(imp.evidence)
            md.append("```")
            md.append("")
            md.append("---")
    md.append("")

    # ── Section 4: Full host inventory ─────────────────────────────────────────
    md.append("## 4. Inventário Completo de Hosts")
    md.append("")
    md.append("| Host | CNAME | IPs Resolvidos | Status HTTP | Server Header | Classificação |")
    md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for host, res in results.items():
        ips_str    = ", ".join(res.dns.ips)   if res.dns.ips   else "*Nenhum*"
        cname_str  = f"`{res.dns.cname}`"     if res.dns.cname else "*Direto*"
        status_str = str(res.http.status)     if res.http.status else "*N/A*"
        server_str = res.http.server          or "*N/A*"
        md.append(
            f"| `{host}` | {cname_str} | {ips_str} | {status_str} "
            f"| {server_str} | {res.classification} ({res.confidence}%) |"
        )

    service_rows = [
        (host, service)
        for host, result in results.items()
        for service in result.services
    ]
    if service_rows:
        md.append("")
        md.append("## 5. Serviços com validação de protocolo")
        md.append("")
        md.append("| Host | Porta | Serviço | Protocolo | Status/Auth | TLS |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for host, service in service_rows:
            state = (
                f"HTTP {service.status}"
                if service.status is not None
                else service.auth_method or "N/A"
            )
            tls_state = (
                "sim" if service.tls_supported is True else
                "não" if service.tls_supported is False else "N/A"
            )
            md.append(
                f"| `{host}` | `{service.port}` | {service.kind} | "
                f"{service.protocol or 'N/A'} | {state} | {tls_state} |"
            )

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(md))
    except Exception:
        pass


def get_history_filepath(target_domain: str) -> str:
    """Returns the JSON file path for historical scan comparisons."""
    target_slug = target_domain.replace("*.", "").replace(".", "_").lower()
    return os.path.join(OUTPUT_DIR, "json", f"history_{target_slug}.json")


def compare_recon_delta(target_domain: str, current_results: Dict[str, HostResult]) -> Dict[str, list]:
    """
    Compares current scan results against the previous scan for the target domain.
    Returns:
        {"new_hosts": [...], "new_ports": [...], "status_changes": [...]}
    """
    history_path = get_history_filepath(target_domain)
    if not os.path.exists(history_path):
        return {"new_hosts": [], "new_ports": [], "status_changes": []}

    try:
        with open(history_path, "r", encoding="utf-8") as f:
            prev_data = json.load(f)
    except Exception:
        return {"new_hosts": [], "new_ports": [], "status_changes": []}

    new_hosts = []
    new_ports = []
    status_changes = []

    for host, res in current_results.items():
        if host not in prev_data:
            new_hosts.append(host)
        else:
            prev_host = prev_data[host]
            # Check for new open ports
            prev_ports = set(p[0] if isinstance(p, (list, tuple)) else p for p in prev_host.get("ports", []))
            curr_ports = set(p[0] for p in res.ports)
            added_ports = curr_ports - prev_ports
            if added_ports:
                new_ports.append(f"{host}:{','.join(str(p) for p in added_ports)}")

            # Check for status changes
            prev_status = prev_host.get("http", {}).get("status")
            curr_status = res.http.status if res.http else None
            if prev_status != curr_status and prev_status is not None:
                status_changes.append(f"{host} (HTTP {prev_status} ➔ {curr_status})")

    return {
        "new_hosts": new_hosts,
        "new_ports": new_ports,
        "status_changes": status_changes,
    }


def save_scan_history(target_domain: str, current_results: Dict[str, HostResult]) -> None:
    """Saves current scan results as historical baseline for future diffs."""
    history_path = get_history_filepath(target_domain)
    export_json(current_results, history_path)
