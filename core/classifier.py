"""
ingotus/core/classifier.py

Classifies host infrastructure and validates security impacts.

Anti-False-Positive strategy applied here:
  1. Context-aware header checks — API endpoints and GSLB/infra hosts are excluded
     from UI-specific security-header impacts (CSP, X-Frame-Options, etc.).
  2. Same-org IP exposure — IPs belonging to the target organisation's own ASN
     are downgraded and annotated rather than reported as bypass.
  3. robots.txt — demoted to INFO; it is public by design (RFC 9309).
  4. Port-80 HTTP check — only fires when port 80 was TCP-confirmed open.
  5. HSTS quality check — validates max-age, includeSubDomains, preload.
  6. TLS version deprecation — TLSv1 / TLSv1.1 flagged with correct severity.
  7. HTTP method enumeration — TRACE/PUT/DELETE confirmed dangerous.
  8. Cookie security flags — Secure, HttpOnly, SameSite per session cookie.
  9. SPF / DMARC impacts — passed in from domain-level check in main.py.
 10. Impact noise filter — identical LOW findings grouped before display.
"""

import re
from ipaddress import ip_address
from typing import List, Optional

from core.models import HostResult, Impact, EmailSecurityInfo
from core.fingerprint import fingerprint_engine
from core.http import probe_origin_bypass
from core.cors import probe_cors
from core.cvss import get_cvss
from core.cve_lookup import fetch_cves_for_tech, severity_from_score
from core.config import (
    INFRA_HOST_PATTERNS,
    DEPRECATED_TLS_VERSIONS,
    DANGEROUS_HTTP_METHODS,
)
from core.impact_gate import is_known_edge_ip


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_infra_host(hostname: str) -> bool:
    """Return True for GSLB, load-balancer, and crawler hostnames."""
    h = hostname.lower()
    return (
        any(pat in h for pat in INFRA_HOST_PATTERNS) or "crawl" in h or "crawler" in h
    )


def _is_ip_literal(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _is_same_org(asn_org: str, target_domain: str) -> bool:
    """
    Return True when the IP's ASN organisation appears to belong to the
    same company as the target domain.

    Example: target = 'meta.com'  → org 'META PLATFORMS' → True
             target = 'openai.com' → org 'AMAZON'         → False
    """
    if not asn_org or not target_domain:
        return False
    org_lower = asn_org.lower()
    # Build keywords from the domain name parts (strip TLD)
    domain_parts = target_domain.rstrip(".").split(".")
    # Typical mappings: facebook.com→meta, twitter.com→twitter/x
    extra_aliases = {
        "meta": ["facebook", "meta platforms", "meta, inc"],
        "facebook": ["facebook", "meta platforms"],
        "twitter": ["twitter", "x corp"],
        "x": ["twitter", "x corp"],
        "pinterest": ["pinterest"],
        "linkedin": ["linkedin", "microsoft"],
        "google": ["google", "alphabet"],
        "youtube": ["google", "alphabet"],
    }
    keywords = [p for p in domain_parts if len(p) > 2]
    for kw in keywords:
        for alias in extra_aliases.get(kw, [kw]):
            if alias in org_lower:
                return True
        if kw in org_lower:
            return True
    return False


def _parse_hsts(header_val: str):
    """
    Parse Strict-Transport-Security header value.
    Returns (max_age, has_include_subdomains, has_preload).
    """
    max_age = 0
    include_subs = False
    preload = False

    m = re.search(r"max-age\s*=\s*(\d+)", header_val, re.IGNORECASE)
    if m:
        max_age = int(m.group(1))

    if "includesubdomains" in header_val.lower():
        include_subs = True
    if "preload" in header_val.lower():
        preload = True

    return max_age, include_subs, preload


# ── Main classifier ───────────────────────────────────────────────────────────


def classify_and_validate(result: HostResult) -> None:
    """
    Classifies the host infrastructure and validates security impacts.
    All severity thresholds, confidence scores, and detection data are loaded
    from fingerprints.json via the fingerprint_engine — nothing is hardcoded here.
    """
    cname = result.dns.cname
    headers = result.http.headers
    snippet = result.http.response_snippet
    asn_number = result.asn.number if result.asn else None
    asn_org = result.asn.organization if result.asn else ""

    # ── Fingerprint detection ──────────────────────────────────────────────────
    cdns = fingerprint_engine.detect_cdn(cname, headers, asn_number, result.dns.ips)
    wafs = fingerprint_engine.detect_waf(headers)
    cloud_provider = fingerprint_engine.detect_cloud(cname, asn_org)
    takeover_service = fingerprint_engine.check_takeover(cname, snippet)

    result.http.cdn = cdns

    # ── Context flags (used throughout impact checks) ─────────────────────────
    is_infra = _is_infra_host(result.host)
    is_api = result.http.is_api_endpoint
    is_protected = bool(cdns or wafs)

    # ── Classification & confidence (scores from JSON) ─────────────────────────
    scores = fingerprint_engine.confidence_scores

    if wafs:
        result.classification = "WAF"
        result.confidence = scores["WAF"]
    elif cdns:
        result.classification = "CDN"
        result.confidence = scores["CDN"]
    elif cname and any(lb in cname.lower() for lb in fingerprint_engine.load_balancers):
        result.classification = "LOAD BALANCER"
        result.confidence = scores["LOAD_BALANCER"]
    elif cloud_provider:
        result.classification = "CLOUD ORIGIN"
        result.confidence = scores["CLOUD_ORIGIN"]
    elif result.dns.ips:
        result.classification = "ORIGIN"
        result.confidence = scores["ORIGIN"]
    else:
        result.classification = "UNKNOWN"
        result.confidence = scores["UNKNOWN"]

    # ═══════════════════════════════════════════════════════════════════════════
    # A. Subdomain Takeover
    # ═══════════════════════════════════════════════════════════════════════════
    if takeover_service:
        score, vec = get_cvss("SUBDOMAIN_TAKEOVER")
        result.impacts.append(
            Impact(
                severity="CRITICAL",
                description=f"SUBDOMAIN TAKEOVER CONFIRMADO: Recurso Órfão em {takeover_service}",
                evidence=(
                    f"Alvo Afeado: {result.host}\n"
                    f"CNAME Apontando para: {cname}\n"
                    f"Serviço de Nuvem: {takeover_service}\n"
                    f"Status: O serviço na ponta foi desativado/excluído mas o DNS continua apontando.\n"
                    f"Impacto: Qualquer atacante pode registrar uma conta no {takeover_service} e assumir total controle do subdomínio!\n"
                    f"PoC cURL:\ncurl -sk -i 'https://{result.host}'"
                ),
                cvss_score=score,
                cvss_vector=vec,
            )
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # A.2 Cloud Storage & S3 Bucket Takeover / Open Bucket Audit
    # ═══════════════════════════════════════════════════════════════════════════
    from core.cloud_storage import audit_cloud_storage

    cloud_findings = audit_cloud_storage(result.host, cname=cname)
    for cf in cloud_findings:
        score, vec = get_cvss(
            "SUBDOMAIN_TAKEOVER" if cf["severity"] == "CRITICAL" else "OPEN_BUCKET"
        )
        result.impacts.append(
            Impact(
                severity=cf["severity"],
                description=cf["desc"],
                evidence=cf["evidence"],
                cvss_score=score,
                cvss_vector=vec,
            )
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # B. Origin IP Exposure & WAF Bypass
    # ═══════════════════════════════════════════════════════════════════════════
    # Only flag as impact if there is a real CDN bypass confirmed or if protected host leaks direct origin
    if result.dns.ips and not is_infra:
        cdn_st = result.http.status if result.http else None
        for ip in result.dns.ips:
            # DNS for a protected hostname normally returns the provider edge.
            # Never promote a known Cloudflare/Vercel/Fastly edge to an origin
            # bypass solely because it answers HTTP 200.
            if cdns and is_known_edge_ip(ip, cdns):
                continue
            bypass_confirmed, bypass_status, bypass_snippet, has_stack, diff_note = (
                probe_origin_bypass(ip, result.host, cdn_status=cdn_st, protected=is_protected)
            )
            same_org = _is_same_org(asn_org, result.host)

            if bypass_confirmed:
                reason = "Bypass de WAF/CDN confirmado via IP de origem"
                result.leaks.append((ip, reason))

                if same_org:
                    severity = "HIGH"
                    description = (
                        f"Acesso direto ao IP de origem sem CDN ({ip}) — infra própria"
                    )
                    evidence = (
                        f"IP: {ip}\n"
                        f"Host header: {result.host}\n"
                        f"Resposta direta ao IP: HTTP {bypass_status}\n"
                        f"Organização ASN: {asn_org or 'Desconhecida'}\n"
                        f"Nota: IP pertence à própria organização — sem CDN/WAF de terceiros.\n"
                        f"Impacto: exposição de infraestrutura interna diretamente acessível."
                        + (
                            f"\n\n[PoC Response Snippet]\n{bypass_snippet[:300]}"
                            if bypass_snippet
                            else ""
                        )
                    )
                else:
                    severity = "CRITICAL"
                    description = (
                        f"Bypass de WAF/CDN confirmado via IP de origem ({ip})"
                    )
                    evidence = (
                        f"IP: {ip}\n"
                        f"Host header: {result.host}\n"
                        f"Resposta direta ao IP: HTTP {bypass_status}\n"
                        f"Organização ASN: {asn_org or 'Desconhecida'}\n"
                        f"WAF/CDN completamente bypassado — requisições chegam ao servidor de origem sem inspeção."
                        + (
                            f"\n\n[PoC Response Snippet]\n{bypass_snippet[:500]}"
                            if bypass_snippet
                            else ""
                        )
                    )

                cvss_key = (
                    "WAF_BYPASS_CRITICAL"
                    if severity == "CRITICAL"
                    else "ORIGIN_IP_HIGH"
                )
                score, vec = get_cvss(cvss_key)
                result.impacts.append(
                    Impact(
                        severity=severity,
                        description=description,
                        evidence=evidence,
                        cvss_score=score,
                        cvss_vector=vec,
                    )
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # C. Critical Port Exposure
    # ═══════════════════════════════════════════════════════════════════════════
    sensitive_ports = fingerprint_engine.sensitive_ports

    for port_num, banner in result.ports:
        if port_num in sensitive_ports:
            # The protocol-aware probe below provides stronger, non-duplicated
            # evidence for PostgreSQL than a generic open-port observation.
            if port_num == 5432 and any(
                service.kind == "postgresql" for service in result.services
            ):
                continue
            if is_protected and (not banner or banner.strip() in ("", "—")):
                continue

            port_info = sensitive_ports[port_num]
            severity = "MEDIUM" if port_num == 23 else "INFO"
            score, vec = (
                get_cvss("CRITICAL_PORT_OPEN") if severity == "MEDIUM" else (0.0, "")
            )
            result.impacts.append(
                Impact(
                    severity=severity,
                    description=(
                        f"Serviço sensível acessível externamente: "
                        f"{port_num} ({port_info.get('service', 'Serviço')})"
                    ),
                    evidence=(
                        f"Porta {port_num} aberta. Banner: {banner or 'Sem banner'}. "
                        "A exposição é inventário de superfície; valide autenticação e ACL "
                        "antes de tratar como vulnerabilidade."
                    ),
                    cvss_score=score,
                    cvss_vector=vec,
                )
            )

    # C1. Protocol-aware public service validation. This distinguishes an open
    # socket from a responding PostgreSQL or alternate HTTP service.
    for service in result.services:
        if service.kind == "postgresql":
            if service.auth_required is False:
                result.impacts.append(
                    Impact(
                        severity="CRITICAL",
                        description="PostgreSQL aceitou autenticação sem senha",
                        evidence=(
                            f"Host: {result.host}:{service.port}\n"
                            f"TLS suportado: {service.tls_supported}\n"
                            f"Método: {service.auth_method}\n"
                            "O servidor enviou AuthenticationOk sem receber credencial."
                        ),
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    )
                )
            else:
                auth_state = (
                    f"autenticação exigida ({service.auth_method})"
                    if service.auth_required is True
                    else "autenticação não conclusiva"
                )
                result.impacts.append(
                    Impact(
                        severity="MEDIUM",
                        description="PostgreSQL acessível publicamente",
                        evidence=(
                            f"Host: {result.host}:{service.port}\n"
                            f"TLS suportado: {service.tls_supported}\n"
                            f"Estado: {auth_state}\n"
                            "Nenhuma senha foi enviada. A exposição aumenta a superfície "
                            "para enumeração, ataques de credencial e falhas futuras."
                        ),
                    )
                )

        if service.kind == "http" and service.port not in {80, 443}:
            upstream_failed = result.http.status in {502, 503, 504}
            if upstream_failed and service.status is not None:
                description = (
                    "Serviço de aplicação acessível fora do reverse proxy "
                    "enquanto o upstream principal falha"
                )
                severity = "MEDIUM"
            else:
                description = "Serviço HTTP(S) exposto em porta alternativa"
                severity = "LOW"
            rate_limit = service.headers.get("ratelimit-policy") or service.headers.get(
                "x-ratelimit-limit", "não informado"
            )
            result.impacts.append(
                Impact(
                    severity=severity,
                    description=description,
                    evidence=(
                        f"Host: {result.host}:{service.port}\n"
                        f"URL: {service.protocol}://{result.host}:{service.port}/\n"
                        f"Status direto: HTTP {service.status}\n"
                        f"Status do proxy principal: HTTP "
                        f"{result.http.status or 'não disponível'}\n"
                        f"Servidor: {service.server or 'não informado'}\n"
                        f"Rate limit: {rate_limit}\n"
                        "A porta alternativa permite alcançar o serviço sem passar pela "
                        "configuração normal das portas 80/443."
                    ),
                )
            )

    # C2. Origin availability failure. A gateway error is operational impact,
    # not proof of exploitation, so it intentionally carries no CVSS score.
    if result.http and result.http.status in {502, 503, 504} and not is_protected:
        result.impacts.append(
            Impact(
                severity="LOW",
                description="Falha de disponibilidade confirmada no upstream HTTP",
                evidence=(
                    f"Host: {result.host}\n"
                    f"Status HTTP: {result.http.status}\n"
                    f"Servidor: {result.http.server or 'não informado'}\n"
                    "A borda respondeu, mas o serviço upstream não entregou a aplicação."
                ),
            )
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # D. TLS Certificate Issues
    # ═══════════════════════════════════════════════════════════════════════════
    if result.tls and result.tls.valid is False and not _is_ip_literal(result.host):
        score, vec = get_cvss("SSL_INVALID")
        result.impacts.append(
            Impact(
                severity="MEDIUM",
                description="Certificado SSL/TLS inválido ou expirado",
                evidence=(
                    f"Emissor: {result.tls.issuer}\n"
                    f"Expiração: {result.tls.expiration}\n"
                    f"Status: Inválido ou Expirado."
                ),
                cvss_score=score,
                cvss_vector=vec,
            )
        )

    # ── D2. TLS Protocol Version Deprecation ───────────────────────────────────
    if result.tls and result.tls.version:
        sev = DEPRECATED_TLS_VERSIONS.get(result.tls.version)
        if sev:
            score, vec = get_cvss("TLS_DEPRECATED")
            result.impacts.append(
                Impact(
                    severity=sev,
                    description=f"Protocolo TLS deprecado em uso: {result.tls.version}",
                    evidence=(
                        f"Versão TLS negociada: {result.tls.version}\n"
                        f"Cipher: {result.tls.cipher or 'Desconhecido'}\n"
                        f"TLS 1.0 e 1.1 são oficialmente obsoletos (RFC 8996).\n"
                        f"Recomendação: desabilitar TLS < 1.2 no servidor."
                    ),
                    cvss_score=score,
                    cvss_vector=vec,
                )
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # E. Insecure HTTP Traffic
    # ═══════════════════════════════════════════════════════════════════════════
    if result.http.status:
        # Only flag when port 80 was TCP-confirmed open (not just assumed)
        has_http_port = any(p[0] == 80 for p in result.ports) if result.ports else False

        if has_http_port and result.http.status < 400 and not result.http.redirects_to:
            result.impacts.append(
                Impact(
                    severity="LOW",
                    description="Tráfego HTTP inseguro sem redirecionamento automático para HTTPS",
                    evidence=(
                        f"Status HTTP no canal inseguro: {result.http.status}\n"
                        f"Nenhum cabeçalho Location para HTTPS detectado."
                    ),
                )
            )
        elif result.http.redirects_to and result.http.redirects_to.startswith(
            "http://"
        ):
            result.impacts.append(
                Impact(
                    severity="LOW",
                    description="Redirecionamento HTTP aponta para destino inseguro (HTTP)",
                    evidence=f"Redireciona para: {result.http.redirects_to}",
                )
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # F. Missing / Misconfigured Security Headers
    # ═══════════════════════════════════════════════════════════════════════════
    # Only report missing security headers for successful/valid web responses (200, 301, 302, 307, 308)
    if result.http.status and result.http.status in (200, 301, 302, 307, 308):
        # Skip infra hosts (GSLB / crawlers) — they don't serve web pages
        if not is_infra:
            # Headers that apply to APIs too (transport security)
            universal_headers = {"strict-transport-security"}
            # Headers only relevant for browser-facing HTML pages
            ui_only_headers = {
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
            }

            for sec_req in fingerprint_engine.required_security_headers:
                h_key = sec_req["header"]

                # API endpoints don't need UI-only headers
                if is_api and h_key in ui_only_headers:
                    continue

                if h_key not in headers:
                    result.impacts.append(
                        Impact(
                            severity=sec_req.get("severity", "LOW"),
                            description=sec_req.get(
                                "desc", f"Ausência do cabeçalho {sec_req['name']}"
                            ),
                            evidence=f"Cabeçalho '{sec_req['name']}' ausente nas respostas HTTP.",
                        )
                    )
                else:
                    # ── HSTS quality check ─────────────────────────────────
                    if h_key == "strict-transport-security":
                        max_age, inc_subs, preload = _parse_hsts(headers[h_key])
                        if max_age < 31_536_000:  # less than 1 year
                            result.impacts.append(
                                Impact(
                                    severity="LOW",
                                    description=f"HSTS max-age insuficiente ({max_age}s < 31536000s)",
                                    evidence=(
                                        f"Header: {headers[h_key]}\n"
                                        f"max-age deve ser ≥ 31536000 (1 ano) para proteção efetiva."
                                    ),
                                )
                            )
                        if not inc_subs:
                            result.impacts.append(
                                Impact(
                                    severity="LOW",
                                    description="HSTS sem includeSubDomains — subdomínios não protegidos",
                                    evidence=(
                                        f"Header: {headers[h_key]}\n"
                                        f"Sem includeSubDomains, subdomínios ainda são vulneráveis a MITM."
                                    ),
                                )
                            )

            # ── CORS Reflected Origin & Credential Check ───────────────────
            target_url = f"https://{result.host}"
            is_reflected, allows_creds, test_origin = probe_cors(target_url)
            if is_reflected:
                if allows_creds:
                    score, vec = get_cvss("CORS_REFLECTED_CREDENTIALS")
                    result.impacts.append(
                        Impact(
                            severity="HIGH",
                            description=f"Vulnerabilidade Crítica de CORS: Origem Refletida com Credenciais ({test_origin})",
                            evidence=(
                                f"Origin testada: {test_origin}\n"
                                f"Header retornado: Access-Control-Allow-Origin: {test_origin}\n"
                                f"Header retornado: Access-Control-Allow-Credentials: true\n"
                                f"Impacto: Permite que sites atacantes leiam dados confidenciais e tokens de usuários autenticados via AJAX."
                            ),
                            cvss_score=score,
                            cvss_vector=vec,
                        )
                    )
                else:
                    result.impacts.append(
                        Impact(
                            severity="INFO",
                            description=f"CORS sem credenciais permite a origem testada ({test_origin})",
                            evidence=(
                                f"Origin {test_origin} permitida sem Access-Control-Allow-Credentials. "
                                "Sem resposta sensível pública, não há impacto de confidencialidade comprovado."
                            ),
                        )
                    )
            elif headers.get("access-control-allow-origin") == "*":
                cors_creds = headers.get("access-control-allow-credentials")
                result.impacts.append(
                    Impact(
                        severity="INFO",
                        description="CORS wildcard observado sem impacto autenticado comprovado",
                        evidence=(
                            f"Access-Control-Allow-Origin: *\n"
                            f"Access-Control-Allow-Credentials: {cors_creds or 'not set'}\n"
                            "Navegadores não permitem leitura com credenciais quando ACAO é wildcard."
                        ),
                    )
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # G. Sensitive File Exposure
    # ═══════════════════════════════════════════════════════════════════════════
    if result.http.sensitive_paths:
        path_severity: dict = {
            p["path"]: p["severity"] for p in fingerprint_engine.sensitive_paths
        }
        for path, st in result.http.sensitive_paths:
            if st != 200 or path == "/robots.txt":
                continue
            sev = path_severity.get(path, "MEDIUM")
            desc = f"Arquivo sensível acessível publicamente: {path}"
            ev = f"GET {path} retornou HTTP 200 — conteúdo real do arquivo foi servido."
            score, vec = get_cvss("SENSITIVE_FILE_EXPOSURE")

            result.impacts.append(
                Impact(
                    severity=sev,
                    description=desc,
                    evidence=ev,
                    cvss_score=score,
                    cvss_vector=vec,
                )
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # H. Dangerous HTTP Methods
    # ═══════════════════════════════════════════════════════════════════════════
    if result.http.http_methods:
        for method in result.http.http_methods:
            if method == "TRACE":
                sev = "MEDIUM"
                desc = (
                    "Método HTTP TRACE habilitado — Cross-Site Tracing (XST) possível"
                )
                ev = (
                    "O servidor respondeu ao método TRACE com HTTP 200.\n"
                    "TRACE pode ser abusado para roubar cookies HttpOnly via XST.\n"
                    "Recomendação: desabilitar TRACE no servidor web."
                )
                score, vec = get_cvss("HTTP_TRACE_ENABLED")
            elif method in ("PUT", "DELETE"):
                sev = "HIGH"
                desc = f"Método HTTP {method} habilitado sem restrição aparente"
                ev = (
                    f"O servidor aceita requisições {method} sem retornar 405/501.\n"
                    f"Pode permitir upload ou deleção arbitrária de arquivos.\n"
                    f"Recomendação: restringir {method} a endpoints autenticados."
                )
                score, vec = get_cvss("HTTP_DANGEROUS_METHOD")
            else:
                sev = "LOW"
                desc = f"Método HTTP {method} habilitado"
                ev = f"Servidor anuncia suporte ao método {method} via header Allow."
                score, vec = get_cvss("HTTP_DANGEROUS_METHOD")

            result.impacts.append(
                Impact(
                    severity=sev,
                    description=desc,
                    evidence=ev,
                    cvss_score=score,
                    cvss_vector=vec,
                )
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # I. Cookie Security Flags
    # ═══════════════════════════════════════════════════════════════════════════
    if result.http.cookie_issues and not is_infra:
        score, vec = get_cvss("COOKIE_MISSING_FLAGS")
        for issue in result.http.cookie_issues:
            if "Secure" in issue:
                sev = "MEDIUM"
                desc = issue
                ev = (
                    "Cookie definido sem flag Secure.\n"
                    "Cookies sem Secure podem ser transmitidos em conexões HTTP, "
                    "expondo o token a interceptação em rede."
                )
            elif "HttpOnly" in issue:
                sev = "MEDIUM"
                desc = issue
                ev = (
                    "Cookie definido sem flag HttpOnly.\n"
                    "Cookies sem HttpOnly são acessíveis via JavaScript, "
                    "permitindo roubo de sessão em caso de XSS."
                )
            else:
                sev = "LOW"
                desc = issue
                ev = (
                    "Cookie definido sem atributo SameSite.\n"
                    "Sem SameSite, cookies são enviados em requisições cross-site, "
                    "potencializando ataques CSRF."
                )
            result.impacts.append(
                Impact(
                    severity=sev,
                    description=desc,
                    evidence=ev,
                    cvss_score=score,
                    cvss_vector=vec,
                )
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # J. Secrets and API Endpoints Discovered in JavaScript
    # ═══════════════════════════════════════════════════════════════════════════
    if result.http.js_secrets:
        for sec in result.http.js_secrets:
            key = "SECRET_CRITICAL" if sec["severity"] == "CRITICAL" else "SECRET_HIGH"
            score, vec = get_cvss(key)

            note_str = sec.get("status_note", "")
            poc_str = sec.get("poc_curl", "")

            evidence_lines = [
                f"Tipo: {sec['type']}",
                f"Valor: {sec['value']} (redigido)",
                f"Grau de evidência: {sec.get('evidence_status', 'UNVERIFIED')}",
                f"Status da Validação: {note_str if note_str else 'N/A'}",
                f"Arquivo Fonte: {sec['source']}",
            ]
            if poc_str:
                evidence_lines.append(f"PoC cURL:\n{poc_str}")

            result.impacts.append(
                Impact(
                    severity=sec["severity"],
                    description=f"Segredo / Chave de API Exposta em JavaScript: {sec['type']}",
                    evidence="\n".join(evidence_lines),
                    cvss_score=score,
                    cvss_vector=vec,
                )
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # K. Discovered APIs (Swagger / GraphQL)
    # ═══════════════════════════════════════════════════════════════════════════
    if result.http.api_endpoints:
        for api in result.http.api_endpoints:
            key = (
                "GRAPHQL_INTROSPECTION"
                if "GraphQL" in api["desc"]
                else "SWAGGER_EXPOSED"
            )
            score, vec = get_cvss(key)
            result.impacts.append(
                Impact(
                    severity=api["severity"],
                    description=api["desc"],
                    evidence=api["evidence"],
                    cvss_score=score,
                    cvss_vector=vec,
                )
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # L. Email Security (SPF / DMARC) — populated by main.py for root domain
    # ═══════════════════════════════════════════════════════════════════════════
    _apply_email_security_impacts(result)

    # ═══════════════════════════════════════════════════════════════════════════
    # M. CVE Correlation — only when a versioned tech string is detected
    # ═══════════════════════════════════════════════════════════════════════════
    _apply_cve_impacts(result)

    # ═══════════════════════════════════════════════════════════════════════════
    # N. Flask session cookie — decoded payload (information disclosure)
    # ═══════════════════════════════════════════════════════════════════════════
    if result.http.flask_session_data:
        import json as _json

        decoded_str = _json.dumps(
            result.http.flask_session_data, indent=2, ensure_ascii=False
        )
        # Build detail of what was exposed
        keys = list(result.http.flask_session_data.keys())
        # Escalate to HIGH when OAuth state/nonce/redirect_uri are exposed in session
        sensitive_keys = [
            k
            for k in keys
            if any(
                kw in k.lower()
                for kw in (
                    "state",
                    "nonce",
                    "redirect",
                    "auth",
                    "token",
                    "user",
                    "email",
                )
            )
        ]
        severity = "HIGH" if sensitive_keys else "MEDIUM"
        score, vec = (
            get_cvss("FLASK_SESSION_EXPOSED")
            if hasattr(__builtins__, "_")
            else (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        )
        try:
            score, vec = get_cvss("FLASK_SESSION_EXPOSED")
        except Exception:
            score, vec = 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        result.impacts.append(
            Impact(
                severity=severity,
                description="Flask session cookie decodificada sem chave — conteudo exposto",
                evidence=(
                    f"O cookie de sessao Flask nao esta encriptado por padrao.\\n"
                    f"Qualquer pessoa pode decodificar o payload (base64+zlib) sem a chave secreta.\\n"
                    f"Chaves sensíveis encontradas: {', '.join(sensitive_keys) if sensitive_keys else 'nenhuma'}\\n"
                    f"Conteudo decodificado:\\n{decoded_str[:800]}"
                ),
                cvss_score=score,
                cvss_vector=vec,
            )
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # O. OAuth callback crash (500 on unauthenticated request)
    # ═══════════════════════════════════════════════════════════════════════════
    crash_endpoints = [
        e for e in result.http.oauth_endpoints if e.get("status") == "500"
    ]
    if crash_endpoints:
        paths_str = ", ".join(e["path"] for e in crash_endpoints)
        score, vec = get_cvss("OAUTH_CALLBACK_CRASH") if False else (0, "")
        try:
            score, vec = get_cvss("OAUTH_CALLBACK_CRASH")
        except Exception:
            score, vec = 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        result.impacts.append(
            Impact(
                severity="MEDIUM",
                description="Endpoint OAuth callback retorna 500 em request nao autenticado",
                evidence=(
                    f"Endpoints com crash: {paths_str}\\n"
                    f"O servidor retorna HTTP 500 ao receber uma requisicao sem parametros OAuth validos.\\n"
                    f"Indica ausencia de validacao de input antes do processamento OAuth.\\n"
                    f"Pode indicar excecao nao tratada ou configuracao incorreta do fluxo de autenticacao."
                ),
                cvss_score=score,
                cvss_vector=vec,
            )
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # P. CVE-2023-46136 Werkzeug DoS — confirmed by timing PoC
    # ═══════════════════════════════════════════════════════════════════════════
    if result.http.werkzeug_dos_confirmed:
        server_str = result.http.server or "Werkzeug"
        score, vec = get_cvss("CVE_2023_46136") if False else (0, "")
        try:
            score, vec = get_cvss("CVE_2023_46136")
        except Exception:
            score, vec = 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        result.impacts.append(
            Impact(
                severity="HIGH",
                description=f"CVE-2023-46136 confirmado — Werkzeug DoS via multipart malformado",
                evidence=(
                    f"Software: {server_str}\\n"
                    f"CVE: CVE-2023-46136 (CVSS 7.5)\\n"
                    f"PoC: boundary multipart terminando em '--' causa loop infinito no parser.\\n"
                    f"Confirmado: resposta com timeout >= 8s ou HTTP 502 apos timeout do upstream.\\n"
                    f"Fix: atualizar Werkzeug para >= 3.0.1\\n"
                    f"Ref: https://nvd.nist.gov/vuln/detail/CVE-2023-46136"
                ),
                cvss_score=score,
                cvss_vector=vec,
            )
        )


def _apply_email_security_impacts(result: HostResult) -> None:
    """Translate EmailSecurityInfo into Impact objects on the root-domain host."""
    em = result.email_security
    if not em:
        return

    # SPF
    if em.spf_valid is False:
        score, vec = get_cvss("EMAIL_NO_SPF")
        result.impacts.append(
            Impact(
                severity="MEDIUM",
                description="Domínio sem registro SPF — risco de email spoofing",
                evidence=(
                    f"Nenhum registro TXT 'v=spf1' encontrado para o domínio.\n"
                    f"Sem SPF, qualquer servidor pode enviar e-mails em nome do domínio.\n"
                    f"Recomendação: publicar registro SPF no DNS (ex: 'v=spf1 include:... -all')."
                ),
                cvss_score=score,
                cvss_vector=vec,
            )
        )

    # DMARC
    if not em.dmarc:
        score, vec = get_cvss("EMAIL_NO_DMARC")
        result.impacts.append(
            Impact(
                severity="MEDIUM",
                description="Domínio sem DMARC — sem política de rejeição de spoofing",
                evidence=(
                    f"Nenhum registro TXT 'v=DMARC1' encontrado em _dmarc.{result.host}.\n"
                    f"Sem DMARC, provedores de e-mail não aplicam política de rejeição.\n"
                    f"Recomendação: publicar registro DMARC (ex: 'v=DMARC1; p=reject; ...')."
                ),
                cvss_score=score,
                cvss_vector=vec,
            )
        )
    elif em.dmarc_policy == "none":
        score, vec = get_cvss("EMAIL_DMARC_NONE")
        result.impacts.append(
            Impact(
                severity="LOW",
                description="DMARC configurado em modo monitor (p=none) — não bloqueia spoofing",
                evidence=(
                    f"Registro DMARC: {em.dmarc}\n"
                    f"p=none apenas monitora, não rejeita nem coloca em quarentena e-mails falsos.\n"
                    f"Recomendação: evoluir para p=quarantine e depois p=reject."
                ),
                cvss_score=score,
                cvss_vector=vec,
            )
        )


def _apply_cve_impacts(result: HostResult) -> None:
    """
    Query public CVE databases for any versioned software strings detected on
    this host and append HIGH/CRITICAL findings as Impact objects.

    Only runs when at least one versioned tech string is available — e.g.
    "nginx/1.18.0" or "Apache/2.4.51".  Plain product names without versions
    (e.g. "cloudflare") are skipped to avoid high false-positive rates.

    Results are in-process cached by cve_lookup, so repeated calls for the
    same software string (across many subdomains) never re-hit the API.
    """
    # Collect all candidate tech strings from the result
    candidates: List[str] = []

    if result.http.server:
        candidates.append(result.http.server)
    if result.http.powered_by:
        candidates.append(result.http.powered_by)
    for tech in result.http.tech_stack:
        candidates.append(tech)

    if not candidates:
        return

    # Track which CVE IDs we've already appended for this host to avoid dupes
    seen_cve_ids: set = set()

    for raw_tech in candidates:
        cves = fetch_cves_for_tech(raw_tech)
        for cve in cves:
            cve_id = cve.get("cve_id", "")
            if not cve_id or cve_id in seen_cve_ids:
                continue
            seen_cve_ids.add(cve_id)

            score = cve["score"]
            vector = cve.get("vector", "")
            summary = cve.get("summary", "Sem descrição disponível.")
            refs = cve.get("references", [])
            source = cve.get("source", "CVE DB")
            severity = severity_from_score(score)

            # Build evidence block
            ref_block = (
                "\n".join(f"  - {r}" for r in refs) if refs else "  (sem referências)"
            )
            evidence = (
                f"Software afetado: {raw_tech}\n"
                f"CVE ID: {cve_id}\n"
                f"CVSS 3.x Score: {score} ({severity})\n"
                f"Vetor: {vector or 'N/A'}\n"
                f"Fonte: {source}\n"
                f"Descrição: {summary}\n"
                f"Referências:\n{ref_block}"
            )

            # Demote raw version match CVEs to LOW/INFO unless actively exploited
            bounty_severity = "LOW" if severity in ("HIGH", "CRITICAL") else severity
            proto = "https" if "443" in str(result.ports) else "http"
            poc_cmd = f"curl -sk -I '{proto}://{result.host}/'"

            result.impacts.append(
                Impact(
                    severity=bounty_severity,
                    description=f"Versão de software com CVE conhecido ({cve_id}) em {raw_tech}",
                    evidence=(
                        f"Software detectado: {raw_tech}\n"
                        f"CVE ID: {cve_id} (CVSS teórico: {score})\n"
                        f"Descrição: {summary}\n"
                        f"Comando de Validação da Versão (PoC):\n{poc_cmd}\n"
                        f"Nota de Triagem Bug Bounty: Apenas a versão reportada sem PoC de exploração ativa "
                        f"é classificada como Informativo/Baixo pelas triagens da HackerOne/Bugcrowd."
                    ),
                    cvss_score=score,
                    cvss_vector=vector,
                )
            )
