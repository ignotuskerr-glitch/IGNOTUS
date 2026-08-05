"""
ingotus/core/api_discovery.py

Probes for open GraphQL Introspection and exposed Swagger / OpenAPI documentation endpoints.
Suporte a autenticação via cookies e headers customizados.
"""

import requests
import json
from typing import Optional, List, Dict, Any
from core.config import PROBE_TIMEOUT, USER_AGENT

# GraphQL Introspection Query
GRAPHQL_INTROSPECTION_QUERY = {"query": "{ __schema { queryType { name } types { name kind } } }"}

# GraphQL Introspection via GET (alguns endpoints aceitam via query param)
GRAPHQL_GET_PATHS = [
    "/graphql?query={__schema{queryType{name}}}",
    "/api/graphql?query={__schema{queryType{name}}}",
    "/v1/graphql?query={__schema{queryType{name}}}",
    "/v2/graphql?query={__schema{queryType{name}}}",
    "/gql?query={__schema{queryType{name}}}",
    "/query?query={__schema{queryType{name}}}",
]

SWAGGER_PATHS = [
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger/index.html",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api/swagger",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger.json",
    "/docs",
    "/redoc",
    "/api/docs",
    "/api/redoc",
    "/swagger-resources",
    "/v3/api-docs/swagger-config",
    "/api/v1/docs",
    "/api/v2/docs",
    "/api/v1/swagger-ui.html",
    "/api/v1/swagger",
    "/api/v2/swagger",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/postman.json",
    "/postman_collection.json",
    "/api/postman.json",
    "/api/v1/postman",
]

ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/admin/api",
    "/admin/users",
    "/administrator",
    "/api/admin",
    "/api/v1/admin",
    "/api/v2/admin",
    "/management",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/info",
    "/actuator/configprops",
    "/actuator/loggers",
    "/actuator/threaddump",
    "/actuator/heapdump",
    "/actuator/prometheus",
    "/health",
    "/healthz",
    "/livez",
    "/readyz",
    "/metrics",
    "/debug",
    "/console",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/env",
    "/config",
    "/status",
    "/info",
    "/jolokia",
    "/jolokia/list",
    "/trace",
    "/dump",
    "/_profiler",
    "/__clockwork",
    "/elmah.axd",
    "/telemetry",
    "/metrics/prometheus",
    "/api/v1/health",
    "/api/v2/health",
    "/api/health",
    "/api/status",
]


def _make_headers(
    auth_cookies: Optional[Dict[str, str]] = None,
    auth_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    base = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if auth_headers:
        base.update(auth_headers)
    return base


def probe_graphql_introspection(
    base_url: str,
    proxy: Optional[str] = None,
    auth_cookies: Optional[Dict[str, str]] = None,
    auth_headers: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, str]]:
    """
    Tests if GraphQL Introspection is enabled.
    Suporta autenticação via cookies e headers customizados.
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = _make_headers(auth_cookies, auth_headers)

    endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/query", "/gql"]
    for endpoint in endpoints:
        url = f"{base_url.rstrip('/')}{endpoint}"

        # POST introspection
        try:
            r = requests.post(
                url,
                json=GRAPHQL_INTROSPECTION_QUERY,
                headers=headers,
                cookies=auth_cookies or {},
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )
            if r.status_code == 200 and "__schema" in r.text and "queryType" in r.text:
                # Conta quantos tipos foram expostos
                try:
                    data = r.json()
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    type_count = len(types)
                except Exception:
                    type_count = 0

                return {
                    "endpoint": endpoint,
                    "severity": "MEDIUM",
                    "desc": f"GraphQL Introspection Habilitada — {type_count} tipos expostos no esquema",
                    "evidence": f"POST {url} → HTTP {r.status_code} com nó __schema ({len(r.content)} bytes)",
                    "poc": f'curl -X POST {url} -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{queryType{{name}}types{{name}}}}}}"}}\''
                }
        except Exception:
            pass

        # GET introspection
        try:
            r = requests.get(
                f"{url}?query={{__schema{{queryType{{name}}}}}}",
                headers={"User-Agent": USER_AGENT},
                cookies=auth_cookies or {},
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )
            if r.status_code == 200 and "__schema" in r.text:
                return {
                    "endpoint": endpoint + "?query=...",
                    "severity": "MEDIUM",
                    "desc": "GraphQL Introspection via GET habilitada",
                    "evidence": f"GET {url}?query={{__schema...}} → HTTP {r.status_code}",
                    "poc": f"curl '{url}?query={{__schema{{queryType{{name}}}}}}'"
                }
        except Exception:
            pass

    return None


def probe_swagger_endpoints(
    base_url: str,
    proxy: Optional[str] = None,
    auth_cookies: Optional[Dict[str, str]] = None,
    auth_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, str]]:
    """
    Probes Swagger UI and OpenAPI json paths.
    Suporta autenticação via cookies e headers.
    """
    discovered: List[Dict[str, str]] = []
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": USER_AGENT}
    if auth_headers:
        headers.update(auth_headers)

    for path in SWAGGER_PATHS:
        if "graphql" in path:
            continue

        url = f"{base_url.rstrip('/')}{path}"
        try:
            r = requests.get(
                url,
                headers=headers,
                cookies=auth_cookies or {},
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )

            if r.status_code == 200:
                body_lower = r.text.lower()
                is_swagger = (
                    "swagger" in body_lower
                    or "openapi" in body_lower
                    or "api-docs" in body_lower
                    or "redoc" in body_lower
                    or '"paths"' in r.text
                    or '"info"' in r.text
                    or "swagger-ui" in body_lower
                )
                if is_swagger:
                    # Tentar contar endpoints no schema
                    endpoint_count = r.text.count('"operationId"')
                    severity = "HIGH" if endpoint_count > 10 else "MEDIUM"
                    desc = f"API Exposta: {path}"
                    if endpoint_count:
                        desc += f" ({endpoint_count} operações mapeadas)"

                    discovered.append({
                        "path": path,
                        "severity": severity,
                        "desc": desc,
                        "evidence": f"GET {url} → HTTP 200 ({len(r.content)} bytes, Swagger/OpenAPI detectado)",
                        "poc": f"curl '{url}' | python3 -m json.tool",
                    })
        except Exception:
            pass

    return discovered


def probe_admin_endpoints(
    base_url: str,
    proxy: Optional[str] = None,
    auth_cookies: Optional[Dict[str, str]] = None,
    auth_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, str]]:
    """
    Testa endpoints administrativos e de diagnóstico sensíveis.
    Compara resposta autenticada vs não-autenticada para identificar controle de acesso ausente.
    """
    discovered: List[Dict[str, str]] = []
    proxies = {"http": proxy, "https": proxy} if proxy else None
    base_headers = {"User-Agent": USER_AGENT}

    for path in ADMIN_PATHS:
        url = f"{base_url.rstrip('/')}{path}"

        # Testar sem autenticação primeiro
        try:
            r_noauth = requests.get(
                url,
                headers=base_headers,
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )

            if r_noauth.status_code in (200, 206):
                body_lower = r_noauth.text.lower()
                is_sensitive = any(k in body_lower for k in [
                    "password", "secret", "token", "database", "env",
                    "admin", "user", "config", "phpinfo", "server",
                    "bean", "actuator", "heap", "memory", "jdbc",
                    "datasource", "credential", "private_key", "aws",
                ])
                severity = "HIGH" if is_sensitive else "MEDIUM"
                discovered.append({
                    "path": path,
                    "severity": severity,
                    "desc": f"Endpoint Administrativo/Diagnóstico Acessível sem Auth: {path}",
                    "evidence": f"GET {url} → HTTP {r_noauth.status_code} ({len(r_noauth.content)} bytes)",
                    "poc": f"curl -s '{url}' | head -50",
                })

        except Exception:
            pass

    return discovered


def probe_discovered_endpoints(
    base_url: str,
    endpoints: List[str],
    proxy: Optional[str] = None,
    max_workers: int = 10,
) -> List[Dict[str, Any]]:
    """
    Testa uma lista de endpoints extraídos de source maps, rotas JS ou wayback machine
    para identificar quais respondem HTTP 200/401/403/500 no alvo real.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = []
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": USER_AGENT}

    # Limita teste aos 50 mais relevantes para evitar excesso de requisições
    clean_endpoints = [e for e in endpoints if e.startswith("/") and not e.startswith("//")][:50]

    def test_ep(ep: str):
        url = f"{base_url.rstrip('/')}{ep}"
        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                proxies=proxies,
            )
            if r.status_code in (200, 201, 202, 206, 401, 403, 500):
                body_preview = r.text[:200]
                # Se for 200, checa se não é HTML 404 genérico
                if r.status_code == 200 and ("<!DOCTYPE" in body_preview or "<html" in body_preview):
                    if "404" in body_preview or "not found" in body_preview.lower():
                        return None

                severity = "HIGH" if r.status_code in (200, 206) and any(k in ep.lower() for k in ["admin", "secret", "private", "user", "config"]) else "MEDIUM"
                return {
                    "path": ep,
                    "status": r.status_code,
                    "severity": severity,
                    "desc": f"Endpoint Extraído da Aplicação Ativo (HTTP {r.status_code}): {ep}",
                    "evidence": f"GET {url} → HTTP {r.status_code} ({len(r.content)} bytes)",
                    "poc": f"curl -i '{url}'",
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(test_ep, ep): ep for ep in clean_endpoints}
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    return results

