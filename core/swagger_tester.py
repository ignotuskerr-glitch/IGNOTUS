"""
ingotus/core/swagger_tester.py

Swagger / OpenAPI Schema Auto-Explorer & Auth Bypass Auditor.
1. Probes common OpenAPI/Swagger definition endpoints.
2. Parses paths, HTTP methods, and required parameters.
3. Tests endpoints without auth headers to identify unauthenticated sensitive endpoints / BOLA candidates.
"""

import json
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from core.config import PROBE_TIMEOUT, USER_AGENT

SWAGGER_SCHEMA_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/docs/openapi.json",
]

SENSITIVE_KEYWORDS = [
    "user", "account", "admin", "token", "auth", "credential",
    "password", "secret", "payment", "billing", "config", "key",
    "upload", "delete", "export", "dump", "log", "file"
]

def audit_swagger_endpoints(base_url: str, proxy: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Discovers Swagger/OpenAPI schemas, parses routes, and audits sensitive paths.
    """
    findings: List[Dict[str, Any]] = []
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": USER_AGENT}

    schema_data = None
    schema_url = None

    for path in SWAGGER_SCHEMA_PATHS:
        target = urljoin(base_url, path)
        try:
            r = requests.get(target, headers=headers, timeout=PROBE_TIMEOUT, verify=False, proxies=proxies)
            if r.status_code == 200 and ("application/json" in r.headers.get("Content-Type", "") or r.text.strip().startswith("{")):
                try:
                    parsed = r.json()
                    if "paths" in parsed or "openapi" in parsed or "swagger" in parsed:
                        schema_data = parsed
                        schema_url = target
                        break
                except Exception:
                    continue
        except Exception:
            continue

    if not schema_data:
        return findings

    paths_dict = schema_data.get("paths", {})
    total_endpoints = len(paths_dict)
    unauth_sensitive_paths = []

    for route, methods in paths_dict.items():
        if not isinstance(methods, dict):
            continue

        is_sensitive = any(kw in route.lower() for kw in SENSITIVE_KEYWORDS)
        
        for method, details in methods.items():
            if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                continue

            test_endpoint = urljoin(base_url, route)
            try:
                # Probe endpoint without auth token
                resp = requests.request(
                    method.upper(),
                    test_endpoint,
                    headers=headers,
                    timeout=PROBE_TIMEOUT,
                    verify=False,
                    proxies=proxies,
                    allow_redirects=False
                )

                if resp.status_code == 200:
                    unauth_sensitive_paths.append({
                        "route": route,
                        "method": method.upper(),
                        "url": test_endpoint,
                        "sensitive": is_sensitive,
                        "summary": details.get("summary", "") if isinstance(details, dict) else ""
                    })
            except Exception:
                continue

    # Formulate Finding
    if unauth_sensitive_paths:
        critical_sensitive = [p for p in unauth_sensitive_paths if p["sensitive"]]
        sev = "HIGH" if critical_sensitive else "MEDIUM"
        
        routes_summary = "\n".join([f"  - [{p['method']}] {p['url']} (Sensível: {p['sensitive']})" for p in unauth_sensitive_paths[:10]])
        
        findings.append({
            "severity": sev,
            "desc": f"Swagger/OpenAPI: {len(unauth_sensitive_paths)} endpoints acessíveis sem autenticação (de {total_endpoints} mapeados)",
            "evidence": (
                f"Schema OpenAPI Encontrado: {schema_url}\n"
                f"Total de Endpoints Mapeados: {total_endpoints}\n"
                f"Endpoints Acessíveis Sem Autenticação: {len(unauth_sensitive_paths)}\n\n"
                f"Amostra de Endpoints Vulneráveis:\n{routes_summary}\n\n"
                f"PoC cURL:\n"
                f"  curl -sk '{schema_url}'\n"
                f"  curl -sk '{unauth_sensitive_paths[0]['url']}' -X {unauth_sensitive_paths[0]['method']}"
            ),
            "poc": f"curl -sk '{unauth_sensitive_paths[0]['url']}' -X {unauth_sensitive_paths[0]['method']}"
        })
    else:
        findings.append({
            "severity": "INFO",
            "desc": f"Swagger/OpenAPI Definition Exposta: {total_endpoints} endpoints mapeados",
            "evidence": (
                f"Schema OpenAPI Público: {schema_url}\n"
                f"Total de Endpoints Mapeados: {total_endpoints}\n"
                f"Nota: Todos os endpoints testados exigiram autenticação ou retornaram códigos de proteção."
            ),
            "poc": f"curl -sk '{schema_url}'"
        })

    return findings
