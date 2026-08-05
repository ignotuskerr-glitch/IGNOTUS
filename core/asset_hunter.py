"""
ingotus/core/asset_hunter.py

Descobre e baixa todos os tipos de ativos expostos em um alvo web:
  - Source Maps (.js.map, .css.map) e arquivos internos referenciados
  - Arquivos de configuração (.env, config.json, config.yml, etc.)
  - Schemas de API (swagger.json, openapi.json, graphql schema)
  - Arquivos de pacote (package.json, package-lock.json, yarn.lock)
  - Exposição Git (.git/HEAD, .git/config, .git/FETCH_HEAD)
  - Arquivos de CI/CD (.travis.yml, Dockerfile, docker-compose.yml)
  - Backups e arquivos temporários (.bak, .old, .backup, ~)
  - Arquivos WebPack/Vite de debug (stats.json, build-manifest.json)
  - IDE e editor (.vscode/settings.json, .idea/workspace.xml)
"""

import re
import os
import json
import requests
import urllib.parse
from typing import Optional, List, Dict, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import PROBE_TIMEOUT, USER_AGENT
from core.path_safety import safe_output_path
from core.asset_catalog import ASSET_CATEGORIES as OPERATIONAL_ASSET_CATEGORIES
from core.redaction import redact_text


# ── Asset categories with paths and severity ──────────────────────────────────

_LEGACY_INLINE_ASSET_CATEGORIES: Dict[str, Dict] = {
    "git_exposure": {
        "severity": "HIGH",
        "desc": "Repositório Git Exposto",
        "paths": [
            "/.git/HEAD",
            "/.git/config",
            "/.git/COMMIT_EDITMSG",
            "/.git/FETCH_HEAD",
            "/.git/index",
            "/.git/packed-refs",
            "/.git/refs/heads/main",
            "/.git/refs/heads/master",
            "/.git/logs/HEAD",
        ],
        "validators": [lambda t: any(k in t for k in ["ref:", "HEAD", "[core]", "gitdir"])],
    },
    "env_files": {
        "severity": "CRITICAL",
        "desc": "Arquivo de Ambiente (.env) com Segredos Exposto",
        "paths": [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/.env.staging",
            "/.env.backup",
            "/.env.old",
            "/.env.example",
            "/config/.env",
            "/backend/.env",
            "/api/.env",
        ],
        "validators": [lambda t: any(k in t.upper() for k in ["SECRET", "KEY", "TOKEN", "PASSWORD", "DATABASE", "API_"])],
    },
    "config_files": {
        "severity": "MEDIUM",
        "desc": "Arquivo de Configuração Exposto",
        "paths": [
            "/config.json",
            "/config.yml",
            "/config.yaml",
            "/settings.json",
            "/settings.yml",
            "/app.config.json",
            "/appsettings.json",
            "/appsettings.Development.json",
            "/web.config",
            "/database.yml",
            "/database.json",
            "/application.yml",
            "/application.properties",
            "/secrets.json",
            "/credentials.json",
        ],
        "validators": [],
    },
    "package_files": {
        "severity": "LOW",
        "desc": "Arquivo de Dependências Exposto (package.json / yarn.lock)",
        "paths": [
            "/package.json",
            "/package-lock.json",
            "/yarn.lock",
            "/composer.json",
            "/composer.lock",
            "/Gemfile",
            "/Gemfile.lock",
            "/requirements.txt",
            "/Pipfile",
            "/go.mod",
            "/go.sum",
            "/pom.xml",
            "/build.gradle",
        ],
        "validators": [],
    },
    "api_schemas": {
        "severity": "MEDIUM",
        "desc": "Schema de API Exposto (Swagger/OpenAPI/GraphQL)",
        "paths": [
            "/swagger.json",
            "/swagger.yaml",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/v1/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/graphql/schema",
            "/schema.graphql",
            "/__schema",
            "/api/swagger.json",
        ],
        "validators": [lambda t: any(k in t for k in ["swagger", "openapi", "paths", "__schema", "queryType"])],
    },
    "ci_cd_files": {
        "severity": "LOW",
        "desc": "Arquivo de CI/CD ou Container Exposto",
        "paths": [
            "/.travis.yml",
            "/.github/workflows/main.yml",
            "/.github/workflows/deploy.yml",
            "/.circleci/config.yml",
            "/Dockerfile",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/.dockerignore",
            "/Jenkinsfile",
            "/azure-pipelines.yml",
        ],
        "validators": [],
    },
    "webpack_debug": {
        "severity": "MEDIUM",
        "desc": "Arquivo de Debug de Build (Webpack/Vite Stats) Exposto",
        "paths": [
            "/build/asset-manifest.json",
            "/build/stats.json",
            "/dist/stats.json",
            "/webpack-stats.json",
            "/build-manifest.json",
            "/__webpack_hmr",
            "/sockjs-node/info",
            "/vite-manifest.json",
            "/.vite/manifest.json",
            "/manifest.json",
        ],
        "validators": [],
    },
    "ide_files": {
        "severity": "LOW",
        "desc": "Arquivo de IDE Exposto",
        "paths": [
            "/.vscode/settings.json",
            "/.vscode/launch.json",
            "/.idea/workspace.xml",
            "/.idea/dataSources.xml",
            "/.idea/dataSources.local.xml",
        ],
        "validators": [],
    },
    "backup_files": {
        "severity": "MEDIUM",
        "desc": "Arquivo de Backup ou Temporário Exposto",
        "paths": [
            "/backup.sql",
            "/backup.tar.gz",
            "/database.sql",
            "/db.sql",
            "/dump.sql",
            "/backup.zip",
            "/site.zip",
            "/www.zip",
            "/html.zip",
            "/index.php.bak",
            "/config.php.bak",
            "/config.php.old",
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php.save",
            "/wp-config.php.txt",
            "/web.config.bak",
            "/settings.py.bak",
        ],
        "validators": [],
    },
    "database_dumps": {
        "severity": "CRITICAL",
        "desc": "Dump de Banco de Dados Exposto",
        "paths": [
            "/dump.sql",
            "/db_backup.sql",
            "/backup.sql.gz",
            "/database.sql.gz",
            "/mysql.sql",
            "/postgres.sql",
            "/data.sql",
            "/export.sql",
            "/full_backup.sql",
            "/.sql",
            "/db.dump",
            "/mongodb.bson",
            "/mongo.dump",
        ],
        "validators": [lambda t: any(k in t.lower() for k in ["create table", "insert into", "dump", "postgresql", "mysql"])],
    },
    "log_files": {
        "severity": "MEDIUM",
        "desc": "Arquivo de Log Exposto",
        "paths": [
            "/error.log",
            "/access.log",
            "/debug.log",
            "/app.log",
            "/laravel.log",
            "/storage/logs/laravel.log",
            "/var/log/nginx/error.log",
            "/logs/error.log",
            "/logs/access.log",
            "/wp-content/debug.log",
            "/.log",
            "/php_errors.log",
            "/application.log",
        ],
        "validators": [],
    },
    "private_keys": {
        "severity": "CRITICAL",
        "desc": "Chave Privada ou Certificado Exposto",
        "paths": [
            "/id_rsa",
            "/id_rsa.pub",
            "/.ssh/id_rsa",
            "/.ssh/id_ed25519",
            "/private.key",
            "/server.key",
            "/ssl.key",
            "/cert.key",
            "/.pem",
            "/key.pem",
            "/private.pem",
            "/server.pem",
            "/certificate.pem",
            "/.crt",
            "/.p12",
            "/.pfx",
        ],
        "validators": [lambda t: any(k in t for k in ["BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN CERTIFICATE"])],
    },
    "cms_config": {
        "severity": "HIGH",
        "desc": "Configuração de CMS/Framework Exposta",
        "paths": [
            "/wp-config.php",
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php.save",
            "/configuration.php",          # Joomla
            "/sites/default/settings.php", # Drupal
            "/config/database.php",
            "/app/config/parameters.yml",
            "/config/app.php",
            "/.htaccess",
            "/web.config",
            "/local.xml",                  # Magento
            "/app/etc/local.xml",
            "/config/secrets.yml",
        ],
        "validators": [lambda t: any(k in t.upper() for k in ["DB_PASSWORD", "DB_USER", "DATABASE", "SECRET", "PASSWORD"])],
    },
    "source_maps": {
        "severity": "MEDIUM",
        "desc": "Source Map Exposto (revela código fonte)",
        "paths": [
            "/main.js.map",
            "/app.js.map",
            "/bundle.js.map",
            "/static/js/main.*.js.map",
            "/dist/main.js.map",
            "/build/static/js/*.map",
            "/.map",
        ],
        "validators": [lambda t: '"version"' in t and '"sources"' in t],
    },
    "admin_panels": {
        "severity": "LOW",
        "desc": "Painel Administrativo ou Rota Sensível",
        "paths": [
            "/admin",
            "/administrator",
            "/wp-admin",
            "/phpmyadmin",
            "/pma",
            "/adminer.php",
            "/adminer",
            "/console",
            "/_debug",
            "/debug",
            "/actuator",           # Spring Boot
            "/actuator/env",
            "/actuator/health",
            "/server-status",
            "/server-info",
            "/.well-known/security.txt",
        ],
        "validators": [],
    },
    "vcs_exposure": {
        "severity": "HIGH",
        "desc": "Outros Sistemas de Versionamento Expostos",
        "paths": [
            "/.svn/entries",
            "/.svn/wc.db",
            "/.hg/hgrc",
            "/.hg/store",
            "/.bzr/README",
            "/CVS/Root",
            "/.git",
        ],
        "validators": [],
    },
    "cloud_config": {
        "severity": "HIGH",
        "desc": "Configuração de Cloud / Infraestrutura Exposta",
        "paths": [
            "/.aws/credentials",
            "/.aws/config",
            "/credentials",
            "/.s3cfg",
            "/s3.yml",
            "/terraform.tfstate",
            "/terraform.tfstate.backup",
            "/.terraform",
            "/ansible.cfg",
            "/inventory",
            "/.kube/config",
            "/kubeconfig",
        ],
        "validators": [lambda t: any(k in t for k in ["aws_access_key_id", "aws_secret_access_key", "AKIA", "-----BEGIN"])],
    },
    "cloud_storage_buckets": {
        "severity": "CRITICAL",
        "desc": "Buckets de Cloud Storage (S3 / Azure / GCP) Expostos",
        "paths": [
            "/?list-type=2",
            "/storage.json",
            "/s3_config.json",
            "/.gcloud/credentials.json",
        ],
        "validators": [lambda t: any(k in t for k in ["<ListBucketResult>", "ListBucketResult", "BucketName", "Contents"])],
    },
    "ai_ml_models": {
        "severity": "HIGH",
        "desc": "Arquivos de Modelos de IA / LLM / Vector DB Expostos",
        "paths": [
            "/model.onnx",
            "/pytorch_model.bin",
            "/model.safetensors",
            "/.langchain",
            "/vector_db",
            "/chroma.sqlite3",
            "/chroma/chroma.sqlite3",
        ],
        "validators": [],
    },
    "graphql_playground": {
        "severity": "MEDIUM",
        "desc": "Interface Interativa GraphQL Playground / GraphiQL Exposta",
        "paths": [
            "/graphiql",
            "/playground",
            "/altair",
            "/v1/graphiql",
            "/api/graphiql",
        ],
        "validators": [lambda t: any(k in t.lower() for k in ["graphiql", "graphql playground", "altair"])],
    },
    "sentry_config": {
        "severity": "LOW",
        "desc": "Configuração / DSN do Sentry Exposta",
        "paths": [
            "/.sentryclirc",
            "/sentry.json",
            "/sentry.properties",
        ],
        "validators": [],
    },
    "nextjs_build_manifests": {
        "severity": "MEDIUM",
        "desc": "Manifestos de Build Interno do Next.js / Turbopack Expostos",
        "paths": [
            "/_next/static/development/_devPagesManifest.json",
            "/_next/static/development/_buildManifest.js",
            "/_next/trace",
            "/_next/server/pages-manifest.json",
            "/_next/server/middleware-manifest.json",
        ],
        "validators": [],
    },
}

# The operational catalog is maintained outside this module.  The legacy
# inline mapping above is retained only as historical reference; runtime
# discovery always uses the validated external catalog.
ASSET_CATEGORIES = OPERATIONAL_ASSET_CATEGORIES

# Source map content types to look for in HTML/JS
SOURCE_MAP_COMMENT_PATTERN = re.compile(r'(?://|/\*)#\s*sourceMappingURL=([^\s\*]+)', re.MULTILINE)
JS_FILE_PATTERN = re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
CSS_FILE_PATTERN = re.compile(r'href=["\']([^"\']+\.css(?:\?[^"\']*)?)["\']', re.IGNORECASE)

# ── Deduplication: evita baixar o mesmo .map várias vezes em scans multi-subdomínio ──
# Guarda as URLs de source map já processadas nesta sessão.
_PROCESSED_MAP_URLS: set = set()


def _make_headers() -> Dict[str, str]:
    return {"User-Agent": USER_AGENT, "Accept": "*/*"}


def _probe_url(url: str, proxy: Optional[str] = None, timeout: int = PROBE_TIMEOUT) -> Optional[requests.Response]:
    """Make a GET request and return the response or None on failure."""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        r = requests.get(
            url, headers=_make_headers(),
            timeout=timeout, verify=False,
            allow_redirects=False, proxies=proxies
        )
        if r.status_code == 200 and len(r.content) > 10:
            return r
    except Exception:
        pass
    return None


def find_sourcemaps_in_page(base_url: str, html: str, proxy: Optional[str] = None) -> List[str]:
    """
    Scan HTML content for JS/CSS files and check each for exposed .map source maps.
    Also checks for //# sourceMappingURL= comments in inline scripts.
    Returns list of discovered source map URLs.
    """
    found_maps: List[str] = []
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Direct sourceMappingURL comments in HTML
    for match in SOURCE_MAP_COMMENT_PATTERN.findall(html):
        url = match.strip()
        if url.startswith("http"):
            found_maps.append(url)
        elif not url.startswith("data:"):
            found_maps.append(urllib.parse.urljoin(base_url, url))

    # JS files referenced in HTML
    js_files = JS_FILE_PATTERN.findall(html)
    css_files = CSS_FILE_PATTERN.findall(html)

    asset_urls = []
    for asset in js_files + css_files:
        if asset.startswith("http"):
            asset_urls.append(asset)
        else:
            asset_urls.append(urllib.parse.urljoin(base_url, asset))

    # For each asset, check if .map exists AND check sourceMappingURL in content
    def check_asset(asset_url: str):
        maps = []
        # 1. Probe .map directly
        map_url = asset_url.split("?")[0] + ".map"
        r = _probe_url(map_url, proxy)
        if r and '"sources"' in r.text:
            maps.append(map_url)

        # 2. Download JS/CSS and look for sourceMappingURL
        r2 = _probe_url(asset_url, proxy)
        if r2:
            for match in SOURCE_MAP_COMMENT_PATTERN.findall(r2.text):
                url = match.strip()
                if url.startswith("http"):
                    maps.append(url)
                elif not url.startswith("data:"):
                    # Relative to the JS file's path
                    maps.append(urllib.parse.urljoin(asset_url, url))
        return maps

    with ThreadPoolExecutor(max_workers=10) as ex:
        for result in ex.map(check_asset, asset_urls[:30]):
            found_maps.extend(result)

    return list(set(found_maps))


def download_sourcemap(map_url: str, output_dir: str, proxy: Optional[str] = None) -> Dict[str, Any]:
    """
    Download a source map and extract all referenced source files within it.
    Source maps can contain URLs to download even MORE source files:
      - sources[] array: paths to original .ts/.tsx/.js/.jsx files
      - sourceRoot: base URL prefix for all sources
      - External source files not embedded in sourcesContent

    Returns dict with stats and list of downloaded file paths.
    """
    result = {
        "map_url": map_url,
        "downloaded": False,
        "files_extracted": 0,
        "external_sources": [],
        "output_dir": output_dir,
        "error": None,
    }

    r = _probe_url(map_url, proxy)
    if not r:
        result["error"] = "URL inaccessível ou não retornou HTTP 200"
        return result

    try:
        data = r.json()
    except Exception:
        result["error"] = "Resposta não é JSON válido"
        return result

    sources: List[str] = data.get("sources", [])
    contents: List[Optional[str]] = data.get("sourcesContent", [])
    source_root: str = data.get("sourceRoot", "")

    if not sources:
        result["error"] = "Source map não contém 'sources'"
        return result

    result["downloaded"] = True
    count = 0

    for idx, src_path in enumerate(sources):
        content = contents[idx] if idx < len(contents) else None

        # Clean webpack/vite/parcel path prefixes
        clean = src_path
        for prefix in ["webpack://", "webpack:///", "vite://", "file://", "/_N_E/", "/turbopack/"]:
            clean = clean.replace(prefix, "")
        clean = clean.lstrip("/\\")
        parts = [p for p in clean.replace("\\", "/").split("/") if p and p != ".."]
        if not parts:
            continue

        target_path = safe_output_path(output_dir, "/".join(parts))
        if target_path is None:
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if content:
            with open(target_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(content)
            count += 1
        else:
            # Try to download the source file directly if no embedded content
            external_url = None
            if src_path.startswith("http"):
                external_url = src_path
            elif source_root:
                external_url = urllib.parse.urljoin(source_root.rstrip("/") + "/", src_path.lstrip("/"))
            else:
                # Try relative to the map URL
                base_of_map = map_url.rsplit("/", 1)[0]
                external_url = urllib.parse.urljoin(base_of_map + "/", src_path.lstrip("/"))

            if external_url:
                result["external_sources"].append(external_url)
                r2 = _probe_url(external_url, proxy)
                if r2:
                    with open(target_path, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(r2.text)
                    count += 1

    result["files_extracted"] = count
    return result


def hunt_assets(base_url: str, proxy: Optional[str] = None, download_dir: Optional[str] = None) -> List[Dict]:
    """
    Main entry point: scan all categories of exposed assets on a target.
    Returns list of Impact-compatible dicts for each discovered asset.
    """
    findings: List[Dict] = []
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Soft 404 Baseline check: fetch a non-existent path to record length
    random_404_url = urllib.parse.urljoin(base, "non_existent_path_soft404_test_8391.html")
    soft_404_len = -1
    try:
        r_404 = requests.get(random_404_url, headers=_make_headers(), timeout=PROBE_TIMEOUT, verify=False, proxies={"http": proxy, "https": proxy} if proxy else None, allow_redirects=False)
        if r_404.status_code == 200:
            soft_404_len = len(r_404.content)
    except Exception:
        pass

    def check_path(category_name: str, category: Dict, path: str):
        url = base + path
        r = _probe_url(url, proxy)
        if not r:
            return None

        body = r.text
        content_len = len(r.content)

        # Skip if response length matches the soft 404 baseline (within 10 bytes tolerance)
        if soft_404_len > 0 and abs(content_len - soft_404_len) < 10:
            return None

        # Skip HTML responses for non-HTML file requests (.env, .git, .sql, .zip, etc.)
        content_type = r.headers.get("Content-Type", "").lower()
        is_html_response = "text/html" in content_type or body.lstrip().startswith("<!DOCTYPE") or body.lstrip().startswith("<html")
        
        # If requesting a non-HTML file but got HTML back, reject it as a custom 404 page
        if is_html_response and not path.endswith(".php") and not path.endswith(".html") and "server-status" not in path:
            return None

        validators = category.get("validators", [])
        if validators and not any(v(body) for v in validators):
            return None

        finding = {
            "category": category_name,
            "url": url,
            "severity": category["severity"],
            "desc": category["desc"],
            "evidence": f"GET {url} → HTTP 200 ({content_len} bytes)",
            "content_preview": redact_text(body[:300]),
        }

        # If source map, extract it
        if category_name == "webpack_debug" and "asset-manifest" in path:
            finding["asset_type"] = "build_manifest"
        if download_dir and '"sources"' in body:
            finding["asset_type"] = "sourcemap"
            dl_result = download_sourcemap(url, download_dir, proxy)
            finding["sourcemap_download"] = dl_result

        return finding

    all_tasks = []
    for cat_name, cat_data in ASSET_CATEGORIES.items():
        for path in cat_data["paths"]:
            all_tasks.append((cat_name, cat_data, path))

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(check_path, cn, cd, p): (cn, p) for cn, cd, p in all_tasks}
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    return findings


def hunt_sourcemaps_deep(base_url: str, html_body: str, proxy: Optional[str] = None,
                          download_dir: Optional[str] = None) -> List[Dict]:
    """
    Deep source map discovery: finds maps referenced in HTML,
    downloads each map, extracts source files, and audits content for hardcoded secrets.
    Returns list of findings.

    Deduplication: source map URLs already processed in this session are skipped
    to prevent the same CDN bundle from being re-downloaded for every subdomain.
    """
    from core.sourcemap_auditor import audit_sourcemap_content, format_findings_as_evidence

    findings = []
    map_urls = find_sourcemaps_in_page(base_url, html_body, proxy)

    # Resolve the host-specific output subfolder once, used for all maps on this host
    host_netloc = urllib.parse.urlparse(base_url).netloc.replace(":", "_")

    for map_url in map_urls:
        # ── Deduplication: skip URLs already downloaded in this session ──────────
        # Strip query params so ?v=abc123 variants of the same file are also skipped
        canonical_map_url = map_url.split("?")[0]
        if canonical_map_url in _PROCESSED_MAP_URLS:
            # Still report the finding (it was already downloaded), but don't re-download
            finding = {
                "category": "sourcemap_exposed",
                "url": map_url,
                "severity": "INFO",
                "desc": "Exposição de JavaScript Source Map (.map) [já extraído]",
                "evidence": f"Source map já processado nesta sessão: {map_url}",
                "secrets_found": 0,
            }
            findings.append(finding)
            continue

        _PROCESSED_MAP_URLS.add(canonical_map_url)

        # Audit source map content for secrets
        audit_res = audit_sourcemap_content(map_url, proxy=proxy)
        has_secrets = audit_res.get("secrets_found", 0) > 0
        max_sev = audit_res.get("highest_severity", "HIGH")

        # A public source map alone is informational. Regex matches remain
        # candidates until a safe validator confirms validity and permissions.
        confirmed = int(audit_res.get("confirmed_findings", 0))
        supported = int(audit_res.get("supported_findings", 0))
        severity = "HIGH" if confirmed and max_sev in ("CRITICAL", "HIGH") else ("MEDIUM" if supported else "INFO")
        desc = "Possível segredo em Source Map (.map) — requer validação segura" if has_secrets else "Source Map público (.map) — exposição informativa"

        evidence_str = f"Source map encontrado em: {map_url}\n"
        if download_dir:
            # ── Output path: output/sourcemaps/DDMMYYYY/TARGET_GROUP/HOST/src/ ──
            # Prevent cross-contamination by grouping hosts by target domain
            from datetime import datetime
            date_folder = datetime.now().strftime("%d%m%Y")
            
            # Helper to extract group name (e.g., gov.br, uol.com.br, openai.com)
            parts = host_netloc.split(".")
            if len(parts) >= 2:
                # If tld is like .gov.br, .com.br, .co.uk
                if len(parts) >= 3 and parts[-2] in ("gov", "com", "net", "org", "edu", "co", "me"):
                    target_group = ".".join(parts[-3:])
                else:
                    target_group = ".".join(parts[-2:])
            else:
                target_group = host_netloc
            target_group = target_group.replace("*", "").replace(":", "_").strip(".")

            map_dir = os.path.join(download_dir, "sourcemaps", date_folder, target_group, host_netloc)
            dl = download_sourcemap(map_url, os.path.join(map_dir, "src"), proxy)
            evidence_str += f"Arquivos reconstruídos: {dl.get('files_extracted', 0)}\n"
            evidence_str += f"Pasta: {map_dir}\n"

        if has_secrets:
            evidence_str += "\n" + format_findings_as_evidence(audit_res)

        finding = {
            "category": "sourcemap_exposed",
            "url": map_url,
            "severity": severity,
            "desc": desc,
            "evidence": evidence_str,
            "secrets_found": audit_res.get("secrets_found", 0),
            "confirmed_findings": confirmed,
            "supported_findings": supported,
            "unverified_findings": int(audit_res.get("unverified_findings", 0)),
            "evidence_policy": audit_res.get("evidence_policy", "strict-impact-v2"),
        }
        findings.append(finding)

    return findings
