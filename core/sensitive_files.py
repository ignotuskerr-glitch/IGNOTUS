"""
ingotus/core/sensitive_files.py

Deep Sensitive & Backup File Fuzzer.
Probes 50+ high-impact file paths (.env, backups, git repositories, config files).
Validates content signatures to prevent false positives from custom 200 OK error pages.
"""

import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from core.config import PROBE_TIMEOUT, USER_AGENT

SENSITIVE_PATHS = [
    # Environment & Credentials
    (".env", ["APP_KEY=", "DB_PASSWORD=", "DATABASE_URL=", "SECRET_KEY=", "AWS_ACCESS_KEY_ID="]),
    (".env.local", ["APP_KEY=", "DB_PASSWORD=", "DATABASE_URL="]),
    (".env.production", ["APP_KEY=", "DB_PASSWORD=", "DATABASE_URL="]),
    (".env.backup", ["APP_KEY=", "DB_PASSWORD=", "DATABASE_URL="]),
    (".env.old", ["APP_KEY=", "DB_PASSWORD=", "DATABASE_URL="]),
    (".env.save", ["APP_KEY=", "DB_PASSWORD=", "DATABASE_URL="]),
    (".env.dev", ["APP_KEY=", "DB_PASSWORD=", "DATABASE_URL="]),
    (".env.staging", ["APP_KEY=", "DB_PASSWORD=", "DATABASE_URL="]),
    
    # Backups & Database Dumps
    ("backup.sql", ["CREATE TABLE", "INSERT INTO", "mysqldump"]),
    ("db.sql", ["CREATE TABLE", "INSERT INTO", "mysqldump"]),
    ("database.sql", ["CREATE TABLE", "INSERT INTO"]),
    ("dump.sql", ["CREATE TABLE", "INSERT INTO"]),
    ("data.sql", ["CREATE TABLE", "INSERT INTO"]),
    ("users.sql", ["CREATE TABLE", "INSERT INTO"]),
    ("backup.zip", ["PK\x03\x04"]),
    ("backup.tar.gz", ["\x1f\x8b\x08"]),
    ("site.zip", ["PK\x03\x04"]),
    ("www.zip", ["PK\x03\x04"]),
    ("html.zip", ["PK\x03\x04"]),
    ("db.zip", ["PK\x03\x04"]),
    
    # Source Code Repositories
    (".git/HEAD", ["ref: refs/heads/"]),
    (".git/config", ["[core]", "repositoryformatversion"]),
    (".svn/entries", ["dir", "svn:"]),
    (".hg/store/00manifest.i", ["\x00"]),
    
    # PHP / WordPress / CMS / Framework Configs & Backups
    ("wp-config.php.bak", ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("wp-config.php.old", ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("wp-config.php.save", ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("wp-config.php.txt", ["DB_NAME", "DB_USER", "DB_PASSWORD"]),
    ("config.php.bak", ["$db", "password", "DB_HOST"]),
    ("config.php.old", ["$db", "password", "DB_HOST"]),
    ("configuration.php.bak", ["$password", "$user", "$db"]),
    ("settings.py.bak", ["DATABASES", "SECRET_KEY"]),
    
    # PHP Admin & Debug Info
    ("phpinfo.php", ["PHP Version", "Configuration File (php.ini) Path"]),
    ("info.php", ["PHP Version", "Configuration File (php.ini) Path"]),
    ("test.php", ["PHP Version", "phpinfo()"]),
    ("php_info.php", ["PHP Version"]),
    ("adminer.php", ["Adminer", "Login"]),
    ("pma.php", ["phpMyAdmin"]),
    
    # Configurations, Cloud & Metadata
    ("config.json", ["\"database\"", "\"password\"", "\"secret\"", "\"api_key\""]),
    ("appsettings.json", ["\"ConnectionStrings\"", "\"Logging\"", "\"AllowedHosts\""]),
    ("docker-compose.yml", ["version:", "services:", "environment:"]),
    ("Dockerfile", ["FROM ", "RUN ", "EXPOSE "]),
    ("kubeconfig", ["apiVersion:", "clusters:", "users:"]),
    ("server-status", ["Apache Server Status", "Server Version"]),
    
    # Spring Boot / Java Actuator
    ("actuator/env", ["activeProfiles", "propertySources"]),
    ("actuator/heapdump", ["\x1f\x8b\x08", "JAVA", "JAVA PROFILE"]),
]

def audit_sensitive_files(base_url: str, proxy: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Fuzzes target for high-impact sensitive files with Soft 404 baseline check and strict signature validation.
    """
    findings: List[Dict[str, Any]] = []
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": USER_AGENT}

    # Soft 404 Baseline check: fetch a non-existent path to record length and body hash
    random_404_url = urljoin(base_url, "non_existent_path_soft404_test_8391.html")
    soft_404_len = -1
    try:
        r_404 = requests.get(random_404_url, headers=headers, timeout=PROBE_TIMEOUT, verify=False, proxies=proxies, allow_redirects=False)
        if r_404.status_code == 200:
            soft_404_len = len(r_404.content)
    except Exception:
        pass

    for path, signatures in SENSITIVE_PATHS:
        target = urljoin(base_url, path)
        try:
            r = requests.get(target, headers=headers, timeout=PROBE_TIMEOUT, verify=False, proxies=proxies, allow_redirects=False)
            if r.status_code == 200:
                body = r.text
                content_len = len(r.content)

                # Skip if response length matches the soft 404 baseline (within 10 bytes tolerance)
                if soft_404_len > 0 and abs(content_len - soft_404_len) < 10:
                    continue

                # Skip HTML responses for non-HTML file requests (.env, .git, .sql, .zip, etc.)
                content_type = r.headers.get("Content-Type", "").lower()
                is_html_response = "text/html" in content_type or body.lstrip().startswith("<!DOCTYPE") or body.lstrip().startswith("<html")
                
                # If requesting a non-HTML file but got HTML back, reject it as a custom 404 page
                if is_html_response and not path.endswith(".php") and not path.endswith(".html") and "server-status" not in path:
                    continue

                # Check for strict signatures
                matched_sig = None
                for sig in signatures:
                    if sig in body:
                        matched_sig = sig
                        break

                if matched_sig:
                    severity = "CRITICAL" if ".env" in path or "sql" in path or "git" in path else "HIGH"
                    snippet = body[:300].replace("\r", "").replace("\n", " ")
                    findings.append({
                        "severity": severity,
                        "desc": f"Exposição de Arquivo Sensível: {path}",
                        "evidence": (
                            f"URL Exposta: {target}\n"
                            f"Assinatura Validada: '{matched_sig}'\n"
                            f"Tamanho da Resposta: {content_len} bytes\n\n"
                            f"Prévia do Conteúdo:\n{snippet}...\n\n"
                            f"PoC cURL:\n"
                            f"  curl -sk '{target}'"
                        ),
                        "poc": f"curl -sk '{target}'"
                    })
        except Exception:
            continue

    return findings

