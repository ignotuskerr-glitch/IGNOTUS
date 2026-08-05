"""
ingotus/core/takeover_checker.py

Detector automático de Subdomain Takeover (Apropriação de Subdomínios).
Analisa registros CNAME de subdomínios e compara com impressões digitais (fingerprints)
de serviços de nuvem/SaaS desconfigurados ou apontamentos abandonados.

Serviços suportados:
  - AWS S3 / CloudFront
  - GitHub Pages
  - Heroku
  - Azure / Azure App Service
  - Shopify
  - WordPress.com
  - Ghost.io
  - Tumblr
  - Fastly
  - Pantheon
  - Surge.sh
  - Zendesk
  - HubSpot
"""

import requests
import dns.resolver
from typing import Optional, Dict, Any, List
from core.config import PROBE_TIMEOUT, USER_AGENT

# ── Fingerprints de serviços vulneráveis a Takeover ───────────────────────────
TAKEOVER_FINGERPRINTS: Dict[str, Dict[str, Any]] = {
    "github_pages": {
        "cname_pattern": ["github.io", "github.map.fastly.net"],
        "fingerprints": ["There isn't a GitHub Pages site here.", "For root domain support, see"],
        "service": "GitHub Pages",
        "severity": "HIGH",
    },
    "aws_s3": {
        "cname_pattern": ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
        "fingerprints": ["The specified bucket does not exist", "NoSuchBucket"],
        "service": "AWS S3 Bucket",
        "severity": "CRITICAL",
    },
    "cloudfront": {
        "cname_pattern": ["cloudfront.net"],
        "fingerprints": ["The request could not be satisfied", "Bad request."],
        "service": "AWS CloudFront",
        "severity": "HIGH",
    },
    "heroku": {
        "cname_pattern": ["herokudns.com", "herokussl.com", "herokuapp.com"],
        "fingerprints": ["<title>No such app</title>", "herokucdn.com/error-pages/no-such-app.html"],
        "service": "Heroku",
        "severity": "HIGH",
    },
    "azure": {
        "cname_pattern": ["azurewebsites.net", "cloudapp.net", "azure-api.net", "trafficmanager.net"],
        "fingerprints": ["404 Web Site not found", "The resource you are looking for has been removed"],
        "service": "Microsoft Azure",
        "severity": "HIGH",
    },
    "shopify": {
        "cname_pattern": ["myshopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable.", "Only one Shopify store can be attached"],
        "service": "Shopify",
        "severity": "HIGH",
    },
    "wordpress": {
        "cname_pattern": ["wordpress.com"],
        "fingerprints": ["Do you want to register", "doesn&#8217;t exist"],
        "service": "WordPress.com",
        "severity": "HIGH",
    },
    "zendesk": {
        "cname_pattern": ["zendesk.com"],
        "fingerprints": ["Help Center Closed", "this help center no longer exists"],
        "service": "Zendesk",
        "severity": "HIGH",
    },
    "ghost": {
        "cname_pattern": ["ghost.io"],
        "fingerprints": ["The thing you were looking for is gone", "Domain mapping error"],
        "service": "Ghost.io",
        "severity": "HIGH",
    },
    "pantheon": {
        "cname_pattern": ["pantheonsite.io"],
        "fingerprints": ["The site you were looking for could not be found", "404 Action Not Found"],
        "service": "Pantheon",
        "severity": "HIGH",
    },
    "surge": {
        "cname_pattern": ["surge.sh"],
        "fingerprints": ["project not found"],
        "service": "Surge.sh",
        "severity": "HIGH",
    },
    "fastly": {
        "cname_pattern": ["fastly.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "service": "Fastly CDN",
        "severity": "HIGH",
    },
    "hubspot": {
        "cname_pattern": ["hubspot.net", "hs-sites.com", "hubspotpagebuilder.com"],
        "fingerprints": ["does not exist in our system", "Domain not configured"],
        "service": "HubSpot",
        "severity": "HIGH",
    },
    "readme_io": {
        "cname_pattern": ["readme.io", "readmessl.com"],
        "fingerprints": ["Project doesnt exist... yet!", "Project not found"],
        "service": "ReadMe.io",
        "severity": "HIGH",
    },
    "webflow": {
        "cname_pattern": ["proxy.webflow.com", "webflow.io"],
        "fingerprints": ["The page you are looking for doesn't exist or has been moved"],
        "service": "Webflow",
        "severity": "HIGH",
    },
    "bitbucket": {
        "cname_pattern": ["bitbucket.io"],
        "fingerprints": ["Repository not found"],
        "service": "Bitbucket Pages",
        "severity": "HIGH",
    },
    "fly_io": {
        "cname_pattern": ["fly.dev", "edgeapp.net"],
        "fingerprints": ["404 - Not Found", "no such app"],
        "service": "Fly.io",
        "severity": "HIGH",
    },
    "render": {
        "cname_pattern": ["onrender.com"],
        "fingerprints": ["Service not found"],
        "service": "Render.com",
        "severity": "HIGH",
    },
}


def check_cname_takeover(subdomain: str, cname_target: Optional[str] = None, proxy: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Verifica se um subdomínio é vulnerável a Subdomain Takeover.
    Analisa o destino CNAME e faz probe HTTP para confirmar o fingerprint de erro.
    """
    # 1. Obter o CNAME via DNS caso não tenha sido fornecido
    if not cname_target:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            answers = resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                cname_target = str(rdata.target).rstrip('.')
                break
        except Exception:
            return None

    if not cname_target:
        return None

    cname_lower = cname_target.lower()

    # 2. Identificar se o CNAME aponta para algum serviço conhecido
    matched_service = None
    service_key = None
    for key, data in TAKEOVER_FINGERPRINTS.items():
        if any(pattern in cname_lower for pattern in data["cname_pattern"]):
            matched_service = data
            service_key = key
            break

    if not matched_service:
        return None

    # 3. Fazer probe HTTP / HTTPS para validar a mensagem de erro de takeover
    urls_to_test = [f"http://{subdomain}", f"https://{subdomain}"]
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": USER_AGENT}

    for url in urls_to_test:
        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=True,
                proxies=proxies,
            )
            body = r.text

            # Verificar se algum dos fingerprints bate com o corpo da resposta
            for fp in matched_service["fingerprints"]:
                if fp in body:
                    return {
                        "subdomain": subdomain,
                        "cname": cname_target,
                        "service": matched_service["service"],
                        "severity": matched_service["severity"],
                        "desc": f"Vulnerabilidade de Subdomain Takeover Detectada: {matched_service['service']}",
                        "evidence": (
                            f"Subdomínio: {subdomain}\n"
                            f"Apontamento CNAME: {cname_target}\n"
                            f"Serviço Afetado: {matched_service['service']}\n"
                            f"Fingerprint Identificado: \"{fp}\"\n\n"
                            f"PoC cURL:\n"
                            f"  curl -i '{url}'"
                        ),
                    }
        except Exception:
            pass

    return None
