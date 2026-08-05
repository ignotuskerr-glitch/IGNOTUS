"""
ingotus/core/cloud_storage.py

Módulo de detecção e auditoria de Buckets de Armazenamento em Nuvem (S3, GCP, Azure, DigitalOcean).
Identifica buckets associados a subdomínios, verifica apontamentos CNAME órfãos e testa permissões
de leitura/escrita de objetos públicos.
"""

import requests
import urllib3
import re
from typing import Optional, Dict, List, Tuple
from core.config import PROBE_TIMEOUT, USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Padrões CNAME de serviços de Cloud Storage
CLOUD_STORAGE_PATTERNS = [
    # AWS S3
    (r"([a-z0-9.\-]+)\.s3[\.\-][a-z0-9\-]+\.amazonaws\.com", "AWS S3 Bucket"),
    (r"([a-z0-9.\-]+)\.s3-website[\.\-][a-z0-9\-]+\.amazonaws\.com", "AWS S3 Website"),
    (r"([a-z0-9.\-]+)\.s3\.amazonaws\.com", "AWS S3 Bucket"),
    # Google Cloud Storage
    (r"storage\.googleapis\.com", "GCP Cloud Storage"),
    (r"([a-z0-9.\-]+)\.storage\.googleapis\.com", "GCP Cloud Storage"),
    # Azure Blob Storage
    (r"([a-z0-9.\-]+)\.blob\.core\.windows\.net", "Azure Blob Storage"),
    (r"([a-z0-9.\-]+)\.web\.core\.windows\.net", "Azure Static Website"),
    # DigitalOcean Spaces
    (r"([a-z0-9.\-]+)\.([a-z0-9\-]+)\.digitaloceanspaces\.com", "DigitalOcean Space"),
    # Wasabi
    (r"([a-z0-9.\-]+)\.s3\.[a-z0-9\-]+\.wasabisys\.com", "Wasabi Bucket"),
    # Alibaba Cloud OSS
    (r"([a-z0-9.\-]+)\.oss\-[a-z0-9\-]+\.aliyuncs\.com", "Alibaba OSS"),
]

# Respostas de buckets não configurados / órfãos (Vulneráveis a Takeover)
BUCKET_TAKEOVER_SIGNATURES = [
    ("AWS S3", "The specified bucket does not exist"),
    ("AWS S3", "NoSuchBucket"),
    ("GCP Storage", "The specified bucket does not exist"),
    ("GCP Storage", "BucketNotFound"),
    ("Azure Blob", "The specified container does not exist"),
    ("Azure Blob", "ContainerNotFound"),
    ("DigitalOcean", "NoSuchBucket"),
]


def audit_cloud_storage(subdomain: str, cname: Optional[str] = None, proxy: Optional[str] = None) -> List[Dict]:
    """
    Audita o subdomínio e CNAME em busca de buckets expostos ou órfãos.
    """
    findings: List[Dict] = []
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": USER_AGENT}

    provider_detected = None
    if cname:
        for pattern, provider in CLOUD_STORAGE_PATTERNS:
            if re.search(pattern, cname, re.IGNORECASE):
                provider_detected = provider
                break

    if not provider_detected:
        return findings

    # Testar o endpoint web do subdomínio para checar resposta do storage
    for proto in ["https", "http"]:
        url = f"{proto}://{subdomain}"
        try:
            r = requests.get(url, headers=headers, timeout=PROBE_TIMEOUT, verify=False, allow_redirects=False, proxies=proxies)
            body = r.text

            # 1. Verificar Takeover de Bucket Órfão
            for service, sig in BUCKET_TAKEOVER_SIGNATURES:
                if sig in body:
                    findings.append({
                        "severity": "CRITICAL",
                        "desc": f"Bucket Órfão Detectado ({provider_detected}) — Suscetível a Bucket Takeover!",
                        "evidence": (
                            f"Host: {subdomain}\n"
                            f"CNAME: {cname}\n"
                            f"Provedor: {provider_detected}\n"
                            f"Assinatura de Erro: '{sig}' na resposta HTTP {r.status_code}\n"
                            f"Impacto: O bucket apontado pelo CNAME não existe. Um atacante pode registrar este bucket e tomar conta do subdomínio."
                        ),
                        "poc": f"curl -sk '{url}'"
                    })
                    return findings

            # 2. Verificar Listagem Pública do Bucket (Open Bucket)
            if r.status_code == 200 and ("<ListBucketResult" in body or "<EnumerationResults" in body):
                findings.append({
                    "severity": "HIGH",
                    "desc": f"Bucket Aberto para Leitura Pública ({provider_detected})",
                    "evidence": (
                        f"Host: {subdomain}\n"
                        f"CNAME: {cname}\n"
                        f"Resposta HTTP 200 contendo XML de listagem de objetos (<ListBucketResult>).\n"
                        f"Impacto: Todos os arquivos e diretórios salvos no armazenamento são publicamente visíveis."
                    ),
                    "poc": f"curl -sk '{url}' | head -30"
                })

        except Exception:
            continue

    return findings
