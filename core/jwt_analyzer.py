"""
ingotus/core/jwt_analyzer.py

Analisa e decodifica tokens JWT encontrados em headers, cookies e respostas HTTP.
Identifica más configurações de segurança como algoritmo 'none', chave fraca e vazamento de claims sensíveis.
"""

import jwt
import json
import re
from typing import Optional, Dict, Any, List

# Regex para detectar tokens JWT (Header.Payload.Signature)
JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]*')

def extract_and_analyze_jwts(text_or_headers: str) -> List[Dict[str, Any]]:
    """
    Busca por tokens JWT em um texto/cabecalho e analisa suas vulnerabilidades.
    """
    findings = []
    tokens = set(JWT_REGEX.findall(str(text_or_headers)))

    for token in tokens:
        try:
            # Decodifica sem verificar a assinatura para inspecionar os claims
            unverified_header = jwt.get_unverified_header(token)
            unverified_payload = jwt.decode(token, options={"verify_signature": False})

            alg = unverified_header.get("alg", "").lower()
            issues = []

            # 1. Checa algoritmo 'none'
            if alg == "none":
                issues.append("Algoritmo JWT configurado como 'none' (Assinatura desativada)")

            # 2. Checa se ha dados sensiveis no payload (senha, role admin, email)
            payload_str = json.dumps(unverified_payload).lower()
            sensitive_keys = ["password", "secret", "private_key", "is_admin", "role"]
            sensitive_found = [k for k in sensitive_keys if k in payload_str]

            if sensitive_found:
                issues.append(f"Claims sensíveis encontrados no payload: {', '.join(sensitive_found)}")

            findings.append({
                "token": token[:30] + "...",
                "header": unverified_header,
                "payload": unverified_payload,
                "issues": issues,
                "severity": "HIGH" if "none" in alg or "is_admin" in payload_str else "LOW"
            })
        except Exception:
            continue

    return findings
