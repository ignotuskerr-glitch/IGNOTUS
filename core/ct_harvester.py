"""
ingotus/core/ct_harvester.py

Coletor de subdomínios via Certificate Transparency Logs (crt.sh).
Consulta registros de certificados SSL/TLS emitidos publicamente para um domínio.
"""

import requests
import re
from typing import List, Set
from core.config import PROBE_TIMEOUT, USER_AGENT


def fetch_ct_subdomains(domain: str) -> List[str]:
    """
    Busca subdomínios registrados nos logs de Certificate Transparency via crt.sh.
    Retorna uma lista de subdomínios únicos formatados e limpos.
    """
    subdomains: Set[str] = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": USER_AGENT}

    try:
        r = requests.get(url, headers=headers, timeout=PROBE_TIMEOUT * 3, verify=True)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                # name_value pode conter múltiplos nomes separados por \n
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    # Remove wildcard prefix (*.)
                    if sub.startswith("*."):
                        sub = sub[2:]
                    # Valida se é um subdomínio válido do domínio alvo
                    if sub.endswith(f".{domain}") or sub == domain:
                        # Ignora nomes com caracteres inválidos
                        if not re.search(r"[^\w\.\-]", sub):
                            subdomains.add(sub)
    except Exception:
        pass

    return sorted(list(subdomains))
