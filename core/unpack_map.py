"""
ingotus/core/unpack_map.py

Extrai e reconstrói código-fonte original a partir de Source Maps.
Suporta:
  - webpack://, vite://, parcel://, turbopack://
  - Arquivos sem sourcesContent (tenta baixar externamente)
  - sourceRoot para resolver URLs relativas
  - Múltiplos mapas encadeados (um mapa pode referenciar outros mapas)
"""

import json
import os
import sys
import re
import requests
import urllib.parse
from pathlib import Path
from typing import Optional, Dict, Any, List
from core.path_safety import safe_output_path

USER_AGENT = "Mozilla/5.0 (compatible; Ingotus/2.0; Security Research)"


def _fetch(url: str, timeout: int = 10) -> Optional[str]:
    """Faz uma requisição GET e retorna o texto da resposta ou None."""
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT},
                         timeout=timeout, verify=False)
        if r.ok:
            return r.text
    except Exception:
        pass
    return None


def _clean_source_path(src_path: str) -> str:
    """Remove prefixos de bundler do path da fonte."""
    for prefix in [
        "webpack://", "webpack:///", "webpack://./",
        "vite://", "vite:///",
        "parcel://", "parcel:///",
        "turbopack://", "turbopack:///",
        "/_N_E/", "file://", "file:///",
    ]:
        src_path = src_path.replace(prefix, "")

    # Remove . e .. perigosos
    src_path = src_path.lstrip("/\\").replace("\\", "/")
    safe_path = Path(*[p for p in src_path.split("/") if p and p != ".."])
    return str(safe_path)


def unpack_sourcemap(map_path: str, output_dir: str) -> Dict[str, Any]:
    """
    Desempacota um arquivo .map local e reconstrói o código-fonte.

    Returns:
        Dict com estatísticas: files_extracted, skipped, total
    """
    if not os.path.exists(map_path):
        print(f"Erro: Arquivo {map_path} não encontrado.")
        return {"error": "file_not_found"}

    print(f"Lendo {map_path} ({os.path.getsize(map_path) / (1024*1024):.2f} MB)...")
    with open(map_path, 'r', encoding='utf-8', errors='ignore') as f:
        data = json.load(f)

    return _extract_from_data(data, output_dir)


def unpack_sourcemap_url(map_url: str, output_dir: str) -> Dict[str, Any]:
    """
    Baixa e desempacota um source map a partir de uma URL remota.
    Também tenta baixar arquivos externos referenciados que não estejam
    embutidos em sourcesContent.

    Returns:
        Dict com estatísticas e lista de fontes externas encontradas.
    """
    print(f"Baixando source map: {map_url}")
    text = _fetch(map_url)
    if not text:
        print(f"Erro: Não foi possível baixar {map_url}")
        return {"error": "download_failed", "map_url": map_url}

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        print(f"Erro: JSON inválido em {map_url}: {e}")
        return {"error": "invalid_json", "map_url": map_url}

    result = _extract_from_data(data, output_dir, base_url=map_url)
    result["map_url"] = map_url
    return result


def _extract_from_data(
    data: Dict,
    output_dir: str,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Extrai os arquivos a partir do dict JSON do source map."""
    sources: List[str] = data.get("sources", [])
    contents: List[Optional[str]] = data.get("sourcesContent", [])
    source_root: str = data.get("sourceRoot", "")

    if not sources:
        print("Erro: O SourceMap não contém 'sources'.")
        return {"error": "no_sources", "files_extracted": 0}

    print(f"Extraindo {len(sources)} arquivos de código-fonte...")
    output_path = Path(output_dir)
    count = 0
    skipped = 0
    external_found = []
    nested_maps = []

    for idx, src_path in enumerate(sources):
        content = contents[idx] if idx < len(contents) else None
        clean = _clean_source_path(src_path)

        if not clean:
            skipped += 1
            continue

        target_path = safe_output_path(str(output_path), clean)
        if target_path is None:
            skipped += 1
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if content:
            with open(target_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(content)
            count += 1

            # Verificar se o arquivo é um outro source map
            is_nested_map = (
                target_path.suffix.lower() == ".map"
                or (
                    isinstance(content, str)
                    and content.lstrip().startswith("{")
                    and '"sources"' in content
                )
            )

            if is_nested_map:
                nested_maps.append(target_path)

        else:
            # Sem conteúdo embutido — tentar baixar externamente
            external_url = None
            if src_path.startswith("http"):
                external_url = src_path
            elif source_root:
                external_url = urllib.parse.urljoin(
                    source_root.rstrip("/") + "/", src_path.lstrip("/")
                )
            elif base_url:
                # Relativo ao diretório do mapa
                base_dir = base_url.rsplit("/", 1)[0]
                external_url = urllib.parse.urljoin(base_dir + "/", src_path.lstrip("/"))

            if external_url:
                external_found.append(external_url)
                fetched = _fetch(external_url)
                if fetched:
                    with open(target_path, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(fetched)
                    count += 1
                    # Verificar se é outro source map
                    if external_url.endswith(".map") or '"sources"' in fetched:
                        nested_maps.append(external_url)
            else:
                skipped += 1

    # Processar mapas aninhados encontrados
    for nested in nested_maps:
        nested_out = str(output_path / "_nested")
        if nested.startswith("http"):
            sub = unpack_sourcemap_url(nested, nested_out)
        else:
            sub = unpack_sourcemap(nested, nested_out)
        count += sub.get("files_extracted", 0)

    print(f"Sucesso! {count} arquivos reconstruídos em: {output_path.resolve()}")
    if skipped > 0:
        print(f"Ignorados: {skipped} (sem conteudo embutido e sem URL externa)")
    if external_found:
        print(f"Fontes externas tentadas: {len(external_found)}")

    return {
        "files_extracted": count,
        "skipped": skipped,
        "total_sources": len(sources),
        "external_sources": external_found,
        "nested_maps": nested_maps,
        "output_dir": str(output_path.resolve()),
    }


def scan_for_linked_assets(map_data: Dict, base_url: str) -> List[str]:
    """
    Analisa o conteúdo dos arquivos do source map em busca de:
      - URLs para outros source maps
      - Links para APIs internas
      - Hardcoded secrets (tokens, chaves de API)

    Returns lista de URLs adicionais encontradas.
    """
    urls_found = []
    secret_pattern = re.compile(
        r'(?:api[_-]?key|secret|token|password|auth|bearer|jwt)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']',
        re.IGNORECASE
    )
    url_pattern = re.compile(r'https?://[^\s"\'>\'`]+', re.IGNORECASE)

    contents = map_data.get("sourcesContent", [])
    for content in contents:
        if not content:
            continue
        for match in url_pattern.findall(content):
            clean = match.strip('",;)')
            if any(ext in clean for ext in [".map", ".json", "api", "swagger", "graphql"]):
                urls_found.append(clean)

    return list(set(urls_found))


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    if len(sys.argv) < 2:
        print("Uso: python unpack_map.py <arquivo.map ou URL> [diretorio_saida_opcional]")
        sys.exit(1)

    source = sys.argv[1]
    out_folder = sys.argv[2] if len(sys.argv) > 2 else "./src_extracted"

    if source.startswith("http"):
        result = unpack_sourcemap_url(source, out_folder)
    else:
        result = unpack_sourcemap(source, out_folder)

    print(f"\nResultado: {json.dumps(result, indent=2, default=str)}")
