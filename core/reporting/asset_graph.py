"""Build a portable graph of discovered infrastructure relationships."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import HostResult


def build_asset_graph(results: dict[str, HostResult]) -> dict[str, list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()

    def add_node(node_id: str, kind: str, label: str, **metadata: Any) -> None:
        nodes[node_id] = {"id": node_id, "kind": kind, "label": label, **metadata}

    for host, result in sorted(results.items()):
        host_id = f"host:{host}"
        add_node(
            host_id,
            "host",
            host,
            classification=result.classification,
            confidence=result.confidence,
        )
        for ip in result.dns.ips:
            ip_id = f"ip:{ip}"
            add_node(ip_id, "ip", ip)
            edges.add((host_id, ip_id, "resolves_to"))
        if result.dns.cname:
            cname_id = f"host:{result.dns.cname.rstrip('.')}"
            add_node(cname_id, "host", result.dns.cname.rstrip("."))
            edges.add((host_id, cname_id, "aliases_to"))
        if result.asn and result.asn.number:
            asn_id = f"asn:{result.asn.number}"
            add_node(asn_id, "asn", result.asn.number, organization=result.asn.organization)
            for ip in result.dns.ips:
                edges.add((f"ip:{ip}", asn_id, "announced_by"))
        for technology in result.http.tech_stack:
            tech_id = f"technology:{technology.casefold()}"
            add_node(tech_id, "technology", technology)
            edges.add((host_id, tech_id, "runs"))

    return {
        "nodes": list(nodes.values()),
        "edges": [
            {"source": source, "target": target, "relation": relation}
            for source, target, relation in sorted(edges)
        ],
    }


def export_asset_graph(results: dict[str, HostResult], destination: str) -> str:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(build_asset_graph(results), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return str(path)
