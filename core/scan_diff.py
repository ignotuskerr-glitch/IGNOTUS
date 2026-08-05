"""
ingotus/core/scan_diff.py

Scan History Comparison & Monitoring Engine.
Compares the current scan results with previous scans in SQLite (ingotus.db)
to identify NEW hosts, NEW open ports, and NEW high/critical vulnerabilities.
"""

import sqlite3
import json
from typing import List, Dict, Set, Optional, Tuple


def get_previous_scan_hosts(db_path: str, target_label: str) -> Optional[Dict[str, Dict]]:
    """
    Retrieves the most recent previous scan for a given target label from SQLite.
    Returns dict mapping host -> host_result_dict.
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get scan IDs for target domain ordered by timestamp DESC
        cursor.execute(
            "SELECT id FROM scans WHERE domain = ? ORDER BY timestamp DESC LIMIT 2",
            (target_label,)
        )
        scan_ids = [row[0] for row in cursor.fetchall()]

        if len(scan_ids) < 2:
            conn.close()
            return None  # No previous scan to compare against

        prev_scan_id = scan_ids[1]
        
        cursor.execute(
            "SELECT subdomain, data FROM results WHERE scan_id = ?",
            (prev_scan_id,)
        )
        rows = cursor.fetchall()
        conn.close()

        prev_hosts = {}
        for host, raw_json in rows:
            prev_hosts[host] = json.loads(raw_json)

        return prev_hosts
    except Exception:
        return None



def calculate_scan_diff(current_results: List[Dict], db_path: str, target_label: str) -> Dict[str, List]:
    """
    Compares current scan results against the previous scan for the target.
    """
    diff_report = {
        "new_subdomains": [],
        "new_open_ports": [],
        "new_vulnerabilities": [],
        "is_first_scan": False
    }

    prev_hosts = get_previous_scan_hosts(db_path, target_label)
    if prev_hosts is None:
        diff_report["is_first_scan"] = True
        return diff_report

    curr_hosts = {}
    for r in current_results:
        d = r.to_dict() if hasattr(r, "to_dict") else r
        curr_hosts[d["host"]] = d


    # 1. New subdomains
    for host in curr_hosts:
        if host not in prev_hosts:
            diff_report["new_subdomains"].append(host)

    # 2. New open ports & new vulnerabilities for existing hosts
    for host, curr_data in curr_hosts.items():
        if host in prev_hosts:
            prev_data = prev_hosts[host]

            # Compare ports robustly supporting both [port_num, service/status] and simple port numbers (integers)
            def _normalize_port(p):
                if isinstance(p, (list, tuple)):
                    return tuple(p)
                return (p, "open")

            prev_ports = set(_normalize_port(p) for p in prev_data.get("ports", []))
            curr_ports = set(_normalize_port(p) for p in curr_data.get("ports", []))
            new_ports = curr_ports - prev_ports
            if new_ports:
                diff_report["new_open_ports"].append({
                    "host": host,
                    "ports": [list(p) for p in new_ports]
                })

            # Compare impacts
            prev_impacts = {imp["description"] for imp in prev_data.get("impacts", [])}
            curr_impacts = curr_data.get("impacts", [])
            for imp in curr_impacts:
                if imp["description"] not in prev_impacts:
                    diff_report["new_vulnerabilities"].append({
                        "host": host,
                        "severity": imp["severity"],
                        "description": imp["description"]
                    })

    return diff_report
