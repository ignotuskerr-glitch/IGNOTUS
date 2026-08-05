from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _stable_snapshot(snapshot: dict, native_probe: list[dict]) -> dict:
    # ── Linux path ─────────────────────────────────────────────────────────────
    if snapshot.get("_os") == "linux":
        integrity = snapshot.get("integrity", {})
        av        = snapshot.get("av", {})
        telemetry = snapshot.get("telemetry", {})
        platform  = snapshot.get("platform", {})
        persist   = snapshot.get("persistence", {})
        return {
            "schema_version": 1,
            "_os": "linux",
            "integrity": {
                "ima_available": integrity.get("ima_available"),
                "critical_libs_count": len(integrity.get("critical_libs") or []),
            },
            "av": {
                "clamav_installed": av.get("clamav_installed"),
                "clamav_running":   av.get("clamav_running"),
                "chkrootkit":       av.get("chkrootkit_available"),
                "rkhunter":         av.get("rkhunter_available"),
            },
            "telemetry": {
                "auditd_running":   telemetry.get("auditd_running"),
                "auditd_rules":     telemetry.get("auditd_rule_count"),
                "journald_running": telemetry.get("journald_running"),
                "syslog_running":   telemetry.get("syslog_running"),
            },
            "platform": {
                "aslr":           platform.get("aslr"),
                "kptr_restrict":  platform.get("kptr_restrict"),
                "dmesg_restrict": platform.get("dmesg_restrict"),
                "apparmor":       platform.get("apparmor_enabled"),
                "selinux":        platform.get("selinux_enabled"),
                "ufw_active":     platform.get("ufw_active"),
                "ssh_root_login": platform.get("ssh_permit_root_login"),
                "ssh_password":   platform.get("ssh_password_auth"),
                "sudoers_nopasswd": platform.get("sudoers_nopasswd_count"),
            },
            "persistence": {
                "user_cron_count":    len(persist.get("user_cron_entries") or []),
                "system_cron_count":  len(persist.get("system_cron_files") or []),
                "rc_local_present":   persist.get("rc_local_present"),
                "non_std_services":   len(persist.get("non_standard_services") or []),
            },
        }

    # ── Windows path ───────────────────────────────────────────────────────────
    telemetry = snapshot.get("telemetry", {})
    event_logs = [
        {
            "name": item.get("name"),
            "exists": item.get("exists"),
            "accessible": item.get("accessible"),
            "enabled": item.get("enabled"),
            "maximum_size_bytes": item.get("maximum_size_bytes"),
            "retention": item.get("retention"),
        }
        for item in telemetry.get("event_logs", [])
    ]
    persistence = snapshot.get("persistence", {})
    return {
        "schema_version": 1,
        "host": snapshot.get("host", {}).get("computer_name"),
        "amsi": snapshot.get("amsi", {}),
        "native_probe": [
            {
                "module": item.get("Module"),
                "export": item.get("Export"),
                "clean_bytes": item.get("CleanBytes"),
                "loaded_bytes": item.get("LoadedBytes"),
                "memory_protection": item.get("MemoryProtection"),
                "status": item.get("Status"),
            }
            for item in native_probe
        ],
        "defender": snapshot.get("defender"),
        "telemetry": {
            key: telemetry.get(key)
            for key in (
                "script_block_logging",
                "script_block_invocation_logging",
                "module_logging",
                "transcription",
                "transcription_output",
                "include_invocation_headers",
            )
        }
        | {
            "event_logs": event_logs,
            "sysmon_services": telemetry.get("sysmon_services", []),
        },
        "platform_protection": snapshot.get("platform_protection", {}),
        "persistence": {
            key: persistence.get(key, [])
            for key in (
                "run_keys",
                "startup_entries",
                "scheduled_tasks_non_microsoft",
                "wmi_filters",
                "wmi_consumers",
                "wmi_bindings",
                "unsigned_drivers",
            )
        },
    }



def save_baseline(path: str | Path, snapshot: dict, native_probe: list[dict]) -> str:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = _stable_snapshot(snapshot, native_probe)
    destination.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return str(destination.resolve())


def _normal(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normal(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_normal(item) for item in value]
        return sorted(
            normalized, key=lambda item: json.dumps(item, sort_keys=True, default=str)
        )
    return value


def _diff(old: Any, new: Any, path: str, output: list[dict]) -> None:
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            child = f"{path}.{key}" if path else key
            if key not in old:
                output.append(
                    {"path": child, "change": "added", "old": None, "new": new[key]}
                )
            elif key not in new:
                output.append(
                    {"path": child, "change": "removed", "old": old[key], "new": None}
                )
            else:
                _diff(old[key], new[key], child, output)
        return
    if _normal(old) != _normal(new):
        output.append({"path": path, "change": "changed", "old": old, "new": new})


def compare_baseline(
    path: str | Path, snapshot: dict, native_probe: list[dict]
) -> list[dict]:
    previous = json.loads(Path(path).read_text(encoding="utf-8"))
    current = _stable_snapshot(snapshot, native_probe)
    changes: list[dict] = []
    _diff(previous, current, "", changes)
    return changes
