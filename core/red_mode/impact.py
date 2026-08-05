from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from core.red_mode.models import RedCheck
except ImportError:
    class RedCheck:
        pass

try:
    from core.red_mode.platform import IS_WINDOWS, IS_WSL
except ImportError:
    import os
    IS_WINDOWS = os.name == "nt"
    try:
        from pathlib import Path
        IS_WSL = not IS_WINDOWS and Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
    except OSError:
        IS_WSL = False


EVENT_EXPECTATIONS = {
    "process": {"security_process_create", "sysmon_process_create"},
    "shell": {
        "powershell_script_block",
        "powershell_module",
        "sysmon_process_create",
        "journald_search",
        "syslog_search",
    },
    "powershell": {  # kept for backward compat
        "powershell_script_block",
        "powershell_module",
        "sysmon_process_create",
    },
    "file": {"sysmon_file_create", "journald_search"},
    "registry": {"sysmon_registry_create_delete", "sysmon_registry_value_set"},
    "tcp_loopback": {"sysmon_network_connect"},
    "named_pipe": {"sysmon_pipe_create", "sysmon_pipe_connect"},
    "credential_dump": {"security_process_create", "sysmon_process_create", "journald_search", "syslog_search"},
    "persistence_sim": {"security_process_create", "sysmon_process_create", "journald_search", "syslog_search", "sysmon_file_create"},
}

ATTACK_MAPPING = {
    "process": "T1059.006",
    "powershell": "T1059.001",
    "file": "T1074.001",
    "registry": "T1112",
    "tcp_loopback": "T1095",
    "named_pipe": "T1559",
    "credential_dump": "T1003",
    "persistence_sim": "T1053.005",
}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _find_mpcmdrun() -> Path | None:
    candidates: list[Path] = []
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    platform = program_data / "Microsoft" / "Windows Defender" / "Platform"
    if platform.is_dir():
        candidates.extend(sorted(platform.glob("*/MpCmdRun.exe"), reverse=True))
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    candidates.append(program_files / "Windows Defender" / "MpCmdRun.exe")
    return next((path for path in candidates if path.is_file()), None)


def _eicar_payload() -> bytes:
    # Standard inert anti-malware test marker. It is written but never executed.
    fragments = (
        "X5O!P%@AP[4",
        "\\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    return "".join(fragments).encode("ascii")


def _query_defender(marker: str, started_at: str) -> dict:
    from core.red_mode.powershell import PROJECT_ROOT, _run_script
    output = _run_script(
        PROJECT_ROOT / "scripts" / "red_mode_defender_impact.ps1",
        "-Marker",
        marker,
        "-StartUtc",
        started_at,
        timeout=90,
    )
    return json.loads(output)


def _run_linux_av_impact(wait_seconds: float = 8.0) -> dict:
    """Linux equivalent: write EICAR to /tmp and check if ClamAV removes it."""
    marker = "IGNOTUS_IMPACT_" + uuid.uuid4().hex.upper()
    started_at = datetime.now(timezone.utc).isoformat()
    monotonic_start = time.monotonic()
    directory = Path(tempfile.mkdtemp(prefix="ignotus-impact-"))
    sample = directory / f"{marker}_eicar.com"
    payload = _eicar_payload()
    payload_sha256 = hashlib.sha256(payload).hexdigest()

    clamdscan = shutil.which("clamdscan")
    clamscan = shutil.which("clamscan")
    scanner = clamdscan or clamscan

    if not scanner:
        # No AV present — cannot test
        try:
            directory.rmdir()
        except OSError:
            pass
        return {
            "id": "linux_eicar",
            "title": "Linux AV prevention canary",
            "standard": "EICAR anti-malware test file",
            "payload_sha256": payload_sha256,
            "safety": "Inert test marker; file was never executed",
            "marker": marker,
            "started_at": started_at,
            "state": "NOT_OBSERVABLE",
            "detected": False,
            "remediated": False,
            "removed_by_control": False,
            "cleaned": True,
            "scanner": None,
            "error": "Nenhum AV encontrado (clamdscan/clamscan). Instale o ClamAV.",
            "duration_ms": round((time.monotonic() - monotonic_start) * 1000),
        }

    write_error = ""
    scan_exit_code = None
    scan_stderr = ""
    existed_after_write = False
    try:
        try:
            sample.write_bytes(payload)
            existed_after_write = sample.exists()
        except OSError as exc:
            write_error = f"{type(exc).__name__}: {exc}"

        if sample.exists():
            completed = subprocess.run(
                [scanner, str(sample)],
                capture_output=True, text=True, check=False, timeout=60,
            )
            scan_exit_code = completed.returncode
            scan_stderr = completed.stderr.strip()[-500:]

        deadline = time.monotonic() + max(0.0, wait_seconds)
        while sample.exists() and time.monotonic() < deadline:
            time.sleep(0.25)

        removed_by_control = existed_after_write and not sample.exists()
        # ClamAV exit code 1 = virus found; 0 = clean; others = error
        detected = scan_exit_code == 1 or removed_by_control
        remediated = removed_by_control

        if detected and remediated:
            state = "BLOCKED"
        elif detected:
            state = "DETECTED"
        elif write_error and not sample.exists():
            state = "BLOCKED_UNCONFIRMED"
        else:
            state = "MISSED"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        state = "ERROR"
        detected = False
        remediated = False
        removed_by_control = False
        scan_stderr = f"{type(exc).__name__}: {exc}"
    finally:
        cleanup_error = ""
        for _ in range(10):
            try:
                if sample.exists():
                    sample.unlink()
                if directory.exists():
                    directory.rmdir()
                break
            except OSError as exc:
                cleanup_error = str(exc)
                time.sleep(0.2)

    cleaned = not sample.exists() and not directory.exists()
    return {
        "id": "linux_eicar",
        "title": "Linux AV prevention canary",
        "standard": "EICAR anti-malware test file",
        "payload_sha256": payload_sha256,
        "safety": "Inert test marker; file was never executed",
        "marker": marker,
        "started_at": started_at,
        "state": state,
        "detected": detected,
        "remediated": remediated,
        "removed_by_control": removed_by_control,
        "cleaned": cleaned,
        "write_error": write_error,
        "scanner": scanner,
        "scan_exit_code": scan_exit_code,
        "scan_stderr": scan_stderr,
        "events": [],
        "threats": [],
        "duration_ms": round((time.monotonic() - monotonic_start) * 1000),
    }


def run_defender_impact(wait_seconds: float = 8.0) -> dict:
    """Dispatch to Windows Defender or Linux ClamAV based on platform."""
    if IS_WINDOWS or IS_WSL:
        return _run_windows_defender_impact(wait_seconds)
    return _run_linux_av_impact(wait_seconds)


def _run_windows_defender_impact(wait_seconds: float = 8.0) -> dict:
    """Prove Windows Defender prevention with an inert EICAR marker and clean all files."""
    marker = "IGNOTUS_IMPACT_" + uuid.uuid4().hex.upper()
    started_at = datetime.now(timezone.utc).isoformat()
    monotonic_start = time.monotonic()
    directory = Path(tempfile.mkdtemp(prefix="ignotus-impact-"))
    sample = directory / f"{marker}_eicar.com"
    payload = _eicar_payload()
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    mpcmdrun = _find_mpcmdrun()

    write_error = ""
    scan_exit_code = None
    scan_stderr = ""
    existed_after_write = False
    try:
        try:
            sample.write_bytes(payload)
            existed_after_write = sample.exists()
        except OSError as exc:
            write_error = f"{type(exc).__name__}: {exc}"

        if mpcmdrun and sample.exists():
            completed = subprocess.run(
                [
                    str(mpcmdrun),
                    "-Scan",
                    "-ScanType",
                    "3",
                    "-File",
                    str(sample),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=90,
            )
            scan_exit_code = completed.returncode
            scan_stderr = completed.stderr.strip()[-500:]

        deadline = time.monotonic() + max(0.0, wait_seconds)
        while sample.exists() and time.monotonic() < deadline:
            time.sleep(0.25)

        if not sample.exists():
            time.sleep(min(1.5, max(0.0, wait_seconds)))

        evidence = _query_defender(marker, started_at)
        events = _as_list(evidence.get("events"))
        threats = _as_list(evidence.get("threats"))
        detected = bool(events or threats)
        remediated = any(item.get("id") in {1117, 1118} for item in events) or any(
            item.get("action_success") is True for item in threats
        )
        removed_by_control = existed_after_write and not sample.exists()

        if detected and (remediated or removed_by_control):
            state = "BLOCKED"
        elif detected:
            state = "DETECTED"
        elif write_error and not sample.exists():
            state = "BLOCKED_UNCONFIRMED"
        else:
            state = "MISSED"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        evidence = {
            "events": [],
            "threats": [],
            "error": f"{type(exc).__name__}: {exc}",
        }
        events = []
        threats = []
        detected = False
        remediated = False
        removed_by_control = existed_after_write and not sample.exists()
        state = "ERROR"
    finally:
        cleanup_error = ""
        for _ in range(20):
            try:
                if sample.exists():
                    sample.unlink()
                if directory.exists():
                    directory.rmdir()
                cleanup_error = ""
                break
            except OSError as exc:
                cleanup_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.25)

    cleaned = not sample.exists() and not directory.exists()
    return {
        "id": "defender_eicar",
        "title": "Defender prevention canary",
        "standard": "EICAR anti-malware test file",
        "payload_sha256": payload_sha256,
        "safety": "Inert test marker; file was never executed",
        "marker": marker,
        "started_at": started_at,
        "state": state,
        "detected": detected,
        "remediated": remediated,
        "removed_by_control": removed_by_control,
        "cleaned": cleaned,
        "write_error": write_error,
        "scanner": str(mpcmdrun) if mpcmdrun else None,
        "scan_exit_code": scan_exit_code,
        "scan_stderr": scan_stderr,
        "events": events,
        "threats": threats,
        "event_log_accessible": evidence.get("event_log_accessible"),
        "threat_history_accessible": evidence.get("threat_history_accessible"),
        "error": evidence.get("error"),
        "cleanup_error": cleanup_error,
        "duration_ms": round((time.monotonic() - monotonic_start) * 1000),
    }


def build_impact_matrix(canaries: dict, defender_impact: dict) -> dict:
    events = canaries.get("events") or []
    event_by_signal = {
        item.get("signal"): item for item in events if item.get("signal")
    }
    matrix: list[dict] = []

    defender_state = defender_impact.get("state", "ERROR")
    matrix.append(
        {
            "id": "defender_eicar",
            "title": "Prevenção antimalware em disco",
            "attack_id": "",
            "state": defender_state,
            "execution": "inert marker written, never executed",
            "observed_signals": [
                f"Defender/{item.get('id')}"
                for item in defender_impact.get("events") or []
            ]
            + [
                f"DefenderThreat/{item.get('threat_id')}"
                for item in defender_impact.get("threats") or []
            ],
            "impact": "prevention",
        }
    )

    for action_name, action in (canaries.get("actions") or {}).items():
        expected = EVENT_EXPECTATIONS.get(action_name, set())
        relevant = [
            event_by_signal[name] for name in expected if name in event_by_signal
        ]
        observed = [item.get("signal") for item in relevant if item.get("observed")]
        observable = [
            item.get("signal")
            for item in relevant
            if item.get("accessible") and item.get("enabled")
        ]
        if action.get("status") != "PASS":
            state = "ERROR"
        elif observed:
            state = "DETECTED"
        elif observable:
            state = "MISSED"
        else:
            state = "NOT_OBSERVABLE"
        matrix.append(
            {
                "id": action_name,
                "title": f"Canário {action_name}",
                "attack_id": ATTACK_MAPPING.get(action_name, ""),
                "state": state,
                "execution": action.get("status"),
                "expected_signals": sorted(expected),
                "observed_signals": sorted(observed),
                "observable_signals": sorted(observable),
                "impact": "telemetry",
            }
        )

    counts = {
        state: sum(item["state"] == state for item in matrix)
        for state in (
            "BLOCKED",
            "DETECTED",
            "MISSED",
            "NOT_OBSERVABLE",
            "BLOCKED_UNCONFIRMED",
            "ERROR",
        )
    }
    effective = counts["BLOCKED"] + counts["DETECTED"]
    coverage = round(100 * effective / len(matrix)) if matrix else 0
    observable = counts["DETECTED"] + counts["MISSED"]
    telemetry_rate = round(100 * counts["DETECTED"] / observable) if observable else 0
    return {
        "matrix": matrix,
        "summary": {
            **counts,
            "total": len(matrix),
            "effective_coverage_percent": coverage,
            "observable_detection_rate_percent": telemetry_rate,
        },
        "defender": defender_impact,
    }


def impact_checks(impact: dict) -> list[RedCheck]:
    checks: list[RedCheck] = []
    for item in impact.get("matrix") or []:
        state = item.get("state")
        if state in {"BLOCKED", "DETECTED"}:
            status = "PASS"
        elif state == "MISSED":
            status = "FAIL"
        else:
            status = "WARN"
        recommendation = ""
        if state == "MISSED":
            recommendation = "A atividade foi executada, o canal estava observável e nenhum evento correlacionável foi encontrado. Corrija a política e o pipeline."
        elif state == "NOT_OBSERVABLE":
            recommendation = (
                "Habilite a fonte de telemetria esperada e encaminhe-a ao SIEM/EDR."
            )
        elif state in {"ERROR", "BLOCKED_UNCONFIRMED"}:
            recommendation = "Repita como administrador e confirme a evidência no Defender/Event Log."
        checks.append(
            RedCheck(
                id=f"IMPACT-{str(item.get('id')).upper()}",
                category="impact",
                status=status,
                title=item.get("title", "Impact validation"),
                detail=(
                    f"state={state}; execution={item.get('execution')}; "
                    f"observed={len(item.get('observed_signals') or [])}"
                ),
                recommendation=recommendation,
                attack_id=item.get("attack_id", ""),
                evidence=item,
            )
        )
    summary = impact.get("summary") or {}
    missed = int(summary.get("MISSED", 0))
    errors = int(summary.get("ERROR", 0))
    coverage = int(summary.get("effective_coverage_percent", 0))
    status = "FAIL" if missed else "WARN" if errors or coverage < 100 else "PASS"
    checks.append(
        RedCheck(
            id="IMPACT-COVERAGE",
            category="impact",
            status=status,
            title="Cobertura defensiva efetiva",
            detail=(
                f"coverage={coverage}%; detection_rate={summary.get('observable_detection_rate_percent', 0)}%; "
                f"blocked={summary.get('BLOCKED', 0)}; detected={summary.get('DETECTED', 0)}; "
                f"missed={missed}; not_observable={summary.get('NOT_OBSERVABLE', 0)}"
            ),
            recommendation="Priorize MISSED, depois fontes NOT_OBSERVABLE, até atingir cobertura comprovada.",
            evidence=summary,
        )
    )
    return checks


if __name__ == "__main__":
    print(json.dumps(run_defender_impact()))

