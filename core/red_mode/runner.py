from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from core.red_mode.baseline import compare_baseline, save_baseline
from core.red_mode.canaries import run_canaries
from core.red_mode.checks import PROFILE_CATEGORIES, evaluate
from core.red_mode.impact import build_impact_matrix, impact_checks, run_defender_impact
from core.red_mode.models import RedCheck, RedRun
from core.red_mode.platform import IS_LINUX, IS_WINDOWS, IS_WSL
from core.red_mode.reporting import write_reports
from core.detection_policy import validate_detection_policy


def _load_detections(path: str | None) -> dict:
    if not path:
        return {}
    return validate_detection_policy(json.loads(Path(path).read_text(encoding="utf-8")))


def _run_remote_combined(target: str, run_canaries_flag: bool, run_impact_flag: bool) -> dict:
    dir_path = Path(__file__).resolve().parent

    def read_stripped(path: Path) -> str:
        content = path.read_text(encoding="utf-8")
        content = content.replace("from __future__ import annotations", "")
        main_idx = content.find('if __name__ == "__main__":')
        if main_idx != -1:
            content = content[:main_idx]
        return content

    snapshot_code = read_stripped(dir_path / "linux_snapshot.py")
    canaries_code = read_stripped(dir_path / "canaries.py")
    impact_code = read_stripped(dir_path / "impact.py")

    dispatcher = f"""
if __name__ == "__main__":
    import json
    
    snapshot_data = collect_linux_snapshot()
    canaries_data = run_canaries() if {run_canaries_flag} else {{}}
    impact_data = run_defender_impact() if {run_impact_flag} else {{}}
    
    print(json.dumps({{
        "snapshot": snapshot_data,
        "canaries": canaries_data,
        "impact": impact_data
    }}))
"""
    combined_script = "from __future__ import annotations\n" + "\n".join([snapshot_code, canaries_code, impact_code, dispatcher])

    cmd = ["ssh", "-o", "ConnectTimeout=10", target, "python3", "-"]
    try:
        completed = subprocess.run(
            cmd,
            input=combined_script,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except Exception as exc:
        raise RuntimeError(f"Falha de conexão SSH: {exc}")
    if completed.returncode != 0:
        err = completed.stderr.strip() or f"exit code {completed.returncode}"
        raise RuntimeError(f"Erro na execução remota via SSH: {err}")
    try:
        return json.loads(completed.stdout.strip())
    except json.JSONDecodeError:
        raise RuntimeError(f"Resposta remota não-JSON: {completed.stdout.strip()[:200]}")


def _collect_snapshot() -> dict:
    """Collect a local security snapshot appropriate for the current OS."""
    if IS_WINDOWS or IS_WSL:
        from core.red_mode.powershell import collect_windows_snapshot
        return collect_windows_snapshot()
    # Pure Linux
    from core.red_mode.linux_snapshot import collect_linux_snapshot
    return collect_linux_snapshot()


def _collect_native_probe(categories: set) -> list[dict]:
    """Collect the native memory-integrity probe (Windows-only, local)."""
    if (IS_WINDOWS or IS_WSL) and "integrity" in categories:
        from core.red_mode.powershell import collect_native_probe
        return collect_native_probe()
    return []


def _collect_amsi_scan(categories: set) -> dict:
    """Run the native AMSI scan (Windows-only, local)."""
    if (IS_WINDOWS or IS_WSL) and "integrity" in categories:
        from core.amsi_audit import _native_amsi_scan
        return _native_amsi_scan()
    return {}


def run_red_mode(
    target: str | None = None,
    profile: str = "quick",
    output_dir: str = "output/red",
    detections_file: str | None = None,
    save_baseline_requested: bool = False,
    compare_baseline_path: str | None = None,
) -> RedRun:
    if profile not in PROFILE_CATEGORIES:
        raise ValueError(f"perfil inválido: {profile}")

    categories = PROFILE_CATEGORIES[profile]

    if target:
        # Single SSH connection for snapshot, canaries, and impact
        run_canaries_flag = bool({"telemetry", "impact"} & categories)
        run_impact_flag = "impact" in categories

        remote_data = _run_remote_combined(target, run_canaries_flag, run_impact_flag)

        snapshot      = remote_data["snapshot"]
        canaries      = remote_data["canaries"]
        remote_impact = remote_data["impact"]

        native_probe  = []
        amsi_scan     = {}

        impact: dict = {}
        if run_impact_flag:
            from core.red_mode.impact import build_impact_matrix
            impact = build_impact_matrix(canaries, remote_impact)
    else:
        snapshot      = _collect_snapshot()
        native_probe  = _collect_native_probe(categories)
        amsi_scan     = _collect_amsi_scan(categories)
        canaries      = run_canaries() if {"telemetry", "impact"} & categories else {}
        impact        = {}
        if "impact" in categories:
            from core.red_mode.impact import build_impact_matrix
            impact = build_impact_matrix(canaries, run_defender_impact())

    detections    = _load_detections(detections_file)
    checks        = evaluate(profile, snapshot, native_probe, amsi_scan, canaries, detections)
    if impact:
        from core.red_mode.impact import impact_checks
        checks.extend(impact_checks(impact))

    drift: list[dict] = []
    baseline_path = compare_baseline_path
    if compare_baseline_path:
        drift = compare_baseline(compare_baseline_path, snapshot, native_probe)
        checks.append(
            RedCheck(
                id="BASELINE-DRIFT",
                category="baseline",
                status="WARN" if drift else "PASS",
                title="Deriva de configuração",
                detail=f"changes={len(drift)}; baseline={Path(compare_baseline_path).resolve()}",
                recommendation="Revise e aprove ou reverta cada alteração antes de promover uma nova baseline."
                if drift
                else "",
                evidence={"changed_paths": [item.get("path") for item in drift[:100]]},
            )
        )

    if save_baseline_requested:
        baseline_path = save_baseline(
            Path(output_dir) / "baselines" / "latest.json", snapshot, native_probe
        )

    run = RedRun(
        profile=profile,
        generated_at=datetime.now(timezone.utc).isoformat(),
        checks=checks,
        snapshot=snapshot,
        native_probe=native_probe,
        canaries=canaries,
        impact=impact,
        drift=drift,
        baseline_path=str(Path(baseline_path).resolve()) if baseline_path else None,
    )
    run.json_path, run.markdown_path = write_reports(run, output_dir)
    return run
