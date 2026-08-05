"""Advanced defensive validation of Windows AMSI and Defender integration."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

AMSI_RESULT_DETECTED = 0x8000


def _powershell_snapshot() -> dict:
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$mp = Get-MpComputerStatus
$providerPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AMSI\Providers'
$providers = @()
if (Test-Path $providerPath) { $providers = @(Get-ChildItem $providerPath | ForEach-Object { $_.PSChildName }) }
$scriptBlock = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$moduleLog = Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$dll = Get-Item "$env:windir\System32\amsi.dll"
$sig = Get-AuthenticodeSignature $dll.FullName
[pscustomobject]@{
  platform = [System.Environment]::OSVersion.VersionString
  language_mode = $ExecutionContext.SessionState.LanguageMode.ToString()
  amsi_dll_path = $dll.FullName
  amsi_dll_version = $dll.VersionInfo.FileVersion
  amsi_signature = $sig.Status.ToString()
  providers = $providers
  defender = if ($mp) { [pscustomobject]@{
    AMServiceEnabled = $mp.AMServiceEnabled
    AntivirusEnabled = $mp.AntivirusEnabled
    AntispywareEnabled = $mp.AntispywareEnabled
    RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
    BehaviorMonitorEnabled = $mp.BehaviorMonitorEnabled
    IoavProtectionEnabled = $mp.IoavProtectionEnabled
    AntivirusSignatureVersion = $mp.AntivirusSignatureVersion
    AntivirusSignatureLastUpdated = $mp.AntivirusSignatureLastUpdated
  }} else { $null }
  script_block_logging = [bool]($scriptBlock.EnableScriptBlockLogging -eq 1)
  module_logging = [bool]($moduleLog.EnableModuleLogging -eq 1)
} | ConvertTo-Json -Depth 5 -Compress
"""
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
        timeout=45,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError(completed.stderr.strip() or "PowerShell snapshot failed")
    return json.loads(completed.stdout)


def _native_amsi_scan() -> dict:
    if os.name != "nt":
        return {"available": False, "error": "Windows required"}

    amsi = ctypes.WinDLL("amsi.dll")
    context = ctypes.c_void_p()
    session = ctypes.c_void_p()
    result = ctypes.c_uint32()

    amsi.AmsiInitialize.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    amsi.AmsiInitialize.restype = ctypes.c_long
    amsi.AmsiOpenSession.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    amsi.AmsiOpenSession.restype = ctypes.c_long
    amsi.AmsiScanString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    amsi.AmsiScanString.restype = ctypes.c_long
    amsi.AmsiCloseSession.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    amsi.AmsiCloseSession.restype = None
    amsi.AmsiUninitialize.argtypes = [ctypes.c_void_p]
    amsi.AmsiUninitialize.restype = None

    init_hr = amsi.AmsiInitialize("Ignotus Defensive AMSI Audit", ctypes.byref(context))
    if init_hr != 0:
        return {"available": False, "initialize_hresult": init_hr}

    try:
        session_hr = amsi.AmsiOpenSession(context, ctypes.byref(session))
        benign_result = ctypes.c_uint32()
        benign_hr = amsi.AmsiScanString(
            context,
            "IGNOTUS_AMSI_BENIGN_CANARY_2026",
            "ignotus-benign-canary.txt",
            session,
            ctypes.byref(benign_result),
        )

        # The EICAR industry test marker is inert text and never written to disk.
        test_marker = (
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        test_hr = amsi.AmsiScanString(
            context,
            test_marker,
            "ignotus-eicar-memory-test.txt",
            session,
            ctypes.byref(result),
        )
        return {
            "available": True,
            "initialize_hresult": init_hr,
            "session_hresult": session_hr,
            "benign_hresult": benign_hr,
            "benign_result": benign_result.value,
            "test_hresult": test_hr,
            "test_result": result.value,
            "benign_allowed": benign_result.value < AMSI_RESULT_DETECTED,
            "test_detected": result.value >= AMSI_RESULT_DETECTED,
        }
    finally:
        if session:
            amsi.AmsiCloseSession(context, session)
        amsi.AmsiUninitialize(context)


def _check(check_id: str, status: str, detail: str) -> dict:
    return {"id": check_id, "status": status, "detail": detail}


def _evaluate(snapshot: dict, native: dict) -> list[dict]:
    checks = []
    signature = snapshot.get("amsi_signature")
    checks.append(_check("AMSI-DLL-SIGNATURE", "PASS" if signature == "Valid" else "FAIL", f"signature={signature}"))
    providers = snapshot.get("providers") or []
    checks.append(_check("AMSI-PROVIDERS", "PASS" if providers else "FAIL", f"registered={len(providers)}"))

    defender = snapshot.get("defender") or {}
    for key in ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled"):
        enabled = defender.get(key) is True
        checks.append(_check(f"DEFENDER-{key.upper()}", "PASS" if enabled else "FAIL", f"enabled={enabled}"))

    checks.append(_check("AMSI-NATIVE-API", "PASS" if native.get("available") else "FAIL", f"available={native.get('available')}"))
    checks.append(_check("AMSI-BENIGN-CONTROL", "PASS" if native.get("benign_allowed") else "FAIL", f"result={native.get('benign_result')}"))
    checks.append(_check("AMSI-TEST-DETECTION", "PASS" if native.get("test_detected") else "FAIL", f"result={native.get('test_result')}"))

    for key, check_id in (("script_block_logging", "POWERSHELL-SCRIPT-BLOCK-LOGGING"), ("module_logging", "POWERSHELL-MODULE-LOGGING")):
        enabled = snapshot.get(key) is True
        checks.append(_check(check_id, "PASS" if enabled else "WARN", f"enabled={enabled}"))
    return checks


def run_amsi_audit(output_dir: str = "output/amsi") -> dict:
    snapshot = _powershell_snapshot()
    native = _native_amsi_scan()
    checks = _evaluate(snapshot, native)
    summary = {
        "passed": sum(item["status"] == "PASS" for item in checks),
        "warnings": sum(item["status"] == "WARN" for item in checks),
        "failed": sum(item["status"] == "FAIL" for item in checks),
    }
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "defensive-native-validation",
        "safety": "No bypass, no malware, no persistence; inert test marker scanned in memory only.",
        "snapshot": snapshot,
        "native_scan": native,
        "checks": checks,
        "summary": summary,
    }

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = destination / f"amsi_audit_{timestamp}.json"
    markdown_path = destination / f"amsi_audit_{timestamp}.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    lines = [
        "# Ignotus Advanced AMSI Audit", "", f"Generated: `{report['generated_at']}`", "",
        "| Check | Status | Detail |", "|---|---|---|",
    ]
    lines.extend(f"| {item['id']} | {item['status']} | {item['detail']} |" for item in checks)
    lines.extend(["", report["safety"], ""])
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    report["json_path"] = str(json_path.resolve())
    report["markdown_path"] = str(markdown_path.resolve())
    return report
