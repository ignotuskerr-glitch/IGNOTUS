import pytest

from core.cli import parse_cli_args
from core.red_mode.baseline import compare_baseline, save_baseline
from core.red_mode.checks import PROFILE_CATEGORIES, evaluate
from core.red_mode.impact import _eicar_payload, build_impact_matrix, impact_checks


def _snapshot():
    return {
        "host": {"computer_name": "TEST"},
        "amsi": {
            "providers": ["provider"],
            "dlls": [
                {
                    "name": "amsi.dll",
                    "signature": "Valid",
                    "version": "1",
                    "path": "C:/Windows/System32/amsi.dll",
                    "sha256": "00",
                }
            ],
        },
        "defender": {
            "status": {
                "am_service": True,
                "antivirus": True,
                "realtime": True,
                "behavior_monitor": True,
                "ioav": True,
                "network_inspection": True,
                "tamper_protected": True,
                "signature_version": "1",
                "signature_updated": "2099-01-01T00:00:00+00:00",
            },
            "preferences": {
                "disable_realtime": False,
                "disable_behavior": False,
                "disable_ioav": False,
                "cloud_reporting": 2,
                "sample_submission": 1,
                "network_protection": 1,
                "pua_protection": 1,
                "controlled_folder_access": 1,
                "exclusions": {
                    "paths": [],
                    "processes": [],
                    "extensions": [],
                    "ips": [],
                },
                "asr_rule_ids": ["rule"],
                "asr_rule_actions": [1],
            },
        },
        "telemetry": {"event_logs": [], "sysmon_services": []},
        "platform_protection": {"firewall_profiles": []},
        "persistence": {},
    }


def _native():
    return [
        {
            "Module": "amsi.dll",
            "Export": "AmsiScanBuffer",
            "Status": "PASS",
            "BytesMatch": True,
            "MemoryProtection": "0x20",
            "WritableExecutable": False,
            "SuspiciousPrologue": False,
        }
    ]


def test_red_mode_is_standalone():
    args, _ = parse_cli_args(["--red-mode", "--red-profile", "full"])
    assert args.red_mode
    assert args.red_profile == "full"


def test_red_mode_rejects_target_scan():
    with pytest.raises(SystemExit):
        parse_cli_args(["example.com", "--red-mode", "--full"])


def test_baseline_flags_require_red_mode():
    with pytest.raises(SystemExit):
        parse_cli_args(["example.com", "--only-impact", "--red-save-baseline"])


def test_baseline_round_trip_and_drift(tmp_path):
    baseline = tmp_path / "baseline.json"
    snapshot = _snapshot()
    save_baseline(baseline, snapshot, _native())
    assert compare_baseline(baseline, snapshot, _native()) == []
    snapshot["defender"]["status"]["realtime"] = False
    changes = compare_baseline(baseline, snapshot, _native())
    assert any(item["path"].endswith("realtime") for item in changes)


def test_quick_profile_evaluates_integrity_defender_and_platform():
    checks = evaluate(
        "quick",
        _snapshot(),
        _native(),
        {"available": True, "benign_allowed": True, "test_detected": True},
        {},
    )
    categories = {check.category for check in checks}
    assert categories == {"integrity", "defender", "platform"}
    assert any(
        check.id == "NATIVE-AMSISCANBUFFER" and check.status == "PASS"
        for check in checks
    )


def test_defender_permission_sentinel_is_not_counted_as_exclusion():
    snapshot = _snapshot()
    snapshot["defender"]["preferences"]["exclusions"]["paths"] = [
        "N/A: Must be an administrator to view exclusions"
    ]
    check = next(
        item
        for item in evaluate("defender", snapshot, [], {}, {}, {})
        if item.id == "DEFENDER-EXCLUSIONS"
    )
    assert check.status == "INFO"
    assert check.evidence["exclusions"] == []


def test_null_asr_placeholder_is_not_counted_as_a_rule():
    snapshot = _snapshot()
    snapshot["defender"]["preferences"]["asr_rule_ids"] = [None]
    snapshot["defender"]["preferences"]["asr_rule_actions"] = [None]
    check = next(
        item
        for item in evaluate("defender", snapshot, [], {}, {}, {})
        if item.id == "DEFENDER-ASR"
    )
    assert check.status == "WARN"
    assert check.evidence["rule_ids"] == []


def test_signed_appdata_startup_is_not_flagged_as_suspicious():
    snapshot = _snapshot()
    snapshot["persistence"] = {
        "run_keys": [
            {
                "name": "SignedApp",
                "command": "C:/Users/Test/AppData/Local/App/app.exe",
                "signature": "Valid",
            }
        ]
    }
    check = next(
        item
        for item in evaluate("persistence", snapshot, [], {}, {}, {})
        if item.id == "PERSISTENCE-RUN_KEYS"
    )
    assert check.status == "INFO"
    assert check.evidence["suspicious"] == []


def test_default_wmi_binding_without_active_consumer_is_not_a_warning():
    snapshot = _snapshot()
    snapshot["persistence"] = {
        "wmi_filters": [{"Name": "SCM Event Log Filter"}],
        "wmi_consumers": [],
        "wmi_bindings": [{"consumer": "NTEventLogEventConsumer"}],
    }
    check = next(
        item
        for item in evaluate("persistence", snapshot, [], {}, {}, {})
        if item.id == "PERSISTENCE-WMI"
    )
    assert check.status == "PASS"


def test_impact_matrix_reports_blocked_detected_and_missed():
    canaries = {
        "actions": {
            "process": {"status": "PASS"},
            "powershell": {"status": "PASS"},
            "file": {"status": "PASS"},
        },
        "events": [
            {
                "signal": "security_process_create",
                "accessible": True,
                "enabled": True,
                "observed": True,
            },
            {
                "signal": "powershell_script_block",
                "accessible": True,
                "enabled": True,
                "observed": False,
            },
        ],
    }
    impact = build_impact_matrix(canaries, {"state": "BLOCKED", "events": []})
    states = {item["id"]: item["state"] for item in impact["matrix"]}
    assert states["defender_eicar"] == "BLOCKED"
    assert states["process"] == "DETECTED"
    assert states["powershell"] == "MISSED"
    assert states["file"] == "NOT_OBSERVABLE"
    checks = impact_checks(impact)
    assert any(
        item.id == "IMPACT-POWERSHELL" and item.status == "FAIL" for item in checks
    )


def test_impact_profile_is_available_from_short_terminal_alias():
    args, _ = parse_cli_args(["red", "impact"])
    assert args.red_mode
    assert args.red_profile == "impact"


def test_eicar_canary_is_the_inert_standard_and_is_not_executed_by_builder():
    payload = _eicar_payload()
    assert len(payload) == 68
    assert payload.startswith(b"X5O!")
    assert payload.endswith(b"$H+H*")


def test_full_profile_includes_real_impact_validation():
    assert "impact" in PROFILE_CATEGORIES["full"]
