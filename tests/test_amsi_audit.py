from core.amsi_audit import _evaluate


def test_amsi_evaluation_requires_real_detection_and_defender_controls():
    snapshot = {
        "amsi_signature": "Valid",
        "providers": ["provider-id"],
        "defender": {
            "AMServiceEnabled": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "BehaviorMonitorEnabled": True,
        },
        "script_block_logging": False,
        "module_logging": True,
    }
    native = {
        "available": True,
        "benign_allowed": True,
        "test_detected": True,
        "benign_result": 1,
        "test_result": 32768,
    }

    checks = _evaluate(snapshot, native)

    assert not any(item["status"] == "FAIL" for item in checks)
    script_logging = next(item for item in checks if item["id"] == "POWERSHELL-SCRIPT-BLOCK-LOGGING")
    assert script_logging["status"] == "WARN"
