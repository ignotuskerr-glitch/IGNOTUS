import json
from pathlib import Path

from core.purple_team import run_purple_team


def test_all_purple_simulations_are_benign_local_and_reported(tmp_path):
    run = run_purple_team(profile="all", output_dir=str(tmp_path))

    assert len(run.results) == 8
    assert run.passed == 8
    assert run.covered == 0
    assert "no evasion" in run.safety_mode
    assert json.loads(Path(run.json_path).read_text(encoding="utf-8"))["summary"]["total"] == 8


def test_detection_mapping_is_reported_as_validated(tmp_path):
    detections = tmp_path / "detections.json"
    detections.write_text(
        json.dumps(
            {"detections": {"PT-PROC-001": {"status": "validated", "rule_id": "RULE-1"}}}
        ),
        encoding="utf-8",
    )

    run = run_purple_team(
        profile="baseline",
        detections_file=str(detections),
        output_dir=str(tmp_path / "reports"),
    )

    assert run.covered == 1
    process = next(item for item in run.results if item.simulation_id == "PT-PROC-001")
    assert process.rule_id == "RULE-1"
