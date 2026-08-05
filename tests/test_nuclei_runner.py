import json

from core.nuclei_runner import _parse_partial_nuclei_jsonl


def test_partial_nuclei_jsonl_is_preserved():
    finding = {
        "template-id": "header-test",
        "matched-at": "https://example.test/",
        "info": {"name": "Header Test", "severity": "low", "tags": ["misconfig"]},
    }

    results = _parse_partial_nuclei_jsonl(
        json.dumps(finding) + "\ntruncated-json",
        "https://example.test/",
    )

    assert len(results) == 1
    assert results[0]["template_id"] == "header-test"
    assert results[0]["severity"] == "LOW"
