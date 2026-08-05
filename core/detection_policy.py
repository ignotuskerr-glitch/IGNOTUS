"""Validation for operational SIEM/EDR detection mappings."""

from __future__ import annotations

from typing import Any


def validate_detection_policy(payload: Any) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("detection policy must be a JSON object")
    # Accept a hand-supplied legacy mapping only by upgrading it in memory to
    # the strict policy.  The runtime never falls back to an example file.
    if "schema_version" not in payload:
        payload = {
            "schema_version": 2,
            "mode": "strict-impact",
            "policy": {
                "require_rule_id_for_validated": True,
                "allow_unverified_as_impact": False,
                "secret_output": "redacted",
            },
            "detections": payload.get("detections", {}),
        }
    if int(payload.get("schema_version", 0)) < 2:
        raise ValueError("detection policy schema_version 2 is required")
    policy = payload.get("policy")
    if not isinstance(policy, dict) or policy.get("mode", payload.get("mode")) not in {"strict-impact", "strict"}:
        # `mode` is accepted at the document root for backwards-compatible
        # operational files, but permissive policies are never accepted.
        if payload.get("mode") not in {"strict-impact", "strict"}:
            raise ValueError("detection policy must declare mode=strict-impact")
    if policy.get("allow_unverified_as_impact") is True:
        raise ValueError("unverified observations cannot be promoted to impact")
    detections = payload.get("detections")
    if not isinstance(detections, dict):
        raise ValueError("detection policy must contain a detections object")
    for key, record in detections.items():
        if not isinstance(record, dict):
            raise ValueError(f"detection {key} must be an object")
        status = str(record.get("status", "")).casefold()
        if status == "validated" and not record.get("rule_id"):
            raise ValueError(f"validated detection {key} requires rule_id")
    return payload
