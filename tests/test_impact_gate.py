from core.impact_gate import classify_secret_evidence, is_known_edge_ip, redact_value, source_class
from core.sourcemap_auditor import audit_sourcemap_content, format_findings_as_evidence


def test_edge_ranges_and_redaction_are_deterministic():
    assert is_known_edge_ip("104.16.20.30", ["Cloudflare"])
    assert not is_known_edge_ip("192.0.2.10", ["Cloudflare"])
    masked = redact_value("AKIAABCDEFGHIJKLMNOP")
    assert "AKIAABCDEFGHIJKLMNOP" not in masked
    assert "sha256:" in masked


def test_source_map_matches_are_supported_but_not_confirmed_and_are_redacted():
    result = audit_sourcemap_content(
        "https://authorized.invalid/app.js.map",
        sources=["webpack:///src/config.ts", "webpack:///node_modules/pkg/index.js"],
        sources_content=[
            'export const key = "AKIAABCDEFGHIJKLMNOP";\n',
            'const key = "AKIAABCDEFGHIJKLMNOP";\n',
        ],
    )
    assert result["first_party_files"] == 1
    assert result["third_party_files"] == 1
    assert result["supported_findings"] == 1
    assert result["confirmed_findings"] == 0
    evidence = format_findings_as_evidence(result)
    assert "AKIAABCDEFGHIJKLMNOP" not in evidence
    assert "SUPPORTED" in evidence


def test_placeholder_secret_is_rejected():
    finding = classify_secret_evidence("AWS Secret Key", "your-secret-key", "src/config.ts")
    assert finding["status"] == "REJECTED"
    assert source_class("webpack:///node_modules/x/index.js") == "third_party"

