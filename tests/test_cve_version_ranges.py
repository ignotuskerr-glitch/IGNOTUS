from core.cve_lookup import _nvd_affects_version


def _configuration(**range_values):
    match = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
        **range_values,
    }
    return [{"nodes": [{"cpeMatch": [match]}]}]


def test_nvd_exclusive_fixed_version_is_not_reported():
    configurations = _configuration(versionEndExcluding="1.22.1")

    assert _nvd_affects_version(configurations, "nginx", "1.22.0")
    assert not _nvd_affects_version(configurations, "nginx", "1.22.1")


def test_nvd_inclusive_range_accepts_boundary():
    configurations = _configuration(
        versionStartIncluding="1.20.0",
        versionEndIncluding="1.22.1",
    )

    assert _nvd_affects_version(configurations, "nginx", "1.22.1")
