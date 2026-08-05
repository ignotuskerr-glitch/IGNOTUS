from pathlib import Path

from core.asset_catalog import ASSET_CATEGORIES, CATALOG_PATH
from core.asset_hunter import ASSET_CATEGORIES as RUNTIME_CATEGORIES


def test_operational_catalog_is_external_and_large():
    assert CATALOG_PATH.name == "asset_catalog.json"
    assert CATALOG_PATH.is_file()
    assert len(CATALOG_PATH.read_text(encoding="utf-8").splitlines()) >= 3000
    assert sum(len(item["paths"]) for item in ASSET_CATEGORIES.values()) >= 3000
    assert RUNTIME_CATEGORIES is ASSET_CATEGORIES


def test_catalog_keeps_validators_for_impact_gating():
    assert ASSET_CATEGORIES["env_files"]["validator_name"] == "env"
    assert ASSET_CATEGORIES["database_dumps"]["validator_name"] == "database_dump"
    assert ASSET_CATEGORIES["source_maps"]["validator_name"] == "source_map"
    assert all(path.startswith("/") for item in ASSET_CATEGORIES.values() for path in item["paths"])

