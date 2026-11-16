import json
import logging
from pathlib import Path

import pytest

from app.config import Settings
from runner.catalog import CATALOG_PATH, CatalogError, load_catalog, load_installed_catalog


def custom_catalog(tmp_path: Path, host: str) -> Path:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    data["runbooks"]["container_restart"]["hosts"] = [host]
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_the_shipped_catalog_is_used_when_there_is_no_custom_file(tmp_path: Path) -> None:
    assert load_installed_catalog(tmp_path / "missing.json").digest == load_catalog().digest


def test_a_custom_file_replaces_the_shipped_catalog(tmp_path: Path) -> None:
    catalog = load_installed_catalog(custom_catalog(tmp_path, "web-1"))
    assert catalog.runbooks["container_restart"].hosts == ("web-1",)
    assert catalog.digest != load_catalog().digest  # hosts are part of what the runner compares


def test_a_schema_error_stops_the_start_instead_of_falling_back(tmp_path: Path) -> None:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"version": 1, "runbooks": {"x": {}}}), encoding="utf-8")
    with pytest.raises(CatalogError, match="catalog.json"):
        load_installed_catalog(path)


def test_invalid_json_is_a_catalog_error_that_names_the_file(tmp_path: Path) -> None:
    path = tmp_path / "catalog.json"
    path.write_text('{"version": 1,}', encoding="utf-8")
    with pytest.raises(CatalogError, match="catalog.json"):
        load_installed_catalog(path)


def test_a_missing_file_is_an_error_when_the_path_was_set_on_purpose(tmp_path: Path) -> None:
    with pytest.raises(CatalogError, match="typo.json"):
        load_installed_catalog(tmp_path / "typo.json", required=True)


def test_a_folder_with_other_files_but_no_catalog_is_warned_about(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "catalogue.json").write_text("{}", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        load_installed_catalog(tmp_path / "catalog.json")
    assert "catalog.json is missing" in caplog.text


def test_the_service_default_is_the_folder_compose_mounts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CATALOG_FILE", raising=False)
    assert Settings(_env_file=None).catalog_file == Path("/etc/pikett/catalog.json")  # type: ignore[call-arg]
