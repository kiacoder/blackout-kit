import json
from pathlib import Path
from unittest.mock import patch

import pytest
from packaging.requirements import Requirement


def test_all_feature_torrent_dependency_targets_supported_platforms():
    import tomllib

    metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    torrent_requirements = metadata["project"]["optional-dependencies"]["all"]
    requirement = next(item for item in torrent_requirements if item.startswith("libtorrent"))

    parsed = Requirement(requirement)
    assert parsed.marker is not None
    assert parsed.marker.evaluate({"sys_platform": "win32", "python_version": "3.12"}) is False
    assert parsed.marker.evaluate({"sys_platform": "win32", "python_version": "3.11"}) is False
    assert parsed.marker.evaluate({"sys_platform": "linux", "python_version": "3.12"}) is True
    assert parsed.marker.evaluate({"sys_platform": "linux", "python_version": "3.14"}) is False


from blackoutkit import settings
from blackoutkit.config import manager


def test_settings_legacy_file_loads_without_schema_marker(monkeypatch, tmp_path):
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps({"proxy_port": 12345}), encoding="utf-8")
    monkeypatch.setattr(settings, "SETTINGS_FILE", settings_file)
    monkeypatch.setattr(settings, "APP_DATA_DIR", tmp_path)

    assert settings.load()["proxy_port"] == 12345


def test_settings_save_writes_schema_marker(monkeypatch, tmp_path):
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "SETTINGS_FILE", settings_file)
    monkeypatch.setattr(settings, "APP_DATA_DIR", tmp_path)

    settings.save(dict(settings.DEFAULTS))

    assert json.loads(settings_file.read_text(encoding="utf-8"))["_schema_version"] == settings.SETTINGS_SCHEMA_VERSION


def test_future_settings_schema_falls_back_to_defaults(monkeypatch, tmp_path):
    settings_file = tmp_path / "settings.json"
    settings_file.write_text(json.dumps({"_schema_version": 999, "proxy_port": 12345}), encoding="utf-8")
    monkeypatch.setattr(settings, "SETTINGS_FILE", settings_file)
    monkeypatch.setattr(settings, "APP_DATA_DIR", tmp_path)

    assert settings.load()["proxy_port"] == settings.DEFAULTS["proxy_port"]


def test_setup_serialization_includes_schema_version(monkeypatch):
    monkeypatch.setattr(manager, "load_configs", lambda: [])
    monkeypatch.setattr("blackoutkit.settings.load", lambda: dict(settings.DEFAULTS))

    payload = manager.serialize_setup()

    assert payload["schema_version"] == manager.SETUP_SCHEMA_VERSION


def test_legacy_setup_deserializes_without_schema_version():
    configs, values = manager.deserialize_setup({"configs": [], "settings": {"proxy_port": 12345}})

    assert configs == []
    assert values == {"proxy_port": 12345}


def test_future_setup_schema_is_rejected_before_parsing():
    with pytest.raises(ValueError, match="Unsupported setup schema version"):
        manager.deserialize_setup({"schema_version": 999, "configs": [], "settings": {}})


def test_setup_schema_rejects_non_integer_version():
    with pytest.raises(ValueError, match="Unsupported setup schema version"):
        manager.deserialize_setup({"schema_version": "1", "configs": [], "settings": {}})
