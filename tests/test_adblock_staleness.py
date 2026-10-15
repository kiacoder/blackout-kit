"""Regression tests for the advisory blocklist-staleness wiring.

Guards the `adblock_auto_update_interval_hours` setting (was dead: defined in
settings.py but read by nothing) and the doctor check that surfaces it.
The interval must never create background egress — staleness is advisory only.
"""
from datetime import datetime, timedelta, timezone

import pytest

from blackoutkit.tools import adblock


def _write_config(tmp_path, monkeypatch, sources):
    import json

    cfg_file = tmp_path / "adblock_config.json"
    cfg_file.write_text(json.dumps({"sources": sources}))
    monkeypatch.setattr(adblock, "_load_adblock_config", lambda: json.loads(cfg_file.read_text()))


def test_never_updated_source_is_stale(tmp_path, monkeypatch):
    _write_config(tmp_path, monkeypatch, [{"name": "easylist", "url": "https://x.test/l", "enabled": True}])
    assert [s["name"] for s in adblock.get_stale_sources(24)] == ["easylist"]


def test_fresh_source_is_not_stale(tmp_path, monkeypatch):
    fresh = datetime.now(timezone.utc).isoformat()
    _write_config(tmp_path, monkeypatch, [{"name": "easylist", "enabled": True, "last_update": fresh}])
    assert adblock.get_stale_sources(24) == []


def test_old_source_is_stale(tmp_path, monkeypatch):
    old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    _write_config(tmp_path, monkeypatch, [{"name": "easylist", "enabled": True, "last_update": old}])
    stale = adblock.get_stale_sources(24)
    assert len(stale) == 1
    assert stale[0]["age_hours"] >= 47


def test_disabled_source_is_never_stale(tmp_path, monkeypatch):
    old = (datetime.now(timezone.utc) - timedelta(hours=999)).isoformat()
    _write_config(tmp_path, monkeypatch, [{"name": "off", "enabled": False, "last_update": old}])
    assert adblock.get_stale_sources(24) == []


def test_zero_interval_disables_the_check(tmp_path, monkeypatch):
    _write_config(tmp_path, monkeypatch, [{"name": "easylist", "enabled": True}])
    assert adblock.get_stale_sources(0) == []


def test_garbage_timestamp_treated_as_stale(tmp_path, monkeypatch):
    _write_config(tmp_path, monkeypatch, [{"name": "broken", "enabled": True, "last_update": "not-a-date"}])
    assert [s["name"] for s in adblock.get_stale_sources(24)] == ["broken"]


def test_setting_exists_with_valid_choices():
    from blackoutkit import settings as cfg

    assert cfg.DEFAULTS["adblock_auto_update_interval_hours"] == 24
    assert "adblock_auto_update_interval_hours" in dict(cfg.SETTING_GROUPS)["Ad Blocking"]


def test_doctor_check_reports_staleness(tmp_path, monkeypatch):
    from blackoutkit import doctor

    old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    monkeypatch.setattr(doctor.cfg, "load", lambda: {
        "adblock_enabled": True,
        "adblock_auto_update_interval_hours": 24,
    })
    monkeypatch.setattr(adblock, "_load_adblock_config", lambda: {
        "sources": [{"name": "easylist", "enabled": True, "last_update": old}]
    })
    result = doctor.check_adblock_staleness()
    assert result.ok is False
    assert "easylist" in result.message
    assert "adblock update" in result.message
    # Advisory only: the fix path must never trigger downloads.
    assert result.fix is None


def test_doctor_check_quiet_when_disabled(monkeypatch):
    from blackoutkit import doctor

    monkeypatch.setattr(doctor.cfg, "load", lambda: {"adblock_enabled": False})
    result = doctor.check_adblock_staleness()
    assert result.ok is True
