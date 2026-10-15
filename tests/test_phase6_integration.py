"""Phase 6 — integration: daemon gating, setting registration, predictor apply."""
from __future__ import annotations

import pytest

from blackoutkit import settings as cfg
from blackoutkit.daemon import _build_traffic_monitor
from blackoutkit.settings import coerce_value
from blackoutkit.typer_cli import _apply_recommendations


# ── setting registration ─────────────────────────────────────────────────────

def test_security_monitor_setting_registered():
    assert "security_monitor_enabled" in cfg.DEFAULTS
    assert cfg.DEFAULTS["security_monitor_enabled"] is False
    assert any(
        "security_monitor_enabled" in keys for keys in cfg.SETTING_GROUPS.values()
    ), "setting must belong to a group so it appears in the settings UI"
    assert coerce_value("security_monitor_enabled", "yes") is True
    assert coerce_value("security_monitor_enabled", "off") is False
    with pytest.raises(ValueError):
        coerce_value("security_monitor_enabled", "maybe")


# ── daemon traffic-monitor gating ────────────────────────────────────────────

def test_build_traffic_monitor_none_when_all_disabled():
    assert _build_traffic_monitor({}) is None


def test_build_traffic_monitor_security_only(monkeypatch):
    monkeypatch.setattr("blackoutkit.security_observer.SecurityObserver", lambda: "OBS")
    monitor = _build_traffic_monitor({"security_monitor_enabled": True})
    assert monitor is not None
    assert monitor._observer == "OBS"
    # detection-only: a no-op log writer keeps connections out of the audit trail
    assert callable(monitor._log_writer)


def test_build_traffic_monitor_logging_only(monkeypatch):
    monkeypatch.setattr("blackoutkit.security_observer.SecurityObserver", lambda: "OBS")
    monitor = _build_traffic_monitor({"traffic_logging_enabled": True})
    assert monitor is not None
    assert monitor._observer is None
    assert monitor._log_writer is None  # default audit-log writer


def test_build_traffic_monitor_both(monkeypatch):
    monkeypatch.setattr("blackoutkit.security_observer.SecurityObserver", lambda: "OBS")
    monitor = _build_traffic_monitor(
        {"traffic_logging_enabled": True, "security_monitor_enabled": True}
    )
    assert monitor._observer == "OBS"
    assert monitor._log_writer is None  # real audit log when logging is on


# ── predictor apply ──────────────────────────────────────────────────────────

def test_apply_recommendations_applies_config_rotation_only(monkeypatch):
    calls = []
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.append((k, v)))
    out = _apply_recommendations([
        {"recommendation_type": "config_rotation"},
        {"recommendation_type": "transport"},
        {"recommendation_type": "dns"},
    ])
    assert calls == [("config_rotation", True)]
    assert out["applied"] == [{"setting": "config_rotation", "value": True}]
    assert {m["type"] for m in out["manual"]} == {"transport", "dns"}


def test_apply_recommendations_reports_failure_as_manual(monkeypatch):
    def _boom(key, value):
        raise ValueError("read-only settings")

    monkeypatch.setattr(cfg, "set_value", _boom)
    out = _apply_recommendations([{"recommendation_type": "config_rotation"}])
    assert out["applied"] == []
    assert out["manual"] and "could not apply" in out["manual"][0]["reason"]
