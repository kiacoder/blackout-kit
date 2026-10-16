"""Phase 8 — Python SDK (blackoutkit.sdk)."""
from __future__ import annotations

from pathlib import Path

import pytest

import blackoutkit
from blackoutkit.sdk import (
    Blackout,
    BlackoutError,
    DependencyError,
    EngineError,
    NotConnectedError,
    SettingsError,
)


@pytest.fixture()
def bk():
    return Blackout()


# ── exceptions ───────────────────────────────────────────────────────────────

def test_exception_hierarchy():
    for exc in (NotConnectedError, EngineError, SettingsError, DependencyError):
        assert issubclass(exc, BlackoutError)
    assert issubclass(BlackoutError, Exception)


# ── metadata ─────────────────────────────────────────────────────────────────

def test_version_matches_package(bk):
    assert bk.version == blackoutkit.__version__


# ── settings ─────────────────────────────────────────────────────────────────

def test_get_setting_unknown_raises(bk):
    with pytest.raises(SettingsError):
        bk.get_setting("definitely_not_a_setting")


def test_get_setting_returns_value(bk, monkeypatch):
    import blackoutkit.settings as cfg

    monkeypatch.setattr(cfg, "load", lambda: {"country": "IR"})
    assert bk.get_setting("country") == "IR"


def test_set_setting_translates_value_error(bk, monkeypatch):
    import blackoutkit.settings as cfg

    def _boom(key, value):
        raise ValueError("must be true or false")

    monkeypatch.setattr(cfg, "set_value", _boom)
    with pytest.raises(SettingsError):
        bk.set_setting("adblock_enabled", "maybe")


def test_set_setting_delegates(bk, monkeypatch):
    import blackoutkit.settings as cfg

    calls = []
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.append((k, v)))
    bk.set_setting("country", "RU")
    assert calls == [("country", "RU")]


# ── engines & capabilities ───────────────────────────────────────────────────

def test_engines_sorted(bk, monkeypatch):
    import blackoutkit.capabilities as caps

    monkeypatch.setattr(caps, "supported_engine_names", lambda platform=None: {"xray", "auto", "sni"})
    assert bk.engines() == ["auto", "sni", "xray"]


def test_capabilities_all(bk, monkeypatch):
    import blackoutkit.capabilities as caps

    monkeypatch.setattr(caps, "all_capabilities", lambda **kw: ["A", "B"])
    monkeypatch.setattr(caps, "serialize_capability", lambda c: {"name": c})
    assert bk.capabilities() == [{"name": "A"}, {"name": "B"}]


def test_capabilities_unknown_engine_raises(bk, monkeypatch):
    import blackoutkit.capabilities as caps

    monkeypatch.setattr(caps, "get_capability", lambda name: None)
    with pytest.raises(BlackoutError):
        bk.capabilities("nope")


# ── readiness & diagnostics ──────────────────────────────────────────────────

def test_readiness_shape(bk, monkeypatch):
    import blackoutkit.readiness as rd

    monkeypatch.setattr(rd, "ready", lambda engine, **kw: True)
    monkeypatch.setattr(rd, "as_dicts", lambda engine: [{"name": "port", "ok": True}])
    result = bk.readiness("xray")
    assert result["engine"] == "xray"
    assert result["ready"] is True
    assert result["checks"] == [{"name": "port", "ok": True}]


class _FakeCheck:
    def __init__(self, name, ok, message, fixable=False, issue_type=None):
        self.name = name
        self.ok = ok
        self.message = message
        self.fixable = fixable
        self.issue_type = issue_type


def test_doctor_shape(bk, monkeypatch):
    import blackoutkit.doctor as doctor

    monkeypatch.setattr(
        doctor, "run_all_checks",
        lambda **kw: [_FakeCheck("bins", False, "missing", fixable=True, issue_type="bins")],
    )
    out = bk.doctor()
    assert out == [{"name": "bins", "ok": False, "message": "missing",
                    "fixable": True, "issue_type": "bins"}]


# ── daemon / connection control ──────────────────────────────────────────────

def test_status_and_connected(bk, monkeypatch):
    import blackoutkit.daemon as daemon

    monkeypatch.setattr(daemon, "get_pid", lambda: 4242)
    monkeypatch.setattr(daemon, "get_state", lambda: {"engine": "xray"})
    st = bk.status()
    assert st == {"running": True, "pid": 4242, "state": {"engine": "xray"}}
    assert bk.connected is True


def test_connect_uses_selected_engine_by_default(bk, monkeypatch):
    import blackoutkit.daemon as daemon
    import blackoutkit.settings as cfg

    monkeypatch.setattr(cfg, "load", lambda: {"selected_engine": "sni"})
    seen = {}

    def _start(engine, env=None):
        seen["engine"] = engine
        return 777

    monkeypatch.setattr(daemon, "start", _start)
    result = bk.connect()
    assert result == {"engine": "sni", "pid": 777}
    assert seen["engine"] == "sni"


def test_connect_translates_runtime_error(bk, monkeypatch):
    import blackoutkit.daemon as daemon

    def _boom(engine, env=None):
        raise RuntimeError("Daemon already running (PID 1).")

    monkeypatch.setattr(daemon, "start", _boom)
    with pytest.raises(EngineError):
        bk.connect("xray")


def test_disconnect(bk, monkeypatch):
    import blackoutkit.daemon as daemon

    monkeypatch.setattr(daemon, "stop", lambda: True)
    assert bk.disconnect() is True


# ── observability passthrough ────────────────────────────────────────────────

def test_metrics_delegates(bk, monkeypatch):
    import blackoutkit.api as api

    monkeypatch.setattr(api, "collect_metrics", lambda: {"available": True, "cpu_percent": 5})
    assert bk.metrics()["cpu_percent"] == 5


def test_connections_delegates_filters(bk, monkeypatch):
    import blackoutkit.api as api

    captured = {}

    def _collect(**kw):
        captured.update(kw)
        return {"available": True, "count": 0, "connections": []}

    monkeypatch.setattr(api, "collect_connections", _collect)
    bk.connections(process="chrome", port=443, established_only=True)
    assert captured == {"established_only": True, "process": "chrome", "port": 443}


def test_bandwidth_delegates(bk, monkeypatch):
    import blackoutkit.api as api

    monkeypatch.setattr(api, "collect_bandwidth", lambda: {"available": True, "totals": {}})
    assert bk.bandwidth()["available"] is True


def test_anomalies_delegates_and_serialises(bk, monkeypatch):
    import blackoutkit.anomaly_detector as ad

    real = ad.Anomaly(
        timestamp="2026-10-15T00:00:00+00:00", anomaly_type="spike",
        severity="high", description="boom", affected_ip="1.2.3.4",
    )

    class _FakeDetector:
        def __init__(self, *a, **kw):
            pass

        def get_anomalies(self, since=None, severity=None):
            return [real]

    monkeypatch.setattr(ad, "AnomalyDetector", _FakeDetector)
    out = bk.anomalies(hours=1)
    assert out[0]["anomaly_type"] == "spike"


def test_threat_stats_delegates(bk, monkeypatch):
    import blackoutkit.threat_feeds as tf

    monkeypatch.setattr(tf, "ThreatFeedsManager", lambda *a, **kw: type("M", (), {"get_stats": lambda self: {"blocked_ips": 3}})())
    assert bk.threat_stats() == {"blocked_ips": 3}


def test_recommendations_delegates(bk, monkeypatch):
    import blackoutkit.predictor as pred

    real = pred.OptimizationRecommendation(
        timestamp="t", recommendation_type="transport", current_value="https",
        suggested_value="xhttp", reason="r", expected_improvement_pct=10.0, confidence=0.7,
    )
    monkeypatch.setattr(pred, "Predictor", lambda *a, **kw: type("P", (), {"get_all_recommendations": lambda self: [real]})())
    assert bk.recommendations()[0]["recommendation_type"] == "transport"


def test_benchmark_delegates(bk, monkeypatch):
    import blackoutkit.benchmarks as bm

    monkeypatch.setattr(bm, "run_benchmarks", lambda samples=20: {"samples": samples})
    assert bk.benchmark(samples=7) == {"samples": 7}


def test_report_delegates(bk, monkeypatch):
    import blackoutkit.reporting as rep

    monkeypatch.setattr(rep, "ReportGenerator", lambda *a, **kw: type(
        "R", (), {"export": lambda self, out, **kw: Path(out)})(),
    )
    assert bk.report(Path("/tmp/x.csv"), format="csv") == Path("/tmp/x.csv")


def test_report_translates_value_error(bk, monkeypatch):
    import blackoutkit.reporting as rep

    def _boom(self, out, **kw):
        raise ValueError("Unsupported report format: xml")

    monkeypatch.setattr(rep, "ReportGenerator", lambda *a, **kw: type("R", (), {"export": _boom})())
    with pytest.raises(BlackoutError):
        bk.report(Path("/tmp/x.xml"), format="xml")


# ── enterprise (Phase 7) ─────────────────────────────────────────────────────

def test_sdk_roles_and_policy(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKOUT_POLICY_FILE", str(tmp_path / "p.json"))
    from blackoutkit.enterprise import Policy, PolicyStore

    PolicyStore(tmp_path / "p.json").save(
        Policy(organization="Acme", principals={"alice": "admin", "bob": "viewer"})
    )
    bk = Blackout()
    assert [r["name"] for r in bk.roles()] == ["viewer", "operator", "admin"]
    assert bk.policy()["organization"] == "Acme"
    assert bk.can("alice", "manage_policy")["allowed"] is True
    assert bk.can("bob", "manage_policy")["allowed"] is False


def test_sdk_can_with_unknown_permission(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKOUT_POLICY_FILE", str(tmp_path / "p.json"))
    out = Blackout().can("anyone", "fly_to_the_moon")
    assert out["allowed"] is False
    assert "does not include" in out["reason"]


def test_sdk_devices(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKOUT_DEVICE_FILE", str(tmp_path / "d.json"))
    from blackoutkit.enterprise import Device, DeviceRegistry

    DeviceRegistry(tmp_path / "d.json").register(Device(id="a", status="connected"))
    board = Blackout().devices()
    assert board["total"] == 1


def test_sdk_compliance():
    out = Blackout().compliance("gdpr")
    assert out["framework"] == "gdpr"
    assert out["total"] > 0
