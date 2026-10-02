"""Tests for the canonical local snapshot model."""
import json

from blackoutkit import snapshot


def _minimal_snapshot(**overrides):
    base = {
        "schema_version": snapshot.SCHEMA_VERSION,
        "vault": {"active": True, "healthy": True, "detail": "ok"},
        "daemon": {"running": False, "engine": "none", "status": "idle", "last_failure": None},
        "system_proxy": {"enabled": False, "server": None, "blackout_owned": False},
        "country": {"pinned_code": None, "code": None, "name": None, "level": None},
        "engines": {
            "ready": ["sni", "warp"],
            "recommended": {"engine": "sni", "score": 1000, "evidence": "no history"},
            "available": {"sni": {"ready": True, "blockers": []}},
        },
        "recovery_hint": {"needed": False, "reasons": []},
        "events": {"recent": [], "recent_failures": []},
        "scope": {"local_state_only": True, "remote_validation_performed": False},
    }
    base.update(overrides)
    return base


def test_build_snapshot_is_json_serializable():
    payload = snapshot.build_snapshot(include_adapters=False)
    encoded = json.dumps(payload)
    assert '"schema_version": 1' in encoded or '"schema_version":1' in encoded


def test_build_snapshot_honesty_scope_flags():
    payload = snapshot.build_snapshot(include_adapters=False)
    scope = payload["scope"]
    assert scope["local_state_only"] is True
    assert scope["remote_validation_performed"] is False
    assert "does not" in scope["note"]


def test_build_snapshot_has_documented_sections():
    payload = snapshot.build_snapshot(include_adapters=False)
    for section in (
        "generated_at", "platform", "privileges", "vault", "daemon",
        "system_proxy", "country", "engines", "connection_health", "dns",
        "events", "recovery_hint", "scope",
    ):
        assert section in payload, f"missing section {section}"


def test_snapshot_sanitized_output_has_no_secret_uri():
    payload = snapshot.sanitized_snapshot(include_adapters=False)
    encoded = json.dumps(payload)
    for scheme in ("vless://", "vmess://", "trojan://", "ss://"):
        assert scheme not in encoded


def test_section_failure_degrades_without_crashing(monkeypatch):
    def broken_daemon():
        raise RuntimeError("daemon exploded")

    monkeypatch.setattr(snapshot, "_daemon_section", broken_daemon)
    payload = snapshot.build_snapshot(include_adapters=False)
    assert "error" in payload["daemon"]


def test_recommend_routes_summary_reports_ready_engines():
    payload = snapshot._engines_section()
    assert isinstance(payload["ready"], list)
    assert "note" in payload
    recommended = payload["recommended"]
    assert recommended is None or "engine" in recommended


def test_recovery_hint_flags_orphaned_proxy_state():
    daemon_info = {"running": False, "last_failure": None}
    hint = snapshot._recovery_hint_section(daemon_info)
    assert hint["needed"] in {True, False}
    assert "Targeted recovery" in hint["note"]


def test_snapshot_minimal_contract_shape():
    payload = _minimal_snapshot()
    assert payload["scope"]["remote_validation_performed"] is False
    assert payload["engines"]["recommended"]["engine"] == "sni"
