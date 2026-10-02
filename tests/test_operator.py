"""Tests for the deterministic operator recommendation layer."""
import json

from blackoutkit import operator


def _snapshot(**overrides):
    base = {
        "schema_version": 1,
        "vault": {"active": True, "healthy": True, "detail": "ok"},
        "daemon": {"running": False, "engine": "none", "status": "idle", "last_failure": None},
        "engines": {
            "ready": ["sni", "warp"],
            "recommended": {"engine": "sni", "score": 1000, "evidence": ""},
        },
        "recovery_hint": {"needed": False, "reasons": []},
        "events": {"recent": [], "recent_failures": []},
    }
    base.update(overrides)
    return base


def test_healthy_state_recommends_monitor_only():
    recs = operator.recommendations_from_snapshot(_snapshot())
    assert [rec.problem for rec in recs] == ["no_problem_detected"]
    top = recs[0]
    assert top.recommended_action == "monitor"
    assert top.safety == operator.READ_ONLY
    assert top.risk == "none"
    assert top.requires_confirmation is False


def test_unreadable_vault_prompts_doctor():
    recs = operator.recommendations_from_snapshot(_snapshot(
        vault={"active": True, "healthy": False, "detail": "cannot authenticate"},
    ))
    assert any(rec.problem == "encrypted_storage_unreadable" for rec in recs)
    assert recs[0].recommended_action == "run_doctor"


def test_no_ready_engines_prompts_doctor():
    recs = operator.recommendations_from_snapshot(_snapshot(
        engines={"ready": [], "recommended": None},
    ))
    assert any(rec.problem == "no_ready_engine" for rec in recs)


def test_recent_failure_suggests_retry_of_same_engine():
    recs = operator.recommendations_from_snapshot(_snapshot(
        daemon={"running": False, "engine": "sni", "status": "failed",
                "last_failure": {"engine": "sni", "reason": "timeout"}},
    ))
    retry = next(rec for rec in recs if rec.problem == "engine_recently_failed")
    # The failed engine is also the recommended one, so retry it directly.
    assert retry.recommended_action == "retry_engine"
    assert retry.params["engine"] == "sni"


def test_recent_failure_suggests_alternative_when_one_exists():
    recs = operator.recommendations_from_snapshot(_snapshot(
        daemon={"running": False, "engine": "xray", "status": "failed",
                "last_failure": {"engine": "xray", "reason": "timeout"}},
    ))
    # In this snapshot sni is recommended and differs from xray.
    switch = next(rec for rec in recs if rec.recommended_action == "connect_engine")
    assert switch.params["engine"] == "sni"
    assert switch.safety == operator.SAFE_REVERSIBLE
    assert switch.requires_confirmation is True


def test_stale_state_requires_privileged_confirmation():
    recs = operator.recommendations_from_snapshot(_snapshot(
        recovery_hint={"needed": True, "reasons": ["orphaned proxy ownership"]},
    ))
    fix = next(rec for rec in recs if rec.problem == "stale_blackout_state")
    assert fix.recommended_action == "clear_blackout_state"
    assert fix.safety == operator.PRIVILEGED_REVERSIBLE
    assert fix.requires_confirmation is True
    assert fix.requires_admin is True


def test_degraded_connection_recommends_reconnect():
    recs = operator.recommendations_from_snapshot(_snapshot(
        daemon={"running": True, "engine": "warp", "status": "reconnecting", "last_failure": None},
    ))
    assert any(rec.problem == "connection_degraded" for rec in recs)


def test_recommendations_are_json_serializable():
    payload = operator.build_recommendations()
    encoded = json.dumps(payload)
    assert "recommendations" in encoded
    assert payload["safety_levels"] == list(operator.SAFETY_LEVELS)


def test_action_catalog_safety_invariants():
    payload = operator.action_catalog_payload()
    by_name = {action["name"]: action for action in payload["actions"]}
    assert set(by_name) == set(operator.ACTION_CATALOG)
    for action in by_name.values():
        assert action["safety"] in operator.SAFETY_LEVELS
        if action["safety"] in {operator.DISRUPTIVE, operator.DESTRUCTIVE, operator.PRIVILEGED_REVERSIBLE}:
            assert action["requires_confirmation"] is True
    destructive = by_name["broad_network_reset"]
    assert destructive["safety"] == operator.DISRUPTIVE
    assert destructive["requires_confirmation"] is True


def test_catalog_references_match_recommendation_actions():
    # Every action a rule can recommend must exist in the catalog.
    exercisable = {
        "run_doctor", "monitor", "retry_engine", "connect_engine",
        "reconnect_engine", "clear_blackout_state",
    }
    assert exercisable <= set(operator.ACTION_CATALOG)


def test_no_observed_state_ever_yields_destructive_recommendation():
    snapshots = [
        _snapshot(),
        _snapshot(vault={"active": True, "healthy": False, "detail": "x"}),
        _snapshot(engines={"ready": [], "recommended": None}),
        _snapshot(daemon={"running": True, "engine": "warp", "status": "degraded", "last_failure": None}),
        _snapshot(recovery_hint={"needed": True, "reasons": ["stale proxy"]}),
    ]
    for snap in snapshots:
        for rec in operator.recommendations_from_snapshot(snap):
            assert rec.safety in {operator.READ_ONLY, operator.SAFE_REVERSIBLE, operator.PRIVILEGED_REVERSIBLE}
            assert rec.safety not in {operator.DESTRUCTIVE}
