"""Phase 7 — Enterprise & Team (blackoutkit.enterprise)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from blackoutkit.enterprise import (
    PERMISSIONS,
    AccessDenied,
    Device,
    DeviceRegistry,
    Policy,
    PolicyEngine,
    PolicyError,
    PolicyStore,
    Principal,
    checks_for,
    evaluate,
    evaluate_all,
    policy_fingerprint,
    sign_policy,
    verify_policy,
)


# ── RBAC ─────────────────────────────────────────────────────────────────────

def test_default_role_permissions():
    e = PolicyEngine()
    assert e.can(Principal("a", "viewer"), "view_status") is True
    assert e.can(Principal("a", "viewer"), "connect") is False
    assert e.can(Principal("a", "operator"), "connect") is True
    assert e.can(Principal("a", "operator"), "manage_policy") is False
    assert e.can(Principal("a", "admin"), "manage_policy") is True
    assert e.permissions_for("admin") == PERMISSIONS


def test_unknown_role_has_no_permissions():
    assert PolicyEngine().permissions_for("ghost") == frozenset()


def test_add_role_rejects_unknown_permission():
    with pytest.raises(ValueError):
        PolicyEngine().add_role("weird", ["view_status", "fly_to_moon"])


def test_require_raises_access_denied():
    e = PolicyEngine()
    e.require(Principal("a", "admin"), "connect")  # no raise
    with pytest.raises(AccessDenied):
        e.require(Principal("a", "viewer"), "connect")


def test_at_least():
    e = PolicyEngine()
    assert e.at_least(Principal("a", "admin"), "operator") is True
    assert e.at_least(Principal("a", "viewer"), "operator") is False


def test_check_is_explainable():
    out = PolicyEngine().check(Principal("a", "viewer"), "connect")
    assert out["allowed"] is False
    assert out["role"] == "viewer"
    assert "does not include" in out["reason"]


def test_role_names_ordered():
    assert PolicyEngine().role_names() == ["viewer", "operator", "admin"]


# ── Policy document ──────────────────────────────────────────────────────────

def test_policy_defaults_and_principal_resolution():
    p = Policy(principals={"alice": "admin"})
    assert p.principal("alice").role == "admin"
    assert p.principal("unknown").role == "viewer"  # default_role
    assert p.engine().can(p.principal("alice"), "manage_policy") is True


def test_policy_validate_rejects_unknown_permission():
    p = Policy(roles={"viewer": ["view_status", "nope"]})
    with pytest.raises(PolicyError):
        p.validate()


def test_policy_validate_rejects_bad_default_role():
    with pytest.raises(PolicyError):
        Policy(default_role="ghost").validate()


def test_policy_validate_rejects_undefined_principal_role():
    with pytest.raises(PolicyError):
        Policy(principals={"x": "ghost"}).validate()


def test_policy_from_dict_rejects_bad_shapes():
    with pytest.raises(PolicyError):
        Policy.from_dict(["not", "an", "object"])
    with pytest.raises(PolicyError):
        Policy.from_dict({"roles": "nope"})


def test_policy_roundtrip_dict():
    p = Policy(organization="Acme", principals={"a": "operator"})
    assert Policy.from_dict(p.to_dict()).principals == {"a": "operator"}


def test_fingerprint_is_stable_and_content_addressed():
    a = Policy(organization="Acme")
    b = Policy(organization="Acme")
    c = Policy(organization="Other")
    assert policy_fingerprint(a) == policy_fingerprint(b)
    assert policy_fingerprint(a) != policy_fingerprint(c)


# ── signing ──────────────────────────────────────────────────────────────────

def test_sign_and_verify():
    p = Policy(organization="Acme")
    sig = sign_policy(p, "secret")
    assert verify_policy(p, "secret", sig) is True
    assert verify_policy(p, "wrong", sig) is False
    assert verify_policy(p, "secret", "sha256=deadbeef") is False


# ── PolicyStore ──────────────────────────────────────────────────────────────

def test_store_roundtrip_unsigned(tmp_path):
    st = PolicyStore(tmp_path / "p.json")
    assert st.load().organization == ""  # default when missing
    st.save(Policy(organization="Acme", principals={"a": "admin"}))
    assert st.load().principals == {"a": "admin"}


def test_store_signed_roundtrip_and_verification(tmp_path):
    st = PolicyStore(tmp_path / "p.json")
    st.save(Policy(organization="Acme"), secret="k")
    assert st.load(secret="k").organization == "Acme"
    with pytest.raises(PolicyError):
        st.load(secret="wrong-secret")


def test_store_requires_signature_when_secret_given(tmp_path):
    st = PolicyStore(tmp_path / "p.json")
    st.save(Policy(organization="Acme"))  # unsigned
    with pytest.raises(PolicyError):
        st.load(secret="k")


def test_store_detects_tampering(tmp_path):
    path = tmp_path / "p.json"
    st = PolicyStore(path)
    st.save(Policy(organization="Acme"), secret="k")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["policy"]["organization"] = "Evil Corp"  # tamper
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PolicyError):
        st.load(secret="k")


def test_store_export_import(tmp_path):
    st = PolicyStore(tmp_path / "p.json")
    st.save(Policy(organization="Acme", principals={"a": "operator"}))
    exported = st.export(tmp_path / "shared.json")
    assert exported.exists()

    other = PolicyStore(tmp_path / "other.json")
    policy = other.import_(exported)
    assert policy.principals == {"a": "operator"}
    assert other.load().organization == "Acme"


# ── Devices ──────────────────────────────────────────────────────────────────

def test_device_requires_id():
    with pytest.raises(ValueError):
        Device.from_dict({"name": "no id"})


def test_registry_register_list_get_remove(tmp_path):
    r = DeviceRegistry(tmp_path / "d.json")
    assert r.register(Device(id="a", name="laptop")) is True
    assert r.register(Device(id="", name="bad")) is False
    assert [d.id for d in r.list()] == ["a"]
    assert r.get("a").name == "laptop"
    assert r.remove("a") is True
    assert r.remove("a") is False


def test_registry_persists(tmp_path):
    path = tmp_path / "d.json"
    DeviceRegistry(path).register(Device(id="a", name="laptop", status="connected"))
    assert DeviceRegistry(path).get("a").status == "connected"


def test_touch_updates_status(tmp_path):
    r = DeviceRegistry(tmp_path / "d.json")
    r.register(Device(id="a", status="idle"))
    assert r.touch("a", status="connected", engine="xray") is True
    d = r.get("a")
    assert d.status == "connected" and d.engine == "xray" and d.last_seen
    assert r.touch("ghost") is False


def test_is_online_threshold():
    now = datetime.now(timezone.utc)
    fresh = Device(id="a", status="connected", last_seen=(now - timedelta(seconds=10)).isoformat())
    stale = Device(id="b", status="connected", last_seen=(now - timedelta(seconds=9999)).isoformat())
    offline = Device(id="c", status="offline", last_seen=now.isoformat())
    assert fresh.is_online(now=now, threshold_sec=300) is True
    assert stale.is_online(now=now, threshold_sec=300) is False
    assert offline.is_online(now=now, threshold_sec=300) is False


def test_dashboard_aggregation(tmp_path):
    now = datetime.now(timezone.utc)
    r = DeviceRegistry(tmp_path / "d.json")
    r.register(Device(id="a", status="connected", last_seen=now.isoformat()))
    r.register(Device(id="b", status="offline", last_seen=now.isoformat()))
    r.register(Device(id="c", status="connected", last_seen=(now - timedelta(hours=2)).isoformat()))
    board = r.dashboard(now=now, threshold_sec=300)
    assert board["total"] == 3
    assert board["online"] == 1
    assert board["offline"] == 2
    assert board["by_status"]["connected"] == 2
    assert len(board["devices"]) == 3


# ── Compliance ───────────────────────────────────────────────────────────────

HARDENED = {
    "traffic_logging_enabled": False,
    "traffic_log_retention_days": 30,
    "adblock_query_log_enabled": False,
    "secrets_vault_enabled": True,
    "xray_doh_dns": True,
    "show_disclaimer": True,
    "tls_allow_insecure": False,
    "security_monitor_enabled": True,
    "plugins_enabled": False,
}


def test_evaluate_shape_and_score():
    out = evaluate("gdpr", settings=HARDENED)
    assert out["framework"] == "gdpr"
    assert out["total"] == len(out["checks"])
    assert out["score"] == round(out["passed"] / out["total"] * 100)
    assert "does not certify" in out["disclaimer"]


def test_gdpr_flags_logging_as_data_minimization_risk():
    ids = {c.id: c for c in checks_for("gdpr", settings={**HARDENED, "traffic_logging_enabled": True})}
    assert ids["data-minimization"].ok is False
    assert "traffic_logging_enabled" in ids["data-minimization"].remediation


def test_hipaa_audit_control_ok_when_logging_on():
    ids = {c.id: c for c in checks_for("hipaa", settings={**HARDENED, "traffic_logging_enabled": True})}
    assert ids["audit-controls"].ok is True


def test_hipaa_access_control_requires_policy():
    without = {c.id: c for c in checks_for("hipaa", settings=HARDENED, policy=None)}
    with_policy = {c.id: c for c in checks_for("hipaa", settings=HARDENED, policy=Policy(principals={"a": "admin"}))}
    assert without["access-control"].ok is False
    assert with_policy["access-control"].ok is True


def test_encryption_check_follows_vault_setting():
    on = {c.id: c for c in checks_for("gdpr", settings={**HARDENED, "secrets_vault_enabled": True})}
    off = {c.id: c for c in checks_for("gdpr", settings={**HARDENED, "secrets_vault_enabled": False})}
    assert on["encryption-at-rest"].ok is True
    assert off["encryption-at-rest"].ok is False


def test_evaluate_all_covers_every_framework():
    out = evaluate_all(settings=HARDENED)
    assert set(out) == {"gdpr", "hipaa", "soc2"}
    assert all(report["total"] > 0 for report in out.values())


def test_unknown_framework_raises():
    with pytest.raises(ValueError):
        evaluate("pci-dss")
