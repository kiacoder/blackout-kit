"""Self-heal and VM safety (blackoutkit.self_heal).

No test here touches the real system: the heal functions are always stubbed and
the identity probes are monkeypatched, so these can run on any machine.
"""
from __future__ import annotations

import pytest

from blackoutkit import self_heal


# ── VM detection ─────────────────────────────────────────────────────────────

def test_detect_virtualization_shape(monkeypatch):
    monkeypatch.setattr(self_heal, "_windows_vm_identity", lambda: ("LENOVO", "21N5"))
    result = self_heal.detect_virtualization()
    assert result["is_virtual"] is False
    assert result["hypervisor"] == "none detected"
    assert result["manufacturer"] == "LENOVO"
    assert set(result) == {"is_virtual", "hypervisor", "manufacturer", "model"}


@pytest.mark.parametrize(
    "vendor, model, expected",
    [
        ("VMware, Inc.", "VMware Virtual Platform", "VMware"),
        ("innotek GmbH", "VirtualBox", "VirtualBox"),
        ("Microsoft Corporation", "Virtual Machine", "Hyper-V"),
        ("QEMU", "Standard PC", "QEMU/KVM"),
        ("Xen", "HVM domU", "Xen"),
    ],
)
def test_detect_virtualization_recognises_hypervisors(monkeypatch, vendor, model, expected):
    monkeypatch.setattr(self_heal, "_windows_vm_identity", lambda: (vendor, model))
    result = self_heal.detect_virtualization()
    assert result["is_virtual"] is True
    assert result["hypervisor"] == expected


def test_detect_virtualization_uses_the_linux_probe_off_windows(monkeypatch):
    monkeypatch.setattr(self_heal, "_linux_vm_identity", lambda: ("QEMU", "Standard PC"))
    monkeypatch.setattr(self_heal, "sys", type("S", (), {"platform": "linux"}))
    result = self_heal.detect_virtualization()
    assert result["is_virtual"] is True
    assert result["hypervisor"] == "QEMU/KVM"


# ── leftover inspection ──────────────────────────────────────────────────────

def test_leftover_state_shape(monkeypatch):
    monkeypatch.setattr(self_heal, "leftover_state", lambda: {
        "proxy": {"current": {}, "owned": False},
        "firewall_active": False,
        "tun_present": False,
        "any_leftover": False,
    })
    # safety_report should not suggest netfix when nothing is left over
    report = self_heal.safety_report()
    assert report["steps"] == []


def test_safety_report_recommends_recovery_when_state_is_left(monkeypatch):
    monkeypatch.setattr(self_heal, "leftover_state", lambda: {
        "proxy": {"owned": True},
        "firewall_active": True,
        "tun_present": False,
        "any_leftover": True,
    })
    monkeypatch.setattr(self_heal, "detect_virtualization", lambda: {
        "is_virtual": True, "hypervisor": "VMware", "manufacturer": "VMware", "model": "x",
    })
    steps = self_heal.safety_report()["steps"]
    assert any("netfix" in step for step in steps)
    assert any("snapshot" in step.lower() for step in steps)


# ── recovery-style steps ─────────────────────────────────────────────────────

def test_self_heal_steps_are_ok_when_there_is_nothing_to_clean(monkeypatch):
    """Having nothing to clean is a success, so netfix must not report failure."""
    monkeypatch.setattr(self_heal, "heal_proxy", lambda: {"cleared_dead_proxy": False, "restored_owned_proxy": False})
    monkeypatch.setattr(self_heal, "heal_firewall", lambda: {"firewall_cleared": False})
    monkeypatch.setattr(self_heal, "heal_tunnel", lambda: {"tunnel_removed": False, "detail": "not Linux"})

    steps = self_heal.self_heal_steps()
    assert len(steps) == 3
    assert all(step["ok"] is True for step in steps)
    assert all(step["detail"] == "nothing to clean" for step in steps)


def test_self_heal_steps_report_what_changed(monkeypatch):
    monkeypatch.setattr(self_heal, "heal_proxy", lambda: {"cleared_dead_proxy": True, "restored_owned_proxy": False})
    monkeypatch.setattr(self_heal, "heal_firewall", lambda: {"firewall_cleared": True})
    monkeypatch.setattr(self_heal, "heal_tunnel", lambda: {"tunnel_removed": False, "detail": "not Linux"})

    steps = {step["name"]: step for step in self_heal.self_heal_steps()}
    assert steps["Clear dead system proxy"]["detail"] == "cleared_dead_proxy=True"
    assert steps["Remove owned firewall rules"]["detail"] == "firewall_cleared=True"


def test_self_heal_steps_mark_a_real_failure(monkeypatch):
    def _boom():
        raise RuntimeError("registry locked")

    monkeypatch.setattr(self_heal, "heal_proxy", _boom)
    monkeypatch.setattr(self_heal, "heal_firewall", lambda: {"firewall_cleared": False})
    monkeypatch.setattr(self_heal, "heal_tunnel", lambda: {"tunnel_removed": False, "detail": "not Linux"})

    steps = {step["name"]: step for step in self_heal.self_heal_steps()}
    assert steps["Clear dead system proxy"]["ok"] is False
    assert steps["Clear dead system proxy"]["detail"] == "RuntimeError"


def test_plan_self_heal_steps_is_read_only():
    steps = self_heal.plan_self_heal_steps()
    assert len(steps) == 3
    assert all(step["ok"] is True for step in steps)


# ── heal_all ─────────────────────────────────────────────────────────────────

def test_heal_all_passes_the_from_daemon_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(self_heal, "heal_proxy", lambda: {})
    monkeypatch.setattr(self_heal, "heal_firewall", lambda: {})
    monkeypatch.setattr(self_heal, "heal_tunnel", lambda: {})

    def _fake_recovery(*, audit_source, from_daemon):
        captured["audit_source"] = audit_source
        captured["from_daemon"] = from_daemon
        return []

    import blackoutkit.tools as tools

    monkeypatch.setattr(tools, "run_network_recovery", _fake_recovery)

    self_heal.heal_all(from_daemon=False)
    assert captured == {"audit_source": "self_heal", "from_daemon": False}

    self_heal.heal_all()
    assert captured["from_daemon"] is True


def test_heal_all_survives_a_recovery_failure(monkeypatch):
    monkeypatch.setattr(self_heal, "heal_proxy", lambda: {})
    monkeypatch.setattr(self_heal, "heal_firewall", lambda: {})
    monkeypatch.setattr(self_heal, "heal_tunnel", lambda: {})

    def _boom(**kwargs):
        raise RuntimeError("netsh missing")

    import blackoutkit.tools as tools

    monkeypatch.setattr(tools, "run_network_recovery", _boom)
    report = self_heal.heal_all()
    assert report["recovery_error"] == "RuntimeError"
    assert "proxy" in report  # the rest still ran
