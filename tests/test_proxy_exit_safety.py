"""Regression: a crash/Ctrl+C must never leave the system proxy pointing at a
dead local port — that blackholes every app on the machine.

These tests never touch the real Windows registry: ownership records are
written straight to a temp file and ``restore_system_proxy`` is stubbed, so the
ownership/PID guard logic is tested in isolation.
"""
from __future__ import annotations

import atexit
import json
import os

import pytest

from blackoutkit import proxy_manager as pm


@pytest.fixture()
def ownership(tmp_path, monkeypatch):
    """Point the ownership record at a temp file and stub the real restore."""
    monkeypatch.setattr(pm, "_PROXY_OWNERSHIP_FILE", tmp_path / "proxy_ownership.json")
    restores: list = []
    monkeypatch.setattr(
        pm, "restore_system_proxy", lambda status: restores.append(status) or True
    )
    yield tmp_path / "proxy_ownership.json", restores


def _record(path, *, pid, target=None, snapshot=None):
    """Write an ownership record with full control over its fields."""
    payload = {
        "schema_version": 1,
        "snapshot": snapshot or {"enabled": False, "server": ""},
        "target": target,
        "pid": pid,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


# ── ownership PID ────────────────────────────────────────────────────────────

def test_ownership_record_stores_owner_pid(ownership):
    pm._write_proxy_ownership(
        {"enabled": False, "server": ""},
        {"enabled": True, "server": "127.0.0.1:10809"},
    )
    record = pm._read_proxy_ownership()
    assert record is not None
    assert record["pid"] == os.getpid()


def test_cleanup_is_scoped_to_the_owner_pid(ownership):
    path, restores = ownership
    _record(path, pid=999999)

    # A foreign process must NOT tear down a proxy someone else owns.
    assert pm.cleanup_owned_system_proxy(owner_pid=1) is False
    assert restores == []

    # The owner may.
    assert pm.cleanup_owned_system_proxy(owner_pid=999999) is True
    assert len(restores) == 1


def test_cleanup_without_pid_is_unscoped(ownership):
    """Legacy records with no pid stay restorable by anyone (backward compat)."""
    path, restores = ownership
    _record(path, pid=None)
    assert pm.cleanup_owned_system_proxy() is True
    assert len(restores) == 1


def test_cleanup_forgets_ownership_when_proxy_was_changed(ownership, monkeypatch):
    """If another process changed the proxy, forget ownership instead of clobbering it."""
    path, restores = ownership
    _record(path, pid=1234, target={"enabled": True, "server": "9.9.9.9:1"})
    monkeypatch.setattr(
        pm, "get_proxy_status", lambda: {"enabled": True, "server": "someone-else:2"}
    )
    assert pm.cleanup_owned_system_proxy(owner_pid=1234) is False
    assert restores == []
    assert pm._read_proxy_ownership() is None  # ownership forgotten


# ── atexit safety net ────────────────────────────────────────────────────────

def test_atexit_handler_restores_owned_proxy(ownership, monkeypatch):
    path, restores = ownership
    _record(path, pid=os.getpid())
    registered: list = []
    monkeypatch.setattr(atexit, "register", registered.append)

    pm.install_atexit_proxy_restore()
    assert len(registered) == 1

    registered[0]()  # simulate interpreter exit
    assert len(restores) == 1


def test_atexit_handler_never_touches_a_daemon_owned_proxy(ownership, monkeypatch):
    path, restores = ownership
    _record(path, pid=424242)  # owned by the daemon, not us
    registered: list = []
    monkeypatch.setattr(atexit, "register", registered.append)

    pm.install_atexit_proxy_restore()
    registered[0]()  # CLI exits
    assert restores == []  # the daemon's proxy is left alone


def test_atexit_handler_swallows_errors(ownership, monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(pm, "cleanup_owned_system_proxy", _boom)
    registered: list = []
    monkeypatch.setattr(atexit, "register", registered.append)

    pm.install_atexit_proxy_restore()
    registered[0]()  # must not raise


# ── console control events ───────────────────────────────────────────────────

def test_ctrl_events_cover_interrupt_and_close():
    """Ctrl+C (0) and Ctrl+Break (1) used to be unhandled — the reported bug."""
    assert 0 in pm._CTRL_EVENTS  # CTRL_C_EVENT
    assert 1 in pm._CTRL_EVENTS  # CTRL_BREAK_EVENT
    assert 2 in pm._CTRL_EVENTS  # CTRL_CLOSE_EVENT
    assert 5 in pm._CTRL_EVENTS  # CTRL_LOGOFF_EVENT
    assert 6 in pm._CTRL_EVENTS  # CTRL_SHUTDOWN_EVENT


def test_exports_include_the_new_helpers():
    assert "install_atexit_proxy_restore" in pm.__all__
