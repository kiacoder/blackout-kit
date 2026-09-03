import json
from unittest.mock import MagicMock, patch

import psutil

from blackoutkit import daemon
from blackoutkit import watchdog


def _lease(tmp_path, *, pid=1234, generation="generation-a", create_time=10.0):
    lease_path = tmp_path / "daemon.lease.json"
    lease_path.write_text(json.dumps({
        "schema_version": 1,
        "pid": pid,
        "generation": generation,
        "create_time": create_time,
    }), encoding="utf-8")
    return lease_path


def _patch_watchdog_paths(monkeypatch, tmp_path):
    lease_path = tmp_path / "daemon.lease.json"
    lifecycle_path = tmp_path / "daemon.lifecycle.lock"
    monkeypatch.setattr(daemon, "LEASE_FILE", lease_path)
    monkeypatch.setattr(daemon, "LIFECYCLE_LOCK_FILE", lifecycle_path)
    monkeypatch.setattr(watchdog, "LEASE_FILE", lease_path, raising=False)
    monkeypatch.setattr(watchdog, "LIFECYCLE_LOCK_FILE", lifecycle_path, raising=False)
    monkeypatch.setattr(watchdog, "psutil", psutil)
    monkeypatch.setattr(watchdog, "read_lease", lambda path: daemon.read_lease(path))
    return lease_path


def test_monitor_without_generation_fails_closed(monkeypatch):
    process = MagicMock(side_effect=AssertionError("process observation was not allowed"))
    monkeypatch.setattr(watchdog.psutil, "Process", process)

    assert watchdog.monitor(1234) is False
    process.assert_not_called()


def test_monitor_missing_lease_does_not_cleanup(monkeypatch, tmp_path):
    _patch_watchdog_paths(monkeypatch, tmp_path)
    cleanup = MagicMock()
    monkeypatch.setattr(watchdog, "perform_watchdog_cleanup", MagicMock(return_value=False), raising=False)

    assert watchdog.monitor(1234, "generation-a") is False
    cleanup.assert_not_called()


def test_monitor_matching_generation_and_gone_process_cleans_owned_state(monkeypatch, tmp_path):
    _patch_watchdog_paths(monkeypatch, tmp_path)
    _lease(tmp_path)
    original_process = psutil.Process
    def fake_process(pid=None):
        if pid == 1234:
            raise psutil.NoSuchProcess(1234)
        return original_process(pid)
    monkeypatch.setattr(watchdog.psutil, "Process", MagicMock(side_effect=fake_process))
    monkeypatch.setattr(watchdog.psutil, "pid_exists", MagicMock(return_value=False))
    cleanup = MagicMock()
    monkeypatch.setattr(watchdog, "perform_watchdog_cleanup", lambda *args, **kwargs: (cleanup(), True)[1], raising=False)

    assert watchdog.monitor(1234, "generation-a") is True
    cleanup.assert_called_once()


def test_monitor_mismatched_generation_never_cleans_newer_lease(monkeypatch, tmp_path):
    _patch_watchdog_paths(monkeypatch, tmp_path)
    _lease(tmp_path, generation="generation-new")
    original_process = psutil.Process
    def fake_process(pid=None):
        if pid == 1234:
            raise AssertionError("stale watchdog observed process")
        return original_process(pid)
    monkeypatch.setattr(watchdog.psutil, "Process", MagicMock(side_effect=fake_process))
    cleanup = MagicMock()
    monkeypatch.setattr(watchdog, "perform_watchdog_cleanup", cleanup, raising=False)

    assert watchdog.monitor(1234, "generation-old") is False
    cleanup.assert_not_called()


def test_monitor_unknown_identity_does_not_cleanup(monkeypatch, tmp_path):
    _patch_watchdog_paths(monkeypatch, tmp_path)
    _lease(tmp_path)
    original_process = psutil.Process
    def fake_process(pid=None):
        if pid == 1234:
            raise psutil.AccessDenied(1234)
        return original_process(pid)
    monkeypatch.setattr(watchdog.psutil, "Process", MagicMock(side_effect=fake_process))
    monkeypatch.setattr(watchdog.psutil, "pid_exists", MagicMock(return_value=False))
    cleanup = MagicMock()
    monkeypatch.setattr("blackoutkit.proxy_manager.cleanup_owned_system_proxy", cleanup)

    assert watchdog.monitor(1234, "generation-a") is False
    cleanup.assert_not_called()


def test_monitor_pid_reuse_does_not_cleanup(monkeypatch, tmp_path):
    _patch_watchdog_paths(monkeypatch, tmp_path)
    _lease(tmp_path, create_time=10.0)
    original_process = psutil.Process
    def fake_process(pid=None):
        if pid == 1234:
            return MagicMock(create_time=lambda: 20.0)
        return original_process(pid)
    monkeypatch.setattr(watchdog.psutil, "Process", MagicMock(side_effect=fake_process))
    monkeypatch.setattr(watchdog.psutil, "pid_exists", MagicMock(return_value=True))
    cleanup = MagicMock()
    monkeypatch.setattr("blackoutkit.proxy_manager.cleanup_owned_system_proxy", cleanup)

    assert watchdog.monitor(1234, "generation-a") is False
    cleanup.assert_not_called()


def test_monitor_rejects_generation_change_after_process_wait(monkeypatch, tmp_path):
    _patch_watchdog_paths(monkeypatch, tmp_path)
    lease_path = _lease(tmp_path)
    proc = MagicMock()
    original_process = psutil.Process
    def fake_process(pid=None):
        if pid == 1234:
            return proc
        return original_process(pid)
    monkeypatch.setattr(watchdog.psutil, "Process", MagicMock(side_effect=fake_process))
    monkeypatch.setattr(watchdog.psutil, "pid_exists", MagicMock(return_value=False))
    cleanup = MagicMock()
    monkeypatch.setattr("blackoutkit.proxy_manager.cleanup_owned_system_proxy", cleanup)

    def replace_lease_after_wait(path):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if path == lease_path and proc.wait.called:
            payload["generation"] = "generation-new"
            path.write_text(json.dumps(payload), encoding="utf-8")
        return daemon.read_lease(path)

    monkeypatch.setattr(watchdog, "read_lease", replace_lease_after_wait)

    assert watchdog.monitor(1234, "generation-a") is False
    cleanup.assert_not_called()


def test_old_watchdog_cannot_clean_newer_lease(monkeypatch, tmp_path):
    _patch_watchdog_paths(monkeypatch, tmp_path)
    _lease(tmp_path, generation="generation-new")
    original_process = psutil.Process
    def fake_process(pid=None):
        if pid == 1234:
            raise AssertionError("stale watchdog observed process")
        return original_process(pid)
    monkeypatch.setattr(watchdog.psutil, "Process", MagicMock(side_effect=fake_process))
    cleanup = MagicMock()
    monkeypatch.setattr(watchdog, "perform_watchdog_cleanup", cleanup, raising=False)

    assert watchdog.monitor(1234, "generation-old") is False
    cleanup.assert_not_called()


def test_monitor_cleans_matching_pid_and_state_files(monkeypatch, tmp_path):
    _patch_watchdog_paths(monkeypatch, tmp_path)
    _lease(tmp_path, pid=1234, generation="generation-a")
    pid_file = tmp_path / "daemon.pid"
    state_file = tmp_path / "daemon_state.json"
    pid_file.write_text("1234", encoding="utf-8")
    state_file.write_text(json.dumps({
        "pid": 1234,
        "generation": "generation-a",
        "engine": "xray",
    }), encoding="utf-8")

    monkeypatch.setattr(daemon, "PID_FILE", pid_file)
    monkeypatch.setattr(daemon, "STATE_FILE", state_file)
    original_process = psutil.Process
    def fake_process(pid=None):
        if pid == 1234:
            raise psutil.NoSuchProcess(1234)
        return original_process(pid)
    monkeypatch.setattr(watchdog.psutil, "Process", MagicMock(side_effect=fake_process))
    monkeypatch.setattr(watchdog.psutil, "pid_exists", MagicMock(return_value=False))

    res = watchdog.monitor(1234, "generation-a")
    assert res is True
    assert not pid_file.exists()
    assert not state_file.exists()

