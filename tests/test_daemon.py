import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from blackoutkit import daemon


def test_watchdog_command_uses_installed_script_when_not_frozen():
    with patch.object(daemon.sys, "frozen", False, create=True):
        command = daemon._watchdog_command(4242, "generation-a")

    assert command == [
        daemon.sys.executable,
        str(Path(daemon.__file__).parent.parent / "watchdog.py"),
        "4242",
        "generation-a",
    ]


def test_watchdog_command_uses_hidden_entrypoint_when_frozen():
    with patch.object(daemon.sys, "frozen", True, create=True):
        command = daemon._watchdog_command(4242, "generation-a")

    assert command == [daemon.sys.executable, "_watchdog", "4242", "generation-a"]


def test_watchdog_command_omits_generation_only_for_legacy_direct_calls():
    with patch.object(daemon.sys, "frozen", False, create=True):
        command = daemon._watchdog_command(4242)

    assert command[-1] == "4242"
    assert "generation-a" not in command



def test_native_gui_command_uses_module_entrypoint_when_installed():
    from blackoutkit import launcher

    with patch.object(launcher.sys, "frozen", False, create=True):
        command = launcher._native_gui_command()

    assert command == [launcher.sys.executable, "-m", "blackoutkit.typer_cli", "gui"]



def test_native_gui_command_uses_hidden_entrypoint_when_frozen():
    from blackoutkit import launcher

    with patch.object(launcher.sys, "frozen", True, create=True):
        command = launcher._native_gui_command()

    assert command == [launcher.sys.executable, "gui"]




class _FakeXRayEngine:
    outcomes = []

    def __init__(self):
        self.name = "XRay"
        self.pid = None
        self.running = False

    def start(self):
        self.running = self.outcomes.pop(0)
        return self.running

    def stop(self):
        self.running = False

    def is_running(self):
        return self.running


def _configure_daemon_loop(monkeypatch, tmp_path, outcomes, waits):
    from blackoutkit.engines import xray
    from blackoutkit import settings
    from blackoutkit import tray
    from blackoutkit import readiness
    from blackoutkit.scanner import proxy_tester

    _FakeXRayEngine.outcomes = list(outcomes)
    monkeypatch.setattr(xray, "XRayEngine", _FakeXRayEngine)
    monkeypatch.setattr(settings, "load", lambda: {
        "auto_set_proxy": False,
        "retry_interval": 1,
        "max_retries": 2,
        "reconnect_initial_delay": 2,
        "reconnect_max_delay": 60,
        "gdpi_backend": "legacy",
    })
    monkeypatch.setattr(readiness, "evaluate", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(tray, "start_tray", lambda *_args: None)
    monkeypatch.setattr(proxy_tester, "test_tcp_port", lambda *_args: None)
    monkeypatch.setattr(daemon.subprocess, "Popen", MagicMock())
    monkeypatch.setattr(daemon, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(daemon, "PID_FILE", tmp_path / "daemon.pid")
    monkeypatch.setattr(daemon, "STATE_FILE", tmp_path / "daemon_state.json")
    monkeypatch.setattr(daemon, "LOG_FILE", tmp_path / "daemon.log")
    monkeypatch.setattr(daemon, "_wait_for_daemon_delay", lambda *_args: next(waits))


def _run_failed_proxy_reconnect(monkeypatch, tmp_path, outcomes, waits):
    _configure_daemon_loop(monkeypatch, tmp_path, outcomes, iter(waits))
    recovery = MagicMock()
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", recovery)

    daemon.run_daemon_loop("xray")
    return recovery, json.loads((tmp_path / "daemon_state.json").read_text(encoding="utf-8"))




def test_reconnect_delay_uses_capped_exponential_backoff():
    assert daemon._reconnect_delay(1, 2, 60) == 2
    assert daemon._reconnect_delay(2, 2, 60) == 4
    assert daemon._reconnect_delay(5, 2, 60) == 32
    assert daemon._reconnect_delay(8, 2, 60) == 60


def test_backoff_wait_stops_when_shutdown_is_requested(monkeypatch):
    checks = iter([False, True])
    sleeps = []
    monkeypatch.setattr(daemon, "_daemon_shutdown_requested", lambda _pid: next(checks))
    monkeypatch.setattr(daemon.time, "sleep", lambda seconds: sleeps.append(seconds))

    assert daemon._wait_for_daemon_delay(10, 4242) is False
    assert sleeps == [1]


def test_daemon_state_uses_daemon_pid_for_dll_backed_engine(tmp_path, monkeypatch):
    state_file = tmp_path / "daemon_state.json"
    monkeypatch.setattr(daemon, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(daemon, "STATE_FILE", state_file)
    cfg = SimpleNamespace(load=lambda: {"gdpi_backend": "native"})

    daemon._write_daemon_state(
        "gdpi",
        cfg,
        4242,
        restarts=2,
        status="reconnecting",
        last_failure="Proxy port closed.",
        next_retry_delay=4,
        started="2026-08-15 10:00:00",
    )

    assert json.loads(state_file.read_text(encoding="utf-8")) == {
        "engine": "gdpi[native]",
        "pid": 4242,
        "started": "2026-08-15 10:00:00",
        "restarts": 2,
        "status": "reconnecting",
        "last_failure": "Proxy port closed.",
        "next_retry_delay": 4,
    }


def test_state_writer_records_connected_reconnect_without_failure(tmp_path, monkeypatch):
    state_file = tmp_path / "daemon_state.json"
    monkeypatch.setattr(daemon, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(daemon, "STATE_FILE", state_file)

    daemon._write_daemon_state(
        "xray",
        SimpleNamespace(load=lambda: {}),
        4242,
        restarts=0,
        status="connected",
        started="2026-08-15 10:00:00",
    )

    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["pid"] == 4242
    assert state["engine"] == "xray"
    assert state["status"] == "connected"
    assert state["last_failure"] is None
    assert state["next_retry_delay"] is None


def test_daemon_retries_after_initial_restart_failure(monkeypatch, tmp_path):
    recovery, state = _run_failed_proxy_reconnect(
        monkeypatch,
        tmp_path,
        outcomes=[True, False, True],
        waits=[True, True, False],
    )

    recovery.assert_called_once_with(from_daemon=True)
    assert state["status"] == "connected"
    assert state["restarts"] == 2


def test_daemon_exits_only_after_retry_budget_is_exhausted(monkeypatch, tmp_path):
    recovery, state = _run_failed_proxy_reconnect(
        monkeypatch,
        tmp_path,
        outcomes=[True, False, False],
        waits=[True, True],
    )

    recovery.assert_called_once_with(from_daemon=True)
    assert state["status"] == "failed"
    assert state["restarts"] == 2
    assert state["last_failure"] == "Proxy port closed."


def test_daemon_recovery_is_not_called_when_restart_succeeds_immediately(monkeypatch, tmp_path):
    recovery, state = _run_failed_proxy_reconnect(
        monkeypatch,
        tmp_path,
        outcomes=[True, True],
        waits=[True, False],
    )

    recovery.assert_not_called()
    assert state["status"] == "connected"
    assert state["restarts"] == 1


def test_daemon_waits_with_configured_backoff_before_follow_up_attempt(monkeypatch, tmp_path):
    _configure_daemon_loop(monkeypatch, tmp_path, [True, False, True], iter([True, True, False]))
    recovery = MagicMock()
    waits = iter([True, True, False])
    recorded_delays = []
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", recovery)
    monkeypatch.setattr(
        daemon,
        "_wait_for_daemon_delay",
        lambda delay, _pid: (recorded_delays.append(delay) or next(waits)),
    )

    daemon.run_daemon_loop("xray")

    recovery.assert_called_once_with(from_daemon=True)
    assert recorded_delays == [1, 2, 1]


def test_reconnect_delay_settings_are_bounded():
    from blackoutkit import settings

    assert settings.validate("reconnect_initial_delay", 0) == (False, "must be 1–600")
    assert settings.validate("reconnect_max_delay", 3601) == (False, "must be 1–3600")
    assert settings.validate("reconnect_initial_delay", 2) == (True, "")
    assert settings.validate("reconnect_max_delay", 60) == (True, "")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows daemon launch test")
def test_start_serializes_env_overrides_as_a_windows_command_line(monkeypatch, tmp_path):
    launch_commands = []
    launch_environments = []
    overrides = {
        "BLACKOUT_COUNTRY": "RU West",
        "BLACKOUT_LABEL": 'A "quoted" value with spaces\\',
    }
    monkeypatch.setattr(daemon, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(daemon, "PID_FILE", tmp_path / "daemon.pid")
    monkeypatch.setattr(daemon, "STATE_FILE", tmp_path / "daemon_state.json")
    monkeypatch.setattr(daemon, "get_pid", lambda: 4242 if (tmp_path / "daemon.pid").exists() else None)
    monkeypatch.setattr(daemon.time, "sleep", lambda *_args: None)

    def fake_run(command, **kwargs):
        launch_commands.append(command)
        launch_environments.append(kwargs["env"])
        (tmp_path / "daemon.pid").write_text("4242", encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(daemon.subprocess, "run", fake_run)
    monkeypatch.setattr(daemon, "is_process_alive", lambda pid: pid == 4242)
    monkeypatch.setattr(daemon, "write_lease", lambda *_args: True)

    pid = daemon.start("xray", env_overrides=overrides)

    generation = launch_environments[0]["BLACKOUT_GENERATION"]
    expected_child_args = [
        str(Path(daemon.__file__).parent.parent.parent / "blackout.py"),
        "_daemon_run",
        "--engine",
        "xray",
        "--generation",
        generation,
        "--env-overrides-json",
        json.dumps(overrides, separators=(",", ":")),
    ]
    power_shell_command = launch_commands[0][-1]
    assert pid == 4242
    assert generation
    assert launch_environments[0]["BLACKOUT_ARGS"] == subprocess.list2cmdline(expected_child_args)
    assert "BLACKOUT_GENERATION" in launch_environments[0]
    assert "generation=$env:BLACKOUT_GENERATION" in power_shell_command
    assert "-ArgumentList $env:BLACKOUT_ARGS" in power_shell_command
    assert "JsonDocument" not in power_shell_command


def test_xray_fragment_accepts_empty_string():
    from blackoutkit import settings

    assert settings.validate("xray_fragment", "") == (True, "")


def test_config_rotation_increments_offset_on_reconnect(monkeypatch, tmp_path):
    _configure_daemon_loop(monkeypatch, tmp_path, [True, False, False], iter([True, True]))
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", MagicMock())
    monkeypatch.delenv("BLACKOUT_CONFIG_OFFSET", raising=False)

    daemon.run_daemon_loop("xray")

    # After all reconnects failed, the offset should have been incremented
    assert os.environ.get("BLACKOUT_CONFIG_OFFSET") is not None
    assert int(os.environ["BLACKOUT_CONFIG_OFFSET"]) >= 1


def test_config_rotation_resets_on_success(monkeypatch, tmp_path):
    _configure_daemon_loop(monkeypatch, tmp_path, [True, True], iter([True, False]))
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", MagicMock())
    monkeypatch.setenv("BLACKOUT_CONFIG_OFFSET", "3")

    daemon.run_daemon_loop("xray")

    # After successful reconnect, offset should be cleared
    assert "BLACKOUT_CONFIG_OFFSET" not in os.environ


def test_stale_daemon_cleanup_cannot_touch_newer_generation(monkeypatch, tmp_path):
    lease_path = tmp_path / "daemon.lease.json"
    lifecycle_path = tmp_path / "daemon.lifecycle.lock"
    lease_path.write_text(json.dumps({
        "schema_version": 1,
        "pid": 4242,
        "generation": "generation-new",
        "create_time": 10.0,
    }), encoding="utf-8")
    monkeypatch.setattr(daemon, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(daemon, "LEASE_FILE", lease_path)
    monkeypatch.setattr(daemon, "LIFECYCLE_LOCK_FILE", lifecycle_path)
    monkeypatch.setattr(daemon, "process_identity_state", lambda *_args: True)

    cleanup_proxy = MagicMock()
    disable_kill_switch = MagicMock()
    clear_endpoint = MagicMock()

    daemon._cleanup_daemon_state(
        4242,
        "generation-old",
        cleanup_proxy,
        disable_kill_switch,
        clear_endpoint,
    )

    assert json.loads(lease_path.read_text(encoding="utf-8"))["generation"] == "generation-new"
    cleanup_proxy.assert_not_called()
    disable_kill_switch.assert_not_called()
    clear_endpoint.assert_not_called()


def test_get_state_rejects_mismatched_generation(tmp_path, monkeypatch):
    state_file = tmp_path / "daemon_state.json"
    lease_file = tmp_path / "daemon.lease.json"
    pid_file = tmp_path / "daemon.pid"

    state_file.write_text(json.dumps({
        "engine": "xray",
        "pid": 4242,
        "generation": "generation-old",
    }), encoding="utf-8")
    lease_file.write_text(json.dumps({
        "schema_version": 1,
        "pid": 4242,
        "generation": "generation-new",
        "create_time": 10.0,
    }), encoding="utf-8")
    pid_file.write_text("4242", encoding="utf-8")

    monkeypatch.setattr(daemon, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(daemon, "STATE_FILE", state_file)
    monkeypatch.setattr(daemon, "PID_FILE", pid_file)
    monkeypatch.setattr(daemon, "LEASE_FILE", lease_file)
    monkeypatch.setattr(daemon, "_lease_path", lambda: lease_file)
    monkeypatch.setattr(daemon, "process_identity_state", lambda *_args: True)

    assert daemon.get_state() is None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows daemon launch test")
def test_start_terminates_spawned_child_if_registration_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(daemon, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(daemon, "PID_FILE", tmp_path / "daemon.pid")
    monkeypatch.setattr(daemon, "STATE_FILE", tmp_path / "daemon_state.json")
    monkeypatch.setattr(daemon, "get_pid", lambda: None)
    monkeypatch.setattr(daemon, "_read_pid_file", lambda: 4242)
    monkeypatch.setattr(daemon, "is_process_alive", lambda _pid: False)
    monkeypatch.setattr(daemon, "_register_spawned_daemon", lambda *_args: False)
    monkeypatch.setattr(daemon.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    monkeypatch.setattr(daemon.time, "sleep", lambda *_args: None)

    mock_process = MagicMock()
    mock_psutil = MagicMock()
    mock_psutil.pid_exists.return_value = True
    mock_psutil.Process.return_value = mock_process
    monkeypatch.setitem(sys.modules, "psutil", mock_psutil)

    res = daemon.start("xray")
    assert res == 0
    mock_process.terminate.assert_called_once()


def test_stop_force_termination_cleans_proxy_and_kill_switch(monkeypatch, tmp_path):
    lease_file = tmp_path / "daemon.lease.json"
    lease_file.write_text(json.dumps({
        "schema_version": 1,
        "pid": 4242,
        "generation": "gen-1",
        "create_time": 10.0,
    }), encoding="utf-8")
    monkeypatch.setattr(daemon, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(daemon, "LEASE_FILE", lease_file)
    monkeypatch.setattr(daemon, "_lease_path", lambda: lease_file)
    monkeypatch.setattr(daemon, "get_pid", lambda: 4242)
    monkeypatch.setattr(daemon, "process_identity_state", lambda *_args: True)
    monkeypatch.setattr("blackoutkit.daemon.ownership.process_identity_state", lambda *_args: True)
    monkeypatch.setattr(daemon, "process_is_gone", lambda *_args: True)
    monkeypatch.setattr("blackoutkit.daemon.ownership.process_is_gone", lambda *_args: True)
    monkeypatch.setattr(daemon.time, "sleep", lambda *_args: None)

    cleanup_proxy = MagicMock()
    disable_ks = MagicMock()
    monkeypatch.setattr("blackoutkit.proxy_manager.cleanup_owned_system_proxy", cleanup_proxy)
    monkeypatch.setattr("blackoutkit.security.disable_kill_switch", disable_ks)
    monkeypatch.setattr("blackoutkit.security.clear_linux_kill_switch_endpoint", MagicMock())
    monkeypatch.setattr(daemon, "_clear_owned_metadata", lambda *a, **k: True)

    stopped = daemon.stop()
    assert stopped is True
    cleanup_proxy.assert_called_once()
    disable_ks.assert_called_once()


def test_daemon_package_exposes_canonical_manager_api():
    assert daemon.__file__.replace("\\", "/").endswith("blackoutkit/daemon/__init__.py")
    for name in (
        "start",
        "stop",
        "get_pid",
        "get_state",
        "read_logs",
        "get_recent_events",
        "run_daemon_loop",
    ):
        assert callable(getattr(daemon, name))
