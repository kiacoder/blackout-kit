import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from blackoutkit.connection_service import ConnectionRequest, ConnectionResult, ConnectionService


class FakeEngine:
    name = "XRay"
    pid = 4242

    def __init__(self):
        self.stopped = False
        self.running = True

    def is_running(self):
        return self.running

    def stop(self):
        self.stopped = True
        self.running = False


def make_service(**overrides):
    values = {
        "settings_load": lambda: {"sni_connect_ip": "", "auto_set_proxy": False, "kill_switch": False},
        "settings_set": Mock(),
        "readiness_evaluate": lambda _engine: [],
        "resolve_engine": lambda args: args.pos_engine or args.engine,
        "linux_default_engine": lambda engine: engine,
        "platform_engine_error": lambda _engine: None,
        "recommended_engine": lambda: "xray",
        "active_profile": lambda: None,
        "route_candidates": lambda: [],
        "is_interactive": lambda: False,
        "scan_sni_ip": Mock(return_value=None),
        "start_engine_stack": Mock(return_value=[]),
        "daemon_start": Mock(return_value=4242),
        "daemon_stop": Mock(return_value=True),
        "daemon_get_pid": Mock(return_value=None),
        "set_proxy": Mock(return_value=True),
        "clear_proxy": Mock(return_value=True),
        "proxy_details": lambda _engine, _settings: None,
        "kill_switch_prepare": Mock(return_value=True),
        "kill_switch_enable": Mock(return_value=True),
        "kill_switch_disable": Mock(return_value=True),
        "kill_switch_clear_endpoint": Mock(),
        "is_admin": lambda: True,
        "sleep": lambda _seconds: None,
        "monotonic": lambda: 0.0,
        "platform": lambda: "linux",
    }
    values.update(overrides)
    return ConnectionService(**values)


def test_request_normalization_uses_positional_engine_precedence_and_background_handoff():
    daemon_start = Mock(return_value=4242)
    service = make_service(daemon_start=daemon_start)

    result = service.connect(ConnectionRequest(
        operation="ignored",
        pos_engine="sni",
        engine="xray",
        background=True,
    ))

    assert result.ok is True
    assert result.status == "background"
    assert result.engine == "sni"
    assert result.pid == 4242
    daemon_start.assert_called_once_with("sni", env_overrides={})


def test_conflicting_presets_fail_before_any_boundary_is_called():
    settings_load = Mock()
    service = make_service(settings_load=settings_load)

    result = service.connect(ConnectionRequest("connect", iran=True, russia=True))

    assert result.ok is False
    assert result.status == "invalid"
    assert result.code == "invalid_preset"
    settings_load.assert_not_called()


def test_readiness_blocker_prevents_sni_scan_settings_write_and_engine_start():
    check = SimpleNamespace(name="Local readiness", ok=False, blocking=True, detail="blocked")
    scan = Mock(return_value=("203.0.113.10", 12.0))
    settings_set = Mock()
    start_stack = Mock()
    service = make_service(
        platform=lambda: "win32",
        readiness_evaluate=lambda _engine: [check],
        scan_sni_ip=scan,
        settings_set=settings_set,
        start_engine_stack=start_stack,
    )

    result = service.connect(ConnectionRequest("connect", pos_engine="sni"))

    assert result.ok is False
    assert result.code == "not_ready"
    assert result.readiness == [{
        "name": "Local readiness",
        "ok": False,
        "blocking": True,
        "detail": "blocked",
    }]
    scan.assert_not_called()
    settings_set.assert_not_called()
    start_stack.assert_not_called()


def test_ready_connection_scans_sni_before_writing_ip_and_starting_daemon():
    order = []
    settings_set = Mock(side_effect=lambda *_args: order.append("settings_write"))
    scan = Mock(side_effect=lambda _settings: (order.append("scan") or ("203.0.113.10", 12.0)))
    daemon_start = Mock(side_effect=lambda *_args, **_kwargs: (order.append("daemon") or 4242))
    service = make_service(
        platform=lambda: "win32",
        scan_sni_ip=scan,
        settings_set=settings_set,
        daemon_start=daemon_start,
    )
    service.readiness_evaluate = lambda _engine: (order.append("readiness") or [])

    result = service.connect(ConnectionRequest("connect", pos_engine="sni", background=True))

    assert result.ok is True
    assert result.sni_scan_attempted is True
    assert result.sni_ip_saved is True
    assert order == ["readiness", "scan", "settings_write", "daemon"]


def test_preset_environment_is_forwarded_and_restored_after_start():
    preset_payload = Mock(return_value=("Russia", {"BLACKOUT_COUNTRY": "RU"}, ["Country profile: Russia"], "footer"))
    daemon_start = Mock()
    observed = {}

    def start(_engine, *, env_overrides):
        observed["environment"] = os.environ.get("BLACKOUT_COUNTRY")
        observed["overrides"] = env_overrides
        return 4242

    service = make_service(
        preset_payload=preset_payload,
        daemon_start=start,
    )
    previous = os.environ.get("BLACKOUT_COUNTRY")
    os.environ["BLACKOUT_COUNTRY"] = "original"
    try:
        result = service.connect(ConnectionRequest("connect", pos_engine="xray", russia=True, background=True))
    finally:
        if previous is None:
            os.environ.pop("BLACKOUT_COUNTRY", None)
        else:
            os.environ["BLACKOUT_COUNTRY"] = previous

    assert result.ok is True
    assert observed == {
        "environment": "RU",
        "overrides": {"BLACKOUT_COUNTRY": "RU"},
    }
    assert os.environ.get("BLACKOUT_COUNTRY") is None
    assert preset_payload.call_count == 2
    assert result.payload()["preset"] == {
        "name": "russia",
        "title": "Russia",
        "changes": ["Country profile: Russia"],
    }
    assert "BLACKOUT_COUNTRY" not in result.payload()["preset"]


def test_foreground_keyboard_interrupt_cleans_engine_proxy_and_kill_switch():
    engine = FakeEngine()
    stop_proxy = Mock(return_value=True)
    disable_kill_switch = Mock(return_value=True)
    clear_endpoint = Mock()
    service = make_service(
        settings_load=lambda: {"sni_connect_ip": "saved", "auto_set_proxy": True, "kill_switch": True},
        start_engine_stack=Mock(return_value=[engine]),
        proxy_details=lambda _engine, _settings: ("127.0.0.1", 10809),
        clear_proxy=stop_proxy,
        kill_switch_disable=disable_kill_switch,
        kill_switch_clear_endpoint=clear_endpoint,
        sleep=Mock(side_effect=KeyboardInterrupt),
    )

    result = service.start(ConnectionRequest("start", pos_engine="tun"))

    assert result.ok is True
    assert result.status == "stopped"
    assert result.cancelled is True
    assert engine.stopped is True
    stop_proxy.assert_called_once_with()
    disable_kill_switch.assert_called_once_with()
    clear_endpoint.assert_called_once_with("tun")


def test_kill_switch_cleanup_runs_when_engine_stack_cannot_start():
    disable_kill_switch = Mock(return_value=True)
    clear_endpoint = Mock()
    service = make_service(
        settings_load=lambda: {"sni_connect_ip": "saved", "auto_set_proxy": False, "kill_switch": True},
        start_engine_stack=Mock(return_value=[]),
        kill_switch_disable=disable_kill_switch,
        kill_switch_clear_endpoint=clear_endpoint,
    )

    result = service.start(ConnectionRequest("start", pos_engine="tun"))

    assert result.ok is False
    assert result.code == "engine_start_failed"
    disable_kill_switch.assert_called_once_with()
    clear_endpoint.assert_called_once_with("tun")


def test_unsupported_engine_fails_before_readiness_or_start():
    readiness = Mock(return_value=[])
    start_stack = Mock()
    service = make_service(
        platform_engine_error=lambda engine: f"{engine} unsupported",
        readiness_evaluate=readiness,
        start_engine_stack=start_stack,
    )

    result = service.start(ConnectionRequest("start", pos_engine="unknown"))

    assert result.ok is False
    assert result.code == "unsupported_engine"
    readiness.assert_not_called()
    start_stack.assert_not_called()


def test_result_payload_contains_safe_lifecycle_fields_only():
    result = ConnectionResult(
        operation="connect",
        ok=True,
        status="background",
        engine="xray",
        pid=4242,
        background=True,
        preset={"name": "russia", "title": "Russia", "changes": [], "overrides": {"BLACKOUT_PASSWORD": "secret"}},
        profile={"code": "RU", "name": "Russia"},
        warnings=["safe warning"],
    )

    payload = result.payload()

    assert payload["pid"] == 4242
    assert payload["preset"] == {"name": "russia", "title": "Russia", "changes": []}
    assert "BLACKOUT_PASSWORD" not in str(payload)
    assert payload["profile"] == {"code": "RU", "name": "Russia"}
    assert payload["warnings"] == ["safe warning"]
