"""capture_cli: allowlist enforcement, tools delegation, console restore."""
import pytest

from blackoutkit.tui.screens import _worker


def test_unknown_command_rejected():
    with pytest.raises(ValueError, match="Unsupported capture command"):
        _worker.capture_cli("rm -rf /")


def test_tools_ping_delegates_with_host(monkeypatch):
    seen = {}

    def fake_cmd_tools(args):
        seen["tools_command"] = args.tools_command
        seen["host"] = args.host

    monkeypatch.setattr(_worker.cli_mod, "cmd_tools", fake_cmd_tools)
    _worker.capture_cli("tools_ping", "example.invalid")
    assert seen == {"tools_command": "ping", "host": "example.invalid"}


def test_tools_ping_default_host(monkeypatch):
    seen = {}

    def fake_cmd_tools(args):
        seen["tools_command"] = args.tools_command
        seen["host"] = args.host

    monkeypatch.setattr(_worker.cli_mod, "cmd_tools", fake_cmd_tools)
    _worker.capture_cli("tools_ping")
    assert seen == {"tools_command": "ping", "host": "1.1.1.1"}


def test_tools_speedtest_delegates(monkeypatch):
    seen = {}

    def fake_cmd_tools(args):
        seen["tools_command"] = args.tools_command

    monkeypatch.setattr(_worker.cli_mod, "cmd_tools", fake_cmd_tools)
    _worker.capture_cli("tools_speedtest")
    assert seen == {"tools_command": "speedtest"}


def test_doctor_delegates(monkeypatch):
    seen = {}

    def fake_cmd_doctor(args):
        seen["local_only"] = args.local_only

    monkeypatch.setattr(_worker.cli_mod, "cmd_doctor", fake_cmd_doctor)
    _worker.capture_cli("doctor")
    assert seen == {"local_only": True}


def test_fix_preview_delegates(monkeypatch):
    seen = {}

    def fake_cmd_fix(args):
        seen["preview"] = args.preview
        seen["full_route_reset"] = args.full_route_reset

    monkeypatch.setattr(_worker.cli_mod, "cmd_fix", fake_cmd_fix)
    _worker.capture_cli("fix_preview")
    assert seen == {"preview": True, "full_route_reset": False}


def test_console_restored_after_capture(monkeypatch):
    original = _worker.cli_mod.console
    monkeypatch.setattr(_worker.cli_mod, "cmd_tools", lambda args: None)
    _worker.capture_cli("tools_ping", "1.1.1.1")
    assert _worker.cli_mod.console is original


def test_console_restored_on_exception(monkeypatch):
    original = _worker.cli_mod.console

    def boom(args):
        raise RuntimeError("simulated error")

    monkeypatch.setattr(_worker.cli_mod, "cmd_tools", boom)
    with pytest.raises(RuntimeError, match="simulated error"):
        _worker.capture_cli("tools_ping", "1.1.1.1")
    assert _worker.cli_mod.console is original
