import sys
from unittest.mock import Mock, patch

import click
import pytest
from typer.testing import CliRunner

from blackoutkit import typer_cli


runner = CliRunner()


def test_json_typer_group_uses_stable_click_exit_type():
    assert typer_cli._JsonTyperGroup._exit_type is click.exceptions.Exit


def test_rich_help_does_not_force_terminal_for_captured_output():
    import typer.rich_utils as rich_utils

    if not typer_cli.sys.stdout.isatty():
        assert rich_utils.FORCE_TERMINAL is False


def test_documented_commands_are_registered():
    result = runner.invoke(typer_cli.app, ["--help"])

    assert result.exit_code == 0
    for command in ("help", "country", "bins", "doctor", "emergency", "logs", "update", "route", "theme"):
        assert command in result.output


def test_status_watch_options_are_registered():
    result = runner.invoke(typer_cli.app, ["status", "--help"])

    assert result.exit_code == 0
    assert "--watch" in result.output
    assert "--interval" in result.output


def test_theme_forwards_palette():
    with patch("blackoutkit.cli.cmd_theme") as cmd_theme:
        typer_cli.theme("light")

    assert cmd_theme.call_args.args[0].palette == "light"


def test_status_forwards_watch_settings():
    with patch("blackoutkit.cli.cmd_status") as cmd_status:
        typer_cli.status(watch=True, interval=3.0)

    args = cmd_status.call_args.args[0]
    assert args.watch is True
    assert args.interval == 3.0


def test_settings_display_value_masks_sensitive_values():
    from blackoutkit import settings

    assert settings.display_value("ikev2_password", "secret") == "[hidden]"
    assert settings.display_value("softether_password", "secret") == "[hidden]"
    assert settings.display_value("xray_fingerprint", "chrome") == "chrome"


def test_settings_set_masks_secret_in_confirmation(monkeypatch):
    from blackoutkit import cli

    printed = []
    monkeypatch.setattr(cli.cfg, "load", lambda: dict(cli.cfg.DEFAULTS))
    monkeypatch.setattr(cli.cfg, "set_value", lambda *_args: None)
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))

    cli.cmd_settings(type("Args", (), {
        "settings_command": "set",
        "key": "ikev2_password",
        "value": "secret-password",
    })())

    assert "[hidden]" in printed[0]
    assert "secret-password" not in printed[0]


def test_settings_rejects_windows_kill_switch_activation(monkeypatch):
    from blackoutkit import cli

    printed = []
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))

    cli.cmd_settings(type("Args", (), {
        "settings_command": "set",
        "key": "kill_switch",
        "value": "true",
    })())

    assert any("available only on Linux" in message for message in printed)


def test_noninteractive_connect_preserves_missing_engine_for_smart_resolution(monkeypatch):
    from blackoutkit.connection_service import ConnectionResult

    monkeypatch.setattr(typer_cli, "is_interactive", lambda: False)
    service = Mock()
    service.connect.return_value = ConnectionResult(operation="connect", ok=True, status="stopped")
    monkeypatch.setattr(typer_cli, "_connection_service", lambda _options: service)

    typer_cli.connect(pos_engine=None, engine=None, background=False, iran=False, russia=False)

    request = service.connect.call_args.args[0]
    assert request.pos_engine is None
    assert request.engine is None
    assert request.background is False
    assert request.russia is False




def test_noninteractive_config_add_does_not_prompt(monkeypatch):
    monkeypatch.setattr(typer_cli, "ask_text", lambda *_args, **_kwargs: None)
    with patch("blackoutkit.cli.cmd_config") as cmd_config:
        typer_cli.cfg_add(None)

    cmd_config.assert_not_called()


def test_noninteractive_hotspot_does_not_prompt(monkeypatch):
    monkeypatch.setattr(typer_cli, "ask_choice", lambda *_args, **_kwargs: None)
    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        typer_cli.tools_hotspot(None)

    cmd_tools.assert_not_called()


def test_documented_options_are_registered():
    checks = {
        ("doctor", "--help"): "--fix",
        ("logs", "--help"): "--lines",
        ("emergency", "--help"): "--background",
        ("update", "--help"): "--apply",
        ("tools", "cert-check", "--help"): "--allow",
        ("country", "--help"): "set",
        ("bins", "--help"): "update",
        ("fix", "--help"): "--full-route-reset",
    }

    for args, expected in checks.items():
        result = runner.invoke(typer_cli.app, list(args))
        assert result.exit_code == 0, result.output
        assert expected in result.output

    result = runner.invoke(typer_cli.app, ["fix", "--help"])
    assert "--full-stack-reset" in result.output
    assert "--flush-arp" in result.output

    result = runner.invoke(typer_cli.app, ["tools", "--help"])
    assert "arp-flush" in result.output

    result = runner.invoke(typer_cli.app, ["connect", "--help"])
    assert "--russia" in result.output

    result = runner.invoke(typer_cli.app, ["start", "--help"])
    assert "--russia" in result.output

    result = runner.invoke(typer_cli.app, ["country", "set", "--help"])
    assert "RU" in result.output


def test_doctor_forwards_fix_options(monkeypatch):
    monkeypatch.setattr(typer_cli, "_output_options", lambda _ctx=None: typer_cli.OutputOptions())
    with patch("blackoutkit.cli.cmd_doctor") as cmd_doctor:
        typer_cli.doctor(fix=True, fix_av=True)

    args = cmd_doctor.call_args.args[0]
    assert args.fix is True
    assert args.fix_av is True


def test_ready_json_serializes_local_checks_and_exit_status(monkeypatch):
    check = SimpleNamespace(name="Platform support", ok=False, blocking=True, detail="unsupported")
    monkeypatch.setattr("blackoutkit.readiness.evaluate", lambda _engine: [check])

    result = runner.invoke(typer_cli.app, ["--json", "ready", "xray"])

    assert result.exit_code == 1
    payload = __import__("json").loads(result.output)
    assert payload["data"] == {
        "checks": [{
            "blocking": True,
            "detail": "unsupported",
            "name": "Platform support",
            "ok": False,
        }],
        "engine": "xray",
        "ready": False,
    }


def test_ready_json_does_not_re_evaluate_checks(monkeypatch):
    checks = [SimpleNamespace(name="Platform support", ok=True, blocking=True, detail="supported")]
    evaluate = Mock(return_value=checks)
    monkeypatch.setattr("blackoutkit.readiness.evaluate", evaluate)

    result = runner.invoke(typer_cli.app, ["--json", "ready", "xray"])

    assert result.exit_code == 0, result.output
    evaluate.assert_called_once_with("xray")


def test_doctor_json_is_read_only_and_machine_readable(monkeypatch):
    result_item = SimpleNamespace(name="settings.json", ok=True, message="OK", fixable=False)
    run_checks = Mock(return_value=[result_item])
    monkeypatch.setattr("blackoutkit.doctor.run_all_checks", run_checks)

    result = runner.invoke(typer_cli.app, ["--json", "doctor"])

    assert result.exit_code == 0, result.output
    assert __import__("json").loads(result.output)["data"] == {
        "checks": [{"detail": "OK", "fixable": False, "name": "settings.json", "ok": True}],
        "ok": True,
    }
    run_checks.assert_called_once_with()


def test_doctor_json_rejects_mutating_flags():
    result = runner.invoke(typer_cli.app, ["--json", "doctor", "--fix"])

    assert result.exit_code == 2
    payload = __import__("json").loads(result.output)
    assert payload["error"]["code"] == "invalid_input"
    assert "read-only" in payload["error"]["message"]


def test_doctor_json_is_core_only_by_default(monkeypatch):
    run_checks = Mock(return_value=[])
    monkeypatch.setattr("blackoutkit.doctor.run_all_checks", run_checks)

    result = runner.invoke(typer_cli.app, ["--json", "doctor"])

    assert result.exit_code == 0, result.output
    run_checks.assert_called_once_with()


def test_doctor_can_include_optional_checks(monkeypatch):
    run_checks = Mock(return_value=[])
    monkeypatch.setattr("blackoutkit.doctor.run_all_checks", run_checks)

    result = runner.invoke(typer_cli.app, ["--json", "doctor", "--include-optional"])

    assert result.exit_code == 0, result.output
    run_checks.assert_called_once_with(include_optional=True)


def test_json_rejects_delegated_command_before_dispatch():
    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        result = runner.invoke(typer_cli.app, ["--json", "tools", "ping", "127.0.0.1"])

    assert result.exit_code == 2
    payload = __import__("json").loads(result.output)
    assert payload["error"]["code"] == "unsupported_output_mode"
    cmd_tools.assert_not_called()


def test_json_rejects_mutating_bins_command_before_dispatch():
    with patch("blackoutkit.cli.cmd_bins") as cmd_bins:
        result = runner.invoke(typer_cli.app, ["--json", "bins", "update"])

    assert result.exit_code == 2
    payload = __import__("json").loads(result.output)
    assert payload["error"]["code"] == "unsupported_output_mode"
    cmd_bins.assert_not_called()


def test_logs_forwards_requested_line_count():
    with patch("blackoutkit.cli.cmd_logs") as cmd_logs:
        typer_cli.logs(lines=200)

    assert cmd_logs.call_args.args[0].lines == 200


def test_emergency_forwards_background_mode():
    with patch("blackoutkit.cli.cmd_emergency") as cmd_emergency:
        typer_cli.emergency(background=True)

    assert cmd_emergency.call_args.args[0].background is True


def test_update_forwards_apply_flag():
    with patch("blackoutkit.cli.cmd_update") as cmd_update:
        typer_cli.update(apply=True)

    assert cmd_update.call_args.args[0].force is True


def test_certificate_check_forwards_allow_flag():
    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        typer_cli.tools_cert_check(host="example.com", allow=True)

    args = cmd_tools.call_args.args[0]
    assert args.tools_command == "cert-check"
    assert args.host == "example.com"
    assert args.allow is True


def test_scan_file_command_is_registered():
    result = runner.invoke(typer_cli.app, ["tools", "scan-file", "--help"])

    assert result.exit_code == 0, result.output
    assert "Existing local file to scan" in result.output


def test_scan_file_forwards_path_to_legacy_dispatcher():
    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        typer_cli.tools_scan_file(path="C:/safe/sample.bin")

    args = cmd_tools.call_args.args[0]
    assert args.tools_command == "scan-file"
    assert args.path == "C:/safe/sample.bin"


def test_file_hash_command_is_registered():
    result = runner.invoke(typer_cli.app, ["tools", "file-hash", "--help"])

    assert result.exit_code == 0, result.output
    assert "Existing local file to fingerprint" in result.output


def test_file_hash_forwards_path_to_legacy_dispatcher():
    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        typer_cli.tools_file_hash(path="C:/safe/sample.bin")

    args = cmd_tools.call_args.args[0]
    assert args.tools_command == "file-hash"
    assert args.path == "C:/safe/sample.bin"


def test_qos_help_advertises_only_monitor_only_contract():
    result = runner.invoke(typer_cli.app, ["tools", "qos", "--help"])
    output = result.output.lower()

    assert result.exit_code == 0, result.output
    assert "off|monitor" in output
    assert "stored rate-limit metadata" in output
    assert "enforce" not in output
    assert "traffic shaping" not in output


def test_qos_cli_rejects_retired_mode_with_supported_modes(monkeypatch):
    from blackoutkit import cli
    from blackoutkit.tools import qos

    printed = []
    monkeypatch.setattr(qos, "set_enforcement_mode", lambda _mode: False)
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))

    cli.cmd_tools(type("Args", (), {
        "tools_command": "qos",
        "qos_subcmd": "mode",
        "mode": "enforce",
    })())

    assert printed == [
        "[error]Invalid mode: enforce. Supported modes: off, monitor.[/error]"
    ]


def test_country_set_forwards_code():
    with patch("blackoutkit.cli.cmd_country") as cmd_country:
        typer_cli.country_set("RU")

    args = cmd_country.call_args.args[0]
    assert args.country_command == "set"
    assert args.code == "RU"


def test_connect_builds_typed_request_without_legacy_dispatch(monkeypatch):
    from blackoutkit.connection_service import ConnectionResult

    service = Mock()
    service.connect.return_value = ConnectionResult(operation="connect", ok=True, status="background", pid=9, engine="xray", background=True)
    monkeypatch.setattr(typer_cli, "_connection_service", lambda _options: service)

    with patch("blackoutkit.cli.cmd_connect") as legacy_connect:
        typer_cli.connect(pos_engine="xray", engine="sni", background=True, iran=False, russia=True)

    request = service.connect.call_args.args[0]
    assert request.pos_engine == "xray"
    assert request.engine == "sni"
    assert request.background is True
    assert request.russia is True
    legacy_connect.assert_not_called()


def test_start_builds_typed_request_without_legacy_dispatch(monkeypatch):
    from blackoutkit.connection_service import ConnectionResult

    service = Mock()
    service.start.return_value = ConnectionResult(operation="start", ok=True, status="background", pid=9, engine="xray", background=True)
    monkeypatch.setattr(typer_cli, "_connection_service", lambda _options: service)

    with patch("blackoutkit.cli.cmd_start") as legacy_start:
        typer_cli.start(pos_engine="xray", engine="sni", background=True, iran=False, russia=True)

    request = service.start.call_args.args[0]
    assert request.pos_engine == "xray"
    assert request.engine == "sni"
    assert request.background is True
    assert request.russia is True
    legacy_start.assert_not_called()



def test_connect_and_start_json_are_rejected_before_service(monkeypatch):
    service = Mock()
    monkeypatch.setattr(typer_cli, "_connection_service", lambda _options: service)

    for command in ("connect", "start"):
        result = runner.invoke(typer_cli.app, ["--json", command, "xray"])
        assert result.exit_code == 2
        assert __import__("json").loads(result.output)["error"]["code"] == "unsupported_output_mode"

    service.connect.assert_not_called()
    service.start.assert_not_called()



def test_direct_connect_call_normalizes_omitted_typer_defaults():
    from blackoutkit.connection_service import ConnectionResult

    service = Mock()
    service.connect.return_value = ConnectionResult(operation="connect", ok=True, status="stopped")
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(typer_cli, "_connection_service", lambda _options: service)
        typer_cli.connect(pos_engine=None, engine=None, background=False, iran=False)
    finally:
        monkeypatch.undo()

    request = service.connect.call_args.args[0]
    assert request.pos_engine is None
    assert request.engine is None
    assert request.background is False
    assert request.iran is False
    assert request.russia is False



def test_direct_start_call_normalizes_omitted_typer_defaults(monkeypatch):
    from blackoutkit.connection_service import ConnectionResult

    service = Mock()
    service.start.return_value = ConnectionResult(operation="start", ok=True, status="stopped")
    monkeypatch.setattr(typer_cli, "_connection_service", lambda _options: service)

    typer_cli.start(pos_engine=None, engine=None, background=False, iran=False, russia=False)

    request = service.start.call_args.args[0]
    assert request.pos_engine is None
    assert request.engine is None
    assert request.background is False
    assert request.iran is False
    assert request.russia is False



















def test_bins_update_forwards_to_legacy_dispatcher():
    with patch("blackoutkit.cli.cmd_bins") as cmd_bins:
        typer_cli.bins_update()

    assert cmd_bins.call_args.args[0].bins_command == "update"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows network recovery CLI test")
def test_fix_forwards_explicit_network_reset_flags_without_legacy_dispatch(monkeypatch):
    plan = [{"name": "Clear system proxy", "ok": True, "detail": "No system proxy configured"}]
    planned = Mock(return_value=plan)
    executed = Mock(return_value=plan)
    monkeypatch.setattr("blackoutkit.tools.plan_network_recovery", planned)
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", executed)

    with patch("blackoutkit.cli.cmd_fix") as cmd_fix:
        typer_cli.fix(full_route_reset=True, full_stack_reset=True, flush_arp=True)

    cmd_fix.assert_not_called()
    planned.assert_called_once_with(
        full_route_reset=True,
        full_stack_reset=True,
        flush_arp=True,
    )
    executed.assert_called_once_with(
        full_route_reset=True,
        full_stack_reset=True,
        flush_arp=True,
        audit_source="cli",
    )


def test_fix_preview_calls_plan_only(monkeypatch):
    plan = [{"name": "Flush DNS cache", "ok": True, "detail": "Would clear the local resolver cache"}]
    planned = Mock(return_value=plan)
    executed = Mock()
    monkeypatch.setattr("blackoutkit.tools.plan_network_recovery", planned)
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", executed)
    monkeypatch.setattr(typer_cli, "_output_options", lambda _ctx=None: typer_cli.OutputOptions())

    typer_cli.fix(preview=True)

    planned.assert_called_once_with(full_route_reset=False, full_stack_reset=False, flush_arp=False)
    executed.assert_not_called()


def test_fix_json_preview_is_one_safe_envelope(monkeypatch):
    plan = [{
        "name": "Clear proxy",
        "ok": True,
        "detail": "vless://secret@example.com:443 password=secret",
    }]
    monkeypatch.setattr("blackoutkit.tools.plan_network_recovery", Mock(return_value=plan))

    result = runner.invoke(typer_cli.app, ["--json", "fix", "--preview"])

    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1
    payload = __import__("json").loads(lines[0])
    assert payload["data"]["operation"] == "preview"
    assert payload["data"]["success"] is True
    assert "secret@example.com" not in result.output
    assert "password=secret" not in result.output


def test_fix_json_history_does_not_run_recovery(monkeypatch):
    records = [{
        "timestamp": "2026-08-31T20:00:00Z",
        "source": "cli",
        "platform": "win32",
        "flags": {"full_route_reset": False, "full_stack_reset": False, "flush_arp": False},
        "actions": [{"name": "Clear proxy", "ok": True, "detail": "password=hidden-secret"}],
    }]
    monkeypatch.setattr("blackoutkit.recovery_audit.history", lambda _lines: records)
    executed = Mock()
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", executed)

    result = runner.invoke(typer_cli.app, ["--json", "fix", "--history", "--history-lines", "1"])

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["lines"] == 1
    assert payload["data"]["history"][0]["actions"][0]["detail"] == "password=[hidden]"
    executed.assert_not_called()


def test_fix_linux_normalizes_windows_only_flags(monkeypatch):
    monkeypatch.setattr(typer_cli.sys, "platform", "linux")
    plan = [{"name": "Targeted Linux recovery", "ok": True, "detail": "ready"}]
    planned = Mock(return_value=plan)
    executed = Mock(return_value=plan)
    monkeypatch.setattr("blackoutkit.tools.plan_network_recovery", planned)
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", executed)

    typer_cli.fix(full_route_reset=True, full_stack_reset=True)

    planned.assert_called_once_with(full_route_reset=False, full_stack_reset=False, flush_arp=False)
    executed.assert_called_once_with(
        full_route_reset=False,
        full_stack_reset=False,
        flush_arp=False,
        audit_source="cli",
    )



def test_fix_returns_nonzero_when_a_recovery_step_fails(monkeypatch):
    monkeypatch.setattr(
        "blackoutkit.tools.plan_network_recovery",
        Mock(return_value=[{"name": "step", "ok": True, "detail": "planned"}]),
    )
    monkeypatch.setattr(
        "blackoutkit.tools.run_network_recovery",
        Mock(return_value=[{"name": "step", "ok": False, "detail": "failed"}]),
    )

    result = runner.invoke(typer_cli.app, ["--json", "fix"])

    assert result.exit_code == 1
    payload = __import__("json").loads(result.output)
    assert payload["ok"] is True
    assert payload["data"]["success"] is False



def test_tools_arp_flush_forwards_to_legacy_dispatcher():
    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        typer_cli.tools_arp_flush()

    assert cmd_tools.call_args.args[0].tools_command == "arp-flush"


def test_tools_mac_is_registered_with_safe_options():
    result = runner.invoke(typer_cli.app, ["tools", "mac", "--help"])

    assert result.exit_code == 0, result.output
    assert "status | randomize | restore" in result.output
    assert "--adapter" in result.output
    assert "--force" in result.output


def test_tools_mac_forwards_action_adapter_and_force():
    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        typer_cli.tools_mac("randomize", adapter="Wi-Fi", force=True)

    args = cmd_tools.call_args.args[0]
    assert args.tools_command == "mac"
    assert args.mac_action == "randomize"
    assert args.adapter == "Wi-Fi"
    assert args.force is True


def test_mac_status_safely_displays_nonstandard_legacy_override(monkeypatch):
    from blackoutkit import cli
    from blackoutkit.tools import mac_spoofer

    monkeypatch.setattr(mac_spoofer, "plan_status", lambda _adapter: {
        "status": "ready",
        "adapter": {
            "name": "Wi-Fi",
            "effective_mac": "02AABBCCDDEE",
            "network_address": "legacy-driver-value",
        },
        "recovery_available": False,
    })

    with cli.console.capture() as capture:
        cli.cmd_tools(type("Args", (), {
            "tools_command": "mac",
            "mac_action": "status",
            "adapter": None,
            "force": False,
        })())

    assert "unsupported legacy value (legacy-driver-value)" in capture.get()


def test_mac_restore_safely_previews_nonstandard_legacy_override(monkeypatch):
    from blackoutkit import cli
    from blackoutkit.tools import mac_spoofer

    plan = {
        "status": "ready",
        "operation": "restore",
        "adapter": {"name": "Wi-Fi"},
        "network_address_present": True,
        "target_network_address": "legacy-driver-value",
    }
    monkeypatch.setattr(mac_spoofer, "plan_restore", lambda _adapter: plan)
    monkeypatch.setattr(cli, "is_interactive", lambda: True)
    monkeypatch.setattr(cli, "confirm", lambda _prompt: True)
    execute = Mock(return_value={"status": "restored"})
    monkeypatch.setattr(mac_spoofer, "execute", execute)

    with cli.console.capture() as capture:
        cli.cmd_tools(type("Args", (), {
            "tools_command": "mac",
            "mac_action": "restore",
            "adapter": None,
            "force": False,
        })())

    execute.assert_called_once_with(plan)
    output = capture.get()
    assert "prior driver value (legacy-driver-value)" in output
    assert "Prior Wi-Fi MAC setting restored" in output


def test_noninteractive_mac_mutation_requires_force(monkeypatch):
    from blackoutkit import cli

    printed = []
    monkeypatch.setattr(cli, "is_interactive", lambda: False)
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))
    plan = {
        "status": "ready",
        "operation": "randomize",
        "adapter": {"name": "Wi-Fi"},
        "target_mac": "02AABBCCDDEE",
        "source": "random",
    }
    monkeypatch.setattr("blackoutkit.tools.mac_spoofer.plan_randomize", lambda _adapter: plan)
    execute = Mock()
    monkeypatch.setattr("blackoutkit.tools.mac_spoofer.execute", execute)

    cli.cmd_tools(type("Args", (), {
        "tools_command": "mac",
        "mac_action": "randomize",
        "adapter": None,
        "force": False,
    })())

    execute.assert_not_called()
    assert any("without --force" in message for message in printed)


def test_tools_netfix_uses_native_targeted_recovery(monkeypatch):
    plan = [{"name": "Clear proxy", "ok": True, "detail": "No Blackout proxy state found"}]
    planned = Mock(return_value=plan)
    executed = Mock(return_value=plan)
    monkeypatch.setattr("blackoutkit.tools.plan_network_recovery", planned)
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", executed)

    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        typer_cli.tools_netfix()

    cmd_tools.assert_not_called()
    planned.assert_called_once_with(
        full_route_reset=False,
        full_stack_reset=False,
        flush_arp=False,
    )
    executed.assert_called_once_with(
        full_route_reset=False,
        full_stack_reset=False,
        flush_arp=False,
        audit_source="tools",
    )


def test_tools_netfix_preview_calls_plan_only(monkeypatch):
    plan = [{"name": "Flush DNS cache", "ok": True, "detail": "Would clear local resolver state"}]
    planned = Mock(return_value=plan)
    executed = Mock()
    monkeypatch.setattr("blackoutkit.tools.plan_network_recovery", planned)
    monkeypatch.setattr("blackoutkit.tools.run_network_recovery", executed)

    typer_cli.tools_netfix(preview=True)

    planned.assert_called_once_with(
        full_route_reset=False,
        full_stack_reset=False,
        flush_arp=False,
    )
    executed.assert_not_called()


def test_tools_netfix_json_preview_is_redacted_and_single_envelope(monkeypatch):
    plan = [{
        "name": "Clear proxy",
        "ok": True,
        "detail": "vless://secret-user@example.com:443 password=secret",
    }]
    monkeypatch.setattr("blackoutkit.tools.plan_network_recovery", Mock(return_value=plan))

    result = runner.invoke(typer_cli.app, ["--json", "tools", "netfix", "--preview"])

    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1
    payload = __import__("json").loads(lines[0])
    assert payload["data"]["operation"] == "preview"
    assert payload["data"]["success"] is True
    assert "secret-user@example.com" not in result.output
    assert "password=secret" not in result.output


def test_tools_netfix_failed_step_returns_nonzero(monkeypatch):
    monkeypatch.setattr(
        "blackoutkit.tools.plan_network_recovery",
        Mock(return_value=[{"name": "step", "ok": True, "detail": "planned"}]),
    )
    monkeypatch.setattr(
        "blackoutkit.tools.run_network_recovery",
        Mock(return_value=[{"name": "step", "ok": False, "detail": "failed"}]),
    )

    result = runner.invoke(typer_cli.app, ["--json", "tools", "netfix"])

    assert result.exit_code == 1, result.output
    payload = __import__("json").loads(result.output)
    assert payload["ok"] is True
    assert payload["data"]["success"] is False


def test_tools_netfix_help_exposes_only_preview():
    result = runner.invoke(typer_cli.app, ["tools", "netfix", "--help"])

    assert result.exit_code == 0, result.output
    assert "--preview" in result.output
    assert "--full-route-reset" not in result.output
    assert "--full-stack-reset" not in result.output
    assert "--history" not in result.output


def test_tools_json_allows_netfix_but_rejects_delegated_tools(monkeypatch):
    monkeypatch.setattr(
        "blackoutkit.tools.plan_network_recovery",
        Mock(return_value=[{"name": "step", "ok": True, "detail": "planned"}]),
    )
    allowed = runner.invoke(typer_cli.app, ["--json", "tools", "netfix", "--preview"])
    assert allowed.exit_code == 0, allowed.output

    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        rejected = runner.invoke(typer_cli.app, ["--json", "tools", "ping", "127.0.0.1"])

    assert rejected.exit_code == 2
    assert __import__("json").loads(rejected.output)["error"]["code"] == "unsupported_output_mode"
    cmd_tools.assert_not_called()


def test_tools_json_without_subcommand_is_one_structured_error():
    result = runner.invoke(typer_cli.app, ["--json", "tools"])

    assert result.exit_code == 2
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1
    payload = __import__("json").loads(lines[0])
    assert payload["error"] == {
        "code": "missing_command",
        "message": "a tools subcommand is required",
    }


def test_tools_without_subcommand_keeps_human_help():
    result = runner.invoke(typer_cli.app, ["tools"])

    assert result.exit_code == 2
    assert "Network diagnostics, DNS, hotspot, and more" in result.output
    assert "netfix" in result.output
    assert "schema_version" not in result.output


def test_shield_forwards_to_legacy_dispatcher():
    with patch("blackoutkit.cli.cmd_shield") as cmd_shield:
        typer_cli.shield()

    cmd_shield.assert_called_once()


def test_shield_does_not_enable_windows_kill_switch(monkeypatch):
    from blackoutkit import cli

    printed = []
    monkeypatch.setattr(cli.sys, "platform", "win32")
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))
    with patch("blackoutkit.security.enable_kill_switch") as enable_kill_switch, \
         patch("blackoutkit.tools.set_dns", return_value=True):
        cli.cmd_shield(object())

    enable_kill_switch.assert_not_called()
    assert any("unavailable on Windows" in message for message in printed)


def test_shield_enables_linux_kill_switch_only_on_success(monkeypatch):
    from blackoutkit import cli

    printed = []
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))
    with patch("blackoutkit.security.enable_kill_switch", return_value=True) as enable_kill_switch, \
         patch("blackoutkit.settings.set_value") as set_value, \
         patch("blackoutkit.tools.set_dns", return_value=True):
        cli.cmd_shield(object())

    enable_kill_switch.assert_called_once()
    set_value.assert_called_once_with("kill_switch", True)
    assert any("Linux kill switch enabled" in message for message in printed)


def test_panic_uses_public_panic_handler_once_without_duplicate_cleanup():
    from blackoutkit import cli

    panic_results = [{"step": "cleanup", "ok": True, "detail": "mocked"}]
    with patch("blackoutkit.tools.trigger_panic", return_value=panic_results) as trigger_panic, \
         patch("blackoutkit.proxy_manager.cleanup_owned_system_proxy") as cleanup_proxy, \
         patch("blackoutkit.security.disable_kill_switch") as disable_kill_switch, \
         patch("blackoutkit.settings.set_value") as set_value, \
         patch("blackoutkit.tools.flush_dns") as flush_dns:
        cli.cmd_panic(object())

    trigger_panic.assert_called_once_with(restore=False)
    cleanup_proxy.assert_not_called()
    disable_kill_switch.assert_not_called()
    set_value.assert_not_called()
    flush_dns.assert_not_called()




def test_launcher_menu_terminal_cli_returns_to_chooser_on_back(monkeypatch):
    from blackoutkit import cli

    choices = iter(["cli", "exit"])
    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: next(choices))
    monkeypatch.setattr(cli, "_interactive_menu", lambda: False)

    cli._show_launcher_menu()

    assert next(choices, "exhausted") == "exhausted"


def test_launcher_menu_terminal_cli_exit_stops_the_whole_chooser(monkeypatch):
    from blackoutkit import cli

    calls = {"run_menu": 0}

    def fake_run_menu(*args, **kwargs):
        calls["run_menu"] += 1
        return "cli"

    monkeypatch.setattr(cli, "run_menu", fake_run_menu)
    monkeypatch.setattr(cli, "_interactive_menu", lambda: True)

    cli._show_launcher_menu()

    assert calls["run_menu"] == 1


def test_launcher_menu_windows_app_calls_start_launcher_then_loops_back(monkeypatch):
    from blackoutkit import cli, launcher

    choices = iter(["gui", "exit"])
    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: next(choices))
    start_launcher = Mock(return_value=True)
    monkeypatch.setattr(launcher, "start_launcher", start_launcher)

    cli._show_launcher_menu()

    start_launcher.assert_called_once()


def test_launcher_menu_back_at_top_level_exits():
    from blackoutkit import cli

    with patch("blackoutkit.cli.run_menu", return_value=None):
        cli._show_launcher_menu()


def test_interactive_menu_exit_returns_true(monkeypatch):
    from blackoutkit import cli

    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: "exit")

    assert cli._interactive_menu() is True


def test_interactive_menu_back_returns_false(monkeypatch):
    from blackoutkit import cli

    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: None)

    assert cli._interactive_menu() is False


def test_interactive_menu_routes_fix_through_native_typer(monkeypatch):
    from blackoutkit import cli

    choices = iter(["fix", "continue", "exit"])
    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: next(choices))
    native_fix = Mock()
    monkeypatch.setattr(typer_cli, "fix", native_fix)

    with patch.object(cli, "cmd_fix") as legacy_fix:
        assert cli._interactive_menu() is True

    native_fix.assert_called_once_with(
        full_route_reset=False,
        full_stack_reset=False,
        flush_arp=False,
        preview=False,
        history=False,
        history_lines=20,
        ctx=None,
    )
    legacy_fix.assert_not_called()


def test_interactive_menu_contains_native_fix_exit(monkeypatch):
    from blackoutkit import cli
    import typer

    choices = iter(["fix", "continue", "exit"])
    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: next(choices))
    native_fix = Mock(side_effect=typer.Exit(code=1))
    monkeypatch.setattr(typer_cli, "fix", native_fix)

    with patch.object(cli, "cmd_fix") as legacy_fix:
        assert cli._interactive_menu() is True

    native_fix.assert_called_once()
    legacy_fix.assert_not_called()


def test_interactive_menu_dispatches_engine_selection_without_crashing(monkeypatch):
    """Regression test: the old menu called msvcrt.getch() with no import and raised NameError."""
    from blackoutkit import cli

    choices = iter(["engine", "continue", "exit"])
    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: next(choices))
    select_engine = Mock()
    monkeypatch.setattr(cli, "cmd_menu_select_engine", select_engine)
    with patch("blackoutkit.terminal_menu.KeyReader") as key_reader_cls:
        key_reader_cls.return_value.read_key.return_value = None
        assert cli._interactive_menu() is True

    select_engine.assert_called_once()


def test_menu_select_engine_sets_preferred_engine(monkeypatch):
    from blackoutkit import cli

    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: "hysteria2")
    set_value = Mock()
    monkeypatch.setattr(cli.cfg, "set_value", set_value)

    cli.cmd_menu_select_engine()

    set_value.assert_called_once_with("selected_engine", "hysteria2")


def test_menu_select_engine_back_does_not_change_settings(monkeypatch):
    from blackoutkit import cli

    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: None)
    set_value = Mock()
    monkeypatch.setattr(cli.cfg, "set_value", set_value)

    cli.cmd_menu_select_engine()

    set_value.assert_not_called()


def test_bare_settings_group_opens_keyboard_editor_when_interactive(monkeypatch):
    from blackoutkit import interactive

    monkeypatch.setattr(typer_cli, "is_interactive", lambda: True)
    run_settings_menu = Mock()
    monkeypatch.setattr(interactive, "run_settings_menu", run_settings_menu)

    typer_cli.settings_status(SimpleNamespace(invoked_subcommand=None))

    run_settings_menu.assert_called_once_with()


def test_bare_settings_group_does_not_prompt_when_noninteractive(monkeypatch):
    monkeypatch.setattr(typer_cli, "is_interactive", lambda: False)
    from blackoutkit import interactive
    run_settings_menu = Mock()
    monkeypatch.setattr(interactive, "run_settings_menu", run_settings_menu)

    typer_cli.settings_status(SimpleNamespace(invoked_subcommand=None))

    run_settings_menu.assert_not_called()


def test_bare_config_group_opens_keyboard_editor_when_interactive(monkeypatch):
    from blackoutkit import interactive

    monkeypatch.setattr(typer_cli, "is_interactive", lambda: True)
    run_config_menu = Mock()
    monkeypatch.setattr(interactive, "run_config_menu", run_config_menu)

    typer_cli.config_status(SimpleNamespace(invoked_subcommand=None))

    run_config_menu.assert_called_once_with()


def test_group_callbacks_skip_interactive_editor_for_explicit_subcommand(monkeypatch):
    from blackoutkit import interactive

    monkeypatch.setattr(typer_cli, "is_interactive", lambda: True)
    run_settings_menu = Mock()
    run_config_menu = Mock()
    monkeypatch.setattr(interactive, "run_settings_menu", run_settings_menu)
    monkeypatch.setattr(interactive, "run_config_menu", run_config_menu)

    ctx = SimpleNamespace(invoked_subcommand="list")
    typer_cli.settings_status(ctx)
    typer_cli.config_status(ctx)

    run_settings_menu.assert_not_called()
    run_config_menu.assert_not_called()


def test_main_menu_dispatches_config_workflow(monkeypatch):
    from blackoutkit import cli

    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: "config")
    run_config = Mock()
    monkeypatch.setattr(cli, "_run_config_menu", run_config)
    choices = iter(["config", "continue", "exit"])
    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: next(choices))

    assert cli._interactive_menu() is True
    run_config.assert_called_once_with()


class SimpleNamespace:
    def __init__(self, **values):
        self.__dict__.update(values)


def test_config_replace_command_is_registered():
    result = runner.invoke(typer_cli.app, ["config", "replace", "--help"])

    assert result.exit_code == 0, result.output
    assert "Replacement V2Ray URI" in result.output


def test_config_replace_forwards_to_manager(monkeypatch):
    replacement = SimpleNamespace(protocol="vless", transport_label=lambda: "TLS")
    replace_config = Mock(return_value=replacement)
    monkeypatch.setattr("blackoutkit.config.manager.replace_config", replace_config)

    typer_cli.cfg_replace(2, "vless://new@example.com:443")

    replace_config.assert_called_once_with(1, "vless://new@example.com:443")



def test_bare_config_usage_shows_readable_options(monkeypatch):
    monkeypatch.setattr(typer_cli, "is_interactive", lambda: False)

    with typer_cli.console.capture() as capture:
        typer_cli.config_status(SimpleNamespace(invoked_subcommand=None))

    output = capture.get()
    assert "list" in output
    assert "replace" in output
    assert "<uri>" in output



def test_bare_settings_usage_shows_readable_options(monkeypatch):
    monkeypatch.setattr(typer_cli, "is_interactive", lambda: False)

    with typer_cli.console.capture() as capture:
        typer_cli.settings_status(SimpleNamespace(invoked_subcommand=None))

    output = capture.get()
    assert "list" in output
    assert "get <key>" in output
    assert "set <key> <value>" in output


def test_bare_groups_in_noninteractive_mode_do_not_open_editor(monkeypatch):
    monkeypatch.setattr(typer_cli, "is_interactive", lambda: False)
    with patch("blackoutkit.interactive.run_settings_menu") as settings_menu, \
         patch("blackoutkit.interactive.run_config_menu") as config_menu:
        typer_cli.settings_status(SimpleNamespace(invoked_subcommand=None))
        typer_cli.config_status(SimpleNamespace(invoked_subcommand=None))

    settings_menu.assert_not_called()
    config_menu.assert_not_called()



def test_main_menu_back_item_returns_to_launcher(monkeypatch):
    from blackoutkit import cli

    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: "back")

    assert cli._interactive_menu() is False



def test_settings_and_config_are_main_menu_items():
    from blackoutkit import cli
    captured = {}

    def fake_run_menu(_title, items, **_kwargs):
        captured["items"] = items
        return None

    with patch.object(cli, "run_menu", side_effect=fake_run_menu):
        assert cli._interactive_menu() is False

    keys = {item.key for item in captured["items"]}
    assert {"settings", "config"}.issubset(keys)


def test_root_output_options_are_registered():
    result = runner.invoke(typer_cli.app, ["--help"])

    assert result.exit_code == 0, result.output
    for option in ("--json", "--quiet", "--verbose", "--no-color"):
        assert option in result.output


def test_root_callback_stores_output_context():
    ctx = SimpleNamespace(invoked_subcommand="version", obj=None)

    typer_cli.app_callback(
        ctx,
        json_output=True,
        quiet=True,
        verbose=True,
        no_color=True,
    )

    assert ctx.obj["output"] == typer_cli.OutputOptions(
        json_output=True,
        quiet=True,
        verbose=True,
        no_color=True,
    )


def test_settings_list_json_is_parseable_and_masks_secrets(monkeypatch):
    values = dict(typer_cli._safe_settings({}))
    values["ikev2_password"] = "secret-password"
    values["softether_password"] = "another-secret"
    monkeypatch.setattr("blackoutkit.settings.load", lambda: values)

    result = runner.invoke(typer_cli.app, ["--json", "settings", "list"])

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["schema_version"] == 1
    assert payload["ok"] is True
    assert payload["data"]["settings"]["ikev2_password"] == "[hidden]"
    assert payload["data"]["settings"]["softether_password"] == "[hidden]"
    assert "secret-password" not in result.output


def test_settings_get_json_masks_secret(monkeypatch):
    monkeypatch.setattr(
        "blackoutkit.settings.load",
        lambda: {**typer_cli._safe_settings({}), "ikev2_password": "secret-password"},
    )

    result = runner.invoke(typer_cli.app, ["--json", "settings", "get", "ikev2_password"])

    assert result.exit_code == 0, result.output
    assert __import__("json").loads(result.output) == {
        "schema_version": 1,
        "ok": True,
        "data": {
            "description": "IKEv2/L2TP VPN password",
            "key": "ikev2_password",
            "value": "[hidden]",
        },
    }
    assert "secret-password" not in result.output


def test_status_json_redacts_system_proxy_and_settings(monkeypatch):
    snapshot = {
        "settings": {**typer_cli._safe_settings({}), "ikev2_password": "secret-password"},
        "pid": 123,
        "state": {"engine": "xray", "pid": 123},
        "proxy": {"enabled": True, "server": "secret-proxy.example:443"},
        "active_engine": "xray",
        "http_port": 10809,
        "socks_port": 10808,
        "http_open": True,
        "socks_open": True,
        "stability": None,
        "latencies": [],
        "events": [],
    }
    monkeypatch.setattr("blackoutkit.cli._status_snapshot", lambda: snapshot)

    result = runner.invoke(typer_cli.app, ["--json", "status"])

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["schema_version"] == 1
    assert payload["ok"] is True
    assert payload["data"]["proxy"] == {"configured": True, "enabled": True}
    assert payload["data"]["settings"]["ikev2_password"] == "[hidden]"
    assert "secret-proxy.example" not in result.output
    assert "secret-password" not in result.output


def test_route_json_uses_local_candidates_only(monkeypatch):
    candidate = SimpleNamespace(
        engine="xray",
        score=900,
        ready=True,
        evidence="local history",
        blockers=(),
        stability={"stable": True},
    )
    monkeypatch.setattr("blackoutkit.cli._routing_candidates", lambda: [candidate])

    result = runner.invoke(typer_cli.app, ["--json", "route"])

    assert result.exit_code == 0, result.output
    assert __import__("json").loads(result.output) == {
        "schema_version": 1,
        "ok": True,
        "data": {
            "candidates": [{
                "blockers": [],
                "engine": "xray",
                "evidence": "local history",
                "ready": True,
                "score": 900,
                "stability": {"stable": True},
            }],
            "recommended": "xray",
        },
    }


def test_version_json_uses_versioned_envelope():
    result = runner.invoke(typer_cli.app, ["--json", "version"])

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["schema_version"] == 1
    assert payload["ok"] is True
    assert payload["data"]["name"] == "blackout-kit"


def test_config_replace_json_reports_requested_index(monkeypatch):
    replacement = SimpleNamespace(
        protocol="vless",
        transport_label=lambda: "TLS",
        name="safe-name",
        raw_uri="vless://secret@example.com:443",
        is_sni_compatible=lambda: False,
    )
    monkeypatch.setattr("blackoutkit.config.manager.replace_config", lambda _index, _uri: replacement)

    result = runner.invoke(
        typer_cli.app,
        ["--json", "config", "replace", "4", "vless://new@example.com:443"],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["config"]["index"] == 4
    assert "secret@example.com" not in result.output


def test_json_error_is_machine_readable_for_invalid_setting():
    result = runner.invoke(
        typer_cli.app,
        ["--json", "settings", "set", "scan_timeout", "not-a-float"],
    )

    assert result.exit_code != 0
    payload = __import__("json").loads(result.output)
    assert payload["schema_version"] == 1
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_input"
    assert "must be a float" in payload["error"]["message"]


def test_settings_set_prompt_uses_secret_reader(monkeypatch):
    set_value = Mock()
    monkeypatch.setattr("blackoutkit.settings.set_value", set_value)
    monkeypatch.setattr(typer_cli, "read_secret", lambda *_args, **_kwargs: "secret-value")

    result = runner.invoke(
        typer_cli.app,
        ["settings", "set", "ikev2_password", "--prompt"],
    )

    assert result.exit_code == 0, result.output
    set_value.assert_called_once_with("ikev2_password", "secret-value")
    assert "secret-value" not in result.output


def test_settings_set_secret_requires_explicit_input_mode():
    result = runner.invoke(
        typer_cli.app,
        ["settings", "set", "ikev2_password", "secret-value"],
    )

    assert result.exit_code != 0
    assert "--prompt or --stdin" in result.output
    assert "secret-value" not in result.output


def test_config_add_stdin_does_not_echo_uri(monkeypatch):
    config = SimpleNamespace(protocol="vless", transport_label=lambda: "TLS", raw_uri="vless://secret@example.com:443")
    monkeypatch.setattr("blackoutkit.config.manager.load_configs", lambda: [])
    monkeypatch.setattr("blackoutkit.config.manager.add_config", lambda _uri: config)

    result = runner.invoke(
        typer_cli.app,
        ["config", "add", "--stdin"],
        input="vless://secret@example.com:443\n",
    )

    assert result.exit_code == 0, result.output
    assert "secret@example.com" not in result.output


def test_config_add_rejects_conflicting_input_modes():
    result = runner.invoke(typer_cli.app, ["config", "add", "--stdin", "--prompt"])

    assert result.exit_code != 0
    assert "only one" in result.output


def test_json_watch_uses_one_envelope_per_line(monkeypatch):
    snapshots = iter([
        {"settings": {}, "proxy": {"enabled": False, "server": ""}, "state": None, "pid": None,
         "active_engine": "unknown", "http_port": None, "socks_port": None,
         "http_open": None, "socks_open": None, "stability": None, "latencies": [], "events": []},
    ])
    monkeypatch.setattr("blackoutkit.cli._status_snapshot", lambda: next(snapshots))
    monkeypatch.setattr(typer_cli.time, "sleep", lambda _interval: (_ for _ in ()).throw(KeyboardInterrupt))

    result = runner.invoke(typer_cli.app, ["--json", "status", "--watch", "--interval", "0.5"])

    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1
    assert __import__("json").loads(lines[0])["ok"] is True
    assert "\\n" not in lines[0]


def test_settings_invalid_value_returns_nonzero():
    result = runner.invoke(typer_cli.app, ["settings", "set", "scan_timeout", "not-a-float"])

    assert result.exit_code != 0
    assert "must be a float" in result.output


def test_config_invalid_number_returns_nonzero():
    result = runner.invoke(
        typer_cli.app,
        ["config", "replace", "0", "vless://new@example.com:443"],
    )

    assert result.exit_code != 0
    assert "config number must be at least 1" in result.output


def test_config_invalid_setup_returns_nonzero():
    result = runner.invoke(
        typer_cli.app,
        ["config", "import-setup", "not-base64", "--force"],
    )

    assert result.exit_code != 0
    assert "Invalid setup string" in result.output


def test_settings_get_json_preserves_list_type(monkeypatch):
    values = {**typer_cli._safe_settings({}), "engine_order": ["xray", "sni"]}
    monkeypatch.setattr("blackoutkit.settings.load", lambda: values)

    result = runner.invoke(typer_cli.app, ["--json", "settings", "get", "engine_order"])

    assert result.exit_code == 0, result.output
    assert __import__("json").loads(result.output)["data"]["value"] == ["xray", "sni"]


def test_config_add_rejects_duplicate_uri(monkeypatch):
    config = SimpleNamespace(
        raw_uri="vless://saved@example.com:443",
        protocol="vless",
        transport_label=lambda: "WS",
    )
    monkeypatch.setattr("blackoutkit.config.manager.load_configs", lambda: [config])
    add_config = Mock()
    monkeypatch.setattr("blackoutkit.config.manager.add_config", add_config)

    result = runner.invoke(
        typer_cli.app,
        ["config", "add", "vless://saved@example.com:443"],
    )

    assert result.exit_code != 0
    assert "already saved" in result.output
    add_config.assert_not_called()


def test_quiet_suppresses_migrated_read_output(monkeypatch):
    monkeypatch.setattr("blackoutkit.settings.load", lambda: dict(typer_cli._safe_settings({})))

    result = runner.invoke(typer_cli.app, ["--quiet", "settings", "list"])

    assert result.exit_code == 0
    assert result.output == ""


def test_root_no_color_does_not_leak_between_invocations(monkeypatch):
    monkeypatch.setattr("blackoutkit.cli._show_launcher_menu", lambda: None)
    monkeypatch.setattr("blackoutkit.theme.print_banner", lambda: None)
    monkeypatch.setattr("blackoutkit.settings.load", lambda: {"show_banner": False})

    first = runner.invoke(typer_cli.app, ["--no-color"])
    assert first.exit_code == 0
    assert typer_cli.console.no_color is True

    second = runner.invoke(typer_cli.app, [])
    assert second.exit_code == 0
    assert typer_cli.console.no_color is typer_cli._DEFAULT_NO_COLOR

    typer_cli.console.no_color = typer_cli._DEFAULT_NO_COLOR


def test_country_json_commands_are_local_and_structured(monkeypatch):
    from blackoutkit import settings as cfg

    monkeypatch.setattr(cfg, "load", lambda: {"country": "RU"})
    result = runner.invoke(typer_cli.app, ["--json", "country"])

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["code"] == "RU"
    assert payload["data"]["pinned"] is True
    assert payload["data"]["auto_detected"] is False

    monkeypatch.setattr(cfg, "load", lambda: {"country": ""})
    listed = runner.invoke(typer_cli.app, ["--json", "country", "list"])

    assert listed.exit_code == 0, listed.output
    records = __import__("json").loads(listed.output)["data"]["profiles"]
    assert {record["code"] for record in records} >= {"IR", "RU", "US"}
    assert all("test_urls" not in record for record in records)


def test_country_set_json_updates_only_the_country_pin(monkeypatch):
    set_value = Mock()
    monkeypatch.setattr("blackoutkit.settings.set_value", set_value)

    result = runner.invoke(typer_cli.app, ["--json", "country", "set", "RU"])

    assert result.exit_code == 0, result.output
    set_value.assert_called_once_with("country", "RU")
    assert __import__("json").loads(result.output)["data"]["code"] == "RU"


def test_country_set_json_rejects_unknown_code():
    result = runner.invoke(typer_cli.app, ["--json", "country", "set", "ZZ"])

    assert result.exit_code == 2
    payload = __import__("json").loads(result.output)
    assert payload["error"]["code"] == "invalid_input"


def test_config_validate_json_reports_safe_metadata(monkeypatch):
    from blackoutkit.config.manager import ProxyConfig

    secret_uri = "vless://secret-user:secret-password@example.com:443?sni=private.example"
    config = ProxyConfig(
        protocol="vless",
        address="example.com",
        port=443,
        uuid="secret-user",
        sni="private.example",
        raw_uri=secret_uri,
    )
    monkeypatch.setattr("blackoutkit.config.manager.load_configs", lambda: [config])

    result = runner.invoke(typer_cli.app, ["--json", "config", "validate"])

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"] == {
        "configs": [{
            "index": 1,
            "ok": True,
            "protocol": "vless",
            "transport": "WS",
        }],
        "valid": True,
    }
    assert "secret-password" not in result.output
    assert secret_uri not in result.output


def test_config_duplicates_json_reports_indexes_without_uris(monkeypatch):
    from blackoutkit.config.manager import ProxyConfig

    duplicate_uri = "trojan://secret@example.com:443"
    configs = [
        ProxyConfig(protocol="trojan", address="example.com", port=443, raw_uri=duplicate_uri),
        ProxyConfig(protocol="trojan", address="example.com", port=443, raw_uri=duplicate_uri),
    ]
    monkeypatch.setattr("blackoutkit.config.manager.load_configs", lambda: configs)

    result = runner.invoke(typer_cli.app, ["--json", "config", "check-duplicates"])

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"] == {
        "duplicate_count": 2,
        "duplicate_groups": [[1, 2]],
        "has_duplicates": True,
    }
    assert "secret@example.com" not in result.output


def test_config_compatibility_json_uses_safe_payload(monkeypatch):
    payload = {
        "configs": [{"index": 1, "protocol": "vless", "transport": "WS", "sni_compatible": False, "name": None}],
        "saved_protocols": ["vless"],
        "installed_components": {"sni-spoofing": True},
        "engines": [{
            "engine": "xray",
            "score": 1000,
            "ready": True,
            "evidence": "No local health history",
            "blockers": [],
            "stability": {},
            "compatible_protocols": ["trojan", "vless"],
            "required_components": ["sni-spoofing"],
            "required_settings": [],
        }],
    }
    monkeypatch.setattr(typer_cli, "_compatibility_payload", lambda _configs: payload)
    monkeypatch.setattr("blackoutkit.config.manager.load_configs", lambda: [])

    result = runner.invoke(typer_cli.app, ["--json", "config", "compatibility"])

    assert result.exit_code == 0, result.output
    assert __import__("json").loads(result.output)["data"] == payload


def test_config_diff_json_compares_redacted_setup_metadata(monkeypatch):
    import base64
    import json
    from blackoutkit.config.manager import ProxyConfig

    current_uri = "vless://current-secret@example.com:443"
    incoming_uri = "vless://incoming-secret@example.net:443"
    current = ProxyConfig(protocol="vless", address="example.com", port=443, raw_uri=current_uri)
    monkeypatch.setattr("blackoutkit.config.manager.load_configs", lambda: [current])
    monkeypatch.setattr("blackoutkit.settings.load", lambda: {"selected_engine": "auto"})
    setup = {
        "schema_version": 1,
        "configs": [incoming_uri],
        "settings": {"selected_engine": "xray"},
    }
    encoded = base64.b64encode(json.dumps(setup).encode()).decode()

    result = runner.invoke(typer_cli.app, ["--json", "config", "diff", encoded])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)["data"]
    assert data["config_changes"] == 1
    assert data["setting_changes"] == 1
    assert data["configs"][0]["status"] == "changed"
    assert current_uri not in result.output
    assert incoming_uri not in result.output


def test_plaintext_config_export_requires_force_in_noninteractive_mode():
    result = runner.invoke(typer_cli.app, ["config", "export"])

    assert result.exit_code == 2
    assert "--force" in result.output


def test_json_plaintext_config_export_never_prints_setup_blob():
    result = runner.invoke(typer_cli.app, ["--json", "config", "export"])

    assert result.exit_code == 2
    payload = __import__("json").loads(result.output)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "unsafe_output"
    assert "Setup string" not in result.output


def test_profile_export_requires_explicit_passphrase_mode(tmp_path):
    output = tmp_path / "profile.bkpf"

    result = runner.invoke(typer_cli.app, ["--json", "config", "profile-export", "--output", str(output)])

    assert result.exit_code == 1
    payload = __import__("json").loads(result.output)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "profile_export_failed"
    assert not output.exists()


def test_profile_export_and_import_use_authenticated_payload(monkeypatch, tmp_path):
    from unittest.mock import Mock

    import json
    from blackoutkit import vault

    profile_path = tmp_path / "portable.bkpf"
    setup = {
        "schema_version": 1,
        "configs": ["vless://profile-secret@example.com:443"],
        "settings": {"selected_engine": "xray"},
    }
    monkeypatch.setattr("blackoutkit.config.manager.serialize_setup", lambda: setup)
    monkeypatch.setattr(typer_cli, "read_secret", lambda *_args, **_kwargs: "passphrase")

    exported = runner.invoke(typer_cli.app, [
        "--json", "config", "profile-export", "--output", str(profile_path), "--stdin",
    ])

    assert exported.exit_code == 0, exported.output
    assert json.loads(exported.output)["data"] == {
        "exported": True,
        "format": "encrypted-profile",
    }
    encrypted = profile_path.read_bytes()
    assert b"profile-secret@example.com" not in encrypted

    apply_setup = Mock()
    monkeypatch.setattr(typer_cli, "_apply_setup", apply_setup)
    imported = runner.invoke(typer_cli.app, [
        "--json", "config", "profile-import", str(profile_path), "--stdin", "--force",
    ])

    assert imported.exit_code == 0, imported.output
    assert json.loads(imported.output)["data"] == {
        "config_count": 1,
        "format": "encrypted-profile",
        "imported": True,
        "setting_count": 1,
    }
    apply_setup.assert_called_once()
    restored_configs, restored_settings = apply_setup.call_args.args
    assert restored_configs[0].raw_uri == setup["configs"][0]
    assert restored_settings == setup["settings"]
    assert vault.decrypt_profile(encrypted, "passphrase") == setup


def test_bins_list_json_reports_local_registry_status(monkeypatch):
    info = SimpleNamespace(
        key="xray",
        display_name="Xray Core",
        required=True,
        github_repo="XTLS/Xray-core",
    )
    monkeypatch.setattr("blackoutkit.downloader.check_installed", lambda: {"xray": False})
    monkeypatch.setattr("blackoutkit.downloader.list_available", lambda: [info])

    result = runner.invoke(typer_cli.app, ["--json", "bins", "list"])

    assert result.exit_code == 0, result.output
    assert __import__("json").loads(result.output)["data"] == {
        "binaries": [{
            "auto_download": True,
            "installed": False,
            "key": "xray",
            "name": "Xray Core",
            "required": True,
        }],
        "installed_count": 0,
        "required_missing": ["xray"],
        "total_count": 1,
    }


def test_bins_status_json_does_not_call_legacy_renderer(monkeypatch):
    monkeypatch.setattr(
        typer_cli,
        "_bins_payload",
        lambda: {
            "binaries": [],
            "installed_count": 0,
            "required_missing": [],
            "total_count": 0,
        },
    )
    with patch("blackoutkit.cli.cmd_bins") as cmd_bins:
        result = runner.invoke(typer_cli.app, ["--json", "bins"])

    assert result.exit_code == 0, result.output
    assert __import__("json").loads(result.output)["data"]["total_count"] == 0
    cmd_bins.assert_not_called()


def test_bins_list_quiet_suppresses_human_output(monkeypatch):
    monkeypatch.setattr(
        typer_cli,
        "_bins_payload",
        lambda: {
            "binaries": [{
                "key": "xray",
                "name": "Xray Core",
                "installed": True,
                "required": True,
                "auto_download": True,
            }],
            "installed_count": 1,
            "required_missing": [],
            "total_count": 1,
        },
    )

    result = runner.invoke(typer_cli.app, ["--quiet", "bins", "list"])

    assert result.exit_code == 0
    assert result.output == ""


def test_json_parser_errors_are_single_line_envelopes():
    cases = [
        ["--json", "--unknown-option"],
        ["--json", "settings", "get"],
        ["--json", "config", "replace", "not-an-int", "value"],
    ]

    for args in cases:
        result = runner.invoke(typer_cli.app, args)
        assert result.exit_code == 2
        lines = [line for line in result.output.splitlines() if line.strip()]
        assert len(lines) == 1
        payload = __import__("json").loads(lines[0])
        assert payload["schema_version"] == 1
        assert payload["ok"] is False


def test_json_root_and_group_without_command_are_structured_errors():
    for args, message in ((["--json"], "a command is required"), (["--json", "config"], "a config subcommand is required"), (["--json", "settings"], "a settings subcommand is required")):
        result = runner.invoke(typer_cli.app, args)
        assert result.exit_code == 2
        payload = __import__("json").loads(result.output)
        assert payload["error"]["code"] == "missing_command"
        assert payload["error"]["message"] == message


def test_human_parser_errors_keep_rich_usage_output():
    result = runner.invoke(typer_cli.app, ["settings", "get"])

    assert result.exit_code == 2
    assert "Missing argument" in result.output
    assert "schema_version" not in result.output


def test_entrypoint_machine_mode_skips_first_run_hint(monkeypatch):
    import blackout as entrypoint

    monkeypatch.setattr(entrypoint.sys, "argv", ["blackout.py", "--json", "version"])
    assert entrypoint._machine_output_requested() is True
    monkeypatch.setattr(entrypoint.sys, "argv", ["blackout.py", "version"])
    assert entrypoint._machine_output_requested() is False


def test_json_doctor_suppresses_warnings(monkeypatch):
    result_item = SimpleNamespace(name="check", ok=True, message="OK", fixable=False)
    monkeypatch.setattr("blackoutkit.doctor.run_all_checks", lambda: [result_item])

    result = runner.invoke(typer_cli.app, ["--json", "doctor"])

    assert result.exit_code == 0
    assert result.output.startswith("{")
    assert "Warning" not in result.output


def test_json_mutation_success_paths_use_safe_envelopes(monkeypatch):
    from blackoutkit.config.manager import ProxyConfig

    monkeypatch.setattr("blackoutkit.settings.set_value", lambda *_args: None)
    updated = runner.invoke(typer_cli.app, ["--json", "settings", "set", "scan_timeout", "1.0"])
    assert updated.exit_code == 0, updated.output
    assert __import__("json").loads(updated.output)["data"] == {
        "key": "scan_timeout",
        "updated": True,
        "value": 1.0,
    }

    monkeypatch.setattr("blackoutkit.settings.reset", lambda: None)
    reset = runner.invoke(typer_cli.app, ["--json", "settings", "reset"])
    assert reset.exit_code == 0, reset.output
    assert __import__("json").loads(reset.output)["data"] == {"reset": True}

    config = ProxyConfig(protocol="vless", address="example.com", port=443, raw_uri="vless://secret@example.com:443")
    monkeypatch.setattr("blackoutkit.config.manager.load_configs", lambda: [])
    monkeypatch.setattr("blackoutkit.config.manager.add_config", lambda _uri: config)
    added = runner.invoke(typer_cli.app, ["--json", "config", "add", "vless://secret@example.com:443"])
    assert added.exit_code == 0, added.output
    assert __import__("json").loads(added.output)["data"] == {
        "added": True,
        "protocol": "vless",
        "transport": "WS",
    }
    assert "secret@example.com" not in added.output


def test_json_config_remove_and_import_success_paths(monkeypatch):
    config = type("Config", (), {"raw_uri": "vless://x@example.com:443"})()
    monkeypatch.setattr("blackoutkit.config.manager.remove_config", lambda _index: None)
    removed = runner.invoke(typer_cli.app, ["--json", "config", "remove", "2"])
    assert removed.exit_code == 0, removed.output
    assert __import__("json").loads(removed.output)["data"] == {"index": 2, "removed": True}

    monkeypatch.setattr("blackoutkit.config.manager.import_and_merge", lambda _url: (3, 5))
    imported = runner.invoke(typer_cli.app, ["--json", "config", "import", "https://example.com/sub"])
    assert imported.exit_code == 0, imported.output
    assert __import__("json").loads(imported.output)["data"] == {"added": 3, "total": 5}


def test_json_encrypt_and_decrypt_success_paths(monkeypatch):
    monkeypatch.setattr("blackoutkit.security.configs_are_obfuscated", lambda: True)
    encrypted = runner.invoke(typer_cli.app, ["--json", "config", "encrypt"])
    assert encrypted.exit_code == 0, encrypted.output
    assert __import__("json").loads(encrypted.output)["data"] == {"already_active": True, "encrypted": True}

    monkeypatch.setattr("blackoutkit.security.configs_are_obfuscated", lambda: False)
    decrypted = runner.invoke(typer_cli.app, ["--json", "config", "decrypt"])
    assert decrypted.exit_code == 0, decrypted.output
    assert __import__("json").loads(decrypted.output)["data"] == {"decrypted": False, "encrypted_data": False}


def test_main_json_internal_error_uses_safe_envelope(monkeypatch):
    import json

    monkeypatch.setattr(typer_cli, "app", lambda: (_ for _ in ()).throw(RuntimeError("secret details")))
    monkeypatch.setattr(typer_cli.sys, "argv", ["blackout", "--json", "version"])
    with typer_cli.console.capture() as capture:
        with pytest.raises(SystemExit) as exc_info:
            typer_cli.main()

    assert exc_info.value.code == 1
    payload = json.loads(capture.get())
    assert payload["error"]["code"] == "internal_error"
    assert "secret details" not in capture.get()
