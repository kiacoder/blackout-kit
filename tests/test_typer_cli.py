from unittest.mock import patch

from typer.testing import CliRunner

from blackoutkit import typer_cli


runner = CliRunner()


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
    monkeypatch.setattr(typer_cli, "is_interactive", lambda: False)
    with patch("blackoutkit.cli.cmd_connect") as cmd_connect:
        typer_cli.connect(pos_engine=None, engine=None, background=False, iran=False)

    args = cmd_connect.call_args.args[0]
    assert args.pos_engine is None
    assert args.engine is None


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


def test_doctor_forwards_fix_options():
    with patch("blackoutkit.cli.cmd_doctor") as cmd_doctor:
        typer_cli.doctor(fix=True, fix_av=True)

    args = cmd_doctor.call_args.args[0]
    assert args.fix is True
    assert args.fix_av is True


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


def test_country_set_forwards_code():
    with patch("blackoutkit.cli.cmd_country") as cmd_country:
        typer_cli.country_set("IR")

    args = cmd_country.call_args.args[0]
    assert args.country_command == "set"
    assert args.code == "IR"


def test_bins_update_forwards_to_legacy_dispatcher():
    with patch("blackoutkit.cli.cmd_bins") as cmd_bins:
        typer_cli.bins_update()

    assert cmd_bins.call_args.args[0].bins_command == "update"


def test_fix_forwards_explicit_network_reset_flags():
    with patch("blackoutkit.cli.cmd_fix") as cmd_fix:
        typer_cli.fix(full_route_reset=True, full_stack_reset=True, flush_arp=True)

    args = cmd_fix.call_args.args[0]
    assert args.full_route_reset is True
    assert args.full_stack_reset is True
    assert args.flush_arp is True


def test_tools_arp_flush_forwards_to_legacy_dispatcher():
    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        typer_cli.tools_arp_flush()

    assert cmd_tools.call_args.args[0].tools_command == "arp-flush"


def test_tools_netfix_uses_shared_default_recovery():
    with patch("blackoutkit.cli.cmd_tools") as cmd_tools:
        typer_cli.tools_netfix()

    args = cmd_tools.call_args.args[0]
    assert args.tools_command == "netfix"
    assert not hasattr(args, "full_route_reset")


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
