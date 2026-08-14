from unittest.mock import patch

from typer.testing import CliRunner

from blackoutkit import typer_cli


runner = CliRunner()


def test_documented_commands_are_registered():
    result = runner.invoke(typer_cli.app, ["--help"])

    assert result.exit_code == 0
    for command in ("help", "country", "bins", "doctor", "emergency", "logs", "update"):
        assert command in result.output


def test_documented_options_are_registered():
    checks = {
        ("doctor", "--help"): "--fix",
        ("logs", "--help"): "--lines",
        ("emergency", "--help"): "--background",
        ("update", "--help"): "--apply",
        ("tools", "cert-check", "--help"): "--allow",
        ("country", "--help"): "set",
        ("bins", "--help"): "update",
    }

    for args, expected in checks.items():
        result = runner.invoke(typer_cli.app, list(args))
        assert result.exit_code == 0, result.output
        assert expected in result.output


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
