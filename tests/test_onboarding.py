import json
from unittest.mock import Mock

from rich.console import Console
from typer.testing import CliRunner

from blackoutkit import onboarding, typer_cli
from blackoutkit.connection_service import ConnectionResult


runner = CliRunner()


def _plan(*, engine="sni", blockers=()):
    return onboarding.SetupPlan(
        platform="win32",
        recommended_engine=engine,
        steps=("doctor --local-only", "capabilities", "route", "config or upstream setup", "ready", "connect"),
        blockers=tuple(blockers),
        requires_upstream=False,
        requires_confirmation=("download runtime components", "save or import configuration", "connect and change local network state"),
    )


def test_read_only_setup_plan_uses_plain_settings_loader(monkeypatch):
    from blackoutkit import settings as cfg
    from blackoutkit.config import manager
    from blackoutkit import downloader

    from blackoutkit import settings as settings_module

    plain_loader = Mock(return_value={
        **settings_module.DEFAULTS,
        "selected_engine": "auto",
    })
    mutable_loader = Mock(side_effect=AssertionError("read-only setup called settings.load"))
    monkeypatch.setattr(cfg, "_load_plain_settings", plain_loader)
    monkeypatch.setattr(cfg, "load", mutable_loader)
    monkeypatch.setattr(manager, "load_configs", lambda: [])
    monkeypatch.setattr(downloader, "check_installed", lambda: {"sni-spoofing": True})
    monkeypatch.setattr(onboarding.sys, "platform", "win32")

    plan = onboarding.build_current_setup_plan(read_only=True)

    plain_loader.assert_called_once_with()
    mutable_loader.assert_not_called()
    assert plan.recommended_engine == "sni"


def test_run_setup_rechecks_until_plan_is_ready(monkeypatch):
    blocked = _plan(blockers=("sni-spoofing missing",))
    ready = _plan()
    plans = iter((blocked, ready))
    actions = iter(("recheck",))
    rendered = []

    monkeypatch.setattr(onboarding, "build_current_setup_plan", lambda: next(plans))
    monkeypatch.setattr(onboarding, "render_setup_plan", lambda plan, _console: rendered.append(plan))

    result = onboarding.run_setup(
        menu_runner=lambda *_args, **_kwargs: next(actions),
        console=Console(record=True),
    )

    assert result == ready
    assert rendered == [blocked, ready]


def test_setup_connect_uses_final_recommended_engine(monkeypatch):
    final_plan = _plan(engine="xray")
    run_setup = Mock(return_value=final_plan)
    service = Mock()
    service.connect.return_value = ConnectionResult(
        operation="connect",
        ok=True,
        status="stopped",
        engine="xray",
    )
    confirm = Mock(return_value=True)

    monkeypatch.setattr(onboarding, "run_setup", run_setup)
    monkeypatch.setattr(typer_cli, "is_interactive", lambda: True)
    monkeypatch.setattr(typer_cli, "confirm", confirm)
    monkeypatch.setattr(typer_cli, "_connection_service", lambda _options: service)

    typer_cli.setup(connect=True)

    run_setup.assert_called_once_with(console=typer_cli.console)
    confirm.assert_called_once()
    request = service.connect.call_args.args[0]
    assert request.pos_engine == "xray"
    assert request.operation == "connect"


def test_setup_connect_is_rejected_without_interactive_terminal(monkeypatch):
    service = Mock()
    monkeypatch.setattr(typer_cli, "_connection_service", lambda _options: service)
    monkeypatch.setattr(typer_cli, "is_interactive", lambda: False)

    result = runner.invoke(typer_cli.app, ["--quiet", "setup", "--connect"])

    assert result.exit_code == 2
    assert "requires an interactive terminal" in result.output
    service.connect.assert_not_called()


def test_setup_json_is_one_read_only_envelope(monkeypatch):
    monkeypatch.setattr(onboarding, "build_current_setup_plan", lambda read_only=False: _plan())

    result = runner.invoke(typer_cli.app, ["--json", "setup"])

    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["ok"] is True
    assert payload["data"]["read_only"] is True
    assert payload["data"]["recommended_engine"] == "sni"


def test_first_run_welcome_is_read_only_and_suppressed_after_first_run(monkeypatch, tmp_path):
    from blackoutkit import settings as cfg

    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr(cfg, "SETTINGS_FILE", settings_file)
    console = Console(record=True, force_terminal=False)

    assert onboarding.render_first_run_welcome(console) is True
    assert "Welcome to Blackout Kit" in console.export_text()
    assert not settings_file.exists()

    monkeypatch.setattr(onboarding, "is_first_run", lambda: False)
    assert onboarding.render_first_run_welcome(console) is False


def test_root_first_run_welcome_renders_once_without_writing_settings(monkeypatch, tmp_path):
    from blackoutkit import settings as cfg

    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr(cfg, "SETTINGS_FILE", settings_file)
    monkeypatch.setattr(typer_cli, "is_interactive", lambda: True)
    monkeypatch.setattr("blackoutkit.cli.print_banner", lambda: None)
    monkeypatch.setattr("blackoutkit.cli._show_launcher_menu", lambda: None)

    result = runner.invoke(typer_cli.app, [])

    assert result.exit_code == 0, result.output
    assert result.output.count("Welcome to Blackout Kit") == 1
    assert not settings_file.exists()


def test_setup_embedded_editors_receive_confirmation_mode(monkeypatch):
    calls = []

    monkeypatch.setattr(onboarding, "build_current_setup_plan", lambda: _plan(blockers=("missing",)))
    monkeypatch.setattr(onboarding, "render_setup_plan", lambda *_args: None)
    def fake_settings(**kwargs):
        calls.append(kwargs)

    monkeypatch.setattr("blackoutkit.interactive.run_settings_menu", fake_settings)
    actions = iter(("settings", "back"))
    onboarding.run_setup(
        menu_runner=lambda *_args: next(actions),
        confirm_runner=lambda _question: False,
        console=Console(record=True),
    )

    assert calls and calls[0]["require_confirmation"] is True


def test_setup_embedded_config_editor_receives_confirmation_mode(monkeypatch):
    calls = []
    plans = iter((_plan(blockers=("missing",)), _plan(blockers=("missing",))))
    monkeypatch.setattr(onboarding, "build_current_setup_plan", lambda: next(plans))
    monkeypatch.setattr(onboarding, "render_setup_plan", lambda *_args: None)
    actions = iter(("config", "back"))
    monkeypatch.setattr(
        "blackoutkit.interactive.run_config_menu",
        lambda **kwargs: calls.append(kwargs),
    )

    onboarding.run_setup(
        menu_runner=lambda *_args: next(actions),
        confirm_runner=lambda _question: False,
        console=Console(record=True),
    )

    assert calls and calls[0]["require_confirmation"] is True