"""Milestone battery: malformed sni-spoof inputs, profile conflicts and
suggestions, env restoration on bootstrap failure, and the interactive
carrier picker."""
import json

from typer.testing import CliRunner

from blackoutkit import isp_profiles, typer_cli
from blackoutkit.connection_service import (
    ConnectionRequest,
    ConnectionResult,
    ConnectionService,
    validate_sni_spoof_domain,
)

runner = CliRunner()


def _quiet_service(**overrides):
    defaults = dict(
        emit=lambda event: None,
        emit_output=False,
        is_interactive=lambda: False,
        readiness_evaluate=lambda _engine: [],
        daemon_start=lambda engine, env_overrides=None: 4321,
        daemon_get_pid=lambda: None,
    )
    defaults.update(overrides)
    return ConnectionService(**defaults)


def _env_snapshot():
    import os

    return {key: value for key, value in os.environ.items() if key.startswith("BLACKOUT_")}


# ───────────── malformed --sni-spoof inputs ─────────────


def test_sni_spoof_rejects_hostname_with_port():
    error = validate_sni_spoof_domain("example.com:443")
    assert error
    assert "port" in error.lower()


def test_sni_spoof_rejects_raw_ipv4():
    error = validate_sni_spoof_domain("1.2.3.4")
    assert error and "ip address" in error.lower()


def test_sni_spoof_rejects_raw_ipv6():
    error = validate_sni_spoof_domain("2001:db8::1")
    assert error and "sni" in error.lower()


def test_sni_spoof_rejects_invalid_tld_characters():
    error = validate_sni_spoof_domain("example.comm!")
    assert error and "letters, digits" in error


# ───────────── --profile conflicts and suggestions ─────────────


def test_profile_iran_conflict_reports_explicit_error():
    svc = _quiet_service()
    result = svc.connect(ConnectionRequest(operation="connect", iran=True, isp_profile="ir-mci"))
    assert result.code == "invalid_preset"
    assert "--profile" in result.message and "--iran" in result.message


def test_profile_russia_conflict_reports_explicit_error():
    svc = _quiet_service()
    result = svc.connect(ConnectionRequest(operation="connect", russia=True, isp_profile="ir-mci"))
    assert result.code == "invalid_preset"
    assert "--russia" in result.message


def test_suggest_isp_profiles_matches_carrier_names_and_typos():
    assert isp_profiles.suggest_isp_profiles("mci")[0] == "ir-mci"
    assert isp_profiles.suggest_isp_profiles("irancell") == ("ir-irancell",)
    assert isp_profiles.suggest_isp_profiles("ir-mcx")[0] == "ir-mci"
    assert isp_profiles.suggest_isp_profiles("zzzznothing") == ()
    assert isp_profiles.suggest_isp_profiles("") == ()


def test_unknown_carrier_error_includes_did_you_mean():
    svc = _quiet_service()
    result = svc.start(ConnectionRequest(operation="start", engine="sni", background=True, isp_profile="mci"))
    assert not result.ok
    assert "Did you mean: ir-mci" in result.message


def test_cli_isp_show_typo_suggests_profile():
    result = runner.invoke(typer_cli.app, ["isp", "show", "ir-mcx"])
    assert result.exit_code == 2
    assert "Did you mean: ir-mci" in result.output


def test_cli_start_unknown_profile_suggests():
    result = runner.invoke(typer_cli.app, ["start", "sni", "--profile", "irancell", "--background"])
    assert result.exit_code == 2
    assert "Did you mean: ir-irancell" in result.output


def test_cli_profile_conflicts_exit_cleanly():
    iran_run = runner.invoke(typer_cli.app, ["start", "sni", "--iran", "--profile", "ir-mci", "--background"])
    assert iran_run.exit_code == 2
    assert "--profile" in iran_run.output
    russia_run = runner.invoke(typer_cli.app, ["connect", "--russia", "--profile", "ir-tci"])
    assert russia_run.exit_code == 2
    assert "--russia" in russia_run.output


# ───────────── env restoration on bootstrap failure ─────────────


def test_env_overrides_restored_after_runtime_error():
    before = _env_snapshot()
    spec = {}

    def daemon_start(engine, env_overrides=None):
        spec["seen"] = dict(env_overrides or {})
        raise RuntimeError("bootstrap exploded")

    svc = _quiet_service(settings_load=lambda: {"selected_engine": "sni"}, daemon_start=daemon_start)
    result = svc.start(ConnectionRequest(operation="start", engine="sni", background=True, sni_spoof="demo.example.com"))
    assert not result.ok and result.code == "daemon_start_failed"
    assert spec["seen"].get("BLACKOUT_SNI_FAKE_SNI") == "demo.example.com"
    assert _env_snapshot() == before


def test_env_overrides_restored_after_generic_exception():
    before = _env_snapshot()

    def daemon_start(engine, env_overrides=None):
        raise ValueError("unexpected bootstrap type")

    svc = _quiet_service(settings_load=lambda: {"selected_engine": "sni"}, daemon_start=daemon_start)
    result = svc.start(ConnectionRequest(operation="start", engine="sni", background=True, isp_profile="ir-mci"))
    assert not result.ok and result.code == "daemon_start_failed"
    assert _env_snapshot() == before


def test_foreground_bootstrap_exception_restores_env():
    before = _env_snapshot()
    calls = {}

    def start_stack(engine, emit=True):
        calls["ran"] = True
        raise OSError("engine binary missing")

    svc = _quiet_service(settings_load=lambda: {"selected_engine": "sni"}, start_engine_stack=start_stack)
    result = svc.start(ConnectionRequest(operation="start", engine="sni", sni_spoof="demo.example.com"))
    assert calls["ran"]
    assert not result.ok and result.code == "engine_start_failed"
    assert _env_snapshot() == before


# ───────────── interactive carrier picker ─────────────


def _picker_service(choose, detect=None, interactive=True):
    svc = ConnectionService(
        emit=lambda event: None,
        emit_output=False,
        is_interactive=lambda: interactive,
        choose_isp=choose,
        detect_isp=detect,
        readiness_evaluate=lambda _engine: [],
        recommended_engine=lambda: "sni",
        active_profile=lambda: None,
        route_candidates=lambda: [],
        settings_load=lambda: {"selected_engine": "auto"},
        daemon_start=lambda engine, env_overrides=None: 4321,
    )

    def stub_start(request, engine, env, **kwargs):
        return ConnectionResult(
            operation="connect", ok=True, status="connected",
            engine=engine, preset=kwargs.get("preset"),
        )

    svc._start_resolved = stub_start
    return svc


def test_picker_selection_applies_carrier_profile():
    svc = _picker_service(lambda: "ir-mci")
    result = svc.connect(ConnectionRequest(operation="connect"))
    assert result.ok and result.engine == "sni"
    assert result.preset["name"] == "isp-profile"
    assert result.preset["overrides"]["BLACKOUT_COUNTRY"] == "IR"


def test_picker_auto_detect_uses_asn_match():
    class Info:
        asn = "AS44244"

    events = []
    svc = _picker_service(lambda: "auto", detect=lambda: isp_profiles.detect_isp_profile(Info()))
    svc.emit = events.append
    result = svc.connect(ConnectionRequest(operation="connect"))
    assert result.ok and result.preset["name"] == "isp-profile"
    assert any("Detected carrier" in str(item.get("message", "")) for item in events)


def test_picker_auto_detect_failure_continues_without_profile():
    svc = _picker_service(lambda: "auto", detect=lambda: None)
    result = svc.connect(ConnectionRequest(operation="connect"))
    assert result.ok and result.preset is None


def test_picker_escape_skips_to_default_flow():
    consulted = []

    def choose():
        consulted.append(1)
        return None

    svc = _picker_service(choose)
    result = svc.connect(ConnectionRequest(operation="connect"))
    assert result.ok and result.preset is None
    assert consulted


def test_picker_never_consulted_when_non_interactive_or_flagged():
    consulted = []

    def choose():
        consulted.append(1)
        return "ir-mci"

    for request in (
        ConnectionRequest(operation="connect", background=True),
        ConnectionRequest(operation="connect", iran=True),
        ConnectionRequest(operation="connect", russia=True),
        ConnectionRequest(operation="connect", sni_spoof="demo.example.com"),
        ConnectionRequest(operation="connect", isp_profile="ir-mci"),
        ConnectionRequest(operation="connect", pos_engine="warp"),
    ):
        _picker_service(choose, interactive=False).connect(request)
        _picker_service(choose).connect(request)
    assert not consulted


def test_cli_keyboard_picker_returns_profile_codes(monkeypatch):
    from blackoutkit import terminal_menu

    captured = {}

    def fake_run_menu(title, items, guide=None, **kwargs):
        assert len(items) == 6  # five carriers + auto-detect
        captured["guide"] = guide
        return items[1].key

    monkeypatch.setattr(terminal_menu, "run_menu", fake_run_menu)
    assert typer_cli._ask_isp_profile() == "ir-irancell"
    assert "Esc" in captured["guide"]

    monkeypatch.setattr(
        terminal_menu, "run_menu",
        lambda title, items, guide=None, **kwargs: str(len(items)),
    )
    assert typer_cli._ask_isp_profile() == "auto"

    monkeypatch.setattr(terminal_menu, "run_menu", lambda *args, **kwargs: None)
    assert typer_cli._ask_isp_profile() is None
