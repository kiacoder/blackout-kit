"""Tests for the Iranian ISP sub-profile schema and transient flags."""
import json

from typer.testing import CliRunner

from blackoutkit import isp_profiles, typer_cli
from blackoutkit.connection_service import (
    ConnectionRequest,
    ConnectionService,
    validate_sni_spoof_domain,
)
from blackoutkit.settings import DEFAULTS

runner = CliRunner()


def _quiet_service(**overrides):
    defaults = dict(
        emit=lambda event: None,
        emit_output=False,
        is_interactive=lambda: False,
        # Never touch real readiness or daemon boundaries in tests; the
        # transient-flag behavior under test lives entirely in request/
        # preset handling, and a real spawned daemon would make these tests
        # order-dependent (live PID blocks later readiness checks).
        readiness_evaluate=lambda _engine: [],
        daemon_start=lambda engine, env_overrides=None: 4321,
        daemon_get_pid=lambda: None,
    )
    defaults.update(overrides)
    return ConnectionService(**defaults)


# ───────────────────────── schema ─────────────────────────


def test_registry_codes_are_unique_and_iran_scoped():
    codes = [profile.code for profile in isp_profiles.list_isp_profiles()]
    assert len(codes) == len(set(codes))
    assert "ir-mci" in codes and "ir-irancell" in codes
    assert all(profile.country_code == "IR" for profile in isp_profiles.list_isp_profiles())


def test_get_isp_profile_is_case_insensitive_and_none_safe():
    assert isp_profiles.get_isp_profile("IR-MCI").code == "ir-mci"
    assert isp_profiles.get_isp_profile("  ir-irancell ") is not None
    assert isp_profiles.get_isp_profile("ir-nonexistent") is None
    assert isp_profiles.get_isp_profile(None) is None
    assert isp_profiles.get_isp_profile("") is None


def test_every_override_key_is_a_real_setting():
    # The profiles apply through the transient env-override mechanism, which
    # only works for real setting keys; a typo'd key would silently no-op.
    for profile in isp_profiles.list_isp_profiles():
        for key in profile.overrides():
            assert key in DEFAULTS, f"{profile.code}: unknown setting key {key}"


def test_detect_isp_profile_matches_asn_prefix():
    class Info:
        asn = "AS44244"

    assert isp_profiles.detect_isp_profile(Info()).code == "ir-irancell"

    class Prefix:
        asn = "AS44244X"  # startswith-style match on padded ASN

    assert isp_profiles.detect_isp_profile(Prefix()) is not None

    class Unknown:
        asn = "AS00000"

    assert isp_profiles.detect_isp_profile(Unknown()) is None

    class NoAsn:
        asn = ""

    assert isp_profiles.detect_isp_profile(NoAsn()) is None
    assert isp_profiles.detect_isp_profile(None) is None


def test_profile_to_dict_is_json_serializable():
    payload = json.dumps(isp_profiles.get_isp_profile("ir-tci").to_dict())
    data = json.loads(payload)
    assert data["access_type"] == "fixed"
    assert data["overrides"]["country"] == "IR"
    assert "field-verified" in data["notes"] or "field-verified" in str(data)


# ───────────────────────── sni-spoof validator ─────────────────────────


def test_sni_spoof_validator_accepts_bare_hostnames():
    assert validate_sni_spoof_domain("www.example.com") is None
    assert validate_sni_spoof_domain("WWW.Example.COM.") is None
    assert validate_sni_spoof_domain("a-b.example.ir") is None


def test_sni_spoof_validator_rejects_non_hostnames():
    for bad in (
        "", "   ", "http://x.com", "x.com/path", "user:pass@x.com",
        "localhost", "x..y.com", "-bad.com", "bad-.com", "a" * 64 + ".com",
        "has space.com", "a" * 300 + ".com",
    ):
        assert validate_sni_spoof_domain(bad), bad


# ───────────────────────── connection service wiring ─────────────────────────


def test_start_with_sni_spoof_applies_transient_override_and_leaves_settings():
    settings_seen = {}
    set_calls = []

    def fake_load():
        return {"selected_engine": "sni"}

    def fake_set(key, value):
        set_calls.append((key, value))

    svc = _quiet_service(settings_load=fake_load, settings_set=fake_set)
    result = svc.start(ConnectionRequest(operation="start", engine="sni", background=True, sni_spoof="Camera.Example.COM."))

    assert result.ok
    assert result.preset["name"] == "sni-spoof"
    assert result.preset["overrides"]["BLACKOUT_SNI_FAKE_SNI"] == "camera.example.com"
    assert "camera.example.com" in result.preset["changes"][0]
    assert set_calls == []  # transient: saved settings untouched


def test_start_with_spoof_on_non_consumer_engine_warns():
    warnings = []
    svc = _quiet_service(emit=warnings.append)
    result = svc.start(ConnectionRequest(operation="start", engine="psiphon", background=True, sni_spoof="demo.example.com"))
    assert result.ok
    assert any("does not read the fake-SNI setting" in str(item.get("message", "")) for item in warnings)


def test_start_rejects_invalid_spoof_domain_cleanly():
    svc = _quiet_service()
    result = svc.start(ConnectionRequest(operation="start", engine="sni", background=True, sni_spoof="http://x.com"))
    assert not result.ok
    assert result.code == "invalid_input"
    assert "bare hostname" in result.message


def test_profile_rejects_conflict_with_country_presets():
    svc = _quiet_service()
    result = svc.connect(ConnectionRequest(operation="connect", iran=True, isp_profile="ir-mci"))
    assert not result.ok
    assert result.code == "invalid_preset"
    result2 = svc.start(ConnectionRequest(operation="start", engine="sni", russia=True, isp_profile="ir-mci", background=True))
    assert not result2.ok
    assert result2.code == "invalid_preset"


def test_start_with_unknown_profile_fails_cleanly():
    svc = _quiet_service()
    result = svc.start(ConnectionRequest(operation="start", engine="sni", background=True, isp_profile="ir-nope"))
    assert not result.ok
    assert result.code == "invalid_input"
    assert "ir-mci" in result.message


def test_start_with_profile_applies_transient_overrides():
    set_calls = []

    def fake_set(key, value):
        set_calls.append((key, value))

    svc = _quiet_service(settings_load=lambda: {"selected_engine": "sni"}, settings_set=fake_set)
    result = svc.start(ConnectionRequest(operation="start", engine="sni", background=True, isp_profile="ir-mci"))

    assert result.ok
    assert result.preset["name"] == "isp-profile"
    overrides = result.preset["overrides"]
    assert overrides["BLACKOUT_COUNTRY"] == "IR"
    assert overrides["BLACKOUT_SNI_FAKE_SNI"]
    assert set_calls == []  # transient only


def test_sni_spoof_wins_over_profile_sni_value():
    svc = _quiet_service()
    result = svc.start(ConnectionRequest(
        operation="start", engine="sni", background=True,
        isp_profile="ir-mci", sni_spoof="explicit.example.com",
    ))
    assert result.ok
    overrides = result.preset["overrides"]
    assert overrides["BLACKOUT_SNI_FAKE_SNI"] == "explicit.example.com"
    assert any("spoof" in change for change in result.preset["changes"])


# ───────────────────────── CLI surface ─────────────────────────


def test_cli_isp_list_and_show():
    result = runner.invoke(typer_cli.app, ["isp", "list"])
    assert result.exit_code == 0
    assert "ir-mci" in result.output and "ir-irancell" in result.output

    result = runner.invoke(typer_cli.app, ["isp", "show", "ir-irancell"])
    assert result.exit_code == 0
    assert "AS44244" in result.output

    result = runner.invoke(typer_cli.app, ["isp", "list", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True and payload["data"]["count"] >= 4


def test_cli_isp_show_unknown_errors_cleanly():
    result = runner.invoke(typer_cli.app, ["isp", "show", "bogus"])
    assert result.exit_code == 2
    assert "ir-mci" in result.output


def test_cli_start_rejects_invalid_spoof():
    result = runner.invoke(typer_cli.app, ["start", "sni", "--sni-spoof", "http://bad", "--background"])
    assert result.exit_code == 2
    assert "bare hostname" in result.output
