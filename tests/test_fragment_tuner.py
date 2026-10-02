"""Tests for the fragment tuner: probe config shape, ranking, binding."""
import json

import pytest
from typer.testing import CliRunner

from blackoutkit import fragment_tuner as ft
from blackoutkit import typer_cli
from blackoutkit.fragment_tuner import ProbeOutcome

runner = CliRunner()


# ───────────── validator ─────────────


def test_validate_fragment_accepts_empty_and_two_part_ranges():
    assert ft.validate_fragment("") is None
    assert ft.validate_fragment("10-20,30-40") is None
    assert ft.validate_fragment("5-10,20-30") is None


def test_validate_fragment_rejects_malformed_ranges():
    assert ft.validate_fragment("10-20") is not None
    assert ft.validate_fragment("a-b,c-d") is not None
    assert ft.validate_fragment("10-20,30-40,50-60") is not None


# ───────────── probe config shape ─────────────


def test_plain_probe_config_has_no_fragment_path():
    config = ft.build_probe_config("1.2.3.4", "www.example.com", 18443, "")
    assert config["inbounds"][0]["protocol"] == "http"
    direct = config["outbounds"][0]
    assert direct["tag"] == "probe-direct"
    assert "sockopt" not in direct["streamSettings"]
    assert direct["settings"]["address"] == "1.2.3.4"
    assert direct["settings"]["port"] == 443
    tls = direct["streamSettings"]["tlsSettings"]
    assert tls["serverName"] == "www.example.com"
    assert "allowInsecure" not in tls  # removed in current Xray builds


def test_fragmented_probe_config_splits_client_hello_via_dialer_proxy():
    config = ft.build_probe_config("1.2.3.4", "www.example.com", 18444, "10-20,30-40")
    tags = [outbound["tag"] for outbound in config["outbounds"]]
    assert tags == ["fragment-out", "probe-direct"]
    fragment_settings = config["outbounds"][0]["settings"]["fragment"]
    assert fragment_settings == {"packets": "tlshello", "length": "10-20", "interval": "30-40"}
    sockopt = config["outbounds"][1]["streamSettings"]["sockopt"]
    assert sockopt["dialerProxy"] == "fragment-out"


def test_build_probe_config_rejects_invalid_fragment():
    with pytest.raises(ValueError):
        ft.build_probe_config("1.2.3.4", "www.example.com", 18445, "nonsense")


def test_probe_config_is_valid_json():
    config = ft.build_probe_config("1.2.3.4", "www.example.com", 18446, "10-50,10-50")
    assert json.loads(json.dumps(config))["log"]["loglevel"] == "error"


# ───────────── ranking and winner selection ─────────────


def test_tune_ranks_by_latency_with_stable_order_tiebreak():
    calls = []

    def prober(fragment, config):
        calls.append(fragment)
        if fragment == "":
            return ProbeOutcome(fragment, False, None, "blocked")
        latency = 40.0 if "10-20" in fragment else 60.0
        return ProbeOutcome(fragment, True, latency, "ok")

    result = ft.tune(
        "1.2.3.4", fake_sni="www.example.com",
        candidates=("", "10-20,30-40", "10-50,10-50"),
        prober=prober,
    )
    assert calls == ["", "10-20,30-40", "10-50,10-50"]
    assert result.winner.fragment == "10-20,30-40"
    assert [item.ok for item in result.outcomes] == [False, True, True]


def test_tune_all_candidates_failing_yields_no_winner():
    result = ft.tune(
        "1.2.3.4", fake_sni="www.example.com", candidates=("",),
        prober=lambda fragment, config: ProbeOutcome(fragment, False, None, "no"),
    )
    assert result.winner is None


def test_tune_equal_latency_prefers_earlier_candidate():
    result = ft.tune(
        "1.2.3.4", fake_sni="www.example.com", candidates=("", "10-20,30-40"),
        prober=lambda fragment, config: ProbeOutcome(fragment, True, 50.0, "ok"),
    )
    # "" (no fragmentation) is first in candidate order and wins ties.
    assert result.winner.fragment == ""


def test_tune_invalid_candidate_recorded_as_failure_without_probing():
    probed = []

    def prober(fragment, config):
        probed.append(fragment)
        return ProbeOutcome(fragment, True, 10.0, "ok")

    result = ft.tune(
        "1.2.3.4", fake_sni="www.example.com", candidates=("10-20", "10-50,10-50"),
        prober=prober,
    )
    assert probed == ["10-50,10-50"]
    assert result.outcomes[0].ok is False
    assert result.winner.fragment == "10-50,10-50"


# ───────────── target resolution and binding ─────────────


def test_resolve_target_ip_prefers_explicit_argument():
    scanner_calls = []

    def scanner(_arg, count):
        scanner_calls.append(count)
        return "9.9.9.9"

    assert ft.resolve_target_ip("1.2.3.4", scanner=scanner) == "1.2.3.4"
    assert not scanner_calls


def test_resolve_target_ip_falls_back_to_scanner():
    assert ft.resolve_target_ip(None, scanner=lambda _arg, count: "5.6.7.8") == "5.6.7.8"


def test_apply_winner_writes_both_settings_keys():
    written = {}
    ft.apply_winner("1.2.3.4", "10-20,30-40", settings_set=lambda key, value: written.update({key: value}))
    assert written == {"sni_connect_ip": "1.2.3.4", "xray_fragment": "10-20,30-40"}


# ───────────── CLI surface (probe fully injected, no network) ─────────────


def test_cli_tune_fragment_json_contract(monkeypatch):
    monkeypatch.setattr(ft, "resolve_target_ip", lambda explicit, count=20: "1.2.3.4")
    monkeypatch.setattr(
        ft, "tune",
        lambda target, **kwargs: ft.TuneResult(
            target_ip=target, fake_sni=kwargs.get("fake_sni") or "www.hcaptcha.com",
            outcomes=(
                ProbeOutcome("", False, None, "blocked"),
                ProbeOutcome("10-20,30-40", True, 42.0, "ok"),
            ),
        ),
    )
    result = runner.invoke(typer_cli.app, ["tune", "fragment", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["data"]["winner"]["fragment"] == "10-20,30-40"
    assert payload["data"]["applied"] is False
    assert "not a bypass guarantee" in payload["data"]["note"]


def test_cli_tune_fragment_apply_writes_settings(monkeypatch, tmp_path):
    written = {}
    monkeypatch.setattr(ft, "resolve_target_ip", lambda explicit, count=20: "1.2.3.4")
    monkeypatch.setattr(
        ft, "tune",
        lambda target, **kwargs: ft.TuneResult(
            target_ip=target, fake_sni="www.hcaptcha.com",
            outcomes=(ProbeOutcome("10-20,30-40", True, 42.0, "ok"),),
        ),
    )
    monkeypatch.setattr(ft, "apply_winner", lambda ip, frag, **kwargs: written.update({"ip": ip, "frag": frag}))
    result = runner.invoke(typer_cli.app, ["tune", "fragment", "--apply", "--json"])
    assert result.exit_code == 0
    assert written == {"ip": "1.2.3.4", "frag": "10-20,30-40"}


def test_cli_tune_fragment_without_clean_ip_errors(monkeypatch):
    monkeypatch.setattr(ft, "resolve_target_ip", lambda explicit, count=20: None)
    result = runner.invoke(typer_cli.app, ["tune", "fragment", "--json"])
    assert result.exit_code == 1
    assert "scan" in result.output.lower()
