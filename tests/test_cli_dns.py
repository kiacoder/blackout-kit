"""`blackout dns` command surface: listing, JSON shape, and failure modes."""
from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from blackoutkit import dns_engine as dns
from blackoutkit import typer_cli

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(dns, "STATE_FILE", tmp_path / "dns_state.json")
    monkeypatch.setattr(dns, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(dns.DNSEngine, "current_servers", lambda self: ["203.0.113.9"])
    return tmp_path


def test_list_shows_both_addresses_for_every_provider():
    result = runner.invoke(typer_cli.app, ["dns", "list"])
    assert result.exit_code == 0
    for prov in dns.providers():
        assert prov.primary in result.stdout
        if prov.secondary:
            assert prov.secondary in result.stdout


def test_list_filters_by_category():
    result = runner.invoke(typer_cli.app, ["dns", "list", "--category", "speed"])
    assert result.exit_code == 0
    assert "77.88.8.8" in result.stdout
    assert "178.22.122.100" not in result.stdout


def test_list_rejects_an_unknown_category():
    # The error goes through the shared rich console, which CliRunner does not
    # capture; the exit code is the contract.
    result = runner.invoke(typer_cli.app, ["dns", "list", "-c", "turbo"])
    assert result.exit_code == 2


def test_json_list_is_machine_readable():
    result = runner.invoke(typer_cli.app, ["--json", "dns", "list"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    providers = payload["data"]["providers"]
    assert payload["data"]["count"] == len(providers) == len(dns.providers())
    shecan = next(p for p in providers if p["key"] == "shecan")
    assert shecan["primary"] == "178.22.122.100"
    assert shecan["secondary"] == "185.51.200.2"


def test_status_json_reports_current_resolvers():
    result = runner.invoke(typer_cli.app, ["--json", "dns"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)["data"]
    assert payload["current_servers"] == ["203.0.113.9"]
    assert payload["active_provider"] is None


def test_set_unknown_provider_exits_non_zero():
    result = runner.invoke(typer_cli.app, ["dns", "set", "nope-nope"])
    assert result.exit_code == 1
    assert "shecan" in result.stdout  # the catalogue is listed as a hint


def test_set_applies_the_pair(monkeypatch):
    calls = []

    def fake_dispatch(self, servers, adapter):
        calls.append((tuple(servers), adapter))
        return dns.DNSApplyResult(True, "ok")

    monkeypatch.setattr(dns.DNSEngine, "_dispatch_apply", fake_dispatch)
    monkeypatch.setattr(dns.DNSEngine, "flush", lambda self: True)

    result = runner.invoke(typer_cli.app, ["dns", "set", "shecan"])
    assert result.exit_code == 0
    assert calls == [(("178.22.122.100", "185.51.200.2"), None)]
    assert "Shecan" in result.stdout


def test_set_forwards_the_adapter_option(monkeypatch):
    calls = []
    monkeypatch.setattr(
        dns.DNSEngine,
        "_dispatch_apply",
        lambda self, servers, adapter: calls.append(adapter) or dns.DNSApplyResult(True, "ok"),
    )
    monkeypatch.setattr(dns.DNSEngine, "flush", lambda self: True)

    result = runner.invoke(typer_cli.app, ["dns", "set", "google", "--adapter", "Wi-Fi"])
    assert result.exit_code == 0
    assert calls == ["Wi-Fi"]


def test_restore_reports_failure_without_a_crash(monkeypatch):
    monkeypatch.setattr(
        dns.DNSEngine,
        "_dispatch_restore",
        lambda self, adapters: dns.DNSApplyResult(False, "needs admin"),
    )
    result = runner.invoke(typer_cli.app, ["dns", "restore"])
    assert result.exit_code == 1
    assert "needs admin" in result.stdout


def test_tools_dns_set_resolves_catalogue_names():
    """The legacy `tools dns-set` path must use the same catalogue."""
    from blackoutkit.cli import cmd_tools
    from blackoutkit import typer_cli as tc

    captured = {}

    class _Args:
        tools_command = "dns-set"
        server = "shecan"
        adapter = None

    import blackoutkit.cli as cli_mod

    original = cli_mod.net_tools
    try:
        class _Net:
            @staticmethod
            def set_dns(ip, adapter=None):
                captured["ip"] = ip
                return True

        cli_mod.net_tools = _Net()
        cmd_tools(_Args())
    finally:
        cli_mod.net_tools = original

    assert captured["ip"] == "178.22.122.100"
    assert tc is not None
