from unittest.mock import MagicMock

import pytest

from blackoutkit import readiness


def test_readiness_never_starts_or_resolves_remote_hosts(monkeypatch):
    calls = []
    monkeypatch.setattr(readiness.cfg, "load", lambda: dict(readiness.cfg.DEFAULTS))
    monkeypatch.setattr(readiness.cfg, "validate_all", lambda _settings: [])
    monkeypatch.setattr(readiness.daemon, "get_pid", lambda: None)
    monkeypatch.setattr(readiness, "check_installed", lambda: {"sni-spoofing": True})
    monkeypatch.setattr(readiness, "load_configs", lambda: [])
    monkeypatch.setattr(readiness.socket, "getaddrinfo", lambda *_args: (_ for _ in ()).throw(AssertionError("must not resolve")))
    monkeypatch.setattr(readiness.socket, "create_connection", lambda *_args: (_ for _ in ()).throw(AssertionError("must not connect")))

    checks = readiness.evaluate("xray")

    assert checks
    assert calls == []


@pytest.mark.parametrize("mode", ["http", "mixed"])
def test_readiness_checks_both_xray_listener_ports_in_each_mode(monkeypatch, mode):
    settings = dict(readiness.cfg.DEFAULTS)
    settings["xray_system_proxy_mode"] = mode
    checked_ports = []
    monkeypatch.setattr(readiness.cfg, "load", lambda: settings)
    monkeypatch.setattr(readiness.cfg, "validate_all", lambda _settings: [])
    monkeypatch.setattr(readiness.daemon, "get_pid", lambda: None)
    monkeypatch.setattr(readiness, "check_installed", lambda: {"sni-spoofing": True})
    monkeypatch.setattr(readiness, "load_configs", lambda: [])
    monkeypatch.setattr(readiness, "_port_free", lambda port: checked_ports.append(port) or True)

    readiness.evaluate("xray")

    assert set(checked_ports) == {10808, 10809}


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_tun_readiness_does_not_treat_upstream_proxy_ports_as_tun_listeners(monkeypatch, platform):
    settings = dict(readiness.cfg.DEFAULTS)
    checked_ports = []
    monkeypatch.setattr(readiness, "_platform_key", lambda: platform)
    monkeypatch.setattr(readiness.cfg, "load", lambda: settings)
    monkeypatch.setattr(readiness.cfg, "validate_all", lambda _settings: [])
    monkeypatch.setattr(readiness.daemon, "get_pid", lambda: None)
    monkeypatch.setattr(readiness, "check_installed", lambda: {"sni-spoofing": True})
    monkeypatch.setattr(readiness, "load_configs", lambda: [])
    monkeypatch.setattr(readiness.vault, "vault_status", lambda: {"healthy": True, "detail": "ok"})
    monkeypatch.setattr(readiness.vault, "settings_vault_status", lambda _enabled: {"healthy": True, "detail": "ok"})
    monkeypatch.setattr(readiness, "_port_free", lambda port: checked_ports.append(port) or True)

    readiness.evaluate("tun")

    assert checked_ports == []


def test_windows_tun_uses_owned_local_upstream_without_saved_config(monkeypatch):
    settings = dict(readiness.cfg.DEFAULTS)
    monkeypatch.setattr(readiness, "_platform_key", lambda: "win32")
    monkeypatch.setattr(readiness.cfg, "load", lambda: settings)
    monkeypatch.setattr(readiness.cfg, "validate_all", lambda _settings: [])
    monkeypatch.setattr(readiness.daemon, "get_pid", lambda: None)
    monkeypatch.setattr(readiness, "check_installed", lambda: {"sni-spoofing": True})
    monkeypatch.setattr(readiness, "load_configs", lambda: [])
    monkeypatch.setattr(readiness.vault, "vault_status", lambda: {"healthy": True, "detail": "ok"})
    monkeypatch.setattr(readiness.vault, "settings_vault_status", lambda _enabled: {"healthy": True, "detail": "ok"})
    monkeypatch.setattr(readiness, "_port_free", lambda _port: True)

    checks = readiness.evaluate("tun")

    assert readiness._upstream_requirement("tun", "win32") == "local_fallback"
    assert not any(check.name.startswith("Proxy configuration") for check in checks)


def test_tun_capability_does_not_claim_local_proxy_listener():
    from blackoutkit.capabilities import get_capability

    capability = get_capability("tun")

    assert capability is not None
    assert capability.local_surface == "network_tunnel"
    assert capability.local_proxy is False
    assert capability.listeners == ()
    assert capability.local_ports_for("win32") == ()
    assert capability.local_ports_for("linux") == ()


def test_readiness_reports_loopback_port_conflict(monkeypatch):
    monkeypatch.setattr(readiness.cfg, "load", lambda: dict(readiness.cfg.DEFAULTS))
    monkeypatch.setattr(readiness.cfg, "validate_all", lambda _settings: [])
    monkeypatch.setattr(readiness.daemon, "get_pid", lambda: None)
    monkeypatch.setattr(readiness, "check_installed", lambda: {"sni-spoofing": True})
    monkeypatch.setattr(readiness, "load_configs", lambda: [])
    monkeypatch.setattr(readiness, "_port_free", lambda port: port != 10809)

    checks = readiness.evaluate("xray")

    assert any(check.name == "Local port 10809" and not check.ok and check.blocking for check in checks)


def test_ready_gate_blocks_connect_before_scan_or_settings_write(monkeypatch):
    from blackoutkit import cli

    monkeypatch.setattr(cli, "_recommended_engine_name", lambda: "xray")
    monkeypatch.setattr(cli, "_ensure_ready", lambda _engine: False)
    scanner = MagicMock()
    monkeypatch.setattr(cli, "generate_cloudflare_ips", scanner)
    monkeypatch.setattr(cli.cfg, "load", lambda: dict(cli.cfg.DEFAULTS))

    cli.cmd_connect(type("Args", (), {"pos_engine": "xray", "engine": None, "background": False, "iran": False, "russia": False})())

    scanner.assert_not_called()
