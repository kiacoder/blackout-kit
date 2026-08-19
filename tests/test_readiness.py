from unittest.mock import MagicMock

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
