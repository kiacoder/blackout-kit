from types import SimpleNamespace

from blackoutkit import cli


def test_status_snapshot_reads_only_local_state(monkeypatch):
    calls = []
    monkeypatch.setattr(cli.cfg, "load", lambda: {"security_mode": "private", "terminal_theme": "dark"})
    monkeypatch.setattr(cli.daemon, "get_pid", lambda: 4242)
    monkeypatch.setattr(cli.daemon, "get_state", lambda: {"engine": "xray", "status": "reconnecting", "next_retry_delay": 4})
    monkeypatch.setattr(cli, "get_proxy_status", lambda: {"enabled": True, "server": "127.0.0.1:10809"})
    monkeypatch.setattr(cli.cfg, "get_engine_proxy_details", lambda *_args: ("127.0.0.1", 10809))
    monkeypatch.setattr(cli, "test_tcp_port", lambda host, port: calls.append((host, port)) or 12.0)
    monkeypatch.setattr(cli.sec, "get_stability_score", lambda *_args: {"avg_ms": 55, "loss_pct": 0, "trend": "stable"})

    snapshot = cli._status_snapshot()

    assert snapshot["active_engine"] == "xray"
    assert snapshot["http_open"] is True
    assert snapshot["socks_open"] is True
    assert calls == [("127.0.0.1", 10809), ("127.0.0.1", 10808)]


def test_status_snapshot_does_not_run_external_connectivity_checks(monkeypatch):
    monkeypatch.setattr(cli.cfg, "load", lambda: {})
    monkeypatch.setattr(cli.daemon, "get_pid", lambda: None)
    monkeypatch.setattr(cli.daemon, "get_state", lambda: None)
    monkeypatch.setattr(cli, "get_proxy_status", lambda: {"enabled": False, "server": ""})
    monkeypatch.setattr(cli, "test_direct", lambda: (_ for _ in ()).throw(AssertionError("must not run")))

    snapshot = cli._status_snapshot()

    assert snapshot["pid"] is None
    assert snapshot["http_open"] is None


def test_cmd_status_one_shot_renders_panel(monkeypatch):
    monkeypatch.setattr(cli, "_status_snapshot", lambda: {
        "state": None,
        "pid": None,
        "proxy": {"enabled": False, "server": ""},
        "active_engine": "unknown",
        "http_open": None,
        "socks_open": None,
        "stability": None,
        "settings": {"security_mode": "speed", "terminal_theme": "dark"},
    })
    printed = []
    monkeypatch.setattr(cli.console, "print", lambda value: printed.append(value))

    cli.cmd_status(SimpleNamespace(watch=False, interval=2.0))

    assert len(printed) == 1
