"""Regression tests for the third audit round (CLI repo).

Each test pins one finding so the behaviour cannot quietly regress.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest


# ── BK-024: the URI parser decodes exactly once ────────────────────────────
def test_uri_query_values_are_decoded_once():
    from blackoutkit.config.manager import parse_v2ray_uri

    config = parse_v2ray_uri(
        "vless://11111111-1111-1111-1111-111111111111@a.com:443"
        "?type=ws&path=%2Fa%2Fb&security=none#x"
    )
    # %2F is a literal slash in the value the user wrote.
    assert config.path == "/a/b"

    # A double-encoded percent must stay encoded: unquoting twice turned
    # %252F into a real slash and corrupted the path.
    again = parse_v2ray_uri(
        "vless://11111111-1111-1111-1111-111111111111@a.com:443"
        "?type=ws&path=%252Fa%252Fb&security=none#x"
    )
    assert again.path == "%2Fa%2Fb"


# ── BK-011: the command browser returns the key, not item.key ──────────────
def test_command_browser_returns_the_key(monkeypatch):
    from blackoutkit import cli_navigator

    nav = cli_navigator.CLINavigator()
    nav.register_command("status", "Show status", "core")
    # run_menu returns the selected item's key (a str), not the MenuItem.
    monkeypatch.setattr(cli_navigator, "run_menu", lambda *a, **k: "status")
    assert nav.show_command_browser() == "status"


# ── BK-026: probe slots are per-instance, and released once ────────────────
def test_probe_releases_the_semaphore_it_acquired(monkeypatch):
    import threading

    from blackoutkit.scanner import proxy_tester

    class Response:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def iter_bytes(self):
            return iter([b"x"])

    class Client:
        def stream(self, *_a, **_k):
            return Response()

    # Replace the global with a fresh semaphore *while a probe is in flight*:
    # the old code released the module global by name and over-released this.
    monkeypatch.setattr(proxy_tester, "_proxy_probe_slots", threading.BoundedSemaphore(4))
    assert proxy_tester._bounded_proxy_request(Client(), "http://x", 1.0) is not None
    proxy_tester.join_probe_threads()
    assert not proxy_tester._proxy_probe_threads


# ── BK-077: blocklists in all three real formats ───────────────────────────
@pytest.mark.parametrize(
    "content,expected",
    [
        ("0.0.0.0 ads.example.com tracker.example.org", {"ads.example.com", "tracker.example.org"}),
        ("phish.example.net\nevil.example.com", {"phish.example.net", "evil.example.com"}),
        ("||ads.example.com^\n||x.example.org^$third-party", {"ads.example.com", "x.example.org"}),
    ],
)
def test_blocklist_formats(content, expected):
    from blackoutkit.tools.adblock import _parse_blocklist_rules

    assert _parse_blocklist_rules(content) == expected


def test_blocklist_skips_comments_and_exceptions():
    from blackoutkit.tools.adblock import _parse_blocklist_rules

    content = "! header\n# hosts comment\n@@allow.example.com\n##.banner\n127.0.0.1 localhost"
    assert _parse_blocklist_rules(content) == set()


# ── BK-073/074: torrents never run outside the tunnel ──────────────────────
def test_torrent_session_refuses_without_a_tunnel(monkeypatch):
    from blackoutkit.tools import torrent_manager

    lt = pytest.importorskip("libtorrent", reason="libtorrent not installed")

    manager = torrent_manager.TorrentDownloadManager()
    monkeypatch.setattr(manager, "session", None, raising=False)

    # Nothing listens on this port, so the session must refuse to start
    # rather than announce over the raw uplink.
    import socket

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    from blackoutkit import settings

    original = settings.load
    monkeypatch.setattr(settings, "load", lambda: {**original(), "xray_socks_port": port})
    with pytest.raises(RuntimeError, match="nothing is listening"):
        manager._init_session()


# ── BK-056: the manifest lives outside bins/ ───────────────────────────────
def test_manifest_is_stored_outside_bins_dir():
    from blackoutkit import BINS_DIR, bin_manifest

    assert not Path(bin_manifest.MANIFEST_FILE).is_relative_to(Path(BINS_DIR))


# ── BK-076: the policy is actually enforced ────────────────────────────────
def test_policy_denies_a_viewer_connect(monkeypatch, tmp_path):
    from blackoutkit.enterprise import enforcement
    from blackoutkit.enterprise.policy import Policy, PolicyStore
    from blackoutkit.enterprise.rbac import AccessDenied

    store = PolicyStore(tmp_path / "policy.json")
    store.save(Policy(principals={"alice": "viewer", "bob": "admin"}, default_role="viewer"))
    monkeypatch.setenv(enforcement.ENV_PRINCIPAL, "alice")

    with pytest.raises(AccessDenied):
        enforcement.check_command("connect", store)
    # Reading status is still fine.
    enforcement.check_command("status", store)

    monkeypatch.setenv(enforcement.ENV_PRINCIPAL, "bob")
    enforcement.check_command("connect", store)


def test_no_policy_means_no_restriction(tmp_path):
    from blackoutkit.enterprise import enforcement
    from blackoutkit.enterprise.policy import PolicyStore

    store = PolicyStore(tmp_path / "absent.json")
    assert enforcement.describe(store).active is False
    enforcement.check_command("connect", store)


def test_unreadable_policy_fails_closed(tmp_path):
    from blackoutkit.enterprise import enforcement
    from blackoutkit.enterprise.policy import PolicyStore
    from blackoutkit.enterprise.rbac import AccessDenied

    path = tmp_path / "policy.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(AccessDenied):
        enforcement.check_command("connect", PolicyStore(path))


def test_cli_exits_3_when_the_policy_denies(monkeypatch, tmp_path):
    from blackoutkit.enterprise.policy import Policy, PolicyStore
    from blackoutkit.typer_cli import app
    from typer.testing import CliRunner

    store = PolicyStore(tmp_path / "policy.json")
    store.save(Policy(principals={"alice": "viewer"}, default_role="viewer"))
    monkeypatch.setenv("BLACKOUT_POLICY_FILE", str(tmp_path / "policy.json"))
    monkeypatch.setenv("BLACKOUT_PRINCIPAL", "alice")

    result = CliRunner().invoke(app, ["connect"])
    assert result.exit_code == 3
    assert "lacks permission" in result.output


# ── BK-012: the dashboard page has no external script ──────────────────────
def test_web_dashboard_has_no_cdn_dependency():
    import io

    source = io.open(
        Path(__file__).resolve().parents[1] / "blackoutkit" / "tools.py",
        encoding="utf-8",
    ).read()
    assert "cdn.jsdelivr.net/npm/chart.js" not in source


# ── BK-008/009: the dashboard reads what the daemon writes ─────────────────
def test_dashboard_derives_state_from_the_daemon_schema(monkeypatch):
    from blackoutkit.dashboard import LiveDashboard

    monkeypatch.setattr(
        "blackoutkit.dashboard.daemon.stream_daemon_ipc_metrics",
        lambda: {"pid": 1, "active": True, "engine": "xray", "uptime": 5.0,
                 "started_at": 1.0, "memory_mb": 12.5},
    )
    monkeypatch.setattr(
        "blackoutkit.dashboard.daemon.get_state",
        lambda: {"status": "connected", "io_bytes": [10, 2], "restarts": 0},
    )

    status = LiveDashboard().get_daemon_status()
    assert status["connected"] is True
    assert status["status"] == "connected"
    assert status["memory_mb"] == 12.5
    assert status["active_connections"] is None  # not tracked, not "0"
