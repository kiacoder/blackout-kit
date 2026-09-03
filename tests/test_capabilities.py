from types import SimpleNamespace

from typer.testing import CliRunner
from blackoutkit.capabilities import (
    PUBLIC_ENGINE_NAMES,
    build_capability_matrix,
    get_capability,
)
from blackoutkit.demo import build_demo_report
from blackoutkit import typer_cli


runner = CliRunner()


def _raise_boundary(*_args, **_kwargs):
    raise AssertionError("demo crossed a prohibited boundary")



def test_capability_catalog_preserves_all_public_engine_targets():
    rows = build_capability_matrix(
        "win32",
        settings={},
        installed={},
        configs=[],
    )

    assert [row["name"] for row in rows] == list(PUBLIC_ENGINE_NAMES)
    assert len(rows) == 17
    assert rows[-1]["name"] == "legend"


def test_capability_matrix_keeps_unsupported_targets_visible():
    rows = build_capability_matrix(
        "darwin",
        settings={},
        installed={},
        configs=[],
    )

    assert len(rows) == 17
    assert all(row["state"] == "unsupported" for row in rows)
    assert all("unsupported on darwin" in row["blockers"] for row in rows)


def test_capability_matrix_reports_actual_awg_and_runtime_blockers():
    rows = build_capability_matrix(
        "win32",
        settings={},
        installed={},
        configs=[],
    )
    awg = next(row for row in rows if row["name"] == "awg")
    tun = next(row for row in rows if row["name"] == "tun")

    assert "awg_config_file" in awg["required_settings"]
    assert "awg_config_file not configured" in awg["blockers"]
    assert tun["runtime_requirements"] == ["sni-spoofing"]


def test_capability_serialization_does_not_include_runtime_secrets_or_paths():
    row = build_capability_matrix(
        "win32",
        settings={"ikev2_password": "secret", "wg_config_file": "C:/secret.conf"},
        installed={},
        configs=[SimpleNamespace(protocol="vless", raw_uri="vless://secret@example.com:443")],
    )[0]

    text = str(row)
    assert "secret" not in text
    assert "C:/secret.conf" not in text
    assert "vless://" not in text


def test_demo_is_simulation_only_and_accepts_local_fixtures():
    report = build_demo_report(
        platform="win32",
        settings={},
        installed={},
        configs=[],
    )

    assert report["mode"] == "demo"
    assert report["simulation_only"] is True
    assert report["network_actions"] == []
    assert report["system_mutations"] == []
    assert report["process_actions"] == []
    assert len(report["capabilities"]) == 17


def test_capability_lookup_exposes_composite_legend():
    legend = get_capability("legend")

    assert legend is not None
    assert legend.composite is True
    assert "tor" in legend.runtime_for("win32")


def test_demo_does_not_cross_runtime_or_network_boundaries(monkeypatch):
    from blackoutkit import daemon, downloader, proxy_manager
    from blackoutkit import settings as cfg
    from blackoutkit import tools
    from blackoutkit.scanner import ip_scanner, proxy_tester

    for module, name in (
        (downloader, "download_binary"),
        (cfg, "save"),
        (cfg, "set_value"),
        (daemon, "get_pid"),
        (daemon, "get_state"),
        (ip_scanner, "generate_cloudflare_ips"),
        (proxy_tester, "test_tcp_port"),
        (proxy_manager, "set_system_proxy"),
        (proxy_manager, "clear_system_proxy"),
        (proxy_manager, "cleanup_owned_system_proxy"),
        (tools, "run_network_recovery"),
    ):
        monkeypatch.setattr(module, name, _raise_boundary, raising=False)
    monkeypatch.setattr("urllib.request.urlopen", _raise_boundary)
    monkeypatch.setattr("socket.create_connection", _raise_boundary)

    report = build_demo_report(
        platform="win32",
        settings={},
        installed={},
        configs=[],
    )

    result = runner.invoke(typer_cli.app, ["--json", "demo"])

    assert report["simulation_only"] is True
    assert result.exit_code == 0, result.output
    assert result.output.count('"mode":"demo"') == 1
    assert "demo crossed a prohibited boundary" not in result.output


def test_demo_human_output_is_simulation_only(monkeypatch):
    monkeypatch.setattr(typer_cli, "is_interactive", lambda: False)
    result = runner.invoke(typer_cli.app, ["demo"])
    assert result.exit_code == 0, result.output
    assert "SIMULATION ONLY" in result.output
    assert "starts no engines" in result.output
    assert "contacts no remote hosts" in result.output
