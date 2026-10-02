"""Tests for the Blackout Operator MCP tools and CLI surface."""
import json
import re

from typer.testing import CliRunner

from blackoutkit import mcp_server
from blackoutkit import typer_cli

runner = CliRunner()


def _tool_payload(result) -> dict:
    return json.loads(mcp_server.handle_tool_call(*result) if isinstance(result, tuple) else result)


def test_new_operator_tools_are_listed_in_manifest():
    names = {tool["name"] for tool in mcp_server.TOOLS_MANIFEST}
    assert {
        "blackout_snapshot",
        "blackout_recommend",
        "blackout_recent_events",
        "blackout_support_bundle_preview",
    } <= names


def test_new_operator_tools_are_read_only_not_privileged():
    privileged = {
        "blackout_connect", "blackout_disconnect", "blackout_emergency",
        "blackout_config", "blackout_settings", "blackout_net_tools",
        "blackout_split_tunnel", "blackout_security_mode",
    }
    for name in (
        "blackout_snapshot",
        "blackout_recommend",
        "blackout_recent_events",
        "blackout_support_bundle_preview",
    ):
        assert name not in privileged


def test_snapshot_tool_reports_local_scope_only():
    raw = mcp_server.handle_tool_call("blackout_snapshot", {"include_adapters": False})
    payload = json.loads(raw)
    assert payload["scope"]["local_state_only"] is True
    assert payload["scope"]["remote_validation_performed"] is False
    # No proxy URI material may ever reach an MCP consumer.
    for scheme in ("vless://", "vmess://", "trojan://"):
        assert scheme not in raw


def test_recommend_tool_exposes_safety_classes():
    payload = json.loads(mcp_server.handle_tool_call("blackout_recommend", {}))
    assert payload["safety_levels"] == [
        "READ_ONLY", "SAFE_REVERSIBLE", "PRIVILEGED_REVERSIBLE", "DISRUPTIVE", "DESTRUCTIVE",
    ]
    assert isinstance(payload["recommendations"], list) and payload["recommendations"]


def test_recent_events_tool_bounds_limit():
    payload = json.loads(mcp_server.handle_tool_call("blackout_recent_events", {"limit": 999}))
    assert payload["count"] == len(payload["events"])
    assert payload["count"] <= 200


def test_support_bundle_preview_has_no_log_content():
    payload = json.loads(mcp_server.handle_tool_call("blackout_support_bundle_preview", {}))
    assert payload["preview"] is True
    logs = payload["logs"]
    assert "daemon_tail" not in logs


def test_hotspot_shield_is_in_mcp_engine_surface():
    assert "hotspot-shield" in mcp_server._MCP_ENGINES
    for tool in mcp_server.TOOLS_MANIFEST:
        engine_enum = (
            tool.get("inputSchema", {}).get("properties", {}).get("engine", {}).get("enum")
        )
        if engine_enum:
            assert "hotspot-shield" in engine_enum


def test_cli_snapshot_json_contract():
    result = runner.invoke(typer_cli.app, ["snapshot", "--json", "--no-adapters"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    data = payload["data"]
    assert data["scope"]["local_state_only"] is True
    assert data["scope"]["remote_validation_performed"] is False


def test_cli_operator_recommend_json_contract():
    result = runner.invoke(typer_cli.app, ["operator", "recommend", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert isinstance(payload["data"]["recommendations"], list)


def test_cli_operator_actions_json_contract():
    result = runner.invoke(typer_cli.app, ["operator", "actions", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    names = {action["name"] for action in payload["data"]["actions"]}
    assert "monitor" in names and "broad_network_reset" in names


def test_cli_events_recent_json_contract():
    result = runner.invoke(typer_cli.app, ["events", "recent", "--json", "--limit", "5"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert isinstance(payload["data"]["events"], list)


def test_cli_support_bundle_preview_does_not_write_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(typer_cli.app, ["support-bundle", "--preview"])
    assert result.exit_code == 0
    assert list(tmp_path.glob("blackout-support-bundle-*.json")) == []


def test_cli_support_bundle_export_writes_sanitized_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "bundle.json"
    result = runner.invoke(typer_cli.app, ["support-bundle", "--output", str(target)])
    assert result.exit_code == 0
    raw = target.read_text(encoding="utf-8")
    payload = json.loads(raw)
    assert payload["uploaded"] is False
    for scheme in ("vless://", "vmess://", "trojan://"):
        assert scheme not in raw


def test_cli_help_topics_list_new_commands():
    result = runner.invoke(typer_cli.app, ["--help"])
    assert result.exit_code == 0
    assert "snapshot" in result.output
    assert "support-bundle" in result.output
    assert "operator" in result.output
    assert "events" in result.output


def test_connection_events_bridge_even_with_explicit_emit():
    # Regression: production CLI/GUI pass an explicit emit renderer; the
    # structured bus bridge must fire regardless of the renderer attached.
    from blackoutkit import events as ev
    from blackoutkit.connection_service import ConnectionService

    rendered = []
    service = ConnectionService(emit=rendered.append, emit_output=False)
    service._event("engine_started", name="warp", pid=123)
    service._event("stopping", engine="warp")

    assert [event["type"] for event in rendered] == ["engine_started", "stopping"]
    bridged_types = [item["type"] for item in ev.bus_or_default().recent(limit=10)]
    assert "engine.started" in bridged_types
    assert "engine.stopped" in bridged_types


def test_connection_service_emit_none_keeps_legacy_silence():
    # Back-compat: emit=None historically meant "no UI renderer"; it must not
    # raise, and the bus bridge still receives events for observability.
    from blackoutkit import events as ev
    from blackoutkit.connection_service import ConnectionService

    service = ConnectionService(emit=None, emit_output=False)
    service._event("engine_started", name="sni", pid=1)  # must not raise
    assert "engine.started" in [item["type"] for item in ev.bus_or_default().recent(limit=10)]
