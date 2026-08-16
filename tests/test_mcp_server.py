import json
from types import SimpleNamespace
from unittest.mock import patch

from blackoutkit import mcp_server as mcp


def test_connect_requires_explicit_engine():
    result = mcp.handle_tool_call("blackout_connect", {})

    assert result == "Error: an explicit supported engine is required"


def test_connect_rejects_legacy_iran_profile():
    result = mcp.handle_tool_call(
        "blackout_connect", {"engine": "xray", "iran": True}
    )

    assert result == "Error: MCP connect does not support the Iran profile"


def test_connect_reports_daemon_start_without_claiming_connection():
    with patch("blackoutkit.daemon.start", return_value=4242) as start:
        result = mcp.handle_tool_call("blackout_connect", {"engine": "xray"})

    start.assert_called_once_with("xray")
    assert "daemon started" in result
    assert "connected" not in result.lower()
    assert "system proxy set" not in result.lower()


def test_disconnect_cleans_only_blackout_managed_state(monkeypatch):
    monkeypatch.setattr(mcp, "_is_blackout_proxy", lambda _proxy: True)
    with patch("blackoutkit.daemon.stop", return_value=True), \
         patch("blackoutkit.settings.load", return_value={"auto_set_proxy": True, "kill_switch": True}), \
         patch("blackoutkit.proxy_manager.get_proxy_status", return_value={"enabled": True, "server": "127.0.0.1:10809"}), \
         patch("blackoutkit.proxy_manager.clear_system_proxy", return_value=True) as clear_proxy, \
         patch("blackoutkit.security.disable_kill_switch", return_value=True) as disable_kill_switch:
        result = mcp.handle_tool_call("blackout_disconnect", {})

    clear_proxy.assert_called_once()
    disable_kill_switch.assert_called_once()
    assert "daemon stopped" in result
    assert "Blackout-managed proxy cleared" in result
    assert "kill switch disabled" in result


def test_blackout_proxy_detection_supports_linux_proxy_url(monkeypatch):
    monkeypatch.setattr(mcp.cfg, "load", lambda: {"xray_http_port": 10809})

    assert mcp._is_blackout_proxy({"enabled": True, "server": "http://127.0.0.1:10809"})


def test_disconnect_preserves_external_proxy(monkeypatch):
    monkeypatch.setattr(mcp, "_is_blackout_proxy", lambda _proxy: False)
    with patch("blackoutkit.daemon.stop", return_value=True), \
         patch("blackoutkit.settings.load", return_value={"auto_set_proxy": True, "kill_switch": False}), \
         patch("blackoutkit.proxy_manager.get_proxy_status", return_value={"enabled": True, "server": "proxy.example:8080"}), \
         patch("blackoutkit.proxy_manager.clear_system_proxy") as clear_proxy:
        result = mcp.handle_tool_call("blackout_disconnect", {})

    clear_proxy.assert_not_called()
    assert "external proxy preserved" in result


def test_settings_list_masks_sensitive_values():
    with patch("blackoutkit.settings.load", return_value={
        "ikev2_password": "secret-password",
        "ikev2_psk": "secret-psk",
        "softether_password": "another-secret",
        "xray_fingerprint": "chrome",
    }):
        result = mcp.handle_tool_call("blackout_settings", {"action": "list"})

    settings = json.loads(result)
    assert settings["ikev2_password"] == "[hidden]"
    assert settings["ikev2_psk"] == "[hidden]"
    assert settings["softether_password"] == "[hidden]"
    assert settings["xray_fingerprint"] == "chrome"


def test_settings_get_masks_sensitive_value():
    with patch("blackoutkit.settings.get", return_value="secret-password"):
        result = mcp.handle_tool_call(
            "blackout_settings", {"action": "get", "key": "ikev2_password"}
        )

    assert json.loads(result) == {"ikev2_password": "[hidden]"}


def test_settings_set_coerces_typed_value():
    with patch("blackoutkit.settings.set_value") as set_value:
        result = mcp.handle_tool_call(
            "blackout_settings",
            {"action": "set", "key": "kill_switch", "value": "false"},
        )

    set_value.assert_called_once_with("kill_switch", False)
    assert result == "✓ Setting 'kill_switch' updated."


def test_settings_coerce_rejects_invalid_boolean():
    with patch("blackoutkit.settings.set_value") as set_value:
        result = mcp.handle_tool_call(
            "blackout_settings",
            {"action": "set", "key": "kill_switch", "value": "maybe"},
        )

    set_value.assert_not_called()
    assert "must be true or false" in result


def test_settings_rejects_windows_kill_switch_activation():
    with patch("sys.platform", "win32"), \
         patch("blackoutkit.settings.load", return_value=dict(mcp.cfg.DEFAULTS)), \
         patch("blackoutkit.settings.save") as save:
        result = mcp.handle_tool_call(
            "blackout_settings",
            {"action": "set", "key": "kill_switch", "value": "true"},
        )

    save.assert_not_called()
    assert "available only on Linux" in result


def test_settings_reset_uses_existing_reset():
    with patch("blackoutkit.settings.reset") as reset:
        result = mcp.handle_tool_call("blackout_settings", {"action": "reset"})

    reset.assert_called_once()
    assert result == "✓ All settings reset to defaults."


def test_security_mode_applies_full_preset():
    with patch("blackoutkit.security.apply_mode") as apply_mode:
        result = mcp.handle_tool_call(
            "blackout_security_mode", {"mode": "private"}
        )

    apply_mode.assert_called_once_with("private")
    assert result == "✓ Security mode applied: private"


def test_config_list_masks_endpoint_metadata():
    config = SimpleNamespace(
        protocol="vless",
        name="trusted-node",
        sni="server.example",
        transport_label=lambda: "REALITY",
    )
    with patch("blackoutkit.config.manager.load_configs", return_value=[config]):
        result = mcp.handle_tool_call("blackout_config", {"action": "list"})

    assert json.loads(result) == {
        "count": 1,
        "configs": [{"index": 1, "protocol": "vless", "transport": "REALITY", "name": "trusted-node"}],
    }
    assert "server.example" not in result


def test_config_add_does_not_echo_credentials():
    config = SimpleNamespace(protocol="vless", name="trusted-node")
    uri = "vless://secret-uuid@server.example:443?security=reality"
    with patch("blackoutkit.config.manager.add_config", return_value=config):
        result = mcp.handle_tool_call(
            "blackout_config", {"action": "add", "uri": uri}
        )

    assert result == "✓ Added VLESS config: trusted-node"
    assert "secret-uuid" not in result


def test_config_import_reports_added_and_total_counts():
    with patch("blackoutkit.config.manager.import_and_merge", return_value=(2, 5)):
        result = mcp.handle_tool_call(
            "blackout_config", {"action": "import", "url": "https://example.test/sub"}
        )

    assert result == "✓ Imported 2 configs. Total saved: 5."


def test_network_recovery_returns_actual_steps():
    steps = [{"name": "Clear proxy", "ok": True, "detail": "done"}]
    with patch("blackoutkit.tools.run_network_recovery", return_value=steps):
        result = mcp.handle_tool_call("blackout_net_tools", {"tool": "netfix"})

    assert json.loads(result) == steps


def test_network_ping_uses_existing_ping_helper():
    with patch("blackoutkit.tools.ping", return_value=[12.5]):
        result = mcp.handle_tool_call(
            "blackout_net_tools", {"tool": "ping", "arg": "example.com"}
        )

    assert result == "Ping to example.com: 12.5ms"


def test_network_hotspot_returns_actual_result():
    with patch("blackoutkit.tools.toggle_hotspot", return_value="Hotspot stopped"):
        result = mcp.handle_tool_call("blackout_net_tools", {"tool": "hotspot"})

    assert result == "Hotspot stopped"


def test_network_dns_flush_reports_failure():
    with patch("blackoutkit.tools.flush_dns", return_value=False):
        result = mcp.handle_tool_call("blackout_net_tools", {"tool": "dns-flush"})

    assert result == "✗ DNS cache flush failed"
