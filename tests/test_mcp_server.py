import io
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from blackoutkit import mcp_server as mcp
from blackoutkit.vault import SECRET_KEYS

FAKE_SECRET = "fixture-mcp-secret-value"  # test fixture, not a credential


@pytest.fixture(autouse=True)
def _handler_tests_bypass_gate(monkeypatch):
    """Handler-behaviour tests call privileged tools directly. The authorization
    gate is covered by TestMcpAuthorization, which re-enables it explicitly."""
    monkeypatch.setattr(mcp, "_MCP_AUTH_ENABLED", False)


def _masked_settings_fixture() -> dict:
    """Fixture derives field names from SECRET_KEYS so this file never
    contains a credential-shaped literal; all values are fake and the tests
    assert masking behavior, not content."""
    values = {name: f"fixture-value-{index}" for index, name in enumerate(SECRET_KEYS)}
    values["xray_fingerprint"] = "chrome"
    return values


def test_ready_returns_local_structured_checks():
    with patch("blackoutkit.readiness.as_dicts", return_value=[{"name": "Local", "ok": True, "blocking": True, "detail": "ok"}]):
        result = mcp.handle_tool_call("blackout_ready", {"engine": "xray"})

    assert json.loads(result) == {
        "engine": "xray",
        "ready": True,
        "checks": [{"name": "Local", "ok": True, "blocking": True, "detail": "ok"}],
    }


def test_connect_requires_explicit_engine():
    result = mcp.handle_tool_call("blackout_connect", {})

    assert result == "Error: an explicit supported engine is required"


def test_connect_rejects_legacy_iran_profile():
    result = mcp.handle_tool_call(
        "blackout_connect", {"engine": "xray", "iran": True}
    )

    assert result == "Error: MCP connect does not support the Iran profile"


def test_connect_reports_daemon_start_without_claiming_connection():
    with patch("blackoutkit.readiness.evaluate", return_value=[]), \
         patch("blackoutkit.daemon.start", return_value=4242) as start:
        result = mcp.handle_tool_call("blackout_connect", {"engine": "xray"})

    start.assert_called_once_with("xray")
    assert "daemon started" in result
    assert "connected" not in result.lower()
    assert "system proxy set" not in result.lower()


def test_disconnect_cleans_only_blackout_managed_state(monkeypatch):
    with patch("blackoutkit.daemon.stop", return_value=True), \
         patch("blackoutkit.settings.load", return_value={"auto_set_proxy": True, "kill_switch": True}), \
         patch("blackoutkit.proxy_manager.get_proxy_status", return_value={"enabled": True, "server": "127.0.0.1:10809"}), \
         patch("blackoutkit.proxy_manager.cleanup_owned_system_proxy", return_value=True) as cleanup_proxy, \
         patch("blackoutkit.security.disable_kill_switch", return_value=True) as disable_kill_switch:
        result = mcp.handle_tool_call("blackout_disconnect", {})

    cleanup_proxy.assert_called_once()
    disable_kill_switch.assert_called_once()
    assert "daemon stopped" in result
    assert "Blackout-managed proxy restored" in result
    assert "kill switch disabled" in result


def test_mcp_engine_schemas_include_awg():
    manifest = {
        tool["name"]: tool
        for tool in mcp.TOOLS_MANIFEST
    }

    for tool_name in ("blackout_ready", "blackout_connect"):
        assert "awg" in manifest[tool_name]["inputSchema"]["properties"]["engine"]["enum"]
    assert "awg" in mcp._MCP_ENGINES


def test_mcp_ready_returns_awg_check_payload(monkeypatch):
    from blackoutkit import readiness

    checks = [{
        "name": "Capability limitation",
        "ok": False,
        "blocking": True,
        "detail": "AmneziaWG outbound is unavailable in the bundled sing-box runtime",
    }]
    monkeypatch.setattr(readiness, "as_dicts", lambda _engine: checks)

    result = mcp.handle_tool_call("blackout_ready", {"engine": "awg"})

    assert json.loads(result) == {
        "engine": "awg",
        "ready": False,
        "checks": checks,
    }


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
    with patch("blackoutkit.settings.load", return_value=_masked_settings_fixture()):
        result = mcp.handle_tool_call("blackout_settings", {"action": "list"})

    settings = json.loads(result)
    fixture = _masked_settings_fixture()
    for name in fixture:
        if name == "xray_fingerprint":
            assert settings[name] == "chrome"
        else:
            assert settings[name] == "[hidden]"


def test_settings_get_masks_sensitive_value():
    field_name = SECRET_KEYS[0]
    with patch("blackoutkit.settings.get", return_value="fixture-value-0"):
        result = mcp.handle_tool_call(
            "blackout_settings", {"action": "get", "key": field_name}
        )

    assert json.loads(result) == {field_name: "[hidden]"}


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
    with patch("blackoutkit.tools.run_network_recovery", return_value=steps) as recovery:
        result = mcp.handle_tool_call("blackout_net_tools", {"tool": "netfix"})

    recovery.assert_called_once_with(audit_source="mcp")
    assert json.loads(result) == steps


def test_network_recovery_preview_is_read_only():
    steps = [{"name": "Clear proxy", "ok": True, "detail": "would clear"}]
    with patch("blackoutkit.tools.plan_network_recovery", return_value=steps) as preview, \
         patch("blackoutkit.tools.run_network_recovery") as recovery:
        result = mcp.handle_tool_call("blackout_net_tools", {"tool": "netfix-preview"})

    preview.assert_called_once_with()
    recovery.assert_not_called()
    assert json.loads(result) == steps


def test_network_recovery_history_is_read_only():
    with patch("blackoutkit.recovery_audit.history", return_value=[{"source": "cli"}]):
        result = mcp.handle_tool_call("blackout_net_tools", {"tool": "netfix-history"})

    assert json.loads(result) == [{"source": "cli"}]


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


# Privileged calls covering every category the audit named: DNS changes, hotspot
# control, network recovery, TUN/engine starts, plus the other state-changing tools.
PRIVILEGED_CASES = [
    ("dns-set", "blackout_net_tools", {"tool": "dns-set", "arg": "1.1.1.1"},
     "blackoutkit.tools.set_dns", True),
    ("dns-flush", "blackout_net_tools", {"tool": "dns-flush"},
     "blackoutkit.tools.flush_dns", True),
    ("hotspot", "blackout_net_tools", {"tool": "hotspot", "arg": "on"},
     "blackoutkit.tools.toggle_hotspot", "Hotspot on"),
    ("netfix", "blackout_net_tools", {"tool": "netfix"},
     "blackoutkit.tools.run_network_recovery", []),
    ("tun-connect", "blackout_connect", {"engine": "tun"},
     "blackoutkit.daemon.start", 4242),
    ("emergency", "blackout_emergency", {},
     "blackoutkit.daemon.start", 4243),
    ("settings-set", "blackout_settings", {"action": "set", "key": "kill_switch", "value": "false"},
     "blackoutkit.settings.set_value", None),
    ("config-remove", "blackout_config", {"action": "remove", "index": 1},
     "blackoutkit.config.manager.remove_config", None),
    ("split-tunnel-add", "blackout_split_tunnel", {"action": "add", "target": "10.0.0.0/8"},
     "blackoutkit.split_tunnel.add_direct_route", None),
    ("security-mode", "blackout_security_mode", {"mode": "private"},
     "blackoutkit.security.apply_mode", None),
    ("disconnect", "blackout_disconnect", {},
     "blackoutkit.daemon.stop", False),
]

READ_ONLY_CASES = [
    ("ping", "blackout_net_tools", {"tool": "ping", "arg": "example.com"},
     "blackoutkit.tools.ping", [12.5]),
    ("dns-bench", "blackout_net_tools", {"tool": "dns-bench"},
     "blackoutkit.tools.benchmark_dns", {"best": "1.1.1.1"}),
    ("netfix-preview", "blackout_net_tools", {"tool": "netfix-preview"},
     "blackoutkit.tools.plan_network_recovery", []),
    ("netfix-history", "blackout_net_tools", {"tool": "netfix-history"},
     "blackoutkit.recovery_audit.history", []),
    ("settings-list", "blackout_settings", {"action": "list"},
     "blackoutkit.settings.load", {}),
    ("settings-get", "blackout_settings", {"action": "get", "key": "kill_switch"},
     "blackoutkit.settings.get", False),
    ("config-list", "blackout_config", {"action": "list"},
     "blackoutkit.config.manager.load_configs", []),
    ("split-tunnel-list", "blackout_split_tunnel", {"action": "list"},
     "blackoutkit.split_tunnel.load_split_rules", []),
    ("security-mode-get", "blackout_security_mode", {},
     "blackoutkit.security.get_current_mode", "speed"),
]


class TestMcpAuthorization:
    @pytest.fixture(autouse=True)
    def _gate_enabled(self, monkeypatch):
        monkeypatch.setattr(mcp, "_MCP_AUTH_ENABLED", True)
        monkeypatch.delenv("BLACKOUT_MCP_TOKEN", raising=False)
        monkeypatch.delenv("BLACKOUT_MCP_SECRET", raising=False)

    # ── _check_mcp_authorization: valid, invalid, and missing tokens ──

    def test_valid_token_is_accepted(self, monkeypatch):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        assert mcp._check_mcp_authorization(FAKE_SECRET) is True

    def test_secret_env_var_is_accepted_as_fallback(self, monkeypatch):
        monkeypatch.setenv("BLACKOUT_MCP_SECRET", FAKE_SECRET)
        assert mcp._check_mcp_authorization(FAKE_SECRET) is True

    def test_token_env_var_takes_precedence_over_secret(self, monkeypatch):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", "primary-value")
        monkeypatch.setenv("BLACKOUT_MCP_SECRET", "secondary-value")
        assert mcp._check_mcp_authorization("primary-value") is True
        assert mcp._check_mcp_authorization("secondary-value") is False

    @pytest.mark.parametrize("presented", [
        "wrong-value",
        FAKE_SECRET[:-1],   # prefix of the secret
        FAKE_SECRET + "x",  # secret with a suffix
        FAKE_SECRET.upper(),
        " " + FAKE_SECRET,
    ])
    def test_invalid_token_is_rejected(self, monkeypatch, presented):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        assert mcp._check_mcp_authorization(presented) is False

    @pytest.mark.parametrize("presented", [None, "", 0, ["fixture"], {"token": FAKE_SECRET}])
    def test_missing_or_non_string_token_is_rejected(self, monkeypatch, presented):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        assert mcp._check_mcp_authorization(presented) is False

    def test_absent_token_argument_is_rejected(self, monkeypatch):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        assert mcp._check_mcp_authorization() is False

    @pytest.mark.parametrize("presented", [FAKE_SECRET, "", None])
    def test_missing_server_secret_fails_closed(self, monkeypatch, presented):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", "")
        monkeypatch.setenv("BLACKOUT_MCP_SECRET", "")
        assert mcp._check_mcp_authorization(presented) is False

    def test_non_ascii_and_surrogate_tokens_do_not_raise(self, monkeypatch):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        assert mcp._check_mcp_authorization("pässwörd-☃") is False
        assert mcp._check_mcp_authorization("\ud800") is False

    def test_comparison_uses_hmac_compare_digest(self, monkeypatch):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        with patch.object(mcp.hmac, "compare_digest", wraps=mcp.hmac.compare_digest) as compare:
            assert mcp._check_mcp_authorization(FAKE_SECRET) is True
        compare.assert_called_once_with(FAKE_SECRET.encode("utf-8"), FAKE_SECRET.encode("utf-8"))

    def test_disabled_gate_allows_calls_without_token(self, monkeypatch):
        monkeypatch.setattr(mcp, "_MCP_AUTH_ENABLED", False)
        assert mcp._check_mcp_authorization() is True

    # ── handle_tool_call: privileged operations ──

    @pytest.mark.parametrize("label, tool, args, target, returned", PRIVILEGED_CASES,
                             ids=[case[0] for case in PRIVILEGED_CASES])
    def test_privileged_operation_denied_without_valid_token(self, monkeypatch, label, tool, args, target, returned):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        with patch(target, return_value=returned) as handler, \
             patch("blackoutkit.readiness.evaluate", return_value=[]):
            missing = mcp.handle_tool_call(tool, dict(args))
            invalid = mcp.handle_tool_call(tool, {**args, "auth_token": "wrong-value"})
        handler.assert_not_called()
        assert missing.startswith("Error: Access denied.")
        assert invalid.startswith("Error: Access denied.")
        assert "wrong-value" not in invalid

    @pytest.mark.parametrize("label, tool, args, target, returned", PRIVILEGED_CASES,
                             ids=[case[0] for case in PRIVILEGED_CASES])
    def test_privileged_operation_runs_with_valid_token(self, monkeypatch, label, tool, args, target, returned):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        with patch(target, return_value=returned) as handler, \
             patch("blackoutkit.readiness.evaluate", return_value=[]):
            result = mcp.handle_tool_call(tool, {**args, "auth_token": FAKE_SECRET})
        handler.assert_called_once()
        assert not result.startswith("Error: Access denied")

    def test_privileged_operation_fails_closed_when_server_has_no_secret(self, monkeypatch):
        with patch("blackoutkit.tools.toggle_hotspot") as hotspot:
            result = mcp.handle_tool_call("blackout_net_tools", {"tool": "hotspot", "auth_token": FAKE_SECRET})
        hotspot.assert_not_called()
        assert result.startswith("Error: Access denied.")
        assert "BLACKOUT_MCP_TOKEN" in result

    @pytest.mark.parametrize("label, tool, args, target, returned", READ_ONLY_CASES,
                             ids=[case[0] for case in READ_ONLY_CASES])
    def test_read_only_operation_needs_no_token(self, monkeypatch, label, tool, args, target, returned):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        with patch(target, return_value=returned) as handler:
            result = mcp.handle_tool_call(tool, dict(args))
        handler.assert_called_once()
        assert not result.startswith("Error: Access denied")

    def test_malformed_arguments_do_not_raise(self, monkeypatch):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        assert mcp.handle_tool_call("blackout_connect", None).startswith("Error: Access denied.")
        assert mcp.handle_tool_call(["blackout_connect"], {}).startswith("Unknown tool")

    def test_manifest_advertises_auth_token_only_on_privileged_tools(self):
        manifest = {tool["name"]: tool for tool in mcp.TOOLS_MANIFEST}
        for name in mcp._PRIVILEGED_TOOLS:
            assert manifest[name]["inputSchema"]["properties"]["auth_token"]["type"] == "string"
        assert "auth_token" not in manifest["blackout_snapshot"]["inputSchema"]["properties"]

    @pytest.mark.parametrize("arguments, expect_hotspot_call", [
        ({"tool": "hotspot"}, False),
        ({"tool": "hotspot", "auth_token": "wrong-value"}, False),
        ({"tool": "hotspot", "auth_token": FAKE_SECRET}, True),
    ])
    def test_stdio_tools_call_enforces_token(self, monkeypatch, arguments, expect_hotspot_call):
        monkeypatch.setenv("BLACKOUT_MCP_TOKEN", FAKE_SECRET)
        request = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "blackout_net_tools", "arguments": arguments}}
        monkeypatch.setattr(mcp, "real_stdin", io.StringIO(json.dumps(request) + "\n"))
        stdout = io.StringIO()
        monkeypatch.setattr(mcp, "real_stdout", stdout)
        with patch("blackoutkit.tools.toggle_hotspot", return_value="Hotspot on") as hotspot:
            mcp.run_mcp_server()
        response = json.loads(stdout.getvalue())
        assert response["id"] == 7
        text = response["result"]["content"][0]["text"]
        assert hotspot.called is expect_hotspot_call
        assert text.startswith("Error: Access denied.") is (not expect_hotspot_call)
