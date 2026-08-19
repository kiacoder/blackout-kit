from types import SimpleNamespace
from unittest.mock import patch

from blackoutkit import cli
from blackoutkit.config.manager import ProxyConfig, load_configs, parse_v2ray_uri, save_configs
from blackoutkit.engines.xray import XRayEngine


REALITY_URI = (
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com"
    "&fp=chrome&pbk=PUBLIC_KEY_PLACEHOLDER&sid=abcd&spx=%2F&type=tcp#Reality%20Node"
)


def _settings():
    return {
        "xray_fingerprint": "firefox",
        "xray_mux_enabled": False,
        "xray_socks_port": 10808,
        "xray_http_port": 10809,
    }


def test_parse_reality_uri_preserves_required_client_parameters():
    config = parse_v2ray_uri(REALITY_URI)

    assert config is not None
    assert config.protocol == "vless"
    assert config.is_reality() is True
    assert config.transport == "tcp"
    assert config.public_key == "PUBLIC_KEY_PLACEHOLDER"
    assert config.short_id == "abcd"
    assert config.spider_x == "/"
    assert config.flow == "xtls-rprx-vision"
    assert config.transport_label() == "REALITY"
    assert config.reality_validation_error() is None


def test_parse_reality_alias_parameters_and_grpc_service_name():
    config = parse_v2ray_uri(
        "vless://id@server.example:443?security=reality&sni=www.example.com"
        "&publicKey=key&shortId=1234&spiderX=%2Fassets&type=grpc&serviceName=grpc-service"
    )

    assert config is not None
    assert config.public_key == "key"
    assert config.short_id == "1234"
    assert config.spider_x == "/assets"
    assert config.transport == "grpc"
    assert config.service_name == "grpc-service"


def test_reality_uri_round_trips_without_rewriting(tmp_path):
    config_path = tmp_path / "configs.txt"

    config = parse_v2ray_uri(REALITY_URI)
    save_configs([config], config_path)

    assert config_path.read_text(encoding="utf-8") == REALITY_URI
    loaded = load_configs(config_path)
    assert len(loaded) == 1
    assert loaded[0].raw_uri == REALITY_URI


def test_reality_validation_reports_only_missing_requirements():
    config = ProxyConfig(protocol="vless", address="server.example", port=443, security="reality")

    assert config.reality_validation_error() == "REALITY config is missing the server public key (pbk)."


def test_config_views_redact_reality_credentials_and_endpoint():
    config = parse_v2ray_uri(REALITY_URI)

    cli.console.begin_capture()
    try:
        with patch("blackoutkit.cli.load_configs", return_value=[config]):
            cli.cmd_config(SimpleNamespace(config_command="list"))
    finally:
        rendered = cli.console.end_capture()

    for secret in (config.address, config.uuid, config.public_key, config.short_id):
        assert secret not in rendered
    assert "REALITY" in rendered


def test_reality_outbound_uses_reality_settings_without_tls_policy():
    config = parse_v2ray_uri(REALITY_URI)
    engine = XRayEngine(proxy_config=config, socks_port=19080, http_port=19081)

    with patch("blackoutkit.settings.load", return_value=_settings()), \
         patch("blackoutkit.cert_bypass.should_allow_insecure") as policy, \
         patch("blackoutkit.tools.resolve_doh", return_value=None):
        outbound = engine._build_outbound(config)

    stream = outbound["streamSettings"]
    user = outbound["settings"]["vnext"][0]["users"][0]
    assert stream["network"] == "tcp"
    assert stream["security"] == "reality"
    assert stream["realitySettings"] == {
        "show": False,
        "fingerprint": "chrome",
        "serverName": "www.microsoft.com",
        "publicKey": "PUBLIC_KEY_PLACEHOLDER",
        "shortId": "abcd",
        "spiderX": "/",
    }
    assert "tlsSettings" not in stream
    assert "wsSettings" not in stream
    assert user == {"id": "11111111-2222-3333-4444-555555555555", "encryption": "none", "flow": "xtls-rprx-vision"}
    policy.assert_not_called()


def test_reality_grpc_outbound_preserves_service_name():
    config = parse_v2ray_uri(
        "vless://id@server.example:443?security=reality&sni=www.example.com"
        "&pbk=key&sid=1234&type=grpc&serviceName=grpc-service"
    )
    engine = XRayEngine(proxy_config=config, socks_port=19080, http_port=19081)

    with patch("blackoutkit.settings.load", return_value=_settings()), \
         patch("blackoutkit.tools.resolve_doh", return_value=None):
        outbound = engine._build_outbound(config)

    assert outbound["streamSettings"]["network"] == "grpc"
    assert outbound["streamSettings"]["grpcSettings"] == {"serviceName": "grpc-service"}
    assert "tlsSettings" not in outbound["streamSettings"]


def test_xhttp_transport_parses_and_generates_correct_stream():
    config = parse_v2ray_uri(
        "vless://id@server.example:443?security=tls&sni=cdn.example&type=xhttp"
        "&path=%2Fxp&host=cdn.example&mode=packet-up"
    )
    assert config.transport == "xhttp"
    assert config.xhttp_mode == "packet-up"
    assert config.path == "/xp"

    engine = XRayEngine(proxy_config=config, socks_port=19080, http_port=19081)

    with patch("blackoutkit.settings.load", return_value=_settings()), \
         patch("blackoutkit.cert_bypass.should_allow_insecure", return_value=(True, "")), \
         patch("blackoutkit.tools.resolve_doh", return_value=None):
        outbound = engine._build_outbound(config)

    stream = outbound["streamSettings"]
    assert stream["network"] == "xhttp"
    assert stream["xhttpSettings"] == {
        "path": "/xp",
        "host": "cdn.example",
        "mode": "packet-up",
    }
    assert "wsSettings" not in stream
    assert "grpcSettings" not in stream


def test_splithttp_transport_normalizes_to_xhttp():
    config = parse_v2ray_uri(
        "vless://id@server.example:443?security=tls&sni=cdn.example&type=splithttp&path=%2Fsp"
    )
    assert config.transport == "xhttp"


def test_xhttp_reality_config_is_valid():
    config = parse_v2ray_uri(
        "vless://id@server.example:443?security=reality&sni=www.microsoft.com"
        "&pbk=KEY&sid=abcd&type=xhttp&mode=auto"
    )
    assert config.transport == "xhttp"
    assert config.is_reality()
    assert config.reality_validation_error() is None


def test_normal_tls_vless_keeps_certificate_policy_and_websocket_stream():
    config = parse_v2ray_uri(
        "vless://id@server.example:443?security=tls&sni=cdn.example&type=ws&path=%2Fws&host=cdn.example"
    )
    engine = XRayEngine(proxy_config=config, socks_port=19080, http_port=19081)

    with patch("blackoutkit.settings.load", return_value=_settings()), \
         patch("blackoutkit.cert_bypass.should_allow_insecure", return_value=(False, "")) as policy, \
         patch("blackoutkit.tools.resolve_doh", return_value=None):
        outbound = engine._build_outbound(config)

    stream = outbound["streamSettings"]
    assert stream["security"] == "tls"
    assert stream["tlsSettings"] == {"serverName": "cdn.example", "fingerprint": "chrome"}
    assert stream["wsSettings"]["path"] == "/ws"
    assert "realitySettings" not in stream
    policy.assert_called_once_with("server.example", 443, "speed")


def test_cert_probe_supports_python_tls_enum_aliases():
    from blackoutkit import cert_bypass as cb

    assert cb._TLS12 == cb.ssl.TLSVersion.TLSv1_2


def test_invalid_reality_config_fails_before_certificate_probe():
    config = ProxyConfig(protocol="vless", address="server.example", port=443, security="reality", sni="www.example.com")
    engine = XRayEngine(proxy_config=config, socks_port=19080, http_port=19081)

    with patch.object(engine, "check_port_free", return_value=True), \
         patch("blackoutkit.cert_bypass.check_host_cert") as cert_probe:
        assert engine.start() is False

    cert_probe.assert_not_called()
