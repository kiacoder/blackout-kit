from unittest.mock import patch
from blackoutkit.engines.sni import SNIEngine
from blackoutkit import settings
from blackoutkit.config.manager import ProxyConfig
from blackoutkit.engines.xray import XRayEngine


def _generate_xray_config_for_proxy_mode(mode):
    values = dict(settings.DEFAULTS)
    values["country"] = ""
    if mode is None:
        values.pop("xray_system_proxy_mode")
    else:
        values["xray_system_proxy_mode"] = mode

    with (
        patch("blackoutkit.engines.xray.cfg.load", return_value=values),
        patch("blackoutkit.tools.resolve_doh", return_value=None),
    ):
        engine = XRayEngine(
            proxy_config=ProxyConfig(protocol="vless", address="example.com", port=443)
        )
        return engine.generate_config()


def test_xray_config_selects_mixed_socks_inbound_without_changing_other_config():
    configs = {
        mode: _generate_xray_config_for_proxy_mode(mode)
        for mode in ("http", None, "mixed")
    }
    baseline = configs["http"]

    for mode, config in configs.items():
        expected_socks_protocol = "mixed" if mode == "mixed" else "socks"
        assert [
            (item["tag"], item["protocol"], item["port"], item["listen"])
            for item in config["inbounds"]
        ] == [
            ("socks-in", expected_socks_protocol, 10808, "127.0.0.1"),
            ("http-in", "http", 10809, "127.0.0.1"),
        ]
        assert [item["settings"] for item in config["inbounds"]] == [
            {"auth": "noauth", "udp": True},
            {},
        ]
        assert [item["sniffing"] for item in config["inbounds"]] == [
            {"enabled": True, "destOverride": ["http", "tls", "fakedns"]},
            {"enabled": True, "destOverride": ["http", "tls", "fakedns"]},
        ]
        assert config["outbounds"] == baseline["outbounds"]
        assert config["routing"] == baseline["routing"]


def test_sni_engine_init():
    engine = SNIEngine()
    assert engine.name == "sni"
    assert engine.listen_port > 0


def test_xray_engine_init():
    engine = XRayEngine()
    assert engine.name == "xray"


def test_linux_xray_rejects_sni_fallback_with_supported_protocol_message(monkeypatch):
    monkeypatch.setattr("blackoutkit.engines.xray.sys.platform", "linux")
    monkeypatch.setattr("blackoutkit.engines.xray.XRayEngine.check_port_free", lambda *_args: True)
    engine = XRayEngine()
    engine.proxy_config = ProxyConfig(protocol="vless", address="127.0.0.1", port=40443)
    errors = []
    monkeypatch.setattr(engine._log, "error", lambda message, *_args: errors.append(message))

    assert engine.start() is False
    assert "VLESS or Trojan" in errors[0]
    assert "VMess runtime path" in errors[0]
