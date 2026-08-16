import pytest
from unittest.mock import patch, MagicMock
from blackoutkit.engines.sni import SNIEngine
from blackoutkit.config.manager import ProxyConfig
from blackoutkit.engines.xray import XRayEngine

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
