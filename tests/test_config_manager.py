import pytest
from blackoutkit.config.manager import ProxyConfig

def test_is_sni_compatible_true():
    # 127.0.0.1 and port 40443
    config1 = ProxyConfig(protocol="vmess", address="127.0.0.1", port=40443)
    assert config1.is_sni_compatible() is True

    # 0.0.0.0 and port 40443
    config2 = ProxyConfig(protocol="vless", address="0.0.0.0", port=40443)
    assert config2.is_sni_compatible() is True

def test_is_sni_compatible_false_wrong_port():
    # Correct address, wrong port
    config1 = ProxyConfig(protocol="vmess", address="127.0.0.1", port=443)
    assert config1.is_sni_compatible() is False

    config2 = ProxyConfig(protocol="trojan", address="0.0.0.0", port=8080)
    assert config2.is_sni_compatible() is False

def test_is_sni_compatible_false_wrong_address():
    # Wrong address, correct port
    config1 = ProxyConfig(protocol="vmess", address="192.168.1.1", port=40443)
    assert config1.is_sni_compatible() is False

    config2 = ProxyConfig(protocol="vless", address="example.com", port=40443)
    assert config2.is_sni_compatible() is False

def test_is_sni_compatible_false_wrong_both():
    # Wrong address, wrong port
    config1 = ProxyConfig(protocol="vmess", address="10.0.0.1", port=443)
    assert config1.is_sni_compatible() is False
