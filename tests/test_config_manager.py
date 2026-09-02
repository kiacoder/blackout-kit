import pytest
from unittest.mock import patch

from blackoutkit.config.manager import ProxyConfig, replace_config


@pytest.fixture
def sample_configs():
    return [
        ProxyConfig(
            protocol="vless",
            address="old.example",
            port=443,
            raw_uri="vless://old@example.com:443",
            name="old",
        ),
    ]


def test_replace_config_validates_before_saving(sample_configs):
    with patch("blackoutkit.config.manager.load_configs", return_value=sample_configs), \
         patch("blackoutkit.config.manager.save_configs") as save:
        replacement = replace_config(0, "vless://new@example.com:443")

    assert replacement.raw_uri == "vless://new@example.com:443"
    save.assert_called_once()
    assert save.call_args.args[0][0].raw_uri == replacement.raw_uri


def test_replace_config_rejects_invalid_uri_without_saving(sample_configs):
    with patch("blackoutkit.config.manager.load_configs", return_value=sample_configs), \
         patch("blackoutkit.config.manager.save_configs") as save:
        with pytest.raises(ValueError, match="Invalid V2Ray URI"):
            replace_config(0, "not-a-uri")

    save.assert_not_called()


def test_replace_config_rejects_duplicate_uri_without_saving():
    configs = [
        ProxyConfig(protocol="vless", address="a.example", port=443, raw_uri="vless://a@a.example:443"),
        ProxyConfig(protocol="vless", address="b.example", port=443, raw_uri="vless://b@b.example:443"),
    ]
    with patch("blackoutkit.config.manager.load_configs", return_value=configs), \
         patch("blackoutkit.config.manager.save_configs") as save:
        with pytest.raises(ValueError, match="already saved"):
            replace_config(0, "vless://b@b.example:443")

    save.assert_not_called()


def test_replace_config_rejects_bad_index_without_saving(sample_configs):
    with patch("blackoutkit.config.manager.load_configs", return_value=sample_configs), \
         patch("blackoutkit.config.manager.save_configs") as save:
        with pytest.raises(IndexError):
            replace_config(1, "vless://new@example.com:443")

    save.assert_not_called()

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
