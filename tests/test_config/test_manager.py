import pytest
import json
import base64
import binascii
from pathlib import Path
from blackoutkit.config.manager import ProxyConfig, save_configs, _parse_vmess, parse_v2ray_uri

def test_save_configs(tmp_path: Path):
    configs = [
        ProxyConfig(protocol="vmess", address="1.1.1.1", port=443, raw_uri="vmess://test1"),
        ProxyConfig(protocol="vless", address="2.2.2.2", port=443, raw_uri="vless://test2"),
        ProxyConfig(protocol="trojan", address="3.3.3.3", port=443, raw_uri=""), # should be skipped
    ]

    test_file = tmp_path / "test_configs.txt"
    save_configs(configs, path=test_file)

    assert test_file.exists()
    content = test_file.read_text(encoding="utf-8")
    assert content == "vmess://test1\nvless://test2"

def test_save_configs_creates_directories(tmp_path: Path):
    configs = [
        ProxyConfig(protocol="vmess", address="1.1.1.1", port=443, raw_uri="vmess://test1"),
    ]

    test_file = tmp_path / "new_dir" / "nested_dir" / "test_configs.txt"
    save_configs(configs, path=test_file)

    assert test_file.exists()
    content = test_file.read_text(encoding="utf-8")
    assert content == "vmess://test1"


def test_save_configs_default_path(monkeypatch, tmp_path: Path):
    # Mock CONFIGS_FILE to point to our tmp_path to avoid modifying real user files
    mock_configs_file = tmp_path / "mock_configs.txt"
    monkeypatch.setattr("blackoutkit.config.manager.CONFIGS_FILE", mock_configs_file)

    configs = [
        ProxyConfig(protocol="vmess", address="1.1.1.1", port=443, raw_uri="vmess://default"),
    ]

    save_configs(configs)

    assert mock_configs_file.exists()
    content = mock_configs_file.read_text(encoding="utf-8")
    assert content == "vmess://default"


def create_vmess_uri(data_dict, strip_padding=True):
    json_str = json.dumps(data_dict)
    b64_str = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
    if strip_padding:
        b64_str = b64_str.rstrip("=")
    return f"vmess://{b64_str}"

def test_parse_vmess_full():
    data = {
        "v": "2",
        "ps": "my-proxy",
        "add": "1.2.3.4",
        "port": "443",
        "id": "my-uuid-1234",
        "net": "ws",
        "host": "my-host.com",
        "path": "/mypath",
        "sni": "my-sni.com"
    }
    uri = create_vmess_uri(data)
    config = _parse_vmess(uri)

    assert isinstance(config, ProxyConfig)
    assert config.protocol == "vmess"
    assert config.name == "my-proxy"
    assert config.address == "1.2.3.4"
    assert config.port == 443
    assert config.uuid == "my-uuid-1234"
    assert config.transport == "ws"
    assert config.host == "my-host.com"
    assert config.path == "/mypath"
    assert config.sni == "my-sni.com"
    assert config.raw_uri == uri

def test_parse_vmess_defaults():
    data = {
        "add": "example.com",
        "id": "test-uuid"
    }
    uri = create_vmess_uri(data)
    config = _parse_vmess(uri)

    assert config.address == "example.com"
    assert config.uuid == "test-uuid"
    assert config.port == 443 # default port
    assert config.sni == ""
    assert config.host == ""
    assert config.path == "/"
    assert config.transport == "ws"
    assert config.name == ""

def test_parse_vmess_sni_fallback_to_host():
    # If sni is not explicitly set, it should fallback to host
    data = {
        "add": "1.2.3.4",
        "host": "fallback-host.com"
    }
    uri = create_vmess_uri(data)
    config = _parse_vmess(uri)

    assert config.host == "fallback-host.com"
    assert config.sni == "fallback-host.com"

def test_parse_vmess_padding():
    data = {"add": "a"}
    # Manually testing with and without padding
    uri_no_pad = create_vmess_uri(data, strip_padding=True)
    uri_pad = create_vmess_uri(data, strip_padding=False)

    config1 = _parse_vmess(uri_no_pad)
    config2 = _parse_vmess(uri_pad)

    assert config1.address == "a"
    assert config2.address == "a"


def test_parse_vmess_invalid_base64():
    # Provide a base64 string that cannot be decoded due to invalid padding/length
    # "hello***" after padding will have 5 data characters which raises binascii.Error
    invalid_uri = "vmess://hello***"
    with pytest.raises(binascii.Error):
        _parse_vmess(invalid_uri)

def test_parse_vmess_invalid_json():
    # Valid base64, but not JSON
    bad_json_b64 = base64.b64encode(b"not json").decode('utf-8')
    invalid_uri = f"vmess://{bad_json_b64}"

    with pytest.raises(json.JSONDecodeError):
        _parse_vmess(invalid_uri)

def test_parse_v2ray_uri_vmess_wrapper():
    data = {"add": "1.2.3.4", "port": 1234}
    uri = create_vmess_uri(data)
    config = parse_v2ray_uri(uri)

    assert config is not None
    assert config.protocol == "vmess"
    assert config.address == "1.2.3.4"
    assert config.port == 1234

def test_parse_v2ray_uri_invalid_returns_none():
    assert parse_v2ray_uri("vmess://invalid_base64!!!") is None
    bad_json = base64.b64encode(b"not json").decode('utf-8')
    assert parse_v2ray_uri(f"vmess://{bad_json}") is None
