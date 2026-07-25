import pytest
from pathlib import Path
from blackoutkit.config.manager import ProxyConfig, save_configs

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
