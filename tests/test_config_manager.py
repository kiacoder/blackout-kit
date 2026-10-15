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


# ── Corrupted-config load surfacing (Edge-Case Audit #1) ─────────────────────

def test_load_configs_success_has_no_error(tmp_path):
    from blackoutkit.config import manager

    path = tmp_path / "configs.txt"
    path.write_text("vless://uuid@example.com:443#ok\n", encoding="utf-8")

    result = manager.load_configs(path)

    assert result.error is None
    assert len(result) == 1
    assert result[0].address == "example.com"


def test_load_configs_missing_file_is_not_an_error(tmp_path):
    """A file that does not exist yet is the legitimate empty state."""
    from blackoutkit.config import manager

    result = manager.load_configs(tmp_path / "absent.txt")

    assert result.error is None
    assert result == []


def test_load_configs_unreadable_file_reports_error(tmp_path):
    """Permission-denied reads must be distinguishable from 'no configs'."""
    from unittest.mock import patch
    from blackoutkit.config import manager

    path = tmp_path / "configs.txt"
    path.write_text("vless://uuid@example.com:443#ok\n", encoding="utf-8")

    real_read_text = type(path).read_text

    def deny(self, *args, **kwargs):
        if self == path:
            raise PermissionError(13, "Permission denied")
        return real_read_text(self, *args, **kwargs)

    with patch.object(type(path), "read_text", deny):
        result = manager.load_configs(path)

    assert result.error is not None
    assert "permission denied" in result.error.lower()
    assert result == []


def test_load_configs_empty_file_is_not_an_error(tmp_path):
    from blackoutkit.config import manager

    path = tmp_path / "configs.txt"
    path.write_text("   \n", encoding="utf-8")

    result = manager.load_configs(path)

    assert result.error is None
    assert result == []


def test_load_configs_result_behaves_like_a_plain_list(tmp_path):
    """Callers that ignore .error keep working unchanged."""
    from blackoutkit.config import manager

    path = tmp_path / "configs.txt"
    path.write_text(
        "vless://uuid@example.com:443#a\ntrojan://pass@example.org:443\n",
        encoding="utf-8",
    )

    result = manager.load_configs(path)

    assert isinstance(result, list)
    assert sorted(c.protocol for c in result) == ["trojan", "vless"]
