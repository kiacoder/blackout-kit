"""Regression tests for the security-relevant medium findings.

Each one is a small, sharp edge that a later refactor could quietly restore.
"""
from __future__ import annotations

import base64

import pytest


# ── BK-039: ss:// links are parsed, in both shapes ─────────────────────────
def _sip002(method: str, password: str, host: str, port: int, name: str = "") -> str:
    token = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    return f"ss://{token}@{host}:{port}#{name}"


def test_shadowsocks_sip002_link_is_parsed():
    from blackoutkit.config.manager import parse_v2ray_uri

    config = parse_v2ray_uri(_sip002("aes-256-gcm", "secret", "example.com", 8388, "Node1"))
    assert config is not None, "ss:// used to be dropped entirely"
    assert config.protocol == "shadowsocks"
    assert (config.address, config.port) == ("example.com", 8388)
    assert config.method == "aes-256-gcm"
    assert config.password == "secret"
    assert config.name == "Node1"
    # Shadowsocks has no TLS layer; marking it tls is what made the builder
    # wrap it in a ClientHello the server cannot answer.
    assert config.security == "none"


def test_shadowsocks_legacy_base64_link_is_parsed():
    from blackoutkit.config.manager import parse_v2ray_uri

    blob = base64.urlsafe_b64encode(
        b"chacha20-ietf-poly1305:p@ss@example.com:8388"
    ).decode().rstrip("=")
    config = parse_v2ray_uri(f"ss://{blob}#Legacy")
    assert config is not None
    assert config.method == "chacha20-ietf-poly1305"
    # The password contains '@', so the split must be on the LAST one.
    assert config.password == "p@ss"
    assert config.address == "example.com"


def test_shadowsocks_plain_percent_encoded_link_is_parsed():
    from blackoutkit.config.manager import parse_v2ray_uri

    config = parse_v2ray_uri("ss://aes-128-gcm:pa%40ss@example.org:443#Plain")
    assert config is not None
    assert config.password == "pa@ss"
    assert config.method == "aes-128-gcm"


def test_shadowsocks_outbound_has_no_tls_block():
    from blackoutkit.config.manager import parse_v2ray_uri
    from blackoutkit.engines.singbox_proxy import SingBoxProxyEngine

    config = parse_v2ray_uri(_sip002("aes-256-gcm", "secret", "example.com", 8388))
    engine = SingBoxProxyEngine.__new__(SingBoxProxyEngine)
    engine.proxy_config = config
    engine.socks_port = 10809

    outbound = engine._generate_config()["outbounds"][0]
    assert outbound["type"] == "shadowsocks"
    assert outbound["method"] == "aes-256-gcm"
    assert "tls" not in outbound


# ── BK-044: no DLL is loaded from the current directory ────────────────────
def test_windivert_is_not_loaded_from_the_working_directory():
    import io
    from pathlib import Path

    source = io.open(
        Path(__file__).resolve().parents[1] / "blackoutkit" / "daemon" / "qos_shaper.py",
        encoding="utf-8",
    ).read()
    assert 'Path.cwd() / "WinDivert.dll"' not in source


# ── BK-067: a URL cannot become a yt-dlp option ────────────────────────────
@pytest.mark.parametrize(
    "url",
    [
        "--exec=touch /tmp/pwned",
        "-f",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "",
    ],
)
def test_media_downloader_rejects_non_http_urls(url):
    from blackoutkit.tools.media_downloader import MediaDownloadManager

    with pytest.raises(ValueError):
        MediaDownloadManager().add_download(url)


def test_media_downloader_passes_the_separator():
    import io
    from pathlib import Path

    source = io.open(
        Path(__file__).resolve().parents[1] / "blackoutkit" / "tools" / "media_downloader.py",
        encoding="utf-8",
    ).read()
    # The "--" must appear before the URL in the argument list.
    assert '"--",' in source
