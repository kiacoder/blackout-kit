"""Tests for the native AmneziaWG engine (awg-go core).

Covers config parsing (incl. obfuscation params), awg:// URI materialization,
and a live start/stop against the real bundled core when it is present.
"""
import base64
import os
import socket
import time
from pathlib import Path

import pytest

from blackoutkit import BINS_DIR, settings
from blackoutkit.engines import amneziawg as awg_mod
from blackoutkit.engines.amneziawg import AmneziaWGEngine, _conf_from_uri, _conf_summary, _parse_awg_conf

SAMPLE_CONF = """[Interface]
PrivateKey = {priv}
Address = 10.66.66.2/32, fd42:42:42::2/128
DNS = 1.1.1.1
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 30
S2 = 40
H1 = 123456-123500
H2 = 234567-234600
H3 = 345678-345700
H4 = 456789-456800

[Peer]
PublicKey = {pub}
Endpoint = 127.0.0.1:39006
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""


def _key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


@pytest.fixture()
def conf_file(tmp_path) -> Path:
    p = tmp_path / "awg.conf"
    p.write_text(SAMPLE_CONF.format(priv=_key(), pub=_key()), encoding="utf-8")
    return p


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ────────────────────────────── parsing ──────────────────────────────

def test_parse_conf_reads_obfuscation_params(conf_file):
    fields = _parse_awg_conf(conf_file)
    assert fields["interface.jc"] == "4"
    assert fields["interface.jmin"] == "40"
    assert fields["interface.jmax"] == "70"
    assert fields["interface.s1"] == "30"
    assert fields["interface.s2"] == "40"
    assert fields["interface.h1"] == "123456-123500"
    assert fields["interface.h4"] == "456789-456800"
    assert fields["peer.endpoint"] == "127.0.0.1:39006"
    assert fields["peer.persistentkeepalive"] == "25"


def test_conf_summary_lists_obfuscation(conf_file):
    summary = _conf_summary(_parse_awg_conf(conf_file))
    assert "endpoint=127.0.0.1:39006" in summary
    assert "jc" in summary and "h4" in summary


def test_conf_from_uri_base64(conf_file):
    uri = "awg://" + base64.urlsafe_b64encode(conf_file.read_bytes()).decode().rstrip("=")
    text = _conf_from_uri(uri)
    assert "[Interface]" in text and "Jc = 4" in text
    assert "Endpoint = 127.0.0.1:39006" in text


def test_conf_from_uri_query_params():
    uri = ("awg://?private_key=" + _key() + "&address=10.0.0.2/32"
           "&endpoint=1.2.3.4:39006&public_key=" + _key() +
           "&jc=5&jmin=50&jmax=80&h1=1111-2222&allowed_ips=0.0.0.0/0")
    text = _conf_from_uri(uri)
    assert "PrivateKey = " in text
    assert "Jc = 5" in text and "H1 = 1111-2222" in text
    assert "Endpoint = 1.2.3.4:39006" in text
    assert "AllowedIPs = 0.0.0.0/0" in text


# ────────────────────────────── lifecycle ──────────────────────────────

def _core_present() -> bool:
    return any((BINS_DIR / n).is_file() for n in ("awg-go.exe", "awg-go"))


def test_start_fails_without_config(monkeypatch):
    monkeypatch.setattr(settings, "load", lambda: {"xray_socks_port": _free_port(), "awg_config_file": ""})
    engine = AmneziaWGEngine(config_file="", socks_port=_free_port())
    assert engine.start() is False


def test_start_fails_on_missing_file(tmp_path):
    engine = AmneziaWGEngine(config_file=str(tmp_path / "nope.conf"), socks_port=_free_port())
    assert engine.start() is False


@pytest.mark.skipif(not _core_present(), reason="awg-go core binary not built")
def test_live_start_and_stop(conf_file, monkeypatch):
    port = _free_port()
    monkeypatch.setattr(settings, "load", lambda: {"xray_socks_port": port, "awg_config_file": str(conf_file)})
    engine = AmneziaWGEngine(config_file=str(conf_file), socks_port=port)
    try:
        assert engine.start() is True
        # SOCKS5 greeting must be answered (no-auth accepted)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.sendall(b"\x05\x01\x00")
            assert s.recv(2) == b"\x05\x00"
        assert engine.is_running() is True
    finally:
        engine.stop()
    time.sleep(0.5)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


def test_awg_uses_dedicated_socks_port():
    """awg must not share xray_socks_port (v2rayN/XRay usually holds 10808)."""
    from blackoutkit import settings

    details = settings.get_engine_proxy_details(
        "awg", {"awg_socks_port": 11080, "xray_socks_port": 10808}
    )
    assert details == ("socks=127.0.0.1", 11080)
    assert settings.DEFAULTS["awg_socks_port"] == 11080


def test_awg_uses_dedicated_socks_port():
    """awg must not share xray_socks_port (v2rayN/XRay usually holds 10808)."""
    from blackoutkit import settings

    details = settings.get_engine_proxy_details(
        "awg", {"awg_socks_port": 11080, "xray_socks_port": 10808}
    )
    assert details == ("socks=127.0.0.1", 11080)
    assert settings.DEFAULTS["awg_socks_port"] == 11080
