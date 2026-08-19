"""Tests for the AmneziaWG engine conf parser."""
from pathlib import Path

from blackoutkit.engines.amneziawg import _parse_awg_conf, _build_singbox_outbound


SAMPLE_CONF = """[Interface]
PrivateKey = abc123privatekey
Address = 10.8.0.2/32
DNS = 1.1.1.1
MTU = 1400
JC = 3
JMin = 10
JMax = 20
S1 = 100
S2 = 200
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = xyz789publickey
PresharedKey = shared123
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
"""


def test_parse_awg_conf_extracts_all_fields(tmp_path):
    conf = tmp_path / "awg.conf"
    conf.write_text(SAMPLE_CONF, encoding="utf-8")

    fields = _parse_awg_conf(conf)

    assert fields["interface.privatekey"] == "abc123privatekey"
    assert fields["interface.address"] == "10.8.0.2/32"
    assert fields["interface.jc"] == "3"
    assert fields["interface.jmin"] == "10"
    assert fields["interface.jmax"] == "20"
    assert fields["interface.s1"] == "100"
    assert fields["interface.s2"] == "200"
    assert fields["peer.publickey"] == "xyz789publickey"
    assert fields["peer.endpoint"] == "vpn.example.com:51820"
    assert fields["peer.presharedkey"] == "shared123"


def test_build_singbox_outbound_generates_amnezia_wireguard(tmp_path):
    conf = tmp_path / "awg.conf"
    conf.write_text(SAMPLE_CONF, encoding="utf-8")
    fields = _parse_awg_conf(conf)

    outbound = _build_singbox_outbound(fields)

    assert outbound["type"] == "amnezia-wireguard"
    assert outbound["tag"] == "proxy"
    assert outbound["server"] == "vpn.example.com"
    assert outbound["server_port"] == 51820
    assert outbound["local_address"] == ["10.8.0.2/32"]
    assert outbound["private_key"] == "abc123privatekey"
    assert outbound["peer_public_key"] == "xyz789publickey"
    assert outbound["pre_shared_key"] == "shared123"
    assert outbound["mtu"] == 1400

    assert outbound["junk_count"] == 3
    assert outbound["junk_packet_min"] == 10
    assert outbound["junk_packet_max"] == 20
    assert outbound["init_packet_junk_size"] == 100
    assert outbound["response_packet_junk_size"] == 200


def test_build_singbox_outbound_defaults_port_when_missing(tmp_path):
    conf = tmp_path / "awg.conf"
    conf.write_text(
        "[Interface]\nPrivateKey = key\nAddress = 10.0.0.2/32\n\n"
        "[Peer]\nPublicKey = pub\nEndpoint = vpn.example.com\n",
        encoding="utf-8",
    )
    fields = _parse_awg_conf(conf)
    outbound = _build_singbox_outbound(fields)

    assert outbound["server"] == "vpn.example.com"
    assert outbound["server_port"] == 51820


def test_awg_engine_registered_in_engine_registry():
    from blackoutkit.engines import ENGINE_REGISTRY, get_engine

    assert "awg" in ENGINE_REGISTRY
    cls = get_engine("awg")
    assert cls.__name__ == "AmneziaWGEngine"


def test_awg_in_linux_engines():
    from blackoutkit.routing import LINUX_ENGINES, platform_engines

    assert "awg" in LINUX_ENGINES
    linux_engines = platform_engines("linux")
    assert "awg" in linux_engines


def test_ru_profile_includes_awg():
    from blackoutkit.country_profiles import get_profile

    profile = get_profile("RU")
    assert "awg" in profile.engine_order
