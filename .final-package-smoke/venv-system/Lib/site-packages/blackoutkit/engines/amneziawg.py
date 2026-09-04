"""
Blackout Kit - AmneziaWG engine.

AmneziaWG is a WireGuard variant with junk-packet obfuscation that resists
DPI detection. It is widely used in Russia as a secondary bypass layer.

This engine parses standard WireGuard .conf files with AmneziaWG-specific
parameters (JC, JMin, JMax, S1, S2, H1-H4) and generates a sing-box
'amnezia-wireguard' outbound config.

Requirements:
  - A WireGuard/AmneziaWG .conf config file (set in settings: awg_config_file)
  - blackout_core.dll (Windows) or blackout-engine (Linux)

Settings:
  awg_config_file  — Full path to your AmneziaWG .conf file
"""
import json
import logging
import sys
from pathlib import Path

from .base import Engine
from .xray import LINUX_RUNNER_NAMES


# The bundled sing-box runtime does not register the AmneziaWG outbound type.
from .. import settings as cfg

_log = logging.getLogger(__name__)

_AWG_SECTION_MAP = {
    "jc": "junk_count",
    "jmin": "junk_packet_min",
    "jmax": "junk_packet_max",
    "s1": "init_packet_junk_size",
    "s2": "response_packet_junk_size",
    "h1": "transport_header_junk_size",
    "h2": "transport_header_junk_size_2",
    "h3": "transport_header_junk_size_3",
    "h4": "transport_header_junk_size_4",
}


def _parse_awg_conf(path: Path) -> dict:
    """Parse an AmneziaWG .conf file into a config dict."""
    text = path.read_text(encoding="utf-8", errors="replace")
    section = None
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            fields[f"{section}.{key.lower()}"] = value
    return fields


def _build_singbox_outbound(fields: dict) -> dict:
    """Build a sing-box amnezia-wireguard outbound from parsed conf fields."""
    server = fields.get("peer.endpoint", "")
    if ":" in server:
        host, port_str = server.rsplit(":", 1)
        port = int(port_str)
    else:
        host = server
        port = 51820

    local_address = fields.get("interface.address", "10.0.0.2/32")
    address_list = [a.strip() for a in local_address.split(",") if a.strip()]

    outbound = {
        "type": "amnezia-wireguard",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "local_address": address_list,
        "private_key": fields.get("interface.privatekey", ""),
        "peer_public_key": fields.get("peer.publickey", ""),
        "mtu": int(fields.get("interface.mtu", "1400") or "1400"),
    }

    preshared = fields.get("peer.presharedkey", "")
    if preshared:
        outbound["pre_shared_key"] = preshared

    dns = fields.get("interface.dns", "")
    if dns:
        outbound["detour"] = "direct"

    for conf_key, singbox_key in _AWG_SECTION_MAP.items():
        value = fields.get(f"interface.{conf_key}")
        if value is None:
            value = fields.get(f"peer.{conf_key}")
        if value is not None:
            try:
                outbound[singbox_key] = int(value)
            except ValueError:
                pass

    return outbound


class AmneziaWGEngine(Engine):
    name = "awg"
    description = "AmneziaWG — obfuscated WireGuard via sing-box (experimental)"
    protocol = "awg"

    def __init__(self, config_file: str = "", socks_port: int | None = None):
        super().__init__()
        s = cfg.load()
        self.config_file = config_file or s.get("awg_config_file", "")
        self.socks_port = socks_port or s["xray_socks_port"]
        self._health_check_addr = ("127.0.0.1", self.socks_port)
        self.proxy_config = None
        self.requested_protocol = None

    def _generate_config(self) -> dict:
        conf_path = Path(self.config_file)
        fields = _parse_awg_conf(conf_path)
        outbound = _build_singbox_outbound(fields)

        return {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": self.socks_port,
                    "sniff": True,
                }
            ],
            "outbounds": [
                outbound,
                {"type": "direct", "tag": "direct"},
            ],
        }

    def start(self) -> bool:
        self._log.error(
            "AmneziaWG cannot start: the bundled sing-box runtime does not "
            "support the amnezia-wireguard outbound type."
        )
        return False
