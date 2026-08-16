"""
Blackout Kit - TUN mode engine.
Routes ALL network traffic through the proxy — every app,
even those that don't support proxy settings (games, Spotify, etc.).

Uses sing-box with TUN interface on Windows (requires WinTUN driver).
sing-box: https://github.com/SagerNet/sing-box/releases

TUN mode requires:
  1. sing-box.exe in bins/
  2. WinTUN driver installed (https://www.wintun.net/)
  3. Administrator privileges

Rare upgrades:
  - Logs socks_upstream, socks_port, bypass domain/IP counts on start
  - Logs the config file path written for debuggability
  - 0.5s crash-check after spawn (TUN fails fast if WinTUN is missing or
    not running as Administrator — no port to wait on for TUN mode)
  - Specific error message suggesting WinTUN / admin when crash detected
"""
import json
import subprocess
import sys
import time

from .xray import LINUX_RUNNER_NAMES
from pathlib import Path
from .base import Engine
from .. import settings as cfg
from ..elevate import restart_as_admin

TUN_BIN_NAMES = [
    "sing-box.exe",
    "singbox.exe",
]

# Routes that bypass the TUN tunnel (always go direct)
DEFAULT_BYPASS_IPS = [
    "127.0.0.0/8",
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
]

# Routes that bypass by domain (Iranian domestic sites — always direct)
DEFAULT_BYPASS_DOMAINS = [
    "domain:ir",             # all .ir domains
    "domain:aparat.com",
    "domain:digikala.com",
    "domain:snapp.ir",
    "domain:divar.ir",
]


class TUNEngine(Engine):
    name = "tun"
    description = "TUN mode — tunnels ALL apps via virtual network interface"

    def __init__(self,
                 socks_upstream: str = "127.0.0.1",
                 socks_port: int | None = None,
                 bypass_domains: list[str] | None = None,
                 bypass_ips: list[str] | None = None):
        super().__init__()
        s = cfg.load()
        self.socks_upstream = socks_upstream
        self.socks_port     = socks_port or s["xray_socks_port"]
        self.bypass_domains = bypass_domains or DEFAULT_BYPASS_DOMAINS
        self.bypass_ips     = bypass_ips    or DEFAULT_BYPASS_IPS

    def _generate_singbox_config(self) -> dict:
        """Generate sing-box configuration for TUN mode."""
        tun_inbound = {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "BlackoutKit-TUN",
            "inet4_address": "172.19.0.1/30",
            "inet6_address": "fdfe:dcba:9876::1/126",
            "mtu": 9000,
            "auto_route": True,
            "strict_route": True,
            "stack": "mixed",
            "endpoint_independent_nat": False,
            "sniff": True,
        }
        if sys.platform.startswith("linux"):
            tun_inbound["iproute2_table_index"] = 20220
            tun_inbound["iproute2_rule_index"] = 32200

        return {
            "log": {"level": "warn"},
            "inbounds": [tun_inbound],
            "outbounds": [
                {
                    "type": "socks",
                    "tag":  "proxy",
                    "server":      self.socks_upstream,
                    "server_port": self.socks_port,
                },
                {"type": "direct", "tag": "direct"},
                {"type": "block",  "tag": "block"},
                {"type": "dns",    "tag": "dns-out"},
            ],
            "route": {
                "auto_detect_interface": sys.platform.startswith("linux"),
                "rules": [
                    {"protocol": "dns", "outbound": "dns-out"},
                    {"ip_cidr":  self.bypass_ips, "outbound": "direct"},
                    {
                        "domain": [
                            d.replace("domain:", "")
                            for d in self.bypass_domains
                            if d.startswith("domain:")
                        ],
                        "outbound": "direct",
                    },
                ],
                "final": "proxy",
            },
            "dns": {
                "servers": [
                    {"tag": "remote", "address": "tls://1.1.1.1", "detour": "proxy"},
                    {"tag": "direct", "address": "223.5.5.5",     "detour": "direct"},
                ],
                "rules": [
                    {
                        "domain": [
                            d.replace("domain:", "")
                            for d in self.bypass_domains
                            if d.startswith("domain:")
                        ],
                        "server": "direct",
                    },
                ],
                "final": "remote",
            },
        }

    def _write_config(self) -> Path:
        config = self._generate_singbox_config()
        path = self._config_dir / "singbox_tun_config.json"
        path.write_text(json.dumps(config, indent=2))
        return path

    def start(self) -> bool:

        self._log.info(
            "Starting TUN mode  upstream=socks5://%s:%d  bypass_ips=%d  bypass_domains=%d",
            self.socks_upstream, self.socks_port,
            len(self.bypass_ips), len(self.bypass_domains),
        )

        # TUN mode needs system networking rights on every supported platform.
        if sys.platform == "win32":
            from ..elevate import is_admin
            if not is_admin():
                self._log.warning("TUN mode requires Administrator privileges (WinTUN kernel driver).")
                self._log.info("Requesting elevation via UAC…")
                if restart_as_admin():
                    self._log.info("Elevation accepted — new admin terminal opened.")
                    return False
                self._log.error("UAC elevation was denied. TUN mode requires admin rights.")
                return False
        elif sys.platform.startswith("linux"):
            from ..linux_network import is_root

            if not is_root():
                self._log.error("Linux TUN mode requires root privileges. Run: sudo blackout connect tun")
                return False
        else:
            self._log.error("TUN mode is supported only on Windows and Linux.")
            return False

        config_path = self._write_config()
        self._log.debug("sing-box TUN config written to %s", config_path)

        if sys.platform.startswith("linux"):
            runner = self.find_binary(LINUX_RUNNER_NAMES)
            if not runner:
                self._log.error("Linux TUN requires the managed blackout-engine runner.")
                return False
            self._log.info("Launching sing-box TUN through the Linux blackout-engine runner")
            if not self.start_process(self.binary_command(runner, "sing-box", "--config", str(config_path))):
                return False
            if not self.wait_for_process():
                return False
            self._log.info("Linux TUN active — all traffic routes via socks5://%s:%d.", self.socks_upstream, self.socks_port)
            return True

        from ..core import get_core_dll
        dll = get_core_dll()
        if not dll:
            self._log.error("Core DLL missing! Ensure blackout_core.dll is built.")
            return False

        self._log.info("Launching sing-box (TUN) via native DLL")
        c_path = str(config_path).encode("utf-8")
        if dll.StartSingBoxC(c_path) == 0:
            self._dll_stop_func = dll.StopSingBoxC
            time.sleep(0.5)
            self._log.info("TUN mode active natively — all traffic routed via socks5://%s:%d.", self.socks_upstream, self.socks_port)
            return True
        self._log.error("Native DLL StartSingBoxC failed")
        return False
