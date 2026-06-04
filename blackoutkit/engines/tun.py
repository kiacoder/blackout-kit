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
import time
from pathlib import Path
from .base import Engine, BINS_DIR
from .. import settings as cfg

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
        return {
            "log": {"level": "warn"},
            "inbounds": [
                {
                    "type":               "tun",
                    "tag":                "tun-in",
                    "inet4_address":      "172.19.0.1/30",
                    "inet6_address":      "fdfe:dcba:9876::1/126",
                    "mtu":                9000,
                    "auto_route":         True,
                    "strict_route":       True,
                    "stack":              "mixed",
                    "endpoint_independent_nat": False,
                    "sniff":              True,
                }
            ],
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
        path = BINS_DIR / "singbox_tun_config.json"
        path.write_text(json.dumps(config, indent=2))
        return path

    def start(self) -> bool:
        binary = self.find_binary(TUN_BIN_NAMES)
        if not binary:
            return False

        self._log.info(
            "Starting TUN mode  upstream=socks5://%s:%d  bypass_ips=%d  bypass_domains=%d",
            self.socks_upstream, self.socks_port,
            len(self.bypass_ips), len(self.bypass_domains),
        )

        config_path = self._write_config()
        self._log.debug("sing-box TUN config written to %s", config_path)

        try:
            self._process = subprocess.Popen(
                [str(binary), "run", "-c", str(config_path)],
                cwd=str(binary.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except Exception as exc:
            self._log.error("Failed to launch sing-box: %s", exc)
            return False

        # TUN mode has no TCP proxy port to wait on — it operates at the
        # network-driver level. Instead, give it 0.5 s and check it's alive.
        # sing-box exits almost immediately if WinTUN is missing or admin is absent.
        time.sleep(0.5)
        if not self.check_process_alive():
            try:
                stderr_out = self._process.stderr.read(512).decode(errors="replace").strip()
            except Exception:
                stderr_out = ""
            if stderr_out:
                self._log.error("sing-box (TUN) crashed. stderr: %s", stderr_out)
            else:
                self._log.error(
                    "sing-box (TUN) exited immediately (rc=%s). "
                    "Common causes: WinTUN driver not installed "
                    "(https://www.wintun.net/) or not running as Administrator.",
                    self._process.returncode,
                )
            return False

        self._log.info(
            "TUN mode active — all traffic routed via socks5://%s:%d  (pid=%s).",
            self.socks_upstream, self.socks_port, self._process.pid,
        )
        return True
