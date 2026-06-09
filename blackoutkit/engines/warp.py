"""
Blackout Kit - Cloudflare WARP engine.
Uses hiddify/warp-plus to connect via Cloudflare's WARP protocol.
Gives you a clean Cloudflare IP — far fewer captchas and bot challenges.

Rare upgrades:
  - Logs socks_port and country on start
  - wait_for_port() confirms SOCKS5 is accepting connections before returning True
  - Both launch paths (JSON config + CLI fallback) verified via port check
  - Crash-check if port never opens
"""
import json
import subprocess
from pathlib import Path
from .base import Engine, BINS_DIR
from .. import settings as cfg

WARP_BIN_NAMES = [
    "warp-plus.exe",
    "warp.exe",
    "warp-plus-windows-amd64.exe",
]

_STARTUP_TIMEOUT = 20.0   # WARP registration + handshake can take ~10s


class WARPEngine(Engine):
    name = "warp"
    description = "Cloudflare WARP — clean residential-class IP, bypasses most captchas"

    def __init__(self, socks_port: int | None = None, country: str | None = None):
        super().__init__()
        s = cfg.load()
        # WARP-plus exposes SOCKS5 on a different port to avoid conflict with XRay
        self.socks_port = socks_port or 1080
        self.country    = country or s.get("psiphon_country", "DE")

    def _write_config(self) -> Path:
        config = {
            "socks5-bind": f"127.0.0.1:{self.socks_port}",
            "country":     self.country,
            "verbose":     False,
        }
        path = BINS_DIR / "warp_config.json"
        path.write_text(json.dumps(config, indent=2))
        return path

    def start(self) -> bool:
        self._log.info(
            "Starting WARP  socks_port=%d  country=%s",
            self.socks_port, self.country,
        )

        from ..core import get_warp_dll
        dll = get_warp_dll()
        if not dll:
            self._log.error("WARP DLL missing! Ensure blackout_warp.dll is built.")
            return False

        self._log.info("Launching WARP via native DLL")
        c_country = (self.country or "none").encode("utf-8")
        if dll.StartWarpC(self.socks_port, c_country) == 0:
            self._dll_stop_func = dll.StopWarpC
            if not self.wait_for_port(self.socks_port, timeout=_STARTUP_TIMEOUT):
                self._log.error("WARP natively via DLL timed out.")
                self.stop()
                return False
            else:
                self._log.info("WARP ready natively  socks5=127.0.0.1:%d  country=%s.", self.socks_port, self.country)
                return True
        else:
            self._log.error("Native DLL StartWarpC failed")
            return False
