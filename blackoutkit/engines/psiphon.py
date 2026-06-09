"""
Blackout Kit - Psiphon engine.
Wraps psiphon-tunnel-core for multi-protocol VPN.
Best as a last-resort fallback — works even during heavy blackouts.
Requires psiphon-tunnel-core-x86_64.exe in bins/.

Rare upgrades:
  - Logs country, http_port, socks_port on start
  - wait_for_port() on http_port confirms Psiphon is connected before returning True
  - 60-second timeout because Psiphon bootstraps slowly under heavy censorship
  - Crash-check if port never opens
"""
import json
import subprocess
from pathlib import Path
from .base import Engine, BINS_DIR
from .. import settings as cfg

PSIPHON_BIN_NAMES = [
    "psiphon-tunnel-core-x86_64.exe",
    "psiphon-tunnel-core.exe",
    "psiphon3.exe",
    "psiphon.exe",
]

_STARTUP_TIMEOUT = 60.0   # Psiphon can take a long time to find a working server


class PsiphonEngine(Engine):
    name = "psiphon"
    description = "Psiphon multi-protocol VPN — ultimate fallback"

    def __init__(self, country: str | None = None, http_port: int | None = None, socks_port: int | None = None):
        super().__init__()
        s = cfg.load()
        self.country    = country    or s["psiphon_country"]
        self.http_port  = http_port  or s["psiphon_http_port"]
        self.socks_port = socks_port or s["psiphon_socks_port"]

    def _write_config(self) -> Path:
        config = {
            "PropagationChannelId":  "FFFFFFFFFFFFFFFF",
            "SponsorId":             "FFFFFFFFFFFFFFFF",
            "LocalHttpProxyPort":    self.http_port,
            "LocalSocksProxyPort":   self.socks_port,
            "EgressRegion":          self.country,
            "DisableLocalHTTPProxy": False,
            "DisableLocalSocksProxy": False,
            "UpstreamProxyUrl":      "",
        }
        path = BINS_DIR / "psiphon_config.json"
        path.write_text(json.dumps(config, indent=2))
        return path

    def start(self) -> bool:
        self._log.info(
            "Starting Psiphon  country=%s  http_port=%d  socks_port=%d",
            self.country, self.http_port, self.socks_port,
        )

        config_path = self._write_config()

        from ..core import get_warp_dll
        dll = get_warp_dll()
        if not dll:
            self._log.error("WARP DLL missing! Ensure blackout_warp.dll is built.")
            return False

        self._log.info("Launching pure Psiphon natively")
        c_config_path = str(config_path.absolute()).encode("utf-8")
        if dll.StartPsiphonC(c_config_path) == 0:
            self._dll_stop_func = dll.StopPsiphonC
            if not self.wait_for_port(self.socks_port, timeout=_STARTUP_TIMEOUT):
                self._log.error("Psiphon natively via DLL timed out.")
                self.stop()
                return False
            else:
                self._log.info("Psiphon ready natively  socks=127.0.0.1:%d  country=%s.", self.socks_port, self.country)
                return True
        else:
            self._log.error("Native DLL StartPsiphonC failed")
            return False
