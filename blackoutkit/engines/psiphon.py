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

        from ..core import get_warp_dll
        dll = get_warp_dll()
        if dll:
            self._log.info("Launching Psiphon via native DLL (Warp+ backend)")
            c_country = (self.country or "DE").encode("utf-8")
            if dll.StartPsiphonC(self.socks_port, self.http_port, c_country) == 0:
                self._dll_stop_func = dll.StopPsiphonC
                if not self.wait_for_port(self.socks_port, timeout=_STARTUP_TIMEOUT):
                    self._log.error("Psiphon natively via DLL timed out. Falling back to executable.")
                    self.stop()
                    self._dll_stop_func = None
                else:
                    self._log.info("Psiphon ready natively  socks=127.0.0.1:%d  country=%s.", self.socks_port, self.country)
                    return True
            else:
                self._log.warning("Native DLL StartPsiphonC failed, falling back to executable")

        binary = self.find_binary(PSIPHON_BIN_NAMES)
        if not binary:
            return False

        config_path = self._write_config()
        self._log.debug("Psiphon config written to %s", config_path)

        try:
            # psiphon-tunnel-core reads config with -config flag
            self._process = subprocess.Popen(
                [str(binary), "-config", str(config_path)],
                cwd=str(binary.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except Exception as exc:
            self._log.error("Failed to launch Psiphon: %s", exc)
            return False

        # Psiphon needs time to find a working server — use a long timeout
        self._log.debug(
            "Waiting up to %.0fs for Psiphon HTTP proxy on port %d…",
            _STARTUP_TIMEOUT, self.http_port,
        )
        if not self.wait_for_port(self.http_port, timeout=_STARTUP_TIMEOUT):
            if not self.check_process_alive():
                self._log.error(
                    "Psiphon exited before HTTP port %d opened (rc=%s).",
                    self.http_port, self._process.returncode,
                )
            else:
                self._log.error(
                    "Psiphon started but HTTP port %d never opened within %.0fs "
                    "(server may be unreachable in this region).",
                    self.http_port, _STARTUP_TIMEOUT,
                )
            self.stop()
            return False

        self._log.info(
            "Psiphon connected  http=127.0.0.1:%d  socks=127.0.0.1:%d  (pid=%s).",
            self.http_port, self.socks_port, self._process.pid,
        )
        return True
