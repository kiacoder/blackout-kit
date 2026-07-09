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

        # ── Try native DLL first ──────────────────────────────────
        from ..core import get_warp_dll
        dll = get_warp_dll()
        if dll:
            self._log.info("Launching WARP via native DLL")
            c_country = (self.country or "none").encode("utf-8")
            if dll.StartWarpC(self.socks_port, c_country) == 0:
                self._dll_stop_func = dll.StopWarpC
                if not self.wait_for_port(self.socks_port, timeout=_STARTUP_TIMEOUT):
                    self._log.error("WARP natively via DLL timed out.")
                    self.stop()
                    self._dll_stop_func = None
                else:
                    self._log.info("WARP ready natively  socks5=127.0.0.1:%d  country=%s.", self.socks_port, self.country)
                    return True
            else:
                self._log.warning("Native DLL StartWarpC failed, falling back to executable")

        # ── Fallback: warp-plus.exe binary ────────────────────────
        binary = self.find_binary(WARP_BIN_NAMES)
        if not binary:
            return False

        config_path = self._write_config()
        self._log.debug("WARP config written to %s", config_path)

        try:
            self._process = subprocess.Popen(
                [str(binary), "--config", str(config_path)],
                cwd=str(binary.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except Exception as exc:
            self._log.error("Failed to launch warp-plus: %s", exc)
            return False

        self._log.debug("Waiting up to %.0fs for WARP SOCKS on port %d\u2026", _STARTUP_TIMEOUT, self.socks_port)
        if not self.wait_for_port(self.socks_port, timeout=_STARTUP_TIMEOUT):
            if not self.check_process_alive():
                self._log.error("warp-plus exited before SOCKS port %d opened (rc=%s).", self.socks_port, self._process.returncode)
            else:
                self._log.error("warp-plus started but SOCKS port %d never opened within %.0fs.", self.socks_port, _STARTUP_TIMEOUT)
            self.stop()
            return False

        self._log.info("WARP connected via executable  socks5=127.0.0.1:%d  country=%s  (pid=%s).", self.socks_port, self.country, self._process.pid)
        return True
