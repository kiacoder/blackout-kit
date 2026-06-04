"""
Blackout Kit - WireGuard engine.
Wraps wireguard.exe (official WireGuard for Windows) or system-installed WireGuard.

WireGuard is a modern, fast, UDP-based VPN with minimal overhead.
Ideal as a secondary bypass layer when combined with SNI or GDPI.

Requirements:
  - wireguard.exe in bins/  OR  WireGuard installed at default path
  - A WireGuard .conf config file (set in settings: wg_config_file)

Settings:
  wg_config_file  — Full path to your WireGuard .conf file
  wg_interface    — Interface/tunnel name (default: wg0)

Download WireGuard: https://www.wireguard.com/install/
"""
import logging
import subprocess
import sys
import threading
import time
from pathlib import Path
from .base import Engine, BINS_DIR

WG_BIN_NAMES     = ["wireguard.exe", "wg.exe"]
SYSTEM_WG        = Path("C:/Program Files/WireGuard/wireguard.exe")
_STARTUP_TIMEOUT = 8.0   # seconds to wait for service to reach RUNNING state
_MONITOR_POLL    = 3.0   # seconds between tunnel health checks


class WireGuardEngine(Engine):
    name = "wireguard"
    description = "WireGuard — fast, modern, kernel-level UDP VPN"

    def __init__(self, config_file: str = "", interface: str = ""):
        super().__init__()
        from .. import settings as cfg
        s = cfg.load()
        self.config_file     = config_file or s.get("wg_config_file", "")
        self.interface       = interface   or s.get("wg_interface",   "wg0")
        self._tunnel_active  = False
        self._monitor_thread: threading.Thread | None = None
        self._log = logging.getLogger(__name__).getChild(self.name)

    # ── Helpers ──────────────────────────────────────────────────

    def _find_wireguard(self) -> Path | None:
        binary = self.find_binary(WG_BIN_NAMES)
        if binary:
            return binary
        if SYSTEM_WG.exists():
            return SYSTEM_WG
        return None

    def _service_name(self) -> str:
        return f"WireGuardTunnel${self.interface}"

    def _is_tunnel_running(self) -> bool:
        """Ask Windows SCM if the WireGuard tunnel service is RUNNING."""
        try:
            result = subprocess.run(
                ["sc", "query", self._service_name()],
                capture_output=True, text=True, timeout=5,
            )
            return "RUNNING" in result.stdout
        except Exception:
            return False

    def _monitor_loop(self):
        """
        Background thread that polls the actual WireGuard service every 3s.
        Sets _tunnel_active=False the moment the service stops.
        """
        while self._tunnel_active:
            if not self._is_tunnel_running():
                self._log.warning(
                    "WireGuard tunnel service stopped unexpectedly on interface %s.", self.interface
                )
                self._tunnel_active = False
                break
            time.sleep(_MONITOR_POLL)

    # ── Engine interface ─────────────────────────────────────────

    def start(self) -> bool:
        if sys.platform != "win32":
            self._log.error("WireGuard engine requires Windows.")
            return False

        binary = self._find_wireguard()
        if not binary:
            return False  # find_binary() already logs the warning

        if not self.config_file:
            self._log.error(
                "WireGuard config file not set. Run: blackout settings set wg_config_file <path.conf>"
            )
            return False

        cfg_path = Path(self.config_file)
        if not cfg_path.exists():
            self._log.error("WireGuard config file not found: %s", self.config_file)
            return False

        self._log.info(
            "Installing WireGuard tunnel service  interface=%s  config=%s",
            self.interface, cfg_path.name,
        )

        try:
            result = subprocess.run(
                [str(binary), "/installtunnelservice", str(cfg_path.resolve())],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode != 0:
                output = (result.stdout + result.stderr).strip()
                self._log.error(
                    "WireGuard /installtunnelservice failed (rc=%d): %s",
                    result.returncode, output or "(no output)",
                )
                return False

            self._log.debug(
                "Tunnel service registered — waiting for RUNNING state (timeout=%.0fs)", _STARTUP_TIMEOUT
            )

            # Wait for the service to reach RUNNING state
            deadline = time.monotonic() + _STARTUP_TIMEOUT
            while time.monotonic() < deadline:
                if self._is_tunnel_running():
                    break
                time.sleep(0.5)
            else:
                self._log.error(
                    "WireGuard service never reached RUNNING within %.0fs. "
                    "Check your .conf file and ensure interface '%s' is not already active.",
                    _STARTUP_TIMEOUT, self.interface,
                )
                subprocess.run(
                    [str(binary), "/uninstalltunnelservice", self.interface],
                    capture_output=True, timeout=10,
                )
                return False

            self._tunnel_active = True
            self._log.info("WireGuard tunnel UP  interface=%s", self.interface)

            self._monitor_thread = threading.Thread(
                target=self._monitor_loop, daemon=True
            )
            self._monitor_thread.start()
            return True

        except Exception as exc:
            self._log.error("Failed to start WireGuard: %s", exc)
            return False

    def stop(self):
        self._tunnel_active = False  # signals monitor thread to exit
        binary = self._find_wireguard()
        if binary:
            try:
                result = subprocess.run(
                    [str(binary), "/uninstalltunnelservice", self.interface],
                    capture_output=True, timeout=15,
                )
                self._log.debug(
                    "WireGuard tunnel service uninstalled (rc=%d).", result.returncode
                )
            except Exception as exc:
                self._log.warning("Failed to uninstall WireGuard service: %s", exc)
        # WireGuard runs as a Windows service — no child process to kill
        self._process = None

    def is_running(self) -> bool:
        """
        Checks the real WireGuard service status — not a fake sentinel.
        Returns False the moment the tunnel service stops.
        """
        return self._tunnel_active and self._is_tunnel_running()
