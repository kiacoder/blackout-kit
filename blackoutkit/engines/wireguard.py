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
import time
from pathlib import Path
from .base import Engine
from .. import settings as cfg

_STARTUP_TIMEOUT = 5.0

class WireGuardEngine(Engine):
    name = "wireguard"
    description = "WireGuard — fast, modern, kernel-level UDP VPN (Native)"

    def __init__(self, config_file: str = "", interface: str = ""):
        super().__init__()
        s = cfg.load()
        self.config_file = config_file or s.get("wg_config_file", "")
        self.interface = interface or s.get("wg_interface", "wg0")
        self.socks_port = s.get("proxy_port", 10809)  # Assuming SOCKS output here?
        self._log = logging.getLogger(__name__).getChild(self.name)

    def start(self) -> bool:
        if not self.config_file:
            self._log.error("WireGuard config file not set. Run: blackout settings set wg_config_file <path.conf>")
            return False

        cfg_path = Path(self.config_file)
        if not cfg_path.exists():
            self._log.error("WireGuard config file not found: %s", self.config_file)
            return False

        self._log.info("Starting pure native WireGuard  interface=%s  config=%s", self.interface, cfg_path.name)

        from ..core import get_core_dll
        dll = get_core_dll()
        if not dll:
            self._log.error("Core DLL missing! Ensure blackout_core.dll is built.")
            return False

        c_config_path = str(cfg_path.absolute()).encode("utf-8")
        if dll.StartWireGuardC(c_config_path, self.socks_port) == 0:
            self._dll_stop_func = dll.StopWireGuardC
            if not self.wait_for_port(self.socks_port, timeout=_STARTUP_TIMEOUT):
                self._log.error("WireGuard natively via DLL timed out.")
                self.stop()
                return False
            self._log.info("WireGuard ready natively  socks=127.0.0.1:%d", self.socks_port)
            return True
        else:
            self._log.error("Native DLL StartWireGuardC failed")
            return False
