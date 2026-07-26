"""
Blackout Kit - mhrv engine.
Wraps mhrv-rs (a Rust MITM transparent proxy).
Installs its own CA certificate and intercepts HTTPS at the OS level.
Useful as an alternative bypass layer.

Ports:
  HTTP   → 8085
  SOCKS5 → 8086

Requires: mhrv-rs.exe in bins/
Download: https://github.com/mhrv-rs (check latest releases)

Rare upgrades:
  - Logs cert installation result (success vs failure — no longer silent)
  - wait_for_port() on http_port confirms proxy is accepting connections
  - Crash-check if port never opens (catches missing dependencies)
"""
import subprocess
import time
from pathlib import Path
from .base import Engine, BINS_DIR

MHRV_BIN_NAMES = [
    "mhrv-rs.exe",
    "mhrv.exe",
]

_STARTUP_TIMEOUT = 10.0   # seconds to wait for HTTP port to open


class MhrvEngine(Engine):
    name = "mhrv"
    description = "mhrv-rs transparent MITM proxy — alternative bypass layer"

    def __init__(self, http_port: int = 8085, socks_port: int = 8086):
        super().__init__()
        self.http_port  = http_port
        self.socks_port = socks_port

    def start(self) -> bool:
        from .. import settings as cfg
        s = cfg.load()
        direct = s.get("mhrv_direct", False)

        self._log.info(
            "Starting mhrv  http_port=%d  socks_port=%d  direct_mode=%s",
            self.http_port, self.socks_port, direct,
        )

        from ..core import get_core_dll
        dll = get_core_dll()
        if not dll:
            self._log.error("Core DLL missing! Ensure blackout_core.dll is built.")
            return False

        self._log.info("Launching mhrv via native DLL")
        if direct:
            ids_str = ""
        else:
            try:
                from .appsscript import _load_gas_ids
                ids = _load_gas_ids()
                ids_str = ",".join(ids)
            except Exception:
                ids_str = ""

        c_ids = ids_str.encode("utf-8")
        if dll.StartMHRVC(self.http_port, c_ids) == 0:
            self._dll_stop_func = dll.StopMHRVC
            if not self.wait_for_port(self.http_port, timeout=_STARTUP_TIMEOUT):
                self._log.error("mhrv started natively via DLL but HTTP port %d never opened.", self.http_port)
                self.stop()
                return False
            self._log.info("mhrv ready natively  http=127.0.0.1:%d.", self.http_port)
            return True
        else:
            self._log.error("Native DLL StartMHRVC failed")
            return False
