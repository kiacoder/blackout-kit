"""
Blackout Kit - SNI Spoofing engine.
Wraps patterniha's SNI-Spoofing binary.
Injects a fake TLS ClientHello to fool DPI,
while relaying the real connection to a Cloudflare IP.

Rare upgrades:
  - Logs config params (connect_ip, fake_sni, listen_port) on start
  - wait_for_port() confirms the listener is accepting connections before returning True
  - Crash-check if the port never opens (process may have exited with an error)
"""
import json
import subprocess
from pathlib import Path
from .base import Engine
from .. import settings as cfg

SNI_BIN_NAMES = [
    "sni-spoofing.exe",
    "SNI-Spoofing_by_patterniha_v1.exe",
    "sni-spoof.exe",
    "sni.exe",
]

_STARTUP_TIMEOUT = 10.0   # seconds to wait for port to open


class SNIEngine(Engine):
    name = "sni"
    description = "SNI packet injection (patterniha method) — most effective against DPI"

    def __init__(self,
                 connect_ip: str | None = None,
                 fake_sni: str | None = None,
                 listen_port: int | None = None):
        super().__init__()
        s = cfg.load()
        self.connect_ip  = connect_ip  or s["sni_connect_ip"]
        self.fake_sni    = fake_sni    or s["sni_fake_sni"]
        self.listen_port = listen_port or s["sni_listen_port"]
        self._health_check_addr = ("127.0.0.1", self.listen_port)

    def _write_config(self) -> Path:
        config = {
            "LISTEN_HOST":  "0.0.0.0",
            "LISTEN_PORT":  self.listen_port,
            "CONNECT_IP":   self.connect_ip,
            "CONNECT_PORT": 443,
            "FAKE_SNI":     self.fake_sni,
        }
        path = self._config_dir / "config.json"
        path.write_text(json.dumps(config, indent=2))
        return path

    def start(self) -> bool:
        self._log.info(
            "Starting SNI spoofer  connect_ip=%s  fake_sni=%s  listen_port=%d",
            self.connect_ip, self.fake_sni, self.listen_port,
        )

        config_path = self._write_config()
        self._log.debug("Config written to %s", config_path)

        from ..core import get_core_dll
        dll = get_core_dll()
        if not dll:
            self._log.error("Core DLL missing! Ensure blackout_core.dll is built.")
            return False

        self._log.info("Launching SNI spoofer via native DLL")
        c_path = str(config_path).encode("utf-8")
        if dll.StartSNIC(c_path) == 0:
            self._dll_stop_func = dll.StopSNIC
            if not self.wait_for_port(self.listen_port, timeout=_STARTUP_TIMEOUT):
                self._log.error("SNI spoofer started via DLL but port %d never opened.", self.listen_port)
                self.stop()
                return False
            self._log.info("SNI spoofer ready natively on port %d.", self.listen_port)
            return True
        else:
            self._log.error("Native DLL StartSNIC failed")
            return False
