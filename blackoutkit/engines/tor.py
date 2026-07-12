"""
Blackout Kit - Tor engine.
Routes traffic through the Tor anonymity network.
Best for maximum anonymity, slower than other engines.
Exposes SOCKS5 on port 9050 (standard Tor port).

Requires tor.exe (Expert Bundle) in bins/.
Download: https://www.torproject.org/download/tor/

Rare upgrades:
  - Logs torrc path and socks_port on start
  - wait_for_port() confirms Tor is bootstrapped and listening before returning True
  - 60-second timeout because Tor must build circuits before the SOCKS port opens
  - Crash-check if port never opens (missing DLL, permission denied, etc.)
"""
import subprocess
from pathlib import Path
from .base import Engine, BINS_DIR

TOR_BIN_NAMES = [
    "tor.exe",
    "Tor\\tor.exe",
]

_STARTUP_TIMEOUT = 60.0   # Tor bootstrap (building circuits) takes 15-60 s


class TorEngine(Engine):
    name = "tor"
    description = "Tor onion network — maximum anonymity, slower speed"

    def __init__(self, socks_port: int = 9050):
        super().__init__()
        self.socks_port = socks_port

    def _write_torrc(self, torrc_path: Path):
        config = (
            f"SocksPort {self.socks_port}\n"
            f"ControlPort 9051\n"
            f"DNSPort 5353\n"
            f"AutomapHostsOnResolve 1\n"
        )
        torrc_path.write_text(config)

    def start(self) -> bool:
        # Search for tor.exe directly in bins/ or in bins/Tor/
        binary = None
        for name in TOR_BIN_NAMES:
            path = BINS_DIR / name
            if path.exists():
                binary = path
                break

        if not binary:
            self._log.warning("Tor binary not found in bins/ — tried: %s", TOR_BIN_NAMES)
            return False

        torrc = binary.parent / "torrc"
        self._write_torrc(torrc)

        self._log.info(
            "Starting Tor  socks_port=%d  torrc=%s",
            self.socks_port, torrc,
        )

        try:
            subprocess.run(["taskkill", "/F", "/IM", "tor.exe"], capture_output=True, timeout=3)
        except Exception:
            pass

        try:
            self._process = subprocess.Popen(
                [str(binary), "-f", str(torrc)],
                cwd=str(binary.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except Exception as exc:
            self._log.error("Failed to launch Tor: %s", exc)
            return False

        # Tor must bootstrap (build circuits) before the SOCKS port opens.
        # This typically takes 15-60 s; we wait up to 60 s.
        self._log.debug(
            "Waiting up to %.0fs for Tor SOCKS port %d (circuit bootstrap)…",
            _STARTUP_TIMEOUT, self.socks_port,
        )
        if not self.wait_for_port(self.socks_port, timeout=_STARTUP_TIMEOUT):
            if not self.check_process_alive():
                self._log.error(
                    "Tor exited before SOCKS port %d opened (rc=%s). "
                    "Missing DLL or not running as Administrator?",
                    self.socks_port, self._process.returncode,
                )
            else:
                self._log.error(
                    "Tor is running but SOCKS port %d never opened within %.0fs "
                    "(network may be too restricted for Tor to bootstrap).",
                    self.socks_port, _STARTUP_TIMEOUT,
                )
            self.stop()
            return False

        self._log.info(
            "Tor bootstrapped  socks5=127.0.0.1:%d  (pid=%s).",
            self.socks_port, self._process.pid,
        )
        return True
