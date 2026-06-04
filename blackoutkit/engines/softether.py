"""
Blackout Kit - SoftEther VPN engine.
Wraps SoftEther VPN Client (vpnclient.exe + vpncmd.exe).

SoftEther supports SSL-VPN, L2TP/IPsec, OpenVPN, L2TPv3, EtherIP.
The SSL-VPN mode mimics HTTPS and is extremely hard to block.

Requirements:
  - SoftEther VPN Client installed  OR  vpnclient.exe + vpncmd.exe in bins/
  - VPN server details (host, hub, username, password)

Settings:
  softether_host      — SoftEther VPN server hostname or IP
  softether_port      — Server port (default 443 for SSL-VPN)
  softether_hub       — Virtual Hub name (e.g. "VPN")
  softether_username  — Account username
  softether_password  — Account password

Download SoftEther: https://www.softether.org/5-download
"""
import subprocess
import sys
import threading
import time
from pathlib import Path
from .base import Engine, BINS_DIR

SE_BIN_NAMES    = ["vpnclient.exe"]
SE_CMD_NAMES    = ["vpncmd.exe"]
SYSTEM_SE_DIR   = Path("C:/Program Files/SoftEther VPN Client")
SE_ACCOUNT_NAME = "BlackoutKit"


class SoftEtherEngine(Engine):
    name = "softether"
    description = "SoftEther VPN — SSL-VPN that looks like HTTPS, very hard to block"

    def __init__(self,
                 host: str = "", port: int = 0,
                 hub: str = "", username: str = "", password: str = ""):
        super().__init__()
        from .. import settings as cfg
        s = cfg.load()
        self.host     = host     or s.get("softether_host",     "")
        self.port     = port     or s.get("softether_port",     443)
        self.hub      = hub      or s.get("softether_hub",      "VPN")
        self.username = username or s.get("softether_username", "")
        self.password = password or s.get("softether_password", "")
        self._connected       = False
        self._monitor_thread: threading.Thread | None = None

    # ── Binary finders ───────────────────────────────────────────

    def _find_client(self) -> Path | None:
        for name in SE_BIN_NAMES:
            p = BINS_DIR / name
            if p.exists():
                return p
        p = SYSTEM_SE_DIR / "vpnclient.exe"
        if p.exists():
            return p
        return None

    def _find_cmd(self) -> Path | None:
        for name in SE_CMD_NAMES:
            p = BINS_DIR / name
            if p.exists():
                return p
        p = SYSTEM_SE_DIR / "vpncmd.exe"
        if p.exists():
            return p
        return None

    # ── vpncmd wrappers ──────────────────────────────────────────

    def _vpncmd(self, *commands: str) -> subprocess.CompletedProcess | None:
        """Send management commands to the VPN client via vpncmd stdin pipe."""
        cmd_bin = self._find_cmd()
        if not cmd_bin:
            return None
        script = "\r\n".join(list(commands) + ["exit"])
        try:
            return subprocess.run(
                [str(cmd_bin), "localhost", "/CLIENT", "/CMD"],
                input=script,
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            return None

    def _is_account_connected(self) -> bool:
        """
        Ask vpncmd for the real account connection status.
        AccountStatusGet returns "Session Status: Connected" when live.
        """
        result = self._vpncmd(f"AccountStatusGet {SE_ACCOUNT_NAME}")
        if result is None:
            return False
        output = result.stdout + result.stderr
        return (
            "Connected" in output
            or "Session Status" in output
            and "Disconnected" not in output
        )

    def _monitor_loop(self):
        """
        Background thread that polls account status every 5s.
        Sets _connected=False the moment the VPN disconnects.
        """
        while self._connected:
            if not self._is_account_connected():
                self._connected = False
                break
            time.sleep(5)

    # ── Engine interface ─────────────────────────────────────────

    def start(self) -> bool:
        if sys.platform != "win32":
            return False

        client = self._find_client()
        if not client:
            return False

        if not self.host or not self.username:
            return False

        try:
            # Start the VPN client service (idempotent if already running)
            subprocess.run(
                [str(client), "start"],
                capture_output=True, timeout=15,
            )
            time.sleep(2)  # Let service initialize

            # Create + connect the account
            r = self._vpncmd(
                f"AccountCreate {SE_ACCOUNT_NAME}"
                f" /SERVER:{self.host}:{self.port}"
                f" /HUB:{self.hub}"
                f" /USERNAME:{self.username}"
                f" /NICNAME:VPN",
                f"AccountPasswordSet {SE_ACCOUNT_NAME}"
                f" /PASSWORD:{self.password} /TYPE:standard",
                f"AccountConnect {SE_ACCOUNT_NAME}",
            )

            if r is None:
                return False

            # Wait up to 15s for the connection to establish
            for _ in range(15):
                if self._is_account_connected():
                    break
                time.sleep(1)
            else:
                return False  # Never connected

            self._connected = True

            # Start REAL monitoring thread — polls actual connection state
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop, daemon=True
            )
            self._monitor_thread.start()
            return True

        except Exception:
            return False

    def stop(self):
        self._connected = False  # Signals monitor thread to exit
        self._vpncmd(
            f"AccountDisconnect {SE_ACCOUNT_NAME}",
            f"AccountDelete {SE_ACCOUNT_NAME}",
        )
        client = self._find_client()
        if client:
            try:
                subprocess.run([str(client), "stop"], capture_output=True, timeout=15)
            except Exception:
                pass
        self._process = None

    def is_running(self) -> bool:
        """
        Returns the real connection status from vpncmd — not a fake ping.
        """
        return self._connected
