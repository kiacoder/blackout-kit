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
                capture_output=True, text=True, encoding="utf-8", timeout=30,
            )
        except Exception:
            return None

    @staticmethod
    def _sanitize(val: str) -> str:
        """Strip CR/LF to prevent injecting extra commands into vpncmd stdin."""
        return val.replace("\r", "").replace("\n", "")

    def _is_account_connected(self, check_cert: bool = False) -> bool:
        """
        Ask vpncmd for the real account connection status.
        AccountStatusGet returns "Session Status: Connected" when live.
        Optionally performs a proactive TLS certificate check to update the cert store.
        """
        # Proactive cert check for the cert store (Task #12 integration)
        if check_cert and self.host:
            from .. import cert_bypass as cb
            # Run in background to avoid blocking the vpncmd call
            threading.Thread(
                target=cb.check_host_cert,
                args=(self.host, self.port),
                kwargs={"timeout": 5.0},
                daemon=True,
            ).start()

        result = self._vpncmd(f"AccountStatusGet {SE_ACCOUNT_NAME}")
        if result is None:
            return False
        output = result.stdout + result.stderr
        # Use exact phrase — "Connected" is a substring of "Disconnected",
        # so checking only "Connected" in output always returns True.
        return "Session Status: Connected" in output

    def _monitor_loop(self):
        """
        Background thread that polls account status every 5s.
        Sets _connected=False only after 3 consecutive failures — tolerates
        transient vpncmd errors without falsely reporting a disconnect.
        """
        consecutive_failures = 0
        while self._connected:
            if not self._is_account_connected():
                consecutive_failures += 1
                if consecutive_failures >= 3:
                    self._connected = False
                    break
            else:
                consecutive_failures = 0
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
            # Track with Popen so stop() can kill it properly
            self._process = subprocess.Popen(
                [str(client), "start"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            try:
                self._process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)
                return False
            self._process = None  # vpnclient runs as a service, not a child
            time.sleep(2)  # Let service initialize

            # Sanitize values — newlines in any field would inject extra vpncmd commands
            host     = self._sanitize(self.host)
            hub      = self._sanitize(self.hub)
            username = self._sanitize(self.username)
            password = self._sanitize(self.password)

            # Create + connect the account
            r = self._vpncmd(
                f"AccountCreate {SE_ACCOUNT_NAME}"
                f" /SERVER:{host}:{self.port}"
                f" /HUB:{hub}"
                f" /USERNAME:{username}"
                f" /NICNAME:VPN",
                f"AccountPasswordSet {SE_ACCOUNT_NAME}"
                f" /PASSWORD:{password} /TYPE:standard",
                f"AccountConnect {SE_ACCOUNT_NAME}",
            )

            if r is None:
                return False

            # Wait up to 15s for the connection to establish
            for _ in range(15):
                if self._is_account_connected(check_cert=True):
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
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
            self._monitor_thread = None
        self._vpncmd(
            f"AccountDisconnect {SE_ACCOUNT_NAME}",
            f"AccountDelete {SE_ACCOUNT_NAME}",
        )
        client = self._find_client()
        if client:
            try:
                proc = subprocess.Popen([str(client), "stop"],
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL,
                                        creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            except Exception:
                pass
        self._process = None

    def is_running(self) -> bool:
        """
        Returns the real connection status from vpncmd — not a fake ping.
        """
        return self._connected
