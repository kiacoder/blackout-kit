"""
Blackout Kit - OpenVPN engine.
Wraps openvpn.exe (community edition) for maximum compatibility.

OpenVPN is battle-tested, widely supported, and can tunnel over TCP port 443
to bypass firewalls that block UDP.

Requirements:
  - openvpn.exe in bins/  OR  OpenVPN installed at default path
  - A .ovpn config file (set in settings: openvpn_config)

Settings:
  openvpn_config  — Full path to your .ovpn config file

Download OpenVPN: https://openvpn.net/community-downloads/
Or use a provider that gives you .ovpn files.
"""
import logging
import subprocess
import sys
import time
from pathlib import Path
from .base import Engine, BINS_DIR

OVPN_BIN_NAMES   = ["openvpn.exe"]
SYSTEM_OVPN      = Path("C:/Program Files/OpenVPN/bin/openvpn.exe")
LOG_PATH         = BINS_DIR / "openvpn.log"
_STARTUP_TIMEOUT = 30.0   # OpenVPN handshake can take a while

# OpenVPN logs this line when the tunnel is fully up
CONNECTED_MARKER = "Initialization Sequence Completed"

# Any of these in the log mean the connection failed
FAILED_MARKERS = [
    "AUTH_FAILED",
    "TLS Error",
    "Connection refused",
    "SIGTERM",
    "connect: Network is unreachable",
    "RESOLVE: Cannot resolve host address",
    "Inactivity timeout",
    "process exiting",
    # NOTE: "read UDPv4" removed — it appears in normal log output during UDP
    # data transfer and would cause false failure detection on every UDP session.
]


class OpenVPNEngine(Engine):
    name = "openvpn"
    description = "OpenVPN — battle-tested TLS-based VPN, works over TCP:443"

    def __init__(self, config_file: str = ""):
        super().__init__()
        from .. import settings as cfg
        s = cfg.load()
        self.config_file = config_file or s.get("openvpn_config", "")
        self._log = logging.getLogger(__name__).getChild(self.name)

    # ── Helpers ──────────────────────────────────────────────────

    def _find_openvpn(self) -> Path | None:
        binary = self.find_binary(OVPN_BIN_NAMES)
        if binary:
            return binary
        if SYSTEM_OVPN.exists():
            return SYSTEM_OVPN
        return None

    def _wait_for_connected(self, timeout: float = _STARTUP_TIMEOUT) -> tuple[bool, str]:
        """
        Watch the OpenVPN log file until the tunnel comes up, a failure marker
        appears, or the process exits.
        Returns (success, failure_reason) — reason is empty string on success.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._process and self._process.poll() is not None:
                return False, f"process exited (rc={self._process.returncode})"

            if LOG_PATH.exists():
                try:
                    content = LOG_PATH.read_text(encoding="utf-8", errors="replace")
                    if CONNECTED_MARKER in content:
                        # Extract remote host for cert store (Task #12 integration)
                        self._update_cert_store(content)
                        return True, ""
                    for marker in FAILED_MARKERS:
                        if marker in content:
                            return False, marker
                except Exception:
                    pass

            time.sleep(0.5)

        return False, f"timed out after {timeout:.0f}s"

    def is_running(self) -> bool:
        """
        Checks both that the process is alive AND the log doesn't show a disconnect.
        Catches cases where openvpn.exe stays alive but the tunnel is actually down.

        Only checks for SIGTERM/exit markers that appear AFTER the last successful
        connection marker — prevents stale markers from a previous session triggering
        a false "not running" result.
        """
        if not super().is_running():
            return False
        if LOG_PATH.exists():
            try:
                content = LOG_PATH.read_text(encoding="utf-8", errors="replace")
                # Find the position of the last successful connection in the log
                last_ok = content.rfind(CONNECTED_MARKER)
                # Only scan for failure markers that appeared AFTER the last connection
                scan = content[last_ok:] if last_ok >= 0 else content
                if "SIGTERM" in scan or "process exiting" in scan:
                    return False
            except Exception:
                pass
        return True

    # ── Engine interface ─────────────────────────────────────────

    def start(self) -> bool:
        if sys.platform != "win32":
            self._log.error("OpenVPN engine requires Windows.")
            return False

        binary = self._find_openvpn()
        if not binary:
            return False  # find_binary() already logs the warning

        if not self.config_file:
            self._log.error(
                "OpenVPN config not set. Run: blackout settings set openvpn_config <path.ovpn>"
            )
            return False

        cfg_path = Path(self.config_file)
        if not cfg_path.exists():
            self._log.error("OpenVPN config file not found: %s", self.config_file)
            return False

        self._log.info("Starting OpenVPN  config=%s", cfg_path.name)

        try:
            LOG_PATH.write_text("")
        except Exception:
            pass

        try:
            self._process = subprocess.Popen(
                [
                    str(binary),
                    "--config", str(cfg_path.resolve()),
                    "--log",    str(LOG_PATH),
                    "--verb",   "3",
                ],
                cwd=str(binary.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            self._log.debug(
                "OpenVPN launched (pid=%s) — waiting for tunnel up (timeout=%.0fs)",
                self._process.pid, _STARTUP_TIMEOUT,
            )
        except Exception as exc:
            self._log.error("Failed to launch OpenVPN: %s", exc)
            return False

        connected, reason = self._wait_for_connected()
        if not connected:
            self._log.error("OpenVPN tunnel failed: %s", reason)
            self.stop()
            return False

        self._log.info("OpenVPN tunnel UP (pid=%s).", self._process.pid)
        return True

    def _update_cert_store(self, log_content: str):
        """Parse the remote host from the OpenVPN log and run a cert probe."""
        # OpenVPN logs lines like: "Attempting to establish TCP connection with [AF_INET]1.2.3.4:443"
        # or "TCP connection established with [AF_INET]1.2.3.4:443"
        import re
        from .. import cert_bypass as cb
        match = re.search(r"connection established with \[AF_INET\]([\d\.]+):(\d+)", log_content)
        if match:
            host, port = match.group(1), int(match.group(2))
            threading.Thread(
                target=cb.check_host_cert,
                args=(host, port),
                kwargs={"timeout": 5.0},
                daemon=True,
            ).start()
