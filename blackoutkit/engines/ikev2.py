"""
Blackout Kit - IKEv2 / L2TP/IPSec VPN engine.
Uses Windows built-in VPN client (RAS) — no extra binary needed!
Supports IKEv2 (recommended, fast, NAT-friendly) and L2TP/IPSec.

Requirements:
  - Windows 10/11
  - A VPN server that supports IKEv2 or L2TP/IPSec
  - Administrator privileges (for creating VPN profile)

Configure in settings:
  ikev2_server       — VPN server address
  ikev2_username     — username
  ikev2_password     — password
  ikev2_psk          — pre-shared key (L2TP only)
  ikev2_tunnel_type  — IKEv2 | L2tp | Sstp | Pptp

Rare upgrades:
  - Validates credentials before attempting connection (clear error log)
  - Waits up to 30s for "Connected" status after rasdial succeeds
  - Logs server, tunnel type, and rasdial output on failure
  - is_running() checks live VPN connection status, not just the monitor process
"""
import os
import subprocess
import sys
import time
from .base import Engine

# Name used for the Windows VPN connection profile
VPN_PROFILE_NAME = "BlackoutKit-VPN"

_CONNECT_TIMEOUT = 30.0   # seconds to wait for "Connected" status
_POLL_INTERVAL   = 1.0    # seconds between connection status polls


class IKEv2Engine(Engine):
    name = "ikev2"
    description = "IKEv2 / L2TP/IPSec — Windows built-in VPN (no binary needed)"

    def __init__(self,
                 server: str       = "",
                 username: str     = "",
                 password: str     = "",
                 psk: str          = "",
                 tunnel_type: str  = "IKEv2"):
        super().__init__()
        from .. import settings as cfg
        s = cfg.load()
        self.server      = server      or s.get("ikev2_server",      "")
        self.username    = username    or s.get("ikev2_username",     "")
        self.password    = password    or s.get("ikev2_password",     "")
        self.psk         = psk         or s.get("ikev2_psk",          "")
        self.tunnel_type = tunnel_type or s.get("ikev2_tunnel_type",  "IKEv2")
        self._connected  = False

    # ── Windows VPN helpers ──────────────────────────────────────

    def _ps(self, script: str, env: dict | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8",
            errors="ignore", timeout=30, env=env,
        )

    def _create_profile(self):
        """Create (or overwrite) the Windows VPN profile via PowerShell."""
        self._log.debug(
            "Creating VPN profile '%s'  type=%s  server=%s",
            VPN_PROFILE_NAME, self.tunnel_type, self.server,
        )
        # Pass credentials via env vars to prevent PowerShell injection when
        # passwords or server addresses contain special chars like " or ;
        env = {
            **os.environ,
            "BK_VPN_SERVER":   self.server,
            "BK_VPN_USERNAME": self.username,
            "BK_VPN_PASSWORD": self.password,
            "BK_VPN_PSK":      self.psk,
        }
        # Validate tunnel_type at runtime — settings JSON could be manually edited
        _ALLOWED_TYPES = {"IKEv2", "L2tp", "Sstp", "Pptp"}
        if self.tunnel_type not in _ALLOWED_TYPES:
            self._log.error(
                "Invalid tunnel_type '%s'. Must be one of: %s",
                self.tunnel_type, ", ".join(sorted(_ALLOWED_TYPES)),
            )
            return

        if self.tunnel_type.lower() == "l2tp":
            ps = (
                '$cred = New-Object System.Management.Automation.PSCredential'
                '($env:BK_VPN_USERNAME,'
                '($env:BK_VPN_PASSWORD | ConvertTo-SecureString -AsPlainText -Force));'
                f'Add-VpnConnection -Name "{VPN_PROFILE_NAME}"'
                ' -ServerAddress $env:BK_VPN_SERVER'
                ' -TunnelType L2tp'
                ' -L2tpPsk $env:BK_VPN_PSK'
                ' -AuthenticationMethod MSChapv2'
                ' -RememberCredential $false'
                ' -Force -PassThru | Out-Null'
            )
        else:
            # tunnel_type is validated against allowlist above — safe to interpolate
            ps = (
                f'Add-VpnConnection -Name "{VPN_PROFILE_NAME}"'
                ' -ServerAddress $env:BK_VPN_SERVER'
                f' -TunnelType {self.tunnel_type}'
                ' -AuthenticationMethod MSChapv2'
                ' -EncryptionLevel Required'
                ' -RememberCredential $false'
                ' -Force -PassThru | Out-Null'
            )
        self._ps(ps, env=env)

    def _connect(self) -> tuple[bool, str]:
        """
        Dial the VPN via Connect-VpnConnection with credentials in env vars.
        Avoids passing the password as a rasdial CLI argument (visible in process listing).
        """
        env = {**os.environ, "BK_VPN_USER": self.username, "BK_VPN_PASS": self.password}
        ps = (
            "try {"
            "  $pass = $env:BK_VPN_PASS | ConvertTo-SecureString -AsPlainText -Force;"
            f" Connect-VpnConnection -Name '{VPN_PROFILE_NAME}'"
            "  -UserName $env:BK_VPN_USER -Password $pass -Force;"
            "  Write-Output 'OK'"
            "} catch {"
            "  Write-Error $_.Exception.Message"
            "}"
        )
        result = self._ps(ps, env=env)
        output = (result.stdout + result.stderr).strip()
        return "OK" in result.stdout, output

    def _wait_for_connected(self) -> bool:
        """
        Poll Get-VpnConnection until status is "Connected" or timeout.
        Returns True when connected, False on timeout.
        """
        deadline = time.monotonic() + _CONNECT_TIMEOUT
        self._log.debug(
            "Waiting up to %.0fs for IKEv2 connection to reach 'Connected' state…",
            _CONNECT_TIMEOUT,
        )
        while time.monotonic() < deadline:
            if self._is_connected():
                return True
            time.sleep(_POLL_INTERVAL)
        return False

    def _disconnect(self):
        """Hang up the VPN connection."""
        subprocess.run(
            ["rasdial", VPN_PROFILE_NAME, "/disconnect"],
            capture_output=True, timeout=15,
        )

    def _delete_profile(self):
        self._ps(f'Remove-VpnConnection -Name "{VPN_PROFILE_NAME}" -Force -PassThru | Out-Null')

    def _is_connected(self) -> bool:
        result = self._ps(
            f'(Get-VpnConnection -Name "{VPN_PROFILE_NAME}" -ErrorAction SilentlyContinue)'
            f'.ConnectionStatus'
        )
        return "Connected" in result.stdout

    # ── Engine interface ─────────────────────────────────────────

    def is_running(self) -> bool:
        """
        Override: also check the live VPN connection status in addition to
        the monitor process, since the VPN can drop without killing the process.
        """
        if not super().is_running():
            return False
        return self._is_connected()

    def start(self) -> bool:
        if sys.platform != "win32":
            self._log.error("IKEv2 engine requires Windows.")
            return False

        # Validate required credentials before touching the system
        if not self.server:
            self._log.error(
                "IKEv2 server address is not configured. "
                "Run: blackout settings set ikev2_server <address>"
            )
            return False
        if not self.username:
            self._log.error(
                "IKEv2 username is not configured. "
                "Run: blackout settings set ikev2_username <username>"
            )
            return False

        self._log.info(
            "Starting IKEv2 VPN  server=%s  type=%s  user=%s",
            self.server, self.tunnel_type, self.username,
        )

        self._create_profile()

        ok, output = self._connect()
        if not ok:
            self._log.error(
                "Connect-VpnConnection failed for profile '%s'. Output: %s",
                VPN_PROFILE_NAME, output or "(no output)",
            )
            return False

        # Connection initiated — now wait for the actual "Connected" state
        if not self._wait_for_connected():
            self._log.error(
                "VPN profile initiated but never reached 'Connected' "
                "state within %.0fs. Server may have rejected credentials.",
                _CONNECT_TIMEOUT,
            )
            self._disconnect()
            return False

        self._connected = True
        self._log.info("IKEv2 VPN connected to %s.", self.server)

        # Spawn a monitor subprocess so base.is_running() has a process to poll
        self._process = subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f'while ($true) {{'
             f'  $s = (Get-VpnConnection -Name "{VPN_PROFILE_NAME}" -EA SilentlyContinue).ConnectionStatus;'
             f'  if ($s -ne "Connected") {{ exit 1 }};'
             f'  Start-Sleep 5'
             f'}}'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        return True

    def stop(self):
        self._disconnect()
        super().stop()
        self._delete_profile()
        self._connected = False
        self._log.info("IKEv2 VPN disconnected and profile removed.")
