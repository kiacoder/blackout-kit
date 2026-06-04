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
        binary = self.find_binary(MHRV_BIN_NAMES)
        if not binary:
            return False

        self._log.info(
            "Starting mhrv  http_port=%d  socks_port=%d",
            self.http_port, self.socks_port,
        )

        # Install CA cert — required for MITM interception to work.
        # This must run before the proxy starts so the cert is trusted.
        self._log.debug("Installing mhrv CA certificate…")
        try:
            cert_result = subprocess.run(
                [str(binary), "--install-cert"],
                cwd=str(binary.parent),
                capture_output=True,
                timeout=15,
            )
            if cert_result.returncode == 0:
                self._log.debug("CA certificate installed successfully.")
            else:
                # Non-fatal: cert may already be installed from a previous run
                stderr = cert_result.stderr.decode(errors="replace").strip()
                self._log.warning(
                    "CA cert install returned rc=%d. "
                    "It may already be installed (continuing). stderr: %s",
                    cert_result.returncode, stderr or "(none)",
                )
        except Exception as exc:
            self._log.warning("CA cert install failed (non-fatal): %s", exc)

        # Short pause to let the certificate store update propagate
        time.sleep(0.5)

        try:
            self._process = subprocess.Popen(
                [str(binary)],
                cwd=str(binary.parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except Exception as exc:
            self._log.error("Failed to launch mhrv: %s", exc)
            return False

        # Wait for the HTTP proxy port to accept connections
        if not self.wait_for_port(self.http_port, timeout=_STARTUP_TIMEOUT):
            if not self.check_process_alive():
                self._log.error(
                    "mhrv exited before HTTP port %d opened (rc=%s). "
                    "Missing Rust runtime or CA cert issue?",
                    self.http_port, self._process.returncode,
                )
            else:
                self._log.error(
                    "mhrv started but HTTP port %d never opened within %.0fs.",
                    self.http_port, _STARTUP_TIMEOUT,
                )
            self.stop()
            return False

        self._log.info(
            "mhrv ready  http=127.0.0.1:%d  socks=127.0.0.1:%d  (pid=%s).",
            self.http_port, self.socks_port, self._process.pid,
        )
        return True
