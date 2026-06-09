"""
Blackout Kit - GoodbyeDPI engine.
Wraps ValdikSS's GoodbyeDPI binary.
Uses TCP fragmentation and packet manipulation to bypass DPI.
Does not require a separate proxy — works at the network level.

Rare upgrades:
  - Logs binary path + flags on start
  - Crash-detection: polls process after 0.5s (catches missing WinDivert DLL)
  - Logs stderr output when the process exits unexpectedly fast
"""
import subprocess
import time
from .base import Engine, BINS_DIR
from .. import settings as cfg

GDPI_BIN_NAMES = [
    "goodbyedpi.exe",
    "goodbyedpi-x86_64.exe",
]


class GoodbyeDPIEngine(Engine):
    name = "gdpi"
    description = "GoodbyeDPI TCP fragmentation — lightweight, no proxy needed"

    def __init__(self, flags: str | None = None):
        super().__init__()
        raw = flags or cfg.get("gdpi_flags") or "-9"
        # Split flags string into list (e.g. "-9" → ["-9"], "-p -r" → ["-p", "-r"])
        self.flags: list[str] = raw.split()

    def start(self) -> bool:
        binary = self.find_binary(GDPI_BIN_NAMES)
        if not binary:
            return False

        self._log.info("Starting GoodbyeDPI  flags=%s", " ".join(self.flags))

        # WinDivert DLL must be in the same folder as goodbyedpi.exe
        try:
            self._process = subprocess.Popen(
                [str(binary)] + self.flags,
                cwd=str(binary.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except Exception as exc:
            self._log.error("Failed to launch GoodbyeDPI: %s", exc)
            return False

        # GoodbyeDPI exits almost instantly if WinDivert is missing or access is denied.
        # Give it 0.5 s and check that it is still alive.
        time.sleep(0.5)
        if not self.check_process_alive():
            # Capture any stderr output to help diagnose the crash
            try:
                stderr_output = self._process.stderr.read(512).decode(errors="replace").strip()
            except Exception:
                stderr_output = ""
            if stderr_output:
                self._log.error("GoodbyeDPI crashed immediately. stderr: %s", stderr_output)
            else:
                self._log.error(
                    "GoodbyeDPI exited immediately (rc=%s). "
                    "WinDivert DLL missing or not running as Administrator?",
                    self._process.returncode,
                )
            return False

        self._log.info("GoodbyeDPI is running (pid=%s).", self._process.pid)
        return True
