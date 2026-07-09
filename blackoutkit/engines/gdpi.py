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

        # Verify WinDivert DLLs are present alongside the binary
        windivert_dll = binary.parent / "WinDivert.dll"
        windivert_sys = binary.parent / "WinDivert64.sys"
        if not windivert_dll.exists() or not windivert_sys.exists():
            self._log.error(
                "WinDivert DLLs not found next to goodbyedpi.exe. "
                "Run: blackout bins download goodbyedpi"
            )
            return False

        # Check admin rights — GoodbyeDPI always needs them
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                self._log.error(
                    "GoodbyeDPI requires Administrator privileges (WinDivert kernel driver). "
                    "Restart terminal as Admin and try again."
                )
                return False
        except Exception:
            pass

        self._log.info("Starting GoodbyeDPI  flags=%s", " ".join(self.flags))

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
            self._log.error(
                "GoodbyeDPI exited immediately (rc=%s). "
                "Try running as Administrator. If that fails: blackout doctor --fix",
                self._process.returncode,
            )
            return False

        self._log.info("GoodbyeDPI is running (pid=%s).", self._process.pid)
        return True
