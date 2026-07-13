"""
Blackout Kit - GoodbyeDPI engine.
Wraps ValdikSS's GoodbyeDPI binary.
Uses TCP fragmentation and packet manipulation to bypass DPI.
Does not require a separate proxy — works at the network level.

Auto-elevation: if running from a non-admin terminal, the engine launches
powershell.exe elevated via UAC, which then spawns goodbyedpi.exe with
full admin rights. The CLI stays in the normal terminal.
"""
import os
import subprocess
import tempfile
import time
from pathlib import Path

from .base import Engine, BINS_DIR
from .. import settings as cfg
from ..elevate import launch_elevated

GDPI_BIN_NAMES = [
    "goodbyedpi.exe",
    "goodbyedpi-x86_64.exe",
]


class GoodbyeDPIEngine(Engine):
    name = "gdpi"
    description = "GoodbyeDPI TCP fragmentation — lightweight, no proxy needed"

    def __init__(self, flags: str | None = None):
        super().__init__()
        raw = flags or cfg.get("gdpi_flags") or "-5"
        self.flags: list[str] = raw.split()
        self._elevated_pid: int | None = None
        self._elevated_handle: int | None = None
        self._pid_file: Path | None = None

    def start(self) -> bool:
        binary = self.find_binary(GDPI_BIN_NAMES)
        if not binary:
            return False

        windivert_dll = binary.parent / "WinDivert.dll"
        windivert_sys = binary.parent / "WinDivert64.sys"
        if not windivert_dll.exists() or not windivert_sys.exists():
            self._log.error(
                "WinDivert DLLs not found next to goodbyedpi.exe. "
                "Run: blackout bins download goodbyedpi"
            )
            return False

        # Attempt to kill any lingering zombies before starting
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "goodbyedpi.exe"],
                capture_output=True, timeout=3,
            )
        except Exception:
            pass

        self._log.info("Starting GoodbyeDPI  flags=%s", " ".join(self.flags))

        if self._try_direct_launch(binary):
            return True

        self._log.info("Direct launch failed — requesting elevation via UAC…")
        return self._try_elevated_launch(binary)

    def _try_direct_launch(self, binary) -> bool:
        try:
            self._process = subprocess.Popen(
                [str(binary)] + self.flags,
                cwd=str(binary.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
        except OSError as exc:
            self._log.error("Failed to launch GoodbyeDPI: %s", exc)
            return False

        time.sleep(0.8)
        if self.check_process_alive():
            self._log.info("GoodbyeDPI is running (pid=%s).", self._process.pid)
            return True

        self._log.info("GoodbyeDPI exited (rc=%s) — likely missing admin rights.", self._process.returncode)
        self._process = None
        return False

    def _try_elevated_launch(self, binary) -> bool:
        self._pid_file = Path(tempfile.mktemp(suffix=".bkpid", prefix="gdpi_"))
        pid_file_str = str(self._pid_file)
        binary_str = str(binary)
        args_str = subprocess.list2cmdline(self.flags)

        cwd_str = str(binary.parent)
        ps_cmd = (
            f"taskkill /F /IM goodbyedpi.exe 2>$null; "
            f"Start-Sleep -Milliseconds 500; "
            f"$p = Start-Process -FilePath '{binary_str}' -WorkingDirectory '{cwd_str}' "
            f"-ArgumentList '{args_str}' -Verb RunAs -WindowStyle Hidden -PassThru; "
            f"$p.Id | Out-File -FilePath '{pid_file_str}' -Encoding UTF8"
        )

        try:
            subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            pass
        except Exception as exc:
            self._log.error("Elevation launch failed: %s", exc)
            return False

        time.sleep(1.0)

        if self._pid_file.exists():
            try:
                raw = self._pid_file.read_text(encoding="utf-8-sig").strip()
                pid = int(raw)
                self._elevated_pid = pid
                self._log.info("GoodbyeDPI running elevated (pid=%s).", pid)
                return True
            except (ValueError, OSError) as exc:
                self._log.error("Failed to read/parse PID file: %s", exc)

        self._log.error("UAC elevation was denied or failed — PID file not found.")
        return False

    def stop(self):
        if self._elevated_pid is not None:
            killed_with_psutil = False
            try:
                import psutil
                try:
                    proc = psutil.Process(self._elevated_pid)
                    proc.terminate()
                    proc.wait(timeout=3)
                    killed_with_psutil = True
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                    pass
            except ImportError:
                pass
            
            if not killed_with_psutil:
                # Need elevation to kill an elevated process if psutil access was denied
                subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-Command",
                        f"Start-Process taskkill -ArgumentList '/F /PID {self._elevated_pid}' -Verb RunAs -WindowStyle Hidden"
                    ],
                    capture_output=True,
                    timeout=5,
                )
            self._elevated_pid = None

        if self._elevated_handle is not None:
            import ctypes
            ctypes.windll.kernel32.TerminateProcess(self._elevated_handle, 0)
            ctypes.windll.kernel32.CloseHandle(self._elevated_handle)
            self._elevated_handle = None

        if self._pid_file is not None:
            try:
                self._pid_file.unlink(missing_ok=True)
            except Exception:
                pass
            self._pid_file = None

        if self._elevated_handle is None and self._elevated_pid is None:
            super().stop()

        self._cleanup_config_dir()

    def is_running(self) -> bool:
        if self._elevated_pid is not None:
            try:
                import psutil
                return psutil.Process(self._elevated_pid).is_running()
            except (ImportError, psutil.NoSuchProcess):
                pass
            try:
                subprocess.run(
                    ["tasklist", "/FI", f"PID eq {self._elevated_pid}"],
                    capture_output=True, timeout=5, check=False,
                )
            except Exception:
                pass
        if self._elevated_handle is not None:
            import ctypes
            if sys.platform == 'win32':
                from ctypes import wintypes
                exit_code = wintypes.DWORD()
            else:
                exit_code = ctypes.c_uint32()
            if ctypes.windll.kernel32.GetExitCodeProcess(self._elevated_handle, ctypes.byref(exit_code)):
                return exit_code.value == 259
        return super().is_running()

    def check_process_alive(self) -> bool:
        if self._elevated_pid is not None:
            try:
                import psutil
                alive = psutil.Process(self._elevated_pid).is_running()
                if not alive:
                    self._log.warning("Elevated GoodbyeDPI exited unexpectedly.")
                return alive
            except (ImportError, psutil.NoSuchProcess):
                return False
        if self._elevated_handle is not None:
            import ctypes
            if sys.platform == 'win32':
                from ctypes import wintypes
                exit_code = wintypes.DWORD()
            else:
                exit_code = ctypes.c_uint32()
            if ctypes.windll.kernel32.GetExitCodeProcess(self._elevated_handle, ctypes.byref(exit_code)):
                alive = exit_code.value == 259
                if not alive:
                    self._log.warning("Elevated GoodbyeDPI exited unexpectedly.")
                return alive
            return False
        return super().check_process_alive()

    @property
    def pid(self) -> int | None:
        if self._elevated_pid is not None:
            return self._elevated_pid
        return super().pid
