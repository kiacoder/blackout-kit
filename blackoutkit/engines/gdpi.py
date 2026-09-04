"""
Blackout Kit - GoodbyeDPI engine.
Supports two backends:
  - legacy: wraps ValdikSS's goodbyedpi.exe with modeset probing and elevation fallback
  - native: experimental Go/WinDivert implementation via blackout_core.dll
"""
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .. import core
from .. import settings as cfg
from .base import BINS_DIR, Engine

GDPI_BIN_NAMES = [
    "goodbyedpi.exe",
    "goodbyedpi-x86_64.exe",
]

MODESETS = [
    "-1",
    "-2",
    "-3",
    "-4",
    "-5",
    "-6",
]

CONNECTIVITY_TARGETS = [
    ("google.com", 443),
    ("1.1.1.1", 443),
    ("8.8.8.8", 443),
    ("youtube.com", 443),
]


class _LegacyGoodbyeDPIEngine(Engine):
    name = "gdpi"
    description = "GoodbyeDPI TCP fragmentation — stable legacy backend"

    def __init__(self, flags: str | None = None):
        super().__init__()
        raw = flags or cfg.get("gdpi_flags") or "auto"
        self.flags: list[str] = raw.split()
        self._elevated_pid: int | None = None
        self._elevated_handle: int | None = None
        self._pid_file: Path | None = None
        self._working_mode: str | None = None

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

        raw_flags = " ".join(self.flags).strip()
        if raw_flags == "auto":
            return self._start_auto(binary)

        self._log.info("Starting GoodbyeDPI  flags=%s", raw_flags)

        if self._try_direct_launch(binary):
            return True

        self._log.info("Direct launch failed — requesting elevation via UAC…")
        return self._try_elevated_launch(binary)

    def _start_auto(self, binary: Path) -> bool:
        always_test_all = cfg.get("gdpi_always_test_all")
        self._log.info("Auto-detecting best GoodbyeDPI modeset...")

        working_modes = []
        for mode in MODESETS:
            self._log.info("Trying modeset %s ...", mode)
            self.flags = mode.split()

            if not self._try_direct_launch(binary):
                self._log.info("Direct launch failed for %s — trying elevated...", mode)
                if not self._try_elevated_launch(binary):
                    self._log.warning("Modeset %s could not start.", mode)
                    continue

            time.sleep(2.0)

            if self._test_connectivity(mode):
                self._log.info("Modeset %s works!", mode)
                working_modes.append(mode)
                if not always_test_all:
                    self._working_mode = mode
                    cfg.set_value("gdpi_flags", mode)
                    self._log.info("Saved modeset %s as default.", mode)
                    return True
            else:
                self._log.warning("Modeset %s started but no connectivity.", mode)

            self.stop()

        if working_modes:
            best_mode = working_modes[0]
            self._log.info(
                "Modeset scan complete. Working modes: %s. Starting GoodbyeDPI with: %s",
                working_modes,
                best_mode,
            )
            self.flags = best_mode.split()
            if not self._try_direct_launch(binary):
                self._try_elevated_launch(binary)
            return True

        self._log.error("All modesets failed — no connectivity.")
        return False

    def _test_connectivity(self, mode: str) -> bool:
        for host, port in CONNECTIVITY_TARGETS:
            try:
                with socket.create_connection((host, port), timeout=3.0):
                    self._log.debug("Connectivity OK via %s:%d (%s)", host, port, mode)
                    return True
            except (TimeoutError, OSError):
                continue
        return False

    def _try_direct_launch(self, binary: Path) -> bool:
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

    def _try_elevated_launch(self, binary: Path) -> bool:
        fd_pid, pid_path = tempfile.mkstemp(suffix=".bkpid", prefix="gdpi_")
        os.close(fd_pid)
        self._pid_file = Path(pid_path)
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

        fd, ps1_path = tempfile.mkstemp(suffix=".ps1", prefix="gdpi_launcher_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(ps_cmd)
        ps1_file = Path(ps1_path)

        try:
            subprocess.run(
                ["cmd.exe", "/c", "powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", str(ps1_file)],
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            pass
        except Exception as exc:
            self._log.error("Elevation launch failed: %s", exc)
            return False
        finally:
            try:
                ps1_file.unlink(missing_ok=True)
            except Exception:
                pass

        time.sleep(1.0)

        if self._pid_file.exists():
            try:
                raw = self._pid_file.read_text(encoding="utf-8-sig").strip()
                pid = int(raw)
                self._elevated_pid = pid
                self._log.info("GoodbyeDPI running elevated (pid=%s).", pid)
                return True
            except (ValueError, OSError, UnicodeDecodeError) as exc:
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
                subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-Command",
                        f"Start-Process taskkill -ArgumentList '/F /PID {self._elevated_pid}' -Verb RunAs -WindowStyle Hidden",
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
            except ImportError:
                psutil = None
            if psutil is not None:
                try:
                    return psutil.Process(self._elevated_pid).is_running()
                except psutil.NoSuchProcess:
                    return False
                except Exception:
                    pass
            try:
                result = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {self._elevated_pid}"],
                    capture_output=True,
                    timeout=5,
                    check=False,
                    text=True,
                )
                return str(self._elevated_pid) in result.stdout
            except Exception:
                return False
        if self._elevated_handle is not None:
            import ctypes
            if sys.platform == "win32":
                from ctypes import wintypes
                exit_code = wintypes.DWORD()
            else:
                exit_code = ctypes.c_uint32()
            if ctypes.windll.kernel32.GetExitCodeProcess(self._elevated_handle, ctypes.byref(exit_code)):
                return exit_code.value == 259
            return False
        return super().is_running()

    def check_process_alive(self) -> bool:
        if self._elevated_pid is not None:
            try:
                import psutil
            except ImportError:
                psutil = None
            if psutil is not None:
                try:
                    alive = psutil.Process(self._elevated_pid).is_running()
                except psutil.NoSuchProcess:
                    return False
                except Exception:
                    return False
                if not alive:
                    self._log.warning("Elevated GoodbyeDPI exited unexpectedly.")
                return alive
            return self.is_running()
        if self._elevated_handle is not None:
            import ctypes
            if sys.platform == "win32":
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


class _NativeGoodbyeDPIEngine(Engine):
    name = "gdpi-native"
    description = "GoodbyeDPI TCP fragmentation (Native Go, experimental)"

    def __init__(self, flags: str | None = None):
        super().__init__()
        self.flags = flags or cfg.get("gdpi_flags") or "auto"

    def start(self) -> bool:
        self._log.info("Starting experimental native Go-GDPI via blackout_core.dll...")
        if self.flags not in ("", "auto"):
            self._log.warning("Native GDPI currently ignores gdpi_flags=%s.", self.flags)
        dll = core.get_core_dll()
        if not dll:
            self._log.error("Could not load blackout_core.dll")
            return False

        old_cwd = os.getcwd()
        try:
            os.chdir(BINS_DIR)
            rc = dll.StartGDPIC()
        finally:
            os.chdir(old_cwd)

        if rc != 0:
            self._log.error(
                "Failed to start experimental native Go-GDPI. "
                "Ensure you are running Blackout Kit as Administrator."
            )
            return False

        time.sleep(1.0)
        if not self.is_running():
            self._log.error("Experimental native Go-GDPI started but did not stay healthy.")
            return False
        self._log.info("Experimental native Go-GDPI started successfully.")
        return True

    def stop(self):
        if not self.is_running():
            self._cleanup_config_dir()
            return

        dll = core.get_core_dll()
        if dll:
            self._log.info("Stopping experimental native Go-GDPI...")
            try:
                dll.StopGDPIC()
            except Exception as exc:
                self._log.error("Error stopping experimental native Go-GDPI: %s", exc)
        self._cleanup_config_dir()

    def is_running(self) -> bool:
        dll = core.get_core_dll()
        if not dll:
            return False
        if not hasattr(dll, "IsGDPIRunningC"):
            self._log.debug("IsGDPIRunningC export missing — treating native GDPI health as unknown.")
            return True
        try:
            return dll.IsGDPIRunningC() == 1
        except Exception:
            return False

    def check_process_alive(self) -> bool:
        alive = self.is_running()
        if not alive:
            self._log.warning("Experimental native Go-GDPI stopped unexpectedly.")
        return alive

    @property
    def pid(self) -> int | None:
        return None


class GoodbyeDPIEngine(Engine):
    name = "gdpi"
    description = "GoodbyeDPI TCP fragmentation — lightweight, no proxy needed"

    def __init__(self, flags: str | None = None, backend: str | None = None):
        super().__init__()
        requested_backend = (backend or cfg.get("gdpi_backend") or "legacy").lower()
        if requested_backend not in ("legacy", "native"):
            self._log.warning("Unknown gdpi backend '%s' — falling back to legacy.", requested_backend)
            requested_backend = "legacy"
        self.backend = requested_backend
        self._impl = (
            _NativeGoodbyeDPIEngine(flags=flags)
            if self.backend == "native"
            else _LegacyGoodbyeDPIEngine(flags=flags)
        )
        self._cleanup_config_dir()
        self._config_dir = self._impl._config_dir
        self._health_check_addr = self._impl._health_check_addr
        self._log = self._impl._log

    def start(self) -> bool:
        return self._impl.start()

    def stop(self):
        return self._impl.stop()

    def is_running(self) -> bool:
        return self._impl.is_running()

    def check_process_alive(self) -> bool:
        return self._impl.check_process_alive()

    @property
    def pid(self) -> int | None:
        return self._impl.pid

    def __getattr__(self, name):
        return getattr(self._impl, name)
