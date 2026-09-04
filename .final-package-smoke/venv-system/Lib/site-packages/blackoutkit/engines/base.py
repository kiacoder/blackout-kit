"""
Blackout Kit - Base engine class.
All bypass engines inherit from this.
"""
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path

from .. import BINS_DIR

# Module-level logger — each engine gets a child: logger.getChild("sni") etc.
logger = logging.getLogger("blackoutkit.engine")


class Engine(ABC):
    name: str = ""
    description: str = ""

    def __init__(self):
        self._process: subprocess.Popen | None = None
        self._dll_stop_func = None
        self._log = logger.getChild(self.name or self.__class__.__name__)
        # Set this to a (host, port) tuple if the engine listens on a known port.
        # is_running() will probe it periodically for DLL-based engines to detect
        # silent crashes (DLL segfault, deadlock, etc.) where _dll_stop_func
        # is still non-None but the engine is actually dead.
        self._health_check_addr: tuple[str, int] | None = None
        # Per-engine temp directory for config files — prevents races when two
        # Blackout instances share the same bins/ folder.
        self._config_dir = Path(tempfile.mkdtemp(prefix="bk_engine_"))

    @abstractmethod
    def start(self) -> bool:
        """Start the engine. Returns True on success."""
        ...

    def stop(self):
        """
        Terminate the engine and all child processes.
        Gives the process 3 seconds to exit gracefully, then force-kills.
        Also cleans up the per-engine config directory.
        """
        try:
            if self._dll_stop_func:
                try:
                    self._dll_stop_func()
                except Exception as exc:
                    self._log.error("Error stopping via DLL: %s", exc)
            elif self._process is not None:
                try:
                    import psutil
                    parent = psutil.Process(self._process.pid)
                    for child in parent.children(recursive=True):
                        try:
                            child.terminate()
                        except psutil.NoSuchProcess:
                            self._log.debug("Child process %d already terminated", child.pid)
                    parent.terminate()
                    try:
                        self._process.wait(timeout=3.0)
                        self._log.debug("Engine stopped gracefully.")
                    except subprocess.TimeoutExpired:
                        self._log.warning("Engine did not exit in 3s — force-killing.")
                        for child in parent.children(recursive=True):
                            try:
                                child.kill()
                            except psutil.NoSuchProcess:
                                self._log.debug("Child process %d already gone during force-kill", child.pid)
                        parent.kill()
                except ImportError:
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=3.0)
                        self._log.debug("Engine stopped gracefully.")
                    except subprocess.TimeoutExpired:
                        self._log.warning("Engine did not exit in 3s — force-killing.")
                        self._process.kill()
                except Exception as exc:
                    self._log.warning("Engine stop encountered an error: %s", exc)
                    try:
                        self._process.kill()
                    except Exception as kill_exc:
                        self._log.warning("Could not kill engine during cleanup: %s", kill_exc)
        finally:
            self._dll_stop_func = None
            self._process = None
            self._cleanup_config_dir()

    def is_running(self) -> bool:
        """Return True if the engine is alive (subprocess or DLL)."""
        # ── Subprocess check ──────────────────────────────────────────
        if self._process is not None:
            return self._process.poll() is None

        # ── DLL check (with port health probe) ────────────────────────
        if self._dll_stop_func is not None:
            if self._health_check_addr is not None:
                host, port = self._health_check_addr
                try:
                    with socket.create_connection((host, port), timeout=1.0):
                        return True
                except OSError:
                    self._log.warning(
                        "DLL engine health check FAILED — port %s:%d is closed. "
                        "Engine likely crashed silently.",
                        host, port,
                    )
                    self._dll_stop_func = None
                    return False
            return True  # No health check port set — assume alive

        return False

    @property
    def pid(self) -> int | None:
        return self._process.pid if self._process else None

    def _cleanup_config_dir(self):
        """Remove the per-engine config directory. Called by stop()."""
        if self._config_dir and self._config_dir.exists():
            try:
                shutil.rmtree(self._config_dir)
            except OSError as exc:
                self._log.warning("Failed to clean up config directory %s: %s", self._config_dir, exc)

    # ──────────────────────────── Helpers ────────────────────────

    def find_binary(self, names: list[str], system_names: list[str] | None = None) -> Path | None:
        """Return a managed binary, or an explicitly permitted system binary on Linux."""
        for name in names:
            path = BINS_DIR / name
            if path.is_file() and (
                not sys.platform.startswith("linux")
                or os.access(path, os.X_OK)
            ):
                self._log.debug("Managed binary found: %s", path)
                return path

        if sys.platform.startswith("linux"):
            for name in system_names or []:
                found = shutil.which(name)
                if found:
                    path = Path(found)
                    self._log.debug("System binary found: %s", path)
                    return path

        self._log.warning(
            "Binary not found in bins/ — tried: %s. Run 'blackout bins download' to install it.",
            names,
        )
        return None

    def start_process(self, command: list[str]) -> bool:
        """Start a managed engine process without inheriting terminal output pipes."""
        try:
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=sys.platform != "win32",
            )
            return True
        except OSError as exc:
            self._log.error("Could not start engine process: %s", exc)
            return False

    def wait_for_process(self, timeout: float = 0.5) -> bool:
        """Return whether a newly spawned process remained alive through its startup window."""
        time.sleep(timeout)
        if self._process is not None and self._process.poll() is None:
            return True
        code = self._process.returncode if self._process is not None else None
        self._log.error("Engine process exited during startup (returncode=%s).", code)
        return False

    def binary_command(self, binary: Path, *arguments: str) -> list[str]:
        """Build a platform-safe executable command."""
        return [str(binary), *arguments]

    def check_port_free(self, port: int, host: str = "127.0.0.1") -> bool:
        """
        Return True if the port is free (nothing is listening on it yet).
        Call this in start() before launching a process to catch port conflicts early.
        If already occupied, logs an actionable error and returns False.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            self._log.error(
                "Port %d is already in use — another process may be running. "
                "Stop it first or change the port in settings.", port
            )
            return False
        finally:
            s.close()

    def wait_for_port(
        self,
        port: int,
        host: str = "127.0.0.1",
        timeout: float = 10.0,
        interval: float = 0.3,
    ) -> bool:
        """
        Poll a local TCP port until it is open or the timeout expires.
        Useful after start() to confirm the proxy/server is ready.

        Returns True when port accepts a connection, False on timeout.
        """
        deadline = time.monotonic() + timeout
        self._log.debug("Waiting for %s:%d to open (timeout=%.1fs)…", host, port, timeout)
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((host, port), timeout=interval):
                    self._log.debug("Port %d is open.", port)
                    return True
            except OSError:
                time.sleep(interval)
        self._log.warning("Timed out waiting for port %d after %.1fs.", port, timeout)
        return False

    def check_process_alive(self) -> bool:
        """
        Return True if self._process is alive or if running natively via DLL.
        Logs a warning if the process has died unexpectedly.
        """
        if self._dll_stop_func is not None:
            return True
        if self._process is None:
            return False
        if self._process.poll() is not None:
            self._log.warning(
                "%s process exited unexpectedly (returncode=%s).",
                self.name, self._process.returncode,
            )
            return False
        return True
