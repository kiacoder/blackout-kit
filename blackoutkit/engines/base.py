"""
Blackout Kit - Base engine class.
All bypass engines inherit from this.
"""
import logging
import socket
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path

BINS_DIR = Path(__file__).parent.parent.parent / "bins"

# Module-level logger — each engine gets a child: logger.getChild("sni") etc.
logger = logging.getLogger("blackoutkit.engine")


class Engine(ABC):
    name: str = ""
    description: str = ""

    def __init__(self):
        self._process: subprocess.Popen | None = None
        self._log = logger.getChild(self.name or self.__class__.__name__)

    @abstractmethod
    def start(self) -> bool:
        """Start the engine. Returns True on success."""
        ...

    def stop(self):
        """
        Terminate the engine and all child processes.
        Gives the process 3 seconds to exit gracefully, then force-kills.
        """
        if self._process is None:
            return
        try:
            try:
                import psutil
                parent = psutil.Process(self._process.pid)
                # Graceful terminate — children first, then parent
                for child in parent.children(recursive=True):
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass
                parent.terminate()
                # Wait up to 3 seconds for clean exit
                try:
                    self._process.wait(timeout=3.0)
                    self._log.debug("Engine stopped gracefully.")
                    return
                except subprocess.TimeoutExpired:
                    self._log.warning("Engine did not exit in 3s — force-killing.")
                # Force-kill anything still alive
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except psutil.NoSuchProcess:
                        pass
                parent.kill()
            except ImportError:
                # psutil not available — plain terminate + wait + kill
                self._process.terminate()
                try:
                    self._process.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    self._process.kill()
        except Exception as exc:
            self._log.debug("Stop error (non-fatal): %s", exc)
            try:
                self._process.kill()
            except Exception:
                pass
        finally:
            self._process = None

    def is_running(self) -> bool:
        """Return True if the engine subprocess is alive."""
        if self._process is None:
            return False
        return self._process.poll() is None

    @property
    def pid(self) -> int | None:
        return self._process.pid if self._process else None

    # ──────────────────────────── Helpers ────────────────────────

    def find_binary(self, names: list[str]) -> Path | None:
        """
        Search bins/ folder for the first matching binary name.
        Logs a warning with a download hint if none are found.
        """
        for name in names:
            path = BINS_DIR / name
            if path.exists():
                self._log.debug("Binary found: %s", path)
                return path
        self._log.warning(
            "Binary not found in bins/ — tried: %s  "
            "Run 'blackout bins download' to auto-install.",
            names,
        )
        return None

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
        Return True if self._process is alive.
        Logs a warning if the process has died unexpectedly.
        """
        if self._process is None:
            return False
        if self._process.poll() is not None:
            self._log.warning(
                "%s process exited unexpectedly (returncode=%s).",
                self.name, self._process.returncode,
            )
            return False
        return True
