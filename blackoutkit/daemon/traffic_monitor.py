"""Background traffic sampler for the local JSONL audit trail."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger(__name__)


def _endpoint(address: object, port: object) -> str:
    host = str(address or "").strip()
    if not host:
        return ""
    try:
        normalized_port = int(port)
    except (TypeError, ValueError):
        normalized_port = 0
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{normalized_port}" if normalized_port else host


class TrafficMonitor:
    """Periodically snapshot active connections and append normalized records."""

    def __init__(
        self,
        sample_interval_sec: int = 10,
        *,
        connection_loader: Callable[..., list[dict[str, Any]]] | None = None,
        log_writer: Callable[[dict[str, Any]], None] | None = None,
        clock: Callable[[], float] | None = None,
    ):
        if sample_interval_sec <= 0:
            raise ValueError("sample_interval_sec must be greater than zero")
        self.sample_interval = sample_interval_sec
        self._connection_loader = connection_loader
        self._log_writer = log_writer
        self._clock = clock or time.time
        self.running = False
        self.thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._known_connections: dict[tuple, dict[str, Any]] = {}

    def start(self) -> None:
        """Start the monitor thread if it is not already running."""
        if self.thread and self.thread.is_alive():
            return
        self._stop_event.clear()
        self.running = True
        self.thread = threading.Thread(
            target=self._monitor_loop,
            name="blackout-traffic-monitor",
            daemon=True,
        )
        self.thread.start()
        _log.debug("TrafficMonitor started (interval=%ss)", self.sample_interval)

    def stop(self) -> None:
        """Request shutdown and wait briefly for the worker to exit."""
        thread = self.thread
        self._stop_event.set()
        if thread and thread is not threading.current_thread():
            thread.join(timeout=5)
        if thread and thread.is_alive():
            _log.warning("TrafficMonitor did not stop within 5 seconds")
            return
        self.running = False
        self.thread = None
        _log.debug("TrafficMonitor stopped")

    def is_running(self) -> bool:
        """Return whether the monitor has an active worker thread."""
        return self.running and self.thread is not None and self.thread.is_alive()

    def _monitor_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    self._snapshot_connections()
                except Exception as exc:
                    _log.error("TrafficMonitor error: %s", exc, exc_info=False)
                if self._stop_event.wait(self.sample_interval):
                    break
        finally:
            self.running = False

    def _load_connections(self) -> list[dict[str, Any]]:
        if self._connection_loader is not None:
            return self._connection_loader(established_only=False)
        from .. import tools

        return tools.get_active_connections(established_only=False)

    def _write_log(self, entry: dict[str, Any]) -> None:
        if self._log_writer is not None:
            self._log_writer(entry)
            return
        from ..tools.traffic_log import append_connection_log

        append_connection_log(entry)

    @staticmethod
    def _connection_key(conn: dict[str, Any]) -> tuple:
        return (
            conn.get("pid", 0),
            conn.get("local_addr", conn.get("local", "")),
            conn.get("local_port", 0),
            conn.get("remote_addr", conn.get("remote", "")),
            conn.get("remote_port", 0),
            str(conn.get("protocol", "tcp")).casefold(),
        )

    @staticmethod
    def _counter(conn: dict[str, Any], *names: str) -> tuple[bool, int]:
        for name in names:
            if name not in conn or conn[name] is None:
                continue
            try:
                return True, max(0, int(conn[name]))
            except (TypeError, ValueError):
                return False, 0
        return False, 0

    def _snapshot_connections(self) -> None:
        try:
            connections = self._load_connections()
        except Exception as exc:
            _log.debug("Could not read active connections: %s", exc)
            return

        now_ts = float(self._clock())
        current_keys = set()
        for conn in connections:
            if not isinstance(conn, dict):
                continue
            key = self._connection_key(conn)
            current_keys.add(key)
            sent_available, sent_total = self._counter(conn, "bytes_sent")
            recv_available, recv_total = self._counter(conn, "bytes_recv", "bytes_received")
            bytes_available = sent_available and recv_available
            previous = self._known_connections.get(key)
            entry = {
                "ts": now_ts,
                "pid": conn.get("pid", 0),
                "process": conn.get("process", "unknown"),
                "protocol": str(conn.get("protocol", "TCP")).casefold(),
                "local": conn.get("local") or _endpoint(conn.get("local_addr"), conn.get("local_port")),
                "remote": conn.get("remote") or _endpoint(conn.get("remote_addr"), conn.get("remote_port")),
                "status": conn.get("status", "UNKNOWN"),
                "bytes_available": bytes_available,
                "bytes_sent": sent_total if bytes_available else 0,
                "bytes_recv": recv_total if bytes_available else 0,
                "duration_sec": 0.0,
            }

            should_write = previous is None
            if previous is not None:
                entry["duration_sec"] = max(0.0, now_ts - previous["ts"])
                if bytes_available and previous.get("bytes_available"):
                    entry["bytes_sent"] = max(0, sent_total - previous["bytes_sent"])
                    entry["bytes_recv"] = max(0, recv_total - previous["bytes_recv"])
                    should_write = bool(entry["bytes_sent"] or entry["bytes_recv"])
                elif entry["status"] != previous.get("status"):
                    should_write = True

            if should_write:
                self._write_log(entry)
            self._known_connections[key] = {
                "ts": now_ts,
                "status": entry["status"],
                "bytes_available": bytes_available,
                "bytes_sent": sent_total,
                "bytes_recv": recv_total,
            }

        for key in set(self._known_connections) - current_keys:
            del self._known_connections[key]
