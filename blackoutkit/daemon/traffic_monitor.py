"""
Blackout Kit - Traffic Monitor Daemon Thread.
Periodically snapshots active connections and logs them to the traffic audit trail.
"""
import logging
import threading
import time
from datetime import datetime, timezone

_log = logging.getLogger(__name__)


class TrafficMonitor:
    """
    Background thread that periodically snaps and logs active connections.
    Call start() to spawn thread, stop() to terminate.
    """

    def __init__(self, sample_interval_sec: int = 10):
        self.sample_interval = sample_interval_sec
        self.running = False
        self.thread = None
        self._known_connections = {}  # Track known conn states to detect lifecycle

    def start(self) -> None:
        """Start the traffic monitor thread."""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        _log.debug(f"TrafficMonitor started (interval={self.sample_interval}s)")

    def stop(self) -> None:
        """Stop the traffic monitor thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        _log.debug("TrafficMonitor stopped")

    def _monitor_loop(self) -> None:
        """Background loop that periodically snapshots connections."""
        from ..tools.tools import get_active_connections
        from ..tools.traffic_log import append_connection_log

        while self.running:
            try:
                self._snapshot_connections()
                time.sleep(self.sample_interval)
            except Exception as e:
                _log.error(f"TrafficMonitor error: {e}", exc_info=False)
                time.sleep(self.sample_interval)

    def _snapshot_connections(self) -> None:
        """Capture current connections and log them."""
        from ..tools.tools import get_active_connections
        from ..tools.traffic_log import append_connection_log

        try:
            connections = get_active_connections(established_only=False)
        except Exception:
            return

        now_ts = datetime.now(timezone.utc).timestamp()

        for conn in connections:
            # Build connection key for tracking
            conn_key = (conn['pid'], conn['local'], conn['remote'], conn['protocol'])

            # Build log entry
            entry = {
                'ts': now_ts,
                'pid': conn['pid'],
                'process': conn['process'],
                'protocol': conn['protocol'],
                'local': conn['local'],
                'remote': conn['remote'],
                'status': conn['status'],
                'bytes_sent': conn.get('bytes_sent', 0),
                'bytes_recv': conn.get('bytes_recv', 0),
            }

            # Track connection lifecycle
            if conn_key in self._known_connections:
                prev_entry = self._known_connections[conn_key]
                # Calculate delta
                delta_sent = max(0, entry['bytes_sent'] - prev_entry.get('bytes_sent', 0))
                delta_recv = max(0, entry['bytes_recv'] - prev_entry.get('bytes_recv', 0))
                entry['bytes_sent'] = delta_sent
                entry['bytes_recv'] = delta_recv
                entry['duration_sec'] = entry['ts'] - prev_entry['ts']
            else:
                # First time seeing this connection
                entry['duration_sec'] = 0

            # Only log if there's meaningful data or status change
            if entry.get('bytes_sent', 0) > 0 or entry.get('bytes_recv', 0) > 0 or \
               conn_key not in self._known_connections:
                append_connection_log(entry)

            # Update known state
            self._known_connections[conn_key] = entry

        # Cleanup closed connections from known set (keep only last 100 for memory)
        if len(self._known_connections) > 1000:
            # Simple cleanup: keep most recent 500 connections
            keys = list(self._known_connections.keys())[-500:]
            self._known_connections = {k: self._known_connections[k] for k in keys}
