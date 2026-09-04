"""
Blackout Kit - QoS Monitor Daemon.
Monitors per-rule throughput and alerts on violations.

Features:
  - Periodic throughput checking
  - Violation detection and logging
  - Alert generation
  - Stats aggregation for CLI display
"""
import logging
import threading
import time
from collections.abc import Callable

_log = logging.getLogger(__name__)


class QosMonitor:
    """
    Background monitor for QoS rule violations.
    Periodically checks throughput against rate limits and alerts.
    """

    def __init__(self, check_interval: int = 5):
        """
        Initialize the QoS monitor.

        Args:
            check_interval: Seconds between throughput checks (default 5)
        """
        self.check_interval = check_interval
        self.active = False
        self.alert_callback: Callable[[dict], None] | None = None
        self._monitor_thread = None
        self._should_stop = False
        self._stop_event = threading.Event()
        self.last_violations = {}  # rule_id -> {type, ts, details}

    def set_alert_callback(self, callback: Callable[[dict], None]) -> None:
        """
        Set a callback function to be called when a violation is detected.
        Callback receives dict with: rule_id, violation_type, details.
        """
        self.alert_callback = callback

    def start(self) -> bool:
        """Start the QoS monitor daemon."""
        if self.is_running():
            return True

        try:
            self._should_stop = False
            self._stop_event.clear()
            self.active = True
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()
            _log.info("QoS Monitor started")
            return True
        except Exception as exc:
            self.active = False
            self._monitor_thread = None
            _log.error("Failed to start QoS Monitor: %s", exc)
            return False

    def stop(self) -> bool:
        """Stop the QoS monitor daemon."""
        thread = self._monitor_thread
        if not self.active and (thread is None or not thread.is_alive()):
            return True

        self._should_stop = True
        self._stop_event.set()
        if thread and thread is not threading.current_thread():
            thread.join(timeout=5)
        if thread and thread.is_alive():
            _log.warning("QoS Monitor did not stop within 5 seconds")
            return False

        self.active = False
        self._monitor_thread = None
        _log.info("QoS Monitor stopped")
        return True

    def is_running(self) -> bool:
        """Return whether the monitor has an active live worker thread."""
        return self.active and self._monitor_thread is not None and self._monitor_thread.is_alive()

    def _monitor_loop(self) -> None:
        """Background loop that periodically checks QoS rule violations."""
        _log.debug("QoS Monitor loop started (interval=%ss)", self.check_interval)
        try:
            while not self._stop_event.is_set():
                try:
                    self._check_violations()
                except Exception as exc:
                    _log.warning("Error in QoS Monitor loop: %s", exc)
                if self._stop_event.wait(self.check_interval):
                    break
        finally:
            self.active = False

    def _check_violations(self) -> None:
        """
        Check current throughput for all enabled QoS rules.
        Alert if any rule's throughput exceeds its limit.
        """
        # Import here to avoid circular dependencies
        from ..tools.qos import (
            calculate_rule_throughput,
            load_qos_rules,
            log_violation,
        )

        rules = load_qos_rules()
        enabled_rules = [r for r in rules if r.get("enabled", True)]

        for rule in enabled_rules:
            rule_id = rule.get("id")
            rate_limit = rule.get("rate_limit_kbps", 0)

            if rate_limit <= 0:
                # No limit, skip
                continue

            rx_kbps, tx_kbps, over_limit = calculate_rule_throughput(rule_id)
            total_kbps = rx_kbps + tx_kbps

            if over_limit and total_kbps > rate_limit:
                # Violation detected
                violation = {
                    "rule_id": rule_id,
                    "name": rule.get("name"),
                    "type": rule.get("type"),
                    "rate_limit": rate_limit,
                    "actual_throughput": total_kbps,
                    "violation_pct": int((total_kbps / rate_limit) * 100),
                    "ts": time.time(),
                }

                # Check if this is a new violation (not already alerted recently)
                last_violation = self.last_violations.get(rule_id)
                time_since_last = time.time() - (last_violation.get("ts", 0) if last_violation else 0)

                # Alert if first violation or 60+ seconds since last alert
                if not last_violation or time_since_last > 60:
                    details = f"{violation['violation_pct']}% of limit ({total_kbps:.1f} kbps vs {rate_limit} kbps)"

                    log_violation(rule_id, "rate_limit_exceeded", details)

                    if self.alert_callback:
                        self.alert_callback(violation)

                    _log.warning(f"QoS Violation: {rule.get('name')} - {details}")

                    self.last_violations[rule_id] = violation


# ──────────────────────────── Module-level Singleton ──────────────────────────

_monitor_instance: QosMonitor | None = None
_monitor_lock = threading.Lock()


def get_monitor(check_interval: int = 5) -> QosMonitor:
    """Get or create the singleton QoS monitor instance."""
    global _monitor_instance

    if _monitor_instance is None:
        with _monitor_lock:
            if _monitor_instance is None:
                _monitor_instance = QosMonitor(check_interval=check_interval)

    return _monitor_instance


def start_qos_monitor() -> bool:
    """Start the global QoS monitor."""
    monitor = get_monitor()
    return monitor.start()


def stop_qos_monitor() -> bool:
    """Stop the global QoS monitor."""
    monitor = get_monitor()
    return monitor.stop()


def is_qos_monitor_running() -> bool:
    """Check if QoS monitor is running."""
    monitor = get_monitor()
    return monitor.is_running()


def set_monitor_alert_callback(callback: Callable[[dict], None]) -> None:
    """Set the alert callback for the monitor."""
    monitor = get_monitor()
    monitor.set_alert_callback(callback)
