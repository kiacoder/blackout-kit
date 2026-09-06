"""Anomaly detection engine for network traffic patterns and security threats."""

from __future__ import annotations

import json
import logging
import math
import os
import tempfile
import threading
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, stdev
from typing import Optional

logger = logging.getLogger(__name__)
_LOG_LOCK = threading.Lock()
_MAX_LOGGED_ANOMALIES = 1000


@dataclass
class ConnectionEvent:
    """Represents a network connection or connection attempt."""

    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0
    state: str = "established"
    geolocation: Optional[str] = None
    process_name: Optional[str] = None
    bytes_available: bool = True


@dataclass
class Anomaly:
    """Detected anomaly event."""

    timestamp: str
    anomaly_type: str
    severity: str
    description: str
    affected_ip: str
    affected_port: Optional[int] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None


class RollingStats:
    """Tracks rolling statistics (mean, stdev) for a metric."""

    def __init__(self, window_size: int = 100):
        if window_size < 2:
            raise ValueError("window_size must be at least 2")
        self.window_size = window_size
        self.values = deque(maxlen=window_size)

    def add(self, value: float) -> None:
        if not math.isfinite(value):
            raise ValueError("metric values must be finite")
        self.values.append(value)

    @property
    def is_ready(self) -> bool:
        return len(self.values) >= 2

    def mean(self) -> float:
        return mean(self.values) if self.values else 0.0

    def stdev(self) -> float:
        return stdev(self.values) if len(self.values) >= 2 else 0.0

    def zscore(self, value: float) -> float:
        """Calculate a z-score against values already in the window."""
        if not self.is_ready:
            return 0.0
        deviation = self.stdev()
        return (value - self.mean()) / deviation if deviation > 0 else 0.0


class AnomalyDetector:
    """Real-time anomaly detection engine."""

    def __init__(
        self,
        log_dir: Optional[Path] = None,
        z_threshold: float = 3.0,
        *,
        persist: bool = True,
        rate_window_seconds: float = 60.0,
    ):
        if not math.isfinite(z_threshold) or z_threshold <= 0:
            raise ValueError("z_threshold must be greater than zero")
        if not math.isfinite(rate_window_seconds) or rate_window_seconds <= 0:
            raise ValueError("rate_window_seconds must be greater than zero")

        self.log_dir = Path(log_dir or Path.home() / ".blackout-kit" / "logs")
        self.anomaly_log = self.log_dir / "anomalies.json"
        self.z_threshold = z_threshold
        self.rate_window_seconds = rate_window_seconds
        self.persist = persist
        if persist:
            self.log_dir.mkdir(parents=True, exist_ok=True)

        self.connection_rate_per_ip = defaultdict(lambda: RollingStats(200))
        self.bandwidth_per_ip = defaultdict(lambda: RollingStats(200))
        self.failed_attempts_per_ip = defaultdict(int)
        self.connection_counts_per_ip = defaultdict(int)
        self._connection_times_per_ip = defaultdict(lambda: deque(maxlen=200))
        self.hourly_connections = deque(maxlen=24)
        self.hourly_bandwidth = deque(maxlen=24)
        self.anomalies: list[Anomaly] = []

    @staticmethod
    def _timestamp(timestamp: float | None = None) -> str:
        value = datetime.now(timezone.utc).timestamp() if timestamp is None else timestamp
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()

    def _record_anomalies(self, anomalies: list[Anomaly]) -> None:
        for anomaly in anomalies:
            self.anomalies.append(anomaly)
            if len(self.anomalies) > _MAX_LOGGED_ANOMALIES:
                del self.anomalies[:-_MAX_LOGGED_ANOMALIES]
            if self.persist:
                self._log_anomaly(anomaly)
            logger.warning("Anomaly detected: %s", anomaly.description)

    def detect(self, event: ConnectionEvent) -> Optional[Anomaly]:
        """Process one connection event and return its first detected anomaly."""
        anomalies: list[Anomaly] = []
        state = str(event.state).casefold()
        if state == "failed":
            anomaly = self._detect_failed_storm(event)
            if anomaly:
                anomalies.append(anomaly)
        elif state == "established":
            for detector in (
                self._detect_spike,
                self._detect_unusual_geolocation,
                self._detect_unusual_port,
                self._detect_exfiltration,
            ):
                anomaly = detector(event)
                if anomaly:
                    anomalies.append(anomaly)

        self._record_anomalies(anomalies)
        return anomalies[0] if anomalies else None

    def _detect_spike(self, event: ConnectionEvent) -> Optional[Anomaly]:
        """Detect an unusually high destination connection rate."""
        destination = str(event.dst_ip).strip()
        try:
            timestamp = float(event.timestamp)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(timestamp):
            return None

        times = self._connection_times_per_ip[destination]
        while times and timestamp - times[0] > self.rate_window_seconds:
            times.popleft()
        current_rate = len(times) + 1
        current_rate /= self.rate_window_seconds
        stats = self.connection_rate_per_ip[destination]
        anomaly = None
        if stats.is_ready:
            zscore = stats.zscore(current_rate)
            baseline = stats.mean()
            is_ratio_anomaly = baseline > 0 and current_rate >= baseline * 2
            if zscore > self.z_threshold or (stats.stdev() == 0 and is_ratio_anomaly):
                anomaly = Anomaly(
                    timestamp=self._timestamp(timestamp),
                    anomaly_type="connection_spike",
                    severity="high",
                    description=f"Connection spike to {destination}: {zscore:.2f}σ above baseline",
                    affected_ip=destination,
                    metric_value=zscore if zscore else current_rate,
                    threshold=self.z_threshold,
                )
        stats.add(current_rate)
        times.append(timestamp)
        self.connection_counts_per_ip[destination] += 1
        return anomaly

    def _detect_failed_storm(self, event: ConnectionEvent) -> Optional[Anomaly]:
        """Detect a connection failure storm."""
        destination = str(event.dst_ip).strip()
        self.failed_attempts_per_ip[destination] += 1
        count = self.failed_attempts_per_ip[destination]
        if count not in {10, 50}:
            return None
        severity = "critical" if count >= 50 else "high"
        return Anomaly(
            timestamp=self._timestamp(event.timestamp),
            anomaly_type="failed_connection_storm",
            severity=severity,
            description=f"Failed connection storm to {destination}: {count} attempts",
            affected_ip=destination,
            metric_value=float(count),
            threshold=10.0,
        )

    def _detect_unusual_geolocation(self, event: ConnectionEvent) -> Optional[Anomaly]:
        """Detect connections to unexpected geolocations."""
        country = str(event.geolocation or "").strip().upper()
        if not country or country in {"US", "LOCAL"}:
            return None
        if country not in {"KP", "IR", "SY", "CU", "VE"}:
            return None
        return Anomaly(
            timestamp=self._timestamp(event.timestamp),
            anomaly_type="unusual_geolocation",
            severity="medium",
            description=f"Unexpected connection to {country}: {event.dst_ip}:{event.dst_port}",
            affected_ip=str(event.dst_ip),
            affected_port=event.dst_port,
        )

    def _detect_unusual_port(self, event: ConnectionEvent) -> Optional[Anomaly]:
        """Detect connections to sensitive ports using an unexpected protocol."""
        unusual_ports = {22, 3389, 135, 445, 1433, 3306, 5432, 27017}
        protocol = str(event.protocol).casefold()
        if event.dst_port not in unusual_ports or protocol in {"ssh", "rdp", "http", "https"}:
            return None
        return Anomaly(
            timestamp=self._timestamp(event.timestamp),
            anomaly_type="unusual_port",
            severity="medium",
            description=f"Suspicious port {event.dst_port}/{protocol} to {event.dst_ip}",
            affected_ip=str(event.dst_ip),
            affected_port=event.dst_port,
        )

    def _detect_exfiltration(self, event: ConnectionEvent) -> Optional[Anomaly]:
        """Detect an unusually large transfer when byte counters are available."""
        if not event.bytes_available:
            return None
        try:
            bytes_sent = float(event.bytes_sent)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(bytes_sent) or bytes_sent < 0:
            return None
        stats = self.bandwidth_per_ip[str(event.dst_ip)]
        anomaly = None
        if stats.is_ready and bytes_sent >= 1024 * 1024:
            zscore = stats.zscore(bytes_sent)
            baseline = stats.mean()
            is_ratio_anomaly = baseline > 0 and bytes_sent >= baseline * 2
            if zscore > self.z_threshold or (stats.stdev() == 0 and is_ratio_anomaly):
                anomaly = Anomaly(
                    timestamp=self._timestamp(event.timestamp),
                    anomaly_type="bulk_exfiltration",
                    severity="critical",
                    description=f"Bulk data transfer to {event.dst_ip}: {bytes_sent / 1024 / 1024:.1f}MB",
                    affected_ip=str(event.dst_ip),
                    metric_value=bytes_sent / 1024 / 1024,
                    threshold=float(stats.mean() / 1024 / 1024),
                )
        stats.add(bytes_sent)
        return anomaly

    def detect_c2_dns(self, domain: str, known_c2_list: list[str]) -> Optional[Anomaly]:
        """Detect and persist a DNS query to known C2 infrastructure."""
        normalized_domain = str(domain).strip().casefold().rstrip(".")
        known = {
            str(item).strip().casefold().rstrip(".")
            for item in known_c2_list
            if str(item).strip()
        }
        if normalized_domain not in known:
            return None
        anomaly = Anomaly(
            timestamp=self._timestamp(),
            anomaly_type="c2_dns_query",
            severity="critical",
            description=f"DNS query to known C2 domain: {normalized_domain}",
            affected_ip=normalized_domain,
        )
        self._record_anomalies([anomaly])
        return anomaly

    def reset_hourly(self) -> None:
        """Record the completed hour and clear all per-hour baselines."""
        total_connections = sum(self.connection_counts_per_ip.values())
        total_bandwidth = sum(
            stats.mean() * len(stats.values)
            for stats in self.bandwidth_per_ip.values()
        )
        self.hourly_connections.append(total_connections)
        self.hourly_bandwidth.append(total_bandwidth)
        self.connection_counts_per_ip.clear()
        self.failed_attempts_per_ip.clear()
        self.connection_rate_per_ip.clear()
        self.bandwidth_per_ip.clear()
        self._connection_times_per_ip.clear()

    def _log_anomaly(self, anomaly: Anomaly) -> None:
        """Persist a bounded anomaly array using an atomic replacement."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        with _LOG_LOCK:
            anomalies: list[dict] = []
            if self.anomaly_log.exists():
                try:
                    data = json.loads(self.anomaly_log.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        anomalies = [item for item in data if isinstance(item, dict)]
                except (json.JSONDecodeError, OSError):
                    pass
            anomalies = (anomalies + [asdict(anomaly)])[-_MAX_LOGGED_ANOMALIES:]
            descriptor, temporary = tempfile.mkstemp(
                prefix=".anomalies-", suffix=".json", dir=self.log_dir
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(anomalies, handle, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.anomaly_log)
            except OSError:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    @staticmethod
    def _parse_anomaly(item: object) -> Optional[Anomaly]:
        if not isinstance(item, dict):
            return None
        required = {"timestamp", "anomaly_type", "severity", "description", "affected_ip"}
        if not required.issubset(item):
            return None
        try:
            anomaly = Anomaly(
                timestamp=str(item["timestamp"]),
                anomaly_type=str(item["anomaly_type"]),
                severity=str(item["severity"]),
                description=str(item["description"]),
                affected_ip=str(item["affected_ip"]),
                affected_port=item.get("affected_port"),
                metric_value=item.get("metric_value"),
                threshold=item.get("threshold"),
            )
            parsed = datetime.fromisoformat(anomaly.timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            if not math.isfinite(parsed.timestamp()):
                return None
            return anomaly
        except (TypeError, ValueError, OverflowError):
            return None

    def get_anomalies(
        self, since: Optional[datetime] = None, severity: Optional[str] = None
    ) -> list[Anomaly]:
        """Get persisted anomalies with optional time and severity filters."""
        loaded: list[Anomaly] = []
        if self.anomaly_log.exists():
            try:
                data = json.loads(self.anomaly_log.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = []
            if isinstance(data, list):
                loaded = [
                    anomaly
                    for item in data
                    if (anomaly := self._parse_anomaly(item)) is not None
                ]
        if loaded:
            self.anomalies = loaded[-_MAX_LOGGED_ANOMALIES:]
        elif not self.anomaly_log.exists():
            loaded = list(self.anomalies)

        if since is not None:
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc)
            loaded = [
                anomaly
                for anomaly in loaded
                if datetime.fromisoformat(
                    anomaly.timestamp.replace("Z", "+00:00")
                ).astimezone(timezone.utc) > since.astimezone(timezone.utc)
            ]
        if severity:
            normalized = severity.casefold()
            loaded = [item for item in loaded if item.severity.casefold() == normalized]
        return loaded

    def alert_summary(self) -> dict:
        """Get summary of in-memory anomalies by type and severity."""
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for anomaly in self.anomalies:
            by_type[anomaly.anomaly_type] += 1
            by_severity[anomaly.severity] += 1
        return {
            "total": len(self.anomalies),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
        }
