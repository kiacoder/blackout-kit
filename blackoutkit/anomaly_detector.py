"""
Blackout Kit - Anomaly Detection Engine.
Detects unusual network connection patterns and potential data exfiltration
using rolling statistics (mean, standard deviation) and rule heuristics.
"""
import json
import logging
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from blackoutkit import APP_DATA_DIR

_log = logging.getLogger(__name__)

ANOMALY_LOG_FILE = APP_DATA_DIR / "logs" / "anomalies.log"


class RollingStats:
    """Calculates rolling mean and standard deviation for a stream of numeric values."""

    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.values: List[float] = []

    def add(self, val: float) -> None:
        self.values.append(float(val))
        if len(self.values) > self.window_size:
            self.values.pop(0)

    @property
    def count(self) -> int:
        return len(self.values)

    @property
    def mean(self) -> float:
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)

    @property
    def stdev(self) -> float:
        if len(self.values) < 2:
            return 0.0
        m = self.mean
        variance = sum((x - m) ** 2 for x in self.values) / (len(self.values) - 1)
        return math.sqrt(variance)

    def z_score(self, val: float) -> float:
        sd = self.stdev
        if sd == 0.0:
            return 0.0
        return (val - self.mean) / sd


class AnomalyDetector:
    """
    Main Anomaly Detection Engine.
    Detects:
      - Connection spikes (botnet/malware)
      - Unexpected geolocations / unexpected remote IPs
      - Unusual ports/protocols (port scanning)
      - Failed connection storms (brute force)
      - Data exfiltration (sustained high bandwidth, bulk data transfer, C2 DNS queries)
    """

    DEFAULT_ALLOWED_PORTS = {80, 443, 53, 22, 8080, 8443, 1080, 9050, 1194, 51820}
    KNOWN_C2_DOMAINS = {"badc2.com", "malware-c2.net", "botnet-control.org", "exfil-server.xyz"}

    def __init__(
        self,
        z_threshold: float = 3.0,
        allowed_ports: Optional[set] = None,
        expected_geos: Optional[set] = None,
        log_path: Optional[Path] = None,
    ):
        self.z_threshold = z_threshold
        self.allowed_ports = allowed_ports if allowed_ports is not None else set(self.DEFAULT_ALLOWED_PORTS)
        self.expected_geos = expected_geos if expected_geos is not None else {"US", "EU", "LOCAL", "CA", "DE", "GB", "NL"}
        self.log_path = log_path or ANOMALY_LOG_FILE

        # Rolling statistics tracking
        self.conn_rate_stats = RollingStats(window_size=50)
        self.bandwidth_stats = RollingStats(window_size=50)
        self.failed_conn_stats = RollingStats(window_size=50)

    def log_anomaly(self, anomaly_type: str, severity: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Record an anomaly alert into the log file and return entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ts": time.time(),
            "type": anomaly_type,
            "severity": severity,
            "details": details,
        }
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            _log.error("Failed to write anomaly log: %s", e)
        return entry

    def inspect_connection_batch(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze a batch of current connections for anomalies.
        """
        anomalies = []
        conn_count = len(connections)
        self.conn_rate_stats.add(conn_count)

        # 1. Connection Spike Check
        if self.conn_rate_stats.count >= 5:
            z = self.conn_rate_stats.z_score(conn_count)
            if z >= self.z_threshold:
                alert = self.log_anomaly(
                    anomaly_type="CONNECTION_SPIKE",
                    severity="HIGH",
                    details={
                        "current_connections": conn_count,
                        "mean_connections": round(self.conn_rate_stats.mean, 2),
                        "z_score": round(z, 2),
                        "message": f"Spike in outbound connections ({conn_count} vs avg {round(self.conn_rate_stats.mean, 1)})",
                    },
                )
                anomalies.append(alert)

        # 2. Failed Connection Storm Check
        failed_count = sum(1 for c in connections if c.get("status") in {"FAILED", "REFUSED", "TIMEOUT", "SYN_SENT"})
        self.failed_conn_stats.add(failed_count)
        if failed_count > 10 and (self.failed_conn_stats.count < 5 or self.failed_conn_stats.z_score(failed_count) >= self.z_threshold):
            alert = self.log_anomaly(
                anomaly_type="FAILED_CONNECTION_STORM",
                severity="HIGH",
                details={
                    "failed_count": failed_count,
                    "message": f"Potential brute-force attack or port scan: {failed_count} failed connections",
                },
            )
            anomalies.append(alert)

        # Iterate per-connection heuristics
        for conn in connections:
            port = conn.get("remote_port", 0)
            geo = conn.get("geo", "UNKNOWN").upper()
            bytes_sent = conn.get("bytes_sent", 0)
            remote_ip = conn.get("remote_ip", "")

            # 3. Port Anomaly
            if port and port not in self.allowed_ports:
                alert = self.log_anomaly(
                    anomaly_type="UNUSUAL_PORT",
                    severity="MEDIUM",
                    details={
                        "remote_ip": remote_ip,
                        "port": port,
                        "process": conn.get("process", "unknown"),
                        "message": f"Connection to unusual/unapproved port {port} on {remote_ip}",
                    },
                )
                anomalies.append(alert)

            # 4. Geolocation Anomaly
            if geo and geo not in self.expected_geos and geo != "UNKNOWN":
                alert = self.log_anomaly(
                    anomaly_type="UNEXPECTED_GEOLOCATION",
                    severity="MEDIUM",
                    details={
                        "remote_ip": remote_ip,
                        "geo": geo,
                        "message": f"Connection to unexpected geolocation: {geo} ({remote_ip})",
                    },
                )
                anomalies.append(alert)

            # 5. Bulk Data Exfiltration Check
            if bytes_sent > 50 * 1024 * 1024:  # 50 MB in single snapshot
                alert = self.log_anomaly(
                    anomaly_type="BULK_DATA_EXFILTRATION",
                    severity="CRITICAL",
                    details={
                        "remote_ip": remote_ip,
                        "bytes_sent": bytes_sent,
                        "process": conn.get("process", "unknown"),
                        "message": f"Bulk data transfer detected: {round(bytes_sent / (1024*1024), 2)} MB sent to {remote_ip}",
                    },
                )
                anomalies.append(alert)

        return anomalies

    def inspect_dns_query(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check DNS query against known C2 domain list."""
        domain_clean = domain.strip().lower().rstrip(".")
        if domain_clean in self.KNOWN_C2_DOMAINS:
            return self.log_anomaly(
                anomaly_type="C2_DNS_QUERY",
                severity="CRITICAL",
                details={
                    "domain": domain_clean,
                    "message": f"DNS query for known C2 botnet domain: {domain_clean}",
                },
            )
        return None

    def get_recent_anomalies(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Read recent log entries from anomalies log file."""
        if not self.log_path.exists():
            return []
        alerts = []
        try:
            with open(self.log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except Exception:
                            continue
            return sorted(alerts, key=lambda x: x.get("ts", 0), reverse=True)[:limit]
        except Exception:
            return []


# Global instance helper
_detector = AnomalyDetector()


def run_anomaly_check(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return _detector.inspect_connection_batch(connections)


def get_anomaly_logs(limit: int = 50) -> List[Dict[str, Any]]:
    return _detector.get_recent_anomalies(limit=limit)
