"""
Blackout Kit - Time-Series Predictor & Predictive Optimization Engine.
Tracks usage statistics over time (hourly/daily/weekly) and generates
predictive recommendations for transport modes, fingerprinting, DNS failover,
and pre-rotation windows.
"""
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from blackoutkit import APP_DATA_DIR

_log = logging.getLogger(__name__)

STATS_DIR = APP_DATA_DIR / "stats"
HISTORY_FILE = STATS_DIR / "history.json"


class NetworkUsagePredictor:
    """Learns usage patterns over time-series windows and computes config recommendations."""

    def __init__(self, history_file: Path = HISTORY_FILE):
        self.history_file = history_file
        self.history_file.parent.mkdir(parents=True, exist_ok=True)

    def _load_history(self) -> Dict[str, Any]:
        if not self.history_file.exists():
            return {"hourly_samples": [], "daily_summary": {}}
        try:
            with open(self.history_file, "r") as f:
                return json.load(f)
        except Exception as e:
            _log.error("Failed to load history file: %s", e)
            return {"hourly_samples": [], "daily_summary": {}}

    def _save_history(self, data: Dict[str, Any]) -> None:
        try:
            self.history_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.history_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            _log.error("Failed to save history file: %s", e)

    def record_usage_snapshot(
        self,
        bandwidth_bytes: int,
        active_connections: int,
        dns_latency_ms: float = 20.0,
        packet_loss_pct: float = 0.0,
    ) -> Dict[str, Any]:
        """Record an hourly sample into history."""
        data = self._load_history()
        now_dt = datetime.now(timezone.utc)
        sample = {
            "timestamp": now_dt.isoformat(),
            "ts": time.time(),
            "hour": now_dt.hour,
            "day_of_week": now_dt.weekday(),
            "bandwidth_bytes": bandwidth_bytes,
            "active_connections": active_connections,
            "dns_latency_ms": dns_latency_ms,
            "packet_loss_pct": packet_loss_pct,
        }
        data["hourly_samples"].append(sample)

        # Keep last 168 hours (1 week)
        if len(data["hourly_samples"]) > 168:
            data["hourly_samples"] = data["hourly_samples"][-168:]

        self._save_history(data)
        return sample

    def analyze_patterns(self) -> Dict[str, Any]:
        """Analyze time-series trends (peak hours, average bandwidth, peak connections)."""
        data = self._load_history()
        samples = data.get("hourly_samples", [])

        if not samples:
            return {
                "peak_hours": [19, 20, 21, 22],  # Default fallback peak hours (7 PM - 10 PM)
                "avg_bandwidth": 0,
                "peak_bandwidth": 0,
                "avg_connections": 0,
                "total_samples": 0,
            }

        hourly_bw: Dict[int, List[int]] = {h: [] for h in range(24)}
        total_bw = 0
        total_conns = 0

        for s in samples:
            h = s.get("hour", 0)
            bw = s.get("bandwidth_bytes", 0)
            conns = s.get("active_connections", 0)
            hourly_bw[h].append(bw)
            total_bw += bw
            total_conns += conns

        # Calculate average bandwidth per hour
        hourly_means = {h: (sum(bws) / len(bws) if bws else 0) for h, bws in hourly_bw.items()}
        sorted_hours = sorted(hourly_means.keys(), key=lambda h: hourly_means[h], reverse=True)
        peak_hours = sorted_hours[:4]

        return {
            "peak_hours": sorted(peak_hours),
            "avg_bandwidth": round(total_bw / len(samples), 2),
            "peak_bandwidth": max((s.get("bandwidth_bytes", 0) for s in samples), default=0),
            "avg_connections": round(total_conns / len(samples), 2),
            "total_samples": len(samples),
        }

    def generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate predictive recommendations based on usage patterns."""
        patterns = self.analyze_patterns()
        current_hour = datetime.now(timezone.utc).hour
        recommendations = []

        # 1. Peak Hour Recommendation
        if current_hour in patterns["peak_hours"]:
            recommendations.append(
                {
                    "category": "TRANSPORT_FINGERPRINT",
                    "action": "ENABLE_HYSTERIA2_CHROME_FP",
                    "priority": "HIGH",
                    "reason": f"Current hour ({current_hour}:00 UTC) is a predicted peak congestion window.",
                    "suggested_config": {"protocol": "hysteria2", "fingerprint": "chrome", "obfs": "salamander"},
                }
            )

        # 2. DNS Reliability Recommendation
        data = self._load_history()
        samples = data.get("hourly_samples", [])
        recent_dns_latency = [s.get("dns_latency_ms", 20.0) for s in samples[-6:]]
        avg_dns = sum(recent_dns_latency) / len(recent_dns_latency) if recent_dns_latency else 20.0

        if avg_dns > 100.0:
            recommendations.append(
                {
                    "category": "DNS_FAILOVER",
                    "action": "SWITCH_TO_DOH_CLOUDFLARE",
                    "priority": "MEDIUM",
                    "reason": f"High DNS latency detected ({round(avg_dns, 1)}ms). Time-of-day DNS degrade predicted.",
                    "suggested_config": {"dns_resolver": "https://1.1.1.1/dns-query", "dns_mode": "doh"},
                }
            )

        # 3. Pre-Rotation Recommendation
        # Pre-rotate 1 hour before peak window
        upcoming_hour = (current_hour + 1) % 24
        if upcoming_hour in patterns["peak_hours"] and current_hour not in patterns["peak_hours"]:
            recommendations.append(
                {
                    "category": "PRE_ROTATE_CONFIG",
                    "action": "ROTATE_SERVER_PROXIES",
                    "priority": "HIGH",
                    "reason": f"Predicted ISP blocking window approaching at {upcoming_hour}:00 UTC. Pre-rotating configs.",
                    "suggested_config": {"auto_rotate": True, "rotation_interval_sec": 1800},
                }
            )

        if not recommendations:
            recommendations.append(
                {
                    "category": "GENERAL_OPTIMIZATION",
                    "action": "MAINTAIN_CURRENT_CONFIG",
                    "priority": "LOW",
                    "reason": "Network traffic is normal and within optimal historical baseline.",
                    "suggested_config": {},
                }
            )

        return recommendations


_predictor = NetworkUsagePredictor()


def record_stats_snapshot(bw: int, conns: int) -> Dict[str, Any]:
    return _predictor.record_usage_snapshot(bandwidth_bytes=bw, active_connections=conns)


def get_predictive_recommendations() -> List[Dict[str, Any]]:
    return _predictor.generate_recommendations()


def get_usage_patterns() -> Dict[str, Any]:
    return _predictor.analyze_patterns()
