"""Predictive optimization engine for network performance tuning."""

from __future__ import annotations

import json
import logging
import math
import os
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Optional

from . import APP_DATA_DIR

logger = logging.getLogger(__name__)
_HISTORY_LOCK = threading.Lock()
_MAX_SAMPLES_PER_HOUR = 100


@dataclass
class UsagePattern:
    """Represents a time-of-day usage pattern."""

    hour: int
    avg_connections: float
    avg_bandwidth_mbps: float
    peak_protocol: str
    reliability_pct: float


@dataclass
class OptimizationRecommendation:
    """Recommended optimization based on patterns."""

    timestamp: str
    recommendation_type: str
    current_value: str
    suggested_value: str
    reason: str
    expected_improvement_pct: float
    confidence: float


class Predictor:
    """Time-series learner for predictive network optimization."""

    def __init__(
        self, stats_dir: Optional[Path] = None, *, load_history: bool = True
    ):
        self.stats_dir = Path(stats_dir or APP_DATA_DIR / "stats")
        self.history_file = self.stats_dir / "history.json"
        self.hourly_stats: dict[int, dict] = {}
        if load_history:
            self._load_history()

    @staticmethod
    def _hour(value: object) -> int:
        try:
            hour = int(value)
        except (TypeError, ValueError):
            raise ValueError("hour must be an integer from 0 to 23") from None
        if not 0 <= hour <= 23:
            raise ValueError("hour must be an integer from 0 to 23")
        return hour

    @staticmethod
    def _finite_number(value: object, *, name: str) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{name} must be a finite non-negative number") from None
        if not math.isfinite(number) or number < 0:
            raise ValueError(f"{name} must be a finite non-negative number")
        return number

    @staticmethod
    def _new_stats() -> dict:
        return {
            "connections": [],
            "connection_count": 0,
            "bandwidth": [],
            "protocols": {},
            "successes": 0,
            "failures": 0,
            "samples": [],
        }

    def record_connection(
        self,
        protocol: str,
        bandwidth_mbps: float,
        success: bool = True,
        hour: Optional[int] = None,
    ) -> None:
        """Record a connection for pattern learning."""
        normalized_hour = (
            datetime.now(timezone.utc).hour if hour is None else self._hour(hour)
        )
        bandwidth = self._finite_number(bandwidth_mbps, name="bandwidth_mbps")
        normalized_protocol = str(protocol or "https").strip().casefold() or "https"
        stats = self.hourly_stats.setdefault(normalized_hour, self._new_stats())

        stats["connections"].append(1)
        stats["bandwidth"].append(bandwidth)
        stats["samples"].append(
            {"connections": 1, "bandwidth": bandwidth, "protocol": normalized_protocol, "success": bool(success)}
        )
        stats["connection_count"] = int(stats.get("connection_count", 0)) + 1
        for key in ("connections", "bandwidth", "samples"):
            if len(stats[key]) > _MAX_SAMPLES_PER_HOUR:
                stats[key] = stats[key][-_MAX_SAMPLES_PER_HOUR:]
        self._recompute_sample_counters(stats)

    @staticmethod
    def _recompute_sample_counters(stats: dict) -> None:
        samples = stats.get("samples")
        if not isinstance(samples, list):
            return
        protocols: dict[str, int] = {}
        successes = failures = 0
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            protocol = str(sample.get("protocol", "https")).casefold() or "https"
            protocols[protocol] = protocols.get(protocol, 0) + 1
            if sample.get("success", True):
                successes += 1
            else:
                failures += 1
        stats["protocols"] = protocols
        stats["successes"] = successes
        stats["failures"] = failures

    def get_pattern(self, hour: int) -> Optional[UsagePattern]:
        """Get learned usage pattern for a specific hour."""
        try:
            normalized_hour = self._hour(hour)
        except ValueError:
            return None
        stats = self.hourly_stats.get(normalized_hour)
        if not isinstance(stats, dict) or not stats.get("connections"):
            return None

        protocols = stats.get("protocols") or {}
        peak_protocol = max(protocols, key=protocols.get) if protocols else "https"
        total = int(stats.get("successes", 0)) + int(stats.get("failures", 0))
        reliability_pct = (int(stats.get("successes", 0)) / total * 100) if total else 100.0
        return UsagePattern(
            hour=normalized_hour,
            avg_connections=mean(stats["connections"]),
            avg_bandwidth_mbps=mean(stats.get("bandwidth") or [0]),
            peak_protocol=peak_protocol,
            reliability_pct=reliability_pct,
        )

    def predict_peak_hours(self) -> list[int]:
        """Predict peak hours based on historical connection volume."""
        volumes = [
            (hour, int(stats.get("connection_count", len(stats.get("connections", [])))))
            for hour, stats in self.hourly_stats.items()
            if isinstance(stats, dict) and stats.get("connections")
        ]
        if not volumes:
            return []
        threshold = mean(value for _, value in volumes)
        return sorted(hour for hour, value in volumes if value > threshold)

    @staticmethod
    def _recommendation_timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def recommend_transport(self, current_transport: str = "https") -> Optional[OptimizationRecommendation]:
        """Recommend transport based on reliability patterns."""
        current_hour = datetime.now(timezone.utc).hour
        pattern = self.get_pattern(current_hour)
        if not pattern or pattern.reliability_pct > 95:
            return None
        alternatives = {"https": "xhttp", "xhttp": "https", "reality": "https"}
        current = str(current_transport).casefold()
        if current not in alternatives:
            return None
        return OptimizationRecommendation(
            timestamp=self._recommendation_timestamp(),
            recommendation_type="transport",
            current_value=current,
            suggested_value=alternatives[current],
            reason=f"Current transport {pattern.reliability_pct:.1f}% reliable at this hour",
            expected_improvement_pct=10.0,
            confidence=0.75,
        )

    def recommend_dns_failover(self, primary_dns: str = "8.8.8.8") -> Optional[OptimizationRecommendation]:
        """Recommend DNS failover based on time-of-day patterns."""
        current_hour = datetime.now(timezone.utc).hour
        pattern = self.get_pattern(current_hour)
        if not pattern or pattern.reliability_pct > 90:
            return None
        failovers = {"8.8.8.8": "1.1.1.1", "1.1.1.1": "8.8.8.8"}
        if primary_dns not in failovers:
            return None
        return OptimizationRecommendation(
            timestamp=self._recommendation_timestamp(),
            recommendation_type="dns",
            current_value=primary_dns,
            suggested_value=failovers[primary_dns],
            reason=f"DNS reliability issues detected at hour {current_hour}",
            expected_improvement_pct=5.0,
            confidence=0.65,
        )

    def recommend_config_rotation(self) -> Optional[OptimizationRecommendation]:
        """Recommend proactive config rotation before predicted peak windows."""
        peak_hours = self.predict_peak_hours()
        if not peak_hours:
            return None
        current_hour = datetime.now(timezone.utc).hour
        next_peak = min((hour - current_hour) % 24 for hour in peak_hours)
        if next_peak != 1:
            return None
        return OptimizationRecommendation(
            timestamp=self._recommendation_timestamp(),
            recommendation_type="config_rotation",
            current_value="current_config",
            suggested_value="rotate_to_secondary",
            reason=f"Peak usage hour approaching in {next_peak} hour(s)",
            expected_improvement_pct=15.0,
            confidence=0.70,
        )

    def get_all_recommendations(self) -> list[OptimizationRecommendation]:
        """Get all active recommendations."""
        recommendations = []
        for recommendation in (
            self.recommend_transport(),
            self.recommend_dns_failover(),
            self.recommend_config_rotation(),
        ):
            if recommendation:
                recommendations.append(recommendation)
        return recommendations

    def _history_payload(self) -> dict[str, dict]:
        data: dict[str, dict] = {}
        for hour, stats in sorted(self.hourly_stats.items()):
            if not isinstance(stats, dict) or not stats.get("connections"):
                continue
            self._recompute_sample_counters(stats)
            protocols = stats.get("protocols") or {}
            total = int(stats.get("successes", 0)) + int(stats.get("failures", 0))
            data[str(hour)] = {
                "avg_connections": mean(stats["connections"]),
                "avg_bandwidth_mbps": mean(stats.get("bandwidth") or [0]),
                "peak_protocol": max(protocols, key=protocols.get) if protocols else "https",
                "reliability_pct": int(stats.get("successes", 0)) / total * 100 if total else 100.0,
                "sample_count": len(stats["connections"]),
                "connection_count": int(stats.get("connection_count", len(stats["connections"]))),
                "successes": int(stats.get("successes", 0)),
                "failures": int(stats.get("failures", 0)),
                "protocols": protocols,
                "samples": stats.get("samples", []),
            }
        return data

    def save_history(self) -> None:
        """Persist learning history using an atomic replacement."""
        self.stats_dir.mkdir(parents=True, exist_ok=True)
        payload = self._history_payload()
        with _HISTORY_LOCK:
            descriptor, temporary = tempfile.mkstemp(
                prefix=".history-", suffix=".json", dir=self.stats_dir
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.history_file)
            except OSError:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise

    @classmethod
    def _stats_from_history(cls, stats: object) -> Optional[dict]:
        if not isinstance(stats, dict):
            return None
        try:
            sample_count = int(stats.get("sample_count", 1))
            connection_count = int(stats.get("connection_count", sample_count))
            if sample_count < 1 or connection_count < sample_count:
                return None
            avg_connections = float(stats.get("avg_connections", 1))
            avg_bandwidth = float(stats.get("avg_bandwidth_mbps", 0))
            if not all(math.isfinite(value) or value == 0 for value in (avg_connections, avg_bandwidth)):
                return None
            if avg_connections < 0 or avg_bandwidth < 0:
                return None
            successes = int(stats.get("successes", round(float(stats.get("reliability_pct", 100)) * sample_count / 100)))
            failures = int(stats.get("failures", sample_count - successes))
            if successes < 0 or failures < 0 or successes + failures != sample_count:
                return None
        except (TypeError, ValueError, OverflowError):
            return None

        samples = stats.get("samples")
        if isinstance(samples, list):
            valid_samples = []
            for sample in samples[-_MAX_SAMPLES_PER_HOUR:]:
                if not isinstance(sample, dict):
                    continue
                try:
                    bandwidth = float(sample.get("bandwidth", 0))
                except (TypeError, ValueError):
                    continue
                if not math.isfinite(bandwidth) or bandwidth < 0:
                    continue
                valid_samples.append({
                    "connections": 1,
                    "bandwidth": bandwidth,
                    "protocol": str(sample.get("protocol", "https")).casefold() or "https",
                    "success": bool(sample.get("success", True)),
                })
            if len(valid_samples) == sample_count:
                samples = valid_samples
        if not isinstance(samples, list) or len(samples) != sample_count:
            protocol = str(stats.get("peak_protocol", "https")).casefold() or "https"
            samples = [
                {"connections": avg_connections, "bandwidth": avg_bandwidth, "protocol": protocol, "success": index < successes}
                for index in range(sample_count)
            ]

        result = cls._new_stats()
        result["connections"] = [sample["connections"] for sample in samples][- _MAX_SAMPLES_PER_HOUR:]
        result["bandwidth"] = [sample["bandwidth"] for sample in samples][- _MAX_SAMPLES_PER_HOUR:]
        result["samples"] = samples[-_MAX_SAMPLES_PER_HOUR:]
        result["connection_count"] = connection_count
        cls._recompute_sample_counters(result)
        return result

    def _load_history(self) -> None:
        """Load historical patterns, ignoring malformed records."""
        if not self.history_file.exists():
            return
        try:
            data = json.loads(self.history_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.warning("Could not load predictor history: invalid or unreadable file")
            return
        if not isinstance(data, dict):
            logger.warning("Could not load predictor history: expected an object")
            return
        for hour_text, raw_stats in data.items():
            try:
                hour = self._hour(hour_text)
            except ValueError:
                continue
            stats = self._stats_from_history(raw_stats)
            if stats is not None:
                self.hourly_stats[hour] = stats

    def clear_history(self) -> None:
        """Clear all learned patterns."""
        self.hourly_stats.clear()
        try:
            self.history_file.unlink(missing_ok=True)
        except OSError:
            pass
