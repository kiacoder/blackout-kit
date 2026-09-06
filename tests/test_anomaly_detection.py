"""Tests for anomaly detection engine."""

import json
import time
from pathlib import Path
from datetime import datetime

import pytest

from blackoutkit.anomaly_detector import (
    AnomalyDetector,
    Anomaly,
    ConnectionEvent,
    RollingStats,
)


class TestRollingStats:
    """Test rolling statistics calculation."""

    def test_empty_stats(self):
        stats = RollingStats()
        assert stats.mean() == 0
        assert stats.stdev() == 0
        assert not stats.is_ready

    def test_single_value(self):
        stats = RollingStats()
        stats.add(10)
        assert not stats.is_ready
        assert stats.mean() == 10

    def test_multiple_values(self):
        stats = RollingStats()
        for i in range(10):
            stats.add(i)
        assert stats.is_ready
        assert stats.mean() == pytest.approx(4.5)

    def test_zscore_calculation(self):
        stats = RollingStats()
        for i in range(100):
            stats.add(i % 10)
        zscore = stats.zscore(50)
        assert zscore > 2  # Should be many std devs away

    def test_window_size_limit(self):
        stats = RollingStats(window_size=5)
        for i in range(10):
            stats.add(i)
        assert len(stats.values) == 5
        assert list(stats.values) == [5, 6, 7, 8, 9]


class TestConnectionSpike:
    """Test connection spike detection."""

    def test_no_spike_in_stable_traffic(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        for i in range(10):
            event = ConnectionEvent(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                dst_port=443,
                protocol="https",
                state="established",
            )
            anomaly = detector.detect(event)
            assert anomaly is None

    def test_detects_spike(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path, z_threshold=1.5)
        # Establish baseline
        for i in range(20):
            event = ConnectionEvent(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                dst_port=443,
                protocol="https",
                state="established",
            )
            detector.detect(event)

        # Spike
        for i in range(50):
            event = ConnectionEvent(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                dst_port=443,
                protocol="https",
                state="established",
            )
            anomaly = detector.detect(event)

        # At least one spike should be detected
        spikes = [a for a in detector.anomalies if a.anomaly_type == "connection_spike"]
        assert len(spikes) > 0


class TestFailedStorm:
    """Test failed connection storm detection."""

    def test_detects_failed_storm(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        for i in range(15):
            event = ConnectionEvent(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                dst_port=22,
                protocol="ssh",
                state="failed",
            )
            anomaly = detector.detect(event)

        storms = [a for a in detector.anomalies if a.anomaly_type == "failed_connection_storm"]
        assert len(storms) >= 1
        assert storms[0].severity in ["high", "critical"]

    def test_no_storm_with_few_failures(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        for i in range(5):
            event = ConnectionEvent(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                dst_port=22,
                protocol="ssh",
                state="failed",
            )
            anomaly = detector.detect(event)
            assert anomaly is None


class TestUnusualGeolocation:
    """Test unusual geolocation detection."""

    def test_detects_unusual_geolocation(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        event = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol="https",
            geolocation="KP",
            state="established",
        )
        anomaly = detector.detect(event)
        assert anomaly is not None
        assert anomaly.anomaly_type == "unusual_geolocation"

    def test_ignores_normal_geolocation(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        event = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol="https",
            geolocation="US",
            state="established",
        )
        anomaly = detector.detect(event)
        assert anomaly is None


class TestUnusualPort:
    """Test unusual port detection."""

    def test_detects_unusual_port(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        event = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=3389,  # RDP
            protocol="tcp",
            state="established",
        )
        anomaly = detector.detect(event)
        assert anomaly is not None
        assert anomaly.anomaly_type == "unusual_port"

    def test_ignores_normal_ports(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        event = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol="https",
            state="established",
        )
        anomaly = detector.detect(event)
        assert anomaly is None


class TestExfiltration:
    """Test data exfiltration detection."""

    def test_detects_bulk_transfer(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path, z_threshold=1.5)
        # Baseline small transfers
        for i in range(10):
            event = ConnectionEvent(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                dst_port=443,
                protocol="https",
                bytes_sent=100 * 1024,  # 100KB
                state="established",
            )
            detector.detect(event)

        # Large transfer
        event = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol="https",
            bytes_sent=500 * 1024 * 1024,  # 500MB
            state="established",
        )
        anomaly = detector.detect(event)

        exfils = [a for a in detector.anomalies if a.anomaly_type == "bulk_exfiltration"]
        assert len(exfils) > 0
        assert exfils[0].severity == "critical"

    def test_ignores_small_transfers(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        event = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=443,
            protocol="https",
            bytes_sent=10 * 1024,  # 10KB
            state="established",
        )
        anomaly = detector.detect(event)
        assert anomaly is None


class TestC2DNSDetection:
    """Test C2 DNS detection."""

    def test_detects_c2_domain(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        c2_list = ["evil.com", "malware.net", "bot.org"]
        anomaly = detector.detect_c2_dns("malware.net", c2_list)
        assert anomaly is not None
        assert anomaly.anomaly_type == "c2_dns_query"
        assert anomaly.severity == "critical"

    def test_ignores_normal_domain(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        c2_list = ["evil.com", "malware.net"]
        anomaly = detector.detect_c2_dns("google.com", c2_list)
        assert anomaly is None

    def test_normalizes_and_persists_case_insensitive_domain(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        anomaly = detector.detect_c2_dns("MALWARE.NET.", ["malware.net"])

        assert anomaly is not None
        assert detector.alert_summary()["by_type"] == {"c2_dns_query": 1}
        assert detector.get_anomalies()[0].affected_ip == "malware.net"


class TestAnomalyLogging:
    """Test anomaly persistence and retrieval."""

    def test_logs_anomalies(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        event = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=3389,
            protocol="tcp",
            state="established",
        )
        detector.detect(event)

        assert detector.anomaly_log.exists()
        with open(detector.anomaly_log) as f:
            data = json.load(f)
            assert len(data) > 0
            assert data[0]["anomaly_type"] == "unusual_port"

    def test_read_only_detection_does_not_write_log(self, tmp_path):
        log_dir = tmp_path / "missing"
        detector = AnomalyDetector(log_dir=log_dir, persist=False)
        event = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=3389,
            protocol="tcp",
            state="established",
        )

        anomaly = detector.detect(event)

        assert anomaly is not None
        assert detector.anomalies == [anomaly]
        assert not log_dir.exists()

    def test_retrieves_anomalies(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        for i in range(5):
            event = ConnectionEvent(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                dst_port=3389,
                protocol="tcp",
                state="established",
            )
            detector.detect(event)

        anomalies = detector.get_anomalies()
        assert len(anomalies) >= 5

    def test_filters_by_severity(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        event = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=3389,
            protocol="tcp",
            state="established",
        )
        detector.detect(event)

        critical = detector.get_anomalies(severity="critical")
        assert len(critical) == 0

        medium = detector.get_anomalies(severity="medium")
        assert len(medium) >= 1


class TestAlertSummary:
    """Test anomaly summary statistics."""

    def test_generates_summary(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)

        # Unusual port
        event1 = ConnectionEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=3389,
            protocol="tcp",
            state="established",
        )
        detector.detect(event1)

        # Failed storm
        for i in range(15):
            event2 = ConnectionEvent(
                timestamp=time.time(),
                src_ip="192.168.1.100",
                dst_ip="10.0.0.2",
                dst_port=22,
                protocol="ssh",
                state="failed",
            )
            detector.detect(event2)

        summary = detector.alert_summary()
        assert summary["total"] >= 2
        assert "unusual_port" in summary["by_type"]
        assert "failed_connection_storm" in summary["by_type"]
        assert "medium" in summary["by_severity"]
        assert "high" in summary["by_severity"]


class TestHourlyReset:
    """Test hourly reset functionality."""

    def test_hourly_reset(self, tmp_path):
        detector = AnomalyDetector(log_dir=tmp_path)
        detector.reset_hourly()
        assert len(detector.hourly_connections) == 1
        assert len(detector.hourly_bandwidth) == 1

        detector.reset_hourly()
        assert len(detector.hourly_connections) == 2
