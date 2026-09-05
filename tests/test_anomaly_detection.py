import os
import tempfile
from pathlib import Path
from blackoutkit.anomaly_detector import AnomalyDetector, RollingStats, run_anomaly_check, get_anomaly_logs

def test_rolling_stats():
    rs = RollingStats(window_size=5)
    for v in [10, 10, 10, 10, 10]:
        rs.add(v)
    assert rs.mean == 10.0
    assert rs.stdev == 0.0
    assert rs.z_score(10) == 0.0

    rs.add(20)
    assert rs.count == 5
    assert rs.mean > 10.0
    assert rs.stdev > 0.0

def test_anomaly_detector_heuristics(tmp_path):
    log_file = tmp_path / "anomalies.log"
    detector = AnomalyDetector(z_threshold=2.0, log_path=log_file)

    # Normal baseline batch
    normal_conns = [
        {"remote_ip": "1.1.1.1", "remote_port": 443, "geo": "US", "bytes_sent": 1000, "status": "ESTABLISHED"}
    ]
    for _ in range(5):
        alerts = detector.inspect_connection_batch(normal_conns)
        assert len(alerts) == 0

    # Test spike & anomalies batch
    anom_conns = [
        {"remote_ip": "2.2.2.2", "remote_port": 31337, "geo": "KP", "bytes_sent": 60000000, "status": "FAILED"}
    ] * 15

    alerts = detector.inspect_connection_batch(anom_conns)
    assert len(alerts) >= 3

    # Test DNS query check
    dns_alert = detector.inspect_dns_query("badc2.com")
    assert dns_alert is not None
    assert dns_alert["type"] == "C2_DNS_QUERY"

    # Test logs reading
    recent = detector.get_recent_anomalies(limit=10)
    assert len(recent) > 0

def test_run_anomaly_check_helpers():
    conns = [{"remote_ip": "1.1.1.1", "remote_port": 9999, "geo": "XX", "bytes_sent": 10, "status": "ESTABLISHED"}]
    alerts = run_anomaly_check(conns)
    assert isinstance(alerts, list)
    logs = get_anomaly_logs(limit=5)
    assert isinstance(logs, list)
