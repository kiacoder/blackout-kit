import json
from pathlib import Path
from blackoutkit.predictor import NetworkUsagePredictor, record_stats_snapshot, get_predictive_recommendations, get_usage_patterns

def test_predictor_recording_and_patterns(tmp_path):
    history_file = tmp_path / "history.json"
    predictor = NetworkUsagePredictor(history_file=history_file)

    # Record snapshots
    for i in range(10):
        predictor.record_usage_snapshot(
            bandwidth_bytes=1000 * (i + 1),
            active_connections=5 + i,
            dns_latency_ms=15.0 + i,
        )

    patterns = predictor.analyze_patterns()
    assert patterns["total_samples"] == 10
    assert patterns["avg_bandwidth"] > 0
    assert patterns["peak_bandwidth"] == 10000

    recs = predictor.generate_recommendations()
    assert isinstance(recs, list)
    assert len(recs) >= 1

def test_predictor_helpers():
    snapshot = record_stats_snapshot(bw=5000, conns=10)
    assert snapshot["bandwidth_bytes"] == 5000

    patterns = get_usage_patterns()
    assert isinstance(patterns, dict)

    recs = get_predictive_recommendations()
    assert isinstance(recs, list)
