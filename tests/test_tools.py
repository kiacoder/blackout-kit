import pytest
from blackoutkit.tools import ping_stats

def test_ping_stats_empty():
    times = []
    result = ping_stats(times)
    assert result == {
        "avg": None,
        "min": None,
        "max": None,
        "jitter": None,
        "loss_pct": 100.0,
    }

def test_ping_stats_all_none():
    times = [None, None, None]
    result = ping_stats(times)
    assert result == {
        "avg": None,
        "min": None,
        "max": None,
        "jitter": None,
        "loss_pct": 100.0,
    }

def test_ping_stats_single_value():
    times = [10.0]
    result = ping_stats(times)
    assert result == {
        "avg": 10.0,
        "min": 10.0,
        "max": 10.0,
        "jitter": None,
        "loss_pct": 0.0,
    }

def test_ping_stats_mixed():
    times = [10.0, None, 20.0]
    result = ping_stats(times)
    assert result["avg"] == 15.0
    assert result["min"] == 10.0
    assert result["max"] == 20.0
    assert result["jitter"] == 10.0
    assert result["loss_pct"] == pytest.approx(33.333333333333336)

def test_ping_stats_all_valid():
    times = [10.0, 20.0, 30.0]
    result = ping_stats(times)
    assert result == {
        "avg": 20.0,
        "min": 10.0,
        "max": 30.0,
        "jitter": 10.0,
        "loss_pct": 0.0,
    }

def test_ping_stats_jitter_calculation():
    # 10.0 -> 5.0 (diff 5.0) -> 15.0 (diff 10.0) -> sum = 15.0, avg = 7.5
    times = [10.0, 5.0, 15.0]
    result = ping_stats(times)
    assert result["jitter"] == 7.5
