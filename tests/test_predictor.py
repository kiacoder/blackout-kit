"""Tests for predictive optimization engine."""

import json

import pytest

from blackoutkit.predictor import Predictor, UsagePattern, OptimizationRecommendation


class TestRecordConnection:
    """Test recording connections for pattern learning."""

    def test_records_connection(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("https", 10.0, success=True, hour=14)
        assert 14 in predictor.hourly_stats
        assert predictor.hourly_stats[14]["connections"] == [1]
        assert predictor.hourly_stats[14]["bandwidth"] == [10.0]

    def test_tracks_protocol_counts(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("https", 10.0, hour=10)
        predictor.record_connection("https", 12.0, hour=10)
        predictor.record_connection("xhttp", 5.0, hour=10)
        assert predictor.hourly_stats[10]["protocols"]["https"] == 2
        assert predictor.hourly_stats[10]["protocols"]["xhttp"] == 1

    def test_tracks_success_and_failure(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("https", 10.0, success=True, hour=5)
        predictor.record_connection("https", 10.0, success=False, hour=5)
        assert predictor.hourly_stats[5]["successes"] == 1
        assert predictor.hourly_stats[5]["failures"] == 1

    def test_caps_samples_at_100(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        for i in range(150):
            predictor.record_connection("https", 10.0, hour=3)
        assert len(predictor.hourly_stats[3]["connections"]) == 100
        assert len(predictor.hourly_stats[3]["bandwidth"]) == 100
        assert predictor.hourly_stats[3]["connection_count"] == 150

    def test_uses_current_hour_when_not_specified(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("https", 10.0)
        assert len(predictor.hourly_stats) == 1


class TestGetPattern:
    """Test retrieving learned usage patterns."""

    def test_returns_none_for_unknown_hour(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        assert predictor.get_pattern(7) is None

    def test_returns_pattern_for_known_hour(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("https", 10.0, success=True, hour=9)
        predictor.record_connection("https", 20.0, success=True, hour=9)

        pattern = predictor.get_pattern(9)
        assert isinstance(pattern, UsagePattern)
        assert pattern.hour == 9
        assert pattern.avg_connections == pytest.approx(1.0)
        assert pattern.avg_bandwidth_mbps == pytest.approx(15.0)
        assert pattern.peak_protocol == "https"
        assert pattern.reliability_pct == pytest.approx(100.0)

    def test_reliability_reflects_failures(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("https", 10.0, success=True, hour=9)
        predictor.record_connection("https", 10.0, success=False, hour=9)
        pattern = predictor.get_pattern(9)
        assert pattern.reliability_pct == pytest.approx(50.0)

    def test_peak_protocol_is_most_common(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("xhttp", 1.0, hour=9)
        predictor.record_connection("https", 1.0, hour=9)
        predictor.record_connection("https", 1.0, hour=9)
        pattern = predictor.get_pattern(9)
        assert pattern.peak_protocol == "https"


class TestPredictPeakHours:
    """Test peak hour prediction."""

    def test_returns_empty_with_no_data(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        assert predictor.predict_peak_hours() == []

    def test_returns_hours_above_mean(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        for _ in range(10):
            predictor.record_connection("https", 1.0, hour=8)
        for _ in range(1):
            predictor.record_connection("https", 1.0, hour=2)

        peaks = predictor.predict_peak_hours()
        assert 8 in peaks
        assert 2 not in peaks


class TestRecommendTransport:
    """Test transport recommendations."""

    def test_no_recommendation_when_reliable(self, tmp_path, monkeypatch):
        predictor = Predictor(stats_dir=tmp_path)
        current_hour = _fixed_hour(monkeypatch, "blackoutkit.predictor", 12)
        predictor.record_connection("https", 10.0, success=True, hour=current_hour)
        assert predictor.recommend_transport("https") is None

    def test_recommends_alternative_when_unreliable(self, tmp_path, monkeypatch):
        predictor = Predictor(stats_dir=tmp_path)
        current_hour = _fixed_hour(monkeypatch, "blackoutkit.predictor", 12)
        for _ in range(9):
            predictor.record_connection("https", 10.0, success=False, hour=current_hour)
        predictor.record_connection("https", 10.0, success=True, hour=current_hour)

        rec = predictor.recommend_transport("https")
        assert isinstance(rec, OptimizationRecommendation)
        assert rec.recommendation_type == "transport"
        assert rec.current_value == "https"
        assert rec.suggested_value == "xhttp"

    def test_no_recommendation_for_unknown_transport(self, tmp_path, monkeypatch):
        predictor = Predictor(stats_dir=tmp_path)
        current_hour = _fixed_hour(monkeypatch, "blackoutkit.predictor", 12)
        for _ in range(9):
            predictor.record_connection("wireguard", 10.0, success=False, hour=current_hour)
        assert predictor.recommend_transport("wireguard") is None


class TestRecommendDnsFailover:
    """Test DNS failover recommendations."""

    def test_no_recommendation_when_reliable(self, tmp_path, monkeypatch):
        predictor = Predictor(stats_dir=tmp_path)
        current_hour = _fixed_hour(monkeypatch, "blackoutkit.predictor", 6)
        predictor.record_connection("https", 10.0, success=True, hour=current_hour)
        assert predictor.recommend_dns_failover("8.8.8.8") is None

    def test_recommends_failover_when_unreliable(self, tmp_path, monkeypatch):
        predictor = Predictor(stats_dir=tmp_path)
        current_hour = _fixed_hour(monkeypatch, "blackoutkit.predictor", 6)
        for _ in range(9):
            predictor.record_connection("https", 10.0, success=False, hour=current_hour)
        predictor.record_connection("https", 10.0, success=True, hour=current_hour)

        rec = predictor.recommend_dns_failover("8.8.8.8")
        assert rec is not None
        assert rec.recommendation_type == "dns"
        assert rec.suggested_value == "1.1.1.1"

    def test_no_recommendation_for_unknown_dns(self, tmp_path, monkeypatch):
        predictor = Predictor(stats_dir=tmp_path)
        current_hour = _fixed_hour(monkeypatch, "blackoutkit.predictor", 6)
        for _ in range(9):
            predictor.record_connection("https", 10.0, success=False, hour=current_hour)
        assert predictor.recommend_dns_failover("9.9.9.9") is None


class TestRecommendConfigRotation:
    """Test config rotation recommendations."""

    def test_no_recommendation_with_no_peaks(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        assert predictor.recommend_config_rotation() is None

    def test_recommends_rotation_one_hour_before_peak(self, tmp_path, monkeypatch):
        predictor = Predictor(stats_dir=tmp_path)
        current_hour = _fixed_hour(monkeypatch, "blackoutkit.predictor", 10)
        peak_hour = (current_hour + 1) % 24

        for _ in range(10):
            predictor.record_connection("https", 1.0, hour=peak_hour)
        predictor.record_connection("https", 1.0, hour=(current_hour + 5) % 24)

        rec = predictor.recommend_config_rotation()
        assert rec is not None
        assert rec.recommendation_type == "config_rotation"


class TestGetAllRecommendations:
    """Test aggregation of all recommendation types."""

    def test_returns_list(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        recs = predictor.get_all_recommendations()
        assert isinstance(recs, list)


class TestHistoryPersistence:
    """Test save/load history persistence."""

    def test_save_and_load_history(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("https", 10.0, success=True, hour=15)
        predictor.record_connection("https", 20.0, success=True, hour=15)
        predictor.save_history()

        assert predictor.history_file.exists()
        with open(predictor.history_file) as f:
            data = json.load(f)
        assert "15" in data
        assert data["15"]["peak_protocol"] == "https"

    def test_loads_history_on_init(self, tmp_path):
        predictor1 = Predictor(stats_dir=tmp_path)
        predictor1.record_connection("https", 10.0, success=True, hour=3)
        predictor1.save_history()

        predictor2 = Predictor(stats_dir=tmp_path)
        assert 3 in predictor2.hourly_stats
        pattern = predictor2.get_pattern(3)
        assert pattern is not None
        assert pattern.avg_bandwidth_mbps == pytest.approx(10.0)

    def test_persists_uncapped_connection_volume(self, tmp_path):
        predictor1 = Predictor(stats_dir=tmp_path)
        for _ in range(150):
            predictor1.record_connection("https", 10.0, hour=3)
        predictor1.save_history()

        predictor2 = Predictor(stats_dir=tmp_path)

        assert len(predictor2.hourly_stats[3]["connections"]) == 100
        assert predictor2.hourly_stats[3]["connection_count"] == 150

    def test_clear_history(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("https", 10.0, hour=4)
        predictor.save_history()
        assert predictor.history_file.exists()

        predictor.clear_history()
        assert not predictor.history_file.exists()
        assert predictor.hourly_stats == {}

    def test_preserves_non_integer_reliability_after_round_trip(self, tmp_path):
        predictor = Predictor(stats_dir=tmp_path)
        predictor.record_connection("https", 10.0, success=True, hour=11)
        predictor.record_connection("https", 10.0, success=False, hour=11)
        predictor.record_connection("https", 10.0, success=False, hour=11)
        predictor.save_history()

        restored = Predictor(stats_dir=tmp_path)

        assert restored.get_pattern(11).reliability_pct == pytest.approx(100 / 3)
        assert restored.hourly_stats[11]["successes"] == 1
        assert restored.hourly_stats[11]["failures"] == 2


def _fixed_hour(monkeypatch, module_path: str, hour: int) -> int:
    """Patch datetime.now(tz=...) in the given module to return a fixed hour."""
    import datetime as real_datetime

    class FixedDateTime(real_datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.datetime(2026, 1, 1, hour, 0, 0)

    monkeypatch.setattr(f"{module_path}.datetime", FixedDateTime)
    return hour
