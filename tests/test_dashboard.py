"""
Tests for the LiveDashboard module.
Verifies status collection, health calculation, rendering, and formatting.
"""
import pytest
from unittest.mock import patch

from blackoutkit.dashboard import LiveDashboard


class TestLiveDashboard:
    """Test suite for LiveDashboard class."""

    @pytest.fixture
    def dashboard(self):
        """Provide a dashboard instance."""
        return LiveDashboard(refresh_interval=0.1)

    @pytest.fixture
    def mock_daemon_status(self):
        """Provide a mock daemon status response."""
        return {
            "pid": 12345,
            "active": True,
            "engine": "xray",
            "uptime": 3600.0,
            "started_at": 1234567890.0,
        }

    @pytest.fixture
    def mock_daemon_state(self):
        """The keys the daemon actually writes.

        It writes `status` and a cumulative `io_bytes` counter - never
        `connected`, `throughput_*` or `active_connections`. The dashboard used
        to read those and therefore always showed Disconnected / 0.00 Mbps.
        """
        return {
            "status": "connected",
            "io_bytes": [1_000_000, 250_000],
            "restarts": 1,
        }

    def test_dashboard_initialization(self, dashboard):
        """Test dashboard initializes with correct defaults."""
        assert dashboard.refresh_interval == 0.1
        assert dashboard.console is not None
        assert dashboard._metrics_history == []

    def test_get_daemon_status_active_daemon(self, dashboard, mock_daemon_status, mock_daemon_state):
        """Test getting status when daemon is active."""
        with patch("blackoutkit.dashboard.daemon.stream_daemon_ipc_metrics") as mock_metrics:
            with patch("blackoutkit.dashboard.daemon.get_state") as mock_state:
                mock_metrics.return_value = mock_daemon_status
                mock_state.return_value = mock_daemon_state

                status = dashboard.get_daemon_status()

                assert status["active"] is True
                assert status["pid"] == 12345
                assert status["engine"] == "xray"
                assert status["status"] == "connected"
                assert status["connected"] is True
                # First sample: there is no previous counter to subtract, so
                # the rate is zero by definition, not because nothing moved.
                assert status["throughput_down"] == 0.0
                assert status["throughput_up"] == 0.0
                # Not tracked by the daemon; reported as unknown, not as zero.
                assert status["active_connections"] is None

                # A second sample one second later gives a real rate:
                # 1_000_000 bytes = 8 Mbit over ~1s.
                dashboard._last_io = (0, 0, 0.0)
                with patch("blackoutkit.dashboard.time.monotonic", return_value=1.0):
                    second = dashboard.get_daemon_status()
                assert second["throughput_down"] == pytest.approx(8.0, rel=0.2)
                assert second["throughput_up"] == pytest.approx(2.0, rel=0.2)

    def test_get_daemon_status_inactive_daemon(self, dashboard, mock_daemon_status, mock_daemon_state):
        """Test getting status when daemon is inactive."""
        mock_status = {
            "pid": None,
            "active": False,
            "engine": None,
            "uptime": 0.0,
            "started_at": None,
        }

        with patch("blackoutkit.dashboard.daemon.stream_daemon_ipc_metrics") as mock_metrics:
            with patch("blackoutkit.dashboard.daemon.get_state") as mock_state:
                mock_metrics.return_value = mock_status
                mock_state.return_value = None

                status = dashboard.get_daemon_status()

                assert status["active"] is False
                assert status["pid"] is None
                assert status["engine"] == "None"

    def test_calculate_health_critical(self, dashboard):
        """Test health status is CRITICAL when daemon is inactive."""
        status = {
            "active": False,
            "connected": False,
            "throughput_down": 0.0,
            "throughput_up": 0.0,
        }

        health = dashboard._calculate_health(status)
        assert health == "CRITICAL"

    def test_calculate_health_warning(self, dashboard):
        """Test health status is WARNING when not connected."""
        status = {
            "active": True,
            "connected": False,
            "throughput_down": 0.0,
            "throughput_up": 0.0,
        }

        health = dashboard._calculate_health(status)
        assert health == "WARNING"

    def test_calculate_health_ok(self, dashboard):
        """Test health status is OK when daemon is active and connected."""
        status = {
            "active": True,
            "connected": True,
            "throughput_down": 5.0,
            "throughput_up": 1.0,
        }

        health = dashboard._calculate_health(status)
        assert health == "OK"

    def test_render_dashboard_returns_panel(self, dashboard):
        """Test render_dashboard returns a valid panel."""
        status = {
            "active": True,
            "pid": 12345,
            "engine": "xray",
            "uptime": 3600.0,
            "connected": True,
            "throughput_down": 5.23,
            "throughput_up": 1.45,
            "active_connections": 4,
            "last_activity_sec": 2.5,
            "health": "OK",
        }

        panel = dashboard.render_dashboard(status)

        # Panel should be a rich Panel object
        assert panel is not None
        assert hasattr(panel, "renderable")

    def test_format_uptime_seconds(self, dashboard):
        """Test uptime formatting for seconds."""
        assert dashboard._format_uptime(45) == "45s"
        assert dashboard._format_uptime(1) == "1s"

    def test_format_uptime_minutes(self, dashboard):
        """Test uptime formatting for minutes."""
        assert dashboard._format_uptime(180) == "3m 0s"
        assert dashboard._format_uptime(125) == "2m 5s"

    def test_format_uptime_hours(self, dashboard):
        """Test uptime formatting for hours."""
        assert dashboard._format_uptime(3600) == "1h 0m"
        assert dashboard._format_uptime(3725) == "1h 2m"

    def test_get_summary_text_active_connected(self, dashboard, mock_daemon_status, mock_daemon_state):
        """Test summary text generation when active and connected."""
        with patch.object(dashboard, "get_daemon_status") as mock_get:
            mock_get.return_value = {
                "active": True,
                "engine": "xray",
                "connected": True,
                "throughput_down": 5.23,
                "throughput_up": 1.45,
                "active_connections": 4,
                "health": "OK",
            }

            summary = dashboard.get_summary_text()

            assert "✅ xray" in summary
            assert "🟢 Connected" in summary
            assert "5.23↓ / 1.45↑ Mbps" in summary
            assert "4 connections" in summary

    def test_get_summary_text_inactive(self, dashboard):
        """Test summary text generation when inactive."""
        with patch.object(dashboard, "get_daemon_status") as mock_get:
            mock_get.return_value = {
                "active": False,
                "engine": "None",
                "connected": False,
                "throughput_down": 0.0,
                "throughput_up": 0.0,
                "active_connections": 0,
                "health": "CRITICAL",
            }

            summary = dashboard.get_summary_text()

            assert "❌ None" in summary
            assert "🔴 Disconnected" in summary
            assert "0 connections" in summary

    def test_show_once_does_not_loop(self, dashboard, mock_daemon_status, mock_daemon_state):
        """Test that show(follow=False) displays once and returns."""
        with patch("blackoutkit.dashboard.daemon.stream_daemon_ipc_metrics") as mock_metrics:
            with patch("blackoutkit.dashboard.daemon.get_state") as mock_state:
                with patch.object(dashboard.console, "print") as mock_print:
                    mock_metrics.return_value = mock_daemon_status
                    mock_state.return_value = mock_daemon_state

                    dashboard.show(follow=False)

                    # Verify print was called exactly once
                    assert mock_print.call_count == 1

    def test_dashboard_handles_missing_state(self, dashboard, mock_daemon_status):
        """Test dashboard gracefully handles missing state file."""
        with patch("blackoutkit.dashboard.daemon.stream_daemon_ipc_metrics") as mock_metrics:
            with patch("blackoutkit.dashboard.daemon.get_state") as mock_state:
                mock_metrics.return_value = mock_daemon_status
                mock_state.return_value = None

                status = dashboard.get_daemon_status()

                assert status["connected"] is False
                assert status["throughput_down"] == 0.0
                assert status["throughput_up"] == 0.0
                assert status["active_connections"] is None

    def test_dashboard_status_includes_all_fields(self, dashboard, mock_daemon_status, mock_daemon_state):
        """Test that all expected fields are present in status."""
        with patch("blackoutkit.dashboard.daemon.stream_daemon_ipc_metrics") as mock_metrics:
            with patch("blackoutkit.dashboard.daemon.get_state") as mock_state:
                mock_metrics.return_value = mock_daemon_status
                mock_state.return_value = mock_daemon_state

                status = dashboard.get_daemon_status()

                required_fields = [
                    "active",
                    "pid",
                    "engine",
                    "uptime",
                    "connected",
                    "throughput_down",
                    "throughput_up",
                    "active_connections",
                    "last_activity_sec",
                    "health",
                ]

                for field in required_fields:
                    assert field in status, f"Missing field: {field}"

    def test_refresh_interval_configurable(self):
        """Test that refresh interval can be customized."""
        dashboard_fast = LiveDashboard(refresh_interval=0.1)
        dashboard_slow = LiveDashboard(refresh_interval=2.0)

        assert dashboard_fast.refresh_interval == 0.1
        assert dashboard_slow.refresh_interval == 2.0

    def test_render_dashboard_with_zero_throughput(self, dashboard):
        """Test rendering dashboard with zero throughput."""
        status = {
            "active": True,
            "pid": 999,
            "engine": "tor",
            "uptime": 60.0,
            "connected": True,
            "throughput_down": 0.0,
            "throughput_up": 0.0,
            "active_connections": 0,
            "last_activity_sec": 30.0,
            "health": "OK",
        }

        panel = dashboard.render_dashboard(status)
        assert panel is not None

    def test_render_dashboard_with_high_throughput(self, dashboard):
        """Test rendering dashboard with high throughput values."""
        status = {
            "active": True,
            "pid": 999,
            "engine": "gdpi",
            "uptime": 7200.0,
            "connected": True,
            "throughput_down": 950.5,
            "throughput_up": 450.2,
            "active_connections": 42,
            "last_activity_sec": 0.1,
            "health": "OK",
        }

        panel = dashboard.render_dashboard(status)
        assert panel is not None

    def test_render_dashboard_large_uptime(self, dashboard):
        """Test formatting of very large uptime values."""
        uptime_24_hours = 86400.0
        formatted = dashboard._format_uptime(uptime_24_hours)

        # Should include hours
        assert "h" in formatted
        assert "m" in formatted


class TestDashboardIntegration:
    """Integration tests for dashboard with real daemon."""

    def test_get_daemon_status_integration(self):
        """Test that get_daemon_status calls correct daemon functions."""
        dashboard = LiveDashboard()

        with patch("blackoutkit.dashboard.daemon.stream_daemon_ipc_metrics") as mock_metrics:
            with patch("blackoutkit.dashboard.daemon.get_state") as mock_state:
                mock_metrics.return_value = {
                    "pid": 100,
                    "active": True,
                    "engine": "test",
                    "uptime": 10.0,
                    "started_at": 1234567890.0,
                }
                mock_state.return_value = {
                    "status": "connected",
                    "io_bytes": [10, 5],
                }

                status = dashboard.get_daemon_status()

                # Verify correct functions were called
                mock_metrics.assert_called_once()
                mock_state.assert_called_once()

                # Verify result combines both sources
                assert status["pid"] == 100
                assert status["connected"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
