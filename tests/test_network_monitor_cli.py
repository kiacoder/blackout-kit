"""Tests for the live-monitor Rich panel builders (latency-monitor, bandwidth)."""
from rich.console import Console

from blackoutkit import cli
from blackoutkit.theme import build_theme


def _render(renderable) -> str:
    console = Console(record=True, width=100, theme=build_theme())
    console.print(renderable)
    return console.export_text()


def test_latency_monitor_panel_shows_collecting_when_empty():
    text = _render(cli._latency_monitor_panel("8.8.8.8", []))
    assert "8.8.8.8" in text
    assert "collecting" in text


def test_latency_monitor_panel_shows_stats_and_loss():
    history = [10.0, 20.0, None, 30.0]
    text = _render(cli._latency_monitor_panel("1.1.1.1", history))
    assert "1.1.1.1" in text
    assert "Loss" in text
    assert "25%" in text
    assert "Jitter" in text


def test_latency_monitor_panel_windows_to_recent_samples():
    history = [100.0] * 5 + [1.0] * 5
    text = _render(cli._latency_monitor_panel("host", history, window=5))
    assert "Samples" in text
    assert "5" in text


def test_bandwidth_panel_no_interfaces_shows_placeholder():
    text = _render(cli._bandwidth_panel({}, {}))
    assert "no interfaces found" in text


def test_bandwidth_panel_lists_active_interfaces_sorted_by_download():
    rates = {
        "eth0": {"rx_bps": 2_000_000.0, "tx_bps": 100_000.0},
        "wlan0": {"rx_bps": 500_000.0, "tx_bps": 50_000.0},
    }
    history = {"eth0": [1.0, 2.0], "wlan0": [0.5]}
    text = _render(cli._bandwidth_panel(rates, history))
    assert "eth0" in text
    assert "wlan0" in text
    assert text.index("eth0") < text.index("wlan0")


def test_bandwidth_panel_hides_idle_interfaces_when_active_ones_exist():
    rates = {
        "eth0": {"rx_bps": 1_000_000.0, "tx_bps": 1_000.0},
        "idle0": {"rx_bps": 0.0, "tx_bps": 0.0},
    }
    text = _render(cli._bandwidth_panel(rates, {}))
    assert "eth0" in text
    assert "idle0" not in text


def test_format_bps_scales_units():
    assert "B/s" in cli._format_bps(500)
    assert "KB/s" in cli._format_bps(5_000)
    assert "MB/s" in cli._format_bps(5_000_000)
    assert "GB/s" in cli._format_bps(5_000_000_000)
