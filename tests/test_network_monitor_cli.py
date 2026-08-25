"""Tests for the live-monitor Rich panel builders (latency-monitor, bandwidth, capture)."""
from collections import deque

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


def test_capture_panel_shows_waiting_when_empty():
    text = _render(cli._capture_panel(deque(), {}, "eth0"))
    assert "eth0" in text
    assert "waiting for traffic" in text


def test_capture_panel_shows_auto_when_no_iface():
    text = _render(cli._capture_panel(deque(), {}, None))
    assert "auto" in text


def test_capture_panel_lists_recent_packets():
    packets = deque([{
        "ts": 1_700_000_000.0, "proto": "TCP", "src": "1.1.1.1", "sport": 443,
        "dst": "2.2.2.2", "dport": 51000, "length": 60, "summary": "TCP",
    }])
    stats = {"total_packets": 1, "protocol_counts": {"TCP": 1}}
    text = _render(cli._capture_panel(packets, stats, "eth0"))
    assert "1.1.1.1:443" in text
    assert "2.2.2.2:51000" in text
    assert "TCP" in text
    assert "1 captured" in text


def test_capture_panel_shows_protocol_footer_counts():
    stats = {"total_packets": 3, "protocol_counts": {"TCP": 2, "UDP": 1}}
    text = _render(cli._capture_panel(deque(), stats, None))
    assert "TCP: 2" in text
    assert "UDP: 1" in text


def test_capture_summary_table_lists_protocols_and_talkers():
    summary = {
        "total_packets": 5, "total_bytes": 500, "duration": 2.5,
        "protocol_counts": {"TCP": 3, "UDP": 2},
        "top_talkers": [("1.1.1.1", 3), ("2.2.2.2", 2)],
    }
    text = _render(cli._capture_summary_table(summary))
    assert "Capture Summary" in text
    assert "TCP" in text
    assert "Top talkers" in text
    assert "1.1.1.1" in text


def test_capture_summary_table_no_talkers_omits_section():
    summary = {
        "total_packets": 0, "total_bytes": 0, "duration": 0.0,
        "protocol_counts": {}, "top_talkers": [],
    }
    text = _render(cli._capture_summary_table(summary))
    assert "Top talkers" not in text


def test_bandwidth_history_caps_samples_per_interface():
    history = {}
    for sample in range(cli.MAX_BANDWIDTH_HISTORY + 1):
        cli._record_bandwidth_history(history, {"eth0": {"rx_bps": float(sample)}})

    assert len(history["eth0"]) == cli.MAX_BANDWIDTH_HISTORY
    assert history["eth0"][0] == 1.0
    assert history["eth0"][-1] == float(cli.MAX_BANDWIDTH_HISTORY)


def test_bandwidth_history_evicts_oldest_interface_and_refreshes_recency():
    history = {}
    for index in range(cli.MAX_BANDWIDTH_INTERFACES):
        cli._record_bandwidth_history(history, {f"iface-{index}": {"rx_bps": float(index)}})

    cli._record_bandwidth_history(history, {"iface-0": {"rx_bps": 99.0}})
    cli._record_bandwidth_history(history, {"iface-new": {"rx_bps": 100.0}})

    assert len(history) == cli.MAX_BANDWIDTH_INTERFACES
    assert "iface-0" in history
    assert "iface-1" not in history
    assert "iface-new" in history
