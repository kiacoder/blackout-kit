"""Tests for the Phase 1 network analysis toolkit: subnet calc, connections,
port scanner, LAN discovery, DNS inspector, and speedtest history."""
import json
import socket
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from blackoutkit import tools


# ─────────────────────────── Subnet calculator ────────────────────

def test_calculate_subnet_slash_24():
    result = tools.calculate_subnet("192.168.1.0/24")
    assert result == {
        "network": "192.168.1.0",
        "broadcast": "192.168.1.255",
        "netmask": "255.255.255.0",
        "cidr": 24,
        "total_hosts": 256,
        "usable_hosts": 254,
        "first_ip": "192.168.1.1",
        "last_ip": "192.168.1.254",
    }


def test_calculate_subnet_slash_28():
    result = tools.calculate_subnet("10.0.0.16/28")
    assert result["network"] == "10.0.0.16"
    assert result["broadcast"] == "10.0.0.31"
    assert result["usable_hosts"] == 14


def test_calculate_subnet_host_bits_set_uses_strict_false():
    """A host address with bits set in the host portion should still resolve the network."""
    result = tools.calculate_subnet("192.168.1.5/24")
    assert result["network"] == "192.168.1.0"


def test_calculate_subnet_slash_31_has_no_usable_range():
    result = tools.calculate_subnet("192.168.1.0/31")
    assert result["total_hosts"] == 2
    assert result["usable_hosts"] == 0
    assert result["first_ip"] == "N/A"


def test_calculate_subnet_invalid_input_returns_none():
    assert tools.calculate_subnet("not-an-ip") is None
    assert tools.calculate_subnet("999.999.999.999/24") is None


# ─────────────────────────── Live connections ─────────────────────

def _fake_conn(pid, laddr, raddr=None, status="ESTABLISHED", type_=socket.SOCK_STREAM):
    return SimpleNamespace(
        pid=pid,
        laddr=SimpleNamespace(ip=laddr[0], port=laddr[1]) if laddr else None,
        raddr=SimpleNamespace(ip=raddr[0], port=raddr[1]) if raddr else None,
        status=status,
        type=type_,
    )


def test_get_active_connections_maps_process_names():
    fake_conns = [
        _fake_conn(1234, ("127.0.0.1", 5000), ("93.184.216.34", 443)),
        _fake_conn(None, ("0.0.0.0", 8080), None, status="LISTEN"),
    ]
    fake_psutil = MagicMock()
    fake_psutil.net_connections.return_value = fake_conns
    fake_psutil.Process.return_value.name.return_value = "chrome.exe"
    fake_psutil.CONN_ESTABLISHED = "ESTABLISHED"
    fake_psutil.AccessDenied = Exception
    fake_psutil.NoSuchProcess = Exception

    with patch.dict("sys.modules", {"psutil": fake_psutil}):
        results = tools.get_active_connections()

    assert len(results) == 2
    chrome_entry = next(r for r in results if r["pid"] == 1234)
    assert chrome_entry["process"] == "chrome.exe"
    assert chrome_entry["remote_addr"] == "93.184.216.34"
    assert chrome_entry["protocol"] == "TCP"

    listen_entry = next(r for r in results if r["pid"] == 0)
    assert listen_entry["process"] == "-"
    assert listen_entry["remote_addr"] == ""


def test_get_active_connections_established_only_filter():
    fake_conns = [
        _fake_conn(1, ("127.0.0.1", 1), status="ESTABLISHED"),
        _fake_conn(2, ("127.0.0.1", 2), status="LISTEN"),
    ]
    fake_psutil = MagicMock()
    fake_psutil.net_connections.return_value = fake_conns
    fake_psutil.Process.return_value.name.return_value = "svc.exe"
    fake_psutil.CONN_ESTABLISHED = "ESTABLISHED"
    fake_psutil.AccessDenied = Exception
    fake_psutil.NoSuchProcess = Exception

    with patch.dict("sys.modules", {"psutil": fake_psutil}):
        results = tools.get_active_connections(established_only=True)

    assert len(results) == 1
    assert results[0]["status"] == "ESTABLISHED"


def test_get_active_connections_handles_access_denied():
    fake_psutil = MagicMock()
    fake_psutil.AccessDenied = PermissionError
    fake_psutil.net_connections.side_effect = fake_psutil.AccessDenied("nope")

    with patch.dict("sys.modules", {"psutil": fake_psutil}):
        results = tools.get_active_connections()

    assert results == []


# ─────────────────────────── Port scanner ──────────────────────────

def test_scan_ports_reports_only_open_ports():
    class FakeSocket:
        def __init__(self, *_args, **_kwargs):
            pass
        def settimeout(self, _t):
            pass
        def connect_ex(self, addr):
            # Port 80 "open" (0), everything else "closed" (1)
            return 0 if addr[1] == 80 else 1
        def close(self):
            pass

    with patch("socket.socket", FakeSocket), \
         patch("socket.gethostbyname", return_value="93.184.216.34"):
        results = tools.scan_ports("example.com", ports=[22, 80, 443])

    assert len(results) == 1
    assert results[0]["port"] == 80
    assert results[0]["service"] == "HTTP"
    assert results[0]["open"] is True


def test_scan_ports_unknown_service_labeled_unknown():
    class FakeSocket:
        def __init__(self, *_args, **_kwargs):
            pass
        def settimeout(self, _t):
            pass
        def connect_ex(self, _addr):
            return 0
        def close(self):
            pass

    with patch("socket.socket", FakeSocket), \
         patch("socket.gethostbyname", return_value="1.2.3.4"):
        results = tools.scan_ports("1.2.3.4", ports=[54321])

    assert results[0]["service"] == "unknown"


def test_scan_ports_unresolvable_host_returns_empty():
    with patch("socket.gethostbyname", side_effect=socket.gaierror("no such host")):
        results = tools.scan_ports("does-not-exist.invalid", ports=[80])

    assert results == []


def test_scan_ports_defaults_to_common_ports_list():
    class FakeSocket:
        def __init__(self, *_args, **_kwargs):
            pass
        def settimeout(self, _t):
            pass
        def connect_ex(self, _addr):
            return 1
        def close(self):
            pass

    with patch("socket.socket", FakeSocket), \
         patch("socket.gethostbyname", return_value="1.2.3.4") as resolve:
        tools.scan_ports("1.2.3.4")

    resolve.assert_called_once()


# ─────────────────────────── LAN discovery ─────────────────────────

def test_discover_lan_hosts_returns_self_and_arp_neighbors():
    with patch.object(tools, "_local_ip_and_prefix", return_value=("192.168.1.50", "192.168.1")), \
         patch.object(tools, "_arp_table", return_value={
             "192.168.1.50": "aa:bb:cc:dd:ee:ff",
             "192.168.1.1": "11:22:33:44:55:66",
         }), \
         patch("socket.socket") as mock_socket_cls, \
         patch("socket.gethostbyaddr", return_value=("router.local", [], [])):
        mock_socket_cls.return_value.connect_ex.return_value = 1
        hosts = tools.discover_lan_hosts()

    assert len(hosts) == 2
    self_entry = next(h for h in hosts if h["is_self"])
    assert self_entry["ip"] == "192.168.1.50"
    assert self_entry["hostname"] == "(this device)"

    neighbor = next(h for h in hosts if not h["is_self"])
    assert neighbor["ip"] == "192.168.1.1"
    assert neighbor["mac"] == "11:22:33:44:55:66"
    assert neighbor["hostname"] == "router.local"


def test_discover_lan_hosts_returns_empty_when_no_local_ip():
    with patch.object(tools, "_local_ip_and_prefix", return_value=None):
        assert tools.discover_lan_hosts() == []


def test_discover_lan_hosts_hostname_lookup_failure_falls_back_to_dash():
    with patch.object(tools, "_local_ip_and_prefix", return_value=("192.168.1.50", "192.168.1")), \
         patch.object(tools, "_arp_table", return_value={"192.168.1.5": "de:ad:be:ef:00:01"}), \
         patch("socket.socket") as mock_socket_cls, \
         patch("socket.gethostbyaddr", side_effect=socket.herror("no ptr record")):
        mock_socket_cls.return_value.connect_ex.return_value = 1
        hosts = tools.discover_lan_hosts()

    neighbor = next(h for h in hosts if not h["is_self"])
    assert neighbor["hostname"] == "-"


# ─────────────────────────── DNS inspector ─────────────────────────

def test_inspect_dns_flags_only_when_trusted_succeeds_and_system_fails():
    def fake_system_resolve(domain, timeout=3.0):
        return None if domain == "www.google.com" else "1.2.3.4"

    with patch.object(tools, "get_system_dns_servers", return_value=["1.1.1.1"]), \
         patch.object(tools, "_system_resolve", side_effect=fake_system_resolve), \
         patch.object(tools, "resolve_doh", return_value="8.8.8.8"):
        report = tools.inspect_dns()

    assert report["servers"] == ["1.1.1.1"]
    assert report["trusted_resolver_reachable"] is True

    google_check = next(c for c in report["checks"] if c["domain"] == "www.google.com")
    assert google_check["suspect"] is True
    assert google_check["system_ip"] == "no response"

    other_check = next(c for c in report["checks"] if c["domain"] != "www.google.com")
    assert other_check["suspect"] is False


def test_inspect_dns_no_false_positive_when_trusted_resolver_unreachable():
    with patch.object(tools, "get_system_dns_servers", return_value=["192.168.1.1"]), \
         patch.object(tools, "_system_resolve", return_value="93.184.216.34"), \
         patch.object(tools, "resolve_doh", return_value=None):
        report = tools.inspect_dns()

    assert report["trusted_resolver_reachable"] is False
    assert all(not c["suspect"] for c in report["checks"])


def test_get_system_dns_servers_linux_reads_resolv_conf(tmp_path, monkeypatch):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 1.1.1.1\nnameserver 8.8.8.8\n# comment\n")

    monkeypatch.setattr(tools.sys, "platform", "linux")
    original_open = open

    def fake_open(path, *args, **kwargs):
        if path == "/etc/resolv.conf":
            return original_open(resolv, *args, **kwargs)
        return original_open(path, *args, **kwargs)

    with patch("builtins.open", fake_open):
        servers = tools.get_system_dns_servers()

    assert servers == ["1.1.1.1", "8.8.8.8"]


# ─────────────────────────── Speedtest history ─────────────────────

def test_record_and_get_speedtest_history_round_trip(tmp_path, monkeypatch):
    history_file = tmp_path / "speedtest_history.json"
    monkeypatch.setattr(tools, "SPEEDTEST_HISTORY_FILE", history_file)
    monkeypatch.setattr(tools, "APP_DATA_DIR", tmp_path)

    tools.record_speedtest_result({"latency_ms": 20.0, "download_mbps": 100.0, "upload_mbps": 10.0})
    tools.record_speedtest_result({"latency_ms": 25.0, "download_mbps": 150.0, "upload_mbps": 15.0})

    history = tools.get_speedtest_history(limit=10)
    assert len(history) == 2
    assert history[0]["download_mbps"] == 100.0
    assert history[1]["download_mbps"] == 150.0
    assert "ts" in history[0]


def test_speedtest_history_caps_at_max_entries(tmp_path, monkeypatch):
    history_file = tmp_path / "speedtest_history.json"
    monkeypatch.setattr(tools, "SPEEDTEST_HISTORY_FILE", history_file)
    monkeypatch.setattr(tools, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(tools, "_SPEEDTEST_HISTORY_MAX", 3)

    for i in range(5):
        tools.record_speedtest_result({"latency_ms": i, "download_mbps": i, "upload_mbps": i})

    stored = json.loads(history_file.read_text())
    assert len(stored) == 3
    assert stored[-1]["download_mbps"] == 4


def test_get_speedtest_history_missing_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "SPEEDTEST_HISTORY_FILE", tmp_path / "does_not_exist.json")
    assert tools.get_speedtest_history() == []


def test_get_speedtest_history_corrupt_file_returns_empty(tmp_path, monkeypatch):
    bad_file = tmp_path / "corrupt.json"
    bad_file.write_text("{not valid json")
    monkeypatch.setattr(tools, "SPEEDTEST_HISTORY_FILE", bad_file)
    assert tools.get_speedtest_history() == []


# ─────────────────────────── Latency monitor ───────────────────────

def test_ping_once_success_returns_positive_rtt():
    with patch("socket.create_connection", return_value=MagicMock()):
        rtt = tools.ping_once("8.8.8.8")
    assert rtt is not None
    assert rtt >= 0


def test_ping_once_failure_returns_none():
    with patch("socket.create_connection", side_effect=OSError("timed out")):
        assert tools.ping_once("8.8.8.8") is None


# ─────────────────────────── Bandwidth monitor ──────────────────────

def test_get_interface_io_counters_maps_psutil_output():
    fake_counter = SimpleNamespace(bytes_recv=100, bytes_sent=50)
    fake_psutil = MagicMock()
    fake_psutil.net_io_counters.return_value = {"eth0": fake_counter}

    with patch.dict("sys.modules", {"psutil": fake_psutil}):
        result = tools.get_interface_io_counters()

    assert result == {"eth0": (100, 50)}


def test_get_interface_io_counters_handles_failure():
    fake_psutil = MagicMock()
    fake_psutil.net_io_counters.side_effect = OSError("boom")

    with patch.dict("sys.modules", {"psutil": fake_psutil}):
        assert tools.get_interface_io_counters() == {}


def test_compute_bandwidth_rates_basic_diff():
    prev = {"eth0": (1000, 500)}
    curr = {"eth0": (3000, 1500)}
    rates = tools.compute_bandwidth_rates(prev, curr, elapsed=2.0)
    assert rates == {"eth0": {"rx_bps": 1000.0, "tx_bps": 500.0}}


def test_compute_bandwidth_rates_new_interface_defaults_to_zero():
    rates = tools.compute_bandwidth_rates({}, {"eth1": (500, 200)}, elapsed=1.0)
    assert rates == {"eth1": {"rx_bps": 0.0, "tx_bps": 0.0}}


def test_compute_bandwidth_rates_clamps_negative_on_counter_reset():
    prev = {"eth0": (5000, 5000)}
    curr = {"eth0": (100, 100)}  # interface restarted, counters reset to near-zero
    rates = tools.compute_bandwidth_rates(prev, curr, elapsed=1.0)
    assert rates == {"eth0": {"rx_bps": 0.0, "tx_bps": 0.0}}


def test_compute_bandwidth_rates_zero_elapsed_returns_empty():
    assert tools.compute_bandwidth_rates({}, {"eth0": (1, 1)}, elapsed=0) == {}


# ─────────────────────────── Packet capture ─────────────────────────

class FakePacket:
    """Minimal stand-in for a scapy packet — only the attributes/methods
    parse_packet_summary() actually touches."""

    def __init__(self, layers=None, length=100, ts=1_700_000_000.0, summary_text="pkt"):
        self._layers = layers or {}
        self._length = length
        self.time = ts
        self._summary_text = summary_text

    def haslayer(self, name):
        return name in self._layers

    def __getitem__(self, name):
        return self._layers[name]

    def __len__(self):
        return self._length

    def summary(self):
        return self._summary_text


def test_parse_packet_summary_tcp():
    pkt = FakePacket({
        "IP": SimpleNamespace(src="1.1.1.1", dst="2.2.2.2"),
        "TCP": SimpleNamespace(sport=51000, dport=443),
    }, length=60, summary_text="IP / TCP 1.1.1.1:51000 > 2.2.2.2:443")
    result = tools.parse_packet_summary(pkt)
    assert result["proto"] == "TCP"
    assert result["src"] == "1.1.1.1"
    assert result["dst"] == "2.2.2.2"
    assert result["sport"] == 51000
    assert result["dport"] == 443
    assert result["length"] == 60
    assert "TCP" in result["summary"]


def test_parse_packet_summary_udp():
    pkt = FakePacket({
        "IP": SimpleNamespace(src="10.0.0.5", dst="8.8.8.8"),
        "UDP": SimpleNamespace(sport=53, dport=53),
    })
    result = tools.parse_packet_summary(pkt)
    assert result["proto"] == "UDP"
    assert result["sport"] == 53
    assert result["dport"] == 53


def test_parse_packet_summary_arp_has_no_ports():
    pkt = FakePacket({"ARP": SimpleNamespace(psrc="192.168.1.5", pdst="192.168.1.1")})
    result = tools.parse_packet_summary(pkt)
    assert result["proto"] == "ARP"
    assert result["src"] == "192.168.1.5"
    assert result["dst"] == "192.168.1.1"
    assert result["sport"] is None
    assert result["dport"] is None


def test_parse_packet_summary_icmp():
    pkt = FakePacket({"IP": SimpleNamespace(src="1.1.1.1", dst="2.2.2.2"), "ICMP": SimpleNamespace()})
    result = tools.parse_packet_summary(pkt)
    assert result["proto"] == "ICMP"
    assert result["sport"] is None


def test_parse_packet_summary_unknown_frame_defaults_to_other():
    pkt = FakePacket({})
    result = tools.parse_packet_summary(pkt)
    assert result["proto"] == "OTHER"
    assert result["src"] == "-"
    assert result["dst"] == "-"


def test_parse_packet_summary_falls_back_when_summary_raises():
    pkt = FakePacket({"IP": SimpleNamespace(src="1.1.1.1", dst="2.2.2.2"), "TCP": SimpleNamespace(sport=1, dport=2)})
    pkt.summary = lambda: (_ for _ in ()).throw(Exception("boom"))
    result = tools.parse_packet_summary(pkt)
    assert "TCP" in result["summary"]


def _patched_scapy(fake_scapy):
    """`import scapy.all as scapy` resolves via attribute access off the parent
    package object (`__import__('scapy.all').all`), not a direct sys.modules
    lookup — so the parent mock's `.all` attribute must *be* fake_scapy."""
    fake_parent = MagicMock()
    fake_parent.all = fake_scapy
    return patch.dict("sys.modules", {"scapy": fake_parent, "scapy.all": fake_scapy})


def test_capture_packets_calls_sniff_with_translated_args():
    fake_scapy = MagicMock()
    calls = {}
    fake_scapy.sniff.side_effect = lambda **kwargs: calls.update(kwargs)

    received = []
    with _patched_scapy(fake_scapy):
        tools.capture_packets(iface="eth0", bpf_filter="tcp", count=5, on_packet=received.append)

    assert calls["iface"] == "eth0"
    assert calls["filter"] == "tcp"
    assert calls["count"] == 5
    assert calls["store"] is False

    fake_pkt = FakePacket({"IP": SimpleNamespace(src="1.1.1.1", dst="2.2.2.2"), "TCP": SimpleNamespace(sport=1, dport=2)})
    calls["prn"](fake_pkt)
    assert len(received) == 1
    assert received[0]["proto"] == "TCP"


def test_capture_packets_stop_filter_reflects_stop_event():
    fake_scapy = MagicMock()
    calls = {}
    fake_scapy.sniff.side_effect = lambda **kwargs: calls.update(kwargs)
    stop_event = threading.Event()

    with _patched_scapy(fake_scapy):
        tools.capture_packets(stop_event=stop_event)

    assert calls["stop_filter"](FakePacket()) is False
    stop_event.set()
    assert calls["stop_filter"](FakePacket()) is True


def test_capture_packets_raises_capture_unavailable_when_scapy_missing():
    with patch.dict("sys.modules", {"scapy.all": None}):
        with pytest.raises(tools.CaptureUnavailable):
            tools.capture_packets()


def test_capture_packets_wraps_sniff_errors_as_capture_unavailable():
    fake_scapy = MagicMock()
    fake_scapy.sniff.side_effect = OSError("Permission denied")

    with _patched_scapy(fake_scapy):
        with pytest.raises(tools.CaptureUnavailable):
            tools.capture_packets()


def test_summarize_capture_packets_empty():
    assert tools.summarize_capture_packets([]) == {
        "total_packets": 0,
        "total_bytes": 0,
        "duration": 0.0,
        "protocol_counts": {},
        "top_talkers": [],
    }


def test_summarize_capture_packets_counts_bytes_and_talkers():
    packets = [
        {"ts": 10.0, "proto": "TCP", "src": "1.1.1.1", "length": 100},
        {"ts": 11.0, "proto": "TCP", "src": "1.1.1.1", "length": 50},
        {"ts": 12.0, "proto": "UDP", "src": "2.2.2.2", "length": 200},
        {"ts": 13.0, "proto": "ARP", "src": "-", "length": 60},
    ]
    summary = tools.summarize_capture_packets(packets)
    assert summary["total_packets"] == 4
    assert summary["total_bytes"] == 410
    assert summary["duration"] == 3.0
    assert summary["protocol_counts"] == {"TCP": 2, "UDP": 1, "ARP": 1}
    assert summary["top_talkers"][0] == ("1.1.1.1", 2)
    assert all(addr != "-" for addr, _ in summary["top_talkers"])


def test_summarize_capture_packets_top_talkers_capped_at_five():
    packets = [{"ts": float(i), "proto": "TCP", "src": f"10.0.0.{i}", "length": 1} for i in range(7)]
    summary = tools.summarize_capture_packets(packets)
    assert len(summary["top_talkers"]) == 5
