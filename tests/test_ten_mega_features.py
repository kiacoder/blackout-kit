import pytest
import os
from blackoutkit.tools import (
    scan_file_yara,
    simulate_network_conditions,
    check_phishing_domain,
    generate_ascii_bandwidth_chart,
    detect_arp_spoofing,
)
from blackoutkit import daemon

def test_yara_scanner(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("eval(base64_decode('test'))")
    res = scan_file_yara(str(f))
    assert res["ok"] is True
    assert res["clean"] is False
    assert len(res["matches"]) >= 1

def test_simulate_network():
    res = simulate_network_conditions(host="8.8.8.8", added_latency_ms=50.0, samples=2)
    assert res["host"] == "8.8.8.8"
    assert "stats" in res

def test_phishing_check():
    res = check_phishing_domain("login-verify-paypal-secure-fix.com")
    assert res["safe"] is False
    assert len(res["reasons"]) >= 1

def test_bandwidth_chart():
    chart = generate_ascii_bandwidth_chart(1_000_000.0, 500_000.0)
    assert "Download" in chart
    assert "Upload" in chart

def test_arp_guard():
    res = detect_arp_spoofing()
    assert "ok" in res

def test_ipc_metrics():
    assert daemon.get_pid() is None or isinstance(daemon.get_pid(), int)
