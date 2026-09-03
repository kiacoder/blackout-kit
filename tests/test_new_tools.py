import pytest
import os
import struct
from blackoutkit.tools import (
    trigger_panic,
    run_network_audit,
    write_pcap_file,
    monitor_process_network,
    run_honeypot_listener,
    run_doh_proxy_server,
)

def test_trigger_panic():
    results = trigger_panic(restore=False)
    assert isinstance(results, list)
    steps = [r["step"] for r in results]
    assert "Stop Daemon & Bypass Engines" in steps
    assert "Clear System Proxy" in steps
    assert "Flush DNS Cache" in steps

def test_run_network_audit():
    audit = run_network_audit()
    assert "score" in audit
    assert "grade" in audit
    assert "findings" in audit
    assert isinstance(audit["findings"], list)
    assert 0 <= audit["score"] <= 100

def test_write_pcap_file(tmp_path):
    pcap_path = str(tmp_path / "test.pcap")
    class DummyPkt:
        def __init__(self):
            self.time = 1234567890.123456
        def __bytes__(self):
            return b"\x00" * 14
        def __len__(self):
            return 14

    ok = write_pcap_file(pcap_path, [DummyPkt()])
    assert ok
    assert os.path.exists(pcap_path)
    with open(pcap_path, "rb") as f:
        magic = f.read(4)
        assert magic == b"\xd4\xc3\xb2\xa1"  # 0xa1b2c3d4 little-endian

def test_monitor_process_network():
    procs = monitor_process_network()
    assert isinstance(procs, list)
    if procs:
        p = procs[0]
        assert "pid" in p
        assert "process" in p
        assert "socket_count" in p

def test_run_honeypot_listener():
    probes = run_honeypot_listener(ports=[39999], duration=0.1)
    assert isinstance(probes, list)
