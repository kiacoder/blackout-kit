import json
import logging
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from blackoutkit.daemon.dns_interceptor import DNSInterceptor, MAX_QUERY_BUFFER
from blackoutkit.daemon.qos_monitor import QosMonitor
from blackoutkit.daemon.traffic_monitor import TrafficMonitor
from blackoutkit.engines import neighbor
from blackoutkit.engines.neighbor import NeighborConnectEngine


class _SocketContext:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_qos_monitor_stops_promptly_and_does_not_duplicate_worker():
    monitor = QosMonitor(check_interval=60)
    checked = threading.Event()
    monitor._check_violations = checked.set

    assert monitor.start() is True
    assert checked.wait(timeout=1)
    worker = monitor._monitor_thread

    assert monitor.start() is True
    assert monitor._monitor_thread is worker
    assert monitor.is_running()

    started = time.monotonic()
    assert monitor.stop() is True
    assert time.monotonic() - started < 1
    assert monitor._monitor_thread is None
    assert not monitor.is_running()
    assert monitor.stop() is True


def test_traffic_monitor_stops_promptly_and_does_not_duplicate_worker(monkeypatch):
    monitor = TrafficMonitor(sample_interval_sec=60)
    sampled = threading.Event()
    monkeypatch.setattr(monitor, "_snapshot_connections", sampled.set)

    monitor.start()
    assert sampled.wait(timeout=1)
    worker = monitor.thread

    monitor.start()
    assert monitor.thread is worker
    assert monitor.is_running()

    started = time.monotonic()
    monitor.stop()
    assert time.monotonic() - started < 1
    assert monitor.thread is None
    assert not monitor.is_running()


def test_dns_interceptor_stops_promptly_and_does_not_duplicate_worker(monkeypatch):
    processed = threading.Event()
    fake_adblock = SimpleNamespace(
        check_domain_blocked=lambda _domain: (False, None),
        log_dns_query=lambda *_args: processed.set(),
    )
    monkeypatch.setitem(sys.modules, "blackoutkit.tools.adblock", fake_adblock)

    interceptor = DNSInterceptor()
    interceptor.queue_query("example.test")
    interceptor.start()
    assert processed.wait(timeout=1)
    worker = interceptor.thread

    interceptor.start()
    assert interceptor.thread is worker
    assert interceptor.is_running()

    started = time.monotonic()
    interceptor.stop()
    assert time.monotonic() - started < 1
    assert interceptor.thread is None
    assert not interceptor.is_running()


def test_dns_interceptor_evicts_oldest_queries_and_reports_overflow(caplog):
    interceptor = DNSInterceptor()

    with caplog.at_level(logging.WARNING, logger="blackoutkit.daemon.dns_interceptor"):
        for index in range(MAX_QUERY_BUFFER + 100):
            interceptor.queue_query(f"query-{index}")

    assert interceptor.get_query_queue_size() == MAX_QUERY_BUFFER
    assert interceptor.get_dropped_query_count() == 100
    assert interceptor._query_buffer[0] == {"domain": "query-100"}
    assert interceptor._query_buffer[-1] == {"domain": f"query-{MAX_QUERY_BUFFER + 99}"}
    messages = [record.getMessage() for record in caplog.records]
    assert messages == [
        "DNS query buffer full; dropped 1 oldest queued queries",
        "DNS query buffer full; dropped 100 oldest queued queries",
    ]


def _configure_qos_storage(monkeypatch, tmp_path):
    from blackoutkit.tools import qos

    monkeypatch.setattr(qos, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(qos, "QOS_RULES_FILE", tmp_path / "qos_rules.json")
    monkeypatch.setattr(qos, "QOS_VIOLATIONS_FILE", tmp_path / "qos_violations.jsonl")
    return qos


def test_qos_global_settings_falls_back_when_storage_read_fails(monkeypatch):
    from blackoutkit.tools import qos

    def fail_to_load():
        raise OSError("unavailable")

    monkeypatch.setattr(qos, "_load_rules_unsafe", fail_to_load)

    assert qos._get_global_settings() == {
        "qos_enabled": False,
        "default_priority": 50,
        "enforcement_mode": "monitor",
    }


def test_qos_normalizes_legacy_and_invalid_persisted_modes(monkeypatch, tmp_path):
    qos = _configure_qos_storage(monkeypatch, tmp_path)

    for mode in ("enforce", "invalid"):
        qos.QOS_RULES_FILE.write_text(
            json.dumps({"rules": [], "global_settings": {"enforcement_mode": mode}}),
            encoding="utf-8",
        )

        assert qos.get_enforcement_mode() == "monitor"
        assert qos.get_qos_stats()["enforcement_mode"] == "monitor"


def test_qos_rejects_retired_enforcement_mode_without_writing(monkeypatch, tmp_path):
    qos = _configure_qos_storage(monkeypatch, tmp_path)

    assert qos.set_enforcement_mode("enforce") is False
    assert not qos.QOS_RULES_FILE.exists()
    assert qos.get_enforcement_mode() == "monitor"


def test_qos_save_normalizes_retired_enforcement_mode(monkeypatch, tmp_path):
    qos = _configure_qos_storage(monkeypatch, tmp_path)

    qos.save_qos_rules([], {"enforcement_mode": "enforce"})

    saved = json.loads(qos.QOS_RULES_FILE.read_text(encoding="utf-8"))
    assert saved["global_settings"]["enforcement_mode"] == "monitor"


def test_settings_normalize_retired_qos_mode_from_file_environment_and_save(monkeypatch, tmp_path):
    from blackoutkit import settings

    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(settings, "SETTINGS_FILE", settings_file)
    settings_file.write_text(json.dumps({"qos_enforcement_mode": "enforce"}), encoding="utf-8")

    assert settings.load()["qos_enforcement_mode"] == "monitor"

    monkeypatch.setenv("BLACKOUT_QOS_ENFORCEMENT_MODE", "enforce")
    assert settings.load()["qos_enforcement_mode"] == "monitor"

    settings.save({**settings.DEFAULTS, "qos_enforcement_mode": "enforce"})
    saved = json.loads(settings_file.read_text(encoding="utf-8"))
    assert saved["qos_enforcement_mode"] == "monitor"


def test_qos_module_liveness_helper_delegates_to_monitor(monkeypatch):
    from blackoutkit.daemon import qos_monitor

    monitor = MagicMock()
    monitor.is_running.return_value = True
    monkeypatch.setattr(qos_monitor, "get_monitor", lambda: monitor)

    assert qos_monitor.is_qos_monitor_running() is True
    monitor.is_running.assert_called_once_with()


def test_neighbor_start_is_idempotent_before_reachability_or_cache_side_effects(monkeypatch):
    from blackoutkit.scanner import neighbor_cache

    connection_attempts = []
    cache_add = MagicMock()
    heartbeat_started = threading.Event()

    def fake_connection(*args, **kwargs):
        connection_attempts.append((args, kwargs))
        return _SocketContext()

    monkeypatch.setattr(neighbor.socket, "create_connection", fake_connection)
    monkeypatch.setattr(neighbor_cache, "add_neighbor", cache_add)

    engine = NeighborConnectEngine(peer_host="192.0.2.10", peer_port=10809)

    def controlled_heartbeat():
        heartbeat_started.set()
        try:
            engine._stop_event.wait()
        finally:
            engine._running = False

    monkeypatch.setattr(engine, "_heartbeat_loop", controlled_heartbeat)

    assert engine.start() is True
    assert heartbeat_started.wait(timeout=1)
    worker = engine._thread

    assert engine.start() is True
    assert engine._thread is worker
    assert len(connection_attempts) == 1
    cache_add.assert_called_once_with("192.0.2.10", 10809)

    engine.stop()
    assert engine._thread is None
    assert not engine.is_running()


def test_neighbor_reports_cache_persistence_failure(monkeypatch, caplog):
    from blackoutkit.scanner import neighbor_cache

    heartbeat_started = threading.Event()
    monkeypatch.setattr(neighbor.socket, "create_connection", lambda *_args, **_kwargs: _SocketContext())
    monkeypatch.setattr(neighbor_cache, "add_neighbor", lambda *_args: (_ for _ in ()).throw(OSError("disk full")))

    engine = NeighborConnectEngine(peer_host="192.0.2.10", peer_port=10809)

    def controlled_heartbeat():
        heartbeat_started.set()
        try:
            engine._stop_event.wait()
        finally:
            engine._running = False

    monkeypatch.setattr(engine, "_heartbeat_loop", controlled_heartbeat)

    with caplog.at_level(logging.WARNING, logger="blackoutkit.engine"):
        assert engine.start() is True
        assert heartbeat_started.wait(timeout=1)

    assert "Failed to persist neighbor cache: disk full" in caplog.text
    engine.stop()


def test_traffic_monitor_normalizes_connections_and_emits_counter_deltas():
    samples = [
        {
            "pid": 42,
            "process": "browser.exe",
            "protocol": "TCP",
            "local_addr": "192.168.1.10",
            "local_port": 50000,
            "remote_addr": "8.8.8.8",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "bytes_sent": 100,
            "bytes_recv": 200,
        }
    ]
    entries = []
    timestamps = iter((100.0, 105.0))
    monitor = TrafficMonitor(
        connection_loader=lambda **_kwargs: list(samples),
        log_writer=entries.append,
        clock=lambda: next(timestamps),
    )

    monitor._snapshot_connections()
    samples[0]["bytes_sent"] = 160
    samples[0]["bytes_recv"] = 260
    monitor._snapshot_connections()

    assert entries[0]["local"] == "192.168.1.10:50000"
    assert entries[0]["remote"] == "8.8.8.8:443"
    assert entries[0]["bytes_available"] is True
    assert (entries[0]["bytes_sent"], entries[0]["bytes_recv"]) == (100, 200)
    assert (entries[1]["bytes_sent"], entries[1]["bytes_recv"]) == (60, 60)
    assert entries[1]["duration_sec"] == 5.0
