"""Phase 6 — live SecurityObserver + TrafficMonitor observer hook."""
from __future__ import annotations

from blackoutkit.daemon.traffic_monitor import TrafficMonitor
from blackoutkit.security_observer import SecurityObserver, split_endpoint

ENTRY = {
    "ts": 1000.0,
    "pid": 1,
    "process": "chrome",
    "protocol": "tcp",
    "local": "127.0.0.1:5000",
    "remote": "1.2.3.4:443",
    "status": "ESTABLISHED",
    "bytes_sent": 10,
    "bytes_recv": 20,
}


class _FakeAnomaly:
    severity = "high"
    anomaly_type = "exfiltration"
    description = "large upload to 1.2.3.4"


class _FakeDetector:
    def __init__(self, result=None):
        self.result = result
        self.calls = []

    def detect(self, event):
        self.calls.append(event)
        return self.result


class _FakeFeeds:
    def __init__(self, ip=False, domain=False, raise_on_ip=False):
        self.ip = ip
        self.domain = domain
        self._raise = raise_on_ip

    def is_ip_blocked(self, ip):
        if self._raise:
            raise RuntimeError("feed broken")
        return self.ip

    def is_domain_blocked(self, domain):
        return self.domain


# ── endpoint parsing ─────────────────────────────────────────────────────────

def test_split_endpoint_variants():
    assert split_endpoint("1.2.3.4:443") == ("1.2.3.4", 443)
    assert split_endpoint("[::1]:8443") == ("::1", 8443)
    assert split_endpoint("example.com") == ("example.com", None)
    assert split_endpoint("") == ("", None)
    assert split_endpoint("2001:db8::1") == ("2001:db8::1", None)


# ── observer ─────────────────────────────────────────────────────────────────

def test_observe_returns_anomaly_hit():
    det = _FakeDetector(_FakeAnomaly())
    obs = SecurityObserver(detector=det, threat_feeds=_FakeFeeds())
    hits = obs.observe(ENTRY)
    assert len(hits) == 1
    assert hits[0]["kind"] == "anomaly"
    assert hits[0]["type"] == "exfiltration"
    # the detector received a ConnectionEvent built from the entry
    assert det.calls[0].dst_ip == "1.2.3.4"
    assert det.calls[0].dst_port == 443


def test_observe_no_hits_when_clean():
    obs = SecurityObserver(detector=_FakeDetector(None), threat_feeds=_FakeFeeds())
    assert obs.observe(ENTRY) == []


def test_observe_passes_bytes_available_flag():
    det = _FakeDetector(None)
    obs = SecurityObserver(detector=det, threat_feeds=_FakeFeeds())
    obs.observe(dict(ENTRY, bytes_available=False))
    assert det.calls[0].bytes_available is False


def test_observe_uses_zero_timestamp_not_clock():
    det = _FakeDetector(None)
    obs = SecurityObserver(detector=det, threat_feeds=_FakeFeeds(), clock=lambda: 999.0)
    obs.observe(dict(ENTRY, ts=0.0))
    assert det.calls[0].timestamp == 0.0


def test_observe_threat_ip_hit():
    obs = SecurityObserver(detector=_FakeDetector(None), threat_feeds=_FakeFeeds(ip=True))
    hits = obs.observe(ENTRY)
    assert len(hits) == 1
    assert hits[0]["kind"] == "threat"
    assert hits[0]["type"] == "blocked_ip"


def test_observe_threat_domain_hit():
    entry = dict(ENTRY, remote="evil.example:443")
    obs = SecurityObserver(detector=_FakeDetector(None), threat_feeds=_FakeFeeds(domain=True))
    hits = obs.observe(entry)
    assert hits and hits[0]["type"] == "blocked_domain"


def test_observe_invokes_on_hit_callback():
    seen = []
    obs = SecurityObserver(
        detector=_FakeDetector(_FakeAnomaly()),
        threat_feeds=_FakeFeeds(ip=True),
        on_hit=seen.append,
    )
    hits = obs.observe(ENTRY)
    assert len(hits) == 2
    assert len(seen) == 2


def test_observe_survives_detector_exception():
    class _Boom:
        def detect(self, event):
            raise RuntimeError("boom")

    obs = SecurityObserver(detector=_Boom(), threat_feeds=_FakeFeeds())
    assert obs.observe(ENTRY) == []  # no crash


def test_observe_survives_threat_feed_exception():
    obs = SecurityObserver(detector=_FakeDetector(None), threat_feeds=_FakeFeeds(raise_on_ip=True))
    assert obs.observe(ENTRY) == []


def test_observe_ignores_non_dict():
    obs = SecurityObserver(detector=_FakeDetector(None), threat_feeds=_FakeFeeds())
    assert obs.observe(None) == []
    assert obs.observe("nope") == []


# ── TrafficMonitor integration ───────────────────────────────────────────────

class _RecordingObserver:
    def __init__(self, raise_on_observe=False):
        self.seen = []
        self._raise = raise_on_observe

    def observe(self, entry):
        if self._raise:
            raise RuntimeError("observer boom")
        self.seen.append(entry)


def _conn():
    return {
        "pid": 1, "process": "chrome", "protocol": "TCP",
        "local_addr": "127.0.0.1", "local_port": 5000,
        "remote_addr": "1.2.3.4", "remote_port": 443,
        "status": "ESTABLISHED", "bytes_sent": 10, "bytes_recv": 20,
    }


def test_traffic_monitor_calls_observer_on_write():
    written = []
    obs = _RecordingObserver()
    monitor = TrafficMonitor(
        connection_loader=lambda **kw: [_conn()],
        log_writer=written.append,
        observer=obs,
        clock=lambda: 1000.0,
    )
    monitor._snapshot_connections()
    assert len(written) == 1
    assert len(obs.seen) == 1
    assert obs.seen[0]["remote"] == "1.2.3.4:443"


def test_traffic_monitor_survives_observer_exception():
    written = []
    monitor = TrafficMonitor(
        connection_loader=lambda **kw: [_conn()],
        log_writer=written.append,
        observer=_RecordingObserver(raise_on_observe=True),
        clock=lambda: 1000.0,
    )
    monitor._snapshot_connections()  # must not raise
    assert len(written) == 1  # the log write still happened


def test_traffic_monitor_without_observer_still_writes():
    written = []
    monitor = TrafficMonitor(
        connection_loader=lambda **kw: [_conn()],
        log_writer=written.append,
        clock=lambda: 1000.0,
    )
    monitor._snapshot_connections()
    assert len(written) == 1
