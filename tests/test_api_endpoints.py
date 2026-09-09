"""Unit tests for Phase 5C REST API endpoints (/api/metrics, /api/connections filtering, /api/bandwidth)."""
import json
import threading
import time
import urllib.error
import urllib.request
import pytest

from blackoutkit import tools
from blackoutkit.tools import run_web_api_dashboard




@pytest.fixture(scope="module")
def api_server():
    host = "127.0.0.1"
    port = 8899
    server_thread = threading.Thread(
        target=run_web_api_dashboard,
        args=(host, port),
        daemon=True,
    )
    server_thread.start()
    time.sleep(0.5)  # Allow server to start up
    yield f"http://{host}:{port}"


def test_api_status_endpoint_uses_bound_origin(api_server):
    req = urllib.request.urlopen(f"{api_server}/api/status")

    assert req.status == 200
    assert req.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:8899"
    data = json.loads(req.read().decode("utf-8"))
    assert data["ok"] is True


def test_api_metrics_endpoint(api_server):
    url = f"{api_server}/api/metrics"
    req = urllib.request.urlopen(url)
    assert req.status == 200
    data = json.loads(req.read().decode("utf-8"))
    assert "timestamp" in data
    assert "active_connections" in data
    assert "established_connections" in data
    assert "bytes_sent" in data
    assert "bytes_recv" in data


def test_api_connections_filtering(api_server):
    url = f"{api_server}/api/connections?port=80"
    req = urllib.request.urlopen(url)
    assert req.status == 200
    data = json.loads(req.read().decode("utf-8"))
    assert "connections" in data
    assert "total" in data


def test_api_bandwidth_endpoint(api_server):
    url = f"{api_server}/api/bandwidth?interval=0.1"
    req = urllib.request.urlopen(url)
    assert req.status == 200
    data = json.loads(req.read().decode("utf-8"))
    assert "timestamp" in data
    assert "interval_seconds" in data
    assert "interfaces" in data


def test_api_live_stream_uses_bound_origin(api_server):
    req = urllib.request.urlopen(f"{api_server}/api/live-stream")

    assert req.status == 200
    assert req.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:8899"
    assert b"data:" in req.read()


def test_api_audit_and_live_stream_accept_query_strings(api_server):
    with urllib.request.urlopen(f"{api_server}/api/audit?source=test") as response:
        assert response.status == 200
    with urllib.request.urlopen(f"{api_server}/api/live-stream?source=test") as response:
        assert response.status == 200
        assert b"data:" in response.read()


@pytest.mark.parametrize("interval", ["abc", "nan", "-1"])
def test_api_bandwidth_rejects_invalid_intervals(api_server, interval):
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(f"{api_server}/api/bandwidth?interval={interval}")
    assert error.value.code == 400


def test_api_status_remains_responsive_during_audit(api_server, monkeypatch):
    audit_started = threading.Event()
    release_audit = threading.Event()
    audit_result = {
        "score": 100,
        "grade": "A+",
        "findings": [],
    }

    def slow_audit():
        audit_started.set()
        assert release_audit.wait(5)
        return audit_result

    monkeypatch.setattr(tools, "run_network_audit", slow_audit)
    audit_errors = []

    def request_audit():
        try:
            with urllib.request.urlopen(f"{api_server}/api/audit", timeout=10) as response:
                assert json.loads(response.read().decode("utf-8")) == audit_result
        except Exception as exc:
            audit_errors.append(exc)

    audit_thread = threading.Thread(target=request_audit)
    audit_thread.start()
    assert audit_started.wait(2)

    started = time.monotonic()
    with urllib.request.urlopen(f"{api_server}/api/status", timeout=2) as response:
        assert response.status == 200
        assert json.loads(response.read().decode("utf-8"))["ok"] is True
    assert time.monotonic() - started < 1.5

    release_audit.set()
    audit_thread.join(timeout=2)
    assert not audit_thread.is_alive()
    assert audit_errors == []
