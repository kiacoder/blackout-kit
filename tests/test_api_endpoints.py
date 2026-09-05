"""Unit tests for Phase 5C REST API endpoints (/api/metrics, /api/connections filtering, /api/bandwidth)."""
import json
import threading
import time
import urllib.request
import pytest

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
