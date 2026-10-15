"""Phase 5 — REST API (blackoutkit.api)."""
from __future__ import annotations

import pytest

from blackoutkit.api import (
    collect_bandwidth,
    collect_connections,
    collect_metrics,
)

# ── collectors (no fastapi needed) ───────────────────────────────────────────

def test_collect_metrics_shape():
    m = collect_metrics()
    assert m["available"] is True
    assert "cpu_percent" in m
    assert set(m["memory"]) >= {"total_bytes", "used_bytes", "percent"}
    assert "running" in m["daemon"]


def test_collect_bandwidth_shape():
    b = collect_bandwidth()
    assert b["available"] is True
    assert set(b["totals"]) >= {"bytes_sent", "bytes_recv"}
    assert isinstance(b["per_nic"], dict)


def test_collect_connections_filtering(monkeypatch):
    import blackoutkit.tools as tools

    fake = [
        {"process": "chrome", "pid": 1, "protocol": "TCP", "local_addr": "127.0.0.1",
         "local_port": 5555, "remote_addr": "1.1.1.1", "remote_port": 443, "status": "ESTABLISHED"},
        {"process": "firefox", "pid": 2, "protocol": "TCP", "local_addr": "127.0.0.1",
         "local_port": 6666, "remote_addr": "8.8.8.8", "remote_port": 53, "status": "ESTABLISHED"},
    ]
    monkeypatch.setattr(tools, "get_active_connections", lambda established_only=False: fake)

    assert collect_connections()["count"] == 2
    assert collect_connections(process="chrome")["count"] == 1
    assert collect_connections(process="CHROME")["count"] == 1  # case-insensitive
    assert collect_connections(port=53)["count"] == 1            # remote port
    assert collect_connections(port=6666)["count"] == 1          # local port
    assert collect_connections(process="nope")["count"] == 0


def test_collect_connections_degrades_when_listing_fails(monkeypatch):
    import blackoutkit.tools as tools

    def _boom(established_only=False):
        raise RuntimeError("access denied")

    monkeypatch.setattr(tools, "get_active_connections", _boom)
    result = collect_connections()
    assert result["available"] is False
    assert "reason" in result


# ── HTTP surface (needs fastapi) ─────────────────────────────────────────────

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from blackoutkit.api import create_app  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(create_app())


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_metrics_endpoint(client):
    r = client.get("/api/metrics")
    assert r.status_code == 200
    assert "available" in r.json()


def test_connections_endpoint_with_filters(client, monkeypatch):
    import blackoutkit.tools as tools

    fake = [
        {"process": "chrome", "pid": 1, "protocol": "TCP", "local_addr": "127.0.0.1",
         "local_port": 5555, "remote_addr": "1.1.1.1", "remote_port": 443, "status": "ESTABLISHED"},
    ]
    monkeypatch.setattr(tools, "get_active_connections", lambda established_only=False: fake)

    r = client.get("/api/connections", params={"process": "chrome"})
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True
    assert body["count"] == 1

    r2 = client.get("/api/connections", params={"port": 9999})
    assert r2.json()["count"] == 0


def test_bandwidth_endpoint(client):
    r = client.get("/api/bandwidth")
    assert r.status_code == 200
    assert "totals" in r.json()
