"""Phase 8 — REST API v2 (events, webhooks, plugins, WebSocket streaming)."""
from __future__ import annotations

import pytest

# fastapi is the optional [api] extra — skip cleanly where it is not installed.
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from blackoutkit.api import create_app  # noqa: E402


@pytest.fixture()
def client():
    return TestClient(create_app())


# ── events ───────────────────────────────────────────────────────────────────

def test_v2_events(client):
    r = client.get("/api/v2/events", params={"limit": 5})
    assert r.status_code == 200
    body = r.json()
    assert "events" in body and isinstance(body["events"], list)


def test_v2_events_validates_limit(client):
    assert client.get("/api/v2/events", params={"limit": 0}).status_code == 422


# ── plugins ──────────────────────────────────────────────────────────────────

def test_v2_plugins(client):
    r = client.get("/api/v2/plugins")
    assert r.status_code == 200
    body = r.json()
    assert "enabled" in body
    assert isinstance(body["plugins"], list)


# ── webhooks ─────────────────────────────────────────────────────────────────

def test_v2_webhooks_crud(client, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKOUT_WEBHOOK_FILE", str(tmp_path / "wh.json"))
    assert client.get("/api/v2/webhooks").json()["webhooks"] == []

    r = client.post("/api/v2/webhooks", json={"url": "https://a.test", "event_prefixes": ["engine"]})
    assert r.status_code == 200

    hooks = client.get("/api/v2/webhooks").json()["webhooks"]
    assert hooks[0]["url"] == "https://a.test"
    assert hooks[0]["event_prefixes"] == ["engine"]
    assert hooks[0]["secret"] is None

    assert client.delete("/api/v2/webhooks", params={"url": "https://a.test"}).json()["removed"] is True
    assert client.get("/api/v2/webhooks").json()["webhooks"] == []


def test_v2_webhooks_requires_url(client, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKOUT_WEBHOOK_FILE", str(tmp_path / "wh.json"))
    assert client.post("/api/v2/webhooks", json={}).status_code == 400
    assert client.post("/api/v2/webhooks", json={"url": "u", "event_prefixes": "x"}).status_code == 400


# ── loopback guard covers v2 ─────────────────────────────────────────────────

def test_v2_remote_denied(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKOUT_WEBHOOK_FILE", str(tmp_path / "wh.json"))
    c = TestClient(create_app(), client=("203.0.113.9", 1234))
    assert c.get("/api/v2/events").status_code == 403


# ── WebSocket streaming ──────────────────────────────────────────────────────

def test_v2_ws_handshake(client):
    with client.websocket_connect("/api/v2/ws/events") as ws:
        first = ws.receive_json()
        assert first["type"] == "stream.connected"
