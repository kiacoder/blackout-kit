"""Tests for the opt-in loopback SSE event bridge."""
import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from blackoutkit import event_bridge
from blackoutkit import events as ev


@pytest.fixture(autouse=True)
def _isolated_event_journal(tmp_path, monkeypatch):
    # Bridge replay merges the on-disk journal; tests must not observe (or
    # depend on) events persisted by other processes on this machine.
    monkeypatch.setattr("blackoutkit.settings.APP_DATA_DIR", tmp_path)


@pytest.fixture()
def bridge():
    bus = ev.EventBus()
    server, state = event_bridge.start_bridge(port=0, bus=bus)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    port = server.server_address[1]
    yield bus, port
    server.shutdown()
    server.server_close()


def test_bridge_refuses_non_loopback_bind():
    with pytest.raises(ValueError):
        event_bridge.start_bridge(host="0.0.0.0", port=0)
    with pytest.raises(ValueError):
        event_bridge.start_bridge(host="192.168.1.10", port=0)


def test_health_endpoint_reports_clients(bridge):
    _bus, port = bridge
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as response:
        payload = json.loads(response.read())
    assert payload["service"] == "blackout-event-bridge"
    assert payload["status"] == "ok"


def test_unknown_path_is_404(bridge):
    _bus, port = bridge
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/nope", timeout=5)
    assert exc_info.value.code == 404


def test_sse_stream_replays_recent_events(bridge):
    bus, port = bridge
    bus.publish({"type": "engine.starting", "engine": "warp", "summary": "starting"})
    bus.publish({"type": "engine.started", "engine": "warp", "summary": "ready"})
    time.sleep(0.2)

    response = urllib.request.urlopen(f"http://127.0.0.1:{port}/events", timeout=8)
    seen = []
    event_payload = None
    for _ in range(20):
        line = response.readline().decode("utf-8", "replace").rstrip("\n")
        if line.startswith("data: "):
            event_payload = json.loads(line[6:])
            seen.append(event_payload["type"])
        if len(seen) >= 2:
            break
    assert seen == ["engine.starting", "engine.started"]
    # Documented event envelope fields survive the stream.
    assert event_payload["engine"] == "warp"
    assert event_payload["event_id"]


def test_streamed_events_never_contain_secret_uris(bridge):
    bus, port = bridge
    published = bus.publish({
        "type": "engine.failed",
        "engine": "xray",
        "severity": "error",
        "details": {"uri": "vless://super-secret@1.2.3.4:443", "code": "x"},
    })
    time.sleep(0.2)

    response = urllib.request.urlopen(f"http://127.0.0.1:{port}/events", timeout=8)
    collected = []
    for _ in range(20):
        line = response.readline().decode("utf-8", "replace").rstrip("\n")
        if line.startswith("data: "):
            collected.append(line[6:])
        if any("engine.failed" in item for item in collected):
            break
    assert collected
    assert "super-secret" not in "".join(collected)
    assert published.to_dict()["details"] == {"code": "x"}
