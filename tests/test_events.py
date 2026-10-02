"""Tests for the structured local event bus (Blackout Operator foundation)."""
import json

import pytest

from blackoutkit import events as ev


def test_event_from_string_gets_defaults():
    event = ev.Event.from_raw("engine.started")
    assert event is not None
    assert event.type == "engine.started"
    assert event.severity == "info"
    assert event.safe_for_logs is True
    assert event.event_id


def test_event_from_rejects_unusable_input():
    assert ev.Event.from_raw(None) is None
    assert ev.Event.from_raw(42) is None
    assert ev.Event.from_raw({"type": ""}) is None
    assert ev.Event.from_raw({"no_type": True}) is None


def test_sensitive_keys_removed_not_masked():
    details = {
        "password": "hunter2",
        "ikev2_psk": "shared-secret",
        "api_key": "sk-123",
        "config_uri": "vless://uuid@host:443",
        "engine": "xray",
        "nested": {"token": "abc", "note": "fine"},
    }
    sanitized = ev.sanitize_details(details)
    assert "password" not in sanitized
    assert "ikev2_psk" not in sanitized
    assert "api_key" not in sanitized
    assert "config_uri" not in sanitized
    assert sanitized["engine"] == "xray"
    assert sanitized["nested"]["note"] == "fine"
    assert "token" not in sanitized["nested"]


def test_secret_uri_values_redacted_whole():
    sanitized = ev.sanitize_details({"raw": "vless://1111-2222@1.2.3.4:443?security=reality"})
    assert sanitized["raw"] == ev.REDACTED
    assert "1111-2222" not in json.dumps(sanitized)


def test_long_strings_bounded():
    sanitized = ev.sanitize_details({"blob": "x" * 5000})
    assert len(sanitized["blob"]) < 1200
    assert sanitized["blob"].endswith("[truncated]")


def test_publish_dispatches_to_observers():
    bus = ev.EventBus()
    seen = []
    stop = bus.subscribe(seen.append)
    published = bus.publish({"type": "engine.started", "engine": "warp"})
    assert published is not None
    assert [event.type for event in seen] == ["engine.started"]
    stop()
    bus.publish({"type": "engine.stopped"})
    assert len(seen) == 1


def test_failing_observer_does_not_break_publish():
    bus = ev.EventBus()

    def boom(_event):
        raise RuntimeError("observer exploded")

    seen = []
    bus.subscribe(boom)
    bus.subscribe(seen.append)
    published = bus.publish("engine.failed")
    assert published is not None
    assert [event.type for event in seen] == ["engine.failed"]


def test_recent_filters_by_type_prefix_and_severity():
    bus = ev.EventBus()
    bus.publish({"type": "engine.started", "severity": "info"})
    bus.publish({"type": "engine.failed", "severity": "error"})
    bus.publish({"type": "connection.lost", "severity": "error"})
    assert [item["type"] for item in bus.recent(type_prefix="engine.")] == [
        "engine.started",
        "engine.failed",
    ]
    assert len(bus.recent(severity="error")) == 2
    assert len(bus.recent(limit=1)) == 1


def test_file_sink_persists_and_rereads(tmp_path):
    path = tmp_path / "events.jsonl"
    bus = ev.EventBus()
    bus.subscribe(ev.make_file_sink(path))
    bus.publish({"type": "engine.started", "engine": "warp", "summary": "hello"})
    loaded = ev.read_event_file(path)
    assert len(loaded) == 1
    assert loaded[0]["type"] == "engine.started"
    assert loaded[0]["summary"] == "hello"


def test_file_sink_rotation_bounds_size(tmp_path):
    path = tmp_path / "events.jsonl"
    sink = ev.make_file_sink(path, max_lines=10)
    for index in range(25):
        sink(ev.Event.from_raw({"type": "engine.started", "summary": str(index)}))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 10
    assert json.loads(lines[-1])["summary"] == "24"


def test_merged_recent_events_dedupes_across_sources(tmp_path, monkeypatch):
    monkeypatch.setattr("blackoutkit.settings.APP_DATA_DIR", tmp_path)
    path = ev.default_event_file()
    persisted = ev.Event.from_raw({"type": "connection.recovered", "summary": "from daemon"})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(persisted.to_dict()) + "\n", encoding="utf-8")

    bus = ev.EventBus()
    bus.publish({"type": "engine.started", "summary": "local"})
    merged = ev.merged_recent_events(bus=bus)
    types = [item["type"] for item in merged]
    assert "connection.recovered" in types
    assert "engine.started" in types


def test_merged_recent_events_applies_type_filter():
    bus = ev.EventBus()
    bus.publish({"type": "engine.started"})
    bus.publish({"type": "connection.lost", "severity": "error"})
    merged = ev.merged_recent_events(type_prefix="engine.", include_persisted=False, bus=bus)
    assert [item["type"] for item in merged] == ["engine.started"]


def test_module_publish_never_raises_on_garbage():
    assert ev.publish(None) is None
    assert ev.publish({"summary": "no type"}) is None


def test_enable_default_persistence_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr("blackoutkit.settings.APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(ev, "_persistence_attached", False)
    ev.enable_default_persistence()
    ev.enable_default_persistence()  # second attach must be a no-op
    ev.publish({"type": "engine.started", "engine": "warp"})
    lines = ev.default_event_file().read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1


def test_known_event_vocabulary_includes_operator_types():
    for expected in (
        "engine.started",
        "engine.failed",
        "connection.recovered",
        "daemon.reconnect_scheduled",
        "user.approval_required",
    ):
        assert expected in ev.KNOWN_EVENT_TYPES
