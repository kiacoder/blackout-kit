"""
Blackout Kit - Structured local event bus (Blackout Operator foundation).

Represents important local Blackout Kit activity as sanitized, typed events
instead of console output only. Events are:

- local only: Blackout Kit never sends events anywhere
- sanitized at the publish boundary: secret-bearing keys and proxy URIs are
  removed before any observer, history, or file sink sees them
- fail-safe: a failing observer can never break networking code

External consumers (MCP clients, local dashboards, avatar hosts) read events
through `recent_events()`, the MCP `blackout_recent_events` tool, or the
opt-in loopback event bridge. Publishing is fire-and-forget and must never
be used for control flow.
"""
from __future__ import annotations

import json
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SEVERITIES: tuple[str, ...] = ("debug", "info", "warning", "error", "critical")

# Documented event vocabulary. Publishing is not restricted to these values,
# but new event types should be added here so external consumers have a
# stable contract.
KNOWN_EVENT_TYPES: frozenset[str] = frozenset({
    "engine.readiness_checked",
    "engine.starting",
    "engine.started",
    "engine.failed",
    "engine.stopped",
    "route.recommended",
    "route.changed",
    "connection.degraded",
    "connection.lost",
    "connection.recovered",
    "doctor.check_completed",
    "doctor.problem_detected",
    "recovery.proposed",
    "recovery.started",
    "recovery.completed",
    "recovery.failed",
    "dns.changed",
    "proxy.changed",
    "daemon.reconnect_scheduled",
    "user.approval_required",
})

REDACTED = "[redacted]"

_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "privatekey", "psk", "passphrase", "authorization",
    "auth", "cookie", "credential", "credentials", "uri", "config_uri",
    "config", "subscription", "seed", "private",
})

_SENSITIVE_KEY_SUFFIXES = (
    "_password", "_passwd", "_token", "_secret", "_psk", "_passphrase",
    "_api_key", "_apikey", "_private_key", "_credential", "_uri",
    "_config_uri",
)

# A detail string containing one of these proxy/credential URI schemes is
# removed whole. Partial masking of credentials is deliberately avoided.
_SECRET_URI_SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://", "ssr://",
    "hysteria://", "hysteria2://", "hy2://", "tuic://", "wireguard://",
    "wg://", "ssh://", "ftp://",
)

_MAX_STRING_VALUE = 1000
_MAX_SUMMARY = 500


def _is_sensitive_key(name: str) -> bool:
    normalized = str(name).lower().replace("-", "_")
    if normalized in _SENSITIVE_KEYS:
        return True
    return normalized.endswith(_SENSITIVE_KEY_SUFFIXES)


def _looks_like_secret_uri(value: str) -> bool:
    lowered = value.lower().lstrip()
    return any(lowered.startswith(scheme) for scheme in _SECRET_URI_SCHEMES)


def sanitize_value(value: Any, _depth: int = 0) -> Any:
    """Return a sanitized copy of a detail value.

    Secret-bearing keys are removed by `sanitize_details`; values here are
    additionally scrubbed for proxy URIs and bounded in size. Prefer removal
    over clever partial masking.
    """
    if _depth > 6:
        return "[truncated]"
    if isinstance(value, str):
        if _looks_like_secret_uri(value):
            return REDACTED
        if len(value) > _MAX_STRING_VALUE:
            return value[:_MAX_STRING_VALUE] + "…[truncated]"
        return value
    if isinstance(value, dict):
        return {
            key: sanitize_value(item, _depth + 1)
            for key, item in value.items()
            if not _is_sensitive_key(key)
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_value(item, _depth + 1) for item in value]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:_MAX_STRING_VALUE]


def sanitize_details(details: dict[str, Any] | None) -> dict[str, Any]:
    """Return a sanitized copy of an event details mapping."""
    if not details:
        return {}
    sanitized = sanitize_value(details)
    return sanitized if isinstance(sanitized, dict) else {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _valid_severity(value: Any) -> str:
    text = str(value or "").lower()
    return text if text in SEVERITIES else "info"


@dataclass(frozen=True)
class Event:
    """One sanitized, structured local event."""

    type: str
    summary: str = ""
    severity: str = "info"
    engine: str | None = None
    source: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    safe_for_logs: bool = True
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: str = field(default_factory=_utc_now)

    @classmethod
    def from_raw(cls, raw: Any) -> "Event | None":
        """Normalize a str, dict, or Event into an Event; None when unusable."""
        if isinstance(raw, cls):
            return raw
        if isinstance(raw, str):
            raw = {"type": raw}
        if not isinstance(raw, dict):
            return None
        event_type = str(raw.get("type") or "").strip()
        if not event_type or len(event_type) > 128:
            return None
        summary = str(raw.get("summary") or raw.get("message") or "")[:_MAX_SUMMARY]
        details = raw.get("details")
        if not isinstance(details, dict):
            details = {
                key: value
                for key, value in raw.items()
                if key not in {
                    "type", "summary", "message", "severity", "engine",
                    "source", "safe_for_logs", "event_id", "timestamp",
                    "details",
                }
            }
        return cls(
            type=event_type,
            summary=summary,
            severity=_valid_severity(raw.get("severity")),
            engine=str(raw["engine"])[:64] if raw.get("engine") else None,
            source=str(raw["source"])[:64] if raw.get("source") else None,
            details=sanitize_details(details),
            safe_for_logs=bool(raw.get("safe_for_logs", True)),
            event_id=str(raw.get("event_id") or uuid.uuid4().hex[:16])[:64],
            timestamp=str(raw.get("timestamp") or _utc_now()),
        )

    def to_dict(self) -> dict[str, Any]:
        """Stable field order for JSON consumers."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "type": self.type,
            "severity": self.severity,
            "engine": self.engine,
            "source": self.source,
            "summary": self.summary,
            "details": dict(self.details),
            "safe_for_logs": self.safe_for_logs,
        }


Observer = Callable[[Event], None]


class EventBus:
    """Thread-safe in-memory publish/subscribe bus with bounded history."""

    def __init__(self, *, history_size: int = 500) -> None:
        self._observers: list[Observer] = []
        self._history: deque[Event] = deque(maxlen=max(1, history_size))
        self._lock = threading.RLock()

    def subscribe(self, callback: Observer) -> Callable[[], None]:
        """Register an observer; returns an idempotent unsubscribe callable."""
        with self._lock:
            if callback not in self._observers:
                self._observers.append(callback)
            observer = callback

        def unsubscribe() -> None:
            with self._lock:
                if observer in self._observers:
                    self._observers.remove(observer)

        return unsubscribe

    def publish(self, event: Any) -> Event | None:
        """Normalize, sanitize, record, and dispatch one event.

        Never raises: unusable input returns None and observer failures are
        swallowed. Networking code may call this unconditionally.
        """
        normalized = Event.from_raw(event)
        if normalized is None:
            return None
        with self._lock:
            self._history.append(normalized)
            observers = list(self._observers)
        for observer in observers:
            try:
                observer(normalized)
            except Exception:
                # Observer isolation is a hard requirement: a broken UI,
                # bridge, or sink must never break engine or recovery code.
                pass
        return normalized

    def recent(
        self,
        *,
        limit: int = 50,
        type_prefix: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Most recent events, oldest first, optionally filtered."""
        with self._lock:
            snapshot = list(self._history)
        if type_prefix:
            snapshot = [
                event for event in snapshot
                if event.type.startswith(type_prefix)
            ]
        if severity:
            snapshot = [event for event in snapshot if event.severity == severity]
        return [event.to_dict() for event in snapshot[-max(0, limit):]]

    def clear(self) -> None:
        with self._lock:
            self._history.clear()


def default_event_file() -> Path:
    """Loopback-local event journal path; resolved late so tests can patch."""
    from . import settings as cfg

    return cfg.APP_DATA_DIR / "events.jsonl"


def _append_event_line(path: Path, line: str, *, max_lines: int) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        with path.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()
        if len(lines) > max_lines:
            with path.open("w", encoding="utf-8") as handle:
                handle.writelines(lines[-max_lines:])
    except OSError:
        # Event persistence is best-effort diagnostics only.
        pass


def make_file_sink(path: Path | None = None, *, max_lines: int = 2000) -> Observer:
    """Build an observer that appends sanitized events to a local JSONL file.

    The sink is thread-safe: daemon threads may publish concurrently, and the
    append+rotate sequence must not interleave. Cross-process writes are
    best-effort (single small appends; rotation failures are swallowed).
    """
    target = Path(path) if path is not None else default_event_file()
    lock = threading.Lock()

    def sink(event: Event) -> None:
        try:
            line = json.dumps(event.to_dict(), ensure_ascii=False)
        except (TypeError, ValueError):
            return
        with lock:
            _append_event_line(target, line, max_lines=max_lines)

    return sink


def read_event_file(path: Path | None = None, *, limit: int = 200) -> list[dict[str, Any]]:
    """Read the most recent persisted events (sanitized again on read)."""
    target = Path(path) if path is not None else default_event_file()
    try:
        with target.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in lines[-max(0, limit):]:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = Event.from_raw(raw)
        if event is not None:
            events.append(event.to_dict())
    return events


def merged_recent_events(
    *,
    limit: int = 50,
    type_prefix: str | None = None,
    include_persisted: bool = True,
    bus: "EventBus | None" = None,
) -> list[dict[str, Any]]:
    """Merge in-process bus history with the local event journal.

    Events emitted by the daemon or other CLI processes live only in the
    journal, so consumers always get the union. Deduplication is by event_id.
    """
    active_bus = bus if bus is not None else bus_or_default()
    combined: dict[str, dict[str, Any]] = {}
    if include_persisted:
        for item in read_event_file(limit=max(limit * 4, 200)):
            combined[item["event_id"]] = item
    for item in active_bus.recent(limit=max(limit * 4, 200)):
        combined[item["event_id"]] = item
    merged = sorted(combined.values(), key=lambda item: item["timestamp"])
    if type_prefix:
        merged = [item for item in merged if item["type"].startswith(type_prefix)]
    return merged[-max(0, limit):]


_default_bus = EventBus()


def bus_or_default() -> EventBus:
    """Process-wide event bus used by CLI, daemon, and doctor wiring."""
    return _default_bus


def publish(event: Any) -> Event | None:
    """Publish to the process-wide bus; never raises."""
    return _default_bus.publish(event)


_persistence_attached = False


def enable_default_persistence(path: Path | None = None) -> None:
    """Attach the local JSONL journal sink to the process-wide bus.

    Idempotent: the sink is attached once per process; repeated calls are
    no-ops so daemon and doctor wiring can both call this safely.
    """
    global _persistence_attached
    if _persistence_attached:
        return
    _default_bus.subscribe(make_file_sink(path))
    _persistence_attached = True


__all__ = [
    "Event",
    "EventBus",
    "KNOWN_EVENT_TYPES",
    "REDACTED",
    "SEVERITIES",
    "bus_or_default",
    "default_event_file",
    "enable_default_persistence",
    "make_file_sink",
    "merged_recent_events",
    "publish",
    "read_event_file",
    "sanitize_details",
    "sanitize_value",
]
