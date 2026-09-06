"""Traffic logging and local network audit helpers."""

from __future__ import annotations

import json
import logging
import math
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import APP_DATA_DIR

_log = logging.getLogger(__name__)
_traffic_lock = threading.Lock()
TRAFFIC_LOG_FILE = APP_DATA_DIR / "traffic.jsonl"


def _log_path(path: str | Path | None = None) -> Path:
    return Path(path) if path is not None else TRAFFIC_LOG_FILE


def _entry_timestamp(entry: object) -> float:
    if not isinstance(entry, dict):
        return 0.0
    try:
        value = float(entry.get("ts", 0) or 0)
    except (TypeError, ValueError):
        return 0.0
    return value if value == value and abs(value) != float("inf") else 0.0


def _entry_number(value: object) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    if not math.isfinite(float(value)) or value < 0:
        return 0
    return value


def _received_bytes(entry: dict) -> int | float:
    value = entry.get("bytes_recv")
    if value is None:
        value = entry.get("bytes_received", 0)
    return _entry_number(value)


def append_connection_log(entry: dict, *, path: str | Path | None = None) -> None:
    """Append one connection snapshot to the JSONL traffic log."""
    log_path = _log_path(path)
    with _traffic_lock:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
        except (OSError, TypeError, ValueError):
            pass


def load_traffic_log(
    since_ts: float | None = None,
    limit: int | None = None,
    *,
    path: str | Path | None = None,
) -> list[dict]:
    """Load valid traffic entries, newest first, with optional filtering."""
    log_path = _log_path(path)
    with _traffic_lock:
        if not log_path.exists():
            return []
        entries: list[dict] = []
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(entry, dict):
                        continue
                    timestamp = _entry_timestamp(entry)
                    if since_ts is None or timestamp >= since_ts:
                        entries.append(entry)
        except OSError:
            return []
        entries.sort(key=_entry_timestamp, reverse=True)
        return entries[:limit] if limit is not None and limit > 0 else entries


def get_traffic_stats(
    app: str | None = None,
    protocol: str | None = None,
    since_ts: float | None = None,
    *,
    path: str | Path | None = None,
) -> dict:
    """Aggregate traffic statistics by process and protocol."""
    entries = load_traffic_log(since_ts=since_ts, path=path)
    stats = {
        "by_app": {},
        "by_protocol": {},
        "total_connections": 0,
        "total_sent_bytes": 0,
        "total_recv_bytes": 0,
    }
    for entry in entries:
        process = str(entry.get("process", "unknown")).lower()
        connection_protocol = str(entry.get("protocol", "unknown")).upper()
        if app and process != app.lower():
            continue
        if protocol and connection_protocol != protocol.upper():
            continue
        sent = _entry_number(entry.get("bytes_sent", 0))
        received = _received_bytes(entry)
        stats["by_app"].setdefault(
            process, {"sent_bytes": 0, "recv_bytes": 0, "conn_count": 0}
        )
        stats["by_app"][process]["sent_bytes"] += sent
        stats["by_app"][process]["recv_bytes"] += received
        stats["by_app"][process]["conn_count"] += 1
        stats["by_protocol"].setdefault(
            connection_protocol, {"sent_bytes": 0, "recv_bytes": 0, "conn_count": 0}
        )
        stats["by_protocol"][connection_protocol]["sent_bytes"] += sent
        stats["by_protocol"][connection_protocol]["recv_bytes"] += received
        stats["by_protocol"][connection_protocol]["conn_count"] += 1
        stats["total_connections"] += 1
        stats["total_sent_bytes"] += sent
        stats["total_recv_bytes"] += received
    return stats


def get_traffic_by_hour(
    since_hours: int = 24,
    *,
    path: str | Path | None = None,
) -> dict:
    """Aggregate traffic by UTC hour."""
    if since_hours < 0:
        raise ValueError("since_hours must not be negative")
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).timestamp()
    stats: dict[str, dict[str, int | float]] = {}
    for entry in load_traffic_log(since_ts=cutoff, path=path):
        timestamp = _entry_timestamp(entry)
        if timestamp == 0.0 and entry.get("ts") not in (0, 0.0, "0", "0.0"):
            continue
        hour = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:00Z"
        )
        bucket = stats.setdefault(
            hour, {"sent_bytes": 0, "recv_bytes": 0, "conn_count": 0}
        )
        bucket["sent_bytes"] += _entry_number(entry.get("bytes_sent", 0))
        bucket["recv_bytes"] += _received_bytes(entry)
        bucket["conn_count"] += 1
    return stats


def get_top_apps(
    limit: int = 10,
    by_metric: str = "bytes_total",
    *,
    path: str | Path | None = None,
) -> list[tuple]:
    """Return applications ranked by a supported traffic metric."""
    stats = get_traffic_stats(path=path)
    if by_metric == "bytes_total":
        ranked = sorted(
            stats["by_app"].items(),
            key=lambda item: item[1]["sent_bytes"] + item[1]["recv_bytes"],
            reverse=True,
        )
        return [
            (name, values["sent_bytes"] + values["recv_bytes"])
            for name, values in ranked[:limit]
        ]
    metric = {
        "conn_count": "conn_count",
        "bytes_sent": "sent_bytes",
        "bytes_recv": "recv_bytes",
    }.get(by_metric)
    if metric is None:
        return []
    ranked = sorted(
        stats["by_app"].items(), key=lambda item: item[1][metric], reverse=True
    )
    return [(name, values[metric]) for name, values in ranked[:limit]]


def prune_old_logs(
    retention_days: int = 30,
    *,
    path: str | Path | None = None,
) -> int:
    """Remove entries older than ``retention_days``."""
    if retention_days < 0:
        raise ValueError("retention_days must not be negative")
    log_path = _log_path(path)
    if not log_path.exists():
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).timestamp()
    try:
        entries = load_traffic_log(path=log_path)
        recent = [entry for entry in entries if _entry_timestamp(entry) >= cutoff]
        removed = len(entries) - len(recent)
        if not removed:
            return 0
        descriptor, temporary = tempfile.mkstemp(
            suffix=".jsonl", dir=log_path.parent, text=True
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                for entry in recent:
                    handle.write(json.dumps(entry, separators=(",", ":")) + "\n")
            os.replace(temporary, log_path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
        return removed
    except (OSError, TypeError, ValueError):
        return 0


def clear_traffic_log(*, path: str | Path | None = None) -> None:
    """Delete the complete traffic log."""
    try:
        _log_path(path).unlink(missing_ok=True)
    except OSError:
        pass


def get_log_size_mb(*, path: str | Path | None = None) -> float:
    """Return the traffic log size in megabytes."""
    log_path = _log_path(path)
    try:
        return log_path.stat().st_size / (1024 * 1024)
    except OSError:
        return 0.0


def get_log_entry_count(*, path: str | Path | None = None) -> int:
    """Return the number of non-empty lines in the traffic log."""
    log_path = _log_path(path)
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0
