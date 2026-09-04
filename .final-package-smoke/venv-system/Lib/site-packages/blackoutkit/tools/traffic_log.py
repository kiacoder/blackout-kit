"""
Blackout Kit - Traffic Logging & Network Audit Trail.
Log and query network connections with per-app/protocol aggregation.

Core features:
  - Append-only JSONL traffic log (one entry per connection snapshot)
  - Query by app, protocol, time range
  - Aggregate stats (bytes per app/protocol/hour)
  - Automatic pruning of old entries
"""
import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)
_traffic_lock = threading.Lock()

from .. import APP_DATA_DIR

TRAFFIC_LOG_FILE = APP_DATA_DIR / "traffic.jsonl"


# ──────────────────────────── Storage & Persistence ──────────────────────────

def append_connection_log(entry: dict) -> None:
    """
    Atomically append a connection entry to the JSONL traffic log (thread-safe).
    Entry should contain: ts, pid, process, protocol, local, remote, status, duration_sec, bytes_sent, bytes_recv
    """
    with _traffic_lock:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

        entry_json = json.dumps(entry, separators=(',', ':'))

        try:
            with open(TRAFFIC_LOG_FILE, 'a') as f:
                f.write(entry_json + '\n')
        except Exception:
            pass  # Silently fail


def load_traffic_log(
    since_ts: Optional[float] = None,
    limit: Optional[int] = None,
) -> list[dict]:
    """
    Load traffic entries from JSONL, optionally filtered by timestamp and limited (thread-safe).
    Returns list of entry dicts, newest first.
    """
    with _traffic_lock:
        if not TRAFFIC_LOG_FILE.exists():
            return []

        entries = []

        try:
            with open(TRAFFIC_LOG_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if since_ts is None or entry.get('ts', 0) >= since_ts:
                            entries.append(entry)
                    except json.JSONDecodeError:
                        continue

            # Return newest first
            entries.sort(key=lambda e: e.get('ts', 0), reverse=True)

            if limit:
                entries = entries[:limit]

            return entries
        except Exception:
            return []


def get_traffic_stats(
    app: Optional[str] = None,
    protocol: Optional[str] = None,
    since_ts: Optional[float] = None,
) -> dict:
    """
    Aggregate traffic stats by app/protocol.
    Returns: {app: {sent_bytes, recv_bytes, conn_count}, protocol: {...}}
    """
    entries = load_traffic_log(since_ts=since_ts)

    stats = {
        'by_app': {},
        'by_protocol': {},
        'total_connections': len(entries),
        'total_sent_bytes': 0,
        'total_recv_bytes': 0,
    }

    for entry in entries:
        proc = entry.get('process', 'unknown').lower()
        prot = entry.get('protocol', 'unknown').upper()
        sent = entry.get('bytes_sent', 0)
        recv = entry.get('bytes_recv', 0)

        # Filter by app/protocol if specified
        if app and proc != app.lower():
            continue
        if protocol and prot != protocol.upper():
            continue

        # Aggregate by app
        if proc not in stats['by_app']:
            stats['by_app'][proc] = {'sent_bytes': 0, 'recv_bytes': 0, 'conn_count': 0}
        stats['by_app'][proc]['sent_bytes'] += sent
        stats['by_app'][proc]['recv_bytes'] += recv
        stats['by_app'][proc]['conn_count'] += 1

        # Aggregate by protocol
        if prot not in stats['by_protocol']:
            stats['by_protocol'][prot] = {'sent_bytes': 0, 'recv_bytes': 0, 'conn_count': 0}
        stats['by_protocol'][prot]['sent_bytes'] += sent
        stats['by_protocol'][prot]['recv_bytes'] += recv
        stats['by_protocol'][prot]['conn_count'] += 1

        # Total
        stats['total_sent_bytes'] += sent
        stats['total_recv_bytes'] += recv

    return stats


def get_traffic_by_hour(since_hours: int = 24) -> dict:
    """
    Aggregate traffic by hour.
    Returns: {hour_iso: {sent_bytes, recv_bytes, conn_count}}
    """
    now = datetime.now(timezone.utc)
    cutoff_ts = (now - timedelta(hours=since_hours)).timestamp()

    entries = load_traffic_log(since_ts=cutoff_ts)

    stats = {}

    for entry in entries:
        ts = entry.get('ts', 0)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        hour_key = dt.strftime('%Y-%m-%dT%H:00Z')

        if hour_key not in stats:
            stats[hour_key] = {'sent_bytes': 0, 'recv_bytes': 0, 'conn_count': 0}

        stats[hour_key]['sent_bytes'] += entry.get('bytes_sent', 0)
        stats[hour_key]['recv_bytes'] += entry.get('bytes_recv', 0)
        stats[hour_key]['conn_count'] += 1

    return stats


def get_top_apps(limit: int = 10, by_metric: str = 'bytes_total') -> list[tuple]:
    """
    Get top N apps by a metric (bytes_total, conn_count, bytes_sent, bytes_recv).
    Returns: [(app_name, metric_value), ...]
    """
    stats = get_traffic_stats()
    by_app = stats['by_app']

    if by_metric == 'bytes_total':
        ranked = sorted(
            by_app.items(),
            key=lambda x: x[1]['sent_bytes'] + x[1]['recv_bytes'],
            reverse=True
        )
    elif by_metric == 'conn_count':
        ranked = sorted(
            by_app.items(),
            key=lambda x: x[1]['conn_count'],
            reverse=True
        )
    elif by_metric == 'bytes_sent':
        ranked = sorted(
            by_app.items(),
            key=lambda x: x[1]['sent_bytes'],
            reverse=True
        )
    elif by_metric == 'bytes_recv':
        ranked = sorted(
            by_app.items(),
            key=lambda x: x[1]['recv_bytes'],
            reverse=True
        )
    else:
        ranked = []

    return [(name, data[by_metric] if by_metric in data else data['sent_bytes'] + data['recv_bytes'])
            for name, data in ranked[:limit]]


def prune_old_logs(retention_days: int = 30) -> int:
    """
    Remove entries older than retention_days.
    Returns number of entries removed.
    """
    if not TRAFFIC_LOG_FILE.exists():
        return 0

    cutoff_ts = (datetime.now(timezone.utc) - timedelta(days=retention_days)).timestamp()

    try:
        entries = load_traffic_log()
        recent = [e for e in entries if e.get('ts', 0) >= cutoff_ts]
        removed_count = len(entries) - len(recent)

        if removed_count > 0:
            # Rewrite log with only recent entries
            fd, tmp_path = tempfile.mkstemp(suffix=".jsonl", dir=APP_DATA_DIR, text=True)
            try:
                with os.fdopen(fd, 'w') as f:
                    for entry in recent:
                        f.write(json.dumps(entry, separators=(',', ':')) + '\n')
                os.replace(tmp_path, TRAFFIC_LOG_FILE)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
                raise

        return removed_count
    except Exception:
        return 0


def clear_traffic_log() -> None:
    """Completely clear the traffic log."""
    try:
        if TRAFFIC_LOG_FILE.exists():
            TRAFFIC_LOG_FILE.unlink()
    except Exception:
        pass


def get_log_size_mb() -> float:
    """Get size of traffic log file in MB."""
    if not TRAFFIC_LOG_FILE.exists():
        return 0.0
    return TRAFFIC_LOG_FILE.stat().st_size / (1024 * 1024)


def get_log_entry_count() -> int:
    """Count total entries in traffic log."""
    if not TRAFFIC_LOG_FILE.exists():
        return 0

    try:
        with open(TRAFFIC_LOG_FILE, 'r') as f:
            return sum(1 for _ in f if _.strip())
    except Exception:
        return 0
