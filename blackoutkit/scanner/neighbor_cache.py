"""LAN neighbor cache management with atomic writes and TTL validation."""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

from .. import APP_DATA_DIR

NEIGHBOR_CACHE_FILE = APP_DATA_DIR / "neighbor_cache.json"
DEFAULT_CACHE_TTL_MINUTES = 10
MAX_CACHED_NEIGHBORS = 50


def _now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _parse_iso_datetime(iso_str: str) -> datetime:
    """Parse ISO 8601 datetime string."""
    return datetime.fromisoformat(iso_str)


def _is_expired(timestamp_iso: str, max_age_minutes: int) -> bool:
    """Check if a timestamp is older than max_age_minutes."""
    try:
        ts = _parse_iso_datetime(timestamp_iso)
        age = datetime.now(timezone.utc) - ts
        return age > timedelta(minutes=max_age_minutes)
    except Exception:
        return True


def save_neighbor_cache(neighbors: list[dict]) -> None:
    """
    Atomically save neighbor list to cache file.

    Args:
        neighbors: List of dicts with {ip, port, mac, hostname, last_seen, is_self, ...}

    Silently fails on write errors (error-resilient pattern).
    """
    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "timestamp": _now_iso(),
            "neighbors": neighbors[:MAX_CACHED_NEIGHBORS],
        }
        fd, tmp_path = tempfile.mkstemp(dir=APP_DATA_DIR, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, NEIGHBOR_CACHE_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception:
        pass


def load_neighbor_cache(max_age_minutes: int = DEFAULT_CACHE_TTL_MINUTES) -> list[dict] | None:
    """
    Load neighbor cache if it exists and is still fresh.

    Args:
        max_age_minutes: Maximum age of cache in minutes. Defaults to 10.

    Returns:
        List of neighbor dicts if cache is valid, None otherwise.
    """
    if not NEIGHBOR_CACHE_FILE.exists():
        return None

    try:
        data = json.loads(NEIGHBOR_CACHE_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None

        timestamp = data.get("timestamp", "")
        if _is_expired(timestamp, max_age_minutes):
            return None

        neighbors = data.get("neighbors", [])
        if not isinstance(neighbors, list):
            return None

        return neighbors
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError, OSError):
        return None


def add_neighbor(
    ip: str,
    port: int,
    mac: str = "",
    hostname: str = "",
    is_self: bool = False,
) -> None:
    """
    Merge a neighbor into the existing cache (avoid duplicates by ip:port).

    Updates last_seen timestamp for known neighbors.
    Atomically writes the updated cache.

    Args:
        ip: Neighbor IP address
        port: Neighbor proxy port
        mac: MAC address (optional)
        hostname: Hostname (optional)
        is_self: Whether this is the local machine
    """
    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

        existing = load_neighbor_cache(max_age_minutes=1440)
        neighbors = existing or []

        key = f"{ip}:{port}"
        found = False
        for n in neighbors:
            if f"{n.get('ip')}:{n.get('port')}" == key:
                n["last_seen"] = _now_iso()
                found = True
                break

        if not found:
            neighbors.append({
                "ip": ip,
                "port": port,
                "mac": mac,
                "hostname": hostname,
                "last_seen": _now_iso(),
                "last_verified": _now_iso(),
                "is_self": is_self,
            })

        save_neighbor_cache(neighbors)
    except Exception:
        pass


def get_neighbors_for_broadcast(
    max_stale_minutes: int = 60,
) -> list[dict]:
    """
    Return recent, verified neighbors suitable for broadcast beacon.

    Filters out stale entries (last verified >max_stale_minutes ago).
    Includes only {ip, port, mac} (minimal payload for broadcast).

    Args:
        max_stale_minutes: Exclude neighbors not verified in this many minutes

    Returns:
        Minimal neighbor dicts for broadcast
    """
    neighbors = load_neighbor_cache(max_age_minutes=1440)
    if not neighbors:
        return []

    fresh = []
    now = datetime.now(timezone.utc)

    for n in neighbors:
        try:
            last_verified = _parse_iso_datetime(n.get("last_verified", ""))
            age = (now - last_verified).total_seconds() / 60
            if age <= max_stale_minutes:
                fresh.append({
                    "ip": n.get("ip"),
                    "port": n.get("port"),
                    "mac": n.get("mac", ""),
                })
        except Exception:
            continue

    return fresh


def clear_neighbor_cache() -> None:
    """Delete the neighbor cache file."""
    try:
        if NEIGHBOR_CACHE_FILE.exists():
            NEIGHBOR_CACHE_FILE.unlink()
    except OSError:
        pass


def cache_age_minutes() -> float:
    """Return age of cache in minutes, or -1 if cache doesn't exist or is corrupted."""
    if not NEIGHBOR_CACHE_FILE.exists():
        return -1

    try:
        data = json.loads(NEIGHBOR_CACHE_FILE.read_text(encoding="utf-8"))
        timestamp = data.get("timestamp", "")
        ts = _parse_iso_datetime(timestamp)
        age = (datetime.now(timezone.utc) - ts).total_seconds() / 60
        return age
    except Exception:
        return -1
