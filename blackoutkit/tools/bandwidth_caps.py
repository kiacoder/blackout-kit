"""
Blackout Kit - Bandwidth Cap Management.
Track daily/monthly per-interface usage against quotas.

Core features:
  - Daily snapshots of per-interface throughput
  - Compare against user-set daily/monthly limits
  - Alert when approaching quota threshold
  - Persistent history (JSON-based)
"""
import json
import logging
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

from .. import APP_DATA_DIR

BANDWIDTH_HISTORY_FILE = APP_DATA_DIR / "bandwidth_history.json"
BANDWIDTH_CAP_SETTINGS_FILE = APP_DATA_DIR / "bandwidth_caps.json"


# ──────────────────────────── Storage & Persistence ──────────────────────────

def save_daily_snapshot(interface: str, rx_bytes: int, tx_bytes: int) -> None:
    """
    Record today's interface throughput.
    Appends to history JSON atomically (one entry per interface per day).
    """
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    today = datetime.now(timezone.utc).date().isoformat()

    # Load existing history
    history = {}
    if BANDWIDTH_HISTORY_FILE.exists():
        try:
            history = json.loads(BANDWIDTH_HISTORY_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            history = {}

    # Ensure interface key exists
    if interface not in history:
        history[interface] = []

    # Check if today already exists (update or append)
    found_today = False
    for i, entry in enumerate(history[interface]):
        if entry.get("date") == today:
            history[interface][i] = {
                "date": today,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
            }
            found_today = True
            break

    if not found_today:
        history[interface].append({
            "date": today,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
        })

    # Keep only last 90 days per interface
    for iface in history:
        if len(history[iface]) > 90:
            history[iface] = history[iface][-90:]

    # Atomic write
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=APP_DATA_DIR, text=True)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(history, f, indent=2)
            os.replace(tmp_path, BANDWIDTH_HISTORY_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise
    except Exception:
        pass  # Silently fail


def load_bandwidth_history(interface: str, days: int = 30) -> list[dict]:
    """
    Load last N days of throughput for an interface.
    Returns list of {date, rx_bytes, tx_bytes} dicts, oldest first.
    """
    if not BANDWIDTH_HISTORY_FILE.exists():
        return []

    try:
        history = json.loads(BANDWIDTH_HISTORY_FILE.read_text())
        entries = history.get(interface, [])

        # Keep only last N days
        if len(entries) > days:
            entries = entries[-days:]

        return entries
    except (json.JSONDecodeError, OSError):
        return []


def get_current_usage(interface: str) -> tuple[int, int, int, int]:
    """
    Calculate today's and this month's cumulative usage.
    Returns: (today_rx_bytes, today_tx_bytes, month_rx_bytes, month_tx_bytes)
    """
    history = load_bandwidth_history(interface, days=31)

    today = datetime.now(timezone.utc).date()
    month_start = today.replace(day=1)

    today_rx = today_tx = 0
    month_rx = month_tx = 0

    for entry in history:
        entry_date = datetime.fromisoformat(entry["date"]).date()

        rx = entry.get("rx_bytes", 0)
        tx = entry.get("tx_bytes", 0)

        # Add to month total if in current month
        if entry_date.month == month_start.month and entry_date.year == month_start.year:
            month_rx += rx
            month_tx += tx

        # Add to today total if today
        if entry_date == today:
            today_rx = rx
            today_tx = tx

    return today_rx, today_tx, month_rx, month_tx


def check_cap_exceeded(
    interface: str,
    daily_limit_mb: Optional[int] = None,
    monthly_limit_mb: Optional[int] = None,
) -> tuple[bool, float, str]:
    """
    Check if usage exceeds limits.
    Returns: (exceeded, percent_used, status_msg)
    """
    if not daily_limit_mb and not monthly_limit_mb:
        return False, 0.0, "No limits set"

    today_rx, today_tx, month_rx, month_tx = get_current_usage(interface)

    today_total_bytes = today_rx + today_tx
    month_total_bytes = month_rx + month_tx

    exceeded = False
    max_pct = 0.0

    # Check daily limit
    if daily_limit_mb:
        daily_bytes = daily_limit_mb * 1024 * 1024
        daily_pct = (today_total_bytes / daily_bytes * 100) if daily_bytes > 0 else 0
        max_pct = max(max_pct, daily_pct)
        if daily_pct >= 100:
            exceeded = True

    # Check monthly limit
    if monthly_limit_mb:
        monthly_bytes = monthly_limit_mb * 1024 * 1024
        monthly_pct = (month_total_bytes / monthly_bytes * 100) if monthly_bytes > 0 else 0
        max_pct = max(max_pct, monthly_pct)
        if monthly_pct >= 100:
            exceeded = True

    status = "OK"
    if max_pct >= 100:
        status = "EXCEEDED"
    elif max_pct >= 80:
        status = "WARNING (80%+)"
    elif max_pct >= 50:
        status = "CAUTION (50%+)"

    return exceeded, max_pct, status


# ──────────────────────────── Cap Settings ──────────────────────────────

def save_caps(caps: dict[str, dict]) -> None:
    """
    Save interface-specific cap settings.
    Format: {interface: {daily_mb: int, monthly_mb: int}}
    """
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=APP_DATA_DIR, text=True)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(caps, f, indent=2)
            os.replace(tmp_path, BANDWIDTH_CAP_SETTINGS_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise
    except Exception:
        pass  # Silently fail


def load_caps() -> dict[str, dict]:
    """
    Load all interface-specific cap settings.
    Returns: {interface: {daily_mb: int, monthly_mb: int}}
    """
    if not BANDWIDTH_CAP_SETTINGS_FILE.exists():
        return {}

    try:
        return json.loads(BANDWIDTH_CAP_SETTINGS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def set_cap(interface: str, daily_mb: Optional[int] = None, monthly_mb: Optional[int] = None) -> None:
    """Update or add a cap for an interface."""
    caps = load_caps()

    if interface not in caps:
        caps[interface] = {}

    if daily_mb is not None:
        caps[interface]["daily_mb"] = daily_mb
    if monthly_mb is not None:
        caps[interface]["monthly_mb"] = monthly_mb

    save_caps(caps)


def get_cap(interface: str) -> tuple[Optional[int], Optional[int]]:
    """Get cap for an interface. Returns (daily_mb, monthly_mb)."""
    caps = load_caps()
    if interface in caps:
        return caps[interface].get("daily_mb"), caps[interface].get("monthly_mb")
    return None, None


def remove_cap(interface: str) -> None:
    """Remove all caps for an interface."""
    caps = load_caps()
    if interface in caps:
        del caps[interface]
        save_caps(caps)


def list_all_caps() -> dict[str, dict]:
    """Get all configured caps."""
    return load_caps()
