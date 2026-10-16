"""Multi-device registry and dashboard (Roadmap Phase 7 — Enterprise & Team).

Each device running Blackout Kit records a heartbeat here (``touch``); the
dashboard aggregates them into online/offline counts and per-status totals. The
registry is a single local JSON file — local-first, no server — but it can be
pointed at a shared location (e.g. a synced folder) so a team sees one view.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger(__name__)

DEFAULT_DEVICE_FILE = Path.home() / ".blackout-kit" / "devices.json"
ONLINE_THRESHOLD_SEC = 300
STATUSES = ("connected", "idle", "offline", "unknown")

__all__ = [
    "Device",
    "DeviceRegistry",
    "DEFAULT_DEVICE_FILE",
    "ONLINE_THRESHOLD_SEC",
    "STATUSES",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse(ts: object) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class Device:
    """One known device."""

    id: str
    name: str = ""
    platform: str = ""
    role: str = "member"
    status: str = "unknown"
    engine: Optional[str] = None
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "platform": self.platform,
            "role": self.role,
            "status": self.status if self.status in STATUSES else "unknown",
            "engine": self.engine,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Device":
        device_id = str(data.get("id") or "").strip()
        if not device_id:
            raise ValueError("device requires an id")
        status = str(data.get("status") or "unknown")
        return cls(
            id=device_id,
            name=str(data.get("name") or ""),
            platform=str(data.get("platform") or ""),
            role=str(data.get("role") or "member"),
            status=status if status in STATUSES else "unknown",
            engine=(str(data["engine"]) if data.get("engine") else None),
            last_seen=str(data.get("last_seen") or ""),
        )

    def is_online(self, *, now: Optional[datetime] = None, threshold_sec: int = ONLINE_THRESHOLD_SEC) -> bool:
        """Whether the device heartbeat is recent and it is not marked offline."""
        if self.status == "offline":
            return False
        seen = _parse(self.last_seen)
        if seen is None:
            return False
        reference = now or datetime.now(timezone.utc)
        return (reference - seen).total_seconds() <= threshold_sec


class DeviceRegistry:
    """Persisted set of devices, keyed by id."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path or os.environ.get("BLACKOUT_DEVICE_FILE") or DEFAULT_DEVICE_FILE)
        self._devices: dict[str, Device] = {}
        self._load()

    # ── persistence ─────────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        items = raw.get("devices", raw) if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                device = Device.from_dict(item)
            except ValueError:
                continue
            self._devices[device.id] = device

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"devices": [d.to_dict() for d in self._devices.values()]}
        descriptor, temporary = tempfile.mkstemp(prefix=".devices-", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            os.replace(temporary, self.path)
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            _log.warning("Could not persist device registry: %s", exc)

    # ── mutation ────────────────────────────────────────────────────────────

    def register(self, device: Device) -> bool:
        """Add or replace a device. Returns ``False`` for a blank id."""
        if not device.id:
            return False
        if not device.last_seen:
            device = Device(**{**device.to_dict(), "last_seen": _utc_now()})
        self._devices[device.id] = device
        self._save()
        return True

    def touch(
        self,
        device_id: str,
        *,
        status: Optional[str] = None,
        engine: Optional[str] = None,
        when: Optional[str] = None,
    ) -> bool:
        """Update a device's heartbeat/status. Returns ``False`` if unknown."""
        device = self._devices.get(str(device_id))
        if device is None:
            return False
        if status is not None:
            device.status = status if status in STATUSES else device.status
        if engine is not None:
            device.engine = engine
        device.last_seen = when or _utc_now()
        self._save()
        return True

    def remove(self, device_id: str) -> bool:
        if str(device_id) in self._devices:
            del self._devices[str(device_id)]
            self._save()
            return True
        return False

    # ── read ────────────────────────────────────────────────────────────────

    def get(self, device_id: str) -> Optional[Device]:
        return self._devices.get(str(device_id))

    def list(self) -> list[Device]:
        return sorted(self._devices.values(), key=lambda d: d.id)

    def dashboard(self, *, threshold_sec: int = ONLINE_THRESHOLD_SEC, now: Optional[datetime] = None) -> dict[str, Any]:
        """Aggregate the fleet: totals, online/offline, and per-status counts."""
        reference = now or datetime.now(timezone.utc)
        by_status = {status: 0 for status in STATUSES}
        devices: list[dict[str, Any]] = []
        online = 0
        for device in self.list():
            is_up = device.is_online(now=reference, threshold_sec=threshold_sec)
            online += 1 if is_up else 0
            by_status[device.status] = by_status.get(device.status, 0) + 1
            devices.append({**device.to_dict(), "online": is_up})
        return {
            "total": len(devices),
            "online": online,
            "offline": len(devices) - online,
            "by_status": by_status,
            "devices": devices,
        }
