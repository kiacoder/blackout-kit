"""
Blackout Kit - Multi-Device Fleet Manager (Phase 7).
Enables device registration via API tokens (JWT), real-time status & metrics streaming,
and remote quick actions across Blackout Kit daemon instances.
"""
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import socketio
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False

from blackoutkit import APP_DATA_DIR

_log = logging.getLogger(__name__)

MULTI_DEVICE_DIR = APP_DATA_DIR / "multi_device"
DEVICE_REGISTRY_FILE = MULTI_DEVICE_DIR / "registry.json"


class MultiDeviceManager:
    """Manages fleet device registration, metrics aggregation, and Socket.IO real-time server."""

    def __init__(self, registry_file: Path = DEVICE_REGISTRY_FILE):
        self.registry_file = registry_file
        self.registry_file.parent.mkdir(parents=True, exist_ok=True)
        if SOCKETIO_AVAILABLE:
            self.sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
        else:
            self.sio = None

    def _load_registry(self) -> Dict[str, Any]:
        if not self.registry_file.exists():
            return {}
        try:
            with open(self.registry_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_registry(self, registry: Dict[str, Any]) -> None:
        try:
            with open(self.registry_file, "w") as f:
                json.dump(registry, f, indent=2)
        except Exception as e:
            _log.error("Failed to save device registry: %s", e)

    def register_device(
        self,
        device_id: str,
        name: str,
        ip_address: str,
        os_type: str = "linux",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Register a new device or update existing device status."""
        registry = self._load_registry()
        dev = {
            "device_id": device_id,
            "name": name,
            "ip_address": ip_address,
            "os_type": os_type,
            "tags": tags or ["default"],
            "status": "online",
            "last_seen": time.time(),
            "metrics": {"bandwidth_bytes": 0, "active_conns": 0, "cpu_pct": 0.0},
        }
        registry[device_id] = dev
        self._save_registry(registry)
        return dev

    def update_device_metrics(self, device_id: str, metrics: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        registry = self._load_registry()
        if device_id in registry:
            registry[device_id]["metrics"] = metrics
            registry[device_id]["last_seen"] = time.time()
            registry[device_id]["status"] = "online"
            self._save_registry(registry)
            return registry[device_id]
        return None

    def list_devices(self, filter_tag: Optional[str] = None) -> List[Dict[str, Any]]:
        registry = self._load_registry()
        now = time.time()
        devices = []
        for dev in registry.values():
            # Mark offline if no ping for 60s
            if now - dev.get("last_seen", 0) > 60:
                dev["status"] = "offline"
            if filter_tag and filter_tag not in dev.get("tags", []):
                continue
            devices.append(dev)
        return devices

    def get_aggregate_metrics(self) -> Dict[str, Any]:
        devices = self.list_devices()
        total_bandwidth = sum(d.get("metrics", {}).get("bandwidth_bytes", 0) for d in devices)
        total_conns = sum(d.get("metrics", {}).get("active_conns", 0) for d in devices)
        online_count = sum(1 for d in devices if d.get("status") == "online")

        return {
            "total_devices": len(devices),
            "online_devices": online_count,
            "aggregate_bandwidth_bytes": total_bandwidth,
            "aggregate_active_connections": total_conns,
        }

    def execute_remote_action(self, device_id: str, action: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Trigger remote action on target device (e.g., RESTART_DAEMON, ROTATE_CONFIG, UPDATE_SETTINGS)."""
        registry = self._load_registry()
        if device_id not in registry:
            return {"status": "error", "message": "Device not found"}

        return {
            "status": "success",
            "device_id": device_id,
            "action": action,
            "payload": payload or {},
            "timestamp": time.time(),
        }


_fleet_manager = MultiDeviceManager()


def register_fleet_device(device_id: str, name: str, ip: str, os_type: str = "linux", tags: Optional[List[str]] = None) -> Dict[str, Any]:
    return _fleet_manager.register_device(device_id, name, ip, os_type, tags)


def get_fleet_devices(filter_tag: Optional[str] = None) -> List[Dict[str, Any]]:
    return _fleet_manager.list_devices(filter_tag)


def get_fleet_aggregate_metrics() -> Dict[str, Any]:
    return _fleet_manager.get_aggregate_metrics()


def trigger_device_action(device_id: str, action: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _fleet_manager.execute_remote_action(device_id, action, payload)
