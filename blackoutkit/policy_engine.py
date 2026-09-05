"""
Blackout Kit - Centralized Policy & Automation Engine (Phase 7).
Handles configuration versioning, admin locked settings enforcement,
fleet-wide policy distribution, and automation rules.
"""
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from blackoutkit import APP_DATA_DIR

_log = logging.getLogger(__name__)

POLICY_DIR = APP_DATA_DIR / "policies"
CONFIG_VERSIONS_FILE = POLICY_DIR / "config_versions.json"
LOCKED_SETTINGS_FILE = POLICY_DIR / "locked_settings.json"
AUTOMATION_RULES_FILE = POLICY_DIR / "automation_rules.json"


class PolicyEngine:
    """Manages fleet policies, configuration versions, locked settings, and automation rules."""

    def __init__(self, policy_dir: Path = POLICY_DIR):
        self.policy_dir = policy_dir
        self.config_versions_file = policy_dir / "config_versions.json"
        self.locked_settings_file = policy_dir / "locked_settings.json"
        self.automation_rules_file = policy_dir / "automation_rules.json"
        self.policy_dir.mkdir(parents=True, exist_ok=True)

    def _read_json(self, path: Path, default: Any) -> Any:
        if not path.exists():
            return default
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception:
            return default

    def _write_json(self, path: Path, data: Any) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            _log.error("Failed writing JSON to %s: %s", path, e)

    # 1. Config Versioning & Distribution
    def publish_config_version(self, version: str, config: Dict[str, Any], author: str = "admin") -> Dict[str, Any]:
        versions = self._read_json(self.config_versions_file, [])
        entry = {
            "version": version,
            "timestamp": time.time(),
            "author": author,
            "config": config,
        }
        versions.append(entry)
        self._write_json(self.config_versions_file, versions)
        return entry

    def get_latest_config(self) -> Optional[Dict[str, Any]]:
        versions = self._read_json(self.config_versions_file, [])
        if not versions:
            return None
        return sorted(versions, key=lambda v: v.get("timestamp", 0))[-1]

    def rollback_config(self, target_version: str) -> Optional[Dict[str, Any]]:
        versions = self._read_json(self.config_versions_file, [])
        for v in versions:
            if v["version"] == target_version:
                return self.publish_config_version(
                    version=f"{target_version}-rollback",
                    config=v["config"],
                    author="rollback-system",
                )
        return None

    # 2. Locked Admin Settings
    def set_locked_settings(self, locked_dict: Dict[str, Any]) -> Dict[str, Any]:
        self._write_json(self.locked_settings_file, locked_dict)
        return locked_dict

    def get_locked_settings(self) -> Dict[str, Any]:
        return self._read_json(self.locked_settings_file, {})

    def enforce_locked_settings(self, user_config: Dict[str, Any]) -> Dict[str, Any]:
        """Override user configuration settings with admin locked values."""
        locked = self.get_locked_settings()
        merged = dict(user_config)
        merged.update(locked)
        return merged

    # 3. Automation Rules
    def add_automation_rule(self, rule_id: str, trigger: str, action: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        rules = self._read_json(self.automation_rules_file, [])
        rule = {
            "rule_id": rule_id,
            "trigger": trigger,
            "action": action,
            "params": params or {},
            "enabled": True,
        }
        # Replace if existing
        rules = [r for r in rules if r["rule_id"] != rule_id]
        rules.append(rule)
        self._write_json(self.automation_rules_file, rules)
        return rule

    def list_automation_rules(self) -> List[Dict[str, Any]]:
        return self._read_json(self.automation_rules_file, [])


_policy_engine = PolicyEngine()


def publish_policy_version(version: str, config: Dict[str, Any], author: str = "admin") -> Dict[str, Any]:
    return _policy_engine.publish_config_version(version, config, author)


def get_active_policy_config() -> Optional[Dict[str, Any]]:
    return _policy_engine.get_latest_config()


def lock_policy_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    return _policy_engine.set_locked_settings(settings)


def apply_locked_policy_overrides(config: Dict[str, Any]) -> Dict[str, Any]:
    return _policy_engine.enforce_locked_settings(config)


def create_automation_rule(rule_id: str, trigger: str, action: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _policy_engine.add_automation_rule(rule_id, trigger, action, params)
