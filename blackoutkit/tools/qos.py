"""
Blackout Kit - Quality of Service (QoS) / Traffic Shaping.
Define and monitor per-app, per-protocol, and per-interface traffic rules.

Core features:
  - Rule types: app, protocol, port, interface
  - Priority-based rate limiting (0-100 scale)
  - Per-rule throughput monitoring and alerting
  - Active WinDivert packet interception (Phase 2)
  - Real-time stats and violations tracking
"""
import json
import logging
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable
from enum import Enum

_log = logging.getLogger(__name__)

from .. import APP_DATA_DIR

QOS_RULES_FILE = APP_DATA_DIR / "qos_rules.json"
QOS_VIOLATIONS_FILE = APP_DATA_DIR / "qos_violations.jsonl"

# ──────────────────────────── Enums & Constants ──────────────────────────

class RuleType(str, Enum):
    """QoS rule types."""
    APP = "app"
    PROTOCOL = "protocol"
    PORT = "port"
    INTERFACE = "interface"


class EnforcementMode(str, Enum):
    """QoS enforcement modes."""
    OFF = "off"
    MONITOR = "monitor"
    ENFORCE = "enforce"


# ──────────────────────────── Storage & Persistence ──────────────────────────

def _load_rules_unsafe() -> dict:
    """Load QoS rules from JSON (internal, no error handling)."""
    if not QOS_RULES_FILE.exists():
        return {"rules": [], "global_settings": {"qos_enabled": False, "default_priority": 50, "enforcement_mode": "monitor"}}
    return json.loads(QOS_RULES_FILE.read_text())


def load_qos_rules() -> list[dict]:
    """
    Load all QoS rules from storage.
    Returns list of rule dicts with: id, name, type, target, priority, rate_limit_kbps, burst_kb, enabled, created.
    """
    try:
        data = _load_rules_unsafe()
        return data.get("rules", [])
    except Exception:
        return []


def save_qos_rules(rules: list[dict], settings: Optional[dict] = None) -> None:
    """
    Atomically save QoS rules to JSON.
    Settings dict includes: qos_enabled, default_priority, enforcement_mode.
    """
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "rules": rules,
        "global_settings": settings or {"qos_enabled": False, "default_priority": 50, "enforcement_mode": "monitor"},
    }

    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=APP_DATA_DIR, text=True)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, QOS_RULES_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
            raise
    except Exception:
        pass


def _get_global_settings() -> dict:
    """Get global QoS settings."""
    try:
        data = _load_rules_unsafe()
        return data.get("global_settings", {"qos_enabled": False, "default_priority": 50, "enforcement_mode": "monitor"})
    except Exception:
        return {"qos_enabled": False, "default_priority": 50, "enforcement_mode": "monitor"}


# ──────────────────────────── Rule Management ──────────────────────────

def add_rule(
    name: str,
    rule_type: str,
    target: str,
    priority: int = 50,
    rate_limit_kbps: int = 0,
    burst_kb: int = 512,
    port_filter: Optional[str] = None,
    interface: Optional[str] = None,
) -> str:
    """
    Add a new QoS rule.
    Returns the rule ID.

    Args:
        name: Human-readable rule name
        rule_type: "app", "protocol", "port", or "interface"
        target: Process name (app), protocol (TCP/UDP), port list, or interface name
        priority: 0-100 (0=lowest, 100=highest)
        rate_limit_kbps: 0 = no limit, >0 = throttle to this rate
        burst_kb: Burst size for token bucket
        port_filter: Comma-separated port list (for port type)
        interface: Interface scope (eth0, wlan0, etc.)
    """
    rules = load_qos_rules()
    settings = _get_global_settings()

    rule_id = f"rule_{uuid.uuid4().hex[:12]}"

    rule = {
        "id": rule_id,
        "name": name,
        "type": rule_type,
        "target": target,
        "priority": max(0, min(100, priority)),
        "rate_limit_kbps": max(0, rate_limit_kbps),
        "burst_kb": max(1, burst_kb),
        "enabled": True,
        "created": datetime.now(timezone.utc).isoformat(),
    }

    if port_filter:
        rule["port_filter"] = port_filter
    if interface:
        rule["interface"] = interface

    rules.append(rule)
    save_qos_rules(rules, settings)

    return rule_id


def remove_rule(rule_id: str) -> bool:
    """Remove a QoS rule by ID. Returns True if found and removed."""
    rules = load_qos_rules()
    settings = _get_global_settings()

    original_len = len(rules)
    rules = [r for r in rules if r.get("id") != rule_id]

    if len(rules) < original_len:
        save_qos_rules(rules, settings)
        return True

    return False


def get_rule(rule_id: str) -> Optional[dict]:
    """Get a rule by ID."""
    rules = load_qos_rules()
    for rule in rules:
        if rule.get("id") == rule_id:
            return rule
    return None


def enable_rule(rule_id: str) -> bool:
    """Enable a rule by ID."""
    rules = load_qos_rules()
    settings = _get_global_settings()

    for rule in rules:
        if rule.get("id") == rule_id:
            rule["enabled"] = True
            save_qos_rules(rules, settings)
            return True

    return False


def disable_rule(rule_id: str) -> bool:
    """Disable a rule by ID."""
    rules = load_qos_rules()
    settings = _get_global_settings()

    for rule in rules:
        if rule.get("id") == rule_id:
            rule["enabled"] = False
            save_qos_rules(rules, settings)
            return True

    return False


def list_rules() -> list[dict]:
    """Get all rules, sorted by priority (highest first)."""
    rules = load_qos_rules()
    return sorted(rules, key=lambda r: r.get("priority", 50), reverse=True)


# ──────────────────────────── Rule Matching & Stats ──────────────────────────

def match_connection_to_rules(connection: dict) -> list[dict]:
    """
    Match a connection dict to applicable QoS rules.
    Connection should have: pid, process, protocol, local_addr, local_port, remote_addr, remote_port.
    Returns list of matching rules (highest priority first).
    """
    rules = load_qos_rules()
    matching = []

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rule_type = rule.get("type", "")

        # Match app rules by process name
        if rule_type == "app":
            if connection.get("process", "").lower() == rule.get("target", "").lower():
                matching.append(rule)

        # Match protocol rules
        elif rule_type == "protocol":
            proto = rule.get("target", "").upper()
            if connection.get("protocol", "").upper() == proto:
                # If port_filter exists, also check ports
                if "port_filter" in rule:
                    try:
                        ports = [int(p.strip()) for p in rule["port_filter"].split(",")]
                        conn_port = connection.get("local_port", 0) or connection.get("remote_port", 0)
                        if conn_port in ports:
                            matching.append(rule)
                    except ValueError:
                        matching.append(rule)  # Malformed port filter, match anyway
                else:
                    matching.append(rule)

        # Match port rules
        elif rule_type == "port":
            try:
                ports = [int(p.strip()) for p in rule.get("target", "").split(",")]
                conn_port = connection.get("local_port", 0) or connection.get("remote_port", 0)
                if conn_port in ports:
                    matching.append(rule)
            except ValueError:
                pass

        # Match interface rules
        elif rule_type == "interface":
            if connection.get("interface") == rule.get("target"):
                matching.append(rule)

    # Sort by priority (highest first)
    return sorted(matching, key=lambda r: r.get("priority", 50), reverse=True)


def _track_rule_throughput() -> dict:
    """
    Internal state for per-rule throughput tracking.
    Tracks per-rule (in_bytes, out_bytes, last_update_ts).
    """
    return {}


_rule_throughput_state = _track_rule_throughput()
_rule_throughput_lock = __import__('threading').Lock()


def calculate_rule_throughput(rule_id: str, since_ts: Optional[float] = None) -> tuple[float, float, bool]:
    """
    Calculate real-time throughput for a rule.
    Returns: (rx_kbps, tx_kbps, over_limit)

    This is a placeholder that uses stored state.
    In production, this would integrate with WinDivert counters or traffic logs.
    """
    global _rule_throughput_state

    rule = get_rule(rule_id)
    if not rule:
        return 0.0, 0.0, False

    rate_limit = rule.get("rate_limit_kbps", 0)

    with _rule_throughput_lock:
        state = _rule_throughput_state.get(rule_id, {"rx": 0, "tx": 0, "ts": time.time()})

    # In a real implementation, this would query WinDivert or read from traffic logs
    # For now, return zero throughput
    rx_kbps = 0.0
    tx_kbps = 0.0
    over_limit = (rx_kbps + tx_kbps) > rate_limit if rate_limit > 0 else False

    return rx_kbps, tx_kbps, over_limit


def compile_qos_rules_for_shaper() -> list[dict]:
    """
    Compile QoS rules into a format suitable for WinDivert packet filtering.
    Returns list of compiled rules with: id, priority, filter_expr, rate_limit_kbps, burst_kb.

    Filter expressions are simplified; actual WinDivert expressions would be more complex.
    """
    rules = list_rules()
    compiled = []

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rule_type = rule.get("type", "")
        target = rule.get("target", "")

        # Build simplified filter expression
        filter_expr = ""

        if rule_type == "app":
            # WinDivert filter: match packets by process ID
            # In actual impl: Packet.ProcessId == {resolved_pid}
            filter_expr = f"app:{target}"

        elif rule_type == "protocol":
            # Match by protocol
            proto_upper = target.upper()
            if proto_upper == "TCP":
                filter_expr = "tcp"
            elif proto_upper == "UDP":
                filter_expr = "udp"
            elif proto_upper == "ICMP":
                filter_expr = "icmp"

            # Add port filter if present
            if "port_filter" in rule:
                filter_expr += f" port:{rule['port_filter']}"

        elif rule_type == "port":
            filter_expr = f"port:{target}"

        elif rule_type == "interface":
            filter_expr = f"ifidx:{target}"

        compiled.append({
            "id": rule.get("id"),
            "priority": rule.get("priority", 50),
            "filter_expr": filter_expr,
            "rate_limit_kbps": rule.get("rate_limit_kbps", 0),
            "burst_kb": rule.get("burst_kb", 512),
        })

    return compiled


def get_qos_stats(rule_id: Optional[str] = None) -> dict:
    """
    Get QoS statistics and status.
    If rule_id is specified, return stats for that rule only.
    Returns dict with: total_rules, enabled_rules, enforcement_mode, per_rule_stats[].
    """
    rules = load_qos_rules()
    settings = _get_global_settings()

    if rule_id:
        # Stats for single rule
        rule = get_rule(rule_id)
        if not rule:
            return {"error": "Rule not found"}

        rx_kbps, tx_kbps, over_limit = calculate_rule_throughput(rule_id)

        return {
            "rule_id": rule_id,
            "name": rule.get("name"),
            "type": rule.get("type"),
            "priority": rule.get("priority"),
            "rate_limit_kbps": rule.get("rate_limit_kbps"),
            "enabled": rule.get("enabled", True),
            "current_rx_kbps": rx_kbps,
            "current_tx_kbps": tx_kbps,
            "over_limit": over_limit,
        }
    else:
        # Aggregate stats
        enabled_rules = [r for r in rules if r.get("enabled", True)]
        per_rule = []

        for rule in rules:
            rx_kbps, tx_kbps, over_limit = calculate_rule_throughput(rule.get("id"))
            per_rule.append({
                "id": rule.get("id"),
                "name": rule.get("name"),
                "priority": rule.get("priority"),
                "rx_kbps": rx_kbps,
                "tx_kbps": tx_kbps,
                "over_limit": over_limit,
            })

        return {
            "total_rules": len(rules),
            "enabled_rules": len(enabled_rules),
            "enforcement_mode": settings.get("enforcement_mode", "monitor"),
            "per_rule_stats": per_rule,
        }


# ──────────────────────────── Violations & Logging ──────────────────────────

def log_violation(rule_id: str, violation_type: str, details: str) -> None:
    """
    Log a QoS violation (e.g., rate limit exceeded).
    Atomically appends to JSONL violations log.
    """
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    entry = {
        "ts": time.time(),
        "rule_id": rule_id,
        "violation_type": violation_type,
        "details": details,
    }

    entry_json = json.dumps(entry, separators=(',', ':'))

    try:
        with open(QOS_VIOLATIONS_FILE, 'a') as f:
            f.write(entry_json + '\n')
    except Exception:
        pass


def get_violations(since_ts: Optional[float] = None, limit: int = 100) -> list[dict]:
    """
    Load QoS violations from JSONL log.
    Returns list of violation dicts, newest first.
    """
    if not QOS_VIOLATIONS_FILE.exists():
        return []

    entries = []

    try:
        with open(QOS_VIOLATIONS_FILE, 'r') as f:
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

        entries.sort(key=lambda e: e.get('ts', 0), reverse=True)

        if limit:
            entries = entries[:limit]

        return entries
    except Exception:
        return []


# ──────────────────────────── Settings Management ──────────────────────────

def set_global_qos_enabled(enabled: bool) -> None:
    """Enable or disable QoS globally."""
    rules = load_qos_rules()
    settings = _get_global_settings()
    settings["qos_enabled"] = enabled
    save_qos_rules(rules, settings)


def set_enforcement_mode(mode: str) -> bool:
    """Set enforcement mode: 'off', 'monitor', or 'enforce'. Returns True if valid."""
    if mode not in ["off", "monitor", "enforce"]:
        return False

    rules = load_qos_rules()
    settings = _get_global_settings()
    settings["enforcement_mode"] = mode
    save_qos_rules(rules, settings)

    return True


def get_enforcement_mode() -> str:
    """Get current enforcement mode."""
    settings = _get_global_settings()
    return settings.get("enforcement_mode", "monitor")
