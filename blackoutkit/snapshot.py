"""
Blackout Kit - Canonical local network snapshot (Blackout Operator foundation).

`build_snapshot()` assembles one structured view of everything Blackout Kit
can locally observe: daemon, system proxy, vault health, per-engine readiness
summary, stability history, recent events, and recovery hints.

Hard honesty rules (project trust boundary):

- A snapshot describes LOCAL state only. It never proves that an upstream
  server is reachable or that censorship is bypassed.
- Sections are independent: one failing section degrades to an error entry
  instead of breaking the whole snapshot.
- Details are sanitized through the event sanitizer before leaving the
  process, so secrets never reach JSON consumers.
"""
from __future__ import annotations

import platform as platform_module
import sys
from datetime import datetime, timezone
from typing import Any

from . import country_profiles, daemon, proxy_manager, routing, security, settings as cfg, vault
from .connection_service import admin_default
from .events import merged_recent_events, sanitize_value

SCHEMA_VERSION = 1

_REMOTE_VALIDATION_NOTE = (
    "This snapshot describes local state only. It does not test upstream "
    "reachability and does not prove that censorship is bypassed."
)

_FAILURE_EVENT_PREFIXES = ("engine.failed", "connection.lost", "recovery.failed", "doctor.problem_detected")


def _section(builder):
    """Run one section builder; degrade to an error entry on failure."""
    try:
        return builder()
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def _vault_section() -> dict[str, Any]:
    state = vault.vault_status()
    return {
        "active": bool(state.get("active")),
        "healthy": bool(state.get("healthy")),
        "detail": str(state.get("detail", "")),
    }


def _daemon_section() -> dict[str, Any]:
    pid = daemon.get_pid()
    state = daemon.get_state() or {}
    return {
        "running": pid is not None,
        "pid": pid,
        "engine": state.get("engine", "none"),
        "status": state.get("status", "idle" if pid is None else "unknown"),
        "restarts": state.get("restarts", 0),
        "last_failure": state.get("last_failure"),
        "next_retry_delay": state.get("next_retry_delay"),
    }


def _system_proxy_section() -> dict[str, Any]:
    status = proxy_manager.get_proxy_status()
    ownership = proxy_manager.proxy_ownership_status()
    return {
        "enabled": bool(status.get("enabled")),
        "server": status.get("server") if status.get("enabled") else None,
        "blackout_owned": ownership is not None,
    }


def _country_section() -> dict[str, Any]:
    pinned_code = str(cfg.load().get("country", "") or "")
    profile = country_profiles.get_profile(pinned_code) if pinned_code else None
    return {
        "pinned_code": pinned_code or None,
        "code": profile.code if profile else None,
        "name": profile.name if profile else None,
        "level": profile.level if profile else None,
        "detection": "pinned" if profile else "auto (not resolved offline)",
    }


def _stability_scores() -> dict[str, dict[str, Any]]:
    scores: dict[str, dict[str, Any]] = {}
    for engine in routing.FOUNDATION_ENGINE_NAMES:
        try:
            score = security.get_stability_score(engine)
        except Exception:
            score = {}
        if score:
            scores[engine] = score
    return scores


def _engines_section() -> dict[str, Any]:
    values = cfg.load()
    try:
        from .downloader import check_installed

        installed = check_installed()
    except Exception:
        installed = {}
    try:
        from .config.manager import load_configs

        configs = load_configs()
        vault_error = None
    except vault.VaultError as exc:
        configs = None
        vault_error = str(exc)
    except Exception as exc:
        configs = None
        vault_error = str(exc)

    candidates = routing.recommend_routes(
        values,
        installed=installed,
        configs=configs,
        stability_scores=_stability_scores(),
        platform=sys.platform,
    )
    engines = {
        candidate.engine: {
            "ready": candidate.ready,
            "score": candidate.score,
            "evidence": candidate.evidence,
            "blockers": list(candidate.blockers),
        }
        for candidate in candidates
    }
    top = candidates[0] if candidates else None
    ready_engines = [candidate.engine for candidate in candidates if candidate.ready]
    return {
        "available": engines,
        "ready": ready_engines,
        "recommended": {
            "engine": top.engine if top else None,
            "score": top.score if top else None,
            "evidence": top.evidence if top else None,
        } if top else None,
        "vault_error": vault_error,
        "note": "Local readiness only; a ready engine is not a working route.",
    }


def _events_section() -> dict[str, Any]:
    recent = merged_recent_events(limit=10)
    failures = [
        event for event in recent
        if any(event["type"].startswith(prefix) for prefix in _FAILURE_EVENT_PREFIXES)
    ]
    return {
        "recent": recent,
        "recent_failures": failures[-5:],
    }


def _recovery_hint_section(daemon_info: dict[str, Any]) -> dict[str, Any]:
    hints: list[str] = []
    if daemon_info.get("running") is False and daemon_info.get("last_failure"):
        hints.append("daemon reported a failure and is not running")
    try:
        ownership = proxy_manager.proxy_ownership_status()
    except Exception:
        ownership = None
    if ownership is not None and not daemon_info.get("running"):
        hints.append("Blackout-managed system proxy state exists without a running daemon")
    return {
        "needed": bool(hints),
        "reasons": hints,
        "note": "Targeted recovery via `blackout fix`; broader resets require explicit confirmation.",
    }


def _dns_section() -> dict[str, Any]:
    values = cfg.load()
    return {
        "doh_over_xray": bool(values.get("xray_doh_dns", False)),
        "note": "Snapshot reads saved settings only; live resolver probing is a separate tool.",
    }


def _adapters_section() -> dict[str, Any]:
    adapters: dict[str, Any] = {}
    try:
        import psutil

        stats = psutil.net_if_stats()
        for name, stat in stats.items():
            adapters[name] = {
                "up": bool(stat.isup),
                "speed_mbps": getattr(stat, "speed", None),
            }
    except Exception as exc:
        return {"error": f"adapter enumeration unavailable: {type(exc).__name__}"}
    return {"adapters": adapters}


def _is_admin() -> bool:
    try:
        return bool(admin_default())
    except Exception:
        return False


def build_snapshot(*, include_adapters: bool = True) -> dict[str, Any]:
    """Assemble the canonical local snapshot. Never raises."""
    daemon_info = _section(_daemon_section)
    snapshot: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "blackout-kit",
        "platform": {
            "system": sys.platform,
            "release": platform_module.release(),
            "machine": platform_module.machine(),
            "python": platform_module.python_version(),
        },
        "privileges": {"admin": _is_admin()},
        "vault": _section(_vault_section),
        "daemon": daemon_info,
        "system_proxy": _section(_system_proxy_section),
        "country": _section(_country_section),
        "engines": _section(_engines_section),
        "connection_health": {
            "daemon_running": bool(daemon_info.get("running")) if isinstance(daemon_info, dict) and "error" not in daemon_info else False,
            "engine": daemon_info.get("engine") if isinstance(daemon_info, dict) else None,
            "scope": "local indicators only",
        },
        "dns": _section(_dns_section),
        "events": _section(_events_section),
        "recovery_hint": _section(lambda: _recovery_hint_section(daemon_info if isinstance(daemon_info, dict) else {})),
        "scope": {
            "local_state_only": True,
            "remote_validation_performed": False,
            "note": _REMOTE_VALIDATION_NOTE,
        },
    }
    if include_adapters:
        snapshot["adapters"] = _section(_adapters_section)
    return snapshot


def sanitized_snapshot(*, include_adapters: bool = True) -> dict[str, Any]:
    """Snapshot with all string values passed through the event sanitizer."""
    return sanitize_value(build_snapshot(include_adapters=include_adapters))


__all__ = [
    "SCHEMA_VERSION",
    "build_snapshot",
    "sanitized_snapshot",
]
