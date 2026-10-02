"""
Blackout Kit - Deterministic operator recommendation layer (Blackout Operator foundation).

Turns local snapshot evidence into structured, ranked recommendations. This is
deliberately NOT an embedded AI model: every rule is deterministic, auditable
code. External AI systems consume these recommendations (CLI, MCP) and decide;
Blackout Kit itself never silently executes DISRUPTIVE or DESTRUCTIVE actions
because a client asked vaguely.

Action safety classes, from least to most invasive:

- READ_ONLY: inspects state, changes nothing
- SAFE_REVERSIBLE: local, easily undone by Blackout-owned commands
- PRIVILEGED_REVERSIBLE: needs elevation; undoable, scoped
- DISRUPTIVE: interrupts connectivity or resets scoped state; explicit confirmation required
- DESTRUCTIVE: broad reset with data loss potential; never suggested silently
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

READ_ONLY = "READ_ONLY"
SAFE_REVERSIBLE = "SAFE_REVERSIBLE"
PRIVILEGED_REVERSIBLE = "PRIVILEGED_REVERSIBLE"
DISRUPTIVE = "DISRUPTIVE"
DESTRUCTIVE = "DESTRUCTIVE"

SAFETY_LEVELS: tuple[str, ...] = (
    READ_ONLY,
    SAFE_REVERSIBLE,
    PRIVILEGED_REVERSIBLE,
    DISRUPTIVE,
    DESTRUCTIVE,
)

_RISK_BY_SAFETY = {
    READ_ONLY: "none",
    SAFE_REVERSIBLE: "low",
    PRIVILEGED_REVERSIBLE: "medium",
    DISRUPTIVE: "high",
    DESTRUCTIVE: "high",
}


@dataclass(frozen=True)
class ActionSpec:
    """Static safety contract for one recommended action."""

    name: str
    safety: str
    requires_admin: bool = False
    requires_confirmation: bool = False
    description: str = ""


ACTION_CATALOG: dict[str, ActionSpec] = {
    spec.name: spec
    for spec in (
        ActionSpec("monitor", READ_ONLY, description="Keep observing; no action needed"),
        ActionSpec("run_readiness", READ_ONLY, description="Run `blackout ready <engine>` for a full local checklist"),
        ActionSpec("run_doctor", READ_ONLY, description="Run `blackout doctor --local-only` diagnostics"),
        ActionSpec("retry_engine", SAFE_REVERSIBLE, requires_confirmation=True,
                   description="Start the last-used engine again"),
        ActionSpec("connect_engine", SAFE_REVERSIBLE, requires_confirmation=True,
                   description="Start an explicitly selected ready engine"),
        ActionSpec("reconnect_engine", SAFE_REVERSIBLE, requires_confirmation=True,
                   description="Stop and start the current engine through Blackout-owned commands"),
        ActionSpec("flush_dns", PRIVILEGED_REVERSIBLE, requires_admin=True, requires_confirmation=True,
                   description="Flush the OS DNS cache"),
        ActionSpec("clear_blackout_state", PRIVILEGED_REVERSIBLE, requires_admin=True, requires_confirmation=True,
                   description="Run `blackout fix`: targeted cleanup of Blackout-owned or stale Blackout state only"),
        ActionSpec("broad_network_reset", DISRUPTIVE, requires_admin=True, requires_confirmation=True,
                   description="Windows-only broad reset (winsock/DNS/IP); never run without explicit human approval"),
    )
}


@dataclass(frozen=True)
class Recommendation:
    """One deterministic recommendation derived from local evidence."""

    problem: str
    recommended_action: str
    confidence: float
    reason: str
    safety: str
    risk: str
    requires_admin: bool
    requires_confirmation: bool
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "problem": self.problem,
            "recommended_action": self.recommended_action,
            "confidence": round(self.confidence, 2),
            "reason": self.reason,
            "risk": self.risk,
            "requires_admin": self.requires_admin,
            "requires_confirmation": self.requires_confirmation,
            "safety": self.safety,
            "params": dict(self.params),
        }


def _spec(name: str) -> ActionSpec:
    return ACTION_CATALOG[name]


def _recommendation(problem: str, action: str, confidence: float, reason: str, **params: Any) -> Recommendation:
    spec = _spec(action)
    return Recommendation(
        problem=problem,
        recommended_action=action,
        confidence=confidence,
        reason=reason,
        safety=spec.safety,
        risk=_RISK_BY_SAFETY[spec.safety],
        requires_admin=spec.requires_admin,
        requires_confirmation=spec.requires_confirmation,
        params=dict(params),
    )


def recommendations_from_snapshot(snapshot: dict[str, Any]) -> list[Recommendation]:
    """Derive ranked recommendations from a canonical snapshot. Pure function."""
    results: list[Recommendation] = []

    vault_info = snapshot.get("vault") or {}
    if isinstance(vault_info, dict) and vault_info.get("active") and not vault_info.get("healthy"):
        results.append(_recommendation(
            "encrypted_storage_unreadable",
            "run_doctor",
            0.92,
            f"Vault is present but unreadable: {vault_info.get('detail', 'authentication failed')}",
        ))

    engines = snapshot.get("engines") or {}
    ready_engines = engines.get("ready") if isinstance(engines, dict) else None
    ready_engines = ready_engines or []
    recommended = (engines.get("recommended") or {}).get("engine") if isinstance(engines, dict) else None

    daemon_info = snapshot.get("daemon") or {}
    daemon_running = bool(daemon_info.get("running")) if isinstance(daemon_info, dict) else False
    last_failure = daemon_info.get("last_failure") if isinstance(daemon_info, dict) else None
    failed_engine = None
    if isinstance(last_failure, dict):
        failed_engine = last_failure.get("engine")
    elif isinstance(last_failure, str) and last_failure:
        failed_engine = last_failure

    if not ready_engines:
        results.append(_recommendation(
            "no_ready_engine",
            "run_doctor",
            0.85,
            "No locally ready engine; run diagnostics to identify missing runtimes or configuration",
        ))

    if not daemon_running and failed_engine:
        if recommended and recommended != failed_engine:
            results.append(_recommendation(
                "engine_recently_failed",
                "connect_engine",
                0.78,
                f"Engine '{failed_engine}' failed previously and '{recommended}' is locally ready",
                engine=recommended,
            ))
        else:
            results.append(_recommendation(
                "engine_recently_failed",
                "retry_engine",
                0.7,
                f"Engine '{failed_engine}' reported a failure and is not running",
                engine=failed_engine,
            ))

    recovery_hint = snapshot.get("recovery_hint") or {}
    if isinstance(recovery_hint, dict) and recovery_hint.get("needed"):
        results.append(_recommendation(
            "stale_blackout_state",
            "clear_blackout_state",
            0.8,
            "; ".join(recovery_hint.get("reasons") or []) or "stale Blackout-owned state detected",
        ))

    if daemon_running:
        status = str(daemon_info.get("status", "")).lower()
        if status in {"degraded", "reconnecting", "unhealthy"}:
            results.append(_recommendation(
                "connection_degraded",
                "reconnect_engine",
                0.66,
                f"Daemon reports '{status}' for engine '{daemon_info.get('engine')}'",
                engine=daemon_info.get("engine"),
            ))

    if not results:
        results.append(_recommendation(
            "no_problem_detected",
            "monitor",
            1.0,
            "Local state is consistent; continue observing",
        ))

    return results


def build_recommendations(*, include_adapters: bool = False) -> dict[str, Any]:
    """Build a sanitized snapshot and its recommendations in one operator payload."""
    from .snapshot import sanitized_snapshot

    snapshot = sanitized_snapshot(include_adapters=include_adapters)
    recommendations = recommendations_from_snapshot(snapshot)
    return {
        "snapshot": snapshot,
        "recommendations": [item.to_dict() for item in recommendations],
        "safety_levels": list(SAFETY_LEVELS),
        "note": (
            "Recommendations are deterministic local analysis, not an AI model. "
            "Blackout Kit never executes DISRUPTIVE or DESTRUCTIVE actions without "
            "explicit human confirmation. Local readiness is not remote success."
        ),
    }


def action_catalog_payload() -> dict[str, Any]:
    """Documented action safety catalog for external consumers."""
    return {
        "actions": [
            {
                "name": spec.name,
                "safety": spec.safety,
                "requires_admin": spec.requires_admin,
                "requires_confirmation": spec.requires_confirmation,
                "description": spec.description,
            }
            for spec in ACTION_CATALOG.values()
        ],
        "safety_levels": list(SAFETY_LEVELS),
    }


__all__ = [
    "ACTION_CATALOG",
    "ActionSpec",
    "DESTRUCTIVE",
    "DISRUPTIVE",
    "PRIVILEGED_REVERSIBLE",
    "READ_ONLY",
    "SAFE_REVERSIBLE",
    "SAFETY_LEVELS",
    "Recommendation",
    "action_catalog_payload",
    "build_recommendations",
    "recommendations_from_snapshot",
]
