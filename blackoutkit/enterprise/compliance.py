"""Compliance checks — GDPR / HIPAA / SOC 2 (Roadmap Phase 7).

Turns the effective settings (and access policy) into an auditable checklist:
each :class:`Check` says whether a control is satisfied, why, and how to fix it.
This is **technical evidence, not a certification** — the same honesty the
report exporter already states.

Note the built-in tension: GDPR favours *data minimization* (logging off) while
HIPAA wants *audit controls* (logging on). The checks surface that explicitly
rather than pretending one setting satisfies both.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional

from .policy import Policy

FRAMEWORKS = ("gdpr", "hipaa", "soc2")

__all__ = ["Check", "FRAMEWORKS", "checks_for", "evaluate", "evaluate_all"]


@dataclass(frozen=True)
class Check:
    """One compliance control's result."""

    id: str
    framework: str
    title: str
    ok: bool
    detail: str
    remediation: str = ""


def _effective_settings(settings: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    if settings is not None:
        return dict(settings)
    from .. import settings as cfg

    return cfg.load()


def _rbac_configured(policy: Optional[Policy]) -> bool:
    return bool(policy and policy.principals)


# ── per-framework checks ─────────────────────────────────────────────────────

def _gdpr(s: dict[str, Any], policy: Optional[Policy]) -> list[Check]:
    logging_on = bool(s.get("traffic_logging_enabled", False))
    retention = int(s.get("traffic_log_retention_days", 0) or 0)
    query_log = bool(s.get("adblock_query_log_enabled", False))
    vault = bool(s.get("secrets_vault_enabled", False))
    doh = bool(s.get("xray_doh_dns", False))
    disclaimer = bool(s.get("show_disclaimer", False))
    return [
        Check("data-minimization", "gdpr", "Data minimization",
              not logging_on,
              "Per-connection audit logging is disabled." if not logging_on
              else "Per-connection audit logging is enabled.",
              "Disable `traffic_logging_enabled` unless a lawful basis requires it."),
        Check("storage-limitation", "gdpr", "Storage limitation",
              not logging_on or 0 < retention <= 90,
              f"Traffic log retention is {retention} day(s).",
              "Keep `traffic_log_retention_days` at or below 90."),
        Check("purpose-limitation", "gdpr", "Purpose limitation",
              not query_log,
              "DNS query logging is disabled." if not query_log else "DNS query logging is enabled.",
              "Disable `adblock_query_log_enabled`."),
        Check("encryption-at-rest", "gdpr", "Encryption at rest",
              vault,
              "Secrets vault is enabled." if vault else "Secrets are stored unencrypted.",
              "Enable `secrets_vault_enabled`."),
        Check("transmission-security", "gdpr", "Integrity of transmission",
              doh,
              "Encrypted DNS (DoH) is enabled." if doh else "DNS is not encrypted.",
              "Enable `xray_doh_dns`."),
        Check("transparency", "gdpr", "Transparency",
              disclaimer,
              "The legal disclaimer is shown." if disclaimer else "The disclaimer is hidden.",
              "Enable `show_disclaimer`."),
    ]


def _hipaa(s: dict[str, Any], policy: Optional[Policy]) -> list[Check]:
    logging_on = bool(s.get("traffic_logging_enabled", False))
    vault = bool(s.get("secrets_vault_enabled", False))
    doh = bool(s.get("xray_doh_dns", False))
    insecure_tls = bool(s.get("tls_allow_insecure", False))
    rbac = _rbac_configured(policy)
    return [
        Check("access-control", "hipaa", "Access control",
              rbac,
              "An access policy with principals is configured." if rbac
              else "No access policy/principals are configured.",
              "Author a policy with roles and principals (`blackout enterprise policy`)."),
        Check("audit-controls", "hipaa", "Audit controls",
              logging_on,
              "Connection activity is recorded." if logging_on
              else "No connection audit trail is recorded.",
              "Enable `traffic_logging_enabled` (note: this conflicts with GDPR data minimization)."),
        Check("transmission-security", "hipaa", "Transmission security",
              doh and not insecure_tls,
              "Encrypted DNS on; insecure TLS not permitted."
              if (doh and not insecure_tls) else "DNS encryption and/or TLS policy is weak.",
              "Enable `xray_doh_dns` and disable `tls_allow_insecure`."),
        Check("person-authentication", "hipaa", "Person/entity authentication",
              vault,
              "The secrets vault is enabled." if vault else "Secrets are not protected at rest.",
              "Enable `secrets_vault_enabled`."),
    ]


def _soc2(s: dict[str, Any], policy: Optional[Policy]) -> list[Check]:
    vault = bool(s.get("secrets_vault_enabled", False))
    monitor = bool(s.get("security_monitor_enabled", False))
    rbac = _rbac_configured(policy)
    plugins = bool(s.get("plugins_enabled", False))
    return [
        Check("access-control", "soc2", "Logical access",
              rbac,
              "Access policy configured." if rbac else "No access policy configured.",
              "Author a policy with roles and principals."),
        Check("encryption", "soc2", "Encryption",
              vault,
              "Secrets vault enabled." if vault else "Secrets stored in the clear.",
              "Enable `secrets_vault_enabled`."),
        Check("monitoring", "soc2", "Monitoring",
              monitor,
              "Live security monitoring is enabled." if monitor else "Live security monitoring is off.",
              "Enable `security_monitor_enabled`."),
        Check("attack-surface", "soc2", "Change/attack-surface management",
              not plugins,
              "Plugins are disabled." if not plugins else "Third-party plugins are enabled.",
              "Disable `plugins_enabled` unless plugins are reviewed and trusted."),
    ]


_BUILDERS = {"gdpr": _gdpr, "hipaa": _hipaa, "soc2": _soc2}


def checks_for(framework: str, *, settings: Optional[Mapping[str, Any]] = None, policy: Optional[Policy] = None) -> list[Check]:
    """Return the checks for one framework. Raises ``ValueError`` if unknown."""
    key = str(framework).lower().strip()
    if key not in _BUILDERS:
        raise ValueError(f"Unsupported framework: {framework}. Choose from: {', '.join(FRAMEWORKS)}")
    return _BUILDERS[key](_effective_settings(settings), policy)


def evaluate(framework: str, *, settings: Optional[Mapping[str, Any]] = None, policy: Optional[Policy] = None) -> dict[str, Any]:
    """Evaluate one framework into a scored, JSON-serialisable report."""
    checks = checks_for(framework, settings=settings, policy=policy)
    passed = sum(1 for c in checks if c.ok)
    total = len(checks)
    return {
        "framework": str(framework).lower().strip(),
        "compliant": passed == total and total > 0,
        "passed": passed,
        "total": total,
        "score": round(passed / total * 100) if total else 0,
        "checks": [asdict(c) for c in checks],
        "disclaimer": "Technical evidence only — this does not certify compliance.",
    }


def evaluate_all(*, settings: Optional[Mapping[str, Any]] = None, policy: Optional[Policy] = None) -> dict[str, Any]:
    """Evaluate every framework into ``{framework: report}``."""
    effective = _effective_settings(settings)
    return {fw: evaluate(fw, settings=effective, policy=policy) for fw in FRAMEWORKS}
