"""Command-level enforcement of the enterprise policy.

`rbac.PolicyEngine` could answer `can()` and `require()`, and the policy
document could map principals to roles - but nothing outside `rbac.py` ever
asked. The authorization layer was a model, not a control: `blackout connect`,
`settings set`, `vault` and the rest ran for anybody.

This module is the single place every subcommand passes through, so the model
is now load-bearing. Enforcement is opt-in in one specific sense: a machine
with no policy file, or a policy that declares no principals, is the default
single-user install and is left alone. Once a policy *does* declare
principals, the checks apply.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .policy import Policy, PolicyStore
from .rbac import AccessDenied, Principal

__all__ = [
    "COMMAND_PERMISSIONS",
    "DEFAULT_PERMISSION",
    "ENV_PRINCIPAL",
    "EnforcementState",
    "check_command",
    "describe",
    "permission_for",
]

# Which permission each top-level command needs. Anything not listed falls back
# to DEFAULT_PERMISSION, so a newly added command is gated by default rather
# than silently open.
COMMAND_PERMISSIONS: dict[str, str] = {
    # read-only
    "status": "view_status",
    "dashboard": "view_metrics",
    "doctor": "view_status",
    "version": "view_status",
    "capabilities": "view_status",
    # session control
    "connect": "connect",
    "disconnect": "disconnect",
    "killswitch": "disconnect",
    # configuration
    "config": "manage_configs",
    "settings": "manage_settings",
    "vault": "manage_settings",
    "plugin": "manage_plugins",
    "plugins": "manage_plugins",
    "enterprise": "manage_policy",
    "policy": "manage_policy",
    # tools and reports
    "tools": "run_tools",
    "scan": "run_tools",
    "benchmark": "run_tools",
    "export": "export_reports",
    "report": "export_reports",
    "compliance": "export_reports",
}

DEFAULT_PERMISSION = "run_tools"

# Name of the principal acting in this process. Without it, the policy's
# default_role applies to a synthetic "local" principal.
ENV_PRINCIPAL = "BLACKOUT_PRINCIPAL"


@dataclass(frozen=True)
class EnforcementState:
    """Whether a policy applies here, and to whom."""

    active: bool
    principal: Optional[Principal]
    detail: str


def permission_for(command: str) -> str:
    """The permission a top-level command requires."""
    return COMMAND_PERMISSIONS.get(str(command), DEFAULT_PERMISSION)


def describe(store: Optional[PolicyStore] = None) -> EnforcementState:
    """Resolve the enforcement state without raising."""
    store = store or PolicyStore()
    if not store.exists():
        return EnforcementState(False, None, "no policy file; single-user defaults apply")

    try:
        policy: Policy = store.load()
    except Exception as exc:  # PolicyError, OSError, bad JSON
        # Fail closed. A policy that cannot be read must not silently turn
        # access control off.
        return EnforcementState(True, None, f"policy could not be read: {exc}")

    if not policy.principals:
        return EnforcementState(False, None, "policy declares no principals")

    name = os.environ.get(ENV_PRINCIPAL, "").strip()
    if name:
        principal = policy.principal(name)
    else:
        principal = Principal("local", policy.default_role)
    return EnforcementState(True, principal, "")


def check_command(command: str, store: Optional[PolicyStore] = None) -> None:
    """Raise :class:`AccessDenied` when the active principal may not run it."""
    state = describe(store)
    if not state.active:
        return
    if state.principal is None:
        raise AccessDenied(state.detail)

    store = store or PolicyStore()
    policy = store.load()
    permission = permission_for(command)
    policy.engine().require(state.principal, permission)
