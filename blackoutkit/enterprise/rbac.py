"""Role-based access control (Roadmap Phase 7 — Enterprise & Team).

A small, local-first RBAC model: a fixed permission vocabulary, three built-in
roles, and a :class:`PolicyEngine` that answers "may this principal do X?".
Blackout Kit is single-process and local-first, so there is no server-side
session — a *principal* is a declared identity (the operator's name + role),
and the engine is used to gate operations consistently across the CLI, the SDK,
and the REST API.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional

__all__ = [
    "PERMISSIONS",
    "DEFAULT_ROLES",
    "ROLE_ORDER",
    "AccessDenied",
    "Role",
    "Principal",
    "PolicyEngine",
]

# The full permission vocabulary. Kept explicit so typos fail loudly.
PERMISSIONS = frozenset({
    "view_status",
    "view_metrics",
    "view_connections",
    "connect",
    "disconnect",
    "manage_configs",
    "manage_settings",
    "manage_policy",
    "manage_plugins",
    "run_tools",
    "export_reports",
})

_VIEWER = frozenset({"view_status", "view_metrics", "view_connections"})
_OPERATOR = _VIEWER | frozenset({
    "connect", "disconnect", "run_tools", "export_reports",
})

DEFAULT_ROLES: dict[str, frozenset[str]] = {
    "viewer": _VIEWER,
    "operator": _OPERATOR,
    "admin": PERMISSIONS,
}

# Ascending privilege — used for "at least this role" checks and display.
ROLE_ORDER: tuple[str, ...] = ("viewer", "operator", "admin")


class AccessDenied(PermissionError):
    """Raised when a principal lacks a required permission."""


@dataclass(frozen=True)
class Role:
    """A named set of permissions."""

    name: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class Principal:
    """A declared identity: a name and the role it holds."""

    name: str
    role: str = "viewer"


class PolicyEngine:
    """Answers access questions against a set of roles."""

    def __init__(self, roles: Optional[Mapping[str, Iterable[str]]] = None):
        self._roles: dict[str, Role] = {}
        for name, perms in (roles if roles is not None else DEFAULT_ROLES).items():
            self.add_role(name, perms)

    # ── roles ───────────────────────────────────────────────────────────────

    def add_role(self, name: str, permissions: Iterable[str]) -> None:
        """Define/replace a role. Raises ``ValueError`` on unknown permissions."""
        role_name = str(name).strip()
        if not role_name:
            raise ValueError("role name must not be empty")
        granted = frozenset(str(p).strip() for p in permissions if str(p).strip())
        unknown = granted - PERMISSIONS
        if unknown:
            raise ValueError(f"unknown permission(s): {', '.join(sorted(unknown))}")
        self._roles[role_name] = Role(role_name, granted)

    def roles(self) -> list[Role]:
        return sorted(self._roles.values(), key=lambda r: (ROLE_ORDER.index(r.name) if r.name in ROLE_ORDER else 99, r.name))

    def role_names(self) -> list[str]:
        return [r.name for r in self.roles()]

    def permissions_for(self, role: str) -> frozenset[str]:
        """Permissions granted to ``role`` (empty for an unknown role)."""
        found = self._roles.get(str(role))
        return found.permissions if found else frozenset()

    # ── checks ──────────────────────────────────────────────────────────────

    def can(self, principal: Principal, permission: str) -> bool:
        """Whether ``principal`` holds ``permission``."""
        return str(permission) in self.permissions_for(principal.role)

    def require(self, principal: Principal, permission: str) -> None:
        """Raise :class:`AccessDenied` unless ``principal`` holds ``permission``."""
        if not self.can(principal, permission):
            raise AccessDenied(
                f"{principal.name!r} (role {principal.role!r}) lacks permission {permission!r}"
            )

    def at_least(self, principal: Principal, role: str) -> bool:
        """Whether ``principal``'s role ranks at or above ``role``."""
        try:
            return ROLE_ORDER.index(principal.role) >= ROLE_ORDER.index(str(role))
        except ValueError:
            return False

    def check(self, principal: Principal, permission: str) -> dict[str, object]:
        """Non-raising check returning an explainable result dict."""
        allowed = self.can(principal, permission)
        return {
            "principal": principal.name,
            "role": principal.role,
            "permission": str(permission),
            "allowed": allowed,
            "reason": "granted" if allowed else f"role {principal.role!r} does not include {permission!r}",
        }
