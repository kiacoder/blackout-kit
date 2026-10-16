"""Enterprise & Team features (Roadmap Phase 7).

Local-first building blocks for organizations:

* :mod:`~blackoutkit.enterprise.rbac` — roles, permissions, and a policy engine.
* :mod:`~blackoutkit.enterprise.policy` — a distributable, optionally signed
  access policy document.
* :mod:`~blackoutkit.enterprise.devices` — a multi-device registry + dashboard.
* :mod:`~blackoutkit.enterprise.compliance` — GDPR/HIPAA/SOC 2 control checks.
"""
from __future__ import annotations

from .compliance import FRAMEWORKS, Check, checks_for, evaluate, evaluate_all
from .devices import DEFAULT_DEVICE_FILE, Device, DeviceRegistry
from .policy import (
    DEFAULT_POLICY_FILE,
    Policy,
    PolicyError,
    PolicyStore,
    policy_fingerprint,
    sign_policy,
    verify_policy,
)
from .rbac import (
    DEFAULT_ROLES,
    PERMISSIONS,
    ROLE_ORDER,
    AccessDenied,
    PolicyEngine,
    Principal,
    Role,
)

__all__ = [
    # rbac
    "PERMISSIONS",
    "DEFAULT_ROLES",
    "ROLE_ORDER",
    "AccessDenied",
    "Role",
    "Principal",
    "PolicyEngine",
    # policy
    "Policy",
    "PolicyStore",
    "PolicyError",
    "DEFAULT_POLICY_FILE",
    "policy_fingerprint",
    "sign_policy",
    "verify_policy",
    # devices
    "Device",
    "DeviceRegistry",
    "DEFAULT_DEVICE_FILE",
    # compliance
    "Check",
    "FRAMEWORKS",
    "checks_for",
    "evaluate",
    "evaluate_all",
]
