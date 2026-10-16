"""Centralized access policy (Roadmap Phase 7 — Enterprise & Team).

A single JSON *policy document* — roles, principals, and a default role — that
an organization can author once and distribute to every device. Loading it
produces a :class:`~blackoutkit.enterprise.rbac.PolicyEngine`, so the CLI, SDK,
and REST API all enforce the same rules.

The document can be **HMAC-signed** so a device can prove the policy it loaded
came from the organization and was not edited in transit.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from .rbac import DEFAULT_ROLES, PERMISSIONS, Principal, PolicyEngine

_log = logging.getLogger(__name__)

DEFAULT_POLICY_FILE = Path.home() / ".blackout-kit" / "policy.json"
POLICY_VERSION = 1

__all__ = [
    "PolicyError",
    "Policy",
    "PolicyStore",
    "DEFAULT_POLICY_FILE",
    "policy_fingerprint",
    "sign_policy",
    "verify_policy",
]


class PolicyError(Exception):
    """Raised for an invalid, unreadable, or tampered policy document."""


def _default_roles() -> dict[str, list[str]]:
    return {name: sorted(perms) for name, perms in DEFAULT_ROLES.items()}


@dataclass
class Policy:
    """An access-control policy document."""

    organization: str = ""
    version: int = POLICY_VERSION
    roles: dict[str, list[str]] = field(default_factory=_default_roles)
    principals: dict[str, str] = field(default_factory=dict)
    default_role: str = "viewer"

    # ── serialization ───────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "organization": self.organization,
            "version": self.version,
            "default_role": self.default_role,
            "roles": {name: sorted(perms) for name, perms in self.roles.items()},
            "principals": dict(self.principals),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        if not isinstance(data, Mapping):
            raise PolicyError("policy must be a JSON object")
        roles = data.get("roles")
        if not isinstance(roles, Mapping):
            raise PolicyError("policy 'roles' must be an object")
        principals = data.get("principals", {})
        if not isinstance(principals, Mapping):
            raise PolicyError("policy 'principals' must be an object")
        try:
            version = int(data.get("version", POLICY_VERSION))
        except (TypeError, ValueError):
            raise PolicyError("policy 'version' must be an integer") from None
        policy = cls(
            organization=str(data.get("organization", "")),
            version=version,
            roles={str(k): [str(p) for p in (v or [])] for k, v in roles.items()},
            principals={str(k): str(v) for k, v in principals.items()},
            default_role=str(data.get("default_role", "viewer")),
        )
        policy.validate()
        return policy

    # ── validation ──────────────────────────────────────────────────────────

    def validate(self) -> None:
        """Raise :class:`PolicyError` if the document is internally inconsistent."""
        if not self.roles:
            raise PolicyError("policy must define at least one role")
        for name, perms in self.roles.items():
            unknown = set(perms) - PERMISSIONS
            if unknown:
                raise PolicyError(f"role {name!r} grants unknown permission(s): {', '.join(sorted(unknown))}")
        if self.default_role not in self.roles:
            raise PolicyError(f"default_role {self.default_role!r} is not a defined role")
        for name, role in self.principals.items():
            if role not in self.roles:
                raise PolicyError(f"principal {name!r} references undefined role {role!r}")

    # ── derived ─────────────────────────────────────────────────────────────

    def engine(self) -> PolicyEngine:
        return PolicyEngine({name: perms for name, perms in self.roles.items()})

    def principal(self, name: str) -> Principal:
        """Resolve a principal name to its declared (name, role)."""
        role = self.principals.get(str(name), self.default_role)
        return Principal(name=str(name), role=role)

    def canonical_bytes(self) -> bytes:
        """Deterministic bytes used for fingerprinting and signing."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── integrity ────────────────────────────────────────────────────────────────

def policy_fingerprint(policy: Policy) -> str:
    """Stable SHA-256 fingerprint of the policy content."""
    return hashlib.sha256(policy.canonical_bytes()).hexdigest()


def sign_policy(policy: Policy, secret: str) -> str:
    """Return a ``sha256=<hex>`` HMAC signature over the policy content."""
    digest = hmac.new(secret.encode("utf-8"), policy.canonical_bytes(), hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_policy(policy: Policy, secret: str, signature: str) -> bool:
    """Constant-time verification of a policy signature."""
    return hmac.compare_digest(sign_policy(policy, secret), str(signature or ""))


# ── persistence ──────────────────────────────────────────────────────────────

class PolicyStore:
    """Load/save a policy document (optionally signed) at a fixed path."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path or os.environ.get("BLACKOUT_POLICY_FILE") or DEFAULT_POLICY_FILE)

    def exists(self) -> bool:
        return self.path.exists()

    def load(self, *, secret: Optional[str] = None) -> Policy:
        """Load the policy. Returns the built-in default when no file exists.

        When ``secret`` is given, a stored signature is verified and a mismatch
        raises :class:`PolicyError`.
        """
        if not self.path.exists():
            return Policy()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"cannot read policy: {exc}") from exc
        envelope = raw if isinstance(raw, dict) else {}
        document = envelope.get("policy", envelope)
        policy = Policy.from_dict(document)
        if secret is not None:
            signature = envelope.get("signature")
            if not signature:
                raise PolicyError("policy is not signed")
            if not verify_policy(policy, secret, signature):
                raise PolicyError("policy signature does not match (tampered or wrong secret)")
        return policy

    def save(self, policy: Policy, *, secret: Optional[str] = None) -> None:
        """Atomically persist the policy (signed when ``secret`` is given)."""
        policy.validate()
        envelope: dict[str, Any] = {
            "policy": policy.to_dict(),
            "fingerprint": policy_fingerprint(policy),
        }
        if secret:
            envelope["signature"] = sign_policy(policy, secret)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".policy-", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(envelope, handle, indent=2)
            os.replace(temporary, self.path)
        except OSError as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise PolicyError(f"cannot write policy: {exc}") from exc

    def export(self, path: Path, *, secret: Optional[str] = None) -> Path:
        """Write the policy to an arbitrary path (for distribution)."""
        target = Path(path)
        PolicyStore(target).save(self.load(secret=secret) if self.path.exists() else Policy(), secret=secret)
        return target

    def import_(self, path: Path, *, secret: Optional[str] = None) -> Policy:
        """Load a policy from an arbitrary path and save it as the active one."""
        policy = PolicyStore(Path(path)).load(secret=secret)
        self.save(policy, secret=secret)
        return policy
