"""Self-heal and VM safety (VM-testing hardening).

When Blackout Kit crashes or is hard-killed, it can leave **owned system state**
behind: a system proxy pointing at a dead local port, kill-switch firewall
rules, or a leftover TUN interface. Any one of those can blackhole a machine —
which is exactly what happens inside a test VM.

Every function here is *owned-only*: it removes things Blackout Kit created and
named, never anything it did not. That makes it safe to run unconditionally at
daemon startup and from ``blackout netfix``.

* :func:`heal_all` — clear every owned leftover (the recovery action)
* :func:`leftover_state` — read-only report of what is still left over
* :func:`detect_virtualization` — is this a VM, and which hypervisor
* :func:`safety_report` — VM + leftover state + what to do about it
"""
from __future__ import annotations

import subprocess
import sys
from typing import Any

__all__ = [
    "heal_all",
    "heal_proxy",
    "heal_firewall",
    "heal_tunnel",
    "leftover_state",
    "detect_virtualization",
    "safety_report",
    "self_heal_steps",
    "plan_self_heal_steps",
]

# Hypervisor fingerprints seen in Win32_ComputerSystem / DMI identifiers.
_VM_VENDORS = {
    "vmware": "VMware",
    "innotek": "VirtualBox",
    "oracle": "VirtualBox",
    "virtualbox": "VirtualBox",
    "microsoft corporation": "Hyper-V",
    "qemu": "QEMU/KVM",
    "kvm": "QEMU/KVM",
    "xen": "Xen",
    "parallels": "Parallels",
    "bochs": "Bochs",
    "amazon ec2": "Amazon EC2",
    "google": "Google Compute Engine",
    "hetzner": "Hetzner",
    "digitalocean": "DigitalOcean",
}


# ── healing ──────────────────────────────────────────────────────────────────

def heal_proxy() -> dict[str, Any]:
    """Clear a system proxy that points at a dead local Blackout port.

    ``force_clear_dead_proxy`` only fires when nothing is listening on the
    target port, so a healthy unrelated proxy is never touched.
    """
    cleared_dead = False
    restored_owned = False
    try:
        from .proxy_manager import cleanup_owned_system_proxy, force_clear_dead_proxy

        cleared_dead = bool(force_clear_dead_proxy())
        restored_owned = bool(cleanup_owned_system_proxy())
    except Exception:
        pass
    return {"cleared_dead_proxy": cleared_dead, "restored_owned_proxy": restored_owned}


def heal_firewall() -> dict[str, Any]:
    """Remove Blackout-owned kill-switch firewall rules (named rules only)."""
    cleared = False
    try:
        from . import security as sec

        cleared = bool(sec.disable_kill_switch())
        sec.clear_linux_kill_switch_endpoint()
    except Exception:
        pass
    return {"firewall_cleared": cleared}


def heal_tunnel() -> dict[str, Any]:
    """Remove a leftover BlackoutKit-TUN interface (Linux)."""
    if not sys.platform.startswith("linux"):
        return {"tunnel_removed": False, "detail": "not Linux"}
    try:
        from . import linux_network

        ok, detail = linux_network.delete_owned_tunnel()
        return {"tunnel_removed": bool(ok), "detail": str(detail)}
    except Exception as exc:
        return {"tunnel_removed": False, "detail": f"{type(exc).__name__}"}


def heal_all(*, from_daemon: bool = True) -> dict[str, Any]:
    """Clear every owned leftover and report what was done.

    Also runs the broader targeted network recovery (routes, DNS, adapters) —
    the same work ``blackout netfix`` exposes. Pass ``from_daemon=False`` for
    the user-facing path, which clears the system proxy rather than preserving
    it for the daemon that is about to set its own.
    """
    report: dict[str, Any] = {
        "proxy": heal_proxy(),
        "firewall": heal_firewall(),
        "tunnel": heal_tunnel(),
    }
    try:
        from .tools import run_network_recovery

        report["recovery"] = run_network_recovery(
            audit_source="self_heal", from_daemon=from_daemon
        )
    except Exception as exc:
        report["recovery_error"] = f"{type(exc).__name__}"
    return report


# ── recovery-style steps ─────────────────────────────────────────────────────

# Resolved by attribute name at call time (not captured as direct references)
# so tests can substitute the healers.
_HEAL_FUNCS = (
    ("Clear dead system proxy", "heal_proxy"),
    ("Remove owned firewall rules", "heal_firewall"),
    ("Remove leftover TUN interface", "heal_tunnel"),
)


def _summarise(detail: dict[str, Any]) -> str:
    """Human-readable one-liner for a heal result dict."""
    changed = [key for key, value in detail.items() if value is True or (isinstance(value, int) and value)]
    if not changed:
        return "nothing to clean"
    return "; ".join(f"{key}={detail[key]}" for key in changed)


def self_heal_steps() -> list[dict[str, Any]]:
    """Perform the owned-state heal, returning recovery-style step dicts.

    ``ok`` means "the operation completed without error" — having nothing to
    clean is a success, so a machine with no leftovers still reports ok. Only a
    genuine failure sets ok=False, which is what ``_recovery_success`` checks.
    """
    steps: list[dict[str, Any]] = []
    for label, attribute in _HEAL_FUNCS:
        try:
            steps.append(
                {"name": label, "ok": True, "detail": _summarise(globals()[attribute]())}
            )
        except Exception as exc:
            steps.append({"name": label, "ok": False, "detail": f"{type(exc).__name__}"})
    return steps


def plan_self_heal_steps() -> list[dict[str, Any]]:
    """Preview of :func:`self_heal_steps` without touching system state."""
    return [
        {"name": label, "ok": True, "detail": "Would clear owned Blackout leftovers"}
        for label, _ in _HEAL_FUNCS
    ]


# ── inspection ───────────────────────────────────────────────────────────────

def leftover_state() -> dict[str, Any]:
    """Read-only report of leftover Blackout-owned system state."""
    proxy: dict[str, Any] = {}
    try:
        from .proxy_manager import get_proxy_status, proxy_ownership_status

        proxy = {"current": get_proxy_status(), "owned": proxy_ownership_status() is not None}
    except Exception:
        proxy = {"error": "unreadable"}

    firewall_active = False
    try:
        from . import security as sec

        firewall_active = bool(sec.kill_switch_is_active())
    except Exception:
        pass

    tunnel = False
    if sys.platform.startswith("linux"):
        try:
            from . import linux_network

            tunnel = bool(linux_network.tunnel_exists())
        except Exception:
            pass

    return {
        "proxy": proxy,
        "firewall_active": firewall_active,
        "tun_present": tunnel,
        "any_leftover": bool(proxy.get("owned") or firewall_active or tunnel),
    }


def detect_virtualization() -> dict[str, Any]:
    """Detect whether we are running inside a VM, and which hypervisor."""
    if sys.platform == "win32":
        manufacturer, model = _windows_vm_identity()
    else:
        manufacturer, model = _linux_vm_identity()

    haystack = f"{manufacturer} {model}".lower()
    vendor = next((label for needle, label in _VM_VENDORS.items() if needle in haystack), None)
    return {
        "is_virtual": vendor is not None,
        "hypervisor": vendor or "none detected",
        "manufacturer": manufacturer,
        "model": model,
    }


def _windows_vm_identity() -> tuple[str, str]:
    script = (
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object -ExpandProperty Manufacturer; "
        "Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Model"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=15,
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return (lines[0] if lines else ""), (lines[1] if len(lines) > 1 else "")
    except Exception:
        return "", ""


def _linux_vm_identity() -> tuple[str, str]:
    vendor = ""
    product = ""
    for path, attribute in (
        ("/sys/class/dmi/id/sys_vendor", "vendor"),
        ("/sys/class/dmi/id/product_name", "product"),
    ):
        try:
            value = open(path, encoding="utf-8").read().strip()
        except OSError:
            continue
        if attribute == "vendor":
            vendor = value
        else:
            product = value
    return vendor, product


def safety_report() -> dict[str, Any]:
    """VM detection + leftover state + the recommended next action."""
    vm = detect_virtualization()
    leftover = leftover_state()
    steps: list[str] = []
    if leftover["any_leftover"]:
        steps.append("Run `blackout netfix` to clear leftover Blackout-owned network state")
    if vm["is_virtual"]:
        steps.append("Take a VM snapshot before testing — a crash can blackhole the network")
    return {"vm": vm, "leftover": leftover, "steps": steps}
