"""Strictly local connection-readiness checks."""
from __future__ import annotations

import os
import shutil
import socket
import sys
from dataclasses import asdict, dataclass

from . import BINS_DIR, daemon, vault
from . import settings as cfg
from .capabilities import get_capability, valid_config_records
from .config.manager import load_configs
from .downloader import check_installed
from .routing import platform_engines


def _platform_key(platform: str | None = None) -> str:
    current = platform or sys.platform
    return "linux" if current.startswith("linux") else current


@dataclass(frozen=True)
class ReadyCheck:
    name: str
    ok: bool
    blocking: bool
    detail: str


def _capability(engine: str):
    return get_capability(engine)


def _setting_value_present(settings: dict, key: str) -> bool:
    value = settings.get(key)
    if not value:
        return False
    if key.endswith(("_config", "_config_file")):
        try:
            return os.path.isfile(os.fspath(value))
        except TypeError:
            return False
    return True


def _port_value(settings: dict, item: str | int) -> int:
    if isinstance(item, int):
        return item
    return int(settings.get(item, cfg.DEFAULTS[item]))


def _local_ports(engine: str, settings: dict) -> tuple[int, ...]:
    capability = _capability(engine)
    if capability is None:
        return ()
    return tuple(_port_value(settings, item) for item in capability.local_ports)


def _setting_requirements(engine: str) -> tuple[str, ...]:
    capability = _capability(engine)
    return tuple(capability.required_settings) if capability else ()


def _runtime_requirements(engine: str, platform: str, settings: dict | None = None) -> tuple[str, ...]:
    capability = _capability(engine)
    return capability.runtime_for(platform, settings) if capability else ()


def _upstream_requirement(engine: str, platform: str) -> str:
    capability = _capability(engine)
    return capability.upstream_for(platform) if capability else "none"


def _compatible_protocols(engine: str, platform: str) -> tuple[str, ...]:
    capability = _capability(engine)
    return capability.protocols_for(platform) if capability else ()


def _check(name: str, ok: bool, detail: str, blocking: bool = True) -> ReadyCheck:
    return ReadyCheck(name, ok, blocking, detail)


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _is_windows_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _selected_config(expected: tuple[str, ...], configs):
    if not expected:
        return None
    return next(
        (item for item in valid_config_records(configs) if str(item.protocol).lower() in expected),
        None,
    )


def _runtime_available(component: str, installed: dict[str, bool]) -> bool:
    if component == "sni-spoofing":
        return bool(installed.get("sni-spoofing") or installed.get("mhrv"))
    return bool(installed.get(component))


def _binary_checks(
    engine: str,
    installed: dict[str, bool],
    platform: str,
    settings: dict,
) -> list[ReadyCheck]:
    capability = _capability(engine)
    requirements = _runtime_requirements(engine, platform, settings)
    if capability is None or not requirements:
        return []
    if platform == "linux":
        runner = BINS_DIR / "blackout-engine"
        available = runner.is_file() and os.access(runner, os.X_OK)
        return [_check(
            "Managed Linux runner",
            available,
            "blackout-engine is available" if available else "Install executable bins/blackout-engine for Linux x86_64",
        )]
    return [
        _check(
            f"Runtime: {name}",
            _runtime_available(name, installed),
            f"{name} is installed" if _runtime_available(name, installed) else f"{name} is missing",
        )
        for name in requirements
    ]


def _privilege_checks(engine: str, platform: str) -> list[ReadyCheck]:
    capability = _capability(engine)
    if capability is None:
        return []
    privilege = capability.privilege
    checks: list[ReadyCheck] = []
    if platform == "win32" and "windows_admin" in privilege:
        admin = _is_windows_admin()
        checks.append(_check(
            "Administrator privileges",
            admin,
            "Administrator privileges are available" if admin else "This engine will require UAC elevation before it can start",
            blocking=False,
        ))
    if platform == "linux" and "linux_root" in privilege:
        root = hasattr(os, "geteuid") and os.geteuid() == 0
        checks.append(_check("Root privileges", root, "Running with sudo" if root else "Run this engine with sudo"))
    return checks


def _linux_network_checks(engine: str) -> list[ReadyCheck]:
    if _platform_key() != "linux":
        return []
    capability = _capability(engine)
    if capability is None or "linux_root" not in capability.privilege:
        return []
    checks = []
    if capability.local_surface == "network_tunnel":
        checks.append(_check("ip command", shutil.which("ip") is not None, "ip is available" if shutil.which("ip") else "Install iproute2 (ip command)"))
    if engine == "tun":
        available = os.path.exists("/dev/net/tun")
        checks.append(_check("TUN device", available, "/dev/net/tun is available" if available else "/dev/net/tun is unavailable"))
    return checks


def evaluate(engine: str, *, allow_active_daemon: bool = False) -> list[ReadyCheck]:
    """Evaluate a selected engine without starting processes or contacting networks."""
    normalized = (engine or "").lower()
    settings = cfg.load()
    platform = _platform_key()
    capability = _capability(normalized)
    checks: list[ReadyCheck] = []

    supported = platform_engines(platform)
    checks.append(_check(
        "Platform support",
        normalized in supported,
        f"{normalized} is supported on this platform" if normalized in supported else f"{normalized or 'no engine'} is unavailable on this platform",
    ))
    if normalized not in supported:
        return checks
    if capability is None:
        return checks

    for blocker in capability.static_blockers:
        checks.append(_check("Capability limitation", False, blocker))

    active_pid = daemon.get_pid()
    checks.append(_check(
        "Daemon state",
        active_pid is None or allow_active_daemon,
        "Daemon ownership is allowed for this internal start" if active_pid is not None and allow_active_daemon else ("No Blackout daemon is active" if active_pid is None else f"Stop the active Blackout daemon (PID {active_pid}) first"),
    ))

    errors = cfg.validate_all(settings)
    checks.append(_check(
        "Settings validation",
        not errors or allow_active_daemon,
        "Internal daemon startup preserves user-facing validation" if errors and allow_active_daemon else ("All saved settings are valid" if not errors else "; ".join(f"{key}: {detail}" for key, detail in errors)),
        blocking=not allow_active_daemon,
    ))

    config_vault_state = vault.vault_status()
    secrets_vault_state = vault.settings_vault_status(settings.get("secrets_vault_enabled", False))
    vault_healthy = bool(config_vault_state["healthy"]) and bool(secrets_vault_state["healthy"])
    vault_detail = str(config_vault_state["detail"]) if not config_vault_state["healthy"] else str(secrets_vault_state["detail"])
    checks.append(_check(
        "Encrypted storage",
        vault_healthy or allow_active_daemon,
        "Internal daemon startup preserves user-facing vault validation" if not vault_healthy and allow_active_daemon else vault_detail,
        blocking=not allow_active_daemon,
    ))

    installed = check_installed()
    for check in _binary_checks(normalized, installed, platform, settings):
        checks.append(ReadyCheck(check.name, check.ok or allow_active_daemon, check.blocking and not allow_active_daemon, "Internal daemon startup preserves user-facing runtime validation" if not check.ok and allow_active_daemon else check.detail))

    for setting in _setting_requirements(normalized):
        present = _setting_value_present(settings, setting)
        checks.append(_check(
            f"Setting: {setting}",
            present,
            f"{setting} is configured" if present else f"Configure {setting} before connecting",
        ))

    for check in _privilege_checks(normalized, platform):
        checks.append(ReadyCheck(check.name, check.ok or allow_active_daemon, check.blocking and not allow_active_daemon, "Internal daemon startup preserves user-facing privilege validation" if not check.ok and allow_active_daemon else check.detail))
    for check in _linux_network_checks(normalized):
        checks.append(ReadyCheck(check.name, check.ok or allow_active_daemon, check.blocking and not allow_active_daemon, "Internal daemon startup preserves user-facing network validation" if not check.ok and allow_active_daemon else check.detail))

    if normalized == "ikev2" and settings.get("ikev2_tunnel_type") == "L2tp":
        checks.append(_check(
            "Setting: ikev2_psk",
            _setting_value_present(settings, "ikev2_psk"),
            "ikev2_psk is configured" if _setting_value_present(settings, "ikev2_psk") else "Configure ikev2_psk for L2TP",
        ))

    try:
        configs = load_configs()
        config_error = None
    except vault.VaultError as exc:
        configs = []
        config_error = str(exc)
    expected_protocols = _compatible_protocols(normalized, platform)
    selected = _selected_config(expected_protocols, configs)
    upstream_requirement = _upstream_requirement(normalized, platform)
    if upstream_requirement == "saved_config":
        checks.append(_check(
            "Proxy configuration",
            selected is not None,
            "A compatible saved proxy configuration is available" if selected else (config_error or "No compatible saved proxy configuration"),
        ))
        if selected is not None:
            error = selected.reality_validation_error()
            checks.append(_check(
                "Proxy configuration syntax",
                error is None,
                "Selected proxy configuration is structurally valid" if error is None else error,
            ))
            if platform == "linux" and normalized in {"xray", "tun"}:
                linux_compatible = selected.address not in {"127.0.0.1", "0.0.0.0", "localhost", "::1"}
                checks.append(_check(
                    "Linux upstream configuration",
                    linux_compatible,
                    "A direct VLESS or Trojan upstream is configured" if linux_compatible else "Linux XRay/TUN requires a direct VLESS or Trojan upstream",
                ))

    for port in _local_ports(normalized, settings):
        available = _port_free(port)
        checks.append(_check(
            f"Local port {port}",
            available,
            f"127.0.0.1:{port} is available" if available else f"127.0.0.1:{port} is already in use",
        ))

    if platform == "linux" and settings.get("kill_switch"):
        checks.append(_check(
            "Kill-switch endpoint",
            True,
            "Endpoint allowlist validation is deferred to start; ready does not resolve remote hosts",
            blocking=False,
        ))

    return checks


def ready(engine: str, *, allow_active_daemon: bool = False) -> bool:
    return all(check.ok or not check.blocking for check in evaluate(engine, allow_active_daemon=allow_active_daemon))


def as_dicts(engine: str) -> list[dict]:
    return [asdict(check) for check in evaluate(engine)]
