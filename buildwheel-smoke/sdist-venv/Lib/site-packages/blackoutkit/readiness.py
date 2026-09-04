"""Strictly local connection-readiness checks."""
from __future__ import annotations

import os
import shutil
import socket
import sys
from dataclasses import asdict, dataclass

from . import BINS_DIR, daemon, settings as cfg, vault
from .config.manager import load_configs
from .downloader import check_installed
from .routing import PROXY_PROTOCOLS, SETTING_REQUIREMENTS, platform_engines


@dataclass(frozen=True)
class ReadyCheck:
    name: str
    ok: bool
    blocking: bool
    detail: str


_WINDOWS_ADMIN_ENGINES = frozenset({"gdpi", "warp", "tun"})
_LOCAL_PORTS = {
    "sni": ("sni_listen_port", "xray_socks_port", "xray_http_port"),
    "xray": ("xray_socks_port", "xray_http_port"),
    "hysteria2": ("xray_socks_port",),
    "tuic": ("xray_socks_port",),
    "psiphon": ("psiphon_http_port", "psiphon_socks_port"),
    "warp": (1080,),
    "tor": (9050,),
    "mhrv": (8085, 8086),
    "appsscript": ("gas_proxy_port",),
}


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


def _selected_config(engine: str, configs):
    expected = PROXY_PROTOCOLS.get(engine)
    if expected is None and engine in {"xray", "tun", "sni", "legend"}:
        expected = {"vless", "trojan", "vmess"}
    if not expected:
        return None
    return next((item for item in configs if item.protocol in expected), None)


def _binary_checks(engine: str, installed: dict[str, bool]) -> list[ReadyCheck]:
    if sys.platform.startswith("linux"):
        runner = BINS_DIR / "blackout-engine"
        return [_check(
            "Managed Linux runner",
            runner.is_file() and os.access(runner, os.X_OK),
            "blackout-engine is available" if runner.is_file() and os.access(runner, os.X_OK) else "Install executable bins/blackout-engine for Linux x86_64",
        )]

    requirements = {
        "sni": ("sni-spoofing",),
        "xray": ("sni-spoofing",),
        "gdpi": ("goodbyedpi",),
        "psiphon": ("warp_dll",),
        "warp": ("warp_dll",),
        "tun": ("sing-box",),
        "tor": ("tor",),
        "mhrv": ("mhrv",),
        "wireguard": ("wireguard",),
        "openvpn": ("openvpn",),
        "softether": ("softether",),
        "legend": ("tor", "sni-spoofing"),
    }.get(engine, ())
    return [
        _check(f"Runtime: {name}", bool(installed.get(name)), f"{name} is installed" if installed.get(name) else f"{name} is missing")
        for name in requirements
    ]


def evaluate(engine: str, *, allow_active_daemon: bool = False) -> list[ReadyCheck]:
    """Evaluate a selected engine without starting processes or contacting networks."""
    normalized = (engine or "").lower()
    settings = cfg.load()
    checks: list[ReadyCheck] = []

    supported = platform_engines()
    checks.append(_check(
        "Platform support",
        normalized in supported,
        f"{normalized} is supported on this platform" if normalized in supported else f"{normalized or 'no engine'} is unavailable on this platform",
    ))
    if normalized not in supported:
        return checks

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
    for check in _binary_checks(normalized, installed):
        checks.append(ReadyCheck(check.name, check.ok or allow_active_daemon, check.blocking and not allow_active_daemon, "Internal daemon startup preserves user-facing runtime validation" if not check.ok and allow_active_daemon else check.detail))

    for setting in SETTING_REQUIREMENTS.get(normalized, ()):
        present = bool(settings.get(setting))
        checks.append(_check(
            f"Setting: {setting}",
            present,
            f"{setting} is configured" if present else f"Configure {setting} before connecting",
        ))

    if normalized == "ikev2" and settings.get("ikev2_tunnel_type") == "L2tp":
        checks.append(_check(
            "Setting: ikev2_psk",
            bool(settings.get("ikev2_psk")),
            "ikev2_psk is configured" if settings.get("ikev2_psk") else "Configure ikev2_psk for L2TP",
        ))

    try:
        configs = load_configs()
        config_error = None
    except vault.VaultError as exc:
        configs = []
        config_error = str(exc)
    selected = _selected_config(normalized, configs)
    config_required = normalized in {"tun", "hysteria2", "tuic"} or (sys.platform.startswith("linux") and normalized in {"xray", "sni", "legend"})
    if normalized in {"xray", "tun", "sni", "legend", "hysteria2", "tuic"}:
        checks.append(_check(
            "Proxy configuration",
            selected is not None or not config_required,
            "A compatible saved proxy configuration is available" if selected else (config_error or "No compatible saved proxy configuration; this engine can use its local fallback on this platform"),
            blocking=config_required,
        ))
        if selected is not None:
            error = selected.reality_validation_error()
            checks.append(_check(
                "Proxy configuration syntax",
                error is None,
                "Selected proxy configuration is structurally valid" if error is None else error,
            ))
            if sys.platform.startswith("linux") and normalized in {"xray", "tun"}:
                linux_compatible = selected.protocol in {"vless", "trojan"} and selected.address not in {"127.0.0.1", "0.0.0.0", "localhost", "::1"}
                checks.append(_check(
                    "Linux upstream configuration",
                    linux_compatible,
                    "A direct VLESS or Trojan upstream is configured" if linux_compatible else "Linux XRay/TUN requires a direct VLESS or Trojan upstream",
                ))

    for item in _LOCAL_PORTS.get(normalized, ()):
        port = settings.get(item, cfg.DEFAULTS[item]) if isinstance(item, str) else item
        available = _port_free(port)
        checks.append(_check(
            f"Local port {port}",
            available,
            f"127.0.0.1:{port} is available" if available else f"127.0.0.1:{port} is already in use",
        ))

    if sys.platform == "win32" and normalized in _WINDOWS_ADMIN_ENGINES:
        admin = _is_windows_admin()
        checks.append(_check(
            "Administrator privileges",
            admin,
            "Administrator privileges are available" if admin else "This engine will require UAC elevation before it can start",
            blocking=False,
        ))

    if sys.platform.startswith("linux"):
        if normalized == "tun":
            root = hasattr(os, "geteuid") and os.geteuid() == 0
            checks.append(_check("Root privileges", root, "Running with sudo" if root else "Run Linux TUN with sudo"))
            checks.append(_check("ip command", shutil.which("ip") is not None, "ip is available" if shutil.which("ip") else "Install iproute2 (ip command)"))
            checks.append(_check("TUN device", os.path.exists("/dev/net/tun"), "/dev/net/tun is available" if os.path.exists("/dev/net/tun") else "/dev/net/tun is unavailable"))
        if settings.get("kill_switch"):
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
