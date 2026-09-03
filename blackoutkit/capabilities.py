"""Pure capability metadata for Blackout Kit engine targets."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import os
import sys
from typing import Any, Iterable


PUBLIC_ENGINE_NAMES = (
    "sni",
    "xray",
    "gdpi",
    "psiphon",
    "warp",
    "tun",
    "tor",
    "mhrv",
    "ikev2",
    "wireguard",
    "openvpn",
    "softether",
    "appsscript",
    "hysteria2",
    "tuic",
    "awg",
    "legend",
)


@dataclass(frozen=True)
class EngineCapability:
    """Static, side-effect-free description of one public capability."""

    name: str
    display_name: str
    category: str
    summary: str
    platforms: tuple[str, ...]
    runtime_requirements: tuple[tuple[str, tuple[str, ...]], ...] = ()
    upstream_requirement: str = "none"
    compatible_protocols: tuple[str, ...] = ()
    platform_upstream_requirements: tuple[tuple[str, str], ...] = ()
    platform_protocols: tuple[tuple[str, tuple[str, ...]], ...] = ()
    required_settings: tuple[str, ...] = ()
    privilege: str = "none"
    local_surface: str = "local_proxy"
    local_proxy: bool = False
    listeners: tuple[str, ...] = ()
    local_ports: tuple[str | int, ...] = ()
    system_effects: tuple[str, ...] = ()
    remote_actions: tuple[str, ...] = ()
    experimental: bool = False
    composite: bool = False
    notes: str = ""
    static_blockers: tuple[str, ...] = ()
    runtime_variants: tuple[tuple[str, str, str, tuple[str, ...]], ...] = ()

    def runtime_for(self, platform: str, settings: dict[str, Any] | None = None) -> tuple[str, ...]:
        for setting, value, variant_platform, requirements in self.runtime_variants:
            if variant_platform == platform and settings and str(settings.get(setting, "")).lower() == value.lower():
                return requirements
        for key, requirements in self.runtime_requirements:
            if key == platform:
                return requirements
        return ()

    def upstream_for(self, platform: str) -> str:
        for key, requirement in self.platform_upstream_requirements:
            if key == platform:
                return requirement
        return self.upstream_requirement

    def protocols_for(self, platform: str) -> tuple[str, ...]:
        for key, protocols in self.platform_protocols:
            if key == platform:
                return protocols
        return self.compatible_protocols


# Runtime keys intentionally use the downloader/readiness vocabulary rather than
# filesystem paths. This keeps capability output portable and secret-free.
_CAPABILITIES: dict[str, EngineCapability] = {
    "sni": EngineCapability(
        "sni", "SNI spoofing", "DPI bypass", "Native SNI plus XRay local proxy stack",
        ("win32",), runtime_requirements=(("win32", ("sni-spoofing",)),),
        upstream_requirement="local_fallback", local_proxy=True,
        listeners=("HTTP proxy (xray_http_port)", "SOCKS5 proxy (xray_socks_port)"),
        local_ports=("sni_listen_port", "xray_socks_port", "xray_http_port"),
        system_effects=("process", "system_proxy"),
        remote_actions=("optional Cloudflare IP scan",),
        notes="Windows composite path; local readiness is not proof of remote reachability.",
    ),
    "xray": EngineCapability(
        "xray", "XRay", "Proxy core", "VLESS, Trojan, and VMess proxy routing",
        ("win32", "linux"),
        runtime_requirements=(("win32", ("sni-spoofing",)), ("linux", ("linux_engine",))),
        upstream_requirement="local_fallback", compatible_protocols=("vless", "trojan", "vmess"),
        platform_upstream_requirements=(("linux", "saved_config"),),
        platform_protocols=(("linux", ("vless", "trojan")),),
        local_proxy=True, listeners=("HTTP proxy (xray_http_port)", "SOCKS5 proxy (xray_socks_port)"),
        local_ports=("xray_socks_port", "xray_http_port"),
        system_effects=("process", "system_proxy"), remote_actions=("upstream connection",),
        notes="Windows supports VLESS, Trojan, and VMess; Linux currently accepts direct VLESS or Trojan upstreams.",
    ),

    "gdpi": EngineCapability(
        "gdpi", "GoodbyeDPI", "TCP handling", "TCP fragmentation and WinDivert interception",
        ("win32",), runtime_requirements=(("win32", ("goodbyedpi",)),),
        runtime_variants=(("gdpi_backend", "native", "win32", ("sni-spoofing",)),),
        privilege="windows_admin", local_surface="dpi_interception",
        system_effects=("process", "network_interception"),
        remote_actions=("optional connectivity probes",), experimental=False,
        notes="The legacy backend uses GoodbyeDPI and WinDivert; native mode uses the Blackout core DLL and remains experimental.",
    ),

    "psiphon": EngineCapability(
        "psiphon", "Psiphon", "VPN/proxy client", "Multi-protocol tunnel client",
        ("win32",), runtime_requirements=(("win32", ("warp_dll",)),),
        upstream_requirement="remote_service", local_proxy=True,
        listeners=("SOCKS5 proxy (psiphon_socks_port)",), local_ports=("psiphon_socks_port",),
        system_effects=("process", "system_proxy"),
        remote_actions=("upstream connection",), notes="Uses a locally supplied or downloaded runtime.",
    ),
    "warp": EngineCapability(
        "warp", "Cloudflare WARP", "VPN/proxy client", "WARP/MASQUE tunnel path",
        ("win32",), runtime_requirements=(("win32", ("warp_dll",)),),
        upstream_requirement="remote_service", local_proxy=True,
        listeners=("SOCKS5 proxy (1080)",), local_ports=(1080,),
        system_effects=("process", "system_proxy"),
        remote_actions=("upstream connection",), notes="Availability depends on the external WARP service.",
    ),
    "tun": EngineCapability(
        "tun", "TUN", "System tunnel", "Route all applications through a virtual network interface",
        ("win32", "linux"),
        runtime_requirements=(("win32", ("sni-spoofing",)), ("linux", ("linux_engine",))),
        upstream_requirement="saved_config", compatible_protocols=("vless", "trojan", "hysteria2", "tuic"),
        platform_upstream_requirements=(("win32", "local_fallback"), ("linux", "saved_config")),
        platform_protocols=(("win32", ()), ("linux", ("vless", "trojan"))),
        privilege="windows_admin_or_linux_root", local_surface="network_tunnel",
        local_ports=("sni_listen_port", "xray_socks_port", "xray_http_port"),

        system_effects=("process", "routes", "virtual_adapter", "system_proxy"),
        remote_actions=("upstream connection",), notes="System-wide behavior requires platform privileges and networking prerequisites.",
    ),
    "tor": EngineCapability(
        "tor", "Tor", "Proxy client", "Tor onion-network local SOCKS proxy",
        ("win32",), runtime_requirements=(("win32", ("tor",)),),
        upstream_requirement="remote_service", local_proxy=True, listeners=("SOCKS5 proxy (9050)",),
        local_ports=(9050,),
        system_effects=("process", "system_proxy", "local_runtime_files"),
        remote_actions=("Tor bootstrap",), notes="Requires a trusted local Tor runtime and does not guarantee anonymity.",
    ),
    "mhrv": EngineCapability(
        "mhrv", "MHRV", "HTTP relay", "Embedded HTTP relay through configured relay IDs",
        ("win32",), runtime_requirements=(("win32", ("sni-spoofing",)),),
        upstream_requirement="local_fallback", local_proxy=True,
        listeners=("HTTP proxy (8085)",), local_ports=(8085,), system_effects=("process", "system_proxy"),
        remote_actions=("relay verification",), notes="HTTP relay only; HTTPS CONNECT is not supported.",
    ),
    "ikev2": EngineCapability(
        "ikev2", "IKEv2/L2TP", "Windows native VPN", "Windows built-in RAS VPN profile",
        ("win32",), upstream_requirement="vpn_profile",
        required_settings=("ikev2_server", "ikev2_username", "ikev2_password"),
        privilege="windows_admin", local_surface="network_tunnel",
        system_effects=("vpn_profile", "routes", "process"), remote_actions=("upstream VPN connection",),
        notes="Uses saved credentials and Windows RAS profile operations.",
    ),
    "wireguard": EngineCapability(
        "wireguard", "WireGuard", "VPN", "Fast UDP tunnel from a supplied configuration",
        ("win32",), runtime_requirements=(("win32", ("sni-spoofing",)),),
        upstream_requirement="vpn_profile", required_settings=("wg_config_file",),
        privilege="windows_admin", local_surface="network_tunnel",
        local_ports=("proxy_port",),
        system_effects=("process", "routes", "virtual_adapter"), remote_actions=("upstream VPN connection",),
        notes="Requires a user-supplied WireGuard configuration file.",
    ),
    "openvpn": EngineCapability(
        "openvpn", "OpenVPN", "VPN", "OpenVPN tunnel from a supplied profile",
        ("win32",), runtime_requirements=(("win32", ("openvpn",)),),
        upstream_requirement="vpn_profile", required_settings=("openvpn_config",),
        privilege="windows_admin", local_surface="network_tunnel",
        system_effects=("process", "routes", "local_runtime_files"), remote_actions=("upstream VPN connection",),
        notes="Requires a user-supplied .ovpn profile and runtime.",
    ),
    "softether": EngineCapability(
        "softether", "SoftEther", "VPN", "SSL-VPN client with a user-supplied account",
        ("win32",), runtime_requirements=(("win32", ("softether-client",)),),
        upstream_requirement="vpn_profile", required_settings=("softether_host", "softether_username", "softether_password"),
        privilege="windows_admin", local_surface="network_tunnel",
        system_effects=("process", "routes", "virtual_adapter", "service"), remote_actions=("upstream VPN connection",),
        notes="The runtime may require installed vpnclient and vpncmd components.",
    ),
    "appsscript": EngineCapability(
        "appsscript", "Apps Script relay", "HTTP relay", "Python HTTP relay through configured deployments",
        ("win32",), upstream_requirement="local_fallback", local_proxy=True,
        listeners=("HTTP proxy (gas_proxy_port)",), local_ports=("gas_proxy_port",), system_effects=("process", "system_proxy"),
        remote_actions=("relay verification",), notes="HTTP relay only; deployment trust remains the user's responsibility.",
    ),
    "hysteria2": EngineCapability(
        "hysteria2", "Hysteria2", "QUIC proxy", "QUIC proxy path through the managed runtime",
        ("win32", "linux"),
        runtime_requirements=(("win32", ("sni-spoofing",)), ("linux", ("linux_engine",))),
        upstream_requirement="saved_config", compatible_protocols=("hysteria2",), local_proxy=True,
        listeners=("SOCKS5 proxy (xray_socks_port)",), local_ports=("xray_socks_port",), system_effects=("process", "system_proxy"),
        remote_actions=("upstream QUIC connection",), notes="Requires a compatible Hysteria2 upstream configuration.",
    ),
    "tuic": EngineCapability(
        "tuic", "TUIC", "QUIC proxy", "QUIC proxy path through the managed runtime",
        ("win32", "linux"),
        runtime_requirements=(("win32", ("sni-spoofing",)), ("linux", ("linux_engine",))),
        upstream_requirement="saved_config", compatible_protocols=("tuic",), local_proxy=True,
        listeners=("SOCKS5 proxy (xray_socks_port)",), local_ports=("xray_socks_port",), system_effects=("process", "system_proxy"),
        remote_actions=("upstream QUIC connection",), notes="Requires a compatible TUIC upstream configuration.",
    ),
    "awg": EngineCapability(
        "awg", "AmneziaWG", "Obfuscated VPN", "AmneziaWG configuration through sing-box",
        ("win32", "linux"),
        runtime_requirements=(("win32", ("sni-spoofing",)), ("linux", ("linux_engine",))),
        upstream_requirement="vpn_profile", compatible_protocols=("awg",), required_settings=("awg_config_file",),
        privilege="none", local_proxy=True,
        listeners=("SOCKS5 proxy (xray_socks_port)",), local_ports=("xray_socks_port",),
        system_effects=("process", "local_runtime_files"),

        remote_actions=("upstream VPN connection",), experimental=True,
        static_blockers=("AmneziaWG outbound is unavailable in the bundled sing-box runtime",),
        notes="Cataloged experimental path; the bundled sing-box runtime currently exposes standard WireGuard, not the AmneziaWG outbound type.",
    ),
    "legend": EngineCapability(
        "legend", "Legend stack", "Composite stack", "Tor, SNI, and XRay composite connection target",
        ("win32",), runtime_requirements=(("win32", ("sni-spoofing", "tor")),),
        upstream_requirement="local_fallback", compatible_protocols=("vless", "trojan", "vmess"),
        local_proxy=True, listeners=("HTTP proxy (xray_http_port)", "SOCKS5 proxy (xray_socks_port)", "SOCKS5 proxy (9050)"),
        local_ports=("xray_socks_port", "xray_http_port", 9050),
        system_effects=("process", "system_proxy", "local_runtime_files"),
        remote_actions=("Tor bootstrap", "upstream connection",), composite=True,
        notes="Connect/start target; separate from the legend security mode.",
    ),
}

# These local-LAN capabilities are intentionally separate from the public
# connect/start target list. They are available to matrix consumers without
# changing the existing launcher semantics.
_LOCAL_CAPABILITIES = (
    EngineCapability(
        "neighbor-share", "Neighbor sharing", "LAN peer", "Share a local proxy with nearby Blackout Kit devices",
        ("win32", "linux"), upstream_requirement="local_peer", local_proxy=True,
        listeners=("LAN discovery and proxy listener",), system_effects=("process", "lan_listener", "local_cache"),
        remote_actions=("LAN multicast",), notes="LAN sharing exposes a local service to explicitly selected peers.",
    ),
    EngineCapability(
        "neighbor-connect", "Neighbor connection", "LAN peer", "Route through a nearby Blackout Kit device",
        ("win32", "linux"), upstream_requirement="local_peer", local_proxy=True,
        system_effects=("system_proxy", "local_cache"), remote_actions=("LAN discovery",),
        notes="Requires a trusted nearby peer; it is not a hosted VPN service.",
    ),
)


def all_capabilities(*, include_local: bool = False) -> tuple[EngineCapability, ...]:
    records = tuple(_CAPABILITIES[name] for name in PUBLIC_ENGINE_NAMES)
    return records + (_LOCAL_CAPABILITIES if include_local else ())


def get_capability(name: str) -> EngineCapability | None:
    normalized = str(name or "").strip().lower()
    if normalized in _CAPABILITIES:
        return _CAPABILITIES[normalized]
    return next((item for item in _LOCAL_CAPABILITIES if item.name == normalized), None)


def supported_engine_names(platform: str | None = None) -> set[str]:
    current = _platform_label(platform or sys.platform)
    return {
        item.name for item in all_capabilities()
        if current in item.platforms
    }


def _platform_label(platform: str) -> str:
    if platform.startswith("linux"):
        return "linux"
    return platform


def _valid_config_protocol(config: Any) -> str | None:
    protocol = str(getattr(config, "protocol", "") or "").strip().lower()
    address = getattr(config, "address", None)
    port = getattr(config, "port", None)
    if not protocol or not isinstance(address, str) or not address.strip():
        return None
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return None
    validation = getattr(config, "reality_validation_error", None)
    if callable(validation):
        try:
            if validation() is not None:
                return None
        except Exception:
            return None
    return protocol


def valid_config_protocols(value: Iterable[Any] | None) -> set[str]:
    protocols = set()
    for item in value or ():
        if isinstance(item, str):
            protocols.add(item.lower())
            continue
        protocol = _valid_config_protocol(item)
        if protocol:
            protocols.add(protocol)
    return protocols


def valid_config_records(value: Iterable[Any] | None) -> tuple[Any, ...]:
    """Return structurally valid config objects without exposing their values."""
    return tuple(
        item for item in value or ()
        if not isinstance(item, str) and _valid_config_protocol(item)
    )


def _protocols(value: Iterable[Any] | None) -> set[str]:
    result = {item.lower() for item in (value or ()) if isinstance(item, str)}
    result.update(valid_config_protocols(value))
    return result


def _installed(value: dict[str, bool] | None) -> dict[str, bool]:
    if value is not None:
        return {str(key): bool(item) for key, item in value.items()}
    try:
        from .downloader import check_installed
        return check_installed()
    except Exception:
        return {}


def _settings(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is not None:
        return dict(value)
    try:
        from . import settings as cfg
        return cfg.load()
    except Exception:
        return {}


def _runtime_available(component: str, installed: dict[str, bool]) -> bool:
    if component == "sni-spoofing":
        return bool(installed.get("sni-spoofing") or installed.get("mhrv"))
    return bool(installed.get(component))


def _runtime_ready(
    capability: EngineCapability,
    platform: str,
    installed: dict[str, bool],
    settings: dict[str, Any],
) -> list[str]:
    if platform not in capability.platforms:
        return []
    return [
        f"{component} missing"
        for component in capability.runtime_for(platform, settings)
        if not _runtime_available(component, installed)
    ]


def _safe_setting_present(settings: dict[str, Any], key: str) -> bool:
    value = settings.get(key)
    if not value:
        return False
    if key.endswith(("_config", "_config_file")):
        try:
            return os.path.isfile(os.fspath(value))
        except TypeError:
            return False
    return True


def build_capability_matrix(
    platform: str | None = None,
    *,
    settings: dict[str, Any] | None = None,
    installed: dict[str, bool] | None = None,
    protocols: Iterable[Any] | None = None,
    configs: Iterable[Any] | None = None,
    include_local: bool = False,
) -> list[dict[str, Any]]:
    """Build safe capability records from local facts without starting anything."""
    current = _platform_label(platform or sys.platform)
    values = _settings(settings)
    binaries = _installed(installed)
    saved_protocols = _protocols(protocols if protocols is not None else configs)
    rows: list[dict[str, Any]] = []

    for capability in all_capabilities(include_local=include_local):
        if current not in capability.platforms:
            platform_status = "unsupported"
            state = "unsupported"
            blockers = [f"unsupported on {current}"]
        else:
            platform_status = "supported"
            blockers = list(capability.static_blockers)
            blockers.extend(_runtime_ready(capability, current, binaries, values))
            blockers.extend(
                f"{key} not configured"
                for key in capability.required_settings
                if not _safe_setting_present(values, key)
            )
            upstream_requirement = capability.upstream_for(current)
            if upstream_requirement == "saved_config":
                compatible = set(capability.protocols_for(current))
                if compatible and not saved_protocols.intersection(compatible):
                    blockers.append("no compatible saved proxy config")
            state = "ready" if not blockers else "blocked"

        upstream_requirement = capability.upstream_for(current)

        rows.append({
            "name": capability.name,
            "display_name": capability.display_name,
            "category": capability.category,
            "summary": capability.summary,
            "platforms": list(capability.platforms),
            "platform_status": platform_status,
            "state": state,
            "runtime_requirements": list(capability.runtime_for(current, values)),
            "upstream_requirement": upstream_requirement,
            "compatible_protocols": list(capability.protocols_for(current)),
            "required_settings": list(capability.required_settings),
            "privilege": capability.privilege,
            "local_surface": capability.local_surface,
            "local_proxy": capability.local_proxy,
            "listeners": list(capability.listeners),
            "local_ports": list(capability.local_ports),
            "system_effects": list(capability.system_effects),
            "remote_actions": list(capability.remote_actions),
            "experimental": capability.experimental,
            "composite": capability.composite,
            "notes": capability.notes,
            "blockers": blockers,
        })
    return rows


def serialize_capability(capability: EngineCapability) -> dict[str, Any]:
    """Serialize static metadata only; never include settings or local paths."""
    payload = asdict(capability)
    payload["platforms"] = list(capability.platforms)
    payload["runtime_requirements"] = {
        platform: list(requirements)
        for platform, requirements in capability.runtime_requirements
    }
    payload["compatible_protocols"] = list(capability.compatible_protocols)
    payload["platform_upstream_requirements"] = dict(capability.platform_upstream_requirements)
    payload["platform_protocols"] = {
        platform: list(protocols)
        for platform, protocols in capability.platform_protocols
    }
    payload["required_settings"] = list(capability.required_settings)
    payload["listeners"] = list(capability.listeners)
    payload["local_ports"] = list(capability.local_ports)
    payload["system_effects"] = list(capability.system_effects)
    payload["remote_actions"] = list(capability.remote_actions)
    return payload


__all__ = [
    "EngineCapability",
    "PUBLIC_ENGINE_NAMES",
    "all_capabilities",
    "build_capability_matrix",
    "get_capability",
    "serialize_capability",
    "supported_engine_names",
    "valid_config_protocols",
    "valid_config_records",
]
