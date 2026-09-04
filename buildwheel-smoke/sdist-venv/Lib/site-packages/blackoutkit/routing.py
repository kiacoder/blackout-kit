"""Local, read-only engine recommendation helpers."""
from dataclasses import dataclass
import sys


LINUX_ENGINES = frozenset({"xray", "tun", "hysteria2", "tuic", "awg"})
PROXY_PROTOCOLS = {
    "hysteria2": {"hysteria2"},
    "tuic": {"tuic"},
    "awg": set(),
}
BINARY_REQUIREMENTS = {
    "sni": ("sni-spoofing",),
    "xray": ("sni-spoofing",),
    "gdpi": ("goodbyedpi",),
    "mhrv": ("mhrv",),
    "legend": ("sni-spoofing",),
    "wireguard": ("wireguard",),
    "softether": ("softether",),
    "tor": ("tor",),
    "openvpn": ("openvpn",),
    "warp": ("warp_dll",),
    "psiphon": ("warp_dll",),
    "tun": ("mhrv",),
    "hysteria2": ("mhrv",),
    "tuic": ("mhrv",),
    "awg": ("mhrv",),
}
SETTING_REQUIREMENTS = {
    "ikev2": ("ikev2_server", "ikev2_username", "ikev2_password"),
    "wireguard": ("wg_config_file",),
    "openvpn": ("openvpn_config",),
    "softether": ("softether_host", "softether_username", "softether_password"),
}


def _binary_available(installed: dict[str, bool], key: str) -> bool:
    if key == "sni-spoofing":
        return installed.get("sni-spoofing", False) or installed.get("mhrv", False)
    return installed.get(key, False)


def _setting_label(key: str) -> str:
    return key.replace("_", " ")


@dataclass(frozen=True)
class RouteCandidate:
    engine: str
    score: int
    ready: bool
    evidence: str
    blockers: tuple[str, ...]
    stability: dict


def platform_engines(platform: str | None = None) -> set[str]:
    current = platform or sys.platform
    if current.startswith("linux"):
        return set(LINUX_ENGINES)
    return {
        "sni", "xray", "gdpi", "psiphon", "warp", "tun", "tor", "mhrv",
        "ikev2", "wireguard", "openvpn", "softether", "appsscript", "hysteria2",
        "tuic", "awg", "legend",
    }


def _priority_order(settings: dict, country_profile, platform: str | None = None) -> list[str]:
    preferred = settings.get("selected_engine", "auto")
    order = []
    if preferred != "auto":
        order.append(preferred)
    if country_profile:
        order.extend(country_profile.engine_order)
    order.extend(settings.get("engine_order", []))
    order.extend(sorted(platform_engines(platform)))
    return list(dict.fromkeys(order))


def recommend_routes(
    settings: dict,
    *,
    country_profile=None,
    installed: dict[str, bool] | None = None,
    protocols: set[str] | None = None,
    stability_scores: dict[str, dict] | None = None,
    platform: str | None = None,
) -> list[RouteCandidate]:
    """Rank engines solely from local configuration and historical observations."""
    installed = installed or {}
    protocols = protocols or set()
    stability_scores = stability_scores or {}
    supported = platform_engines(platform)
    candidates = []

    for priority, engine in enumerate(_priority_order(settings, country_profile, platform)):
        if engine not in supported:
            continue
        blockers = []
        if (platform or sys.platform).startswith("linux"):
            if not installed.get("linux_engine", False):
                blockers.append("Linux runner missing")
        else:
            for binary in BINARY_REQUIREMENTS.get(engine, ()):
                if not _binary_available(installed, binary):
                    blockers.append(f"{binary} missing")
            for setting in SETTING_REQUIREMENTS.get(engine, ()):
                if not settings.get(setting):
                    blockers.append(f"{_setting_label(setting)} not configured")

        expected_protocols = PROXY_PROTOCOLS.get(engine)
        if (platform or sys.platform).startswith("linux") and engine in {"xray", "tun"}:
            expected_protocols = {"vless", "trojan"}
        if expected_protocols and not protocols.intersection(expected_protocols):
            blockers.append("No compatible saved proxy config")

        if engine == "appsscript" and not protocols:
            blockers.append("No saved relay config")

        if engine == "mhrv" and not settings.get("mhrv_direct", False) and not protocols:
            blockers.append("No saved relay config")

        stability = stability_scores.get(engine, {})
        score = 1000 - priority * 10
        if settings.get("selected_engine") == engine:
            score += 500
        if country_profile and engine in country_profile.engine_order:
            score += max(0, 100 - country_profile.engine_order.index(engine) * 20)
        if stability.get("stable"):
            score += 75
        elif stability.get("avg_ms") is not None:
            score -= 75

        evidence = "No local health history"
        if stability.get("avg_ms") is not None:
            evidence = (
                f"{stability['avg_ms']:.0f}ms average, "
                f"{stability.get('loss_pct', 0):.0f}% loss, {stability.get('trend', 'unknown')}"
            )
        candidates.append(RouteCandidate(
            engine=engine,
            score=score,
            ready=not blockers,
            evidence=evidence,
            blockers=tuple(blockers),
            stability=stability,
        ))

    return sorted(candidates, key=lambda candidate: (candidate.ready, candidate.score), reverse=True)


def recommended_engine(*args, **kwargs) -> RouteCandidate | None:
    candidates = recommend_routes(*args, **kwargs)
    return next((candidate for candidate in candidates if candidate.ready), candidates[0] if candidates else None)
