"""Local, read-only engine recommendation helpers."""
import os
import sys
from dataclasses import dataclass

from .capabilities import (
    all_capabilities,
    get_capability,
    valid_config_protocols,
)


def _normalize_platform(platform: str | None = None) -> str:
    current = platform or sys.platform
    return "linux" if current.startswith("linux") else current


def _supported_platform(platform: str) -> set[str]:
    return {
        capability.name
        for capability in all_capabilities()
        if platform in capability.platforms
    }


LINUX_ENGINES = frozenset(_supported_platform("linux"))
WINDOWS_ENGINES = frozenset(_supported_platform("win32"))
BINARY_REQUIREMENTS = {
    capability.name: capability.runtime_for("win32")
    for capability in all_capabilities()
    if capability.runtime_for("win32")
}
SETTING_REQUIREMENTS = {
    capability.name: tuple(capability.required_settings)
    for capability in all_capabilities()
    if capability.required_settings
}
PROXY_PROTOCOLS = {
    capability.name: set(capability.protocols_for("win32"))
    for capability in all_capabilities()
    if capability.protocols_for("win32")
}
FOUNDATION_ENGINE_NAMES = tuple(capability.name for capability in all_capabilities())


def platform_engines(platform: str | None = None) -> set[str]:
    return _supported_platform(_normalize_platform(platform))


def _binary_available(installed: dict[str, bool], key: str) -> bool:
    if key == "sni-spoofing":
        return bool(installed.get("sni-spoofing") or installed.get("mhrv"))
    return bool(installed.get(key))


def _saved_protocols(
    protocols: set[str] | None,
    configs,
) -> set[str]:
    if configs is None:
        return {str(protocol).lower() for protocol in (protocols or set())}
    return valid_config_protocols(configs)


def _setting_configured(settings: dict, key: str) -> bool:
    value = settings.get(key)
    if not value:
        return False
    if key.endswith(("_config", "_config_file")):
        try:
            return os.path.isfile(os.fspath(value))
        except TypeError:
            return False
    return True


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
    configs=None,
    stability_scores: dict[str, dict] | None = None,
    platform: str | None = None,
) -> list[RouteCandidate]:
    """Rank engines solely from local configuration and historical observations."""
    installed = installed or {}
    protocols = _saved_protocols(protocols, configs)
    stability_scores = stability_scores or {}
    platform_name = _normalize_platform(platform)
    supported = platform_engines(platform_name)
    candidates = []

    for priority, engine in enumerate(_priority_order(settings, country_profile, platform_name)):
        if engine not in supported:
            continue
        capability = get_capability(engine)
        if capability is None:
            continue
        blockers = list(capability.static_blockers)

        for component in capability.runtime_for(platform_name, settings):
            if not _binary_available(installed, component):
                blockers.append(
                    "Linux runner missing" if component == "linux_engine" else f"{component} missing"
                )

        for setting in capability.required_settings:
            if not _setting_configured(settings, setting):
                blockers.append(f"{_setting_label(setting)} not configured")

        if capability.upstream_for(platform_name) == "saved_config":
            expected_protocols = set(capability.protocols_for(platform_name))
            if expected_protocols and not protocols.intersection(expected_protocols):
                blockers.append("No compatible saved proxy config")

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


__all__ = [
    "BINARY_REQUIREMENTS",
    "FOUNDATION_ENGINE_NAMES",
    "LINUX_ENGINES",
    "PROXY_PROTOCOLS",
    "SETTING_REQUIREMENTS",
    "WINDOWS_ENGINES",
    "RouteCandidate",
    "platform_engines",
    "recommend_routes",
    "recommended_engine",
]
