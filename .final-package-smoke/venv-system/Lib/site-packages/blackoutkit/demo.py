"""Read-only local demonstration and simulation report."""
from __future__ import annotations

import sys
from typing import Any, Iterable

from .capabilities import build_capability_matrix
from .config.manager import load_configs
from .routing import recommend_routes


GOLDEN_PATH = (
    "doctor --local-only",
    "capabilities",
    "route",
    "config or upstream setup",
    "ready",
    "connect",
)


def _plain_settings(settings: dict[str, Any] | None) -> dict[str, Any]:
    if settings is not None:
        return dict(settings)
    from . import settings as cfg

    return dict(cfg._load_plain_settings())


def _installed_components(installed: dict[str, bool] | None) -> dict[str, bool]:
    if installed is not None:
        return {str(key): bool(value) for key, value in installed.items()}
    from .downloader import check_installed

    return check_installed()


def _saved_configs(configs: Iterable[Any] | None) -> list[Any]:
    return list(configs) if configs is not None else load_configs()


def _route_rows(settings: dict[str, Any], installed: dict[str, bool], configs: list[Any], platform: str):
    return recommend_routes(
        settings,
        installed=installed,
        protocols={str(config.protocol).lower() for config in configs},
        configs=configs,
        stability_scores={},
        platform=platform,
    )


def build_demo_report(
    *,
    platform: str | None = None,
    settings: dict[str, Any] | None = None,
    installed: dict[str, bool] | None = None,
    configs: Iterable[Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic simulation without starting or probing anything."""
    current_platform = platform or sys.platform
    values = _plain_settings(settings)
    components = _installed_components(installed)
    saved = _saved_configs(configs)
    candidates = _route_rows(values, components, saved, current_platform)
    recommended = next((item for item in candidates if item.ready), candidates[0] if candidates else None)
    matrix = build_capability_matrix(
        current_platform,
        settings=values,
        installed=components,
        configs=saved,
    )

    return {
        "mode": "demo",
        "simulation_only": True,
        "platform": current_platform,
        "capabilities": matrix,
        "installed_components": {
            key: bool(value) for key, value in sorted(components.items())
        },
        "saved_config_count": len(saved),
        "route": {
            "recommended": recommended.engine if recommended else None,
            "candidates": [
                {
                    "engine": item.engine,
                    "ready": bool(item.ready),
                    "blockers": list(item.blockers),
                    "evidence": item.evidence,
                }
                for item in candidates
            ],
        },
        "local_readiness": {
            "evaluated": False,
            "detail": "Demo reports capability blockers only; configured ports and daemon state were not probed.",
        },
        "golden_path": list(GOLDEN_PATH),
        "network_actions": [],
        "system_mutations": [],
        "process_actions": [],
        "next_steps": [
            "Run `blackout setup` for the guided local checklist.",
            "Add a trusted upstream configuration when the selected capability requires one.",
            "Run `blackout ready <engine>` before an explicit connection.",
        ],
    }


__all__ = ["GOLDEN_PATH", "build_demo_report"]
