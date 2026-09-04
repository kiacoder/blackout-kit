"""
Blackout Kit — Config package public API.

Re-exports the most useful names from config.manager so callers can write:

    from blackoutkit.config import load_configs, add_config, ProxyConfig

instead of the longer:

    from blackoutkit.config.manager import load_configs, add_config, ProxyConfig

Rare upgrades:
  - Clean public re-exports (no need to know about the manager sub-module)
  - get_active_config(): returns the first saved config, or None
  - config_count(): returns number of saved configs
  - has_configs(): quick boolean check — useful in preflight / doctor
"""

from .manager import (
    ProxyConfig,
    add_config,
    duplicate_config_indexes,
    import_and_merge,
    import_from_subscription,
    load_configs,
    parse_v2ray_uri,
    remove_config,
    replace_config,
    save_configs,
    validate_configs,
)


def get_active_config() -> "ProxyConfig | None":
    """
    Return the first saved config, or None if no configs are saved.

    Useful for quick checks:
        if get_active_config() is None:
            console.print("[warning]No configs saved — run: blackout config add <uri>[/warning]")
    """
    configs = load_configs()
    return configs[0] if configs else None


def config_count() -> int:
    """Return the number of saved V2Ray configs."""
    return len(load_configs())


def has_configs() -> bool:
    """Return True if at least one config is saved."""
    return config_count() > 0


__all__ = [
    # From manager
    "ProxyConfig",
    "add_config",
    "config_count",
    "duplicate_config_indexes",
    # Package-level helpers
    "get_active_config",
    "has_configs",
    "import_and_merge",
    "import_from_subscription",
    "load_configs",
    "parse_v2ray_uri",
    "remove_config",
    "replace_config",
    "save_configs",
    "validate_configs",
]
