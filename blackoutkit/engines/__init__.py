"""
Blackout Kit — Engine registry and discovery.

Rare upgrades:
  - ENGINE_REGISTRY: maps engine name → class (single source of truth)
  - get_engine(name): returns an engine class by string name
  - list_engines(): returns (name, description) for every engine
  - engine_names(): returns sorted list of all valid engine name strings

This replaces scattered `if engine == "sni": SNIEngine()` patterns in cli.py
with a single registry lookup: get_engine("sni")().
"""

from .sni        import SNIEngine
from .xray       import XRayEngine
from .gdpi       import GoodbyeDPIEngine
from .psiphon    import PsiphonEngine
from .warp       import WARPEngine
from .tun        import TUNEngine
from .tor        import TorEngine
from .mhrv       import MhrvEngine
from .ikev2      import IKEv2Engine
from .wireguard  import WireGuardEngine
from .openvpn    import OpenVPNEngine
from .softether  import SoftEtherEngine
from .neighbor   import NeighborShareEngine, NeighborConnectEngine
from .appsscript import AppsScriptEngine
from .singbox_proxy import SingBoxProxyEngine
from .base       import Engine

# ──────────────────────────── Registry ───────────────────────────────────────
# Single source of truth: engine name → engine class.
# Add new engines here — nothing else needs updating.

ENGINE_REGISTRY: dict[str, type[Engine]] = {
    "sni":        SNIEngine,
    "xray":       XRayEngine,
    "gdpi":       GoodbyeDPIEngine,
    "psiphon":    PsiphonEngine,
    "warp":       WARPEngine,
    "tun":        TUNEngine,
    "tor":        TorEngine,
    "mhrv":       MhrvEngine,
    "ikev2":      IKEv2Engine,
    "wireguard":  WireGuardEngine,
    "openvpn":    OpenVPNEngine,
    "softether":  SoftEtherEngine,
    "neighbor":   NeighborShareEngine,
    "appsscript": AppsScriptEngine,
    "hysteria2":  SingBoxProxyEngine,
    "tuic":       SingBoxProxyEngine,
}


# ──────────────────────────── Public helpers ─────────────────────────────────

def get_engine(name: str) -> type[Engine]:
    """
    Return the engine class for the given name string.

    Raises ValueError with a helpful message if the name is not recognised.

    Usage:
        EngineClass = get_engine("sni")
        instance    = EngineClass()
        instance.start()
    """
    cls = ENGINE_REGISTRY.get(name.lower())
    if cls is None:
        valid = ", ".join(sorted(ENGINE_REGISTRY))
        raise ValueError(
            f"Unknown engine '{name}'. Valid engines: {valid}"
        )
    return cls


def list_engines() -> list[tuple[str, str]]:
    """
    Return a list of (name, description) for every registered engine,
    sorted alphabetically by name.

    Usage:
        for name, desc in list_engines():
            print(f"{name:12} {desc}")
    """
    return [
        (name, cls.description)
        for name, cls in sorted(ENGINE_REGISTRY.items())
    ]


def engine_names() -> list[str]:
    """Return a sorted list of all valid engine name strings."""
    return sorted(ENGINE_REGISTRY.keys())


# ──────────────────────────── Public API ─────────────────────────────────────

__all__ = [
    # Engine classes
    "SNIEngine", "XRayEngine", "GoodbyeDPIEngine",
    "PsiphonEngine", "WARPEngine", "TUNEngine", "TorEngine",
    "MhrvEngine", "IKEv2Engine",
    "WireGuardEngine", "OpenVPNEngine", "SoftEtherEngine",
    "NeighborShareEngine", "NeighborConnectEngine",
    "AppsScriptEngine",
    "Engine",
    # Registry & helpers
    "ENGINE_REGISTRY",
    "get_engine",
    "list_engines",
    "engine_names",
]
