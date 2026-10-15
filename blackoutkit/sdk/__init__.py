"""Blackout Kit Python SDK (Roadmap Phase 8).

Embed Blackout Kit in your own Python programs::

    from blackoutkit.sdk import Blackout

    bk = Blackout()
    bk.version
    bk.engines()
    bk.metrics()

See :class:`blackoutkit.sdk.client.Blackout` for the full surface. Every method
delegates to the same internals the CLI uses; only :meth:`Blackout.connect`
starts a network engine.
"""
from __future__ import annotations

from .client import Blackout
from .exceptions import (
    BlackoutError,
    DependencyError,
    EngineError,
    NotConnectedError,
    SettingsError,
)

__all__ = [
    "Blackout",
    "BlackoutError",
    "NotConnectedError",
    "EngineError",
    "SettingsError",
    "DependencyError",
]
