"""Exception hierarchy for the Blackout Kit Python SDK.

All errors raised by :class:`blackoutkit.sdk.Blackout` derive from
:class:`BlackoutError`, so callers can catch a single type::

    from blackoutkit.sdk import Blackout, BlackoutError

    try:
        Blackout().connect()
    except BlackoutError as exc:
        ...
"""
from __future__ import annotations

__all__ = [
    "BlackoutError",
    "NotConnectedError",
    "EngineError",
    "SettingsError",
    "DependencyError",
]


class BlackoutError(Exception):
    """Base class for every error raised by the SDK."""


class NotConnectedError(BlackoutError):
    """An operation requires a running daemon, but none is connected."""


class EngineError(BlackoutError):
    """An engine could not be started or stopped."""


class SettingsError(BlackoutError):
    """A setting is unknown or its value is invalid."""


class DependencyError(BlackoutError):
    """An optional dependency required for the operation is not installed."""
