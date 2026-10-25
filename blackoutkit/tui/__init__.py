# blackoutkit/tui/__init__.py
"""Blackout Console - full-screen Textual TUI for Blackout Kit.

This package is present in every install, but the Textual dependency is an
optional extra (`pip install blackout-kit[tui]`). Every entry point funnels
through console_available()/launch_console(), which fail soft to the legacy
terminal experience when Textual is missing or stdout is not a TTY.
"""
from __future__ import annotations

import sys


def _import_textual():
    try:
        import textual  # noqa: F401
    except Exception:
        return None
    return textual


def console_available() -> bool:
    """True only when Textual is importable and stdout is an interactive TTY."""
    if _import_textual() is None:
        return False
    try:
        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    return True


def launch_console() -> int:
    """Run the Console. Returns 0 on normal exit, 2 when unavailable."""
    if not console_available():
        print(
            "Blackout Console requires an interactive terminal and the [tui] extra:\n"
            "  pip install blackout-kit[tui]\n"
            "Falling back is safe: plain `blackout` commands are unchanged."
        )
        return 2
    from .app import BlackoutConsole

    BlackoutConsole().run()
    return 0
