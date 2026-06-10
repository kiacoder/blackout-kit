"""
Blackout Kit — Advanced DPI bypass & censorship circumvention toolkit.

This package root exposes version metadata, shared path constants, and
version-check helpers so every sub-module can import them from one place
instead of re-defining them locally.

Rare upgrades:
  - Full metadata block (version, author, license, URL, Python requirement)
  - APP_DATA_DIR / PROJECT_ROOT shared path constants
  - get_version() — returns version tuple for comparison
  - check_version(minimum) — raises RuntimeError if version is too old
"""
from pathlib import Path

# ─────────────────────────── Package metadata ────────────────────────────────

__version__        = "1.0.1"
__author__         = "Kiacoder & contributors"
__description__    = "Advanced DPI bypass & censorship circumvention toolkit"
__license__        = "MIT"
__url__            = "https://github.com/kiacoder/blackout-kit"
__python_requires__ = ">=3.9"

# ─────────────────────────── Shared path constants ───────────────────────────
# Import from here instead of recomputing in every module.

import sys

APP_DATA_DIR = Path.home() / ".blackout-kit"

if getattr(sys, 'frozen', False):
    # Running as compiled PyInstaller executable
    # Use the folder where the .exe is as PROJECT_ROOT, or just use APP_DATA_DIR for everything
    PROJECT_ROOT = Path(sys.executable).parent
    BINS_DIR     = APP_DATA_DIR / "bins"
    DATA_DIR     = APP_DATA_DIR / "data"
    
    # Also define _MEIPASS for internal bundled assets
    _MEIPASS = Path(sys._MEIPASS)
else:
    # Running from source
    PROJECT_ROOT = Path(__file__).parent.parent
    BINS_DIR     = PROJECT_ROOT / "bins"
    DATA_DIR     = PROJECT_ROOT / "data"

# Ensure persistent directories exist
BINS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────── Version helpers ─────────────────────────────────

def get_version() -> tuple[int, int, int]:
    """Return the current version as a comparable integer tuple, e.g. (1, 0, 0)."""
    parts = __version__.split(".")
    try:
        return tuple(int(p) for p in parts[:3])   # type: ignore[return-value]
    except (ValueError, AttributeError):
        return (0, 0, 0)


def check_version(minimum: str) -> bool:
    """
    Return True if the installed version is at least `minimum`.

    Usage:
        from blackoutkit import check_version
        if not check_version("1.2.0"):
            raise RuntimeError("Please update Blackout Kit.")
    """
    min_parts = tuple(int(p) for p in minimum.split(".")[:3])
    return get_version() >= min_parts


# ─────────────────────────── Public API ──────────────────────────────────────

__all__ = [
    "__version__",
    "__author__",
    "__description__",
    "__license__",
    "__url__",
    "__python_requires__",
    "PROJECT_ROOT",
    "APP_DATA_DIR",
    "BINS_DIR",
    "DATA_DIR",
    "get_version",
    "check_version",
]
