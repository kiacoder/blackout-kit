"""
Blackout Kit — Network security and bypass toolkit.

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

__version__        = "1.1.1"
__author__         = "Kiacoder & contributors"
__description__    = "Network security and bypass toolkit"
__license__        = "MIT"
__url__            = "https://github.com/kiacoder/blackout-kit"
__python_requires__ = ">=3.10"

# ─────────────────────────── Shared path constants ───────────────────────────
# Import from here instead of recomputing in every module.

import sys

APP_DATA_DIR = Path.home() / ".blackout-kit"

if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).parent
    BINS_DIR = APP_DATA_DIR / "bins"
    DATA_DIR = APP_DATA_DIR / "data"
    _MEIPASS = Path(sys._MEIPASS)
else:
    PROJECT_ROOT = Path(__file__).parent.parent
    source_data_dir = PROJECT_ROOT / "data"
    source_checkout = (PROJECT_ROOT / "blackout.py").is_file()
    if source_checkout:
        BINS_DIR = PROJECT_ROOT / "bins"
        DATA_DIR = source_data_dir
    else:
        BINS_DIR = APP_DATA_DIR / "bins"
        DATA_DIR = APP_DATA_DIR / "data"

def resource_path(relative_path: str) -> Path:
    """Return a bundled or source resource path without exposing package internals."""
    relative = Path(relative_path)
    package_relative = Path("resources") / relative if relative.parts and relative.parts[0] in {"data", "assets"} else relative
    candidates = []
    if getattr(sys, "frozen", False):
        candidates.extend(
            (
                _MEIPASS / relative,
                _MEIPASS / package_relative,
                _MEIPASS / "blackoutkit" / package_relative,
            )
        )
    else:
        source_resource = PROJECT_ROOT / relative
        if (PROJECT_ROOT / "data" / "configs.txt").is_file():
            candidates.append(source_resource)
        candidates.extend(
            (
                Path(__file__).parent / package_relative,
                Path(__file__).parent / relative,
                source_resource,
                Path(sys.prefix) / relative,
            )
        )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0] if candidates else relative



def ensure_frozen_resources() -> None:
    """Copy bundled mutable data into the user data directory when frozen."""
    if not getattr(sys, "frozen", False):
        return
    import shutil

    bundled_data_candidates = (
        _MEIPASS / "data",
        _MEIPASS / "blackoutkit" / "resources" / "data",
    )
    bundled_data = next((path for path in bundled_data_candidates if path.exists()), None)
    if bundled_data is None:
        return
    for source in bundled_data.iterdir():
        if not source.is_file() or source.name == "configs.txt":
            continue
        destination = DATA_DIR / source.name
        if not destination.exists() or destination.stat().st_size != source.stat().st_size:
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            except OSError:
                continue

    bundled_assets_candidates = (
        _MEIPASS / "assets",
        _MEIPASS / "blackoutkit" / "resources" / "assets",
    )
    bundled_assets = next((path for path in bundled_assets_candidates if path.exists()), None)
    if bundled_assets is None:
        return
    for source in bundled_assets.iterdir():
        if not source.is_file():
            continue
        destination = DATA_DIR / "assets" / source.name
        if not destination.exists() or destination.stat().st_size != source.stat().st_size:
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            except OSError:
                continue


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
    "APP_DATA_DIR",
    "BINS_DIR",
    "DATA_DIR",
    "PROJECT_ROOT",
    "__author__",
    "__description__",
    "__license__",
    "__python_requires__",
    "__url__",
    "__version__",
    "check_version",
    "ensure_frozen_resources",
    "get_version",
    "resource_path",
]
