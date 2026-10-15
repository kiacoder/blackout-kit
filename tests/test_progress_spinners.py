"""Phase 5 — CLI progress spinners.

Progress UI already existed for the four roadmap targets:
  * ``bins download``  → Rich progress bar (theme.create_download_progress)
  * ``media watch``    → live table
  * ``torrent watch``  → live table
  * ``tools capture``  → rich.live.Live panel
This locks the reusable spinner helpers so the wiring keeps working.
"""
from __future__ import annotations

from rich.progress import Progress

from blackoutkit.theme import create_download_progress, spinner


def test_theme_spinner_is_a_context_manager():
    entered = False
    with spinner("Testing…"):
        entered = True
    assert entered


def test_create_download_progress_returns_progress():
    p = create_download_progress()
    assert isinstance(p, Progress)
    # A spinner column must be present for the "spinner" requirement.
    column_types = {type(c).__name__ for c in p.columns}
    assert "SpinnerColumn" in column_types


def test_progress_module_spinner_smoke():
    from blackoutkit.progress import spinner as progress_spinner

    with progress_spinner("Loading…"):
        pass
