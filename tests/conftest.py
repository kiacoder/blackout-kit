"""
Pytest session bootstrap for Blackout Kit.

Many modules compute their state directory at *import time*::

    APP_DATA_DIR = Path.home() / ".blackout-kit"

If the test suite runs with the real ``HOME``/``USERPROFILE``, every test that
touches settings, the vault, the cert store, automation rules, etc. would read
and write the developer's real ``~/.blackout-kit`` — leaking state between runs
and risking clobbering real credentials.

To prevent that, this conftest redirects ``HOME`` / ``USERPROFILE`` / ``TMPDIR``
(and the common XDG locations) to an isolated temporary directory **before** any
test module (and therefore ``blackoutkit``) is imported. Because pytest imports
``tests/conftest.py`` while collecting the ``tests/`` package, the environment is
already rewritten by the time ``import blackoutkit`` executes at the top of each
test module, so ``Path.home()`` resolves into the sandbox.
"""
from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

# ── Isolate the home / temp dirs before any module reads Path.home() ──
# mkdtemp() runs against the *original* TMPDIR, so the sandbox root itself lives
# in the real temp (harmless); everything written under it is what we redirect.
_ISOLATED_HOME = Path(tempfile.mkdtemp(prefix="blackout-test-home-"))
_ISOLATED_HOME.mkdir(parents=True, exist_ok=True)


def _apply_isolation() -> None:
    os.environ["HOME"] = str(_ISOLATED_HOME)
    # Windows resolves Path.home() from USERPROFILE.
    os.environ["USERPROFILE"] = str(_ISOLATED_HOME)
    # Drives tempfile.gettempdir() (and thus pytest's tmp_path base).
    os.environ["TMPDIR"] = str(_ISOLATED_HOME)
    os.environ.setdefault("TMP", str(_ISOLATED_HOME))
    os.environ.setdefault("TEMP", str(_ISOLATED_HOME))
    # A few modules probe XDG locations on Linux; keep those in the sandbox too.
    os.environ["XDG_CONFIG_HOME"] = str(_ISOLATED_HOME / "xdg-config")
    os.environ["XDG_DATA_HOME"] = str(_ISOLATED_HOME / "xdg-data")
    os.environ["XDG_CACHE_HOME"] = str(_ISOLATED_HOME / "xdg-cache")
    (_ISOLATED_HOME / "xdg-config").mkdir(parents=True, exist_ok=True)
    (_ISOLATED_HOME / "xdg-data").mkdir(parents=True, exist_ok=True)
    (_ISOLATED_HOME / "xdg-cache").mkdir(parents=True, exist_ok=True)


_apply_isolation()


def _cleanup_isolated_home() -> None:
    shutil.rmtree(_ISOLATED_HOME, ignore_errors=True)


atexit.register(_cleanup_isolated_home)


import pytest


@pytest.fixture(scope="session", autouse=True)
def _isolate_runtime_state():
    """Re-assert the sandbox for the whole session.

    Acts as a belt-and-suspenders guarantee: even if a future plugin or conftest
    were to import ``blackoutkit`` before this module's top-level code runs, the
    env vars stay pinned, and the sandbox directory is ensured to exist.
    """
    _apply_isolation()
    _ISOLATED_HOME.mkdir(parents=True, exist_ok=True)
    yield
    # Best-effort sweep of any state written under the sandbox during the run.
    for child in (".blackout-kit", "configs.enc", "secrets.enc"):
        p = _ISOLATED_HOME / child
        if p.exists():
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
