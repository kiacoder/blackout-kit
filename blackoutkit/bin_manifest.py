"""SHA-256 manifest for managed engine binaries.

Downloads already verify the GitHub asset digest, but nothing re-checks the
file after it lands in ``bins/``. A process that can write that directory can
swap ``xray.exe`` for its own payload and have it launched - possibly under a
later UAC elevation. This module pins the hash of every binary the first time
it is seen (trust on first use) and refuses to launch one whose bytes changed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

from . import BINS_DIR

_log = logging.getLogger(__name__)

MANIFEST_FILE = BINS_DIR / ".manifest.json"


def _manifest_path() -> Path:
    return MANIFEST_FILE


def _load() -> dict[str, str]:
    try:
        data = json.loads(_manifest_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def _save(entries: dict[str, str]) -> None:
    try:
        _manifest_path().parent.mkdir(parents=True, exist_ok=True)
        temporary = _manifest_path().with_suffix(".tmp")
        temporary.write_text(json.dumps(entries, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(temporary, _manifest_path())
    except OSError as exc:
        _log.warning("Could not persist the binary manifest: %s", exc)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _key(path: Path) -> str:
    try:
        return path.resolve().relative_to(BINS_DIR.resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def record(path: Path) -> str | None:
    """Pin (or refresh) the hash of one binary. Returns the hash, or None."""
    try:
        digest = sha256_file(path)
    except OSError as exc:
        _log.warning("Could not hash %s: %s", path, exc)
        return None
    entries = _load()
    entries[_key(path)] = digest
    _save(entries)
    return digest


def verify(path: Path) -> tuple[bool, str]:
    """Check one binary against the manifest.

    - recorded and matching  -> (True, "")
    - recorded and differing -> (False, "hash mismatch ...")
    - not recorded yet       -> pin it now (TOFU) and allow
    """
    if not path.is_file():
        return False, "binary is missing"
    try:
        digest = sha256_file(path)
    except OSError as exc:
        return False, f"cannot read binary: {exc}"

    entries = _load()
    key = _key(path)
    expected = entries.get(key)
    if expected is None:
        entries[key] = digest
        _save(entries)
        _log.debug("Pinned %s at %s (first use)", key, digest[:12])
        return True, ""
    if expected != digest:
        return False, (
            f"hash mismatch for {key}: expected {expected[:16]}…, found {digest[:16]}…"
        )
    return True, ""


def verify_all() -> list[tuple[str, bool, str]]:
    """Verify every binary the manifest knows about. Returns (name, ok, detail)."""
    results: list[tuple[str, bool, str]] = []
    for key in sorted(_load()):
        path = BINS_DIR / key
        ok, detail = verify(path)
        results.append((key, ok, detail))
    return results
