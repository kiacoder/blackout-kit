"""Small process-identity guard for daemon lifecycle state."""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from .ownership import (
    acquire_start_lock,
    lease_matches,
    new_generation,
    perform_watchdog_cleanup,
    process_identity_state,
    read_lease,
    release_lease,
    release_start_lock,
    write_lease,
)


def start_lock(path: Path) -> tuple[str, Path]:
    token = acquire_start_lock(path)
    return token, path


def end_start_lock(token: str, path: Path) -> None:
    release_start_lock(path, token)


def make_generation() -> str:
    return new_generation()


def lease_path(app_data_dir: Path) -> Path:
    return app_data_dir / "daemon.lease.json"


def lifecycle_path(app_data_dir: Path) -> Path:
    return app_data_dir / "daemon.lifecycle.lock"


def register(app_data_dir: Path, pid: int, generation: str) -> bool:
    return write_lease(lease_path(app_data_dir), lifecycle_path(app_data_dir), generation, pid)


def current(app_data_dir: Path, pid: int | None = None) -> dict | None:
    lease = read_lease(lease_path(app_data_dir))
    if lease is None or (pid is not None and lease["pid"] != pid):
        return None
    state = process_identity_state(lease["pid"], lease["create_time"])
    return lease if state is True else None


def matches(app_data_dir: Path, pid: int, generation: str) -> bool:
    return lease_matches(lease_path(app_data_dir), generation, pid)


def release(app_data_dir: Path, pid: int, generation: str) -> bool:
    return release_lease(lease_path(app_data_dir), lifecycle_path(app_data_dir), generation, pid)


def cleanup_after_exit(
    app_data_dir: Path,
    pid: int,
    generation: str,
    cleanup: Callable[[], None],
) -> bool:
    return perform_watchdog_cleanup(
        lease_path(app_data_dir),
        lifecycle_path(app_data_dir),
        pid,
        generation,
        cleanup,
    )


def write_pid(path: Path, pid: int) -> None:
    path.write_text(str(pid), encoding="utf-8")


def read_pid(path: Path) -> int | None:
    try:
        pid = int(path.read_text(encoding="utf-8-sig").replace("\x00", "").strip())
    except (OSError, ValueError, TypeError):
        return None
    return pid if pid > 0 else None


def state_generation(path: Path) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    generation = data.get("generation") if isinstance(data, dict) else None
    return generation if isinstance(generation, str) and generation else None
