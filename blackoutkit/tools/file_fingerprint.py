from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK_SIZE = 64 * 1024


def _result(status: str, target: Path, **details: str | int) -> dict:
    return {"status": status, "target": str(target), **details}


def _stat_snapshot(path: Path) -> tuple[int, int, int, int]:
    state = path.stat()
    return state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns


def fingerprint_file(path: str | Path) -> dict:
    target = Path(path).expanduser().resolve()
    if not target.is_file():
        return _result(
            "invalid-target",
            target,
            detail="Provide an existing regular file.",
        )

    try:
        before = _stat_snapshot(target)
        digest = hashlib.sha256()
        byte_count = 0
        with target.open("rb") as source:
            while chunk := source.read(CHUNK_SIZE):
                digest.update(chunk)
                byte_count += len(chunk)
        after = _stat_snapshot(target)
    except OSError as exc:
        return _result("read-error", target, detail=str(exc))

    if before != after:
        return _result(
            "changed-during-read",
            target,
            detail="The file changed while it was being read; no stable digest was produced.",
        )

    return _result(
        "fingerprinted",
        target,
        sha256=digest.hexdigest(),
        bytes=byte_count,
    )
