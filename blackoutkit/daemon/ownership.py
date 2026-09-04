"""Generation-scoped daemon ownership and process-identity helpers."""
from __future__ import annotations

import json
import math
import os
import secrets
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path


class OwnershipBusy(RuntimeError):
    """A lifecycle lock is held by a process that cannot be reclaimed safely."""


def process_create_time(pid: int) -> float | None:
    try:
        import psutil
    except ImportError:
        return None
    try:
        return float(psutil.Process(pid).create_time())
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError, ValueError, TypeError):
        return None


def process_identity_state(pid: object, expected_create_time: object) -> bool | None:
    """Return true for the same process, false for a different/gone process."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return None
    try:
        expected = float(expected_create_time)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(expected):
        return None
    try:
        import psutil
    except ImportError:
        return None
    try:
        actual = float(psutil.Process(pid).create_time())
    except psutil.NoSuchProcess:
        return False
    except (psutil.AccessDenied, psutil.ZombieProcess, OSError, ValueError, TypeError):
        return None
    return abs(actual - expected) < 0.001


def process_is_gone(pid: int, expected_create_time: object) -> bool:
    """Return true only when identity is different and the PID is no longer live."""
    state = process_identity_state(pid, expected_create_time)
    if state is True or state is None:
        return False
    try:
        import psutil
        return not psutil.pid_exists(pid)
    except (ImportError, OSError):
        return False


def new_generation() -> str:
    return secrets.token_urlsafe(32)


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, separators=(",", ":"))
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _owner_record(payload: dict | None) -> dict | None:
    if payload is None:
        return None
    pid = payload.get("pid")
    generation = payload.get("generation")
    create_time = payload.get("create_time")
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 0
        or not isinstance(generation, str)
        or not generation
        or len(generation) > 256
    ):
        return None
    try:
        create_time = float(create_time)
        schema_version = int(payload.get("schema_version", 1))
    except (TypeError, ValueError):
        return None
    if not math.isfinite(create_time):
        return None
    return {
        "schema_version": schema_version,
        "pid": pid,
        "generation": generation,
        "create_time": create_time,
    }


def read_lease(path: Path) -> dict | None:
    return _owner_record(_read_json(path))


def _lock_owner(payload: dict | None) -> dict | None:
    if payload is None:
        return None
    owner = _owner_record({**payload, "generation": payload.get("token")})
    if owner is None:
        return None
    owner["token"] = payload.get("token")
    return owner if isinstance(owner["token"], str) and owner["token"] else None


def _owner_is_gone(payload: dict | None) -> bool:
    owner = _lock_owner(payload)
    return bool(owner and process_is_gone(owner["pid"], owner["create_time"]))


def _lock_lifecycle_fd(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_lifecycle_fd(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def lifecycle_lock(path: Path) -> Iterator[None]:
    """Serialize lifecycle mutations with a kernel-released advisory lock."""
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(16)
    current_pid = os.getpid()
    current_create_time = process_create_time(current_pid)
    if current_create_time is None:
        raise OwnershipBusy("Could not establish lifecycle process identity.")
    payload = {
        "schema_version": 1,
        "pid": current_pid,
        "create_time": current_create_time,
        "token": token,
    }
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, b" ")
            _lock_lifecycle_fd(fd)
        except Exception:
            os.close(fd)
            raise
    except (OSError, ImportError) as exc:
        raise OwnershipBusy("Lifecycle lock is active or unavailable.") from exc

    try:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, encoded)
        yield
    finally:
        try:
            _unlock_lifecycle_fd(fd)
        finally:
            os.close(fd)


def write_lease(lease_path: Path, lock_path: Path, generation: str, pid: int) -> bool:
    """Claim a generation for a PID, never replacing a live different owner."""
    create_time = process_create_time(pid)
    if create_time is None or not isinstance(generation, str) or not generation or len(generation) > 256:
        return False
    try:
        with lifecycle_lock(lock_path):
            current = read_lease(lease_path)
            if current:
                state = process_identity_state(current["pid"], current["create_time"])
                if current["generation"] == generation and current["pid"] == pid and state is True:
                    return True
                if state is not False or not process_is_gone(current["pid"], current["create_time"]):
                    return False
            _write_json_atomic(
                lease_path,
                {
                    "schema_version": 1,
                    "pid": pid,
                    "generation": generation,
                    "create_time": create_time,
                },
            )
            return True
    except (OSError, OwnershipBusy):
        return False


def claim_lease(lease_path: Path, lock_path: Path, generation: str, pid: int | None = None) -> bool:
    return write_lease(lease_path, lock_path, generation, os.getpid() if pid is None else pid)


def lease_matches(lease_path: Path, generation: str, pid: int | None = None) -> bool:
    pid = os.getpid() if pid is None else pid
    current = read_lease(lease_path)
    return bool(
        current
        and current["pid"] == pid
        and current["generation"] == generation
        and process_identity_state(pid, current["create_time"]) is True
    )


def release_lease(lease_path: Path, lock_path: Path, generation: str, pid: int | None = None) -> bool:
    pid = os.getpid() if pid is None else pid
    try:
        with lifecycle_lock(lock_path):
            current = read_lease(lease_path)
            if not current or current["pid"] != pid or current["generation"] != generation:
                return False
            if process_identity_state(pid, current["create_time"]) is not True:
                return False
            lease_path.unlink(missing_ok=True)
            return True
    except (OSError, OwnershipBusy):
        return False




def perform_watchdog_cleanup(
    lease_path: Path,
    lock_path: Path,
    pid: int,
    generation: str,
    cleanup: Callable[[], None],
    metadata_cleanup: Callable[[], None] | None = None,
) -> bool:
    """Run cleanup only after the exact leased process has exited."""
    try:
        with lifecycle_lock(lock_path):
            current = read_lease(lease_path)
            if not current or current["pid"] != pid or current["generation"] != generation:
                return False
            if not process_is_gone(pid, current["create_time"]):
                return False
            cleanup()
            if read_lease(lease_path) != current:
                return False
            if metadata_cleanup is not None:
                metadata_cleanup()
            if read_lease(lease_path) == current:
                lease_path.unlink(missing_ok=True)
                return True
            return False
    except (OSError, OwnershipBusy) as e:
        print("perform_watchdog_cleanup raised", e)
        return False


def acquire_start_lock(path: Path) -> str:
    """Create a start lock and reclaim only a lock owned by a gone process."""
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(16)
    pid = os.getpid()
    create_time = process_create_time(pid)
    if create_time is None:
        raise RuntimeError("Could not establish start process identity.")
    owner = {"schema_version": 1, "pid": pid, "create_time": create_time, "token": token}
    for _attempt in range(3):
        try:
            path.mkdir(exist_ok=False)
        except FileExistsError:
            current = _read_json(path / "owner.json")
            if current is None:
                raise RuntimeError("Daemon start lock is unreadable; refusing to alter daemon state.")
            if not _owner_is_gone(current):
                raise RuntimeError("Another 'blackout start' is in progress. Try again in a moment.")
            try:
                (path / "owner.json").unlink(missing_ok=True)
                path.rmdir()
            except OSError:
                raise RuntimeError("Another 'blackout start' is in progress. Try again in a moment.")
            continue
        else:
            try:
                _write_json_atomic(path / "owner.json", owner)
            except Exception:
                try:
                    path.rmdir()
                except OSError:
                    pass
                raise
            return token
    raise RuntimeError("Could not acquire the daemon start lock.")


def release_start_lock(path: Path, token: str) -> None:
    owner_path = path / "owner.json"
    try:
        current = _read_json(owner_path)
        if current and current.get("token") == token:
            owner_path.unlink(missing_ok=True)
            path.rmdir()
    except (OSError, ValueError, TypeError, AttributeError):
        pass
