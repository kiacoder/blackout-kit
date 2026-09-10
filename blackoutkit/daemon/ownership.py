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
    if state is True:
        return False
    try:
        import psutil
        # If identity check succeeded (state is False), use psutil to confirm
        if state is False:
            return not psutil.pid_exists(pid)
        # If identity check failed (state is None), try psutil as fallback
        if state is None:
            if psutil.pid_exists(pid):
                return False
            return True
    except (ImportError, OSError):
        return False
    return False


def new_generation() -> str:
    return secrets.token_urlsafe(32)


def _write_json_atomic(path: Path, payload: dict) -> None:
    # Explicitly set permissions to 0o700 on Unix for security
    import sys
    path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        path.parent.chmod(0o700)
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
    """Create a start lock and reclaim only a lock owned by a gone process.

    Uses try/retry pattern for safe TOCTOU handling.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(16)
    pid = os.getpid()
    create_time = process_create_time(pid)
    if create_time is None:
        raise RuntimeError("Could not establish start process identity.")

    owner = {"schema_version": 1, "pid": pid, "create_time": create_time, "token": token}

    # Try up to 3 times to acquire the lock
    for attempt in range(3):
        try:
            # Try to create the lock directory (atomic on all platforms)
            path.mkdir(exist_ok=False)
            # Directory created successfully; we own the lock
            try:
                _write_json_atomic(path / "owner.json", owner)
            except Exception as e:
                try:
                    path.rmdir()
                except OSError:
                    pass
                raise RuntimeError(f"Could not write lock file: {e}") from e
            return token
        except FileExistsError:
            # Directory already exists; check if owner is gone
            current = _read_json(path / "owner.json")
            if current is None:
                # Lock file is corrupted/unreadable
                raise RuntimeError("Daemon start lock is unreadable; refusing to alter daemon state.")
            if _owner_is_gone(current):
                # Owner is gone; try to reclaim
                try:
                    (path / "owner.json").unlink(missing_ok=True)
                    path.rmdir()
                except OSError:
                    # Failed to reclaim; retry loop
                    continue
                # Successfully cleaned up stale lock; retry mkdir
                continue
            else:
                # Owner is still alive
                raise RuntimeError("Another 'blackout start' is in progress. Try again in a moment.")

    raise RuntimeError("Could not acquire the daemon start lock after retries.")


def release_start_lock(path: Path, token: str) -> None:
    owner_path = path / "owner.json"
    try:
        current = _read_json(owner_path)
        if current and current.get("token") == token:
            owner_path.unlink(missing_ok=True)
            path.rmdir()
    except (OSError, ValueError, TypeError, AttributeError):
        pass


def cleanup_stale_records(lock_dir: Path) -> None:
    """Remove ownership records from dead processes on daemon startup.

    Cleans up:
    - Stale daemon.start.lock from dead process
    - Stale daemon.lease.json from dead process
    - Stale PID file from dead process
    """
    lock_dir.mkdir(parents=True, exist_ok=True)

    # Clean up stale start lock
    start_lock_path = lock_dir / "daemon.start.lock"
    if start_lock_path.exists():
        owner = _lock_owner(_read_json(start_lock_path / "owner.json"))
        if owner and _owner_is_gone(owner):
            try:
                (start_lock_path / "owner.json").unlink(missing_ok=True)
                start_lock_path.rmdir()
            except OSError:
                pass

    # Clean up stale lease
    lease_path = lock_dir / "daemon.lease.json"
    if lease_path.exists():
        try:
            with lifecycle_lock(lock_dir / "daemon.lifecycle.lock"):
                lease = read_lease(lease_path)
                if lease and process_is_gone(lease["pid"], lease["create_time"]):
                    lease_path.unlink(missing_ok=True)
        except (OSError, OwnershipBusy):
            pass

    # Clean up stale PID file if process is gone
    pid_file = lock_dir / "daemon.pid"
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text(encoding="utf-8-sig").replace("\x00", "").strip())
            if pid > 0:
                import psutil
                if not psutil.pid_exists(pid):
                    pid_file.unlink(missing_ok=True)
        except (OSError, ValueError, ImportError):
            pass
