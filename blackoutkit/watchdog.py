"""
Blackout Kit - Watchdog process.
Monitors the daemon PID. If the daemon process exits abruptly (e.g., End Task),
this watchdog instantly unsets the Windows system proxy to restore internet.
"""
import sys
import time
from pathlib import Path

import psutil

# Ensure blackoutkit is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from blackoutkit.daemon.ownership import (
    perform_watchdog_cleanup,
    process_identity_state,
    process_is_gone,
    read_lease,
)


def _watchdog_log(message: str) -> None:
    """Record why the watchdog bailed.

    stdout/stderr are DEVNULL when the daemon spawns us, so a bare
    ``return False`` used to vanish without a trace — leaving the machine
    blackholed with no explanation. Append to the daemon log instead.
    """
    try:
        from datetime import datetime, timezone

        from blackoutkit.daemon import LOG_FILE

        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} [WARNING] watchdog: {message}\n")
    except Exception:
        pass


def monitor(daemon_pid: int, generation: str | None = None):
    if not generation:
        _watchdog_log(f"no generation for daemon pid {daemon_pid} — exiting without protection")
        return False

    from blackoutkit.daemon import LEASE_FILE, LIFECYCLE_LOCK_FILE

    lease = read_lease(LEASE_FILE)
    if not lease or lease["pid"] != daemon_pid or lease["generation"] != generation:
        _watchdog_log(
            f"lease mismatch for pid {daemon_pid} (lease={lease}) — exiting without protection"
        )
        return False
    identity = process_identity_state(daemon_pid, lease["create_time"])
    if identity is False and not process_is_gone(daemon_pid, lease["create_time"]):
        _watchdog_log(f"daemon pid {daemon_pid} identity mismatch — exiting without protection")
        return False
    if identity is None:
        _watchdog_log(f"cannot determine identity of pid {daemon_pid} — exiting without protection")
        return False

    try:
        proc = psutil.Process(daemon_pid)
        proc.wait()
    except psutil.NoSuchProcess:
        pass
    except Exception:
        while psutil.pid_exists(daemon_pid):
            current = read_lease(LEASE_FILE)
            if not current or current["pid"] != daemon_pid or current["generation"] != generation:
                return False
            identity = process_identity_state(daemon_pid, current["create_time"])
            if identity is not True:
                return False
            time.sleep(1)

    current = read_lease(LEASE_FILE)
    if not current or current["pid"] != daemon_pid or current["generation"] != generation:
        return False

    def cleanup_owned_state():
        from blackoutkit.proxy_manager import cleanup_owned_system_proxy
        try:
            cleanup_owned_system_proxy()
        except Exception:
            pass
        try:
            from blackoutkit.security import disable_kill_switch
            disable_kill_switch()
        except Exception:
            pass
        if sys.platform.startswith("linux"):
            try:
                from blackoutkit import linux_network
                linux_network.delete_owned_tunnel()
            except Exception:
                pass
            try:
                from blackoutkit import linux_network
                linux_network.flush_dns_cache()
            except Exception:
                pass

    def cleanup_metadata():
        import json

        from blackoutkit.daemon import PID_FILE, STATE_FILE
        try:
            if PID_FILE.exists():
                raw = PID_FILE.read_text(encoding="utf-8-sig").replace("\x00", "").strip()
                if raw and int(raw) == daemon_pid:
                    PID_FILE.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            if STATE_FILE.exists():
                data = json.loads(STATE_FILE.read_text(encoding="utf-8-sig").strip())
                if isinstance(data, dict) and data.get("pid") == daemon_pid and data.get("generation") == generation:
                    STATE_FILE.unlink(missing_ok=True)
        except Exception:
            pass

    return perform_watchdog_cleanup(
        LEASE_FILE,
        LIFECYCLE_LOCK_FILE,
        daemon_pid,
        generation,
        cleanup_owned_state,
        metadata_cleanup=cleanup_metadata,
    )


if __name__ == "__main__":
    if len(sys.argv) > 2:
        try:
            monitor(int(sys.argv[1]), sys.argv[2])
        except ValueError:
            pass
