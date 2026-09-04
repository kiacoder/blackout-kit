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


def monitor(daemon_pid: int, generation: str | None = None):
    if not generation:
        return False

    from blackoutkit.daemon import LEASE_FILE, LIFECYCLE_LOCK_FILE

    lease = read_lease(LEASE_FILE)
    if not lease or lease["pid"] != daemon_pid or lease["generation"] != generation:
        return False
    identity = process_identity_state(daemon_pid, lease["create_time"])
    if identity is False and not process_is_gone(daemon_pid, lease["create_time"]):
        return False
    if identity is None:
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
