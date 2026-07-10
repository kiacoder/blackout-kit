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

def monitor(daemon_pid: int):
    # Wait until the daemon dies
    try:
        proc = psutil.Process(daemon_pid)
        proc.wait()
    except psutil.NoSuchProcess:
        pass
    except Exception:
        # Fallback polling if wait() fails
        while psutil.pid_exists(daemon_pid):
            time.sleep(1)

    # Daemon has died. Check if we need to clean up.
    try:
        from blackoutkit.proxy_manager import clear_system_proxy
        clear_system_proxy()
    except Exception:
        pass

    # Also disable kill switch if active — prevents permanent internet block
    # after a crash/End Task. The daemon normally disables it on clean shutdown,
    # but on abrupt termination only the watchdog can do this.
    try:
        from blackoutkit.security import disable_kill_switch
        disable_kill_switch()
    except Exception:
        pass

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            pid = int(sys.argv[1])
            monitor(pid)
        except ValueError:
            pass
