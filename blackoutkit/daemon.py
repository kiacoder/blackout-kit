"""
Blackout Kit - Background daemon management.
Starts and stops engines as persistent background processes.
Stores PID and state in ~/.blackout-kit/
"""
import json
import logging
import os
import sys
import subprocess
import time
from pathlib import Path

APP_DATA_DIR = Path.home() / ".blackout-kit"
PID_FILE     = APP_DATA_DIR / "daemon.pid"
LOG_FILE     = APP_DATA_DIR / "daemon.log"
STATE_FILE   = APP_DATA_DIR / "daemon_state.json"


def _ensure_dir():
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)


def is_process_alive(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def get_pid() -> int | None:
    """Return the daemon PID if it is alive, else None."""
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text().strip())
        if is_process_alive(pid):
            return pid
        PID_FILE.unlink(missing_ok=True)
        return None
    except Exception:
        return None


def start(engine_name: str) -> int:
    """
    Launch a background daemon process for the given engine.
    Returns the PID of the spawned process.
    Raises RuntimeError if a daemon is already running.
    """
    _ensure_dir()
    existing = get_pid()
    if existing:
        raise RuntimeError(f"Daemon already running (PID {existing}). Run 'blackout stop' first.")

    entry = Path(__file__).parent.parent / "blackout.py"

    cmd = [sys.executable, str(entry), "_daemon_run", "--engine", engine_name]

    log_file = open(LOG_FILE, "w", encoding="utf-8")

    kwargs = {
        "stdout": log_file,
        "stderr": subprocess.STDOUT,
        "close_fds": True,
    }

    if sys.platform == "win32":
        DETACHED      = 0x00000008  # DETACHED_PROCESS
        NO_WINDOW     = 0x08000000  # CREATE_NO_WINDOW
        NEW_GROUP     = 0x00000200  # CREATE_NEW_PROCESS_GROUP
        kwargs["creationflags"] = DETACHED | NO_WINDOW | NEW_GROUP
    else:
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **kwargs)

    PID_FILE.write_text(str(proc.pid))
    STATE_FILE.write_text(json.dumps({
        "engine":    engine_name,
        "pid":       proc.pid,
        "started":   time.strftime("%Y-%m-%d %H:%M:%S"),
    }))

    return proc.pid


def stop() -> bool:
    """
    Stop the running daemon and all its children.
    Returns True if a daemon was stopped.
    """
    pid = get_pid()
    if not pid:
        return False

    try:
        import psutil
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            child.terminate()
        parent.terminate()
    except ImportError:
        try:
            import signal
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
    except Exception:
        pass

    PID_FILE.unlink(missing_ok=True)
    return True


def get_state() -> dict | None:
    if not STATE_FILE.exists():
        return None
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return None


def read_logs(lines: int = 50) -> str:
    if not LOG_FILE.exists():
        return "(no logs yet)"
    content = LOG_FILE.read_text(encoding="utf-8", errors="replace")
    all_lines = content.splitlines()
    return "\n".join(all_lines[-lines:])


# ─────────────────────────── Daemon runner ───────────────────────
# This function is called by the background process itself.

def run_daemon_loop(engine_name: str):
    """
    Internal: runs inside the background process.
    Starts the requested engine(s) and monitors them.
    """
    from .engines.sni       import SNIEngine
    from .engines.xray      import XRayEngine
    from .engines.gdpi      import GoodbyeDPIEngine
    from .engines.psiphon   import PsiphonEngine
    from .engines.warp      import WARPEngine
    from .engines.tun       import TUNEngine
    from .engines.tor       import TorEngine
    from .engines.mhrv      import MhrvEngine
    from .engines.ikev2     import IKEv2Engine
    from .engines.wireguard import WireGuardEngine
    from .engines.openvpn   import OpenVPNEngine
    from .engines.softether import SoftEtherEngine
    from . import settings as cfg
    from . import security as sec
    from .proxy_manager import set_system_proxy, clear_system_proxy

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger("blackout-daemon")
    log.info(f"Daemon starting. Engine: {engine_name}")

    ENGINE_MAP = {
        "sni":        lambda: (SNIEngine(), XRayEngine()),
        "gdpi":       lambda: (GoodbyeDPIEngine(),),
        "psiphon":    lambda: (PsiphonEngine(),),
        "warp":       lambda: (WARPEngine(),),
        "tun":        lambda: (TUNEngine(),),
        "tor":        lambda: (TorEngine(),),
        "mhrv":       lambda: (MhrvEngine(),),
        "ikev2":      lambda: (IKEv2Engine(),),
        "wireguard":  lambda: (WireGuardEngine(),),
        "openvpn":    lambda: (OpenVPNEngine(),),
        "softether":  lambda: (SoftEtherEngine(),),
    }

    s = cfg.load()

    def try_start_engines(name: str) -> list:
        factory = ENGINE_MAP.get(name)
        if not factory:
            log.warning(f"Unknown engine: {name}")
            return []
        engines = list(factory())
        started = []
        for eng in engines:
            if eng.start():
                log.info(f"{eng.name} started (PID {eng.pid})")
                started.append(eng)
            else:
                log.warning(f"{eng.name} failed to start (binary not in bins/?)")
        return started

    if engine_name == "emergency":
        order = s.get("engine_order", ["sni", "gdpi", "psiphon"])
        active: list = []
        for ename in order:
            active = try_start_engines(ename)
            if active:
                log.info(f"Using engine: {ename}")
                break
        if not active:
            log.error("All engines failed. Exiting daemon.")
            return
    else:
        active = try_start_engines(engine_name)
        if not active:
            log.error(f"Engine '{engine_name}' failed. Exiting.")
            return

    # Set system proxy (point at XRay HTTP port)
    if s.get("auto_set_proxy", True):
        if set_system_proxy(s["proxy_host"], s["proxy_port"]):
            log.info(f"System proxy set to {s['proxy_host']}:{s['proxy_port']}")
        else:
            log.warning("Could not set system proxy (run as admin?)")

    log.info("Daemon running. Monitoring engines...")
    retry_interval = s.get("retry_interval", 30)
    # Track which engine stack is active (for stability logging)
    active_engine_name = engine_name if engine_name != "emergency" else (
        active[0].name if active else "unknown"
    )

    try:
        while True:
            time.sleep(retry_interval)

            # Check if any engine crashed
            alive = [e for e in active if e.is_running()]
            if not alive:
                log.warning("All engines stopped unexpectedly.")
                break

            # Connectivity probe + stability tracking
            from .scanner.proxy_tester import test_tcp_port
            latency = test_tcp_port("127.0.0.1", s["xray_http_port"])
            try:
                sec.record_latency(active_engine_name, latency)
            except Exception:
                pass

            if latency is None:
                log.warning("HTTP proxy port closed — engine may have crashed.")
            else:
                log.info(f"Heartbeat OK — proxy latency: {latency:.0f}ms")

            # Kill switch: if proxy went down and kill switch is on, block traffic
            if latency is None and s.get("kill_switch", False):
                log.warning("Kill switch active — blocking traffic until proxy recovers.")

    except KeyboardInterrupt:
        pass
    finally:
        log.info("Daemon shutting down. Stopping engines...")
        for eng in active:
            eng.stop()
        # Disable kill switch on clean exit so user isn't left with blocked internet
        if s.get("kill_switch", False):
            try:
                sec.disable_kill_switch()
                log.info("Kill switch disabled.")
            except Exception:
                pass
        if s.get("auto_set_proxy", True):
            clear_system_proxy()
            log.info("System proxy cleared.")
        log.info("Done.")
