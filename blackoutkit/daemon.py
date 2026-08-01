"""
Blackout Kit - Background daemon management.
Starts and stops engines as persistent background processes.
Stores PID and state in ~/.blackout-kit/
"""
import json
import logging
import logging.handlers
import os
import sys
import subprocess
import threading as _threading
import time
from pathlib import Path

APP_DATA_DIR = Path.home() / ".blackout-kit"
PID_FILE     = APP_DATA_DIR / "daemon.pid"
LOG_FILE     = APP_DATA_DIR / "daemon.log"
CRASH_LOG    = APP_DATA_DIR / "daemon.out"
STATE_FILE   = APP_DATA_DIR / "daemon_state.json"
LOCK_FILE    = APP_DATA_DIR / "daemon.lock"

_shutdown_requested = False


def _ensure_dir():
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)


def is_process_alive(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    import psutil
    return psutil.pid_exists(pid)


def get_pid() -> int | None:
    """Return the daemon PID if it is alive, else None."""
    if not PID_FILE.exists():
        return None
    try:
        raw = PID_FILE.read_text(encoding="utf-8-sig").strip()
        raw = raw.replace("\x00", "").strip()
        if not raw:
            return None
        pid = int(raw)
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

    # Atomic lock creation
    lock_path = APP_DATA_DIR / "daemon.start.lock"
    try:
        try:
            lock_path.mkdir(exist_ok=False)
        except FileExistsError:
            # If lock is old (e.g. 10s), assume it's stale and take it
            if time.time() - lock_path.stat().st_mtime > 10:
                try:
                    lock_path.rmdir()
                    lock_path.mkdir(exist_ok=False)
                except Exception:
                    # Someone else might have just taken it or deleted it
                    pass
            else:
                # Still locked by another 'start' command
                time.sleep(1)
                # One retry
                try:
                    lock_path.mkdir(exist_ok=False)
                except FileExistsError:
                    raise RuntimeError("Another 'blackout start' is in progress. Try again in a moment.")

        existing = get_pid()
        if existing:
            raise RuntimeError(f"Daemon already running (PID {existing}). Run 'blackout stop' first.")

        if getattr(sys, 'frozen', False):
            cmd = [sys.executable, "_daemon_run", "--engine", engine_name]
        else:
            entry = Path(__file__).parent.parent / "blackout.py"
            exe = sys.executable
            exe_w = exe.replace("python.exe", "pythonw.exe")
            if os.path.exists(exe_w):
                exe = exe_w
            cmd = [exe, str(entry), "_daemon_run", "--engine", engine_name]

        PID_FILE.unlink(missing_ok=True)
        STATE_FILE.unlink(missing_ok=True)
        
        ps_cmd = (
            f"$p = Start-Process -FilePath '{cmd[0]}' "
            f"-ArgumentList '{' '.join(cmd[1:])}' -WorkingDirectory '{os.getcwd()}' -Verb RunAs -WindowStyle Hidden -PassThru; "
            f"if ($p) {{ $p.Id | Out-File -FilePath '{PID_FILE}' -Encoding UTF8; "
            f"'{{\"engine\":\"{engine_name}\",\"pid\":' + $p.Id.ToString() + ',\"started\":\"' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '\"}}' | Out-File -FilePath '{STATE_FILE}' -Encoding UTF8 }}"
        )
        
        subprocess.run(
            ["powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", ps_cmd],
            creationflags=0x08000000
        )
        
        # Wait for PID_FILE (give user time to click UAC)
        for _ in range(600):
            if PID_FILE.exists():
                break
            time.sleep(0.1)
            
        pid = get_pid()
        if pid:
            return pid
        return 0
    finally:
        try:
            (APP_DATA_DIR / "daemon.start.lock").rmdir()
        except Exception:
            pass


def stop() -> bool:
    """
    Stop the running daemon and all its children.
    Returns True if a daemon was stopped.
    """
    pid = get_pid()
    if not pid:
        # Check for orphan lock file just in case
        LOCK_FILE.unlink(missing_ok=True)
        return False

    # Create a shutdown request file so the daemon gracefully exits
    (APP_DATA_DIR / "daemon.stop.request").touch(exist_ok=True)

    try:
        import psutil
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                child.terminate()
            except Exception:
                pass
        parent.terminate()
        # Wait a bit for it to cleanup
        try:
            parent.wait(timeout=3)
        except psutil.TimeoutExpired:
            parent.kill()
    except ImportError:
        try:
            import signal
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
    except Exception:
        pass

    PID_FILE.unlink(missing_ok=True)
    STATE_FILE.unlink(missing_ok=True)
    LOCK_FILE.unlink(missing_ok=True)
    return True


def get_state() -> dict | None:
    if not STATE_FILE.exists():
        return None
    try:
        raw = STATE_FILE.read_text(encoding="utf-8-sig").strip()
        raw = raw.replace("\x00", "").strip()
        data = json.loads(raw)
        # Verify that the PID in the state file is actually the one in PID_FILE
        # and that it is still alive.
        active_pid = get_pid()
        if not active_pid or data.get("pid") != active_pid:
            return None
        return data
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
    import os
    import sys
    global _shutdown_requested, cfg_lock
    cfg_lock = _threading.Lock()
    try:
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        sys.stderr = devnull
    except Exception:
        pass

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
    from .engines.singbox_proxy import Hysteria2Engine, TuicEngine
    from . import settings as cfg
    from . import security as sec
    from .proxy_manager import set_system_proxy, clear_system_proxy

    # Setup rotating logs
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
    ))
    
    log = logging.getLogger("blackout-daemon")
    log.setLevel(logging.INFO)
    log.addHandler(handler)
    # Also log to stderr so it goes to CRASH_LOG for debugging startup
    log.addHandler(logging.StreamHandler())

    # Spawn the watchdog process to handle forceful termination (End Task)
    try:
        watchdog_script = Path(__file__).parent / "watchdog.py"
        subprocess.Popen(
            [sys.executable, str(watchdog_script), str(os.getpid())],
            creationflags=0x08000000 | 0x00000008, # DETACHED_PROCESS | CREATE_NO_WINDOW
            close_fds=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log.info("Watchdog process spawned for proxy safety.")
    except Exception as e:
        log.warning(f"Failed to spawn watchdog: {e}")

    log.info(f"Daemon starting (PID {os.getpid()}). Engine: {engine_name}")

    ENGINE_MAP = {
        "sni":        lambda: (SNIEngine(), XRayEngine()),
        "xray":       lambda: (XRayEngine(),),
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
        "hysteria2":  lambda: (Hysteria2Engine(),),
        "tuic":       lambda: (TuicEngine(),),
        "legend":     lambda: (TorEngine(), SNIEngine(), XRayEngine()),
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
                # Treat any failure in the group as a full group failure.
                # e.g. SNI+XRay: SNI ok but XRay fails → proxy port never opens.
                # Stop already-started engines and let emergency mode try the next one.
                log.warning(
                    f"{eng.name} failed — rolling back partial group start."
                )
                for already_started in started:
                    try:
                        already_started.stop()
                    except Exception:
                        pass
                return []
        return started

    active_engine_name = engine_name
    if engine_name == "emergency":
        order = s.get("engine_order", ["sni", "gdpi", "psiphon"])
        active: list = []
        for ename in order:
            active = try_start_engines(ename)
            if active:
                log.info(f"Using engine: {ename}")
                active_engine_name = ename
                break
        if not active:
            log.error("All engines failed. Exiting daemon.")
            return
    else:
        active = try_start_engines(engine_name)
        if not active:
            log.error(f"Engine '{engine_name}' failed. Exiting.")
            return

    # Set system proxy (point at active engine proxy/port)
    if s.get("auto_set_proxy", True):
        proxy_info = cfg.get_engine_proxy_details(active_engine_name, s)
        if proxy_info:
            p_host, p_port = proxy_info
            if set_system_proxy(p_host, p_port):
                log.info(f"System proxy set to {p_host}:{p_port}")
            else:
                log.warning("Could not set system proxy (run as admin?)")
        else:
            log.info("Network-level engine active — no system proxy needed.")

    # Start system tray integration
    try:
        from .tray import start_tray
        import threading
        
        def _on_tray_stop():
            log.info("Tray requested shutdown.")
            global _shutdown_requested
            _shutdown_requested = True

        tray_thread = threading.Thread(target=start_tray, args=(active_engine_name, _on_tray_stop), daemon=True)
        tray_thread.start()
        log.info("System tray initialized.")
    except Exception as e:
        log.warning(f"Failed to start system tray: {e}")

    log.info("Daemon running. Monitoring engines...")
    retry_interval   = s.get("retry_interval", 30)
    max_restarts     = s.get("max_retries", 3)
    restart_count    = 0


    my_pid = os.getpid()
    try:
        while True:
            # Sleep in small increments to respond to shutdown requests faster
            for _ in range(retry_interval):
                time.sleep(1)
                if _shutdown_requested:
                    break
            
            if _shutdown_requested:
                break

            if (APP_DATA_DIR / "daemon.stop.request").exists():
                log.info("Shutdown request received from CLI. Exiting cleanly.")
                (APP_DATA_DIR / "daemon.stop.request").unlink(missing_ok=True)
                break

            # Stability check: Ensure we still own the PID file.
            # If someone else started a daemon, we should exit to avoid conflicts.
            try:
                if PID_FILE.exists():
                    current_raw = PID_FILE.read_text(encoding="utf-8-sig").strip().replace("\x00", "")
                    current_pid = int(current_raw) if current_raw else 0
                    if current_pid != my_pid:
                        log.warning(f"PID file changed (new PID {current_pid}). Exiting to avoid conflict.")
                        break
                else:
                    # Re-assert ourselves if the file was accidentally deleted
                    PID_FILE.write_text(str(my_pid))
            except Exception:
                pass

            # Check if any engine crashed
            alive = [e for e in active if e.is_running()]
            if not alive:
                if restart_count >= max_restarts:
                    log.error(
                        "All engines stopped and max restart attempts (%d) exhausted. "
                        "Exiting daemon.",
                        max_restarts,
                    )
                    break
                log.warning(
                    "All engines stopped unexpectedly. "
                    "Attempting restart %d/%d...",
                    restart_count + 1, max_restarts,
                )
                # Clean up any stragglers before restarting
                for eng in active:
                    try:
                        eng.stop()
                    except Exception:
                        pass
                active = try_start_engines(active_engine_name)
                restart_count += 1
                if not active:
                    log.error("Restart #%d failed. Exiting daemon.", restart_count)
                    break
                log.info(
                    "Engine restarted successfully (attempt %d/%d).",
                    restart_count, max_restarts,
                )
                # Update state file so 'blackout status' shows accurate info
                try:
                    STATE_FILE.write_text(json.dumps({
                        "engine":   active_engine_name,
                        "pid":      active[0].pid if active[0].pid else -1,
                        "started":  time.strftime("%Y-%m-%d %H:%M:%S"),
                        "restarts": restart_count,
                    }))
                except Exception:
                    pass
                continue  # Skip latency check this cycle — restart just happened
            # Connectivity probe + stability tracking
            with cfg_lock:
                pinfo = cfg.get_engine_proxy_details(active_engine_name, s)
            if pinfo:
                p_host, p_port = pinfo
                if isinstance(p_host, str) and p_host.startswith("socks="):
                    p_host = p_host.split("=", 1)[1]
                from .scanner.proxy_tester import test_tcp_port
                latency = test_tcp_port(p_host, p_port)
            else:
                latency = None

            try:
                sec.record_latency(active_engine_name, latency)
            except Exception:
                pass

            if latency is None:
                log.warning("Proxy port closed — engine may have crashed.")
                if restart_count < max_restarts:
                    log.warning("Attempting restart %d/%d...", restart_count+1, max_restarts+1)
                    for eng in active:
                        try:
                            eng.stop()
                        except Exception:
                            pass
                    active = try_start_engines(active_engine_name)
                    restart_count += 1
                    if not active:
                        log.error("Restart #%d failed.", restart_count)
                    else:
                        log.info("Engine restarted (attempt %d/%d).", restart_count, max_restarts)
                        try:
                            STATE_FILE.write_text(json.dumps({
                                "engine":   active_engine_name,
                                "pid":      active[0].pid if active[0].pid else -1,
                                "started":  time.strftime("%Y-%m-%d %H:%M:%S"),
                                "restarts": restart_count,
                            }))
                        except Exception:
                            pass
                        continue  # Skip rest of the loop iteration
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
