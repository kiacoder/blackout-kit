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
cfg_lock = None


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
        (APP_DATA_DIR / "daemon.stop.request").unlink(missing_ok=True)

        if sys.platform.startswith("linux"):
            process = subprocess.Popen(
                cmd,
                cwd=os.getcwd(),
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            PID_FILE.write_text(str(process.pid), encoding="utf-8")
            STATE_FILE.write_text(
                json.dumps({
                    "engine": engine_name,
                    "pid": process.pid,
                    "started": time.strftime("%Y-%m-%d %H:%M:%S"),
                }),
                encoding="utf-8",
            )
            return process.pid

        ADMIN_REQUIRED_ENGINES = {"gdpi", "warp", "tun"}
        verb_clause = "-Verb RunAs " if engine_name in ADMIN_REQUIRED_ENGINES else ""

        args_ps = ", ".join(f"'{a}'" for a in cmd[1:])
        ps_cmd = (
            f"$p = Start-Process -FilePath '{cmd[0]}' "
            f"-ArgumentList @({args_ps}) -WorkingDirectory '{os.getcwd()}' {verb_clause}-WindowStyle Hidden -PassThru; "
            f"if ($p) {{ $p.Id | Out-File -FilePath '{PID_FILE}' -Encoding UTF8; "
            f"'{{\"engine\":\"{engine_name}\",\"pid\":' + $p.Id.ToString() + ',\"started\":\"' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '\"}}' | Out-File -FilePath '{STATE_FILE}' -Encoding UTF8 }}"
        )

        subprocess.run(
            ["powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", ps_cmd],
            creationflags=0x08000000,
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
        if data.get("engine") == "gdpi":
            try:
                from . import settings as cfg
                data["engine"] = _engine_state_payload_name("gdpi", cfg)
            except Exception:
                pass
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

def _engine_state_payload_name(engine_name: str, cfg_module) -> str:
    if engine_name == "gdpi":
        backend = str(cfg_module.load().get("gdpi_backend", "legacy")).lower()
        return f"gdpi[{backend}]"
    return engine_name


def _reconnect_delay(attempt: int, initial_delay: int, maximum_delay: int) -> int:
    """Return the capped exponential wait before the next reconnect attempt."""
    return min(initial_delay * (2 ** max(attempt - 1, 0)), maximum_delay)


def _daemon_shutdown_requested(daemon_pid: int) -> bool:
    """Return whether this daemon should stop without disturbing another daemon."""
    if _shutdown_requested or (APP_DATA_DIR / "daemon.stop.request").exists():
        return True
    try:
        if not PID_FILE.exists():
            PID_FILE.write_text(str(daemon_pid), encoding="utf-8")
            return False
        raw = PID_FILE.read_text(encoding="utf-8-sig").strip().replace("\x00", "")
        if not raw:
            PID_FILE.write_text(str(daemon_pid), encoding="utf-8")
            return False
        return int(raw) != daemon_pid
    except Exception:
        return False


def _wait_for_daemon_delay(delay_seconds: int, daemon_pid: int) -> bool:
    """Wait in one-second increments; False means shutdown or PID ownership changed."""
    for _ in range(max(0, int(delay_seconds))):
        if _daemon_shutdown_requested(daemon_pid):
            return False
        time.sleep(1)
    return not _daemon_shutdown_requested(daemon_pid)


def _write_daemon_state(
    engine_name: str,
    cfg_module,
    daemon_pid: int,
    *,
    restarts: int,
    status: str,
    last_failure: str | None = None,
    next_retry_delay: int | None = None,
    started: str | None = None,
) -> None:
    """Persist a state snapshot owned by the daemon, not an individual engine."""
    _ensure_dir()
    state = {
        "engine": _engine_state_payload_name(engine_name, cfg_module),
        "pid": daemon_pid,
        "started": started or time.strftime("%Y-%m-%d %H:%M:%S"),
        "restarts": restarts,
        "status": status,
        "last_failure": last_failure,
        "next_retry_delay": next_retry_delay,
    }
    try:
        temporary = STATE_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(state), encoding="utf-8")
        os.replace(temporary, STATE_FILE)
    except Exception:
        pass


def run_daemon_loop(engine_name: str):
    """
    Internal: runs inside the background process.
    Starts the requested engine(s) and monitors them.
    """
    import os
    import sys
    global cfg_lock, _shutdown_requested
    _shutdown_requested = False
    cfg_lock = _threading.Lock()
    try:
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        sys.stderr = devnull
    except Exception:
        pass

    from .engines.xray import XRayEngine
    from .engines.tun import TUNEngine
    from .engines.singbox_proxy import Hysteria2Engine, TuicEngine

    if sys.platform == "win32":
        from .engines.sni import SNIEngine
        from .engines.gdpi import GoodbyeDPIEngine
        from .engines.psiphon import PsiphonEngine
        from .engines.warp import WARPEngine
        from .engines.tor import TorEngine
        from .engines.mhrv import MhrvEngine
        from .engines.ikev2 import IKEv2Engine
        from .engines.wireguard import WireGuardEngine
        from .engines.openvpn import OpenVPNEngine
        from .engines.softether import SoftEtherEngine
    else:
        SNIEngine = GoodbyeDPIEngine = PsiphonEngine = WARPEngine = None
        TorEngine = MhrvEngine = IKEv2Engine = WireGuardEngine = None
        OpenVPNEngine = SoftEtherEngine = None
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

    # Spawn the watchdog process to handle forceful termination (End Task).
    try:
        watchdog_script = Path(__file__).parent / "watchdog.py"
        watchdog_kwargs = {
            "close_fds": True,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            watchdog_kwargs["creationflags"] = 0x08000000 | 0x00000008
        else:
            watchdog_kwargs["start_new_session"] = True
        subprocess.Popen(
            [sys.executable, str(watchdog_script), str(os.getpid())],
            **watchdog_kwargs,
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
        "tun":        lambda: (XRayEngine(), TUNEngine()) if sys.platform.startswith("linux") else (TUNEngine(),),
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

    if sys.platform.startswith("linux"):
        ENGINE_MAP = {
            name: factory
            for name, factory in ENGINE_MAP.items()
            if name in {"xray", "tun", "hysteria2", "tuic"}
        }
    s = cfg.load()

    def try_start_engines(name: str) -> list:
        factory = ENGINE_MAP.get(name)
        if not factory:
            log.warning(f"Unknown engine: {name}")
            return []
        from . import readiness
        checks = readiness.evaluate(name, allow_active_daemon=True)
        blockers = [check.detail for check in checks if check.blocking and not check.ok]
        if blockers:
            log.warning("Local readiness blocked %s: %s", name, "; ".join(blockers))
            return []

        linux_kill_switch = sys.platform.startswith("linux") and s.get("kill_switch", False)
        if linux_kill_switch and not sec.prepare_linux_kill_switch(name):
            log.error("Could not resolve a safe Linux kill-switch endpoint for %s.", name)
            return []
        if linux_kill_switch and not sec.enable_kill_switch(name):
            log.error("Linux kill switch could not be enabled for %s; refusing to start the tunnel.", name)
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
                if linux_kill_switch:
                    sec.disable_kill_switch()
                    sec.clear_linux_kill_switch_endpoint(name)
                return []
        return started

    active_engine_name = engine_name
    if engine_name == "emergency":
        order = (
            ["tun", "xray", "hysteria2", "tuic"]
            if sys.platform.startswith("linux")
            else s.get("engine_order", ["sni", "gdpi", "psiphon"])
        )
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
    retry_interval = s.get("retry_interval", 30)
    max_restarts = s.get("max_retries", 3)
    initial_reconnect_delay = s.get("reconnect_initial_delay", 2)
    maximum_reconnect_delay = s.get("reconnect_max_delay", 60)
    restart_count = 0
    my_pid = os.getpid()
    daemon_started = time.strftime("%Y-%m-%d %H:%M:%S")
    _write_daemon_state(
        active_engine_name,
        cfg,
        my_pid,
        restarts=restart_count,
        status="connected",
        started=daemon_started,
    )

    def _stop_active_engines() -> None:
        nonlocal active
        for eng in active:
            try:
                eng.stop()
            except Exception:
                pass
        active = []

    def _reconnect(failure_reason: str) -> bool:
        nonlocal active, restart_count
        while restart_count < max_restarts:
            if _daemon_shutdown_requested(my_pid):
                return False
            _stop_active_engines()
            restart_count += 1
            log.warning(
                "%s Restart attempt %d/%d.",
                failure_reason,
                restart_count,
                max_restarts,
            )
            active = try_start_engines(active_engine_name)
            if active:
                _write_daemon_state(
                    active_engine_name,
                    cfg,
                    my_pid,
                    restarts=restart_count,
                    status="connected",
                    started=daemon_started,
                )
                log.info("Engine restarted successfully (attempt %d/%d).", restart_count, max_restarts)
                return True

            if restart_count >= max_restarts:
                break

            next_delay = _reconnect_delay(
                restart_count,
                initial_reconnect_delay,
                maximum_reconnect_delay,
            )
            _write_daemon_state(
                active_engine_name,
                cfg,
                my_pid,
                restarts=restart_count,
                status="reconnecting",
                last_failure=failure_reason,
                next_retry_delay=next_delay,
                started=daemon_started,
            )
            log.warning("Restart attempt %d/%d failed; retrying in %ds.", restart_count, max_restarts, next_delay)
            if restart_count == 1:
                try:
                    from . import tools
                    tools.run_network_recovery(from_daemon=True)
                    log.info("Applied targeted daemon recovery after failed restart.")
                except Exception as exc:
                    log.warning("Targeted daemon recovery failed: %s", exc)
            if not _wait_for_daemon_delay(next_delay, my_pid):
                return False

        _write_daemon_state(
            active_engine_name,
            cfg,
            my_pid,
            restarts=restart_count,
            status="failed",
            last_failure=failure_reason,
            started=daemon_started,
        )
        log.error("Reconnect attempts exhausted after %d failure(s).", restart_count)
        return False

    try:
        while _wait_for_daemon_delay(retry_interval, my_pid):
            alive = [engine for engine in active if engine.is_running()]
            if not alive:
                if not _reconnect("All engines stopped unexpectedly."):
                    break
                continue

            with cfg_lock:
                proxy_info = cfg.get_engine_proxy_details(active_engine_name, s)
            if proxy_info:
                proxy_host, proxy_port = proxy_info
                if isinstance(proxy_host, str) and proxy_host.startswith("socks="):
                    proxy_host = proxy_host.split("=", 1)[1]
                from .scanner.proxy_tester import test_tcp_port
                latency = test_tcp_port(proxy_host, proxy_port)
                try:
                    sec.record_latency(active_engine_name, latency)
                except Exception:
                    pass
                if latency is None:
                    log.warning("Proxy port closed — engine may have crashed.")
                    if not _reconnect("Proxy port closed."):
                        break
                    continue
                log.info(f"Heartbeat OK — proxy latency: {latency:.0f}ms")
            else:
                log.debug("Network-level engine has no proxy port; skipping proxy health probe.")

            if restart_count:
                log.info("Healthy heartbeat received; reconnect budget reset.")
            restart_count = 0
            _write_daemon_state(
                active_engine_name,
                cfg,
                my_pid,
                restarts=restart_count,
                status="connected",
                started=daemon_started,
            )

    except KeyboardInterrupt:
        pass
    finally:
        if (APP_DATA_DIR / "daemon.stop.request").exists():
            (APP_DATA_DIR / "daemon.stop.request").unlink(missing_ok=True)
        log.info("Daemon shutting down. Stopping engines...")
        _stop_active_engines()
        if s.get("kill_switch", False):
            try:
                sec.disable_kill_switch()
                sec.clear_linux_kill_switch_endpoint()
                log.info("Kill switch disabled.")
            except Exception:
                pass
        if s.get("auto_set_proxy", True):
            clear_system_proxy()
            log.info("System proxy cleared.")
        log.info("Done.")
