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
import tempfile
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
_shutdown_lock = _threading.Lock()
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


def _watchdog_command(pid: int) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "_watchdog", str(pid)]
    watchdog_script = Path(__file__).parent.parent / "watchdog.py"
    return [sys.executable, str(watchdog_script), str(pid)]


def start(engine_name: str, env_overrides: dict[str, str] | None = None) -> int:
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
            try:
                lock_mtime = lock_path.stat().st_mtime
            except FileNotFoundError:
                # Another process deleted it between the FileExistsError and stat() call
                lock_mtime = 0
            if time.time() - lock_mtime > 10:
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
            entry = Path(__file__).parent.parent.parent / "blackout.py"
            exe = sys.executable
            exe_w = exe.replace("python.exe", "pythonw.exe")
            if os.path.exists(exe_w):
                exe = exe_w
            if entry.exists():
                cmd = [exe, str(entry), "_daemon_run", "--engine", engine_name]
            else:
                cmd = [exe, "-m", "blackoutkit.typer_cli", "_daemon_run", "--engine", engine_name]
        if env_overrides:
            cmd.extend(["--env-overrides-json", json.dumps(env_overrides, separators=(",", ":"))])

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
            # Atomic write of PID file
            fd, tmp_path = tempfile.mkstemp(dir=APP_DATA_DIR, text=True)
            try:
                with os.fdopen(fd, 'w') as f:
                    f.write(str(process.pid))
                os.replace(tmp_path, str(PID_FILE))
            except Exception:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

            # Atomic write of STATE file
            fd, tmp_path = tempfile.mkstemp(dir=APP_DATA_DIR, text=True)
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump({
                        "engine": engine_name,
                        "pid": process.pid,
                        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }, f)
                os.replace(tmp_path, str(STATE_FILE))
            except Exception:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            return process.pid

        ADMIN_REQUIRED_ENGINES = {"gdpi", "warp", "tun"}
        verb_clause = "-Verb RunAs " if engine_name in ADMIN_REQUIRED_ENGINES else ""

        # Build safe environment variables instead of string interpolation
        env_for_ps = {
            **os.environ,
            "BLACKOUT_EXE": cmd[0],
            "BLACKOUT_ARGS": subprocess.list2cmdline(cmd[1:]),
            "BLACKOUT_WORKDIR": os.getcwd(),
            "BLACKOUT_ENGINE": engine_name,
            "BLACKOUT_PID_FILE": str(PID_FILE),
            "BLACKOUT_STATE_FILE": str(STATE_FILE),
        }

        ps_cmd = (
            "$p = Start-Process -FilePath $env:BLACKOUT_EXE "
            "-ArgumentList $env:BLACKOUT_ARGS -WorkingDirectory $env:BLACKOUT_WORKDIR " + verb_clause +
            "-WindowStyle Hidden -PassThru; "
            "if ($p) { $p.Id | Out-File -FilePath $env:BLACKOUT_PID_FILE -Encoding UTF8; "
            "@{engine=$env:BLACKOUT_ENGINE;pid=$p.Id;started=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')} | ConvertTo-Json | Out-File -FilePath $env:BLACKOUT_STATE_FILE -Encoding UTF8 }"
        )

        try:
            subprocess.run(
                ["powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", ps_cmd],
                creationflags=0x08000000,
                env=env_for_ps,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            import logging
            logging.warning("Daemon startup via PowerShell timed out (120s) — UAC prompt may still be pending")

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

    ipc_file = APP_DATA_DIR / "daemon.ipc"
    if ipc_file.exists():
        try:
            port = int(ipc_file.read_text().strip())
            import socket
            with socket.create_connection(("127.0.0.1", port), timeout=2.0) as conn:
                conn.sendall(b"STOP\n")
            # Wait for graceful shutdown
            for _ in range(30):
                if not ipc_file.exists():
                    return True
                time.sleep(0.1)
        except Exception as e:
            import logging
            logging.debug("Graceful daemon shutdown via IPC failed: %s", e)

    # Create a shutdown request file as fallback
    (APP_DATA_DIR / "daemon.stop.request").touch(exist_ok=True)

    try:
        import psutil
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                child.terminate()
            except Exception as e:
                import logging
                logging.debug("Failed to terminate child process %s: %s", child.pid, e)
        parent.terminate()
        # Wait a bit for it to cleanup
        try:
            parent.wait(3)
        except psutil.TimeoutExpired:
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except Exception as e:
                    import logging
                    logging.debug("Failed to kill child process %s: %s", child.pid, e)
            parent.kill()
    except ImportError:
        import ctypes
        import logging
        PROCESS_TERMINATE = 1
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if handle:
            result = ctypes.windll.kernel32.TerminateProcess(handle, -1)
            if not result:
                logging.warning("TerminateProcess returned false for PID %d", pid)
            ctypes.windll.kernel32.CloseHandle(handle)
        else:
            logging.warning("Could not open process handle for PID %d (may be already terminated)", pid)
    except Exception as e:
        import logging
        logging.debug("Process cleanup exception for PID %d: %s", pid, e)

    time.sleep(1)
    PID_FILE.unlink(missing_ok=True)
    LOCK_FILE.unlink(missing_ok=True)
    STATE_FILE.unlink(missing_ok=True)
    ipc_file.unlink(missing_ok=True)
    (APP_DATA_DIR / "daemon.stop.request").unlink(missing_ok=True)
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
                from .. import settings as cfg
                data["engine"] = _engine_state_payload_name("gdpi", cfg)
            except Exception:
                pass
        return data
    except Exception:
        return None


def read_logs(lines: int = 50) -> str:
    """Return the last N lines of the daemon log."""
    if not LOG_FILE.exists():
        return "No daemon logs available."
    try:
        content = LOG_FILE.read_text(encoding="utf-8", errors="replace")
        all_lines = content.splitlines()
        return "\n".join(all_lines[-lines:])
    except Exception as exc:
        return f"Could not read log file: {exc}"


def get_recent_events(lines: int = 5) -> list[str]:
    """Parse the daemon log for connection lifecycle events."""
    if not LOG_FILE.exists():
        return []
    try:
        content = LOG_FILE.read_text(encoding="utf-8", errors="replace")
        events = []
        for line in reversed(content.splitlines()):
            if "Starting engine" in line or "Daemon shutting down" in line or "stopped unexpectedly" in line or "Proxy port closed" in line or "Reconnecting" in line:
                # Strip out the typical format "YYYY-MM-DD HH:MM:SS,ms - INFO - "
                parts = line.split(" - ", 2)
                if len(parts) >= 3:
                    ts = parts[0].split(",")[0].split(" ")[1] # Just HH:MM:SS
                    msg = parts[2]
                    events.append(f"{ts} - {msg}")
                else:
                    events.append(line)
            if len(events) >= lines:
                break
        return list(reversed(events))
    except Exception:
        return []


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
    with _shutdown_lock:
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
    io_bytes: tuple[int, int] | None = None,
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
    if io_bytes is not None:
        state["io_bytes"] = io_bytes
    try:
        temporary = STATE_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(state), encoding="utf-8")
        os.replace(temporary, STATE_FILE)
    except Exception as e:
        import logging
        logging.warning("Failed to write daemon state file: %s", e)


def run_daemon_loop(engine_name: str, env_overrides_json: str | None = None):
    """
    Internal: runs inside the background process.
    Starts the requested engine(s) and monitors them.
    """
    env_overrides = {}
    if env_overrides_json:
        try:
            env_overrides = json.loads(env_overrides_json)
        except json.JSONDecodeError:
            env_overrides = {}
    for key, value in env_overrides.items():
        os.environ[key] = str(value)

    global cfg_lock, _shutdown_requested, _shutdown_lock
    with _shutdown_lock:
        _shutdown_requested = False
    cfg_lock = _threading.Lock()
    devnull = None
    try:
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        sys.stderr = devnull
    except Exception as e:
        logging.debug("Failed to redirect stdout/stderr to devnull: %s", e)
        if devnull is not None:
            try:
                devnull.close()
            except Exception as close_e:
                logging.debug("Failed to close devnull file: %s", close_e)

    from ..engines.xray import XRayEngine
    from ..engines.tun import TUNEngine
    from ..engines.singbox_proxy import Hysteria2Engine, TuicEngine
    from ..engines.amneziawg import AmneziaWGEngine

    if sys.platform == "win32":
        from ..engines.sni import SNIEngine
        from ..engines.gdpi import GoodbyeDPIEngine
        from ..engines.psiphon import PsiphonEngine
        from ..engines.warp import WARPEngine
        from ..engines.tor import TorEngine
        from ..engines.mhrv import MhrvEngine
        from ..engines.ikev2 import IKEv2Engine
        from ..engines.wireguard import WireGuardEngine
        from ..engines.openvpn import OpenVPNEngine
        from ..engines.softether import SoftEtherEngine
    else:
        SNIEngine = GoodbyeDPIEngine = PsiphonEngine = WARPEngine = None
        TorEngine = MhrvEngine = IKEv2Engine = WireGuardEngine = None
        OpenVPNEngine = SoftEtherEngine = None
    from .. import settings as cfg
    from .. import security as sec
    from ..proxy_manager import set_system_proxy, clear_system_proxy

    _ensure_dir()

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
        watchdog_kwargs = {
            "close_fds": True,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            watchdog_kwargs["creationflags"] = 0x08000000 | 0x00000008
        else:
            watchdog_kwargs["start_new_session"] = True
        subprocess.Popen(_watchdog_command(os.getpid()), **watchdog_kwargs)
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
        "awg":        lambda: (AmneziaWGEngine(),),
        "legend":     lambda: (TorEngine(), SNIEngine(), XRayEngine()),
    }

    if sys.platform.startswith("linux"):
        ENGINE_MAP = {
            name: factory
            for name, factory in ENGINE_MAP.items()
            if name in {"xray", "tun", "hysteria2", "tuic", "awg"}
        }
    s = cfg.load()

    def try_start_engines(name: str) -> list:
        factory = ENGINE_MAP.get(name)
        if not factory:
            log.warning(f"Unknown engine: {name}")
            return []
        from .. import readiness
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

        import concurrent.futures
        engines = list(factory())
        started = []
        failed = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(engines) if engines else 1) as executor:
            future_to_eng = {executor.submit(eng.start): eng for eng in engines}
            for future in concurrent.futures.as_completed(future_to_eng):
                eng = future_to_eng[future]
                try:
                    success = future.result()
                    if success:
                        log.info(f"{eng.name} started (PID {eng.pid})")
                        started.append(eng)
                    else:
                        failed = True
                except Exception as exc:
                    log.error(f"{eng.name} start exception: {exc}")
                    failed = True

        if failed or len(started) != len(engines):
            log.warning("One or more engines failed — rolling back partial group start.")
            for already_started in started:
                try:
                    already_started.stop()
                except Exception as e:
                    log.error("Failed to stop engine %s during rollback: %s", already_started.name, e)
            if linux_kill_switch:
                sec.disable_kill_switch()
                sec.clear_linux_kill_switch_endpoint(name)
            return []

        return engines

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
        from ..tray import start_tray
        import threading

        def _on_tray_stop():
            log.info("Tray requested shutdown.")
            global _shutdown_requested
            with _shutdown_lock:
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
            except Exception as e:
                log.error("Failed to stop engine %s: %s", eng.name, e)
        active = []

    def _reconnect(failure_reason: str) -> bool:
        nonlocal active, restart_count
        while restart_count < max_restarts:
            if _daemon_shutdown_requested(my_pid):
                return False
            _stop_active_engines()
            restart_count += 1

            if s.get("config_rotation", True):
                try:
                    current_offset = int(os.environ.get("BLACKOUT_CONFIG_OFFSET", "0"))
                except ValueError:
                    current_offset = 0
                os.environ["BLACKOUT_CONFIG_OFFSET"] = str(current_offset + 1)
                log.info(
                    "Config rotation: trying next saved config (offset %d → %d).",
                    current_offset, current_offset + 1,
                )

            log.warning(
                "%s Restart attempt %d/%d.",
                failure_reason,
                restart_count,
                max_restarts,
            )
            active = try_start_engines(active_engine_name)
            if active:
                os.environ.pop("BLACKOUT_CONFIG_OFFSET", None)
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
                    from .. import tools
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
        # Track previous run total bytes in case of engine restarts
        accumulated_rx = 0
        accumulated_tx = 0
        data_phase_failures = 0

        while _wait_for_daemon_delay(retry_interval, my_pid):
            alive = [engine for engine in active if engine.is_running()]
            if not alive:
                if not _reconnect("All engines stopped unexpectedly."):
                    break
                continue

            rx, tx = 0, 0
            try:
                import psutil
                for engine in alive:
                    if engine.pid:
                        try:
                            p = psutil.Process(engine.pid)
                            io = p.io_counters()
                            rx += io.read_bytes
                            tx += io.write_bytes
                        except (psutil.NoSuchProcess, psutil.ProcessError) as e:
                            log.debug("Could not get IO counters for engine PID %d: %s", engine.pid, e)
                        except Exception as e:
                            log.warning("Unexpected error getting IO counters for engine %s (PID %d): %s", engine.name, engine.pid, e)
            except ImportError:
                log.debug("psutil not available for IO counter collection")

            with cfg_lock:
                proxy_info = cfg.get_engine_proxy_details(active_engine_name, s)
            if proxy_info:
                proxy_host, proxy_port = proxy_info
                if isinstance(proxy_host, str) and proxy_host.startswith("socks="):
                    proxy_host = proxy_host.split("=", 1)[1]
                from ..scanner.proxy_tester import test_tcp_port
                latency = test_tcp_port(proxy_host, proxy_port)
                try:
                    sec.record_latency(active_engine_name, latency)
                except Exception as e:
                    log.debug("Failed to record latency for %s: %s", active_engine_name, e)
                if latency is None:
                    log.warning("Proxy port closed — engine may have crashed.")
                    if not _reconnect("Proxy port closed."):
                        break
                    continue

                if s.get("config_rotation", True):
                    from ..scanner.proxy_tester import test_http_proxy
                    http_latency = test_http_proxy(proxy_host, proxy_port, timeout=5)
                    if http_latency is None:
                        data_phase_failures += 1
                        log.warning(
                            "TCP port open but HTTP proxy dead (%d consecutive failure(s)) "
                            "— possible data-phase drop (endpoint may be blocked by TSPU).",
                            data_phase_failures,
                        )
                        if data_phase_failures >= 2:
                            log.warning("Data-phase drop confirmed — rotating to next config.")
                            data_phase_failures = 0
                            if not _reconnect("Data-phase drop (port open but no data flow)."):
                                break
                            continue
                    else:
                        if data_phase_failures:
                            log.info("HTTP proxy recovered after %d data-phase failure(s).", data_phase_failures)
                        data_phase_failures = 0

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
                io_bytes=(accumulated_rx + rx, accumulated_tx + tx)
            )

    except KeyboardInterrupt:
        log.info("Daemon received CTRL+C interrupt, initiating graceful shutdown.")
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
            except Exception as e:
                log.error("Failed to disable kill switch during shutdown: %s", e)
        if s.get("auto_set_proxy", True):
            clear_system_proxy()
            log.info("System proxy cleared.")
        log.info("Done.")
