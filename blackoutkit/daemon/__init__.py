"""
Blackout Kit - Background daemon management.
Starts and stops engines as persistent background processes.
Stores PID and state in ~/.blackout-kit/
"""
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import tempfile
import threading as _threading
import time
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path

from .ownership import (
    OwnershipBusy,
    acquire_start_lock,
    lease_matches,
    lifecycle_lock,
    new_generation,
    process_identity_state,
    process_is_gone,
    read_lease,
    release_lease,
    release_start_lock,
    write_lease,
)

APP_DATA_DIR = Path.home() / ".blackout-kit"
PID_FILE     = APP_DATA_DIR / "daemon.pid"
LOG_FILE     = APP_DATA_DIR / "daemon.log"
CRASH_LOG    = APP_DATA_DIR / "daemon.out"
STATE_FILE   = APP_DATA_DIR / "daemon_state.json"
LOCK_FILE    = APP_DATA_DIR / "daemon.lock"
LEASE_FILE   = APP_DATA_DIR / "daemon.lease.json"
LIFECYCLE_LOCK_FILE = APP_DATA_DIR / "daemon.lifecycle.lock"


def _lease_path() -> Path:
    return APP_DATA_DIR / "daemon.lease.json"


def _lifecycle_path() -> Path:
    return APP_DATA_DIR / "daemon.lifecycle.lock"


def _read_pid_file() -> int | None:
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8-sig").replace("\x00", "").strip())
    except (OSError, ValueError, TypeError):
        return None
    return pid if pid > 0 else None


def _active_lease(pid: int | None = None) -> dict | None:
    lease = read_lease(_lease_path())
    if lease is None or (pid is not None and lease["pid"] != pid):
        return None
    return lease if process_identity_state(lease["pid"], lease["create_time"]) is True else None


def _register_lease(pid: int, generation: str) -> bool:
    return write_lease(_lease_path(), _lifecycle_path(), generation, pid)


def _lease_is_current(pid: int, generation: str) -> bool:
    return lease_matches(_lease_path(), generation, pid)


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
    """Return the daemon PID only when its lease identity is valid."""
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8-sig").replace("\x00", "").strip())
    except (OSError, ValueError, TypeError):
        return None
    lease = read_lease(_lease_path())
    if lease is None or lease["pid"] != pid:
        return None
    return pid if process_identity_state(pid, lease["create_time"]) is True else None


def _watchdog_command(pid: int, generation: str | None = None) -> list[str]:
    if getattr(sys, "frozen", False):
        command = [sys.executable, "_watchdog", str(pid)]
    else:
        watchdog_script = Path(__file__).parent.parent / "watchdog.py"
        command = [sys.executable, str(watchdog_script), str(pid)]
    return command if generation is None else [*command, generation]


def _write_pid_file(pid: int) -> None:
    _ensure_dir()
    fd, temporary = tempfile.mkstemp(dir=APP_DATA_DIR, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(str(pid))
        os.replace(temporary, PID_FILE)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _register_spawned_daemon(pid: int, generation: str) -> bool:
    if not write_lease(_lease_path(), _lifecycle_path(), generation, pid):
        return False
    try:
        _write_pid_file(pid)
    except OSError:
        release_lease(_lease_path(), _lifecycle_path(), generation, pid)
        return False
    return True


def _release_spawned_daemon(pid: int, generation: str) -> bool:
    return _clear_owned_metadata(pid, generation)


def _clear_owned_metadata(
    pid: int,
    generation: str,
    *,
    expected_create_time: object | None = None,
    require_gone: bool = False,
) -> bool:
    try:
        with lifecycle_lock(_lifecycle_path()):
            lease = read_lease(_lease_path())
            if not lease or lease["pid"] != pid or lease["generation"] != generation:
                return False
            if expected_create_time is not None:
                try:
                    if float(lease["create_time"]) != float(expected_create_time):
                        return False
                except (TypeError, ValueError):
                    return False
            identity = process_identity_state(pid, lease["create_time"])
            if require_gone:
                if not process_is_gone(pid, lease["create_time"]):
                    return False
            elif identity is not True:
                return False
            _lease_path().unlink(missing_ok=True)
            if _read_pid_file() == pid:
                PID_FILE.unlink(missing_ok=True)
            try:
                state = json.loads(STATE_FILE.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError, TypeError):
                state = None
            if isinstance(state, dict) and state.get("pid") == pid and state.get("generation") == generation:
                STATE_FILE.unlink(missing_ok=True)
            return True
    except (OSError, OwnershipBusy):
        return False


def _release_daemon_lease(pid: int, generation: str) -> bool:
    return _clear_owned_metadata(pid, generation)



def start(engine_name: str, env_overrides: dict[str, str] | None = None) -> int:
    """
    Launch a background daemon process for the given engine.
    Returns the PID of the spawned process.
    Raises RuntimeError if a daemon is already running.
    """
    _ensure_dir()

    lock_path = APP_DATA_DIR / "daemon.start.lock"
    lock_token = acquire_start_lock(lock_path)
    generation = new_generation()
    try:
        existing = get_pid()
        active_lease = _active_lease()
        if active_lease:
            raise RuntimeError(
                f"Daemon already running (PID {active_lease['pid']}). Run 'blackout stop' first."
            )
        if not existing:
            stale_pid = _read_pid_file()
            if stale_pid and is_process_alive(stale_pid):
                raise RuntimeError(
                    f"Daemon PID {stale_pid} is active but its ownership cannot be verified; refusing to replace it."
                )
        if existing:
            raise RuntimeError(f"Daemon already running (PID {existing}). Run 'blackout stop' first.")
        if read_lease(_lease_path()) is not None:
            raise RuntimeError("Daemon ownership is unreadable or stale; refusing to replace daemon state.")
        (APP_DATA_DIR / "daemon.stop.request").unlink(missing_ok=True)
        PID_FILE.unlink(missing_ok=True)
        STATE_FILE.unlink(missing_ok=True)

        if getattr(sys, 'frozen', False):
            cmd = [sys.executable, "_daemon_run", "--engine", engine_name, "--generation", generation]
        else:
            entry = Path(__file__).parent.parent.parent / "blackout.py"
            exe = sys.executable
            exe_w = exe.replace("python.exe", "pythonw.exe")
            if os.path.exists(exe_w):
                exe = exe_w
            if entry.exists():
                cmd = [exe, str(entry), "_daemon_run", "--engine", engine_name, "--generation", generation]
            else:
                cmd = [exe, "-m", "blackoutkit.typer_cli", "_daemon_run", "--engine", engine_name, "--generation", generation]
        if env_overrides:
            cmd.extend(["--env-overrides-json", json.dumps(env_overrides, separators=(",", ":"))])

        if sys.platform.startswith("linux"):
            process = subprocess.Popen(
                cmd,
                cwd=os.getcwd(),
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if not _register_spawned_daemon(process.pid, generation):
                if process.poll() is None:
                    process.terminate()
                raise RuntimeError("Could not establish daemon process ownership.")
            return process.pid

        ADMIN_REQUIRED_ENGINES = {"gdpi", "warp", "tun"}
        verb_clause = "-Verb RunAs " if engine_name in ADMIN_REQUIRED_ENGINES else ""

        env_for_ps = {
            **os.environ,
            "BLACKOUT_EXE": cmd[0],
            "BLACKOUT_ARGS": subprocess.list2cmdline(cmd[1:]),
            "BLACKOUT_WORKDIR": os.getcwd(),
            "BLACKOUT_ENGINE": engine_name,
            "BLACKOUT_GENERATION": generation,
            "BLACKOUT_PID_FILE": str(PID_FILE),
            "BLACKOUT_STATE_FILE": str(STATE_FILE),
        }

        ps_cmd = (
            "$p = Start-Process -FilePath $env:BLACKOUT_EXE "
            "-ArgumentList $env:BLACKOUT_ARGS -WorkingDirectory $env:BLACKOUT_WORKDIR " + verb_clause +
            "-WindowStyle Hidden -PassThru; "
            "if ($p) { $p.Id | Out-File -FilePath $env:BLACKOUT_PID_FILE -Encoding UTF8; "
            "@{engine=$env:BLACKOUT_ENGINE;pid=$p.Id;generation=$env:BLACKOUT_GENERATION;started=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')} | ConvertTo-Json | Out-File -FilePath $env:BLACKOUT_STATE_FILE -Encoding UTF8 }"
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

        for _ in range(600):
            if PID_FILE.exists():
                break
            time.sleep(0.1)

        pid = _read_pid_file()
        if pid:
            if _register_spawned_daemon(pid, generation):
                return pid
            try:
                import psutil
                if psutil.pid_exists(pid):
                    psutil.Process(pid).terminate()
            except Exception:
                pass
        return 0
    finally:
        release_start_lock(lock_path, lock_token)


def stop() -> bool:
    """
    Stop the running daemon and all its children.
    Returns True if a daemon was stopped.
    """
    pid = get_pid()
    lease = _active_lease(pid)
    if not pid or lease is None:
        return False
    generation = lease["generation"]
    expected_create_time = lease["create_time"]
    if process_identity_state(pid, expected_create_time) is not True:
        return False

    def still_owned() -> bool:
        return (
            lease_matches(_lease_path(), generation, pid)
            and process_identity_state(pid, expected_create_time) is True
        )

    if not still_owned():
        return False

    # Check for orphan lock file only after ownership was verified.
    LOCK_FILE.unlink(missing_ok=True)

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
                    return _clear_owned_metadata(
                        pid,
                        generation,
                        expected_create_time=expected_create_time,
                        require_gone=True,
                    )
                time.sleep(0.1)
        except Exception as e:
            import logging
            logging.debug("Graceful daemon shutdown via IPC failed: %s", e)

    # Create a generation-scoped shutdown request as fallback.
    (APP_DATA_DIR / "daemon.stop.request").write_text(generation, encoding="utf-8")

    try:
        import psutil
        if not still_owned():
            return False
        parent = psutil.Process(pid)
        if not still_owned():
            return False
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
    try:
        from ..proxy_manager import cleanup_owned_system_proxy
        cleanup_owned_system_proxy()
    except Exception:
        pass
    try:
        from .. import security as sec
        sec.disable_kill_switch()
        sec.clear_linux_kill_switch_endpoint()
    except Exception:
        pass
    ret = _clear_owned_metadata(
        pid,
        generation,
        expected_create_time=expected_create_time,
        require_gone=True,
    )
    if not ret:
        print("CLEAR METADATA FAILED")
        return False
    LOCK_FILE.unlink(missing_ok=True)
    ipc_file.unlink(missing_ok=True)
    _clear_shutdown_request(generation)
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
        lease = read_lease(_lease_path())
        if lease and lease.get("generation") and data.get("generation") != lease.get("generation"):
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


def _daemon_shutdown_requested(daemon_pid: int, generation: str | None = None) -> bool:
    """Return whether this daemon should stop without disturbing another daemon."""
    if generation is not None and not _lease_is_current(daemon_pid, generation):
        return True
    with _shutdown_lock:
        if _shutdown_requested:
            return True
    stop_request = APP_DATA_DIR / "daemon.stop.request"
    if stop_request.exists():
        try:
            requested_generation = stop_request.read_text(encoding="utf-8-sig").strip()
        except OSError:
            requested_generation = ""
        if generation is None or not requested_generation or requested_generation == generation:
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


def _cleanup_daemon_state(
    pid: int,
    generation: str,
    cleanup_proxy: Callable[[], object] | None,
    disable_kill_switch: Callable[[], object] | None,
    clear_kill_switch_endpoint: Callable[[], object] | None,
) -> None:
    """Clean shared state only while this daemon still owns its lease."""
    if not _lease_is_current(pid, generation):
        return
    try:
        with lifecycle_lock(_lifecycle_path()):
            lease = read_lease(_lease_path())
            if not lease or lease["pid"] != pid or lease["generation"] != generation:
                return
            if cleanup_proxy:
                cleanup_proxy()
            if disable_kill_switch:
                disable_kill_switch()
            if clear_kill_switch_endpoint:
                clear_kill_switch_endpoint()
    except (OSError, OwnershipBusy):
        return


def _clear_shutdown_request(generation: str | None = None) -> None:
    path = APP_DATA_DIR / "daemon.stop.request"
    try:
        if generation is None or path.read_text(encoding="utf-8-sig").strip() == generation:
            path.unlink(missing_ok=True)
    except OSError:
        pass


def _wait_for_daemon_delay(
    delay_seconds: int,
    daemon_pid: int,
    generation: str | None = None,
) -> bool:
    """Wait in one-second increments; False means shutdown or PID ownership changed."""
    def shutdown_requested() -> bool:
        return (
            _daemon_shutdown_requested(daemon_pid)
            if generation is None
            else _daemon_shutdown_requested(daemon_pid, generation)
        )

    for _ in range(max(0, int(delay_seconds))):
        if shutdown_requested():
            return False
        time.sleep(1)
    return not shutdown_requested()


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
    generation: str | None = None,
) -> None:
    """Persist a state snapshot owned by the daemon, not an individual engine."""
    _ensure_dir()
    try:
        with lifecycle_lock(_lifecycle_path()):
            if generation is not None and not _lease_is_current(daemon_pid, generation):
                return
            state = {
                "engine": _engine_state_payload_name(engine_name, cfg_module),
                "pid": daemon_pid,
                "started": started or time.strftime("%Y-%m-%d %H:%M:%S"),
                "restarts": restarts,
                "status": status,
                "last_failure": last_failure,
                "next_retry_delay": next_retry_delay,
            }
            if generation is not None:
                state["generation"] = generation
            if io_bytes is not None:
                state["io_bytes"] = io_bytes
            temporary = STATE_FILE.with_suffix(".tmp")
            temporary.write_text(json.dumps(state), encoding="utf-8")
            os.replace(temporary, STATE_FILE)
    except (OSError, OwnershipBusy) as e:
        import logging
        logging.warning("Failed to write daemon state file: %s", e)


def run_daemon_loop(
    engine_name: str,
    env_overrides_json: str | None = None,
    generation: str | None = None,
):
    """Claim generation-scoped ownership before running the daemon child."""
    requested_generation = generation or os.environ.get("BLACKOUT_GENERATION")
    direct_call = requested_generation is None
    effective_generation = requested_generation or new_generation()
    daemon_pid = os.getpid()
    if not _register_lease(daemon_pid, effective_generation):
        return False
    try:
        if not direct_call:
            _write_pid_file(daemon_pid)
        try:
            return _run_daemon_loop(
                engine_name,
                env_overrides_json,
                effective_generation,
                None if direct_call else effective_generation,
            )
        finally:
            if direct_call:
                _release_daemon_lease(daemon_pid, effective_generation)
                PID_FILE.unlink(missing_ok=True)
            else:
                _release_spawned_daemon(daemon_pid, effective_generation)
    except Exception:
        if not direct_call:
            _release_spawned_daemon(daemon_pid, effective_generation)
        raise


def _run_daemon_loop(
    engine_name: str,
    env_overrides_json: str | None,
    generation: str,
    state_generation: str | None,
):
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

    from ..engines.amneziawg import AmneziaWGEngine
    from ..engines.singbox_proxy import Hysteria2Engine, TuicEngine
    from ..engines.tun import TUNEngine
    from ..engines.xray import XRayEngine

    if sys.platform == "win32":
        from ..engines.gdpi import GoodbyeDPIEngine
        from ..engines.ikev2 import IKEv2Engine
        from ..engines.mhrv import MhrvEngine
        from ..engines.openvpn import OpenVPNEngine
        from ..engines.psiphon import PsiphonEngine
        from ..engines.sni import SNIEngine
        from ..engines.softether import SoftEtherEngine
        from ..engines.tor import TorEngine
        from ..engines.warp import WARPEngine
        from ..engines.wireguard import WireGuardEngine
    else:
        SNIEngine = GoodbyeDPIEngine = PsiphonEngine = WARPEngine = None
        TorEngine = MhrvEngine = IKEv2Engine = WireGuardEngine = None
        OpenVPNEngine = SoftEtherEngine = None
    from .. import security as sec
    from .. import settings as cfg
    from ..proxy_manager import cleanup_owned_system_proxy, set_system_proxy

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
        subprocess.Popen(_watchdog_command(os.getpid(), generation), **watchdog_kwargs)
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
        "tun":        lambda: (SNIEngine(), XRayEngine(), TUNEngine()) if sys.platform == "win32" else (XRayEngine(), TUNEngine()),
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
    traffic_monitor = None

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
        import threading

        from ..tray import start_tray

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
        generation=state_generation,
    )

    if s.get("traffic_logging_enabled", False):
        try:
            from .traffic_monitor import TrafficMonitor

            traffic_monitor = TrafficMonitor(
                sample_interval_sec=int(s.get("traffic_log_sample_interval_sec", 10))
            )
            traffic_monitor.start()
            log.info("Traffic monitor initialized.")
        except Exception as exc:
            traffic_monitor = None
            log.warning("Traffic monitor could not start: %s", exc)

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
            if _daemon_shutdown_requested(my_pid, generation):
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
                    generation=state_generation,
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
                generation=state_generation,
            )
            log.warning("Restart attempt %d/%d failed; retrying in %ds.", restart_count, max_restarts, next_delay)
            if restart_count == 1:
                try:
                    from .. import tools
                    tools.run_network_recovery(from_daemon=True)
                    log.info("Applied targeted daemon recovery after failed restart.")
                except Exception as exc:
                    log.warning("Targeted daemon recovery failed: %s", exc)
            waited = (
                _wait_for_daemon_delay(next_delay, my_pid)
                if state_generation is None
                else _wait_for_daemon_delay(next_delay, my_pid, state_generation)
            )
            if not waited:
                return False

        _write_daemon_state(
            active_engine_name,
            cfg,
            my_pid,
            restarts=restart_count,
            status="failed",
            last_failure=failure_reason,
            started=daemon_started,
            generation=state_generation,
        )
        log.error("Reconnect attempts exhausted after %d failure(s).", restart_count)
        return False

    try:
        # Track previous run total bytes in case of engine restarts
        accumulated_rx = 0
        accumulated_tx = 0
        data_phase_failures = 0

        while (
            _wait_for_daemon_delay(retry_interval, my_pid)
            if state_generation is None
            else _wait_for_daemon_delay(retry_interval, my_pid, state_generation)
        ):
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
                io_bytes=(accumulated_rx + rx, accumulated_tx + tx),
                generation=state_generation,
            )

    except KeyboardInterrupt:
        log.info("Daemon received CTRL+C interrupt, initiating graceful shutdown.")
    finally:
        _clear_shutdown_request(generation)
        log.info("Daemon shutting down. Stopping engines...")
        if traffic_monitor is not None:
            try:
                traffic_monitor.stop()
            except Exception as exc:
                log.warning("Traffic monitor could not stop cleanly: %s", exc)
        _stop_active_engines()
        _cleanup_daemon_state(
            my_pid,
            generation,
            cleanup_owned_system_proxy if s.get("auto_set_proxy", True) else None,
            sec.disable_kill_switch if s.get("kill_switch", False) else None,
            sec.clear_linux_kill_switch_endpoint if s.get("kill_switch", False) else None,
        )
        log.info("Done.")


# ─────────────────────────── High-Performance Daemon IPC ───────────────────

def stream_daemon_ipc_metrics() -> dict:
    """
    ⚡ High-Performance Daemon IPC Metrics Stream:
    Fast in-memory daemon health & throughput metrics without disk polling.
    """
    pid = get_pid()
    active = bool(pid and is_process_alive(pid))
    state = get_state()

    return {
        "pid": pid,
        "active": active,
        "engine": state.get("engine") if state else None,
        "started_at": state.get("started_at") if state else None,
        "uptime": time.time() - state["started_at"] if (state and "started_at" in state) else 0.0,
        "memory_mb": 0.0,
    }
