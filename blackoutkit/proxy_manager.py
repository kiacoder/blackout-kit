"""Local system-proxy management with ownership-aware cleanup."""
from __future__ import annotations

import json
import os
import subprocess
import sys

from . import APP_DATA_DIR

_last_error: str = ""
_PROXY_OWNERSHIP_FILE = APP_DATA_DIR / "proxy_ownership.json"
_restoring_proxy = False
_ctrl_handler_ref = None


_PROXY_FIELDS = (
    "override",
    "http_proxy",
    "https_proxy",
    "http_proxy_present",
    "https_proxy_present",
)


def _proxy_record(value: dict | None) -> dict:
    value = value or {}
    record = {
        "enabled": bool(value.get("enabled")),
        "server": str(value.get("server", "")),
    }
    for key in _PROXY_FIELDS:
        if key in value:
            record[key] = value[key] if key.endswith("_present") else str(value.get(key, ""))
    return record


def _read_proxy_ownership() -> dict | None:
    try:
        payload = json.loads(_PROXY_OWNERSHIP_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("snapshot"), dict):
        return None
    target = payload.get("target")
    return {
        "snapshot": _proxy_record(payload["snapshot"]),
        "target": _proxy_record(target) if isinstance(target, dict) else None,
        # PID of the process that SET the proxy. Exit handlers use this so a
        # short-lived CLI process never tears down a proxy the long-running
        # daemon still owns.
        "pid": payload.get("pid"),
    }


def _write_proxy_ownership(snapshot: dict, target: dict) -> None:
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = _PROXY_OWNERSHIP_FILE.with_suffix(".tmp")
    try:
        temporary.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "snapshot": _proxy_record(snapshot),
                    "target": _proxy_record(target),
                    "pid": os.getpid(),
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        os.replace(temporary, _PROXY_OWNERSHIP_FILE)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _forget_proxy_ownership() -> None:
    try:
        _PROXY_OWNERSHIP_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _proxy_records_equal(left: dict | None, right: dict | None) -> bool:
    return _proxy_record(left) == _proxy_record(right)


# Every local listener Blackout Kit can point the system proxy at. Used to
# recognise our OWN stale proxy so it is never captured as the user's
# clean baseline nor left behind on stop.
_OUR_PROXY_PORTS = (10808, 10809, 40443, 18080, 11080, 11081, 8087, 8085, 1081, 1080, 9050)


def _points_at_our_port(server: str | None) -> bool:
    """True when server is 127.0.0.1:<our port> in either "host:port" or
    "socks=host:port" form."""
    if not server:
        return False
    value = server.split("=", 1)[1] if "=" in server else server
    host, sep, port_str = value.rpartition(":")
    if not sep or host not in ("127.0.0.1", "localhost", "::1"):
        return False
    try:
        return int(port_str) in _OUR_PROXY_PORTS
    except ValueError:
        return False


def _clean_baseline() -> dict:
    """What the system proxy looked like before Blackout ever touched it.

    A crash/kill can leave ProxyEnable=1 pointing at one of our now-dead
    ports. Capturing THAT as the snapshot means every later stop
    "restores" the broken proxy - the machine keeps a dead local proxy
    until reboot. The baseline for our own leftovers is simply: off.
    """
    return {"enabled": False, "server": "", "override": ""}

def _desired_proxy(host: str, port: int, protocol: str) -> dict:
    server = f"socks={host}:{port}" if protocol == "socks" else f"{host}:{port}"
    return {"enabled": True, "server": server}


def _mark_proxy_owned(snapshot: dict, target: dict) -> None:
    if _restoring_proxy:
        return
    existing = _read_proxy_ownership()
    if existing is not None and _proxy_records_equal(existing.get("target"), snapshot):
        snapshot = existing.get("snapshot", snapshot)
    try:
        _write_proxy_ownership(snapshot, target)
    except OSError:
        pass


def _restore_windows_proxy_snapshot(status: dict) -> bool:
    """Restore WinINET values exactly, including override and disabled metadata."""
    global _last_error
    try:
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        try:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(bool(status.get("enabled"))))
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(status.get("server", "")))
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, str(status.get("override", "")))
        finally:
            winreg.CloseKey(key)
        _notify_proxy_change()
        _last_error = ""
        return True
    except PermissionError:
        _last_error = "Registry write denied — run as Administrator."
    except Exception as exc:
        _last_error = f"Registry error: {exc}"
    return False


def _restore_environment_proxy_snapshot(status: dict) -> bool:
    for key in ("http_proxy", "https_proxy"):
        present_key = f"{key}_present"
        if present_key in status:
            present = bool(status[present_key])
        else:
            present = bool(status.get(key, ""))
        if present:
            os.environ[key] = str(status.get(key, ""))
        else:
            os.environ.pop(key, None)
    return True


def force_clear_dead_proxy(ports: tuple[int, ...] | None = None) -> bool:
    """Clear the system proxy when it points at a dead local Blackout port.

    This is the safety net for the kill/crash path: if ProxyEnable=1 and
    ProxyServer targets 127.0.0.1 on one of our known proxy ports while
    NOTHING is listening there, every app on the machine is blackholed.
    Ownership does not matter in that state — the setting is broken by
    definition. Only fires when the target port is genuinely unreachable,
    so a healthy unrelated proxy (or a live Blackout tunnel) is never touched.
    """
    if sys.platform != "win32":
        return False
    try:
        import winreg
    except ImportError:
        return False
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        try:
            enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
            server = str(winreg.QueryValueEx(key, "ProxyServer")[0] or "")
        finally:
            winreg.CloseKey(key)
    except (FileNotFoundError, OSError):
        return False
    if not enabled or ":" not in server:
        return False
    if "=" in server and not server.lower().startswith("socks="):
        return False
    server_value = server.split("=", 1)[1] if "=" in server else server
    host, _, port_str = server_value.rpartition(":")
    if host not in ("127.0.0.1", "localhost", "::1"):
        return False
    try:
        port = int(port_str)
    except ValueError:
        return False
    if ports is None:
        from . import settings as cfg
        ports = (
            cfg.DEFAULTS.get("xray_http_port", 10809),
            cfg.DEFAULTS.get("xray_socks_port", 10808),
            cfg.DEFAULTS.get("sni_listen_port", 40443),
            cfg.DEFAULTS.get("v2_tunnel_port", 18080),
        )
        try:
            ports = ports + (int(cfg.load().get("xray_http_port", 10809)),)
        except Exception:
            pass
    if port not in ports:
        return False
    import socket
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return False  # something IS listening — not dead, leave it alone
    except OSError:
        pass
    return clear_system_proxy()


def cleanup_owned_system_proxy(owner_pid: int | None = None) -> bool:
    """Restore an owned proxy only when no other process changed it.

    Pass ``owner_pid`` to restrict the restore to the process that set the
    proxy — an exit handler running in a short-lived CLI process must never
    tear down a proxy the long-running daemon still owns. Omit it (or pass
    ``None``) for the daemon/watchdog paths, which may restore on the owner's
    behalf once it is gone.
    """
    record = _read_proxy_ownership()
    if record is None:
        return False
    if (
        owner_pid is not None
        and record.get("pid") is not None
        and record["pid"] != owner_pid
    ):
        return False
    target = record.get("target")
    live = get_proxy_status()
    if target is not None and not _proxy_records_equal(live, target):
        # The live proxy is not what we set. If it still points at one of OUR
        # ports the machine is blackholed no matter who changed it — clear it
        # instead of giving up and leaving the user offline until a reboot.
        if live.get("enabled") and _points_at_our_port(live.get("server")):
            result = clear_system_proxy()
            _forget_proxy_ownership()
            return result
        _forget_proxy_ownership()
        return False

    global _restoring_proxy
    try:
        _restoring_proxy = True
        result = restore_system_proxy(record["snapshot"])
    finally:
        _restoring_proxy = False
    if result:
        _forget_proxy_ownership()
    return result


def proxy_ownership_status() -> dict | None:
    """Return the persisted proxy ownership record, if one exists."""
    return _read_proxy_ownership()


def get_last_error() -> str:
    """Return the human-readable error message from the last failed operation."""
    return _last_error


def is_admin() -> bool:
    """Return True if the current process has administrator/root privileges."""
    if sys.platform != "win32":
        return os.geteuid() == 0
    try:
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def set_system_proxy(host: str = "127.0.0.1", port: int = 10809, protocol: str = "http") -> bool:
    """Set a local HTTP or SOCKS system proxy and record ownership."""
    global _last_error
    previous = get_proxy_status()
    if host.startswith("socks="):
        protocol = "socks"
        host = host.split("=", 1)[1]
    target = _desired_proxy(host, port, protocol)
    # Never adopt our own leftover as the user's baseline - see _clean_baseline.
    if previous.get("enabled") and _points_at_our_port(previous.get("server")):
        previous = _clean_baseline()

    if sys.platform != "win32":
        value = f"socks5://{host}:{port}" if protocol == "socks" else f"http://{host}:{port}"
        os.environ["http_proxy"] = value
        os.environ["https_proxy"] = value
        _mark_proxy_owned(previous, get_proxy_status() or target)
        return True

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        import winreg
        from . import split_tunnel

        def _write_registry() -> None:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
            try:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, target["server"])
                winreg.SetValueEx(
                    key, "ProxyOverride", 0, winreg.REG_SZ,
                    split_tunnel.get_proxy_override_string(),
                )
            finally:
                winreg.CloseKey(key)

        _write_registry()
        _notify_proxy_change()

        def _matches(snapshot: dict | None) -> bool:
            return bool(
                snapshot
                and snapshot.get("enabled")
                and str(snapshot.get("server") or "") == target["server"]
            )

        actual = get_proxy_status()
        if not _matches(actual):
            # Observed on a machine running Hotspot Shield + PlanetVPN +
            # master_vpn: the registry write alone persisted (verified for 2s),
            # but the WinINET "settings changed" broadcast woke those managers
            # and they restored their own proxy state, erasing ours within
            # 0.5s. Re-apply the values without announcing them — the tunnel is
            # already running, and every app that starts after this reads the
            # registry anyway.
            _write_registry()
            actual = get_proxy_status()

        # Verify the write instead of assuming it landed. A policy, another VPN
        # client, or a registry redirector can swallow it — and returning True
        # regardless is how "System proxy set to 127.0.0.1:10809" ended up in
        # the log while `blackout status` read the registry back as Off and
        # browsers used nothing at all.
        if not _matches(actual):
            _last_error = (
                "the system proxy did not stick — another VPN/proxy manager or a "
                f"policy is overriding it (registry reads {actual.get('server')!r}, "
                f"enabled={actual.get('enabled')})"
            )
            return False
        _last_error = ""
        _mark_proxy_owned(previous, actual or target)
        return True
    except PermissionError:
        _last_error = f"Registry write denied — run Blackout Kit as Administrator."
    except Exception as exc:
        _last_error = f"Registry error: {exc}"

    return False


def restore_system_proxy(status: dict) -> bool:
    """Restore a proxy snapshot captured before Blackout Kit changed it."""
    status = dict(status)
    if status.get("enabled") and _points_at_our_port(status.get("server")):
        # Snapshot poisoned by an earlier buggy cycle: it points at our own
        # dead port. Restoring it literally re-breaks the machine, so treat it
        # as the clean baseline it should have been.
        status = _clean_baseline()
    if sys.platform != "win32":
        return _restore_environment_proxy_snapshot(status)
    return _restore_windows_proxy_snapshot(status)


def clear_system_proxy() -> bool:
    """Clear the system proxy and remove any stale ownership record."""
    global _last_error
    if sys.platform != "win32":
        os.environ.pop("http_proxy", None)
        os.environ.pop("https_proxy", None)
        if not _restoring_proxy:
            _forget_proxy_ownership()
        return True

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        import winreg

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        try:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "")
        finally:
            winreg.CloseKey(key)
        _notify_proxy_change()
        _last_error = ""
        if not _restoring_proxy:
            _forget_proxy_ownership()
        return True
    except PermissionError:
        _last_error = "Registry write denied — run as Administrator."
    except Exception as exc:
        _last_error = f"Registry error: {exc}"

    return False


def get_proxy_status() -> dict:
    """Return current system proxy status, including exact restore metadata."""
    if sys.platform != "win32":
        http_proxy = os.environ.get("http_proxy", "")
        https_proxy = os.environ.get("https_proxy", "")
        return {
            "enabled": bool(http_proxy or https_proxy),
            "server": http_proxy,
            "http_proxy": http_proxy,
            "https_proxy": https_proxy,
            "http_proxy_present": "http_proxy" in os.environ,
            "https_proxy_present": "https_proxy" in os.environ,
        }

    try:
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        try:
            values = {}
            for name, default in (("ProxyEnable", 0), ("ProxyServer", ""), ("ProxyOverride", "")):
                try:
                    values[name] = winreg.QueryValueEx(key, name)[0]
                except (FileNotFoundError, StopIteration):
                    values[name] = default
        finally:
            winreg.CloseKey(key)
        return {
            "enabled": bool(values["ProxyEnable"]),
            "server": str(values["ProxyServer"] or ""),
            "override": str(values["ProxyOverride"] or ""),
        }
    except Exception:
        return {"enabled": False, "server": "", "override": ""}


def _notify_proxy_change():
    """Tell WinInet to apply the proxy change immediately."""
    try:
        import ctypes

        wininet = ctypes.windll.Wininet
        wininet.InternetSetOptionW(0, 95, 0, 0)
        wininet.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


# Windows console control events we restore on. 0 = CTRL_C_EVENT and
# 1 = CTRL_BREAK_EVENT also surface as KeyboardInterrupt in a process with a
# Python-level handler, but a background daemon console has none — so cover
# them here rather than relying on the CLI's try/except.
_CTRL_EVENTS = (0, 1, 2, 5, 6)


def install_console_close_handler():
    """Restore an owned proxy when the Windows console is closed or interrupted."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        import ctypes.wintypes

        HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)

        def ctrl_handler(ctrl_type):
            if ctrl_type in _CTRL_EVENTS:
                cleanup_owned_system_proxy(owner_pid=os.getpid())
            return False

        global _ctrl_handler_ref
        _ctrl_handler_ref = HandlerRoutine(ctrl_handler)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_handler_ref, True)
    except Exception:
        pass


def install_atexit_proxy_restore() -> None:
    """Restore an owned proxy when this process exits for any reason.

    Covers ``sys.exit()``, an unhandled exception, and normal termination —
    the paths where no explicit stop/cleanup call runs. Scoped to this process
    through the ownership PID, so it never tears down a proxy the daemon still
    owns. It does **not** cover a hard kill (End Task / ``TerminateProcess``);
    that is the watchdog's job.
    """
    import atexit

    def _restore_on_exit() -> None:
        try:
            cleanup_owned_system_proxy(owner_pid=os.getpid())
        except Exception:
            pass

    atexit.register(_restore_on_exit)


def _legacy_restore_alias(status: dict) -> bool:
    return restore_system_proxy(status)


# Compatibility name used by older adapters.
restore_proxy = _legacy_restore_alias


__all__ = [
    "cleanup_owned_system_proxy",
    "clear_system_proxy",
    "get_last_error",
    "get_proxy_status",
    "install_atexit_proxy_restore",
    "install_console_close_handler",
    "is_admin",
    "proxy_ownership_status",
    "restore_proxy",
    "restore_system_proxy",
    "set_system_proxy",
]
