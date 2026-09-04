"""Local system-proxy management with ownership-aware cleanup."""
from __future__ import annotations

import json
import os
from pathlib import Path
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


def cleanup_owned_system_proxy() -> bool:
    """Restore an owned proxy only when no other process changed it."""
    record = _read_proxy_ownership()
    if record is None:
        return False
    target = record.get("target")
    if target is not None and not _proxy_records_equal(get_proxy_status(), target):
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

    if sys.platform != "win32":
        value = f"socks5://{host}:{port}" if protocol == "socks" else f"http://{host}:{port}"
        os.environ["http_proxy"] = value
        os.environ["https_proxy"] = value
        _mark_proxy_owned(previous, get_proxy_status() or target)
        return True

    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        import winreg

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        try:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, target["server"])
            from . import split_tunnel

            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, split_tunnel.get_proxy_override_string())
        finally:
            winreg.CloseKey(key)
        _notify_proxy_change()
        _last_error = ""
        _mark_proxy_owned(previous, get_proxy_status() or target)
        return True
    except PermissionError:
        _last_error = f"Registry write denied — run Blackout Kit as Administrator or enable '{key_path}'."
    except Exception as exc:
        _last_error = f"Registry error: {exc}"

    try:
        result = subprocess.run(
            ["netsh", "winhttp", "set", "proxy", target["server"]],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            _last_error = ""
            _mark_proxy_owned(previous, get_proxy_status() or target)
            return True
        _last_error = f"netsh fallback failed (rc={result.returncode})"
    except Exception as exc:
        _last_error = f"netsh fallback error: {exc}"
    return False


def restore_system_proxy(status: dict) -> bool:
    """Restore a proxy snapshot captured before Blackout Kit changed it."""
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

    try:
        result = subprocess.run(
            ["netsh", "winhttp", "reset", "proxy"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            _last_error = ""
            if not _restoring_proxy:
                _forget_proxy_ownership()
            return True
        _last_error = f"netsh reset failed (rc={result.returncode})"
    except Exception as exc:
        _last_error = f"netsh error: {exc}"
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


def install_console_close_handler():
    """Restore an owned proxy when the Windows console is closed."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        import ctypes.wintypes

        HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)

        def ctrl_handler(ctrl_type):
            if ctrl_type in (2, 5, 6):
                cleanup_owned_system_proxy()
            return False

        global _ctrl_handler_ref
        _ctrl_handler_ref = HandlerRoutine(ctrl_handler)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_handler_ref, True)
    except Exception:
        pass


def _legacy_restore_alias(status: dict) -> bool:
    return restore_system_proxy(status)


# Compatibility name used by older adapters.
restore_proxy = _legacy_restore_alias


__all__ = [
    "cleanup_owned_system_proxy",
    "clear_system_proxy",
    "get_last_error",
    "get_proxy_status",
    "install_console_close_handler",
    "is_admin",
    "proxy_ownership_status",
    "restore_proxy",
    "restore_system_proxy",
    "set_system_proxy",
]
