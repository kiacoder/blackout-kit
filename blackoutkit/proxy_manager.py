"""
Blackout Kit - Windows system proxy manager.

Auto-sets and clears the Windows system proxy (HTTP/HTTPS).
Features:
  - Registry write + WinInet live notification (changes apply instantly)
  - netsh fallback if registry write fails
  - is_admin() check with clear error messages
  - _last_error: readable error string on failure (call get_last_error())
"""
import sys
import subprocess

_last_error: str = ""


def get_last_error() -> str:
    """Return the human-readable error message from the last failed operation."""
    return _last_error


def is_admin() -> bool:
    """Return True if the current process has administrator/root privileges."""
    if sys.platform != "win32":
        import os
        return os.geteuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def set_system_proxy(host: str = "127.0.0.1", port: int = 10809, protocol: str = "http") -> bool:
    """
    Set Windows system proxy to route HTTP/HTTPS through host:port.
    Bypasses: localhost, 127.*, LAN ranges, <local> hostnames.
    Returns True on success, False on failure (call get_last_error() for details).
    """
    global _last_error

    if host.startswith("socks="):
        protocol = "socks"
        host = host.split("=")[1]

    if sys.platform != "win32":
        import os
        if protocol == "socks":
            os.environ["http_proxy"]  = f"socks5://{host}:{port}"
            os.environ["https_proxy"] = f"socks5://{host}:{port}"
        else:
            os.environ["http_proxy"]  = f"http://{host}:{port}"
            os.environ["https_proxy"] = f"http://{host}:{port}"
        return True

    if sys.platform == "win32":
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            proxy_str = f"socks={host}:{port}" if protocol == "socks" else f"{host}:{port}"
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_str)
            from . import split_tunnel
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, split_tunnel.get_proxy_override_string())
            winreg.CloseKey(key)
            _notify_proxy_change()
            _last_error = ""
            return True
        except PermissionError:
            _last_error = (
                f"Registry write denied — run Blackout Kit as Administrator "
                f"or enable '{key_path}'."
            )
        except Exception as exc:
            _last_error = f"Registry error: {exc}"

    # Fallback: netsh (works without registry access)
    try:
        proxy_str = f"socks={host}:{port}" if protocol == "socks" else f"{host}:{port}"
        result = subprocess.run(
            ["netsh", "winhttp", "set", "proxy", proxy_str],
            capture_output=True, timeout=10,
        )
        if result.returncode == 0:
            _last_error = ""
            return True
        _last_error = f"netsh fallback failed (rc={result.returncode})"
    except Exception as exc:
        _last_error = f"netsh fallback error: {exc}"

    return False


def clear_system_proxy() -> bool:
    """
    Remove the Windows system proxy and restore direct connection.
    Returns True on success.
    """
    global _last_error

    if sys.platform != "win32":
        import os
        os.environ.pop("http_proxy",  None)
        os.environ.pop("https_proxy", None)
        return True

    if sys.platform == "win32":
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "")
            winreg.CloseKey(key)
            _notify_proxy_change()
            _last_error = ""
            return True
        except PermissionError:
            _last_error = "Registry write denied — run as Administrator."
        except Exception as exc:
            _last_error = f"Registry error: {exc}"

    try:
        result = subprocess.run(
            ["netsh", "winhttp", "reset", "proxy"],
            capture_output=True, timeout=10,
        )
        if result.returncode == 0:
            _last_error = ""
            return True
        _last_error = f"netsh reset failed (rc={result.returncode})"
    except Exception as exc:
        _last_error = f"netsh error: {exc}"

    return False


def get_proxy_status() -> dict:
    """
    Return current system proxy status.
    Returns: {"enabled": bool, "server": str}
    """
    if sys.platform != "win32":
        import os
        proxy = os.environ.get("http_proxy", "")
        return {"enabled": bool(proxy), "server": proxy}

    if sys.platform == "win32":
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key      = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
            try:
                enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
                server  = winreg.QueryValueEx(key, "ProxyServer")[0]
            except FileNotFoundError:
                enabled, server = 0, ""
            winreg.CloseKey(key)
            return {"enabled": bool(enabled), "server": server}
        except Exception:
            return {"enabled": False, "server": ""}
    return {"enabled": False, "server": ""}


def _notify_proxy_change():
    """Tell WinInet to apply the proxy change immediately — no reboot required."""
    try:
        import ctypes
        INTERNET_OPTION_SETTINGS_CHANGED = 95
        INTERNET_OPTION_REFRESH          = 37
        wininet = ctypes.windll.Wininet
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH,          0, 0)
    except Exception:
        pass


_ctrl_handler_ref = None

def install_console_close_handler():
    """
    Installs a Windows console control handler to catch when the user 
    closes the PowerShell/CMD window (CTRL_CLOSE_EVENT).
    This ensures the system proxy is cleanly disabled before the OS
    hard-kills the Python process.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        import ctypes.wintypes

        HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)

        def ctrl_handler(ctrl_type):
            # 2 = CTRL_CLOSE_EVENT, 5 = CTRL_LOGOFF_EVENT, 6 = CTRL_SHUTDOWN_EVENT
            if ctrl_type in (2, 5, 6):
                clear_system_proxy()
            return False  # Return False to pass the event to the next handler (default OS exit)

        global _ctrl_handler_ref
        _ctrl_handler_ref = HandlerRoutine(ctrl_handler)

        ctypes.windll.kernel32.SetConsoleCtrlHandler(_ctrl_handler_ref, True)
    except Exception:
        # Silently fail if we can't install the handler
        pass
