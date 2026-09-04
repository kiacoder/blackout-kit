"""
Blackout Kit — Elevation helpers.
Provides UAC auto-elevation so the CLI stays in a normal terminal
and only the subprocess that actually needs admin gets the UAC prompt.
"""
import ctypes
import os
import subprocess
import sys
import time
from pathlib import Path

if sys.platform == "win32":
    import winreg
    from ctypes import wintypes

ENGINES_REQUIRING_ADMIN = frozenset({"gdpi", "tun", "softether", "ikev2", "wireguard", "openvpn"})

SEE_MASK_NOCLOSEPROCESS = 0x00000040
STILL_ACTIVE = 259
SW_HIDE = 0
SW_SHOW = 1
SW_SHOWDEFAULT = 10
ERROR_CANCELLED = 1223

if sys.platform == "win32":
    class _SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", wintypes.ULONG),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", wintypes.LPVOID),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hMonitor", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]


def is_admin() -> bool:
    if sys.platform != "win32":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        if ctypes.windll.shell32.IsUserAnAdmin() != 0:
            return True
    except Exception:
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE", 0, winreg.KEY_WRITE):
            pass
        return True
    except OSError:
        pass
    return False


def needs_admin(engine_name: str) -> bool:
    return engine_name.lower() in ENGINES_REQUIRING_ADMIN


def launch_elevated(exe_path: str | Path, args: list[str] | None = None, cwd: str | Path | None = None) -> tuple[int | None, int | None]:
    if sys.platform != "win32":
        # Basic implementation for Linux/Mac if needed, or just run normally
        return None, None

    args = args or []
    params = " ".join(args) if args else None
    sei = _SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(_SHELLEXECUTEINFOW)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = str(exe_path)
    sei.lpParameters = params
    sei.lpDirectory = str(cwd) if cwd else str(Path(exe_path).parent)
    sei.nShow = SW_HIDE

    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        err = ctypes.get_last_error()
        if err == ERROR_CANCELLED:
            return None, None
        return None, None

    time.sleep(0.5)
    exit_code = wintypes.DWORD()
    if ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code)):
        if exit_code.value != STILL_ACTIVE:
            ctypes.windll.kernel32.CloseHandle(sei.hProcess)
            return None, None

    pid = ctypes.windll.kernel32.GetProcessId(sei.hProcess)
    return sei.hProcess, pid


def terminate_elevated(handle: int) -> None:
    if sys.platform != "win32":
        return
    ctypes.windll.kernel32.TerminateProcess(handle, 0)
    ctypes.windll.kernel32.CloseHandle(handle)


def is_elevated_alive(handle: int) -> bool:
    if sys.platform != "win32":
        return False
    exit_code = wintypes.DWORD()
    if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        return exit_code.value == STILL_ACTIVE
    return False


def restart_as_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        params = subprocess.list2cmdline(sys.argv)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1,
        )
        return result > 32
    except Exception:
        return False
