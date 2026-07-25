import ctypes
import os
import sys
from pathlib import Path
import logging

_log = logging.getLogger("blackoutkit.core")

from . import BINS_DIR

_dll = None

def get_core_dll():
    global _dll
    if _dll is not None:
        return _dll



    if sys.platform != "win32":
        return None

    dll_path = BINS_DIR / "blackout_core.dll"
    if not dll_path.exists():
        return None

    try:
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(str(BINS_DIR))
        _dll = ctypes.CDLL(str(dll_path))
        
        _dll.StartXrayC.argtypes = [ctypes.c_char_p]
        _dll.StartXrayC.restype = ctypes.c_int
        _dll.StopXrayC.argtypes = []
        
        _dll.StartSingBoxC.argtypes = [ctypes.c_char_p]
        _dll.StartSingBoxC.restype = ctypes.c_int
        _dll.StopSingBoxC.argtypes = []
        
        _dll.StartSNIC.argtypes = [ctypes.c_char_p]
        _dll.StartSNIC.restype = ctypes.c_int
        _dll.StopSNIC.argtypes = []
        
        _dll.StartMHRVC.argtypes = [ctypes.c_int, ctypes.c_char_p]
        _dll.StartMHRVC.restype = ctypes.c_int
        _dll.StopMHRVC.argtypes = []

        _dll.StartWireGuardC.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _dll.StartWireGuardC.restype = ctypes.c_int
        _dll.StopWireGuardC.argtypes = []
        
        return _dll
    except Exception as e:
        _log.error("Failed to load core engine DLL: %s", e)
        return None

_warp_dll = None

def get_warp_dll():
    global _warp_dll
    if _warp_dll is not None:
        return _warp_dll



    if sys.platform != "win32":
        return None

    dll_path = BINS_DIR / "blackout_warp.dll"
    if not dll_path.exists():
        return None

    try:
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(str(BINS_DIR))
        _warp_dll = ctypes.CDLL(str(dll_path))
        
        _warp_dll.StartWarpC.argtypes = [ctypes.c_int, ctypes.c_char_p]
        _warp_dll.StartWarpC.restype = ctypes.c_int
        _warp_dll.StopWarpC.argtypes = []
        
        _warp_dll.StartPsiphonC.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        _warp_dll.StartPsiphonC.restype = ctypes.c_int
        _warp_dll.StopPsiphonC.argtypes = []
        
        return _warp_dll
    except Exception as e:
        _log.error("Failed to load warp engine DLL: %s", e)
        return None

