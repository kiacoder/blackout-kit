import ctypes
import os
import sys
from pathlib import Path
import logging

_log = logging.getLogger("blackoutkit.core")

BINS_DIR = Path(__file__).parent.parent / "bins"

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
        
        return _dll
    except Exception as e:
        _log.error("Failed to load core engine DLL: %s", e)
        return None
