import pytest
import sys
from unittest.mock import patch, MagicMock

import blackoutkit.core
from blackoutkit.core import get_core_dll, get_warp_dll

@pytest.fixture(autouse=True)
def reset_globals():
    blackoutkit.core._dll = None
    blackoutkit.core._warp_dll = None
    yield
    blackoutkit.core._dll = None
    blackoutkit.core._warp_dll = None

@patch("sys.platform", "linux")
def test_get_core_dll_linux():
    assert get_core_dll() is None

@patch("sys.platform", "win32")
@patch("pathlib.Path.exists")
def test_get_core_dll_win32_not_exists(mock_exists):
    mock_exists.return_value = False
    assert get_core_dll() is None

@patch("sys.platform", "win32")
@patch("pathlib.Path.exists")
@patch("ctypes.CDLL")
@patch("os.add_dll_directory", create=True)
def test_get_core_dll_win32_success(mock_add_dll, mock_cdll, mock_exists):
    mock_exists.return_value = True
    mock_dll_instance = MagicMock()
    mock_cdll.return_value = mock_dll_instance
    
    dll = get_core_dll()
    assert dll is mock_dll_instance
    # second call should return cached instance
    assert get_core_dll() is mock_dll_instance

@patch("sys.platform", "win32")
@patch("pathlib.Path.exists")
@patch("ctypes.CDLL", side_effect=Exception("Failed to load"))
def test_get_core_dll_win32_exception(mock_cdll, mock_exists):
    mock_exists.return_value = True
    assert get_core_dll() is None

@patch("sys.platform", "linux")
def test_get_warp_dll_linux():
    assert get_warp_dll() is None

@patch("sys.platform", "win32")
@patch("pathlib.Path.exists")
def test_get_warp_dll_win32_not_exists(mock_exists):
    mock_exists.return_value = False
    assert get_warp_dll() is None

@patch("sys.platform", "win32")
@patch("pathlib.Path.exists")
@patch("ctypes.CDLL")
@patch("os.add_dll_directory", create=True)
def test_get_warp_dll_win32_success(mock_add_dll, mock_cdll, mock_exists):
    mock_exists.return_value = True
    mock_dll_instance = MagicMock()
    mock_cdll.return_value = mock_dll_instance
    
    dll = get_warp_dll()
    assert dll is mock_dll_instance
    assert get_warp_dll() is mock_dll_instance

@patch("sys.platform", "win32")
@patch("pathlib.Path.exists")
@patch("ctypes.CDLL", side_effect=Exception("Failed to load warp"))
def test_get_warp_dll_win32_exception(mock_cdll, mock_exists):
    mock_exists.return_value = True
    assert get_warp_dll() is None
