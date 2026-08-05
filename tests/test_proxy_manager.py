import pytest
import sys
from unittest.mock import patch, MagicMock

from blackoutkit.proxy_manager import (
    get_last_error,
    is_admin,
    set_system_proxy,
    clear_system_proxy,
    get_proxy_status,
    install_console_close_handler,
    _notify_proxy_change
)

def test_get_last_error():
    assert isinstance(get_last_error(), str)

@patch("sys.platform", "win32")
@patch("ctypes.windll.shell32.IsUserAnAdmin")
def test_is_admin_win32_true(mock_is_admin):
    mock_is_admin.return_value = 1
    assert is_admin() is True

@patch("sys.platform", "win32")
@patch("ctypes.windll.shell32.IsUserAnAdmin")
def test_is_admin_win32_false(mock_is_admin):
    mock_is_admin.return_value = 0
    assert is_admin() is False

@patch("sys.platform", "win32")
@patch("ctypes.windll.shell32.IsUserAnAdmin", side_effect=Exception("mock err"))
def test_is_admin_win32_exception(mock_is_admin):
    assert is_admin() is False

@patch("sys.platform", "linux")
@patch("os.geteuid", create=True)
def test_is_admin_linux(mock_geteuid):
    mock_geteuid.return_value = 0
    assert is_admin() is True
    mock_geteuid.return_value = 1000
    assert is_admin() is False

@patch("sys.platform", "win32")
@patch("winreg.OpenKey")
@patch("winreg.SetValueEx")
@patch("winreg.CloseKey")
@patch("blackoutkit.proxy_manager._notify_proxy_change")
def test_set_system_proxy_winreg_success(mock_notify, mock_close, mock_set, mock_open):
    res = set_system_proxy("127.0.0.1", 10809, "http")
    assert res is True
    assert get_last_error() == ""
    mock_notify.assert_called_once()

@patch("sys.platform", "win32")
@patch("winreg.OpenKey")
@patch("winreg.SetValueEx")
@patch("winreg.CloseKey")
@patch("blackoutkit.proxy_manager._notify_proxy_change")
def test_set_system_proxy_winreg_socks(mock_notify, mock_close, mock_set, mock_open):
    res = set_system_proxy("socks=127.0.0.1", 10809, "socks")
    assert res is True
    assert get_last_error() == ""

@patch("sys.platform", "win32")
@patch("winreg.OpenKey", side_effect=PermissionError("denied"))
@patch("subprocess.run")
def test_set_system_proxy_winreg_permission_error_netsh_fallback(mock_run, mock_open):
    mock_run.return_value = MagicMock(returncode=0)
    res = set_system_proxy("127.0.0.1", 10809, "http")
    assert res is True
    assert "Registry write denied" in get_last_error() or get_last_error() == ""

@patch("sys.platform", "win32")
@patch("winreg.OpenKey", side_effect=Exception("reg err"))
@patch("subprocess.run")
def test_set_system_proxy_netsh_fail(mock_run, mock_open):
    mock_run.return_value = MagicMock(returncode=1)
    res = set_system_proxy("127.0.0.1", 10809, "http")
    assert res is False
    assert "netsh fallback failed (rc=1)" in get_last_error()

@patch("sys.platform", "linux")
@patch("os.environ", {})
def test_set_system_proxy_linux():
    res = set_system_proxy("127.0.0.1", 10809, "http")
    assert res is True

@patch("sys.platform", "linux")
@patch("os.environ", {})
def test_set_system_proxy_linux_socks():
    res = set_system_proxy("127.0.0.1", 10809, "socks")
    assert res is True

@patch("sys.platform", "win32")
@patch("winreg.OpenKey")
@patch("winreg.SetValueEx")
@patch("winreg.CloseKey")
@patch("blackoutkit.proxy_manager._notify_proxy_change")
def test_clear_system_proxy_winreg_success(mock_notify, mock_close, mock_set, mock_open):
    res = clear_system_proxy()
    assert res is True

@patch("sys.platform", "win32")
@patch("winreg.OpenKey", side_effect=PermissionError("denied"))
@patch("subprocess.run")
def test_clear_system_proxy_netsh_fallback(mock_run, mock_open):
    mock_run.return_value = MagicMock(returncode=0)
    res = clear_system_proxy()
    assert res is True

@patch("sys.platform", "linux")
@patch("os.environ", {"http_proxy": "test", "https_proxy": "test"})
def test_clear_system_proxy_linux():
    import os
    res = clear_system_proxy()
    assert res is True
    assert "http_proxy" not in os.environ

@patch("sys.platform", "win32")
@patch("winreg.OpenKey")
@patch("winreg.QueryValueEx")
@patch("winreg.CloseKey")
def test_get_proxy_status_win32(mock_close, mock_query, mock_open):
    mock_query.side_effect = [(1, 1), ("127.0.0.1:10809", 1)]
    status = get_proxy_status()
    assert status["enabled"] is True
    assert status["server"] == "127.0.0.1:10809"

@patch("sys.platform", "win32")
@patch("winreg.OpenKey")
@patch("winreg.QueryValueEx", side_effect=FileNotFoundError("not found"))
@patch("winreg.CloseKey")
def test_get_proxy_status_win32_not_found(mock_close, mock_query, mock_open):
    status = get_proxy_status()
    assert status["enabled"] is False
    assert status["server"] == ""

@patch("sys.platform", "win32")
@patch("ctypes.windll.Wininet.InternetSetOptionW")
def test_notify_proxy_change(mock_internet_set_option):
    _notify_proxy_change()
    assert mock_internet_set_option.call_count == 2

@patch("sys.platform", "win32")
@patch("ctypes.windll.kernel32.SetConsoleCtrlHandler")
@patch("ctypes.WINFUNCTYPE")
def test_install_console_close_handler(mock_winfunctype, mock_set_console):
    install_console_close_handler()
    mock_winfunctype.assert_called_once()
    mock_set_console.assert_called_once()

@patch("sys.platform", "win32")
@patch("subprocess.run", side_effect=Exception("netsh bad"))
@patch("winreg.OpenKey", side_effect=PermissionError("denied"))
def test_set_system_proxy_netsh_exception(mock_open, mock_run):
    res = set_system_proxy("1.1.1.1", 80, "http")
    assert res is False
    assert "netsh fallback error: netsh bad" in get_last_error()

@patch("sys.platform", "win32")
@patch("subprocess.run", side_effect=Exception("netsh fatal"))
@patch("winreg.OpenKey", side_effect=Exception("reg fatal"))
def test_clear_system_proxy_exceptions(mock_open, mock_run):
    res = clear_system_proxy()
    assert res is False
    assert "netsh error: netsh fatal" in get_last_error()

@patch("sys.platform", "linux")
@patch("os.environ", {})
def test_get_proxy_status_linux():
    import os
    os.environ["http_proxy"] = "1.2.3.4:80"
    res = get_proxy_status()
    assert res["enabled"] is True
    assert res["server"] == "1.2.3.4:80"

@patch("sys.platform", "win32")
@patch("winreg.OpenKey", side_effect=Exception("fatal"))
def test_get_proxy_status_win32_exception(mock_open):
    res = get_proxy_status()
    assert res["enabled"] is False
    assert res["server"] == ""

@patch("sys.platform", "win32")
@patch("ctypes.windll.Wininet.InternetSetOptionW", side_effect=Exception("wininet err"))
def test_notify_proxy_change_exception(mock_set):
    _notify_proxy_change()

@patch("sys.platform", "linux")
def test_install_console_close_handler_linux():
    install_console_close_handler()

@patch("sys.platform", "win32")
@patch("ctypes.WINFUNCTYPE")
@patch("ctypes.windll.kernel32.SetConsoleCtrlHandler", side_effect=Exception("err"))
def test_install_console_close_handler_win32_exception(mock_set, mock_func):
    install_console_close_handler()
