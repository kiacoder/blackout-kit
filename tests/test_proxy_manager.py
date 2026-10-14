import pytest
import sys
from unittest.mock import patch, MagicMock

if sys.platform != "win32":
    sys.modules.setdefault("winreg", MagicMock())


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

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("ctypes.windll.shell32.IsUserAnAdmin", create=True)
def test_is_admin_win32_true(mock_is_admin):
    mock_is_admin.return_value = 1
    assert is_admin() is True

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("ctypes.windll.shell32.IsUserAnAdmin", create=True)
def test_is_admin_win32_false(mock_is_admin):
    mock_is_admin.return_value = 0
    assert is_admin() is False

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
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

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
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

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("winreg.OpenKey")
@patch("winreg.SetValueEx")
@patch("winreg.CloseKey")
@patch("blackoutkit.proxy_manager._notify_proxy_change")
def test_set_system_proxy_winreg_socks(mock_notify, mock_close, mock_set, mock_open):
    res = set_system_proxy("socks=127.0.0.1", 10809, "socks")
    assert res is True
    assert get_last_error() == ""

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("winreg.OpenKey", side_effect=PermissionError("denied"))
@patch("subprocess.run")
def test_set_system_proxy_winreg_permission_error_netsh_fallback(mock_run, mock_open):
    # WinHTTP fallback removed for security (Bug 10 fix: fail-closed instead of SSRF-prone fallback)
    # When WinINET write fails, we now fail closed instead of falling back to WinHTTP
    mock_run.return_value = MagicMock(returncode=0)
    res = set_system_proxy("127.0.0.1", 10809, "http")
    assert res is False
    assert "Registry write denied" in get_last_error()

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("winreg.OpenKey", side_effect=Exception("reg err"))
@patch("subprocess.run")
def test_set_system_proxy_netsh_fail(mock_run, mock_open):
    # WinHTTP fallback removed for security (Bug 10 fix)
    # Registry error causes failure, no netsh fallback anymore
    mock_run.return_value = MagicMock(returncode=1)
    res = set_system_proxy("127.0.0.1", 10809, "http")
    assert res is False
    assert "Registry error" in get_last_error()

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

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("winreg.OpenKey")
@patch("winreg.SetValueEx")
@patch("winreg.CloseKey")
@patch("blackoutkit.proxy_manager._notify_proxy_change")
def test_clear_system_proxy_winreg_success(mock_notify, mock_close, mock_set, mock_open):
    res = clear_system_proxy()
    assert res is True

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("winreg.OpenKey", side_effect=PermissionError("denied"))
@patch("subprocess.run")
def test_clear_system_proxy_netsh_fallback(mock_run, mock_open):
    # WinHTTP fallback removed for security (Bug 10 fix: fail-closed)
    # When WinINET write fails, we now fail closed instead of falling back to WinHTTP
    mock_run.return_value = MagicMock(returncode=0)
    res = clear_system_proxy()
    assert res is False

@patch("sys.platform", "linux")
@patch("os.environ", {"http_proxy": "test", "https_proxy": "test"})
def test_clear_system_proxy_linux():
    import os
    res = clear_system_proxy()
    assert res is True
    assert "http_proxy" not in os.environ

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("winreg.OpenKey")
@patch("winreg.QueryValueEx")
@patch("winreg.CloseKey")
def test_get_proxy_status_win32(mock_close, mock_query, mock_open):
    mock_query.side_effect = [(1, 1), ("127.0.0.1:10809", 1)]
    status = get_proxy_status()
    assert status["enabled"] is True
    assert status["server"] == "127.0.0.1:10809"

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("winreg.OpenKey")
@patch("winreg.QueryValueEx", side_effect=FileNotFoundError("not found"))
@patch("winreg.CloseKey")
def test_get_proxy_status_win32_not_found(mock_close, mock_query, mock_open):
    status = get_proxy_status()
    assert status["enabled"] is False
    assert status["server"] == ""

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("ctypes.windll.Wininet.InternetSetOptionW", create=True)
def test_notify_proxy_change(mock_internet_set_option):
    _notify_proxy_change()
    assert mock_internet_set_option.call_count == 2

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("ctypes.windll.kernel32.SetConsoleCtrlHandler", create=True)
@patch("ctypes.WINFUNCTYPE", create=True)
def test_install_console_close_handler(mock_winfunctype, mock_set_console):
    install_console_close_handler()
    mock_winfunctype.assert_called_once()
    mock_set_console.assert_called_once()

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("subprocess.run", side_effect=Exception("netsh bad"))
@patch("winreg.OpenKey", side_effect=PermissionError("denied"))
def test_set_system_proxy_netsh_exception(mock_open, mock_run):
    # WinHTTP fallback removed for security (Bug 10 fix)
    # Registry error causes failure, no netsh fallback anymore
    res = set_system_proxy("1.1.1.1", 80, "http")
    assert res is False
    assert "Registry write denied" in get_last_error()

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("subprocess.run", side_effect=Exception("netsh fatal"))
@patch("winreg.OpenKey", side_effect=Exception("reg fatal"))
def test_clear_system_proxy_exceptions(mock_open, mock_run):
    # WinHTTP fallback removed for security (Bug 10 fix)
    # Registry error causes failure, no netsh fallback anymore
    res = clear_system_proxy()
    assert res is False
    assert "Registry error" in get_last_error()

@patch("sys.platform", "linux")
@patch("os.environ", {})
def test_get_proxy_status_linux():
    import os
    os.environ["http_proxy"] = "1.2.3.4:80"
    res = get_proxy_status()
    assert res["enabled"] is True
    assert res["server"] == "1.2.3.4:80"

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("winreg.OpenKey", side_effect=Exception("fatal"))
def test_get_proxy_status_win32_exception(mock_open):
    res = get_proxy_status()
    assert res["enabled"] is False
    assert res["server"] == ""

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("ctypes.windll.Wininet.InternetSetOptionW", side_effect=Exception("wininet err"))
def test_notify_proxy_change_exception(mock_set):
    _notify_proxy_change()

@patch("sys.platform", "linux")
def test_install_console_close_handler_linux():
    install_console_close_handler()

@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
@patch("sys.platform", "win32")
@patch("ctypes.WINFUNCTYPE", create=True)
@patch("ctypes.windll.kernel32.SetConsoleCtrlHandler", side_effect=Exception("err"))
def test_install_console_close_handler_win32_exception(mock_set, mock_func):
    install_console_close_handler()


# ── force_clear_dead_proxy safety net ────────────────────────────────────────

def _set_win_proxy(enabled: int, server: str, monkeypatch):
    """Drive force_clear_dead_proxy's registry reads through a fake winreg."""
    import types

    class FakeKey:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def QueryValueEx(self, name):
            if name == "ProxyEnable":
                return enabled, None
            if name == "ProxyServer":
                return server, None
            raise FileNotFoundError(name)

        def SetValueEx(self, *a):
            pass

        def Close(self):
            pass

    fake = types.ModuleType("winreg")
    fake.OpenKey = lambda *a, **k: FakeKey()
    fake.CloseKey = lambda key: None

    def _query(key, name):
        return key.QueryValueEx(name)

    fake.QueryValueEx = _query
    fake.KEY_READ = fake.KEY_WRITE = 0
    fake.REG_DWORD = fake.REG_SZ = 0
    fake.HKEY_CURRENT_USER = 0
    fake.FileNotFoundError = FileNotFoundError
    monkeypatch.setitem(__import__("sys").modules, "winreg", fake)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
def test_force_clear_ignores_disabled_proxy(monkeypatch):
    from blackoutkit import proxy_manager as pm
    _set_win_proxy(0, "127.0.0.1:10809", monkeypatch)
    called = {"clear": 0}
    monkeypatch.setattr(pm, "clear_system_proxy", lambda: called.__setitem__("clear", called["clear"] + 1) or True)
    assert pm.force_clear_dead_proxy() is False
    assert called["clear"] == 0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
def test_force_clear_ignores_external_proxy_host(monkeypatch):
    from blackoutkit import proxy_manager as pm
    _set_win_proxy(1, "192.168.1.10:8080", monkeypatch)
    called = {"clear": 0}
    monkeypatch.setattr(pm, "clear_system_proxy", lambda: called.__setitem__("clear", 1) or True)
    assert pm.force_clear_dead_proxy() is False
    assert called["clear"] == 0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
def test_force_clear_ignores_live_listener(monkeypatch):
    """If something IS listening on the target port, never touch the proxy."""
    import socket
    from blackoutkit import proxy_manager as pm
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        _set_win_proxy(1, f"127.0.0.1:{port}", monkeypatch)
        called = {"clear": 0}
        monkeypatch.setattr(pm, "clear_system_proxy", lambda: called.__setitem__("clear", 1) or True)
        assert pm.force_clear_dead_proxy(ports=(port,)) is False
        assert called["clear"] == 0
    finally:
        blocker.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows proxy manager test")
def test_force_clear_fires_on_dead_blackout_port(monkeypatch):
    """The broken state from the 2026-10-11 incident: proxy enabled, pointing
    at a Blackout port with no listener — must be cleared."""
    import socket
    from blackoutkit import proxy_manager as pm
    # grab a definitely-free port then release it
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    _set_win_proxy(1, f"127.0.0.1:{dead_port}", monkeypatch)
    called = {"clear": 0}
    monkeypatch.setattr(pm, "clear_system_proxy", lambda: called.__setitem__("clear", 1) or True)
    assert pm.force_clear_dead_proxy(ports=(dead_port,)) is True
    assert called["clear"] == 1
