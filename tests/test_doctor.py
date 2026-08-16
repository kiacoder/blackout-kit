import pytest
import sys
import os
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import blackoutkit.doctor as doc
from blackoutkit.doctor import CheckResult

def test_check_result():
    r = doc.CheckResult("name", True, "msg", fixable=True, fix=lambda: "fixed")
    assert r.name == "name"
    assert r.ok is True
    assert r.message == "msg"
    assert r.fixable is True
    assert r.fix() == "fixed"

@patch("blackoutkit.doctor.PROJECT_ROOT")
def test_check_data_files(mock_root, tmp_path):
    mock_root.__truediv__.return_value = tmp_path / "mocked"
    res = doc.check_data_files()
    assert len(res) == 3
    assert not res[0].ok
    res[0].fix()
    
    (tmp_path / "mocked").write_text("")
    res2 = doc.check_data_files()
    assert not res2[0].ok
    res2[0].fix()
    
    (tmp_path / "mocked").write_text("ok")
    res3 = doc.check_data_files()
    assert res3[0].ok

@patch("blackoutkit.settings.load")
@patch("blackoutkit.settings.DEFAULTS", {"a": 1})
def test_check_settings(mock_load):
    mock_load.return_value = {"a": 1}
    assert doc.check_settings().ok is True
    
    mock_load.return_value = {}
    assert doc.check_settings().ok is False
    
    mock_load.side_effect = Exception("err")
    assert doc.check_settings().ok is False

@patch("blackoutkit.doctor.BINS_DIR")
def test_check_bins_dir(mock_bins, tmp_path):
    mock_bins.exists.return_value = False
    res = doc.check_bins_dir()
    assert res.ok is False
    res.fix()
    mock_bins.exists.return_value = True
    assert doc.check_bins_dir().ok is True

@patch("blackoutkit.doctor.APP_DATA_DIR")
def test_check_app_data_dir(mock_data, tmp_path):
    mock_data.exists.return_value = False
    res = doc.check_app_data_dir()
    assert res.ok is False
    res.fix()
    mock_data.exists.return_value = True
    assert doc.check_app_data_dir().ok is True

@patch("builtins.__import__")
def test_check_python_deps(mock_import):
    res = doc.check_python_deps()
    assert all(r.ok for r in res)
    
    mock_import.side_effect = ImportError("err")
    res2 = doc.check_python_deps()
    assert all(not r.ok for r in res2)
    with patch("subprocess.run"):
        res2[0].fix()

@patch("blackoutkit.doctor._gdpi_backend", return_value="native")
def test_check_bins_present(mock_backend, tmp_path):
    with patch("blackoutkit.downloader.BINS_DIR", tmp_path):
        res = doc.check_bins_present()
        assert not res[0].ok

@patch("blackoutkit.doctor.BINS_DIR")
@patch("blackoutkit.doctor._gdpi_backend")
def test_check_windivert(mock_backend, mock_bins):
    mock_backend.return_value = "legacy"
    mock_bins.__truediv__.return_value.exists.return_value = False
    assert doc.check_windivert().ok is False
    
    mock_bins.__truediv__.return_value.exists.return_value = True
    assert doc.check_windivert().ok is True

@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_check_network_driver(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    assert doc.check_network_driver().ok is True
    
    mock_run.return_value = MagicMock(returncode=1)
    res = doc.check_network_driver()
    assert res.ok is False
    res.fix()
    
    mock_run.side_effect = Exception("err")
    assert doc.check_network_driver().ok is False

@patch("sys.platform", "win32")
@patch("os.environ", {"PATH": "dummy"})
@patch("sys.argv", ["test.exe"])
def test_check_system_path():
    res = doc.check_system_path()
    assert res.ok is False

@patch("urllib.request.urlopen")
def test_check_internet(mock_url):
    assert doc.check_internet().ok is True
    mock_url.side_effect = Exception("err")
    assert doc.check_internet().ok is False

@patch("shutil.disk_usage")
def test_check_disk_space(mock_disk):
    mock_disk.return_value = MagicMock(free=500*1024*1024)
    assert doc.check_disk_space().ok is True
    mock_disk.return_value = MagicMock(free=100*1024*1024)
    assert doc.check_disk_space().ok is False

@patch("subprocess.run")
def test_check_binary_runnable(mock_run, tmp_path):
    with patch("blackoutkit.doctor.BINS_DIR", tmp_path), \
         patch("blackoutkit.doctor._gdpi_backend", return_value="legacy"):
        engine = tmp_path / "blackout-engine.exe"
        engine.touch()
        gdpi = tmp_path / "goodbyedpi.exe"
        gdpi.touch()
        
        mock_run.return_value = MagicMock(returncode=1)
        res = doc.check_binary_runnable()
        assert len(res) == 2
        assert res[0].ok is True
        
        mock_run.side_effect = FileNotFoundError()
        assert doc.check_binary_runnable()[1].ok is False
        
        mock_run.side_effect = PermissionError()
        assert doc.check_binary_runnable()[0].ok is False

@patch("blackoutkit.security.configs_are_obfuscated")
def test_check_config_security(mock_obf):
    mock_obf.return_value = True
    assert doc.check_config_security().ok is True
    
    mock_obf.return_value = False
    with patch("blackoutkit.config.manager.load_configs", return_value=["c"]):
        res = doc.check_config_security()
        assert res.ok is False

@patch("psutil.process_iter")
@patch("os.getpid", return_value=123)
def test_check_process_conflicts(mock_pid, mock_iter):
    assert doc.check_process_conflicts().ok is True
    
    mock_p = MagicMock()
    mock_p.info = {"pid": 456, "name": "xray.exe"}
    mock_p.exe.return_value = "c:\\blackout-kit\\xray.exe"
    mock_p.name.return_value = "xray.exe"
    mock_p.pid = 456
    mock_iter.return_value = [mock_p]
    
    res = doc.check_process_conflicts()
    assert res.ok is False
    res.fix()

@patch("sys.platform", "win32")
@patch("blackoutkit.security.disable_kill_switch")
@patch("blackoutkit.settings.set_value")
@patch("blackoutkit.settings.load", return_value={"kill_switch": True})
def test_check_firewall_rules_resets_unsupported_windows_setting(mock_load, mock_set_value, mock_disable):
    result = doc.check_firewall_rules()

    assert result.ok is False
    assert result.fixable is True
    assert "unavailable" in result.message
    result.fix()
    mock_disable.assert_called_once()
    mock_set_value.assert_called_once_with("kill_switch", False)


@patch("sys.platform", "win32")
@patch("blackoutkit.settings.load", return_value={"kill_switch": False})
def test_check_firewall_rules_reports_windows_unavailability_when_disabled(mock_load):
    result = doc.check_firewall_rules()

    assert result.ok is True
    assert "unavailable" in result.message

@patch("sys.platform", "win32")
@patch("platform.machine", return_value="AMD64")
@patch("platform.release", return_value="10")
@patch("platform.version", return_value="10.0")
def test_check_windows_compat(mock_ver, mock_rel, mock_mach):
    assert doc.check_windows_compat().ok is True

@patch("blackoutkit.proxy_manager.is_admin", return_value=True)
def test_check_admin_privileges(mock_admin):
    assert doc.check_admin_privileges().ok is True

@patch("sys.platform", "win32")
@patch("blackoutkit.tools.get_network_recovery_snapshot")
def test_check_tun_adapter(mock_snapshot):
    mock_snapshot.return_value = {
        "adapters": [{
            "Name": "TAP-Windows", "InterfaceIndex": 10, "Status": "Up",
            "InterfaceDescription": "TAP-Windows Adapter", "DriverDescription": "TAP",
            "IpAddresses": ["10.8.0.2/24"], "DnsServers": [],
        }],
        "routes": [{"InterfaceIndex": 10, "DestinationPrefix": "10.8.0.0/24", "NextHop": "0.0.0.0"}],
    }
    assert doc.check_tun_adapter().ok is True

@patch("sys.platform", "win32")
@patch("blackoutkit.proxy_manager.is_admin", return_value=True)
@patch("subprocess.run")
def test_check_firewall_exclusion(mock_run, mock_admin):
    mock_run.return_value = MagicMock(stdout=str(doc.BINS_DIR).lower())
    assert doc.check_firewall_exclusion().ok is True

@patch("blackoutkit.doctor.check_app_data_dir", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_settings", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_disk_space", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_internet", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_country_profile", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_network_driver", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_windivert", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_system_path", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_config_security", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_process_conflicts", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_firewall_rules", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_firewall_exclusion", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_windows_compat", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_tun_adapter", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_ports_in_use", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_admin_privileges", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_stale_proxy", return_value=doc.CheckResult("t", True, "m"))
@patch("blackoutkit.doctor.check_data_files", return_value=[])
@patch("blackoutkit.doctor.check_python_deps", return_value=[])
@patch("blackoutkit.doctor.check_bins_present", return_value=[])
@patch("blackoutkit.doctor.check_binary_runnable", return_value=[])
@patch("blackoutkit.doctor.check_bins_dir")
def test_run_all_checks(*mocks):
    mocks[0].return_value = doc.CheckResult("test", False, "msg", fixable=True, fix=lambda: None)
    res = doc.run_all_checks(auto_fix=True)
    assert res[0].ok is True

@patch("sys.platform", "win32")
@patch("blackoutkit.settings.load", return_value={})
@patch("winreg.OpenKey")
@patch("winreg.QueryValueEx")
def test_check_stale_proxy(mock_q, mock_ok, mock_load):
    # test disabled
    mock_q.side_effect = [(0, None), ("", None)]
    assert doc.check_stale_proxy().ok is True
    
    # test active but ours
    mock_q.side_effect = [(1, None), ("127.0.0.1:10808", None)]
    with patch("blackoutkit.daemon.get_pid", return_value=None):
        res = doc.check_stale_proxy()
        assert res.ok is False
        
    # test active but ours and daemon running
    mock_q.side_effect = [(1, None), ("127.0.0.1:10808", None)]
    with patch("blackoutkit.daemon.get_pid", return_value=123):
        assert doc.check_stale_proxy().ok is True
        
    # test external
    mock_q.side_effect = [(1, None), ("8.8.8.8:8080", None)]
    assert doc.check_stale_proxy().ok is True
    
    # test winreg exception
    mock_ok.side_effect = Exception("err")
    assert doc.check_stale_proxy().ok is True

@patch("psutil.net_connections")
@patch("blackoutkit.settings.load", return_value={})
def test_check_ports_in_use(mock_load, mock_net):
    # test ok
    mock_net.return_value = []
    assert doc.check_ports_in_use().ok is True
    
    # test conflict
    conn = MagicMock()
    conn.status = "LISTEN"
    conn.laddr.port = 40443
    conn.pid = 123
    mock_net.return_value = [conn]
    
    with patch("psutil.Process") as mock_proc:
        mock_proc.return_value.name.return_value = "other.exe"
        res = doc.check_ports_in_use()
        assert res.ok is False
        res.fix()

def test_get_execution_context():
    with patch("sys.argv", ["blackout.py"]):
        ctx = doc.get_execution_context()
        assert ctx["prefix"] == "python blackout.py"
    
    with patch("sys.argv", ["blackout"]):
        ctx = doc.get_execution_context()
        assert ctx["prefix"] == "blackout"

@patch("blackoutkit.doctor._load_country_profile_quietly")
def test_check_country_profile(mock_load):
    mock_load.return_value = MagicMock(name="Test", code="TS", censorship_level="High")
    assert doc.check_country_profile().ok is True
