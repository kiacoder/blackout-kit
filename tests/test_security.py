import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import blackoutkit.security as sec
import blackoutkit.settings as cfg

# === MODES ===
def test_apply_mode():
    with patch("blackoutkit.settings.load", return_value={"xray_fingerprint": "chrome", "security_mode": "speed"}), \
         patch("blackoutkit.settings.save") as mock_save:
        sec.apply_mode("private")
        saved = mock_save.call_args[0][0]
        assert saved["security_mode"] == "private"
        assert saved["xray_fingerprint"] == "random"

def test_apply_mode_invalid():
    with pytest.raises(ValueError):
        sec.apply_mode("fake_mode")

def test_get_current_mode():
    with patch("blackoutkit.settings.load", return_value={"security_mode": "legend"}):
        assert sec.get_current_mode() == "legend"

def test_mode_description():
    assert "legendary" in sec.mode_description("legend").lower()

def test_is_mode_enforced():
    with patch("blackoutkit.settings.load", return_value={"security_mode": "private", "xray_fingerprint": "random", "xray_log_level": "none", "xray_mux_enabled": True, "gdpi_flags": "-9"}):
        ok, mismatches = sec.is_mode_enforced()
        assert ok is True
        assert len(mismatches) == 0

def test_is_mode_enforced_mismatch():
    with patch("blackoutkit.settings.load", return_value={"security_mode": "private", "xray_fingerprint": "chrome"}):
        ok, mismatches = sec.is_mode_enforced()
        assert ok is False
        assert len(mismatches) > 0

# === KILL SWITCH ===
@patch("sys.platform", "linux")
def test_kill_switch_linux():
    assert sec.enable_kill_switch() is False
    assert sec.disable_kill_switch() is False
    ok, details = sec.test_kill_switch()
    assert ok is True
    assert sec.kill_switch_is_active() is False

@patch("sys.platform", "win32")
@patch("subprocess.run")
@patch("blackoutkit.security._get_proxy_processes")
def test_enable_kill_switch_win32(mock_get_proxies, mock_run):
    mock_get_proxies.return_value = ["C:\\test\\xray.exe"]
    mock_run.return_value = MagicMock(stdout="OK:kill_switch_enabled", stderr="")
    with patch("blackoutkit.security.kill_switch_is_active", return_value=True):
        assert sec.enable_kill_switch() is True

@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_disable_kill_switch_win32(mock_run):
    mock_run.return_value = MagicMock(stdout="OK")
    assert sec.disable_kill_switch() is True

@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_kill_switch_is_active_win32(mock_run):
    mock_result = MagicMock()
    mock_result.stdout = "ACTIVE"
    mock_run.return_value = mock_result
    assert sec.kill_switch_is_active() is True
    
    mock_result.stdout = "FOO"
    assert sec.kill_switch_is_active() is False

@patch("sys.platform", "win32")
@patch("blackoutkit.security.kill_switch_is_active", return_value=True)
@patch("socket.create_connection", side_effect=OSError("Blocked"))
@patch("socket.getaddrinfo")
def test_test_kill_switch_success(mock_gai, mock_cc, mock_active):
    passed, msg = sec.test_kill_switch()
    assert passed is True
    assert "Kill switch VERIFIED" in msg

@patch("sys.platform", "win32")
@patch("blackoutkit.security.kill_switch_is_active", return_value=True)
@patch("socket.create_connection")
def test_test_kill_switch_failed_conn(mock_cc, mock_active):
    passed, msg = sec.test_kill_switch()
    assert passed is False
    assert "Kill switch FAILED" in msg

@patch("sys.platform", "win32")
@patch("blackoutkit.security.kill_switch_is_active", return_value=False)
def test_test_kill_switch_not_active(mock_active):
    passed, msg = sec.test_kill_switch()
    assert passed is False
    assert "Kill switch is NOT active" in msg


# === CRYPTO ===
@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_get_machine_id_win32(mock_run):
    mock_run.return_value = MagicMock(stdout="UUID\n12345678-1234-1234-1234-123456789012\n")
    assert sec._get_machine_id() == b"12345678-1234-1234-1234-123456789012"

@patch("sys.platform", "linux")
@patch("platform.node", return_value="linux-host")
def test_get_machine_id_linux(mock_node):
    assert sec._get_machine_id() == b"linux-host"

def test_atomic_write_bytes(tmp_path):
    target = tmp_path / "test.bin"
    sec._atomic_write_bytes(target, b"hello")
    assert target.read_bytes() == b"hello"

@patch("blackoutkit.security.CONFIGS_FILE", MagicMock(exists=MagicMock(return_value=False)))
def test_obfuscate_configs_no_file():
    sec.obfuscate_configs()

# Let's use real file operations via tmp_path for crypto tests
def test_obfuscate_deobfuscate_configs_full(tmp_path):
    conf = tmp_path / "configs.txt"
    enc = tmp_path / "configs.enc"
    conf.write_bytes(b"secret config")
    
    with patch("blackoutkit.security.CONFIGS_FILE", conf), \
         patch("blackoutkit.security.ENC_CONFIGS", enc), \
         patch("blackoutkit.security.APP_DATA_DIR", tmp_path):
         
        sec.obfuscate_configs()
        assert not conf.exists()
        assert enc.exists()
        assert sec.configs_are_obfuscated()
        
        ok = sec.deobfuscate_configs()
        assert ok
        assert conf.exists()
        assert conf.read_bytes() == b"secret config"

def test_deobfuscate_configs_no_file():
    with patch("blackoutkit.security.ENC_CONFIGS", MagicMock(exists=MagicMock(return_value=False))):
        assert sec.deobfuscate_configs() is False

# === AV EXCLUSION ===
@patch("sys.platform", "linux")
def test_defender_linux():
    assert sec.add_defender_exclusion() is False
    assert sec.remove_defender_exclusion() is False
    assert sec.verify_exclusion_added() is False
    assert sec.list_defender_exclusions() == []

@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_add_defender_exclusion_success(mock_run):
    mock_run.return_value = MagicMock(stdout="OK")
    assert sec.add_defender_exclusion(Path("C:\\bins")) is True

@patch("sys.platform", "win32")
@patch("subprocess.run")
@patch("blackoutkit.elevate.launch_elevated")
@patch("ctypes.windll.kernel32")
def test_add_defender_exclusion_elevate(mock_kernel, mock_elevate, mock_run):
    mock_run.return_value = MagicMock(stdout="")
    mock_elevate.return_value = (123, 456)
    
    # We need to mock the marker file writing
    original_mkstemp = tempfile.mkstemp
    def fake_mkstemp(*args, **kwargs):
        fd, path = original_mkstemp(*args, **kwargs)
        # write OK to marker file so it succeeds
        with open(path, "w") as f:
            f.write("OK")
        return fd, path
    
    with patch("tempfile.mkstemp", side_effect=fake_mkstemp):
        assert sec.add_defender_exclusion(Path("C:\\bins")) is True

@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_list_defender_exclusions(mock_run):
    mock_run.return_value = MagicMock(stdout="C:\\bins\nD:\\tools\n")
    assert sec.list_defender_exclusions() == ["C:\\bins", "D:\\tools"]

# === STABILITY TRACKING ===
def test_stability_tracker(tmp_path):
    stab_file = tmp_path / "stability.json"
    with patch("blackoutkit.security._STABILITY_FILE", stab_file), \
         patch("blackoutkit.security.APP_DATA_DIR", tmp_path):
        
        # Test empty
        sec.reset_stability()
        assert sec.get_stability_score("xray")["loss_pct"] == 100
        assert sec.all_stability_scores() == {}
        
        # Record some latency
        sec.record_latency("xray", 100.0)
        sec.record_latency("xray", 120.0)
        sec.record_latency("xray", None)  # loss
        
        score = sec.get_stability_score("xray")
        assert score["avg_ms"] == 110.0
        assert score["loss_pct"] > 0
        
        scores = sec.all_stability_scores()
        assert "xray" in scores
        
        # Test alert
        sec.record_latency("xray", None)
        sec.record_latency("xray", None) # high loss
        alert, msg = sec.stability_alert("xray", threshold_loss_pct=20)
        assert alert is True
        assert "packet loss" in msg
        
        # Reset
        sec.reset_stability("xray")
        assert sec.get_stability_score("xray")["loss_pct"] == 100
