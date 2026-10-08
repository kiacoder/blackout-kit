import base64
import pytest
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
@patch("blackoutkit.linux_network.kill_switch_is_active", return_value=True)
@patch("blackoutkit.linux_network.remove_owned_firewall", return_value=(True, "removed"))
@patch("blackoutkit.linux_network.enable_kill_switch", return_value=(True, "enabled"))
@patch("blackoutkit.security._linux_kill_switch_endpoints", return_value=[("1.1.1.1", 443)])
def test_kill_switch_linux(mock_endpoints, mock_enable, mock_remove, mock_active):
    assert sec.enable_kill_switch() is True
    mock_enable.assert_called_once_with([("1.1.1.1", 443)])
    assert sec.disable_kill_switch() is True
    mock_remove.assert_called_once()
    ok, details = sec.test_kill_switch()
    assert ok is True
    assert "Linux kill switch is active" in details
    assert sec.kill_switch_is_active() is True


@patch("sys.platform", "linux")
@patch("blackoutkit.linux_network.enable_kill_switch", return_value=(False, "No validated proxy endpoint IP and port are available"))
@patch("blackoutkit.security._linux_kill_switch_endpoints", return_value=[])
def test_linux_kill_switch_refuses_missing_endpoint_allowlist(mock_endpoints, mock_enable):
    assert sec.enable_kill_switch() is False
    mock_enable.assert_called_once_with([])

@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_enable_kill_switch_win32_cleans_legacy_rules(mock_run):
    mock_run.return_value = MagicMock(stdout="OK")

    assert sec.enable_kill_switch() is False
    assert mock_run.call_count == 1
    assert "BlackoutKit-KillSwitch-Block" in mock_run.call_args.args[0][3]


@patch("sys.platform", "win32")
def test_kill_switch_is_unavailable_on_windows():
    assert sec.kill_switch_is_active() is False


@patch("sys.platform", "win32")
def test_test_kill_switch_reports_windows_unavailability():
    passed, message = sec.test_kill_switch()

    assert passed is False
    assert "unavailable on Windows" in message


def test_proxy_process_list_excludes_shared_library(tmp_path):
    with patch("blackoutkit.security.BINS_DIR", tmp_path):
        (tmp_path / "blackout_core.dll").write_bytes(b"dll")
        (tmp_path / "xray.exe").write_bytes(b"exe")

        processes = sec._get_proxy_processes()

    assert str((tmp_path / "xray.exe").resolve()) in processes
    assert str((tmp_path / "blackout_core.dll").resolve()) not in processes

@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_enable_kill_switch_removes_legacy_rules_before_refusing(mock_run):
    mock_run.return_value = MagicMock(stdout="OK")

    assert sec.enable_kill_switch() is False
    mock_run.assert_called_once()
    assert "BlackoutKit-KillSwitch-Block" in mock_run.call_args.args[0][3]


@patch("sys.platform", "win32")
@patch("subprocess.run", side_effect=OSError("powershell unavailable"))
def test_enable_kill_switch_handles_legacy_cleanup_failure(mock_run):
    assert sec.enable_kill_switch() is False


@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_disable_kill_switch_win32(mock_run):
    mock_run.return_value = MagicMock(stdout="OK")
    assert sec.disable_kill_switch() is True

@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_kill_switch_status_does_not_query_unsafe_legacy_rules(mock_run):
    assert sec.kill_switch_is_active() is False
    mock_run.assert_not_called()


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
def test_obfuscate_configs_no_file(tmp_path):
    # Keep the secret-vault file and settings out of the shared sandbox home so
    # this test can't leak state into test_deobfuscate_configs_no_file.
    with patch("blackoutkit.vault.ENC_SECRETS_FILE", tmp_path / "secrets.enc"), \
         patch("blackoutkit.security.APP_DATA_DIR", tmp_path):
        sec.obfuscate_configs()

# Let's use real file operations via tmp_path for crypto tests
def test_obfuscate_deobfuscate_configs_full(tmp_path):
    conf = tmp_path / "configs.txt"
    enc = tmp_path / "configs.enc"
    conf.write_bytes(b"secret config")
    
    with patch("blackoutkit.security.CONFIGS_FILE", conf), \
         patch("blackoutkit.security.ENC_CONFIGS", enc), \
         patch("blackoutkit.security.APP_DATA_DIR", tmp_path), \
         patch("blackoutkit.vault.ENC_SECRETS_FILE", tmp_path / "secrets.enc"):
         
        sec.obfuscate_configs()
        assert not conf.exists()
        assert enc.exists()
        assert sec.configs_are_obfuscated()
        
        ok = sec.deobfuscate_configs()
        assert ok
        assert conf.exists()
        assert conf.read_bytes() == b"secret config"

def test_deobfuscate_configs_no_file(tmp_path):
    with patch("blackoutkit.security.ENC_CONFIGS", MagicMock(exists=MagicMock(return_value=False))), \
         patch("blackoutkit.vault.ENC_SECRETS_FILE", tmp_path / "secrets.enc"):
        assert sec.deobfuscate_configs() is False

# === AV EXCLUSION: WinDivert driver folder only, never automatic ===
@pytest.fixture
def isolated_bins(tmp_path, monkeypatch):
    """A bins/ layout with the isolated WinDivert driver folder holding only the driver."""
    bins = tmp_path / "bins"
    folder = bins / "windivert"
    folder.mkdir(parents=True)
    (folder / "WinDivert.dll").write_bytes(b"MZ")
    (folder / "WinDivert64.sys").write_bytes(b"MZ")
    monkeypatch.setattr(sec, "BINS_DIR", bins)
    monkeypatch.setattr(sec, "WINDIVERT_DIR", folder)
    return bins, folder


def _encoded_script(mock_run) -> str:
    args = mock_run.call_args.args[0]
    return base64.b64decode(args[args.index("-EncodedCommand") + 1]).decode("utf-16-le")


@patch("sys.platform", "linux")
def test_defender_functions_are_noops_off_windows():
    assert sec.add_windivert_exclusion(confirmed=True) is False
    assert sec.remove_windivert_exclusion(confirmed=True) is False
    assert sec.windivert_folder_excluded() is False
    assert sec.verify_exclusion_added() is False
    assert sec.list_defender_exclusions() == []


@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_add_never_runs_without_explicit_confirmation(mock_run, isolated_bins):
    assert sec.add_windivert_exclusion() is False
    assert sec.add_windivert_exclusion(confirmed=False) is False
    mock_run.assert_not_called()


@patch("sys.platform", "win32")
@patch("subprocess.run")
@patch("blackoutkit.elevate.launch_elevated", return_value=(None, None))
def test_uac_is_not_requested_without_confirmation(mock_elevate, mock_run, isolated_bins):
    with patch.object(sec, "list_defender_exclusions", return_value=[]):
        assert sec.add_windivert_exclusion(confirmed=False) is False
    mock_elevate.assert_not_called()
    mock_run.assert_not_called()


@patch("sys.platform", "win32")
@patch("subprocess.run")
@patch("blackoutkit.elevate.launch_elevated")
def test_add_targets_only_the_driver_folder_and_requests_uac_last(mock_elevate, mock_run, isolated_bins):
    bins, folder = isolated_bins
    mock_run.return_value = MagicMock(stdout="", returncode=1)
    mock_elevate.return_value = (None, None)
    with patch.object(sec, "list_defender_exclusions", side_effect=[[], [], [str(folder)]]):
        assert sec.add_windivert_exclusion(confirmed=True) is True
    script = _encoded_script(mock_run)
    assert f"Add-MpPreference -ExclusionPath '{folder}'" in script
    assert f"-ExclusionPath '{bins}'" not in script  # never the broad bins/ parent
    mock_elevate.assert_called_once()
    elevated_script = base64.b64decode(
        mock_elevate.call_args.args[1][-1]
    ).decode("utf-16-le")
    assert elevated_script == script


@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_add_refuses_folder_holding_anything_besides_the_driver(mock_run, isolated_bins):
    _bins, folder = isolated_bins
    (folder / "goodbyedpi.exe").write_bytes(b"MZ")
    assert "must contain only" in sec.windivert_folder_problem()
    assert sec.add_windivert_exclusion(confirmed=True) is False
    mock_run.assert_not_called()


@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_add_refuses_when_target_is_bins_itself(mock_run, tmp_path, monkeypatch):
    bins = tmp_path / "bins"
    bins.mkdir()
    monkeypatch.setattr(sec, "BINS_DIR", bins)
    monkeypatch.setattr(sec, "WINDIVERT_DIR", bins)
    assert sec.windivert_folder_problem() is not None
    assert sec.add_windivert_exclusion(confirmed=True) is False
    mock_run.assert_not_called()


def test_problem_reports_missing_and_linked_folders(tmp_path, monkeypatch):
    bins = tmp_path / "bins"
    bins.mkdir()
    monkeypatch.setattr(sec, "BINS_DIR", bins)
    monkeypatch.setattr(sec, "WINDIVERT_DIR", bins / "windivert")
    assert "does not exist" in sec.windivert_folder_problem()

    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / "WinDivert.dll").write_bytes(b"MZ")
    (real / "WinDivert64.sys").write_bytes(b"MZ")
    try:
        (bins / "windivert").symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    assert "link or junction" in sec.windivert_folder_problem()


def test_exclusion_match_is_exact_not_substring(isolated_bins):
    _bins, folder = isolated_bins
    assert sec.windivert_folder_excluded([f"{folder}2"]) is False
    assert sec.windivert_folder_excluded([str(folder.parent)]) is False
    assert sec.windivert_folder_excluded([str(folder)]) is True


@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_list_and_verify_read_defender_state(mock_run, isolated_bins):
    _bins, folder = isolated_bins
    mock_run.return_value = MagicMock(stdout=f"{folder}\nD:\\\\tools\n", returncode=0)
    assert sec.verify_exclusion_added() is True
    assert sec.list_defender_exclusions() == [str(folder), "D:\\\\tools"]


@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_setup_declined_changes_nothing_and_points_to_socks_modes(mock_run, isolated_bins):
    messages = []
    with patch.object(sec, "list_defender_exclusions", return_value=[]), \
         patch("blackoutkit.elevate.launch_elevated") as mock_elevate:
        status = sec.run_windivert_exclusion_setup(confirm=lambda: False, emit=messages.append)
    assert status == "declined"
    mock_run.assert_not_called()
    mock_elevate.assert_not_called()
    text = "\n".join(messages)
    assert "No changes were made" in text
    assert "SOCKS5" in text


@patch("sys.platform", "win32")
@patch("subprocess.run")
@patch("blackoutkit.elevate.launch_elevated")
def test_warning_is_shown_and_confirmed_before_uac(mock_elevate, mock_run, isolated_bins):
    _bins, folder = isolated_bins
    events = []
    mock_run.return_value = MagicMock(stdout="", returncode=1)
    mock_elevate.side_effect = lambda *a, **k: (events.append("uac"), (None, None))[1]

    def emit(message):
        events.append(("emit", message))

    def confirm():
        events.append("confirm")
        return True

    # reads: already-present check, pre-add check, after the non-elevated try (unchanged), after UAC
    with patch.object(sec, "list_defender_exclusions", side_effect=[[], [], [], [str(folder)]]):
        status = sec.run_windivert_exclusion_setup(confirm=confirm, emit=emit)
    assert status == "added"
    warning_index = next(i for i, e in enumerate(events) if isinstance(e, tuple) and "FALSE POSITIVES" in e[1])
    assert warning_index < events.index("confirm") < events.index("uac")
    warning = events[warning_index][1]
    assert str(folder) in warning
    assert "blackout config --remove-defender-exclusion" in warning


@patch("sys.platform", "win32")
@patch("subprocess.run")
@patch("blackoutkit.elevate.launch_elevated")
def test_setup_refuses_unsafe_folder_without_prompting(mock_elevate, mock_run, isolated_bins):
    _bins, folder = isolated_bins
    (folder / "extra.exe").write_bytes(b"MZ")
    confirm = MagicMock(return_value=True)
    status = sec.run_windivert_exclusion_setup(confirm=confirm, emit=lambda _m: None)
    assert status == "unsafe-folder"
    confirm.assert_not_called()
    mock_run.assert_not_called()
    mock_elevate.assert_not_called()


@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_setup_reports_existing_exclusion_without_changes(mock_run, isolated_bins):
    _bins, folder = isolated_bins
    with patch.object(sec, "list_defender_exclusions", return_value=[str(folder)]):
        status = sec.run_windivert_exclusion_setup(confirm=lambda: True, emit=lambda _m: None)
    assert status == "already-present"
    mock_run.assert_not_called()


@patch("sys.platform", "win32")
@patch("subprocess.run")
@patch("blackoutkit.elevate.launch_elevated", return_value=(None, None))
def test_remove_is_narrow_and_confirmed(mock_elevate, mock_run, isolated_bins):
    _bins, folder = isolated_bins
    mock_run.return_value = MagicMock(stdout="", returncode=1)
    # reads: present-check, pre-remove check, after the non-elevated try (still present), after UAC (gone)
    with patch.object(sec, "list_defender_exclusions", side_effect=[[str(folder)], [str(folder)], [str(folder)], []]):
        status = sec.run_windivert_exclusion_setup(confirm=lambda: True, emit=lambda _m: None, remove=True)
    assert status == "removed"
    assert f"Remove-MpPreference -ExclusionPath '{folder}'" in _encoded_script(mock_run)
    mock_elevate.assert_called_once()


@patch("sys.platform", "win32")
@patch("subprocess.run")
def test_remove_declined_changes_nothing(mock_run, isolated_bins):
    _bins, folder = isolated_bins
    with patch.object(sec, "list_defender_exclusions", return_value=[str(folder)]):
        status = sec.run_windivert_exclusion_setup(confirm=lambda: False, emit=lambda _m: None, remove=True)
    assert status == "declined"
    mock_run.assert_not_called()


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
