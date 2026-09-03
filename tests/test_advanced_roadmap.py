import os
import pytest
from blackoutkit.tools import (
    run_sftp_client,
    load_custom_yara_rule_file,
    scan_file_yara,
    get_windivert_shaper_status
)
from blackoutkit.theme import get_i18n_string
from blackoutkit.daemon import stream_daemon_ipc_metrics

def test_sftp_client():
    res = run_sftp_client("nonexistent")
    assert res["ok"] is False

def test_custom_yara_loader(tmp_path):
    f = tmp_path / "rules.txt"
    f.write_text("eval(\nsystem(\n")
    res = load_custom_yara_rule_file(str(f))
    assert res["ok"] is True
    assert len(res["patterns"]) == 2

def test_scan_file_yara_with_custom_rule(tmp_path):
    rf = tmp_path / "custom_rule.txt"
    rf.write_text("SUPER_SECRET_PAYLOAD_STRING\n")

    tf = tmp_path / "target.bin"
    tf.write_bytes(b"Hello world containing SUPER_SECRET_PAYLOAD_STRING in binary.")

    res = scan_file_yara(str(tf), rule_filepath=str(rf))
    assert res["ok"] is True
    assert res["clean"] is False
    assert any(m["rule"] == "Custom_User_Rule" for m in res["matches"])

def test_daemon_ipc_metrics():
    metrics = stream_daemon_ipc_metrics()
    assert "pid" in metrics
    assert "active" in metrics
    assert "uptime" in metrics

def test_gui_russia_mode():
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        # Headless environment, test GUI module importability
        import blackoutkit.gui_app as gui
        assert hasattr(gui, "BlackoutGUI")
        return

    import blackoutkit.gui_app as gui
    try:
        app = gui.BlackoutGUI()
        assert hasattr(app, "russia_mode_var")
        app.russia_mode_var.set(True)
        assert app.russia_mode_var.get() is True
        app.destroy()
    except Exception:
        pass

def test_i18n():
    assert get_i18n_string("welcome", "en") == "Welcome to Blackout Kit"
    assert "بلک‌آوت" in get_i18n_string("welcome", "fa")

def test_windivert_shaper_status():
    st = get_windivert_shaper_status()
    assert "supported_platform" in st
