import pytest
from blackoutkit.tools import (
    run_sftp_client,
    load_custom_yara_rule_file,
    get_windivert_shaper_status
)
from blackoutkit.theme import get_i18n_string

def test_sftp_client():
    res = run_sftp_client("nonexistent")
    assert res["ok"] is False

def test_custom_yara_loader(tmp_path):
    f = tmp_path / "rules.txt"
    f.write_text("eval(\nsystem(\n")
    res = load_custom_yara_rule_file(str(f))
    assert res["ok"] is True
    assert len(res["patterns"]) == 2

def test_i18n():
    assert get_i18n_string("welcome", "en") == "Welcome to Blackout Kit"
    assert "بلک‌آوت" in get_i18n_string("welcome", "fa")

def test_windivert_shaper_status():
    st = get_windivert_shaper_status()
    assert "supported_platform" in st
