import pytest
import os
from blackoutkit.tools import (
    explain_network_state,
    save_ssh_profile,
    list_ssh_profiles,
    remove_ssh_profile,
    run_web_api_dashboard,
)

def test_explain_network_state():
    res = explain_network_state()
    assert isinstance(res, dict)
    assert "security_score" in res
    assert "anomalies" in res
    assert "active_processes_count" in res

def test_ssh_vault():
    assert save_ssh_profile("test_p4", "10.0.0.1", "admin", port=2222)
    profiles = list_ssh_profiles()
    assert any(p["name"] == "test_p4" for p in profiles)
    p = next(p for p in profiles if p["name"] == "test_p4")
    assert p["host"] == "10.0.0.1"
    assert p["port"] == 2222
    assert remove_ssh_profile("test_p4")
    assert not any(p["name"] == "test_p4" for p in list_ssh_profiles())
