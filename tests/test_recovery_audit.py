import json

from blackoutkit import recovery_audit, tools


def test_recovery_audit_redacts_uri_credentials(monkeypatch, tmp_path):
    audit_file = tmp_path / "recovery_audit.jsonl"
    monkeypatch.setattr(recovery_audit, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(recovery_audit, "AUDIT_FILE", audit_file)

    recovery_audit.record(
        source="cli",
        flags={"flush_arp": False},
        results=[{"name": "Clear proxy", "ok": True, "detail": "vless://secret-user@proxy.example:443 password=secret"}],
    )

    content = audit_file.read_text()
    assert "secret-user" not in content
    assert "password=secret" not in content
    assert "[hidden]" in content


def test_recovery_audit_keeps_bounded_history(monkeypatch, tmp_path):
    audit_file = tmp_path / "recovery_audit.jsonl"
    monkeypatch.setattr(recovery_audit, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(recovery_audit, "AUDIT_FILE", audit_file)
    monkeypatch.setattr(recovery_audit, "MAX_RECORDS", 2)

    for index in range(3):
        recovery_audit.record(source="cli", flags={}, results=[{"name": str(index), "ok": True, "detail": "done"}])

    assert len(audit_file.read_text().splitlines()) == 2


def test_windows_preview_does_not_mutate(monkeypatch):
    monkeypatch.setattr(tools.sys, "platform", "win32")
    monkeypatch.setattr("blackoutkit.daemon.get_state", lambda: None)
    monkeypatch.setattr(tools, "get_network_recovery_snapshot", lambda: {"adapters": [], "routes": []})
    proxy_status = lambda: {"enabled": False, "server": ""}
    monkeypatch.setattr("blackoutkit.proxy_manager.get_proxy_status", proxy_status)
    mutate = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not mutate"))
    monkeypatch.setattr(tools, "clear_stale_blackout_proxy", mutate)
    monkeypatch.setattr(tools, "_run_recovery_script", mutate)

    plan = tools.plan_network_recovery()

    assert any(step["name"] == "Flush DNS cache" for step in plan)
