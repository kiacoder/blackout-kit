"""Tests for the sanitized support bundle."""
import json

from blackoutkit import support_bundle


def test_scrub_line_drops_proxy_uri_lines():
    assert support_bundle.scrub_line("added config: vless://uuid@host:443?x=1") is None
    assert support_bundle.scrub_line("import vmess://eyJhZGQiOiJhIn0=") is None
    assert support_bundle.scrub_line("hysteria2://pass@host:443/") is None


def test_scrub_line_redacts_assignment_values_keeps_keys():
    kept = support_bundle.scrub_line("ikev2_password = sup3r-secret")
    assert kept is not None
    assert "sup3r-secret" not in kept
    assert "ikev2_password" in kept
    assert support_bundle.REDACTED in kept or "[redacted]" in kept


def test_scrub_line_keeps_normal_log_lines():
    line = "2026-10-01 12:00:00 [INFO] Daemon starting (PID 1234). Engine: warp"
    assert support_bundle.scrub_line(line) == line


def test_scrub_text_removes_sensitive_lines_only():
    text = "\n".join([
        "safe line one",
        "trojan://password@server:443",
        "safe line two",
    ])
    scrubbed = support_bundle.scrub_text(text)
    assert "trojan://" not in scrubbed
    assert "safe line one" in scrubbed
    assert "safe line two" in scrubbed


def test_sanitized_settings_masks_secret_values(monkeypatch):
    monkeypatch.setattr(
        "blackoutkit.settings.load",
        lambda: {"security_mode": "SPEED", "ikev2_password": "real-secret", "selected_engine": "sni"},
    )
    sanitized = support_bundle.sanitized_settings()
    encoded = json.dumps(sanitized)
    assert "real-secret" not in encoded
    assert sanitized["security_mode"] == "SPEED"


def test_preview_has_structure_but_no_log_content():
    payload = support_bundle.preview()
    assert payload["preview"] is True
    logs = payload["logs"]
    assert "daemon_tail" not in logs
    assert "daemon_tail_chars" in logs
    assert payload["excluded"]
    assert payload["uploaded"] is False


def test_collect_has_required_sections():
    payload = support_bundle.collect()
    for section in (
        "bundle_schema_version", "generated_at", "system", "install",
        "versions", "snapshot", "daemon_errors", "logs",
        "recovery_history", "settings", "redaction_policy", "excluded",
    ):
        assert section in payload, f"missing {section}"
    assert payload["uploaded"] is False


def test_collect_output_contains_no_proxy_uri(monkeypatch):
    monkeypatch.setattr(
        "blackoutkit.daemon.read_logs",
        lambda lines=50: "vless://leak@host:443\nnormal line",
    )
    payload = support_bundle.collect()
    encoded = json.dumps(payload)
    assert "vless://" not in encoded
    assert "normal line" in encoded


def test_export_refuses_overwrite(tmp_path):
    target = tmp_path / "bundle.json"
    target.write_text("{}", encoding="utf-8")
    import pytest

    with pytest.raises(FileExistsError):
        support_bundle.export_bundle(target)


def test_export_writes_sanitized_json(tmp_path):
    target = tmp_path / "bundle.json"
    written = support_bundle.export_bundle(target)
    assert written == target
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["bundle_schema_version"] == support_bundle.BUNDLE_SCHEMA_VERSION
    assert payload["uploaded"] is False
