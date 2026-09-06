"""CLI contracts for Phase 6 automation and reporting."""

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from blackoutkit import typer_cli


runner = CliRunner()


def test_phase6_commands_are_registered():
    tools_help = runner.invoke(typer_cli.app, ["tools", "--help"])
    report_help = runner.invoke(typer_cli.app, ["report", "--help"])
    feeds_help = runner.invoke(typer_cli.app, ["tools", "threat-feeds", "--help"])

    assert tools_help.exit_code == 0, tools_help.output
    assert report_help.exit_code == 0, report_help.output
    assert feeds_help.exit_code == 0, feeds_help.output
    for command in ("anomaly-check", "anomaly-log", "predict", "threat-feeds"):
        assert command in tools_help.output
    assert "export" in report_help.output
    for command in ("list", "add", "remove", "update"):
        assert command in feeds_help.output


def test_connection_event_adapter_parses_traffic_record():
    event = typer_cli._connection_event_from_traffic(
        {
            "ts": 100.0,
            "process": "browser",
            "protocol": "TCP",
            "local": "192.168.1.2:50000",
            "remote": "8.8.8.8:443",
            "status": "ESTABLISHED",
            "bytes_sent": 10,
            "bytes_recv": 20,
        }
    )

    assert event is not None
    assert (event.src_ip, event.dst_ip, event.dst_port) == (
        "192.168.1.2",
        "8.8.8.8",
        443,
    )
    assert event.protocol == "tcp"
    assert (event.bytes_sent, event.bytes_received) == (10, 20)


def test_anomaly_scan_adapter_detects_unusual_port(monkeypatch):
    monkeypatch.setattr(
        typer_cli,
        "_recent_traffic",
        lambda *_args: [
            {
                "ts": 100.0,
                "local": "192.168.1.2:50000",
                "remote": "10.0.0.1:3389",
                "protocol": "TCP",
                "status": "ESTABLISHED",
            }
        ],
    )

    payload = typer_cli._anomaly_scan_payload(24, 100, 3.0)

    assert payload["scanned"] == 1
    assert payload["detected"] == 1
    assert payload["anomalies"][0]["anomaly_type"] == "unusual_port"


def test_predict_adapter_uses_hourly_traffic_volume(monkeypatch):
    base = datetime.now().replace(minute=0, second=0, microsecond=0)
    samples = []
    for hour, count in ((8, 5), (2, 1)):
        for _ in range(count):
            samples.append(
                {
                    "ts": base.replace(hour=hour).timestamp(),
                    "protocol": "HTTPS",
                    "status": "ESTABLISHED",
                    "bytes_sent": 1000,
                    "bytes_recv": 2000,
                    "duration_sec": 1,
                }
            )
    monkeypatch.setattr(typer_cli, "_recent_traffic", lambda *_args: samples)

    payload = typer_cli._predict_payload(24, 100, "https", "8.8.8.8")

    assert payload["samples"] == 6
    assert payload["peak_hours"] == [8]


def test_anomaly_check_json_uses_safe_envelope(monkeypatch):
    payload = {
        "scanned": 10,
        "detected": 1,
        "summary": {"total": 1, "by_type": {"connection_spike": 1}, "by_severity": {"high": 1}},
        "anomalies": [],
    }
    monkeypatch.setattr(typer_cli, "_anomaly_scan_payload", lambda *_args: payload)

    result = runner.invoke(
        typer_cli.app,
        ["--json", "tools", "anomaly-check", "--hours", "12", "--limit", "50"],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["data"] == payload


def test_anomaly_check_rejects_invalid_window():
    result = runner.invoke(
        typer_cli.app, ["--json", "tools", "anomaly-check", "--hours", "0"]
    )

    assert result.exit_code == 2
    assert json.loads(result.output)["error"]["code"] == "invalid_input"


def test_anomaly_log_json_filters_and_serializes(monkeypatch):
    called = {}

    def payload(hours, limit, severity):
        called.update(hours=hours, limit=limit, severity=severity)
        return {"total": 0, "by_type": {}, "by_severity": {}, "anomalies": []}

    monkeypatch.setattr(typer_cli, "_anomaly_log_payload", payload)
    result = runner.invoke(
        typer_cli.app,
        ["--json", "tools", "anomaly-log", "--severity", "HIGH", "--limit", "5"],
    )

    assert result.exit_code == 0, result.output
    assert called == {"hours": 24, "limit": 5, "severity": "high"}
    assert json.loads(result.output)["data"]["total"] == 0


def test_predict_json_is_structured(monkeypatch):
    payload = {
        "samples": 20,
        "peak_hours": [8],
        "patterns": [],
        "recommendations": [],
    }
    monkeypatch.setattr(typer_cli, "_predict_payload", lambda *_args: payload)

    result = runner.invoke(typer_cli.app, ["--json", "tools", "predict"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["data"] == payload


def test_predict_quiet_suppresses_output(monkeypatch):
    monkeypatch.setattr(
        typer_cli,
        "_predict_payload",
        lambda *_args: {"samples": 0, "peak_hours": [], "patterns": [], "recommendations": []},
    )

    result = runner.invoke(typer_cli.app, ["--quiet", "tools", "predict"])

    assert result.exit_code == 0
    assert result.output == ""


def test_threat_feed_list_json_omits_source_url(monkeypatch):
    from blackoutkit.threat_feeds import ThreatFeed

    feed = ThreatFeed(
        name="private",
        url="https://token:secret@example.com/feed",
        feed_type="ip",
    )
    manager = Mock()
    manager.list_feeds.return_value = [feed]
    monkeypatch.setattr("blackoutkit.threat_feeds.ThreatFeedsManager", lambda: manager)

    result = runner.invoke(
        typer_cli.app, ["--json", "tools", "threat-feeds", "list"]
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["data"]["feeds"] == [
        {
            "enabled": True,
            "entry_count": 0,
            "feed_type": "ip",
            "last_updated": None,
            "name": "private",
        }
    ]
    assert "token:secret" not in result.output


def test_threat_feed_add_forwards_validated_configuration(monkeypatch):
    manager = Mock()
    manager.add_feed.return_value = True
    monkeypatch.setattr("blackoutkit.threat_feeds.ThreatFeedsManager", lambda: manager)

    result = runner.invoke(
        typer_cli.app,
        [
            "--json",
            "tools",
            "threat-feeds",
            "add",
            "custom",
            "--url",
            "https://example.com/feed",
            "--type",
            "IP",
        ],
    )

    assert result.exit_code == 0, result.output
    feed = manager.add_feed.call_args.args[0]
    assert (feed.name, feed.url, feed.feed_type) == (
        "custom",
        "https://example.com/feed",
        "ip",
    )
    assert json.loads(result.output)["data"] == {
        "added": True,
        "feed_type": "ip",
        "name": "custom",
    }


def test_threat_feed_update_returns_nonzero_for_partial_failure(monkeypatch):
    manager = Mock()
    manager.update_feeds.return_value = {"good": True, "bad": False}
    manager.feeds = {
        "good": SimpleNamespace(enabled=True),
        "bad": SimpleNamespace(enabled=True),
    }
    manager.get_stats.return_value = {
        "total_feeds": 2,
        "enabled_feeds": 2,
        "blocked_ips": 1,
        "blocked_domains": 0,
        "last_update": "now",
    }
    monkeypatch.setattr("blackoutkit.threat_feeds.ThreatFeedsManager", lambda: manager)

    result = runner.invoke(
        typer_cli.app, ["--json", "tools", "threat-feeds", "update"]
    )

    assert result.exit_code == 1
    assert json.loads(result.output)["data"]["failed"] == 1


def test_threat_feed_update_skips_disabled_without_failure(monkeypatch):
    manager = Mock()
    manager.update_feeds.return_value = {"disabled": False}
    manager.feeds = {"disabled": SimpleNamespace(enabled=False)}
    manager.get_stats.return_value = {
        "total_feeds": 1,
        "enabled_feeds": 0,
        "blocked_ips": 0,
        "blocked_domains": 0,
        "last_update": "never",
    }
    monkeypatch.setattr("blackoutkit.threat_feeds.ThreatFeedsManager", lambda: manager)

    result = runner.invoke(
        typer_cli.app, ["--json", "tools", "threat-feeds", "update"]
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["data"] | {"stats": None, "results": None} == {
        "updated": 0,
        "failed": 0,
        "skipped": 1,
        "stats": None,
        "results": None,
    }


def test_report_export_json_creates_csv(tmp_path, monkeypatch):
    now = datetime.now(timezone.utc).timestamp()
    traffic_log = tmp_path / "traffic.jsonl"
    traffic_log.write_text(
        json.dumps(
            {
                "ts": now,
                "process": "browser",
                "protocol": "TCP",
                "local": "127.0.0.1:1",
                "remote": "8.8.8.8:443",
                "status": "ESTABLISHED",
                "bytes_sent": 1,
                "bytes_recv": 2,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    from blackoutkit.reporting import ReportGenerator

    monkeypatch.setattr(
        "blackoutkit.reporting.ReportGenerator",
        lambda: ReportGenerator(data_dir=tmp_path, device_name="test"),
    )
    output = tmp_path / "report.csv"

    result = runner.invoke(
        typer_cli.app,
        [
            "--json",
            "report",
            "export",
            "--format",
            "csv",
            "--output",
            str(output),
            "--compliance",
            "gdpr",
        ],
    )

    assert result.exit_code == 0, result.output
    assert output.exists()
    assert json.loads(result.output)["data"] == {
        "compliance_mode": "gdpr",
        "exported": True,
        "format": "csv",
        "period_hours": 24,
    }


def test_report_export_rejects_invalid_format(tmp_path):
    result = runner.invoke(
        typer_cli.app,
        [
            "--json",
            "report",
            "export",
            "--format",
            "html",
            "--output",
            str(tmp_path / "report.html"),
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.output)["error"]["code"] == "invalid_input"


def test_report_group_json_requires_subcommand():
    result = runner.invoke(typer_cli.app, ["--json", "report"])

    assert result.exit_code == 2
    assert json.loads(result.output)["error"] == {
        "code": "missing_command",
        "message": "a report subcommand is required",
    }
