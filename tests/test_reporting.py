"""Tests for advanced reporting exports."""

import csv
import json
from datetime import datetime, timedelta, timezone

import pytest

from blackoutkit.reporting import ReportGenerator


def _write_evidence(tmp_path):
    now = datetime.now(timezone.utc)
    traffic = [
        {
            "ts": now.timestamp(),
            "process": "browser.exe",
            "protocol": "TCP",
            "local": "192.168.1.10:50000",
            "remote": "8.8.8.8:443",
            "status": "ESTABLISHED",
            "bytes_sent": 1024,
            "bytes_recv": 2048,
        },
        {
            "ts": (now - timedelta(hours=48)).timestamp(),
            "process": "old.exe",
            "protocol": "UDP",
            "local": "192.168.1.10:53000",
            "remote": "1.1.1.1:53",
            "status": "NONE",
            "bytes_sent": 64,
            "bytes_recv": 128,
        },
    ]
    (tmp_path / "traffic.jsonl").write_text(
        "\n".join(json.dumps(item) for item in traffic) + "\nnot-json\n",
        encoding="utf-8",
    )

    anomaly_dir = tmp_path / "logs"
    anomaly_dir.mkdir()
    (anomaly_dir / "anomalies.json").write_text(
        json.dumps(
            [
                {
                    "timestamp": now.isoformat(),
                    "anomaly_type": "bulk_exfiltration",
                    "severity": "critical",
                    "description": "Large transfer to 8.8.8.8 token=secret",
                    "affected_ip": "8.8.8.8",
                    "affected_port": 443,
                    "metric_value": 500,
                    "threshold": 10,
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "recovery_audit.jsonl").write_text(
        json.dumps(
            {
                "timestamp": now.isoformat(),
                "source": "cli-user",
                "device": "workstation-01",
                "actions": [
                    {
                        "name": "flush_dns",
                        "ok": True,
                        "detail": "Reset 192.168.1.10 password=secret",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )


class TestBuildReport:
    def test_combines_summary_usage_anomaly_and_audit_evidence(self, tmp_path):
        _write_evidence(tmp_path)
        report = ReportGenerator(data_dir=tmp_path, device_name="test-device").build_report()

        assert report["summary"] == {
            "total_connections": 1,
            "bytes_sent": 1024,
            "bytes_received": 2048,
            "total_anomalies": 1,
            "anomalies_by_severity": {"critical": 1},
            "audit_actions": 1,
        }
        assert report["usage_by_hour"][0]["connections"] == 1
        assert report["audit_events"][0]["action"] == "flush_dns"
        assert "secret" not in report["audit_events"][0]["detail"]
        assert "secret" not in report["anomalies"][0]["description"]

    @pytest.mark.parametrize("mode", ["gdpr", "hipaa", "soc2"])
    def test_builds_each_compliance_checklist(self, tmp_path, mode):
        report = ReportGenerator(data_dir=tmp_path).build_report(compliance_mode=mode)

        assert report["compliance_mode"] == mode
        assert len(report["compliance_checklist"]) == 4
        assert report["compliance_disclaimer"]

    @pytest.mark.parametrize("mode", ["gdpr", "hipaa"])
    def test_privacy_profiles_pseudonymize_identifiers(self, tmp_path, mode):
        _write_evidence(tmp_path)
        report = ReportGenerator(
            data_dir=tmp_path, device_name="workstation-01"
        ).build_report(compliance_mode=mode)
        serialized = json.dumps(report)

        for sensitive in (
            "workstation-01",
            "browser.exe",
            "192.168.1.10",
            "8.8.8.8",
            "cli-user",
        ):
            assert sensitive not in serialized
        assert "anon-" in serialized

    def test_soc2_preserves_operational_identifiers(self, tmp_path):
        _write_evidence(tmp_path)
        report = ReportGenerator(data_dir=tmp_path).build_report(
            compliance_mode="soc2"
        )

        assert report["connections"][0]["process"] == "browser.exe"
        assert report["anomalies"][0]["affected_ip"] == "8.8.8.8"

    def test_ignores_missing_and_corrupt_evidence(self, tmp_path):
        (tmp_path / "logs").mkdir()
        (tmp_path / "logs" / "anomalies.json").write_text("invalid", encoding="utf-8")

        report = ReportGenerator(data_dir=tmp_path).build_report()

        assert report["summary"]["total_connections"] == 0
        assert report["summary"]["total_anomalies"] == 0
        assert report["summary"]["audit_actions"] == 0

    def test_rejects_invalid_options(self, tmp_path):
        generator = ReportGenerator(data_dir=tmp_path)

        with pytest.raises(ValueError, match="compliance mode"):
            generator.build_report(compliance_mode="pci")
        with pytest.raises(ValueError, match="greater than zero"):
            generator.build_report(since_hours=0)
        with pytest.raises(ValueError, match="report format"):
            generator.export(tmp_path / "report.txt", format="txt")


class TestExports:
    def test_csv_contains_all_record_types(self, tmp_path):
        _write_evidence(tmp_path)
        output = tmp_path / "nested" / "report.csv"

        exported = ReportGenerator(data_dir=tmp_path).export(
            output, format="csv", compliance_mode="soc2"
        )

        with exported.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        record_types = {row["record_type"] for row in rows}
        assert {
            "summary",
            "connection",
            "anomaly",
            "usage",
            "audit",
            "compliance_control",
        } <= record_types

    def test_pdf_has_valid_signature_and_content(self, tmp_path):
        _write_evidence(tmp_path)
        output = tmp_path / "report.pdf"

        exported = ReportGenerator(data_dir=tmp_path).export(
            output, format="pdf", compliance_mode="gdpr"
        )

        assert exported.read_bytes().startswith(b"%PDF-")
        assert exported.stat().st_size > 1000
