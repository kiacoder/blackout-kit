"""Local network, anomaly, and audit report exports."""

from __future__ import annotations

import csv
import hashlib
import html
import ipaddress
import json
import math
import platform
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from . import APP_DATA_DIR
from .recovery_audit import redact

SUPPORTED_FORMATS = {"csv", "pdf"}
SUPPORTED_COMPLIANCE_MODES = {"gdpr", "hipaa", "soc2"}

_CSV_FIELDS = [
    "record_type",
    "timestamp",
    "category",
    "severity",
    "actor",
    "device",
    "process",
    "protocol",
    "local",
    "remote",
    "port",
    "status",
    "bytes_sent",
    "bytes_received",
    "metric",
    "value",
    "threshold",
    "detail",
]
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:.%]*(?![A-Za-z0-9])"
)


class ReportGenerator:
    """Collect local evidence and export it as CSV or PDF."""

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        *,
        traffic_log: Optional[Path] = None,
        anomaly_log: Optional[Path] = None,
        audit_log: Optional[Path] = None,
        device_name: Optional[str] = None,
    ):
        self.data_dir = Path(data_dir or APP_DATA_DIR)
        self.traffic_log = Path(traffic_log or self.data_dir / "traffic.jsonl")
        self.anomaly_log = Path(anomaly_log or self.data_dir / "logs" / "anomalies.json")
        self.audit_log = Path(audit_log or self.data_dir / "recovery_audit.jsonl")
        self.device_name = device_name or platform.node() or platform.system()

    def build_report(
        self,
        *,
        compliance_mode: Optional[str] = None,
        since_hours: Optional[int] = 24,
    ) -> dict[str, Any]:
        """Build a normalized report without writing it to disk."""
        mode = self._validate_compliance_mode(compliance_mode)
        if since_hours is not None and since_hours <= 0:
            raise ValueError("since_hours must be greater than zero")

        generated_at = datetime.now(timezone.utc)
        cutoff = (
            generated_at - timedelta(hours=since_hours)
            if since_hours is not None
            else None
        )
        connections = [
            self._normalize_connection(item)
            for item in self._read_jsonl(self.traffic_log)
            if self._is_recent(item.get("ts"), cutoff)
        ]
        anomalies = [
            self._normalize_anomaly(item)
            for item in self._read_json_array(self.anomaly_log)
            if self._is_recent(item.get("timestamp"), cutoff)
        ]
        audit_events = []
        for record in self._read_jsonl(self.audit_log):
            if self._is_recent(record.get("timestamp"), cutoff):
                audit_events.extend(self._normalize_audit_record(record))

        report = {
            "generated_at": generated_at.isoformat(),
            "device": self.device_name,
            "period_hours": since_hours,
            "compliance_mode": mode,
            "connections": connections,
            "anomalies": anomalies,
            "usage_by_hour": self._usage_by_hour(connections),
            "audit_events": audit_events,
            "summary": self._summary(connections, anomalies, audit_events),
            "compliance_checklist": self._compliance_checklist(
                mode, connections, anomalies, audit_events
            ),
            "compliance_disclaimer": (
                "This export organizes technical evidence and does not certify compliance."
                if mode
                else None
            ),
        }
        return self._apply_privacy_profile(report, mode)

    def export(
        self,
        output: Path,
        *,
        format: str,
        compliance_mode: Optional[str] = None,
        since_hours: Optional[int] = 24,
    ) -> Path:
        """Build and write a report in the requested format."""
        export_format = str(format).lower().strip()
        if export_format not in SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported report format: {format}. Choose from: csv, pdf"
            )
        report = self.build_report(
            compliance_mode=compliance_mode, since_hours=since_hours
        )
        output = Path(output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        if export_format == "csv":
            self._write_csv(output, report)
        else:
            self._write_pdf(output, report)
        return output

    @staticmethod
    def _validate_compliance_mode(mode: Optional[str]) -> Optional[str]:
        if mode is None:
            return None
        normalized = str(mode).lower().strip()
        if normalized not in SUPPORTED_COMPLIANCE_MODES:
            raise ValueError(
                f"Unsupported compliance mode: {mode}. Choose from: gdpr, hipaa, soc2"
            )
        return normalized

    @staticmethod
    def _read_jsonl(path: Path):
        if not path.exists():
            return
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, dict):
                        yield item
        except OSError:
            return

    @staticmethod
    def _read_json_array(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            return []
        if not isinstance(data, list):
            return []
        return [item for item in data if isinstance(item, dict)]

    @classmethod
    def _is_recent(cls, value: Any, cutoff: Optional[datetime]) -> bool:
        timestamp = cls._parse_timestamp(value)
        return timestamp is not None and (cutoff is None or timestamp >= cutoff)

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[datetime]:
        if isinstance(value, bool):
            return None
        try:
            if isinstance(value, (int, float)):
                if not math.isfinite(float(value)):
                    return None
                return datetime.fromtimestamp(value, tz=timezone.utc)
            if isinstance(value, str):
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    return None
                return parsed.astimezone(timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
        return None

    @classmethod
    def _timestamp_text(cls, value: Any) -> str:
        parsed = cls._parse_timestamp(value)
        return parsed.isoformat() if parsed else (str(value) if value is not None else "")

    @classmethod
    def _normalize_connection(cls, item: dict[str, Any]) -> dict[str, Any]:
        received = item.get("bytes_recv")
        if received is None:
            received = item.get("bytes_received")
        return {
            "timestamp": cls._timestamp_text(item.get("ts")),
            "process": str(item.get("process", "unknown")),
            "protocol": str(item.get("protocol", "unknown")),
            "local": str(item.get("local", "")),
            "remote": str(item.get("remote", "")),
            "status": str(item.get("status", "unknown")),
            "bytes_sent": cls._safe_number(item.get("bytes_sent")),
            "bytes_received": cls._safe_number(received),
        }

    @classmethod
    def _normalize_anomaly(cls, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "timestamp": cls._timestamp_text(item.get("timestamp")),
            "anomaly_type": str(item.get("anomaly_type", "unknown")),
            "severity": str(item.get("severity", "unknown")),
            "description": redact(item.get("description", "")),
            "affected_ip": str(item.get("affected_ip", "")),
            "affected_port": item.get("affected_port"),
            "metric_value": cls._safe_number(item.get("metric_value")) if item.get("metric_value") is not None else None,
            "threshold": cls._safe_number(item.get("threshold")) if item.get("threshold") is not None else None,
        }

    def _normalize_audit_record(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        timestamp = self._timestamp_text(record.get("timestamp"))
        actor = redact(record.get("actor", record.get("source", "unknown")))
        device = redact(record.get("device", self.device_name))
        raw_actions = record.get("actions")
        actions = [item for item in raw_actions or [] if isinstance(item, dict)]
        if not actions:
            actions = [{"name": "audit_event", "ok": True, "detail": ""}]
        return [
            {
                "timestamp": timestamp,
                "actor": actor,
                "device": device,
                "action": redact(action.get("name", "unknown")),
                "status": "ok" if action.get("ok") else "failed",
                "detail": redact(action.get("detail", "")),
            }
            for action in actions
        ]

    @staticmethod
    def _safe_number(value: Any) -> float | int:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return 0
        if not math.isfinite(float(value)) or value < 0:
            return 0
        return value

    @classmethod
    def _usage_by_hour(cls, connections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        buckets: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"connections": 0, "bytes_sent": 0, "bytes_received": 0}
        )
        for connection in connections:
            timestamp = cls._parse_timestamp(connection["timestamp"])
            if timestamp is None:
                continue
            hour = timestamp.strftime("%Y-%m-%dT%H:00:00Z")
            buckets[hour]["connections"] += 1
            buckets[hour]["bytes_sent"] += connection["bytes_sent"]
            buckets[hour]["bytes_received"] += connection["bytes_received"]
        return [{"hour": hour, **buckets[hour]} for hour in sorted(buckets)]

    @staticmethod
    def _summary(
        connections: list[dict[str, Any]],
        anomalies: list[dict[str, Any]],
        audit_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        severity_counts: dict[str, int] = defaultdict(int)
        for anomaly in anomalies:
            severity_counts[anomaly["severity"]] += 1
        return {
            "total_connections": len(connections),
            "bytes_sent": sum(item["bytes_sent"] for item in connections),
            "bytes_received": sum(item["bytes_received"] for item in connections),
            "total_anomalies": len(anomalies),
            "anomalies_by_severity": dict(severity_counts),
            "audit_actions": len(audit_events),
        }

    @staticmethod
    def _compliance_checklist(
        mode: Optional[str],
        connections: list[dict[str, Any]],
        anomalies: list[dict[str, Any]],
        audit_events: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        if mode is None:
            return []
        evidence = {
            "connections": f"{len(connections)} connection records included",
            "anomalies": f"{len(anomalies)} security anomalies included",
            "audit": f"{len(audit_events)} change actions included",
        }
        templates = {
            "gdpr": [
                ("GDPR-5.1(c)", "Data minimization", "included", "Identifiers are pseudonymized"),
                ("GDPR-30", "Records of processing", "included", evidence["audit"]),
                ("GDPR-32", "Security monitoring", "included", evidence["anomalies"]),
                ("GDPR-retention", "Retention policy", "manual_review", "Confirm local retention matches policy"),
            ],
            "hipaa": [
                ("HIPAA-164.312(b)", "Audit controls", "included", evidence["audit"]),
                ("HIPAA-164.312(e)(1)", "Transmission evidence", "included", evidence["connections"]),
                ("HIPAA-164.308(a)(1)", "Risk analysis evidence", "included", evidence["anomalies"]),
                ("HIPAA-164.514(b)", "De-identification", "included", "Identifiers are pseudonymized"),
            ],
            "soc2": [
                ("SOC2-CC7.2", "System monitoring", "included", evidence["anomalies"]),
                ("SOC2-CC7.3", "Event evaluation", "included", evidence["anomalies"]),
                ("SOC2-CC8.1", "Change management", "included", evidence["audit"]),
                ("SOC2-CC6.1", "Logical access", "manual_review", "Review access controls separately"),
            ],
        }
        return [
            {"control": control, "title": title, "status": status, "evidence": detail}
            for control, title, status, detail in templates[mode]
        ]

    @classmethod
    def _apply_privacy_profile(
        cls, report: dict[str, Any], mode: Optional[str]
    ) -> dict[str, Any]:
        if mode not in {"gdpr", "hipaa"}:
            return report
        report["device"] = cls._pseudonymize(report["device"])
        for connection in report["connections"]:
            connection["process"] = cls._pseudonymize(connection["process"])
            connection["local"] = cls._pseudonymize(connection["local"])
            connection["remote"] = cls._pseudonymize(connection["remote"])
        for anomaly in report["anomalies"]:
            anomaly["affected_ip"] = cls._pseudonymize(anomaly["affected_ip"])
            anomaly["description"] = cls._redact_ips(anomaly["description"])
        for event in report["audit_events"]:
            event["actor"] = cls._pseudonymize(event["actor"])
            event["device"] = cls._pseudonymize(event["device"])
            event["detail"] = cls._redact_ips(event["detail"])
        return report

    @staticmethod
    def _pseudonymize(value: Any) -> str:
        text = str(value) if value is not None else ""
        if not text:
            return ""
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        return f"anon-{digest}"

    @classmethod
    def _redact_ips(cls, value: Any) -> str:
        text = str(value or "")

        def replace(match: re.Match) -> str:
            candidate = match.group(0).strip("[]")
            try:
                ipaddress.ip_address(candidate.split("%", 1)[0])
            except ValueError:
                return match.group(0)
            return cls._pseudonymize(candidate)

        text = _IPV4_PATTERN.sub(replace, text)
        return _IPV6_PATTERN.sub(replace, text)

    @classmethod
    def _write_csv(cls, output: Path, report: dict[str, Any]) -> None:
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=_CSV_FIELDS)
            writer.writeheader()
            for metric, value in report["summary"].items():
                if isinstance(value, dict):
                    value = json.dumps(value, sort_keys=True)
                writer.writerow({"record_type": "summary", "metric": metric, "value": value})
            for item in report["connections"]:
                writer.writerow({"record_type": "connection", **item})
            for item in report["anomalies"]:
                writer.writerow({
                    "record_type": "anomaly",
                    "timestamp": item["timestamp"],
                    "category": item["anomaly_type"],
                    "severity": item["severity"],
                    "remote": item["affected_ip"],
                    "port": item["affected_port"],
                    "value": item["metric_value"],
                    "threshold": item["threshold"],
                    "detail": item["description"],
                })
            for item in report["usage_by_hour"]:
                writer.writerow({
                    "record_type": "usage",
                    "timestamp": item["hour"],
                    "metric": "connections",
                    "value": item["connections"],
                    "bytes_sent": item["bytes_sent"],
                    "bytes_received": item["bytes_received"],
                })
            for item in report["audit_events"]:
                writer.writerow({
                    "record_type": "audit",
                    "timestamp": item["timestamp"],
                    "actor": item["actor"],
                    "device": item["device"],
                    "category": item["action"],
                    "status": item["status"],
                    "detail": item["detail"],
                })
            for item in report["compliance_checklist"]:
                writer.writerow({
                    "record_type": "compliance_control",
                    "category": item["control"],
                    "status": item["status"],
                    "detail": f"{item['title']}: {item['evidence']}",
                })

    @staticmethod
    def _write_pdf(output: Path, report: dict[str, Any]) -> None:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table

        styles = getSampleStyleSheet()
        document = SimpleDocTemplate(
            str(output), pagesize=letter,
            rightMargin=0.5 * inch, leftMargin=0.5 * inch,
            topMargin=0.5 * inch, bottomMargin=0.5 * inch,
        )
        story = [
            Paragraph("Blackout Kit Network Report", styles["Title"]),
            Paragraph(
                f"Generated {html.escape(report['generated_at'])} on {html.escape(report['device'])}",
                styles["Normal"],
            ),
            Spacer(1, 12),
        ]
        summary_rows = [["Metric", "Value"]] + [
            [key.replace("_", " ").title(), html.escape(str(value))]
            for key, value in report["summary"].items()
        ]
        story.extend([ReportGenerator._styled_table(summary_rows, colors), Spacer(1, 12)])

        if report["compliance_mode"]:
            story.append(Paragraph(
                f"{report['compliance_mode'].upper()} Evidence Checklist", styles["Heading2"]
            ))
            control_rows = [["Control", "Status", "Evidence"]] + [
                [html.escape(item["control"]), html.escape(item["status"]),
                 Paragraph(html.escape(item["evidence"]), styles["BodyText"])]
                for item in report["compliance_checklist"]
            ]
            story.extend([ReportGenerator._styled_table(control_rows, colors), Spacer(1, 8)])
            story.append(Paragraph(html.escape(report["compliance_disclaimer"]), styles["Italic"]))

        story.append(Paragraph("Hourly Usage", styles["Heading2"]))
        usage_rows = [["Hour", "Connections", "Sent", "Received"]] + [
            [html.escape(item["hour"]), str(item["connections"]),
             str(item["bytes_sent"]), str(item["bytes_received"])]
            for item in report["usage_by_hour"][-100:]
        ]
        story.extend([ReportGenerator._styled_table(usage_rows, colors), Spacer(1, 12)])

        story.append(Paragraph("Connections", styles["Heading2"]))
        connection_rows = [["Time", "Process", "Protocol", "Remote", "Status"]] + [
            [html.escape(item["timestamp"]), html.escape(item["process"]),
             html.escape(item["protocol"]), html.escape(item["remote"]),
             html.escape(item["status"])]
            for item in report["connections"][-100:]
        ]
        story.extend([ReportGenerator._styled_table(connection_rows, colors), Spacer(1, 12)])

        story.append(Paragraph("Anomalies", styles["Heading2"]))
        anomaly_rows = [["Time", "Severity", "Type", "Target"]] + [
            [html.escape(item["timestamp"]), html.escape(item["severity"]),
             html.escape(item["anomaly_type"]), html.escape(item["affected_ip"])]
            for item in report["anomalies"][-100:]
        ]
        story.extend([ReportGenerator._styled_table(anomaly_rows, colors), Spacer(1, 12)])

        story.append(Paragraph("Audit Actions", styles["Heading2"]))
        audit_rows = [["Time", "Actor", "Action", "Status"]] + [
            [html.escape(item["timestamp"]), html.escape(item["actor"]),
             html.escape(item["action"]), html.escape(item["status"])]
            for item in report["audit_events"][-100:]
        ]
        story.append(ReportGenerator._styled_table(audit_rows, colors))
        document.build(story)

    @staticmethod
    def _styled_table(rows: list[list[Any]], colors: Any):
        from reportlab.platypus import Table, TableStyle

        table = Table(rows, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
        ]))
        return table
