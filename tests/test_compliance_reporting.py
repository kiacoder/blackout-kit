from blackoutkit.compliance_reporting import (
    ComplianceReportingEngine,
    record_compliance_audit,
    query_audit_trail,
    get_sla_dashboard_metrics,
)

def test_compliance_audit_trail(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    engine = ComplianceReportingEngine(audit_file=audit_file)

    evt1 = engine.log_audit_event("POLICY_CHANGE", "admin@acme.com", "dev-101", {"setting": "force_tls"})
    assert evt1["action"] == "POLICY_CHANGE"
    assert evt1["device_id"] == "dev-101"

    logs = engine.get_audit_logs(device_id="dev-101")
    assert len(logs) == 1
    assert logs[0]["actor"] == "admin@acme.com"

def test_sla_metrics_calculation(tmp_path):
    engine = ComplianceReportingEngine(audit_file=tmp_path / "a.jsonl")

    devices = [
        {"device_id": "d1", "status": "online", "config_version": "v1.0"},
        {"device_id": "d2", "status": "online", "config_version": "v1.0"},
        {"device_id": "d3", "status": "offline", "config_version": "outdated"},
    ]

    metrics = engine.calculate_sla_metrics(devices)
    assert metrics["fleet_uptime_pct"] == 66.67
    assert metrics["config_compliance_pct"] == 66.67
    assert metrics["total_assessed_devices"] == 3

def test_compliance_reporting_helpers():
    rec = record_compliance_audit("CONFIG_ROTATE", "user1", "dev-99", {"reason": "routine"})
    assert rec["action"] == "CONFIG_ROTATE"

    logs = query_audit_trail(limit=5)
    assert isinstance(logs, list)

    metrics = get_sla_dashboard_metrics([])
    assert metrics["fleet_uptime_pct"] == 100.0
