import csv
from pathlib import Path
from blackoutkit.reporting import ReportExporter, export_report

def test_csv_report_generation(tmp_path):
    csv_file = tmp_path / "report.csv"
    exporter = ReportExporter()

    entries = [
        {"process": "chrome.exe", "protocol": "TCP", "remote_ip": "1.1.1.1", "remote_port": 443, "bytes_sent": 500, "bytes_recv": 2000, "status": "ESTABLISHED"}
    ]
    res_path = exporter.generate_csv_report(csv_file, data_type="connections", entries=entries)
    assert res_path.exists()

    with open(csv_file, "r") as f:
        reader = list(csv.reader(f))
        assert len(reader) == 2
        assert reader[1][1] == "chrome.exe"

def test_csv_compliance_export(tmp_path):
    csv_file = tmp_path / "compliance.csv"
    res_path = export_report(str(csv_file), fmt="csv", data_type="compliance")
    assert res_path.exists()

    with open(csv_file, "r") as f:
        reader = list(csv.reader(f))
        assert len(reader) > 5

def test_pdf_report_generation(tmp_path):
    pdf_file = tmp_path / "report.pdf"
    exporter = ReportExporter()

    res_path = exporter.generate_pdf_report(pdf_file, mode="HIPAA")
    assert res_path.exists()
    assert pdf_file.stat().st_size > 1000

def test_export_report_helper(tmp_path):
    pdf_file = tmp_path / "report_helper.pdf"
    res_path = export_report(str(pdf_file), fmt="pdf", mode="SOC2")
    assert res_path.exists()
