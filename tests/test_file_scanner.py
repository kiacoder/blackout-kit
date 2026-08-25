from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from blackoutkit.tools import file_scanner


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"sample")
    return target


def test_scan_file_rejects_missing_target_without_starting_scanner(monkeypatch, tmp_path):
    run = Mock()
    monkeypatch.setattr(file_scanner.subprocess, "run", run)

    result = file_scanner.scan_file(tmp_path / "missing.bin")

    assert result["status"] == "invalid-target"
    assert run.call_count == 0


def test_scan_file_rejects_directory_without_starting_scanner(monkeypatch, tmp_path):
    run = Mock()
    monkeypatch.setattr(file_scanner.subprocess, "run", run)

    result = file_scanner.scan_file(tmp_path)

    assert result["status"] == "invalid-target"
    assert run.call_count == 0


def test_scan_file_reports_unsupported_platform_without_discovery(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "linux")
    discover = Mock()
    monkeypatch.setattr(file_scanner, "find_defender", discover)

    result = file_scanner.scan_file(_target(tmp_path))

    assert result["status"] == "unsupported-platform"
    discover.assert_not_called()


def test_find_defender_discovers_platform_executable(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "win32")
    program_data = tmp_path / "ProgramData"
    defender = (
        program_data
        / "Microsoft"
        / "Windows Defender"
        / "Platform"
        / "4.18.25050.5"
        / "MpCmdRun.exe"
    )
    defender.parent.mkdir(parents=True)
    defender.write_bytes(b"")
    monkeypatch.setenv("ProgramData", str(program_data))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "ProgramFiles"))

    assert file_scanner.find_defender() == defender


def test_scan_file_reports_unavailable_scanner_without_starting_process(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "win32")
    monkeypatch.setattr(file_scanner, "find_defender", lambda: None)
    run = Mock()
    monkeypatch.setattr(file_scanner.subprocess, "run", run)

    result = file_scanner.scan_file(_target(tmp_path))

    assert result["status"] == "scanner-unavailable"
    assert run.call_count == 0


def test_scan_file_constructs_non_remediating_argument_list(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "win32")
    defender = tmp_path / "MpCmdRun.exe"
    target = _target(tmp_path)
    monkeypatch.setattr(file_scanner, "find_defender", lambda: defender)
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(file_scanner.subprocess, "run", run)

    result = file_scanner.scan_file(target)

    assert result["status"] == "clean"
    command = run.call_args.args[0]
    assert command == [
        str(defender),
        "-Scan",
        "-ScanType",
        "3",
        "-File",
        str(target.resolve()),
        "-DisableRemediation",
    ]
    assert run.call_args.kwargs == {
        "capture_output": True,
        "text": True,
        "timeout": 300,
        "check": False,
    }


def test_scan_file_reports_confirmed_detection_from_defender_output(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "win32")
    monkeypatch.setattr(file_scanner, "find_defender", lambda: tmp_path / "MpCmdRun.exe")
    monkeypatch.setattr(
        file_scanner.subprocess,
        "run",
        Mock(return_value=SimpleNamespace(returncode=2, stdout="Threat detected: Example.Test", stderr="")),
    )

    result = file_scanner.scan_file(_target(tmp_path))

    assert result["status"] == "detected"
    assert result["returncode"] == 2


def test_scan_file_treats_singular_negative_defender_output_as_indeterminate(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "win32")
    monkeypatch.setattr(file_scanner, "find_defender", lambda: tmp_path / "MpCmdRun.exe")
    monkeypatch.setattr(
        file_scanner.subprocess,
        "run",
        Mock(return_value=SimpleNamespace(returncode=2, stdout="No threat detected", stderr="")),
    )

    result = file_scanner.scan_file(_target(tmp_path))

    assert result["status"] == "indeterminate"
    assert result["returncode"] == 2


def test_scan_file_treats_plural_negative_defender_output_as_indeterminate(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "win32")
    monkeypatch.setattr(file_scanner, "find_defender", lambda: tmp_path / "MpCmdRun.exe")
    monkeypatch.setattr(
        file_scanner.subprocess,
        "run",
        Mock(return_value=SimpleNamespace(returncode=2, stdout="No threats detected", stderr="")),
    )

    result = file_scanner.scan_file(_target(tmp_path))

    assert result["status"] == "indeterminate"
    assert result["returncode"] == 2


def test_scan_file_treats_ambiguous_defender_code_as_indeterminate(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "win32")
    monkeypatch.setattr(file_scanner, "find_defender", lambda: tmp_path / "MpCmdRun.exe")
    monkeypatch.setattr(
        file_scanner.subprocess,
        "run",
        Mock(return_value=SimpleNamespace(returncode=2, stdout="Scan completed.", stderr="")),
    )

    result = file_scanner.scan_file(_target(tmp_path))

    assert result["status"] == "indeterminate"
    assert result["returncode"] == 2


def test_scan_file_reports_native_execution_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "win32")
    monkeypatch.setattr(file_scanner, "find_defender", lambda: tmp_path / "MpCmdRun.exe")
    monkeypatch.setattr(
        file_scanner.subprocess,
        "run",
        Mock(side_effect=OSError("access denied")),
    )

    result = file_scanner.scan_file(_target(tmp_path))

    assert result["status"] == "scanner-error"
    assert result["detail"] == "access denied"


def test_scan_file_reports_timeout_without_retrying(monkeypatch, tmp_path):
    monkeypatch.setattr(file_scanner.sys, "platform", "win32")
    monkeypatch.setattr(file_scanner, "find_defender", lambda: tmp_path / "MpCmdRun.exe")
    run = Mock(side_effect=file_scanner.subprocess.TimeoutExpired("MpCmdRun.exe", 300))
    monkeypatch.setattr(file_scanner.subprocess, "run", run)

    result = file_scanner.scan_file(_target(tmp_path))

    assert result["status"] == "scanner-error"
    assert run.call_count == 1


def test_tools_dispatcher_renders_clean_result(monkeypatch, tmp_path):
    from blackoutkit import cli

    printed = []
    monkeypatch.setattr(
        "blackoutkit.tools.file_scanner.scan_file",
        lambda _path: {"status": "clean", "target": str(tmp_path / "sample.bin"), "detail": None},
    )
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))

    cli.cmd_tools(type("Args", (), {"tools_command": "scan-file", "path": str(tmp_path / "sample.bin")})())

    assert any("No threats reported" in message for message in printed)


def test_tools_dispatcher_renders_indeterminate_result(monkeypatch, tmp_path):
    from blackoutkit import cli

    printed = []
    monkeypatch.setattr(
        "blackoutkit.tools.file_scanner.scan_file",
        lambda _path: {"status": "indeterminate", "target": str(tmp_path / "sample.bin"), "detail": "Scanner output unavailable."},
    )
    monkeypatch.setattr(cli.console, "print", lambda message: printed.append(str(message)))

    cli.cmd_tools(type("Args", (), {"tools_command": "scan-file", "path": str(tmp_path / "sample.bin")})())

    assert any("indeterminate" in message for message in printed)
    assert any("Scanner output unavailable." in message for message in printed)
