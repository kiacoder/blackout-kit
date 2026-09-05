"""Tests for Phase 5A: CLI UX Polish (Error Formatting, Spinners, Tables)."""
import pytest
from rich.console import Console
from blackoutkit.cli_error_handler import format_error, handle_cli_exception

def test_format_error_standard(capsys):
    console = Console(stderr=True, no_color=True)
    exit_code = format_error(
        summary="Configuration loading failed",
        reason="Missing key 'dns_servers' in config.yaml",
        hint="Run 'blackout config --help' for details",
        console=console,
        exit_code=1,
    )
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Error: Configuration loading failed" in captured.err
    assert "Reason: Missing key 'dns_servers' in config.yaml" in captured.err
    assert "Hint: Run 'blackout config --help' for details" in captured.err

def test_handle_cli_exception(capsys):
    console = Console(stderr=True, no_color=True)
    try:
        raise ValueError("Invalid integer value 'abc'")
    except Exception as exc:
        exit_code = handle_cli_exception(
            exc,
            command_name="settings set",
            console=console,
        )
        assert exit_code == 1

    captured = capsys.readouterr()
    assert "Error: Command 'settings set' failed: Invalid integer value 'abc'" in captured.err
    assert "Reason: Invalid integer value 'abc'" in captured.err
    assert "Hint: blackout settings set --help" in captured.err
