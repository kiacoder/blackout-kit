"""Phase 5 — standardized errors: reason + hints format (cli_error_handler)."""
from __future__ import annotations

import io

from rich.console import Console

from blackoutkit.cli_error_handler import format_error, handle_cli_exception


def _capture_console() -> Console:
    return Console(file=io.StringIO(), force_terminal=False, width=100)


def test_format_error_emits_summary_reason_hint():
    c = _capture_console()
    rc = format_error(
        summary="Connection failed",
        reason="engine exited with code 1",
        hint="run 'blackout doctor' for diagnostics",
        console=c,
    )
    out = c.file.getvalue()
    assert rc == 1
    assert "Error:" in out and "Connection failed" in out
    assert "Reason:" in out and "engine exited with code 1" in out
    assert "Hint:" in out and "blackout doctor" in out


def test_format_error_omits_reason_and_hint_when_absent():
    c = _capture_console()
    format_error(summary="Boom", console=c)
    out = c.file.getvalue()
    assert "Error:" in out and "Boom" in out
    assert "Reason:" not in out
    assert "Hint:" not in out


def test_handle_cli_exception_wraps_exception():
    c = _capture_console()
    rc = handle_cli_exception(RuntimeError("disk full"), "backup", console=c)
    out = c.file.getvalue()
    assert rc == 1
    assert "backup" in out
    assert "disk full" in out
    assert "Hint:" in out and "blackout backup --help" in out
