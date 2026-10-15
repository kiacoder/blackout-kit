"""Regression tests for engine-failure escalation (Edge-Case Audit #7).

The daemon used to log every failed restart at warning level and `blackout
status` showed only "Next retry: Ns" — a reconnect loop looked like a hang
with no stated reason. The escalation threshold and the status-panel reason
are the user-facing half of that fix; the log side lives in the daemon loop.
"""
from blackoutkit.cli import _status_panel
from blackoutkit.daemon import ENGINE_FAILURE_ESCALATE_AFTER


def _snapshot(status, last_failure=None, next_retry_delay=None):
    return {
        "state": {
            "status": status,
            "started": "2026-10-15 10:00:00",
            "last_failure": last_failure,
            "next_retry_delay": next_retry_delay,
        },
        "pid": 1234,
        "active_engine": "xray",
        "stability": None,
        "latencies": [],
        "proxy": {"enabled": False, "server": None},
        "http_open": None,
        "socks_open": None,
        "settings": {"security_mode": "speed", "terminal_theme": "dark"},
        "events": [],
    }


def _render(status, **kwargs):
    import io

    from rich.console import Console

    from blackoutkit.theme import build_theme

    # A private console carrying the app theme: the panel border style only
    # exists on the theme the CLI installs, and swapping the shared console's
    # file leaks rich's cached terminal state into other tests.
    buffer = io.StringIO()
    console = Console(
        theme=build_theme(),
        file=buffer,
        width=140,
        no_color=True,
        legacy_windows=False,
    )
    console.print(_status_panel(_snapshot(status, **kwargs)))
    return buffer.getvalue()


def test_escalation_threshold_is_small_and_sane():
    assert ENGINE_FAILURE_ESCALATE_AFTER == 3


def test_status_shows_failure_reason_while_reconnecting():
    text = _render("reconnecting", last_failure="xray binary exited 127", next_retry_delay=30)
    assert "xray binary exited 127" in text
    assert "Next retry" in text
    assert "blackout doctor" in text


def test_status_shows_failure_reason_after_exhaustion():
    text = _render("failed", last_failure="no compatible saved config")
    assert "no compatible saved config" in text


def test_status_handles_dict_shaped_failure_reason():
    text = _render("reconnecting", last_failure={"engine": "xray", "reason": "port in use"})
    assert "port in use" in text


def test_status_has_no_failure_line_when_healthy():
    text = _render("connected", last_failure=None)
    assert "Last failure" not in text


def test_status_has_no_failure_line_when_reason_absent():
    text = _render("reconnecting", last_failure=None, next_retry_delay=15)
    assert "Last failure" not in text
    assert "Next retry" in text
