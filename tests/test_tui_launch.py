# tests/test_tui_launch.py
"""Guards for launching the Blackout Console."""

from blackoutkit import tui


def test_console_available_false_without_textual(monkeypatch):
    monkeypatch.setattr(tui, "_import_textual", lambda: None)
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    assert tui.console_available() is False


def test_console_available_true_with_textual_and_tty(monkeypatch):
    import types

    monkeypatch.setattr(tui, "_import_textual", lambda: types.SimpleNamespace())
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    assert tui.console_available() is True


def test_launch_console_returns_2_when_unavailable(monkeypatch, capsys):
    monkeypatch.setattr(tui, "console_available", lambda: False)
    code = tui.launch_console()
    assert code == 2
    out = capsys.readouterr().out
    assert "pip install" in out and "tui" in out
