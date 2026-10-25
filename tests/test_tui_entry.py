"""Chooser gains a TUI option; fallback keeps legacy CLI when unavailable."""
from types import SimpleNamespace

from blackoutkit import cli


def test_chooser_items_with_tui_available(monkeypatch):
    monkeypatch.setattr(cli, "sys", SimpleNamespace(platform="win32"))
    import blackoutkit.tui as tui

    monkeypatch.setattr(tui, "console_available", lambda: True)
    items = cli._launcher_items()
    keys = [item.key for item in items]
    assert keys == ["tui", "gui", "exit"]


def test_chooser_items_fallback_without_textual(monkeypatch):
    monkeypatch.setattr(cli, "sys", SimpleNamespace(platform="win32"))
    import blackoutkit.tui as tui

    monkeypatch.setattr(tui, "console_available", lambda: False)
    items = cli._launcher_items()
    keys = [item.key for item in items]
    assert keys == ["cli", "gui", "exit"]
    cli_item = next(item for item in items if item.key == "cli")
    assert cli_item.enabled is True


def test_chooser_non_win32_disables_gui(monkeypatch):
    monkeypatch.setattr(cli, "sys", SimpleNamespace(platform="linux"))
    import blackoutkit.tui as tui

    monkeypatch.setattr(tui, "console_available", lambda: True)
    items = cli._launcher_items()
    gui_item = next(item for item in items if item.key == "gui")
    assert gui_item.enabled is False


def test_launcher_menu_dispatch_tui(monkeypatch):
    import blackoutkit.tui as tui

    launched = []

    monkeypatch.setattr(tui, "console_available", lambda: True)
    monkeypatch.setattr(tui, "launch_console", lambda: launched.append("tui") or 0)

    choices = iter(["tui", "exit"])
    monkeypatch.setattr(cli, "run_menu", lambda *a, **k: next(choices))

    cli._show_launcher_menu()
    assert launched == ["tui"]
    assert next(choices, "exhausted") == "exhausted"  # looped back for exit, did not return
