# blackoutkit/tui/screens/settingsscr.py
"""Searchable settings editor backed by settings.validate/set_value."""
from __future__ import annotations

from textual.screen import Screen
from textual.widgets import Button, Input, Label, ListItem, ListView, Static

from ..state import ConsoleState


class SettingsScreen(Screen):
    SCREEN_ID = "settings"

    DEFAULT_CSS = """
    SettingsScreen {
        layout: vertical;
        padding: 1;
    }
    SettingsScreen Input {
        width: 1fr;
        height: 3;
    }
    SettingsScreen Button {
        width: 1fr;
        height: 3;
    }
    SettingsScreen #settings-list {
        height: 1fr;
    }
    SettingsScreen #settings-detail, SettingsScreen #settings-status {
        height: auto;
    }
    """

    def __init__(self, state: ConsoleState) -> None:
        super().__init__()
        self._state = state
        self._selected: str | None = None

    def compose(self):
        yield Static("Settings — type to search, select a key, edit + Save", markup=False)
        yield Input(placeholder="Search settings", id="settings-search")
        yield ListView(id="settings-list")
        yield Static("", id="settings-detail", markup=False)
        yield Input(placeholder="New value", id="settings-value")
        yield Button("Save", id="btn-save")
        yield Static("", id="settings-status", markup=False)

    def on_mount(self) -> None:
        self.refresh_list()

    def refresh_list(self, filter_text: str = "") -> None:
        view = self.query_one("#settings-list", ListView)
        view.clear()
        needle = filter_text.strip().lower()
        for group, keys in self._state.setting_groups():
            matching = [k for k in keys if needle in k.lower() or needle in group.lower()]
            if not matching:
                continue
            view.append(ListItem(Label(group.upper(), markup=False), disabled=True))
            for key in matching:
                view.append(ListItem(Label(key, markup=False), name=key))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "settings-search":
            self.refresh_list(event.value)

    def on_list_view_selected(self, event) -> None:
        if event.item.name:
            self.select_key(event.item.name)

    def select_key(self, key: str) -> None:
        self._selected = key
        detail = self._state.setting_detail(key)
        choices = self._state.setting_choices(key)
        if choices:
            detail += f"   (choices: {', '.join(choices)})"
        self.query_one("#settings-detail", Static).update(detail)

    def do_save(self, raw: str) -> None:
        if not self._selected:
            self.query_one("#settings-status", Static).update("Select a setting first.")
            return
        ok, message = self._state.save_setting(self._selected, raw)
        self.query_one("#settings-status", Static).update(message)
        if ok:
            self.select_key(self._selected)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            self.do_save(self.query_one("#settings-value", Input).value)
