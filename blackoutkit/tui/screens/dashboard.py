"""Dashboard: local status + quick actions posted to the Console app."""
from __future__ import annotations

from textual.message import Message
from textual.screen import Screen
from textual.widgets import ListItem, ListView, Static

from ..widgets.status_strip import StatusStrip


class DashAction(Message):
    def __init__(self, kind: str) -> None:
        super().__init__()
        self.kind = kind


class DashboardScreen(Screen):
    SCREEN_ID = "dashboard"

    def __init__(self, state) -> None:
        super().__init__()
        self._state = state

    def compose(self):
        yield StatusStrip(state=self._state)
        yield Static("Quick actions — press Enter to run", id="dash-hint", markup=False)
        yield ListView(
            ListItem(Static("Connect (smart engine)", markup=False), name="connect"),
            ListItem(Static("Stop tunnel", markup=False), name="stop"),
            ListItem(Static("Emergency candidates", markup=False), name="emergency"),
            id="dash-actions",
        )

    def action_connect(self) -> None:
        self.post_message(DashAction("connect"))

    def action_stop(self) -> None:
        self.post_message(DashAction("stop"))

    def action_emergency(self) -> None:
        self.post_message(DashAction("emergency"))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        kind = event.item.name or ""
        if kind in {"connect", "stop", "emergency"}:
            self.post_message(DashAction(kind))
