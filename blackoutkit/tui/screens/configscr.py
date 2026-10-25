"""Saved-config manager: safe summaries only; raw URIs are never displayed."""
from __future__ import annotations

from textual.screen import Screen
from textual.widgets import Button, Input, Static

from ..state import ConsoleState


class ConfigScreen(Screen):
    SCREEN_ID = "config"

    DEFAULT_CSS = """
    ConfigScreen {
        layout: vertical;
        padding: 1;
    }
    ConfigScreen Input {
        width: 1fr;
        height: 3;
    }
    ConfigScreen Button {
        width: 1fr;
        height: 3;
    }
    ConfigScreen #config-rows, ConfigScreen #config-status {
        height: auto;
    }
    """

    def __init__(self, state: ConsoleState) -> None:
        super().__init__()
        self._state = state

    def compose(self):
        yield Static("Saved configs — summaries only; secrets are never shown", markup=False)
        yield Static("", id="config-rows", markup=False)
        yield Input(placeholder="Paste config URI to add", id="add-uri")
        yield Button("Add URI", id="btn-add")
        yield Input(placeholder="Subscription URL", id="sub-url")
        yield Button("Import subscription", id="btn-import")
        yield Static("", id="config-status", markup=False)

    def on_mount(self) -> None:
        self.refresh_rows()

    def refresh_rows(self) -> None:
        rows = self._state.config_summaries() or ["(no saved configs)"]
        self.query_one("#config-rows", Static).update("\n".join(rows))

    def _flash(self, message: str) -> None:
        self.query_one("#config-status", Static).update(message)

    def do_add(self, uri: str) -> None:
        ok = False
        try:
            ok, _reason = self._state.add_config_uri(uri.strip())
        except Exception:
            ok = False
        finally:
            self.query_one("#add-uri", Input).value = ""
        self._flash("Config added." if ok else "Could not add this config. Check its format and try again.")
        if ok:
            self.refresh_rows()

    def do_import(self, url: str) -> None:
        count = 0
        try:
            count, _reason = self._state.import_subscription(url.strip())
        except Exception:
            count = 0
        finally:
            self.query_one("#sub-url", Input).value = ""
        if count:
            self._flash(f"Imported {count} configs.")
            self.refresh_rows()
        else:
            self._flash("Could not import this subscription. Check the link and try again.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-add":
            self.do_add(self.query_one("#add-uri", Input).value)
        elif event.button.id == "btn-import":
            self.do_import(self.query_one("#sub-url", Input).value)
