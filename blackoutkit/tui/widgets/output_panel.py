"""Collapsible, plain-text command output panel."""
from __future__ import annotations

from textual.timer import Timer
from textual.widgets import Button, Collapsible, Static


class CollapsibleOutput(Collapsible):
    DEFAULT_CSS = """
    CollapsibleOutput {
        height: auto;
        max-height: 24;
    }
    CollapsibleOutput #output-body {
        height: auto;
        max-height: 20;
        overflow-y: auto;
    }
    """

    def __init__(self, title: str = "output", collapsed: bool = True) -> None:
        body = Static("", id="output-body", markup=False)
        copy_button = Button("Copy", id="copy-output")
        super().__init__(body, copy_button, title=title, collapsed=collapsed)
        self._last_text = ""
        self._copy_feedback: Timer | None = None

    def set_text(self, text: str) -> None:
        self._last_text = text
        self.query_one("#output-body", Static).update(text)

    @property
    def last_text(self) -> str:
        return self._last_text

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "copy-output" or not self._last_text:
            return
        self.app.copy_to_clipboard(self._last_text)
        event.button.label = "Copied"
        if self._copy_feedback is not None:
            self._copy_feedback.stop()
        self._copy_feedback = self.set_timer(1.5, self._reset_copy_label)

    def _reset_copy_label(self) -> None:
        self.query_one("#copy-output", Button).label = "Copy"
        self._copy_feedback = None

    def on_unmount(self) -> None:
        if self._copy_feedback is not None:
            self._copy_feedback.stop()
            self._copy_feedback = None
