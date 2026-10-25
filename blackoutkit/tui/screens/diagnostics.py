"""Local doctor and network-recovery preview in background workers."""
from __future__ import annotations

from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Static

from ._worker import capture_cli, run_bg
from ..widgets.output_panel import CollapsibleOutput

__all__ = ["DiagnosticsScreen", "capture_cli"]


class DiagnosticsScreen(Screen):
    SCREEN_ID = "diagnostics"

    DEFAULT_CSS = """
    DiagnosticsScreen {
        layout: vertical;
        padding: 1;
    }
    DiagnosticsScreen Button {
        width: 1fr;
        height: 3;
    }
    DiagnosticsScreen CollapsibleOutput {
        height: 1fr;
    }
    """

    def __init__(self, state) -> None:
        super().__init__()
        self._state = state

    def compose(self):
        with Vertical():
            yield Static("Diagnostics — local checks and preview only", markup=False)
            yield Button("Run doctor", id="btn-doctor")
            yield Button("Fix --preview", id="btn-fix-preview")
            panel = CollapsibleOutput(title="diagnostics output", collapsed=False)
            panel.id = "diag-output"
            yield panel

    def _set_output(self, text: str) -> None:
        self.query_one("#diag-output", CollapsibleOutput).set_text(text)

    def run_doctor(self) -> None:
        self._set_output("Running local diagnostic…")
        run_bg(
            self,
            self._state.doctor_fn or (lambda: capture_cli("doctor")),
            self._set_output,
            group="diagnostics",
        )

    def run_fix_preview(self) -> None:
        self._set_output("Running local diagnostic…")
        run_bg(
            self,
            self._state.fix_preview_fn or (lambda: capture_cli("fix_preview")),
            self._set_output,
            group="diagnostics",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-doctor":
            event.stop()
            self.run_doctor()
        elif event.button.id == "btn-fix-preview":
            event.stop()
            self.run_fix_preview()
