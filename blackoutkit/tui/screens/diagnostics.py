"""Local doctor and network-recovery preview in background workers."""
from __future__ import annotations

import io

from rich.console import Console
from textual import work
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Static

from blackoutkit import cli as cli_mod
from ..widgets.output_panel import CollapsibleOutput


def capture_cli(command: str) -> str:
    """Capture one of two allowlisted, non-mutating CLI diagnostic paths."""
    buffer = io.StringIO()
    original_console = cli_mod.console
    cli_mod.console = Console(file=buffer, force_terminal=False, width=100)
    try:
        if command == "doctor":
            args = cli_mod._make_fake_args(local_only=True, include_optional=False)
            cli_mod.cmd_doctor(args)
        elif command == "fix_preview":
            args = cli_mod._make_fake_args(
                preview=True,
                full_route_reset=False,
                full_stack_reset=False,
                flush_arp=False,
                history=False,
                history_lines=20,
            )
            cli_mod.cmd_fix(args)
        else:
            raise ValueError(f"Unsupported diagnostics command: {command!r}")
    finally:
        cli_mod.console = original_console
    return buffer.getvalue()


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

    @work(thread=True, exclusive=True, group="diagnostics")
    def run_doctor(self) -> None:
        self._run(self._state.doctor_fn or (lambda: capture_cli("doctor")))

    @work(thread=True, exclusive=True, group="diagnostics")
    def run_fix_preview(self) -> None:
        self._run(self._state.fix_preview_fn or (lambda: capture_cli("fix_preview")))

    def _run(self, operation) -> None:
        self.app.call_from_thread(self._set_output, "Running local diagnostic…")
        try:
            text = str(operation())
        except Exception as exc:  # noqa: BLE001
            text = f"error: {exc}"
        self.app.call_from_thread(self._set_output, text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-doctor":
            self.run_doctor()
        elif event.button.id == "btn-fix-preview":
            self.run_fix_preview()
