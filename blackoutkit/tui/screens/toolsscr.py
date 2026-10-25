# blackoutkit/tui/screens/toolsscr.py
"""Network tools; heavy ops run in background worker threads."""
from __future__ import annotations

from textual.screen import Screen
from textual.widgets import Button, Input, Static

from ._worker import capture_cli, run_bg
from ..widgets.output_panel import CollapsibleOutput


class ToolsScreen(Screen):
    SCREEN_ID = "tools"

    DEFAULT_CSS = """
    ToolsScreen {
        layout: vertical;
        padding: 1;
    }
    ToolsScreen Input {
        width: 1fr;
        height: 3;
    }
    ToolsScreen Button {
        width: 1fr;
        height: 3;
    }
    ToolsScreen CollapsibleOutput {
        height: 1fr;
    }
    """

    def __init__(self, ping_fn=None, speedtest_fn=None) -> None:
        super().__init__()
        self._ping_fn = ping_fn
        self._speedtest_fn = speedtest_fn

    def compose(self):
        yield Static("Tools — ping and speedtest (runs the real CLI path)", markup=False)
        yield Input(placeholder="Ping target (host or IP)", id="ping-target")
        yield Button("Run ping", id="btn-ping")
        yield Button("Run speedtest (~20s)", id="btn-speedtest")
        yield CollapsibleOutput(title="tools output", collapsed=False)

    def ping_output(self) -> str:
        return self.query_one(CollapsibleOutput).last_text

    def _fill(self, text: str) -> None:
        self.query_one(CollapsibleOutput).set_text(text)

    def do_ping(self, target: str) -> None:
        self._fill(f"Running ping to {target}...")
        fn = (lambda: self._ping_fn(target)) if self._ping_fn else (lambda: capture_cli("tools_ping", target))
        run_bg(self, fn, self._fill, group="tools-ping")

    def do_speedtest(self) -> None:
        self._fill("Running speedtest (~20s)...")
        fn = self._speedtest_fn or (lambda: capture_cli("tools_speedtest"))
        run_bg(self, fn, self._fill, group="tools-speedtest")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-ping":
            event.stop()
            target = self.query_one("#ping-target", Input).value.strip() or "1.1.1.1"
            self.do_ping(target)
        elif event.button.id == "btn-speedtest":
            event.stop()
            self.do_speedtest()
