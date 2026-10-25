"""Tools screen runs background operations and renders output in CollapsibleOutput."""
import pytest

textual = pytest.importorskip("textual")
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import Input, Static  # noqa: E402

from blackoutkit.tui.screens.toolsscr import ToolsScreen  # noqa: E402


class ToolsApp(App):
    def __init__(self, ping_fn=None, speedtest_fn=None):
        super().__init__()
        self._ping_fn = ping_fn or (lambda target: f"pong {target}")
        self._speedtest_fn = speedtest_fn or (lambda: "12.3 Mbit/s")

    def compose(self) -> ComposeResult:
        yield Static("Test root", markup=False)

    def on_mount(self) -> None:
        self.push_screen(ToolsScreen(ping_fn=self._ping_fn, speedtest_fn=self._speedtest_fn))


def _screen(app: ToolsApp) -> ToolsScreen:
    assert isinstance(app.screen, ToolsScreen)
    return app.screen


@pytest.mark.asyncio
async def test_ping_tab_runs_and_fills_output():
    app = ToolsApp(ping_fn=lambda target: f"[b]pong[/b] {target}")
    async with app.run_test() as pilot:
        screen = _screen(app)
        screen.do_ping("1.1.1.1")
        for _ in range(50):
            await pilot.pause(0.05)
            if "pong 1.1.1.1" in screen.ping_output():
                break
        # Verify literal markup tag survival (regression check for markup=False)
        assert "[b]pong[/b] 1.1.1.1" in screen.ping_output()


@pytest.mark.asyncio
async def test_speedtest_runs_and_fills_output():
    app = ToolsApp()
    async with app.run_test() as pilot:
        screen = _screen(app)
        screen.do_speedtest()
        for _ in range(50):
            await pilot.pause(0.05)
            if "12.3 Mbit/s" in screen.ping_output():
                break
        assert "12.3 Mbit/s" in screen.ping_output()


@pytest.mark.asyncio
async def test_button_clicks_dispatch():
    called = []
    app = ToolsApp(
        ping_fn=lambda t: called.append(f"ping:{t}") or f"pinged {t}",
        speedtest_fn=lambda: called.append("speedtest") or "speed 100",
    )
    async with app.run_test() as pilot:
        screen = _screen(app)
        screen.query_one("#ping-target", Input).value = "8.8.8.8"
        await pilot.click("#btn-ping")
        for _ in range(50):
            await pilot.pause(0.05)
            if called:
                break
        assert called == ["ping:8.8.8.8"]
        assert "pinged 8.8.8.8" in screen.ping_output()

        await pilot.click("#btn-speedtest")
        for _ in range(50):
            await pilot.pause(0.05)
            if len(called) == 2:
                break
        assert called == ["ping:8.8.8.8", "speedtest"]
        assert "speed 100" in screen.ping_output()
