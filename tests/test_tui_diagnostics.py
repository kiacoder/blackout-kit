"""Diagnostics runs workers and fills the output panel."""
import pytest

textual = pytest.importorskip("textual")
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import Button, Static  # noqa: E402

from blackoutkit.tui.screens.diagnostics import DiagnosticsScreen  # noqa: E402
from blackoutkit.tui.state import ConsoleState  # noqa: E402
from blackoutkit.tui.widgets.output_panel import CollapsibleOutput  # noqa: E402


def _state(doctor_fn=None, fix_preview_fn=None):
    return ConsoleState(
        snapshot_fn=lambda: {}, capabilities_fn=lambda **k: (),
        load_configs_fn=lambda: [], add_config_fn=lambda uri: None,
        import_subscription_fn=lambda url: [], settings_load_fn=lambda: {},
        settings_groups_fn=lambda: [], settings_choices_fn=lambda key: None,
        settings_display_fn=lambda key, value: str(value),
        settings_validate_fn=lambda key, value: (True, ""), settings_set_fn=lambda key, value: None,
        doctor_fn=doctor_fn or (lambda: "doctor says: all local checks pass"),
        fix_preview_fn=fix_preview_fn or (lambda: "fix preview: nothing to repair"),
    )


class DiagApp(App):
    def __init__(self, state=None):
        super().__init__()
        self.state = state or _state()

    def compose(self) -> ComposeResult:
        yield Static("Test root", markup=False)

    def on_mount(self) -> None:
        self.push_screen(DiagnosticsScreen(state=self.state))


def _screen(app: DiagApp) -> DiagnosticsScreen:
    assert isinstance(app.screen, DiagnosticsScreen)
    return app.screen


def _panel(app: DiagApp) -> CollapsibleOutput:
    return app.screen.query_one("#diag-output", CollapsibleOutput)


def _button(app: DiagApp, button_id: str) -> Button:
    return app.screen.query_one(f"#{button_id}", Button)


def _button_pressed(app: DiagApp, button_id: str) -> None:
    app.screen.on_button_pressed(Button.Pressed(_button(app, button_id)))


@pytest.mark.asyncio
async def test_doctor_worker_fills_output_panel():
    app = DiagApp()
    async with app.run_test() as pilot:
        screen = _screen(app)
        screen.run_doctor()
        for _ in range(50):
            await pilot.pause(0.05)
            panel = _panel(app)
            if "all local checks pass" in panel.last_text:
                break
        assert "all local checks pass" in _panel(app).last_text


@pytest.mark.asyncio
async def test_fix_preview_worker_fills_output_panel():
    app = DiagApp()
    async with app.run_test() as pilot:
        screen = _screen(app)
        screen.run_fix_preview()
        for _ in range(50):
            await pilot.pause(0.05)
            panel = _panel(app)
            if "nothing to repair" in panel.last_text:
                break
        assert "nothing to repair" in _panel(app).last_text


@pytest.mark.asyncio
async def test_buttons_dispatch_read_only_operations():
    called = []
    app = DiagApp(_state(
        doctor_fn=lambda: called.append("doctor") or "doctor output",
        fix_preview_fn=lambda: called.append("fix_preview") or "fix output",
    ))
    async with app.run_test() as pilot:
        await pilot.pause()
        _button_pressed(app, "btn-doctor")
        for _ in range(50):
            await pilot.pause(0.05)
            if called:
                break
        _button_pressed(app, "btn-fix-preview")
        for _ in range(50):
            await pilot.pause(0.05)
            if len(called) == 2:
                break
        assert called == ["doctor", "fix_preview"]
        output = _panel(app).last_text
        assert "fix output" in output
