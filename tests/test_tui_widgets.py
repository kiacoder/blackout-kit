"""Collapsible output + spinner behavior."""
import pytest

textual = pytest.importorskip("textual")
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import Button, Static  # noqa: E402

from blackoutkit.tui.widgets.op_spinner import OperationSpinner  # noqa: E402
from blackoutkit.tui.widgets.output_panel import CollapsibleOutput  # noqa: E402


class WidgetApp(App):
    def compose(self) -> ComposeResult:
        yield CollapsibleOutput(title="doctor")
        yield OperationSpinner()


@pytest.mark.asyncio
async def test_output_panel_collapsed_then_expands_with_text():
    app = WidgetApp()
    async with app.run_test() as pilot:
        panel = app.query_one(CollapsibleOutput)
        assert panel.collapsed is True
        panel.set_text("doctor output line\nsecond line [b] stays literal")
        panel.collapsed = False
        await pilot.pause()
        body = panel.query_one("#output-body", Static)
        rendered = str(body.visual)
        assert "second line" in rendered
        assert "[b] stays literal" in rendered
        assert panel.last_text == "doctor output line\nsecond line [b] stays literal"


@pytest.mark.asyncio
async def test_output_copy_button_copies_last_text():
    app = WidgetApp()
    async with app.run_test() as pilot:
        panel = app.query_one(CollapsibleOutput)
        panel.collapsed = False
        panel.set_text("diagnostic [b] data")
        await pilot.pause()
        await pilot.click("#copy-output")
        assert app._clipboard == "diagnostic [b] data"
        assert str(app.query_one("#copy-output", Button).label) == "Copied"
        await pilot.pause(1.6)
        assert str(app.query_one("#copy-output", Button).label) == "Copy"


@pytest.mark.asyncio
async def test_copy_button_is_noop_without_output():
    app = WidgetApp()
    async with app.run_test() as pilot:
        panel = app.query_one(CollapsibleOutput)
        panel.collapsed = False
        await pilot.pause()
        await pilot.click("#copy-output")
        assert app._clipboard == ""
        assert str(app.query_one("#copy-output", Button).label) == "Copy"


@pytest.mark.asyncio
async def test_spinner_lifecycle_inside_app():
    app = WidgetApp()
    async with app.run_test() as pilot:
        spinner = app.query_one(OperationSpinner)
        assert spinner.is_running() is False
        spinner.start("doctor")
        assert spinner.is_running() is True
        initial_text = spinner.label_text()
        await pilot.pause(0.5)
        assert spinner.label_text() != initial_text
        spinner.finish(ok=True, note="done [b] still literal")
        assert spinner.is_running() is False
        assert "done [b] still literal" in spinner.label_text()
        assert "done [b] still literal" in str(spinner.visual)
        await pilot.pause(2.6)
        assert spinner.display is False
        assert spinner.is_running() is False
        assert "done [b] still literal" in spinner.label_text()
        assert "done [b] still literal" in str(spinner.visual)
        assert spinner._tick is None
        assert spinner._hide is None


def test_spinner_label_before_mount_is_safe():
    spinner = OperationSpinner()
    assert spinner.is_running() is False
    assert spinner.label_text() == ""
    assert spinner._tick is None
    assert spinner._hide is None
