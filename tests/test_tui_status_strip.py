# tests/test_tui_status_strip.py
"""StatusStrip renders local-only status and never claims reachability."""
import pytest

textual = pytest.importorskip("textual")
from textual.app import App, ComposeResult  # noqa: E402

from blackoutkit.tui.state import ConsoleState  # noqa: E402
from blackoutkit.tui.widgets.status_strip import StatusStrip  # noqa: E402


SNAP = {
    "pid": 4242,
    "active_engine": "xray",
    "http_port": 10809,
    "socks_port": 10808,
    "settings": {"country": "IR"},
}


def _fake_state() -> ConsoleState:
    return ConsoleState(
        snapshot_fn=lambda: SNAP,
        capabilities_fn=lambda **k: (),
        load_configs_fn=lambda: [],
        add_config_fn=lambda uri: None,
        import_subscription_fn=lambda url: [],
        settings_load_fn=lambda: {},
        settings_groups_fn=lambda: [],
        settings_choices_fn=lambda key: None,
        settings_display_fn=lambda key, value: str(value),
        settings_validate_fn=lambda key, value: (True, ""),
        settings_set_fn=lambda key, value: None,
    )


class StripApp(App):
    def compose(self) -> ComposeResult:
        yield StatusStrip(state=_fake_state(), interval=0.2)


@pytest.mark.asyncio
async def test_strip_renders_local_fact_line():
    app = StripApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        strip = app.query_one(StatusStrip)
        text = str(strip.renderable if hasattr(strip, "renderable") else strip._content)
        assert "xray" in text
        assert "4242" in text
        assert "local" in text.lower()


def test_compose_line_handles_error_snapshot():
    line = StatusStrip.compose_line({"error": "daemon dead"})
    assert "daemon dead" in line
    assert "🔴" in line


def test_compose_line_alive_snapshot():
    line = StatusStrip.compose_line(SNAP)
    assert "🟢" in line and "xray" in line and "IR" in line
