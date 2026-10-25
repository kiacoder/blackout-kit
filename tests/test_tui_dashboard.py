"""Dashboard shows status strip and posts quick-action messages."""
import pytest

textual = pytest.importorskip("textual")
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import ListView  # noqa: E402

from blackoutkit.tui.screens.dashboard import DashAction, DashboardScreen  # noqa: E402
from blackoutkit.tui.state import ConsoleState  # noqa: E402
from blackoutkit.tui.widgets.status_strip import StatusStrip  # noqa: E402


def _state() -> ConsoleState:
    return ConsoleState(
        snapshot_fn=lambda: {"pid": None, "active_engine": "none", "settings": {}},
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


class DashApp(App):
    def __init__(self):
        super().__init__()
        self.seen: list[str] = []

    def compose(self) -> ComposeResult:
        yield DashboardScreen(state=_state())

    def on_dash_action(self, event: DashAction) -> None:
        self.seen.append(event.kind)


@pytest.mark.asyncio
async def test_dashboard_has_strip_and_posts_each_quick_action():
    app = DashApp()
    async with app.run_test() as pilot:
        assert app.query_one(StatusStrip) is not None
        screen = app.query_one(DashboardScreen)
        view = screen.query_one("#dash-actions", ListView)
        assert [item.name for item in view.children] == ["connect", "stop", "emergency"]

        screen.action_connect()
        screen.action_stop()
        screen.action_emergency()
        await pilot.pause()
        assert app.seen == ["connect", "stop", "emergency"]

        screen.post_message(DashAction("connect"))
        await pilot.pause()
        assert app.seen[-1] == "connect"
        assert len(app.seen) == 4
