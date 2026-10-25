"""Settings screen: search filter, detail, validated save."""
import pytest

textual = pytest.importorskip("textual")
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import Static  # noqa: E402

from blackoutkit.tui.screens.settingsscr import SettingsScreen  # noqa: E402
from blackoutkit.tui.state import ConsoleState  # noqa: E402


def _state() -> ConsoleState:
    return ConsoleState(
        snapshot_fn=lambda: {},
        capabilities_fn=lambda **k: (),
        load_configs_fn=lambda: [],
        add_config_fn=lambda uri: None,
        import_subscription_fn=lambda url: [],
        settings_load_fn=lambda: {"xray_socks_port": 10808},
        settings_groups_fn=lambda: [("Proxy", ["xray_socks_port"])],
        settings_choices_fn=lambda key: ("dark", "light") if key == "terminal_theme" else None,
        settings_display_fn=lambda key, value: str(value),
        settings_validate_fn=lambda key, value: (key == "xray_socks_port" and str(value).isdigit(), "[WinError 2] bad"),
        settings_set_fn=lambda key, value: None,
    )


class SettingsApp(App):
    def compose(self) -> ComposeResult:
        yield Static("Test root", markup=False)

    def on_mount(self) -> None:
        self.push_screen(SettingsScreen(state=_state()))


def _screen(app: SettingsApp) -> SettingsScreen:
    assert isinstance(app.screen, SettingsScreen)
    return app.screen


@pytest.mark.asyncio
async def test_search_filters_and_save_rejects_invalid():
    app = SettingsApp()
    async with app.run_test() as pilot:
        screen = _screen(app)
        screen.refresh_list("socks")
        await pilot.pause()
        items = [str(item.query_one("Static").render()) for item in screen.query("ListView ListItem")]
        assert any("xray_socks_port" in text for text in items)
        screen.select_key("xray_socks_port")
        await pilot.pause()
        assert "xray_socks_port = 10808" in str(screen.query_one("#settings-detail", Static).visual)
        screen.do_save("not-a-port")
        await pilot.pause()
        status_text = str(screen.query_one("#settings-status", Static).visual)
        assert "[WinError 2] bad" in status_text
        assert "bad" in status_text
        screen.do_save("10810")
        await pilot.pause()
        assert "Saved" in str(screen.query_one("#settings-status", Static).visual)
