"""Config screen never echoes credentials and clears submitted inputs."""
import pytest

textual = pytest.importorskip("textual")
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import Input, Static  # noqa: E402

from blackoutkit.tui.screens.configscr import ConfigScreen  # noqa: E402
from blackoutkit.tui.state import ConsoleState  # noqa: E402


def _state(*, add_config_fn=None, import_subscription_fn=None, load_configs_fn=None):
    return ConsoleState(
        snapshot_fn=lambda: {}, capabilities_fn=lambda **kwargs: (),
        load_configs_fn=load_configs_fn or (lambda: ["[vless] safe summary — example:443"]),
        add_config_fn=add_config_fn or (lambda uri: None),
        import_subscription_fn=import_subscription_fn or (lambda url: [object(), object()]),
        settings_load_fn=lambda: {}, settings_groups_fn=lambda: [],
        settings_choices_fn=lambda key: None,
        settings_display_fn=lambda key, value: str(value),
        settings_validate_fn=lambda key, value: (True, ""), settings_set_fn=lambda key, value: None,
    )


class ConfigApp(App):
    def __init__(self, state=None):
        super().__init__()
        self.state = state or _state()

    def compose(self) -> ComposeResult:
        yield Static("Test root", markup=False)

    def on_mount(self) -> None:
        self.push_screen(ConfigScreen(state=self.state))


def _screen(app: ConfigApp) -> ConfigScreen:
    assert isinstance(app.screen, ConfigScreen)
    return app.screen


@pytest.mark.asyncio
async def test_add_error_does_not_echo_uri_or_exception_and_clears_input():
    secret = "vmess://private-secret-token"
    state = _state(add_config_fn=lambda uri: (_ for _ in ()).throw(ValueError(secret)))
    app = ConfigApp(state)
    async with app.run_test() as pilot:
        screen = _screen(app)
        screen.query_one("#add-uri", Input).value = secret
        await pilot.click("#btn-add")
        await pilot.pause()
        assert screen.query_one("#add-uri", Input).value == ""
        status = str(screen.query_one("#config-status", Static).visual)
        rows = str(screen.query_one("#config-rows", Static).visual)
        assert "Could not add" in status
        assert secret not in status and secret not in rows


@pytest.mark.asyncio
async def test_import_error_does_not_echo_url_or_exception_and_clears_input():
    secret = "https://example.invalid/sub?token=do-not-echo"
    state = _state(import_subscription_fn=lambda url: (_ for _ in ()).throw(ValueError(secret)))
    app = ConfigApp(state)
    async with app.run_test() as pilot:
        screen = _screen(app)
        screen.query_one("#sub-url", Input).value = secret
        await pilot.click("#btn-import")
        await pilot.pause()
        assert screen.query_one("#sub-url", Input).value == ""
        status = str(screen.query_one("#config-status", Static).visual)
        assert "Could not import" in status
        assert secret not in status


@pytest.mark.asyncio
async def test_success_shows_generic_status_and_clears_both_fields():
    app = ConfigApp(_state())
    async with app.run_test() as pilot:
        screen = _screen(app)
        screen.query_one("#add-uri", Input).value = "vless://example-token@example:443"
        await pilot.click("#btn-add")
        await pilot.pause()
        assert screen.query_one("#add-uri", Input).value == ""
        status = str(screen.query_one("#config-status", Static).visual)
        assert status == "Config added."
        assert "example-token" not in status
        screen.query_one("#sub-url", Input).value = "https://example.invalid/sub?token=secret"
        await pilot.click("#btn-import")
        await pilot.pause()
        assert screen.query_one("#sub-url", Input).value == ""
        status = str(screen.query_one("#config-status", Static).visual)
        assert status == "Imported 2 configs."
        assert "secret" not in status
