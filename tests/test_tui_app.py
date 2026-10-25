"""Console app: screens registered, bindings switch screens, quit confirmation."""
import pytest

textual = pytest.importorskip("textual")
from blackoutkit.tui.app import BlackoutConsole  # noqa: E402
from blackoutkit.tui.screens.configscr import ConfigScreen  # noqa: E402
from blackoutkit.tui.screens.connect import ConnectAction, ConnectScreen  # noqa: E402
from blackoutkit.tui.screens.dashboard import DashAction, DashboardScreen  # noqa: E402
from blackoutkit.tui.screens.diagnostics import DiagnosticsScreen  # noqa: E402
from blackoutkit.tui.screens.settingsscr import SettingsScreen  # noqa: E402
from blackoutkit.tui.screens.toolsscr import ToolsScreen  # noqa: E402


@pytest.mark.asyncio
async def test_bindings_switch_screens():
    app = BlackoutConsole(state_for_tests=True)
    async with app.run_test() as pilot:
        assert isinstance(app.screen, DashboardScreen)

        await pilot.press("c")
        await pilot.pause()
        assert isinstance(app.screen, ConnectScreen)

        await pilot.press("d")
        await pilot.pause()
        assert isinstance(app.screen, DiagnosticsScreen)

        await pilot.press("g")
        await pilot.pause()
        assert isinstance(app.screen, ConfigScreen)

        await pilot.press("o")
        await pilot.pause()
        assert isinstance(app.screen, SettingsScreen)

        await pilot.press("t")
        await pilot.pause()
        assert isinstance(app.screen, ToolsScreen)

        await pilot.press("s")
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)


@pytest.mark.asyncio
async def test_quit_binding_asks_when_engine_alive(monkeypatch):
    app = BlackoutConsole(state_for_tests=True)
    async with app.run_test() as pilot:
        monkeypatch.setattr(type(app), "engine_alive", property(lambda self: True))
        await pilot.press("q")
        await pilot.pause()
        assert app.screen.name or app.screen.id  # a confirm dialog/screen is on top
        assert not app._exit_confirmed  # app did not exit immediately

        # Pressing q again confirms exit
        await pilot.press("q")
        await pilot.pause()
        assert app._exit_confirmed


@pytest.mark.asyncio
async def test_quit_binding_exits_immediately_when_engine_not_alive():
    app = BlackoutConsole(state_for_tests=True)
    async with app.run_test() as pilot:
        assert not app.engine_alive
        await pilot.press("q")
        await pilot.pause()
        assert app._exit_confirmed


@pytest.mark.asyncio
async def test_actions_trigger_tunnel_runner():
    called = []

    def fake_runner(cmd, *args):
        called.append((cmd, args))
        return f"ran {cmd}"

    app = BlackoutConsole(state_for_tests=True)
    app._tunnel_runner = fake_runner

    async with app.run_test() as pilot:
        app.post_message(DashAction("connect"))
        await pilot.pause(0.1)
        assert ("connect", ()) in called

        app.post_message(DashAction("stop"))
        await pilot.pause(0.1)
        assert ("stop", ()) in called

        app.post_message(DashAction("emergency"))
        await pilot.pause(0.1)
        assert ("emergency", ()) in called

        app.post_message(ConnectAction("start", "xray"))
        await pilot.pause(0.1)
        assert ("connect", ("xray",)) in called


@pytest.mark.asyncio
async def test_tunnel_toasts_render_markup_literally(monkeypatch):
    app = BlackoutConsole(state_for_tests=True)

    def boom(command, *args):
        raise ValueError("[/b] mismatched close from config")

    app._tunnel_runner = boom
    calls = []
    monkeypatch.setattr(app, "notify", lambda message, **kwargs: calls.append((message, kwargs)))

    async with app.run_test() as pilot:
        app.post_message(DashAction("connect"))
        for _ in range(50):
            await pilot.pause(0.05)
            if len(calls) >= 2:
                break
        assert len(calls) >= 2
        started_msg, started_kwargs = calls[0]
        assert "connect started" in started_msg
        assert started_kwargs.get("markup") is False
        result_msg, result_kwargs = calls[1]
        assert "[/b] mismatched close from config" in result_msg
        assert result_kwargs.get("markup") is False
