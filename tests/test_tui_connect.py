"""Connect screen maps local readiness and posts selected engine actions."""
import pytest

textual = pytest.importorskip("textual")
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import ListView  # noqa: E402

from blackoutkit.tui.screens.connect import ConnectAction, ConnectScreen  # noqa: E402

MATRIX = [
    {"name": "xray", "display_name": "XRay", "summary": "Proxy core", "state": "ready", "blockers": []},
    {"name": "tun", "display_name": "TUN", "summary": "Network tunnel", "state": "blocked", "blockers": ["TUN runtime is missing"]},
    {"name": "linux_only", "display_name": "Linux only", "summary": "Linux engine", "state": "unsupported", "blockers": ["unsupported on win32"]},
]


class ConnectApp(App):
    def __init__(self):
        super().__init__()
        self.seen: list[ConnectAction] = []

    def compose(self) -> ComposeResult:
        yield ConnectScreen(state=None, capability_matrix_fn=lambda **kwargs: MATRIX)

    def on_connect_action(self, event: ConnectAction) -> None:
        self.seen.append(event)


@pytest.mark.asyncio
async def test_readiness_states_and_selected_engine_action():
    app = ConnectApp()
    async with app.run_test() as pilot:
        screen = app.query_one(ConnectScreen)
        rows = screen.build_rows()
        assert [row["state"] for row in rows] == ["ready", "blocked", "unsupported"]
        assert "local check only" in rows[0]["detail"]
        assert "remote reachability" not in rows[0]["detail"].lower()
        view = app.query_one("#engine-list", ListView)
        view.focus()
        view.index = 0
        view.action_select_cursor()
        await pilot.pause()
        assert [(event.kind, event.engine) for event in app.seen] == [("start", "xray")]


def test_set_rows_renders_supplied_normalized_rows():
    screen = ConnectScreen(state=None, capability_matrix_fn=lambda **kwargs: MATRIX)
    assert screen.build_rows()[1] == {
        "name": "tun", "display_name": "TUN", "state": "blocked",
        "detail": "Network tunnel · TUN runtime is missing · local check only",
    }
