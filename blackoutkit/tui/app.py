# blackoutkit/tui/app.py
"""BlackoutConsole — the assembled full-screen TUI app."""
from __future__ import annotations

from typing import Callable

from textual.app import App
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from .screens._worker import capture_cli, run_bg
from .screens.configscr import ConfigScreen
from .screens.connect import ConnectAction, ConnectScreen
from .screens.dashboard import DashAction, DashboardScreen
from .screens.diagnostics import DiagnosticsScreen
from .screens.settingsscr import SettingsScreen
from .screens.toolsscr import ToolsScreen
from .state import ConsoleState
from .theme import DARK_CSS, LIGHT_CSS  # noqa: F401


class QuitConfirmScreen(ModalScreen):
    """Modal dialog displayed when quitting while an engine process is active."""

    DEFAULT_CSS = """
    QuitConfirmScreen {
        align: center middle;
    }
    #confirm-dialog {
        padding: 1 2;
        width: 60;
        height: auto;
        border: thick $error;
        background: $surface;
    }
    #confirm-msg {
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("q", "confirm_quit", "Quit", priority=True),
        Binding("escape", "cancel_quit", "Cancel", priority=True),
    ]

    def __init__(self) -> None:
        super().__init__(id="confirm-quit", name="confirm-quit")

    def compose(self):
        with Vertical(id="confirm-dialog"):
            yield Static(
                "A proxy engine is currently running!\nPress 'q' again or click Quit to exit, or Esc to cancel.",
                id="confirm-msg",
                markup=False,
            )
            yield Button("Quit anyway", id="btn-quit-confirm", variant="error")
            yield Button("Cancel", id="btn-quit-cancel")

    def action_confirm_quit(self) -> None:
        app = getattr(self, "app", None)
        if app is not None:
            app._exit_confirmed = True
            app.exit()

    def action_cancel_quit(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "btn-quit-confirm":
            self.action_confirm_quit()
        elif event.button.id == "btn-quit-cancel":
            self.action_cancel_quit()


class BlackoutConsole(App):
    """Blackout Kit Console terminal interface."""

    CSS = DARK_CSS

    BINDINGS = [
        Binding("s", "switch_screen('dashboard')", "Status", priority=True),
        Binding("c", "switch_screen('connect')", "Connect", priority=True),
        Binding("d", "switch_screen('diagnostics')", "Doctor", priority=True),
        Binding("g", "switch_screen('config')", "Config", priority=True),
        Binding("o", "switch_screen('settings')", "Settings", priority=True),
        Binding("t", "switch_screen('tools')", "Tools", priority=True),
        Binding("question_mark", "help_keys", "Keys", priority=True),
        Binding("escape", "escape_key", "Back", priority=True),
        Binding("q", "quit_app", "Quit", priority=True),
    ]

    def __init__(self, state_for_tests: bool = False) -> None:
        super().__init__()
        if state_for_tests:
            stub = lambda *a, **k: "stub"  # noqa: E731
            self._state = ConsoleState(
                snapshot_fn=lambda: {"pid": None, "active_engine": "none", "settings": {}},
                capabilities_fn=lambda **k: (),
                load_configs_fn=lambda: [],
                add_config_fn=stub,
                import_subscription_fn=stub,
                settings_load_fn=lambda: {},
                settings_groups_fn=lambda: [],
                settings_choices_fn=lambda key: None,
                settings_display_fn=lambda key, value: str(value),
                settings_validate_fn=lambda key, value: (True, ""),
                settings_set_fn=stub,
                doctor_fn=stub,
                fix_preview_fn=stub,
            )
            self._tunnel_runner: Callable[..., str] = stub
        else:
            self._state = ConsoleState.default()
            self._tunnel_runner = lambda command, *args: capture_cli(command, *args)
        self._exit_confirmed = False

    def on_mount(self) -> None:
        self._dashboard = DashboardScreen(state=self._state)
        self.install_screen(self._dashboard, name="dashboard")
        self.install_screen(ConnectScreen(state=self._state), name="connect")
        self.install_screen(DiagnosticsScreen(state=self._state), name="diagnostics")
        self.install_screen(ConfigScreen(state=self._state), name="config")
        self.install_screen(SettingsScreen(state=self._state), name="settings")
        self.install_screen(ToolsScreen(), name="tools")
        self.install_screen(QuitConfirmScreen(), name="confirm-quit")
        self.push_screen("dashboard")

    @property
    def engine_alive(self) -> bool:
        return bool(self._state.snapshot().get("pid"))

    def action_switch_screen(self, name: str) -> None:
        self.switch_screen(name)

    def action_help_keys(self) -> None:
        self.notify("Keys: s status · c connect · d doctor · g config · o settings · t tools · Esc back · q quit")

    def action_escape_key(self) -> None:
        if self.focused is not None:
            self.set_focus(None)
        elif not isinstance(self.screen, DashboardScreen):
            self.switch_screen("dashboard")

    def action_quit_app(self) -> None:
        if self.engine_alive and not self._exit_confirmed:
            if not isinstance(self.screen, QuitConfirmScreen):
                self.push_screen("confirm-quit")
                return
        self._exit_confirmed = True
        self.exit()

    def _run_tunnel(self, command: str, *args: str) -> None:
        self.notify(f"{command} started in background…")
        run_bg(
            self,
            lambda: self._tunnel_runner(command, *args),
            lambda text: self.notify(text[:200] or "done"),
            group="tunnel",
        )

    def on_dash_action(self, event: DashAction) -> None:
        if event.kind in ("connect", "emergency", "stop"):
            self._run_tunnel(event.kind)

    def on_connect_action(self, event: ConnectAction) -> None:
        if event.kind == "start":
            if event.engine:
                self._run_tunnel("connect", event.engine)
            else:
                self._run_tunnel("connect")
